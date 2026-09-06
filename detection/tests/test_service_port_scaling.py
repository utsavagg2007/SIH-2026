"""``unique_service_port_count`` must be O(1), and must stay correct.

The count used to be a ``sum(...)`` over the live port dict, evaluated on the
hot qualification path - once per flow, before anything had decided the flow
was interesting. A port scan's whole character is that every flow brings a
port nobody has seen, so the scan grew with exactly the traffic it existed to
qualify: measured per-flow cost rose 13x between a 500-port and an 8 000-port
sweep.

Two things are pinned here, in this order of importance:

1. **Correctness** - the maintained counter equals a materialized reference,
   through arrival, repetition, expiry and refill, at any boundary.
2. **Flatness** - per-flow cost does not grow with the size of the sweep.

The timing test asserts a deliberately loose bound. It is there to catch the
reintroduction of a per-flow scan, which shows up as a several-fold rise; it
is not a microbenchmark and must not fail because a shared CI box was busy.
"""

from __future__ import annotations

import time

import pytest

from detection_core import PortScanConfig, PortScanDetector
from detection_core.aggregators import ActivityWindow, FlowObservation

MAX_SERVICE_PORT = 49_151


def observation(ts: float, port: int | None, *, dst_ip: str = "10.0.0.80"):
    return FlowObservation(
        timestamp=ts,
        dst_ip=dst_ip,
        dst_port=port,
        proto="tcp",
        src_ip="10.0.0.66",
        orig_packets=1,
        orig_bytes=40,
        resp_bytes=0,
        conn_state="S0",
    )


def materialized(window: ActivityWindow, boundary: int) -> int:
    """The reference: build the set, then count it."""
    return len({p for p in window.dst_ports() if p <= boundary})


# --------------------------------------------------------------------------
# 1. Correctness of the incremental counter
# --------------------------------------------------------------------------


@pytest.mark.parametrize("boundary", [0, 1, 22, 1023, 49_151, 65_535])
def test_the_counter_matches_the_materialized_reference(boundary):
    """Arrival, repetition and expiry, checked after every single step."""
    window = ActivityWindow(60.0, service_port_max=boundary)
    ts = 1_000.0
    # Ports either side of every boundary, with repeats and a portless flow.
    ports = [22, 80, 443, 1023, 1024, 49_151, 49_152, 65_535, 22, 80, None, 443]

    for step, port in enumerate(ports * 3):
        ts += 1.0
        window.observe(observation(ts, port))
        assert window.unique_service_port_count(boundary) == materialized(
            window, boundary
        ), f"after arrival step={step} port={port}"

    # Drain by advancing event time past the window, checking on the way out.
    for step in range(70):
        ts += 1.0
        window.expire(ts)
        assert window.unique_service_port_count(boundary) == materialized(
            window, boundary
        ), f"during expiry step={step}"

    assert window.is_empty()
    assert window.unique_service_port_count(boundary) == 0

    # Refill after a full drain: the counter must have returned to zero, not
    # merely looked like it.
    for port in ports:
        ts += 1.0
        window.observe(observation(ts, port))
    assert window.unique_service_port_count(boundary) == materialized(window, boundary)


def test_an_unpinned_boundary_is_still_answered_exactly():
    """Any boundary other than the pinned one falls back to the scan."""
    window = ActivityWindow(60.0, service_port_max=1023)
    for i, port in enumerate([22, 80, 443, 8080, 49_151, 60_000]):
        window.observe(observation(1_000.0 + i, port))

    for boundary in (0, 22, 79, 1023, 8080, 49_151, 65_535):
        assert window.unique_service_port_count(boundary) == materialized(
            window, boundary
        ), f"boundary={boundary}"


def test_no_pinned_boundary_still_works():
    """A window constructed without a boundary answers by scanning."""
    window = ActivityWindow(60.0)
    assert window.service_port_max is None
    for i, port in enumerate([22, 443, 50_000]):
        window.observe(observation(1_000.0 + i, port))
    assert window.unique_service_port_count(MAX_SERVICE_PORT) == 2


def test_clear_resets_the_counter():
    window = ActivityWindow(60.0, service_port_max=MAX_SERVICE_PORT)
    for i, port in enumerate([22, 80, 443]):
        window.observe(observation(1_000.0 + i, port))
    assert window.unique_service_port_count(MAX_SERVICE_PORT) == 3

    window.clear()
    assert window.unique_service_port_count(MAX_SERVICE_PORT) == 0
    window.observe(observation(2_000.0, 22))
    assert window.unique_service_port_count(MAX_SERVICE_PORT) == 1


def test_a_rejected_boundary_is_rejected_early():
    with pytest.raises(ValueError):
        ActivityWindow(60.0, service_port_max=-1)
    with pytest.raises(ValueError):
        ActivityWindow(60.0, service_port_max=65_536)


def test_the_detector_pins_its_own_boundary():
    """PortScanDetector must actually take the fast path, not just allow it."""
    config = PortScanConfig()
    detector = PortScanDetector(config)
    assert detector._windows.service_port_max == config.max_service_port


# --------------------------------------------------------------------------
# 2. Flat per-flow cost on attack-shaped traffic
# --------------------------------------------------------------------------


def _per_flow_microseconds(port_count: int) -> float:
    """Drive the window the way ``process()`` does, once per flow."""
    window = ActivityWindow(3_600.0, service_port_max=MAX_SERVICE_PORT)
    observations = [
        observation(1_000.0 + i * 0.001, 1 + (i % 49_000)) for i in range(port_count)
    ]

    start = time.perf_counter()
    for obs in observations:
        window.observe(obs)
        window.unique_dst_port_count()
        window.max_hosts_per_port()
        window.unique_service_port_count(MAX_SERVICE_PORT)
    return (time.perf_counter() - start) / port_count * 1e6


@pytest.mark.parametrize("port_count", [500, 1_000, 2_000, 4_000, 8_000])
def test_the_sweep_still_qualifies_at_every_size(port_count):
    """Flatness is worthless if the big sweeps stopped being detected."""
    window = ActivityWindow(3_600.0, service_port_max=MAX_SERVICE_PORT)
    for i in range(port_count):
        window.observe(observation(1_000.0 + i * 0.001, 1 + (i % 49_000)))
    assert window.unique_service_port_count(MAX_SERVICE_PORT) == materialized(
        window, MAX_SERVICE_PORT
    )


def test_per_flow_cost_does_not_grow_with_the_sweep():
    """16x the ports must not cost meaningfully more per flow.

    The pre-fix implementation measured 13x here. The bound is 4x so that a
    noisy machine cannot fail the build while a returned linear scan still
    cannot pass it.
    """
    small = min(_per_flow_microseconds(500) for _ in range(3))
    large = min(_per_flow_microseconds(8_000) for _ in range(3))

    assert large < small * 4.0, (
        f"per-flow cost grew {large / small:.1f}x from 500 to 8000 ports "
        f"({small:.2f}us -> {large:.2f}us); the hot path looks linear again"
    )
