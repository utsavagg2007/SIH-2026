"""Differential test: scalar cardinality and widest fanout vs the collections.

``ActivityWindow`` gained four scalar counts and a widest-host-fanout query so
that PortScanDetector and DDoSDetector can qualify a window without building a
set of every port or source on every flow. That materialization was quadratic
in exactly the traffic those detectors exist to catch: a scan or a flood is,
by definition, a stream of values nobody has seen before.

The scalar answers must be *exactly* what the collection-returning APIs would
have said, so every test here asserts against the collection form rather than
against a hand-computed number. The collections are themselves pinned against
the original scan-based implementation in
``test_sliding_window_equivalence.py``, so the chain reaches back to the
pre-optimization behaviour.
"""

from __future__ import annotations

import random

import pytest

from detection_core.aggregators import ActivityWindow, FlowObservation

SEED = 20260830


def observation(
    timestamp: float,
    *,
    dst_ip: str = "10.0.0.1",
    dst_port: int | None = 443,
    proto: str | None = "tcp",
    src_ip: str | None = "10.0.0.9",
    orig_bytes: int = 100,
) -> FlowObservation:
    return FlowObservation(
        timestamp=timestamp,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        src_ip=src_ip,
        orig_packets=1,
        orig_bytes=orig_bytes,
        resp_bytes=200,
    )


def reference_fanout(window: ActivityWindow) -> int:
    """What the detector used to compute, from the materialized mapping."""
    return max((len(hosts) for hosts in window.hosts_by_port().values()), default=0)


def assert_scalars_match(window: ActivityWindow, context: str) -> None:
    """Every scalar equals the length of the collection it replaces."""
    assert window.unique_dst_port_count() == len(window.dst_ports()), context
    assert window.unique_dst_ip_count() == len(window.dst_ips()), context
    assert window.unique_src_ip_count() == len(window.src_ips()), context
    assert window.unique_protocol_count() == len(window.protocols()), context
    assert window.max_hosts_per_port() == reference_fanout(window), context


# --------------------------------------------------------------------------
# 1-18. Randomized differential comparison
# --------------------------------------------------------------------------


@pytest.mark.parametrize("window_seconds", [1.0, 10.0, 60.0])
@pytest.mark.parametrize("run", range(4))
def test_randomized_sequences_agree_at_every_step(window_seconds, run):
    """Small pools, so repeats and shared (port, host) pairs are common."""
    rng = random.Random(SEED + run * 13 + int(window_seconds))
    window = ActivityWindow(window_seconds)

    hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    ports = [22, 80, 443, None]
    sources = ["192.168.0.5", "192.168.0.6", None]
    protocols = ["tcp", "udp", None]

    timestamp = 1000.0
    for step in range(400):
        timestamp += rng.choice([0.0, 0.0, 0.1, 0.5, 1.0, 3.0, 25.0])
        window.observe(
            observation(
                timestamp,
                dst_ip=rng.choice(hosts),
                dst_port=rng.choice(ports),
                proto=rng.choice(protocols),
                src_ip=rng.choice(sources),
            )
        )
        assert_scalars_match(window, f"run={run} w={window_seconds} step={step}")


def test_attack_shaped_growth_agrees_throughout():
    """The shapes the optimization is for: every flow a brand-new value."""
    vertical = ActivityWindow(60.0)
    horizontal = ActivityWindow(60.0)
    flood = ActivityWindow(60.0)

    for index in range(300):
        timestamp = 1000.0 + index * 0.01
        vertical.observe(observation(timestamp, dst_port=1 + index))
        horizontal.observe(
            observation(timestamp, dst_port=22, dst_ip=f"10.1.{index // 256}.{index % 256}")
        )
        flood.observe(
            observation(timestamp, src_ip=f"198.1.{index // 256}.{index % 256}")
        )

        assert_scalars_match(vertical, f"vertical step={index}")
        assert_scalars_match(horizontal, f"horizontal step={index}")
        assert_scalars_match(flood, f"flood step={index}")

    assert vertical.unique_dst_port_count() == 300
    assert horizontal.max_hosts_per_port() == 300
    assert flood.unique_src_ip_count() == 300


# --------------------------------------------------------------------------
# Named cases: duplicates, expiry, and the fanout maximum
# --------------------------------------------------------------------------


def test_repeated_values_count_once():
    window = ActivityWindow(60.0)
    for _ in range(5):
        window.observe(observation(1000.0, dst_port=443, src_ip="10.9.9.9"))

    assert window.unique_dst_port_count() == 1
    assert window.unique_src_ip_count() == 1
    assert window.max_hosts_per_port() == 1
    assert_scalars_match(window, "repeats")


def test_a_duplicate_expiring_does_not_drop_the_value():
    """One of two live copies leaving must not remove the value."""
    window = ActivityWindow(10.0)
    window.observe(observation(1000.0, dst_port=443, src_ip="10.9.9.9"))
    window.observe(observation(1005.0, dst_port=443, src_ip="10.9.9.9"))

    window.expire(1010.5)  # drops only the first

    assert window.unique_dst_port_count() == 1
    assert window.unique_src_ip_count() == 1
    assert window.max_hosts_per_port() == 1
    assert_scalars_match(window, "one duplicate expired")


def test_the_final_occurrence_expiring_drops_the_value():
    window = ActivityWindow(10.0)
    window.observe(observation(1000.0, dst_port=443, src_ip="10.9.9.9"))
    window.observe(observation(1005.0, dst_port=22, src_ip="10.8.8.8"))

    window.expire(1011.0)

    assert window.dst_ports() == {22}
    assert window.unique_dst_port_count() == 1
    assert window.unique_src_ip_count() == 1
    assert_scalars_match(window, "final occurrence expired")


def test_missing_optional_values_are_excluded():
    window = ActivityWindow(60.0)
    window.observe(observation(1000.0, dst_port=None, src_ip=None, proto=None))
    window.observe(observation(1001.0, dst_port=443, src_ip="10.1.1.1"))

    assert window.unique_dst_port_count() == 1
    assert window.unique_src_ip_count() == 1
    assert window.unique_protocol_count() == 1
    # dst_ip is required, so both observations contribute a host.
    assert window.unique_dst_ip_count() == 1  # same host in both
    assert_scalars_match(window, "missing optionals")


def test_fanout_rises_as_hosts_are_added_to_one_port():
    window = ActivityWindow(60.0)
    for index in range(6):
        window.observe(observation(1000.0 + index, dst_port=22, dst_ip=f"10.0.0.{index}"))
        assert window.max_hosts_per_port() == index + 1
        assert_scalars_match(window, f"growth {index}")


def test_a_repeated_host_port_pair_does_not_raise_fanout():
    window = ActivityWindow(60.0)
    window.observe(observation(1000.0, dst_port=22, dst_ip="10.0.0.7"))
    window.observe(observation(1001.0, dst_port=22, dst_ip="10.0.0.7"))

    assert window.max_hosts_per_port() == 1
    assert_scalars_match(window, "repeated pair")


def test_fanout_falls_when_the_widest_port_loses_hosts():
    window = ActivityWindow(10.0)
    # Port 22 reaches three hosts; port 80 reaches one.
    for index in range(3):
        window.observe(observation(1000.0 + index, dst_port=22, dst_ip=f"10.0.0.{index}"))
    window.observe(observation(1008.0, dst_port=80, dst_ip="10.0.1.1"))
    assert window.max_hosts_per_port() == 3

    window.expire(1010.5)  # drops 10.0.0.0 from port 22
    assert window.max_hosts_per_port() == 2
    assert_scalars_match(window, "fanout fell to 2")

    window.expire(1012.5)  # drops the rest of port 22
    assert window.max_hosts_per_port() == 1
    assert_scalars_match(window, "only port 80 left")


def test_the_previous_maximum_port_disappearing_recomputes():
    """The recorded maximum leaving entirely, not merely shrinking."""
    window = ActivityWindow(10.0)
    for index in range(4):
        window.observe(observation(1000.0 + index * 0.1, dst_port=22, dst_ip=f"10.0.0.{index}"))
    for index in range(2):
        window.observe(observation(1005.0 + index, dst_port=80, dst_ip=f"10.0.1.{index}"))
    assert window.max_hosts_per_port() == 4

    # Everything on port 22 expires at once; port 80 survives.
    window.expire(1011.0)

    assert 22 not in window.hosts_by_port()
    assert window.max_hosts_per_port() == 2
    assert_scalars_match(window, "widest port gone")


def test_a_tie_between_ports_is_handled():
    window = ActivityWindow(60.0)
    for index in range(3):
        window.observe(observation(1000.0 + index, dst_port=22, dst_ip=f"10.0.0.{index}"))
        window.observe(observation(1000.5 + index, dst_port=80, dst_ip=f"10.0.1.{index}"))

    assert window.max_hosts_per_port() == 3
    assert window._fanout_buckets == {3: 2}
    assert_scalars_match(window, "tie")


def test_complete_expiry_then_refill():
    window = ActivityWindow(5.0)
    for index in range(4):
        window.observe(observation(1000.0 + index, dst_port=20 + index, dst_ip=f"10.0.0.{index}"))

    window.expire(999_999.0)
    assert window.is_empty()
    assert window.unique_dst_port_count() == 0
    assert window.unique_src_ip_count() == 0
    assert window.max_hosts_per_port() == 0
    assert_scalars_match(window, "drained")

    window.observe(observation(1_000_000.0, dst_port=443, dst_ip="10.5.5.5"))
    assert window.unique_dst_port_count() == 1
    assert window.max_hosts_per_port() == 1
    assert_scalars_match(window, "refilled")


def test_the_exact_event_time_boundary():
    window = ActivityWindow(10.0)
    window.observe(observation(1000.0, dst_port=22, dst_ip="10.0.0.1"))
    window.observe(observation(1005.0, dst_port=80, dst_ip="10.0.0.2"))

    window.expire(1010.0)  # cutoff 1000.0, half-open: the first has left
    assert window.unique_dst_port_count() == 1
    assert_scalars_match(window, "exact boundary")

    window.expire(1015.0)
    assert window.unique_dst_port_count() == 0
    assert_scalars_match(window, "past boundary")


def test_out_of_order_arrival_is_counted_the_same_way():
    window = ActivityWindow(600.0)
    window.observe(observation(1000.0, dst_port=22))
    window.observe(observation(1050.0, dst_port=80))
    window.observe(observation(1020.0, dst_port=443))  # late

    assert window.unique_dst_port_count() == 3
    assert_scalars_match(window, "out of order")


# --------------------------------------------------------------------------
# Phase 10: no new state leak
# --------------------------------------------------------------------------


def assert_no_fanout_residue(window: ActivityWindow) -> None:
    """Test-only invariant: a drained window keeps no fanout bookkeeping."""
    assert window._hosts_by_port == {}
    assert window._fanout_buckets == {}
    assert window.max_hosts_per_port() == 0


def test_buckets_never_hold_a_zero_count():
    window = ActivityWindow(10.0)
    for index in range(5):
        window.observe(observation(1000.0 + index, dst_port=22, dst_ip=f"10.0.0.{index}"))
    window.expire(1011.0)

    assert all(count > 0 for count in window._fanout_buckets.values())
    assert all(fanout > 0 for fanout in window._fanout_buckets)


def test_a_complete_drain_leaves_no_cardinality_state():
    window = ActivityWindow(1.0)
    for index in range(2_000):
        window.observe(
            observation(
                1000.0 + index * 2.0,
                dst_port=1 + index,
                dst_ip=f"10.{index // 256 % 256}.{index % 256}.1",
                src_ip=f"192.168.{index // 256 % 256}.{index % 256}",
            )
        )
        assert window.attempts == 1  # each observation expires the previous
        assert window.unique_dst_port_count() == 1
        assert window.max_hosts_per_port() == 1

    window.expire(9_999_999.0)
    assert_no_fanout_residue(window)
    assert window._dst_port_counts == {}
    assert window._src_ip_counts == {}


def test_high_cardinality_history_does_not_accumulate_buckets():
    """Thousands of distinct ports, but only ever a few live fanout values."""
    window = ActivityWindow(60.0)
    for index in range(3_000):
        window.observe(observation(1000.0 + index * 0.001, dst_port=1 + index))

    # Every port has exactly one host, so there is one bucket, not 3,000.
    assert window.unique_dst_port_count() == 3_000
    assert window._fanout_buckets == {1: 3_000}
    assert window.max_hosts_per_port() == 1

    window.expire(9_999_999.0)
    assert_no_fanout_residue(window)


def test_clear_resets_the_fanout_state():
    window = ActivityWindow(60.0)
    for index in range(5):
        window.observe(observation(1000.0 + index, dst_port=22, dst_ip=f"10.0.0.{index}"))

    window.clear()

    assert_no_fanout_residue(window)
    assert_scalars_match(window, "cleared")
