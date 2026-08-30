"""Rolling window tests.

The window is key-agnostic: port scanning keys it by source IP, DDoS by
destination IP. These tests exercise it directly.
"""

from __future__ import annotations

import pytest

from detection_core.aggregators import ActivityWindow, FlowObservation, WindowIndex

from .conftest import make_flow


def obs(
    ts: float,
    dst_ip: str = "10.0.0.9",
    port: int | None = 80,
    proto: str = "tcp",
    src_ip: str | None = None,
    orig_packets: int = 0,
    orig_bytes: int = 0,
):
    return FlowObservation(
        timestamp=ts,
        dst_ip=dst_ip,
        dst_port=port,
        proto=proto,
        src_ip=src_ip,
        orig_packets=orig_packets,
        orig_bytes=orig_bytes,
    )


# --------------------------------------------------------------------------
# FlowObservation
# --------------------------------------------------------------------------


def test_observation_from_flow():
    flow = make_flow(timestamp=100.0, dst_ip="10.0.0.2", dst_port=443, proto="tcp")
    observation = FlowObservation.from_flow(flow)
    assert observation.timestamp == 100.0
    assert observation.dst_ip == "10.0.0.2"
    assert observation.dst_port == 443
    assert observation.proto == "tcp"


def test_observation_carries_source_and_originator_volume():
    """Responder counters are excluded - they are the destination's replies."""
    flow = make_flow(
        src_ip="10.9.9.9", orig_pkts=4, resp_pkts=6, orig_bytes=100, resp_bytes=250
    )
    observation = FlowObservation.from_flow(flow)
    assert observation.src_ip == "10.9.9.9"
    assert observation.orig_packets == 4
    assert observation.orig_bytes == 100


def test_observation_volume_defaults_to_zero():
    observation = FlowObservation(timestamp=1.0, dst_ip="10.0.0.1")
    assert observation.src_ip is None
    assert observation.orig_packets == 0
    assert observation.orig_bytes == 0


def test_observation_from_flow_without_port():
    observation = FlowObservation.from_flow(make_flow(dst_port=None))
    assert observation.dst_port is None


# --------------------------------------------------------------------------
# ActivityWindow
# --------------------------------------------------------------------------


def test_window_rejects_non_positive_span():
    with pytest.raises(ValueError):
        ActivityWindow(0)


def test_window_counts_distinct_values_only():
    window = ActivityWindow(60.0)
    for _ in range(5):
        window.observe(obs(100.0, dst_ip="10.0.0.9", port=80))

    assert window.attempts == 5
    assert window.dst_ports() == {80}
    assert window.dst_ips() == {"10.0.0.9"}


def test_window_tracks_multiple_ports_and_hosts():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", 22))
    window.observe(obs(101.0, "10.0.0.2", 80))
    window.observe(obs(102.0, "10.0.0.3", 443))

    assert window.dst_ports() == {22, 80, 443}
    assert window.dst_ips() == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert window.attempts == 3


def test_missing_port_is_not_counted_as_a_port():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", None))
    window.observe(obs(101.0, "10.0.0.2", None))

    assert window.dst_ports() == set()
    assert window.dst_ips() == {"10.0.0.1", "10.0.0.2"}


def test_expiry_drops_old_observations():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", 22))
    window.observe(obs(120.0, "10.0.0.2", 80))
    assert window.attempts == 2

    # At t=170 the t=100 observation is 70s old and must be gone.
    window.observe(obs(170.0, "10.0.0.3", 443))
    assert window.attempts == 2
    assert window.dst_ports() == {80, 443}
    assert 22 not in window.dst_ports()


def test_window_is_half_open_at_the_boundary():
    """An observation exactly window_seconds old has expired."""
    window = ActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", 22))
    window.observe(obs(160.0, "10.0.0.2", 80))
    assert window.dst_ports() == {80}


def test_expire_can_be_called_without_a_new_observation():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0))
    window.expire(1000.0)
    assert window.is_empty()


def test_time_span():
    window = ActivityWindow(60.0)
    assert window.time_span() is None
    window.observe(obs(100.0))
    window.observe(obs(130.0))
    assert window.time_span() == (100.0, 130.0)


def test_hosts_by_port_groups_fanout():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", 22))
    window.observe(obs(101.0, "10.0.0.2", 22))
    window.observe(obs(102.0, "10.0.0.3", 80))

    assert window.hosts_by_port() == {22: {"10.0.0.1", "10.0.0.2"}, 80: {"10.0.0.3"}}


def test_hosts_by_port_deduplicates_repeat_visits():
    window = ActivityWindow(60.0)
    for _ in range(10):
        window.observe(obs(100.0, "10.0.0.1", 22))

    assert window.hosts_by_port() == {22: {"10.0.0.1"}}


def test_hosts_by_port_excludes_portless_observations():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", None))
    window.observe(obs(101.0, "10.0.0.2", None))
    window.observe(obs(102.0, "10.0.0.3", 22))

    assert window.hosts_by_port() == {22: {"10.0.0.3"}}


def test_hosts_by_port_respects_expiry():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", 22))
    window.observe(obs(200.0, "10.0.0.2", 22))

    assert window.hosts_by_port() == {22: {"10.0.0.2"}}


def test_hosts_by_port_empty_window():
    assert ActivityWindow(60.0).hosts_by_port() == {}


def test_src_ips_are_distinct():
    window = ActivityWindow(60.0)
    for _ in range(5):
        window.observe(obs(100.0, src_ip="10.0.0.1"))
    window.observe(obs(101.0, src_ip="10.0.0.2"))

    assert window.src_ips() == {"10.0.0.1", "10.0.0.2"}


def test_src_ips_ignores_observations_without_a_source():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0, src_ip=None))
    window.observe(obs(101.0, src_ip="10.0.0.1"))

    assert window.src_ips() == {"10.0.0.1"}


def test_volume_totals_accumulate():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0, orig_packets=10, orig_bytes=500))
    window.observe(obs(101.0, orig_packets=5, orig_bytes=250))

    assert window.total_orig_packets() == 15
    assert window.total_orig_bytes() == 750


def test_volume_totals_are_zero_on_an_empty_window():
    window = ActivityWindow(60.0)
    assert window.total_orig_packets() == 0
    assert window.total_orig_bytes() == 0


def test_volume_totals_respect_expiry():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0, orig_packets=999, orig_bytes=9999))
    window.observe(obs(200.0, orig_packets=3, orig_bytes=30))

    assert window.total_orig_packets() == 3
    assert window.total_orig_bytes() == 30


def test_window_volume_ignores_responder_traffic():
    """A heavy-response flow contributes only its originator counters."""
    window = ActivityWindow(60.0)
    window.observe(
        FlowObservation.from_flow(
            make_flow(orig_pkts=2, resp_pkts=500, orig_bytes=200, resp_bytes=900_000)
        )
    )

    assert window.total_orig_packets() == 2
    assert window.total_orig_bytes() == 200


def test_duration_is_zero_for_a_single_observation():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0))
    assert window.duration() == 0.0


def test_duration_is_zero_for_simultaneous_observations():
    window = ActivityWindow(60.0)
    for _ in range(5):
        window.observe(obs(100.0))
    assert window.duration() == 0.0


def test_duration_is_zero_on_an_empty_window():
    assert ActivityWindow(60.0).duration() == 0.0


def test_timestamps_are_returned_in_arrival_order():
    window = ActivityWindow(60.0)
    for ts in (100.0, 110.0, 130.0):
        window.observe(obs(ts))

    assert window.timestamps() == [100.0, 110.0, 130.0]


def test_timestamps_respect_expiry():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0))
    window.observe(obs(200.0))

    assert window.timestamps() == [200.0]


def test_timestamps_on_an_empty_window():
    assert ActivityWindow(60.0).timestamps() == []


def test_index_accepts_a_composite_tuple_key():
    """Beacon state keys on (src, dst, port, proto) - and a None port."""
    index = WindowIndex(60.0)
    ported = ("10.0.0.1", "10.0.0.2", 443, "tcp")
    portless = ("10.0.0.1", "10.0.0.2", None, "tcp")

    index.observe(ported, obs(100.0))
    index.observe(portless, obs(101.0))

    assert len(index) == 2
    assert index.get(ported).attempts == 1
    assert index.get(portless).attempts == 1


def test_duration_spans_the_window_contents():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0))
    window.observe(obs(130.0))
    assert window.duration() == pytest.approx(30.0)


def test_protocols():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0, proto="tcp"))
    window.observe(obs(101.0, proto="udp"))
    assert window.protocols() == {"tcp", "udp"}


def test_clear_empties_the_window():
    window = ActivityWindow(60.0)
    window.observe(obs(100.0))
    window.clear()
    assert window.is_empty()
    assert len(window) == 0


# --------------------------------------------------------------------------
# WindowIndex
# --------------------------------------------------------------------------


def test_index_isolates_sources():
    index = WindowIndex(60.0)
    index.observe("10.0.0.1", obs(100.0, "10.1.1.1", 22))
    index.observe("10.0.0.2", obs(100.0, "10.2.2.2", 80))

    assert index.get("10.0.0.1").dst_ports() == {22}
    assert index.get("10.0.0.2").dst_ports() == {80}
    assert len(index) == 2


def test_index_returns_the_touched_window():
    index = WindowIndex(60.0)
    window = index.observe("10.0.0.1", obs(100.0))
    assert window is index.get("10.0.0.1")


def test_index_get_unknown_source():
    assert WindowIndex(60.0).get("10.0.0.99") is None


def test_index_clear():
    index = WindowIndex(60.0)
    index.observe("10.0.0.1", obs(100.0))
    index.clear()
    assert len(index) == 0
    assert "10.0.0.1" not in index


def test_index_sweeps_out_silent_sources():
    """Memory stays bounded when many sources appear once and go quiet."""
    index = WindowIndex(60.0, sweep_every=1)
    index.observe("10.0.0.1", obs(100.0))
    index.observe("10.0.0.2", obs(101.0))
    assert len(index) == 2

    # A much later observation triggers a sweep; both earlier sources have
    # aged out of their windows and should be dropped entirely.
    index.observe("10.9.9.9", obs(100000.0))
    assert len(index) == 1
    assert "10.9.9.9" in index


def test_index_keeps_sources_that_are_still_active():
    index = WindowIndex(60.0, sweep_every=1)
    index.observe("10.0.0.1", obs(100.0))
    index.observe("10.0.0.2", obs(110.0))
    assert len(index) == 2


def test_index_rejects_non_positive_window():
    with pytest.raises(ValueError):
        WindowIndex(-1)
