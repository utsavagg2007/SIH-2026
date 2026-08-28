"""Rolling per-source window tests."""

from __future__ import annotations

import pytest

from detection_core.aggregators import (
    FlowObservation,
    SourceActivityWindow,
    SourceWindowIndex,
)

from .conftest import make_flow


def obs(ts: float, dst_ip: str = "10.0.0.9", port: int | None = 80, proto: str = "tcp"):
    return FlowObservation(timestamp=ts, dst_ip=dst_ip, dst_port=port, proto=proto)


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


def test_observation_from_flow_without_port():
    observation = FlowObservation.from_flow(make_flow(dst_port=None))
    assert observation.dst_port is None


# --------------------------------------------------------------------------
# SourceActivityWindow
# --------------------------------------------------------------------------


def test_window_rejects_non_positive_span():
    with pytest.raises(ValueError):
        SourceActivityWindow(0)


def test_window_counts_distinct_values_only():
    window = SourceActivityWindow(60.0)
    for _ in range(5):
        window.observe(obs(100.0, dst_ip="10.0.0.9", port=80))

    assert window.attempts == 5
    assert window.dst_ports() == {80}
    assert window.dst_ips() == {"10.0.0.9"}


def test_window_tracks_multiple_ports_and_hosts():
    window = SourceActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", 22))
    window.observe(obs(101.0, "10.0.0.2", 80))
    window.observe(obs(102.0, "10.0.0.3", 443))

    assert window.dst_ports() == {22, 80, 443}
    assert window.dst_ips() == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert window.attempts == 3


def test_missing_port_is_not_counted_as_a_port():
    window = SourceActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", None))
    window.observe(obs(101.0, "10.0.0.2", None))

    assert window.dst_ports() == set()
    assert window.dst_ips() == {"10.0.0.1", "10.0.0.2"}


def test_expiry_drops_old_observations():
    window = SourceActivityWindow(60.0)
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
    window = SourceActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", 22))
    window.observe(obs(160.0, "10.0.0.2", 80))
    assert window.dst_ports() == {80}


def test_expire_can_be_called_without_a_new_observation():
    window = SourceActivityWindow(60.0)
    window.observe(obs(100.0))
    window.expire(1000.0)
    assert window.is_empty()


def test_time_span():
    window = SourceActivityWindow(60.0)
    assert window.time_span() is None
    window.observe(obs(100.0))
    window.observe(obs(130.0))
    assert window.time_span() == (100.0, 130.0)


def test_hosts_by_port_groups_fanout():
    window = SourceActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", 22))
    window.observe(obs(101.0, "10.0.0.2", 22))
    window.observe(obs(102.0, "10.0.0.3", 80))

    assert window.hosts_by_port() == {22: {"10.0.0.1", "10.0.0.2"}, 80: {"10.0.0.3"}}


def test_hosts_by_port_deduplicates_repeat_visits():
    window = SourceActivityWindow(60.0)
    for _ in range(10):
        window.observe(obs(100.0, "10.0.0.1", 22))

    assert window.hosts_by_port() == {22: {"10.0.0.1"}}


def test_hosts_by_port_excludes_portless_observations():
    window = SourceActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", None))
    window.observe(obs(101.0, "10.0.0.2", None))
    window.observe(obs(102.0, "10.0.0.3", 22))

    assert window.hosts_by_port() == {22: {"10.0.0.3"}}


def test_hosts_by_port_respects_expiry():
    window = SourceActivityWindow(60.0)
    window.observe(obs(100.0, "10.0.0.1", 22))
    window.observe(obs(200.0, "10.0.0.2", 22))

    assert window.hosts_by_port() == {22: {"10.0.0.2"}}


def test_hosts_by_port_empty_window():
    assert SourceActivityWindow(60.0).hosts_by_port() == {}


def test_protocols():
    window = SourceActivityWindow(60.0)
    window.observe(obs(100.0, proto="tcp"))
    window.observe(obs(101.0, proto="udp"))
    assert window.protocols() == {"tcp", "udp"}


def test_clear_empties_the_window():
    window = SourceActivityWindow(60.0)
    window.observe(obs(100.0))
    window.clear()
    assert window.is_empty()
    assert len(window) == 0


# --------------------------------------------------------------------------
# SourceWindowIndex
# --------------------------------------------------------------------------


def test_index_isolates_sources():
    index = SourceWindowIndex(60.0)
    index.observe("10.0.0.1", obs(100.0, "10.1.1.1", 22))
    index.observe("10.0.0.2", obs(100.0, "10.2.2.2", 80))

    assert index.get("10.0.0.1").dst_ports() == {22}
    assert index.get("10.0.0.2").dst_ports() == {80}
    assert len(index) == 2


def test_index_returns_the_touched_window():
    index = SourceWindowIndex(60.0)
    window = index.observe("10.0.0.1", obs(100.0))
    assert window is index.get("10.0.0.1")


def test_index_get_unknown_source():
    assert SourceWindowIndex(60.0).get("10.0.0.99") is None


def test_index_clear():
    index = SourceWindowIndex(60.0)
    index.observe("10.0.0.1", obs(100.0))
    index.clear()
    assert len(index) == 0
    assert "10.0.0.1" not in index


def test_index_sweeps_out_silent_sources():
    """Memory stays bounded when many sources appear once and go quiet."""
    index = SourceWindowIndex(60.0, sweep_every=1)
    index.observe("10.0.0.1", obs(100.0))
    index.observe("10.0.0.2", obs(101.0))
    assert len(index) == 2

    # A much later observation triggers a sweep; both earlier sources have
    # aged out of their windows and should be dropped entirely.
    index.observe("10.9.9.9", obs(100000.0))
    assert len(index) == 1
    assert "10.9.9.9" in index


def test_index_keeps_sources_that_are_still_active():
    index = SourceWindowIndex(60.0, sweep_every=1)
    index.observe("10.0.0.1", obs(100.0))
    index.observe("10.0.0.2", obs(110.0))
    assert len(index) == 2


def test_index_rejects_non_positive_window():
    with pytest.raises(ValueError):
        SourceWindowIndex(-1)
