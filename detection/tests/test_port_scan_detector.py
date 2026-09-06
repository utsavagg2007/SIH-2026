"""PortScanDetector tests.

Numbered comments map to the acceptance list: normal traffic, vertical,
horizontal, combined, expiry, source isolation, cooldown, reset, missing
port, alert conformance, score range, and engine integration.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from detection_core import (
    DetectionEngine,
    EventScope,
    PortScanConfig,
    PortScanDetector,
    ScoreType,
    Severity,
    ThreatAlert,
    ThreatClass,
)

from .conftest import DummyDetector, make_flow

SCANNER = "10.0.0.66"
VICTIM = "10.0.0.80"


@pytest.fixture
def config() -> PortScanConfig:
    """Small thresholds so tests stay short and readable."""
    return PortScanConfig(
        window_seconds=60.0,
        min_unique_ports=5,
        min_unique_hosts=4,
        cooldown_seconds=300.0,
    )


@pytest.fixture
def detector(config) -> PortScanDetector:
    return PortScanDetector(config)


@pytest.fixture
def combined_config() -> PortScanConfig:
    """Equal thresholds, so both signals can cross on the same flow."""
    return PortScanConfig(
        window_seconds=60.0,
        min_unique_ports=5,
        min_unique_hosts=5,
        cooldown_seconds=300.0,
    )


@pytest.fixture
def escalating_config() -> PortScanConfig:
    """No cooldown, so every qualifying flow re-scores as the scan widens."""
    return PortScanConfig(
        window_seconds=60.0,
        min_unique_ports=5,
        min_unique_hosts=99,
        cooldown_seconds=0.0,
    )


def scan_flow(
    *,
    src: str = SCANNER,
    dst: str = VICTIM,
    port: int | None = 80,
    ts: float = 1000.0,
    proto: str = "tcp",
    resp_bytes: int = 0,
    resp_pkts: int = 0,
    conn_state: str | None = None,
):
    """A probe: the target does not answer with a payload.

    ``resp_bytes`` defaults to 0 rather than inheriting ``make_flow``'s 200,
    because a scanned port returning 200 bytes of payload is not a scanned
    port - it is a served request. Every test below is about scan *shape*, so
    the shared helper's browsing-shaped default was quietly describing the
    wrong traffic. The detector's responder-engagement check reads exactly
    this, so it is now stated rather than assumed.
    """
    return make_flow(
        src_ip=src,
        dst_ip=dst,
        dst_port=port,
        timestamp=ts,
        proto=proto,
        resp_bytes=resp_bytes,
        resp_pkts=resp_pkts,
        conn_state=conn_state,
    )


def feed(detector, flows):
    """Push flows through and return every alert emitted."""
    alerts = []
    for flow in flows:
        alerts.extend(detector.process(flow))
    return alerts


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------


def test_documented_defaults():
    config = PortScanConfig()
    assert config.window_seconds == 60.0
    assert config.min_unique_ports == 15
    assert config.min_unique_hosts == 20
    assert config.cooldown_seconds == 300.0
    assert config.max_service_port == 49151
    assert config.min_service_ports == 3
    assert config.established_resp_bytes == 100
    assert config.max_established_fraction == 0.20
    assert config.min_incomplete_fraction == 0.05
    assert config.min_conn_state_coverage == 0.50


def test_detector_uses_defaults_when_unconfigured():
    assert PortScanDetector().config == PortScanConfig()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"window_seconds": 0},
        {"window_seconds": -1},
        {"min_unique_ports": 0},
        {"min_unique_hosts": 0},
        {"cooldown_seconds": -1},
        {"saturation_multiple": 1.0},
        {"combined_bonus": 1.5},
        {"max_service_port": -1},
        {"max_service_port": 70000},
        {"min_service_ports": -1},
        {"established_resp_bytes": -1},
        {"max_established_fraction": 1.5},
        {"max_established_fraction": -0.1},
        {"min_incomplete_fraction": 1.5},
        {"min_conn_state_coverage": 1.5},
    ],
)
def test_invalid_config_rejected(kwargs):
    with pytest.raises(ValueError):
        PortScanConfig(**kwargs)


def test_detector_identity():
    detector = PortScanDetector()
    assert detector.name == "port_scan"
    assert detector.version == "0.3.1"


# --------------------------------------------------------------------------
# 1. Normal traffic -> no alert
# --------------------------------------------------------------------------


def test_normal_traffic_produces_no_alert(detector):
    flows = [
        scan_flow(dst="10.0.0.80", port=443, ts=1000.0),
        scan_flow(dst="10.0.0.80", port=443, ts=1001.0),
        scan_flow(dst="10.0.0.81", port=80, ts=1002.0),
    ]
    assert feed(detector, flows) == []


def test_just_below_thresholds_stays_quiet(detector):
    """4 ports across 3 hosts: under both a 5-port and a 4-host threshold."""
    flows = [
        scan_flow(dst="10.0.0.80", port=22, ts=1000.0),
        scan_flow(dst="10.0.0.80", port=80, ts=1001.0),
        scan_flow(dst="10.0.0.81", port=443, ts=1002.0),
        scan_flow(dst="10.0.0.82", port=8080, ts=1003.0),
    ]
    assert feed(detector, flows) == []


# --------------------------------------------------------------------------
# 2. Many ports quickly -> vertical scan
# --------------------------------------------------------------------------


def test_vertical_scan_detected(detector):
    ports = [22, 23, 25, 80, 443]
    alerts = feed(
        detector,
        [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate(ports)],
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.threat_class is ThreatClass.PORT_SCAN
    assert alert.evidence["scan_type"] == "vertical"
    assert alert.evidence["unique_dst_ports"] == 5
    assert alert.evidence["unique_dst_ips"] == 1
    assert alert.evidence["connection_attempts"] == 5


def test_vertical_scan_alert_names_the_single_target(detector):
    """One host, many ports: dst_ip is known, dst_port is not."""
    alert = feed(
        detector,
        [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate([22, 23, 25, 80, 443])],
    )[0]

    assert alert.dst_ip == VICTIM
    assert alert.dst_port is None
    assert alert.protocol == "tcp"


def test_alert_fires_on_the_exact_flow_that_crosses_the_threshold(detector):
    """3. Near-real-time: no waiting for more traffic."""
    ports = [22, 23, 25, 80, 443]
    emitted = [len(detector.process(scan_flow(port=p, ts=1000.0 + i)))
               for i, p in enumerate(ports)]
    assert emitted == [0, 0, 0, 0, 1]


# --------------------------------------------------------------------------
# 3. Same port repeatedly -> no vertical scan
# --------------------------------------------------------------------------


def test_repeated_same_port_is_not_a_vertical_scan(detector):
    flows = [scan_flow(port=443, ts=1000.0 + i) for i in range(50)]
    assert feed(detector, flows) == []


def test_repeated_same_host_is_not_a_horizontal_scan(detector):
    flows = [scan_flow(dst="10.0.0.80", port=443, ts=1000.0 + i) for i in range(50)]
    assert feed(detector, flows) == []


# --------------------------------------------------------------------------
# 4. Many hosts quickly -> horizontal scan
# --------------------------------------------------------------------------


def test_horizontal_scan_detected(detector):
    """1. Many hosts on the SAME port is a subnet sweep."""
    hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    alerts = feed(
        detector,
        [scan_flow(dst=h, port=445, ts=1000.0 + i) for i, h in enumerate(hosts)],
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.evidence["scan_type"] == "horizontal"
    assert alert.evidence["unique_dst_ips"] == 4
    assert alert.evidence["unique_dst_ports"] == 1


def test_horizontal_scan_alert_names_the_single_port(detector):
    """Many hosts, one port: dst_port is known, dst_ip is not."""
    hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    alert = feed(
        detector,
        [scan_flow(dst=h, port=445, ts=1000.0 + i) for i, h in enumerate(hosts)],
    )[0]

    assert alert.dst_port == 445
    assert alert.dst_ip is None


def test_horizontal_evidence_names_the_scanned_port(detector):
    """5. Evidence must say which port was swept."""
    hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    alert = feed(
        detector,
        [scan_flow(dst=h, port=22, ts=1000.0 + i) for i, h in enumerate(hosts)],
    )[0]

    assert alert.evidence["horizontal_dst_port"] == 22
    assert alert.evidence["max_hosts_per_port"] == 4


def test_many_hosts_across_unrelated_ports_is_not_horizontal():
    """2. The CDN-browsing false positive this change exists to kill.

    20 distinct hosts, but every one on a different port, so no single port
    ever fans out. min_unique_hosts=4 must NOT fire on the total host count.
    """
    detector = PortScanDetector(
        PortScanConfig(min_unique_ports=999, min_unique_hosts=4, window_seconds=60.0)
    )
    flows = [
        scan_flow(dst=f"10.0.{i}.{i}", port=10000 + i, ts=1000.0 + i) for i in range(20)
    ]
    assert feed(detector, flows) == []


def test_fanout_split_across_two_ports_stays_below_threshold(detector):
    """3. Two ports at 3 hosts each is not one port at 6 hosts."""
    flows = []
    for i in range(3):
        flows.append(scan_flow(dst=f"10.0.0.{i}", port=22, ts=1000.0 + i))
        flows.append(scan_flow(dst=f"10.0.1.{i}", port=80, ts=1010.0 + i))

    assert feed(detector, flows) == []


def test_one_port_reaching_the_threshold_alerts(detector):
    """4. Port 80 stays under; port 22 crosses and fires."""
    flows = [
        scan_flow(dst="10.0.1.0", port=80, ts=1000.0),
        scan_flow(dst="10.0.1.1", port=80, ts=1001.0),
        scan_flow(dst="10.0.0.0", port=22, ts=1002.0),
        scan_flow(dst="10.0.0.1", port=22, ts=1003.0),
        scan_flow(dst="10.0.0.2", port=22, ts=1004.0),
        scan_flow(dst="10.0.0.3", port=22, ts=1005.0),
    ]
    alerts = feed(detector, flows)

    assert len(alerts) == 1
    assert alerts[0].evidence["scan_type"] == "horizontal"
    assert alerts[0].evidence["horizontal_dst_port"] == 22


def test_horizontal_fanout_expires_with_the_window(detector):
    """7. Hosts that age out stop counting toward the fan-out."""
    for i in range(3):
        assert detector.process(scan_flow(dst=f"10.0.0.{i}", port=22, ts=1000.0 + i)) == []

    # Far outside the 60s window: the earlier three hosts are gone.
    assert detector.process(scan_flow(dst="10.0.0.9", port=22, ts=5000.0)) == []
    assert detector._windows.get(SCANNER).hosts_by_port() == {22: {"10.0.0.9"}}


def test_horizontal_fanout_is_isolated_per_source(detector):
    """8. Two sources sweeping :22 must not pool their fan-out."""
    flows = []
    for i in range(3):
        flows.append(scan_flow(src="10.0.0.1", dst=f"10.9.0.{i}", port=22, ts=1000.0 + i))
        flows.append(scan_flow(src="10.0.0.2", dst=f"10.9.1.{i}", port=22, ts=1000.0 + i))

    assert feed(detector, flows) == []


def test_vertical_still_uses_total_distinct_ports(detector):
    """Vertical detection is unchanged by the horizontal rework."""
    alerts = feed(
        detector,
        [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate([22, 23, 25, 80, 443])],
    )
    assert len(alerts) == 1
    assert alerts[0].evidence["scan_type"] == "vertical"
    assert alerts[0].evidence["horizontal_dst_port"] is None


# --------------------------------------------------------------------------
# 5. Both thresholds -> combined
# --------------------------------------------------------------------------


def combined_flows() -> list:
    """Sweep :22 across 5 hosts, then 4 more ports on one of them.

    Reaches the horizontal threshold first, then the vertical one, so the
    final flow satisfies both at once.
    """
    flows = [scan_flow(dst=f"10.0.0.{i}", port=22, ts=1000.0 + i) for i in range(5)]
    flows += [
        scan_flow(dst="10.0.0.0", port=port, ts=1010.0 + i)
        for i, port in enumerate([23, 24, 25, 26])
    ]
    return flows


def test_combined_scan_detected(combined_config):
    """9. Both conditions satisfied at once."""
    detector = PortScanDetector(combined_config)
    alerts = feed(detector, combined_flows())

    alert = alerts[-1]
    assert alert.evidence["scan_type"] == "combined"
    assert alert.evidence["unique_dst_ports"] == 5
    assert alert.evidence["unique_dst_ips"] == 5
    assert alert.evidence["horizontal_dst_port"] == 22
    # Many hosts and many ports: neither can be named without inventing one.
    assert alert.dst_ip is None
    assert alert.dst_port is None


def test_combined_scores_higher_than_a_single_signal(combined_config):
    """The combined bonus must actually raise the score."""
    vertical_only = feed(
        PortScanDetector(combined_config),
        [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate([22, 23, 25, 80, 443])],
    )[0]
    combined = feed(PortScanDetector(combined_config), combined_flows())[-1]

    assert vertical_only.evidence["scan_type"] == "vertical"
    assert combined.evidence["scan_type"] == "combined"
    assert combined.score > vertical_only.score


def test_one_host_per_port_is_vertical_not_horizontal(config):
    """5 hosts and 5 ports, but one host per port: only vertical fires."""
    detector = PortScanDetector(config)
    alerts = feed(
        detector,
        [scan_flow(dst=f"10.0.0.{i}", port=20 + i, ts=1000.0 + i) for i in range(5)],
    )
    assert len(alerts) == 1
    assert alerts[0].evidence["scan_type"] == "vertical"
    assert alerts[0].evidence["horizontal_dst_port"] is None


# --------------------------------------------------------------------------
# 6. Expiry
# --------------------------------------------------------------------------


def test_expired_flows_leave_the_window(detector):
    """4 ports, then a 5th far outside the window: never 5 at once."""
    for i, port in enumerate([22, 23, 25, 80]):
        assert detector.process(scan_flow(port=port, ts=1000.0 + i)) == []

    assert detector.process(scan_flow(port=443, ts=5000.0)) == []
    assert detector._windows.get(SCANNER).attempts == 1


def test_scan_split_across_windows_does_not_alert(detector):
    """Slow scanning below the rate threshold is out of scope by design."""
    flows = [scan_flow(port=1000 + i, ts=1000.0 + i * 120.0) for i in range(10)]
    assert feed(detector, flows) == []


def test_window_boundary_is_respected(detector):
    for i, port in enumerate([22, 23, 25, 80]):
        detector.process(scan_flow(port=port, ts=1000.0 + i))

    # t=1060 expires the t=1000 observation, so only 4 ports are in window.
    assert detector.process(scan_flow(port=443, ts=1060.0)) == []


# --------------------------------------------------------------------------
# 7. Source isolation
# --------------------------------------------------------------------------


def test_sources_do_not_contaminate_each_other(detector):
    """Two hosts each touching 3 ports must not add up to a scan."""
    flows = []
    for i, port in enumerate([22, 23, 25]):
        flows.append(scan_flow(src="10.0.0.1", port=port, ts=1000.0 + i))
        flows.append(scan_flow(src="10.0.0.2", port=port + 100, ts=1000.0 + i))

    assert feed(detector, flows) == []


def test_only_the_scanning_source_is_alerted(detector):
    noise = [scan_flow(src="10.0.0.9", port=443, ts=1000.0 + i) for i in range(10)]
    scan = [
        scan_flow(src="10.0.0.1", port=p, ts=1000.0 + i)
        for i, p in enumerate([22, 23, 25, 80, 443])
    ]

    alerts = feed(detector, noise + scan)
    assert len(alerts) == 1
    assert alerts[0].src_ip == "10.0.0.1"


# --------------------------------------------------------------------------
# 8 & 9. Cooldown
# --------------------------------------------------------------------------


def test_cooldown_suppresses_alert_spam(detector):
    """Scanning hard for a long time must not alert on every single flow.

    60 qualifying flows collapse to one alert per severity band crossed
    (LOW -> MEDIUM -> HIGH -> CRITICAL), not 56 alerts.
    """
    flows = [scan_flow(port=1000 + i, ts=1000.0 + i) for i in range(60)]
    alerts = feed(detector, flows)

    assert len(alerts) == 4
    assert [a.severity for a in alerts] == [
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]


# With min_unique_ports=5 and saturation_multiple=4.0, the score is
# 0.5 + 0.5 * (ports/5 - 1) / 3, so each band starts at these port counts.
# 17 lands exactly on the 0.90 cutoff, which score rounding makes
# deterministic - it used to compute 0.8999... and classify one band low.
_PORTS_FOR_BAND = {
    Severity.LOW: 5,
    Severity.MEDIUM: 8,
    Severity.HIGH: 13,
    Severity.CRITICAL: 17,
}


def vertical_flows(port_count: int, start_ts: float = 1000.0) -> list:
    """`port_count` distinct ports on one host, one second apart."""
    return [
        scan_flow(port=1000 + i, ts=start_ts + i * 0.1) for i in range(port_count)
    ]


def test_first_threshold_crossing_alerts_immediately(detector):
    """10."""
    alerts = feed(detector, vertical_flows(_PORTS_FOR_BAND[Severity.LOW]))
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.LOW


def test_same_severity_during_cooldown_is_suppressed(detector):
    """11 and 13. A rising score inside one band is not news."""
    alerts = feed(detector, vertical_flows(7))  # 5 -> LOW, 6 and 7 still LOW
    assert len(alerts) == 1

    # More MEDIUM-band flows after a MEDIUM alert stay quiet too.
    more = feed(detector, [scan_flow(port=2000 + i, ts=1010.0 + i * 0.1) for i in range(3)])
    assert [a.severity for a in more] == [Severity.MEDIUM]


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        (Severity.LOW, Severity.MEDIUM),
        (Severity.MEDIUM, Severity.HIGH),
        (Severity.HIGH, Severity.CRITICAL),
    ],
)
def test_rising_severity_escapes_cooldown(detector, lower, higher):
    """12, 14 and 15."""
    alerts = feed(detector, vertical_flows(_PORTS_FOR_BAND[higher]))
    severities = [a.severity for a in alerts]

    assert lower in severities
    assert higher in severities
    assert severities.index(higher) > severities.index(lower)
    # Every alert is a strict escalation on the one before it.
    assert severities == sorted(set(severities), key=severities.index)


def test_escalation_alerts_are_strictly_increasing(detector):
    alerts = feed(detector, vertical_flows(40))
    ranks = [
        [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL].index(a.severity)
        for a in alerts
    ]
    assert ranks == sorted(ranks)
    assert len(ranks) == len(set(ranks))


def test_no_escalation_for_a_score_bump_inside_one_band(detector):
    """A higher score alone is not enough - the band must change."""
    first = feed(detector, vertical_flows(5))
    assert len(first) == 1
    assert first[0].severity is Severity.LOW

    # 6 and 7 ports score higher than 5 but are still LOW.
    more = feed(detector, [scan_flow(port=1005 + i, ts=1001.0 + i * 0.1) for i in range(2)])
    assert more == []


def test_cooldown_expiry_permits_a_normal_alert_again(config):
    """16."""
    detector = PortScanDetector(config)
    first = feed(detector, vertical_flows(5))
    assert len(first) == 1

    later = 1000.0 + config.cooldown_seconds + 10.0
    second = feed(detector, vertical_flows(5, start_ts=later))

    assert len(second) == 1
    assert second[0].severity is Severity.LOW  # same band, but cooldown expired


def test_reset_clears_escalation_state(detector):
    """17."""
    feed(detector, vertical_flows(_PORTS_FOR_BAND[Severity.HIGH]))
    assert detector._state[SCANNER].last_severity is Severity.HIGH

    detector.reset()

    assert detector._state == {}
    # A fresh LOW scan alerts again, which a surviving HIGH would have blocked.
    alerts = feed(detector, vertical_flows(5, start_ts=1100.0))
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.LOW


def test_escalation_is_per_source(config):
    """One source escalating must not silence another's first alert."""
    detector = PortScanDetector(config)
    feed(
        detector,
        [scan_flow(src="10.0.0.1", port=1000 + i, ts=1000.0 + i * 0.1) for i in range(20)],
    )
    alerts = feed(
        detector,
        [scan_flow(src="10.0.0.2", port=1000 + i, ts=1002.0 + i * 0.1) for i in range(5)],
    )

    assert len(alerts) == 1
    assert alerts[0].src_ip == "10.0.0.2"
    assert alerts[0].severity is Severity.LOW


def test_alert_repeats_after_cooldown_expires(config):
    detector = PortScanDetector(config)
    first = feed(
        detector,
        [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate([22, 23, 25, 80, 443])],
    )
    assert len(first) == 1

    # Same source scanning again, well past cooldown_seconds=300.
    later = 1000.0 + config.cooldown_seconds + 10.0
    second = feed(
        detector,
        [scan_flow(port=p, ts=later + i) for i, p in enumerate([22, 23, 25, 80, 443])],
    )
    assert len(second) == 1
    assert second[0].alert_id != first[0].alert_id


def test_cooldown_is_per_source(config):
    detector = PortScanDetector(config)
    ports = [22, 23, 25, 80, 443]

    first = feed(
        detector, [scan_flow(src="10.0.0.1", port=p, ts=1000.0 + i) for i, p in enumerate(ports)]
    )
    second = feed(
        detector, [scan_flow(src="10.0.0.2", port=p, ts=1005.0 + i) for i, p in enumerate(ports)]
    )

    assert len(first) == 1 and len(second) == 1
    assert {first[0].src_ip, second[0].src_ip} == {"10.0.0.1", "10.0.0.2"}


def test_zero_cooldown_alerts_every_qualifying_flow():
    detector = PortScanDetector(
        PortScanConfig(min_unique_ports=5, min_unique_hosts=99, cooldown_seconds=0.0)
    )
    flows = [scan_flow(port=1000 + i, ts=1000.0 + i) for i in range(8)]
    # First 4 flows are below threshold; the remaining 4 each alert.
    assert len(feed(detector, flows)) == 4


# --------------------------------------------------------------------------
# 10. reset
# --------------------------------------------------------------------------


def test_reset_clears_all_state(detector):
    feed(
        detector,
        [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate([22, 23, 25, 80, 443])],
    )
    assert len(detector._windows) == 1

    detector.reset()

    assert len(detector._windows) == 0
    assert detector._state == {}


def test_reset_clears_cooldown_too(detector):
    ports = [22, 23, 25, 80, 443]
    feed(detector, [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate(ports)])
    detector.reset()

    # Immediately rescanning would be suppressed if cooldown had survived.
    alerts = feed(detector, [scan_flow(port=p, ts=1010.0 + i) for i, p in enumerate(ports)])
    assert len(alerts) == 1


# --------------------------------------------------------------------------
# 11. Missing dst_port
# --------------------------------------------------------------------------


def test_missing_dst_port_never_counts_as_a_port(detector):
    flows = [scan_flow(port=None, ts=1000.0 + i) for i in range(20)]
    assert feed(detector, flows) == []


def test_missing_dst_port_does_not_feed_horizontal_fanout(detector):
    """6. With no port there is nothing to correlate across hosts."""
    hosts = [f"10.0.0.{i}" for i in range(20)]
    alerts = feed(
        detector,
        [scan_flow(dst=h, port=None, ts=1000.0 + i) for i, h in enumerate(hosts)],
    )
    assert alerts == []


def test_portless_flows_do_not_dilute_a_real_sweep(detector):
    """Portless noise alongside a genuine :22 sweep must not hide it."""
    flows = [
        scan_flow(dst="10.9.9.9", port=None, ts=1000.0),
        scan_flow(dst="10.0.0.1", port=22, ts=1001.0),
        scan_flow(dst="10.9.9.8", port=None, ts=1002.0),
        scan_flow(dst="10.0.0.2", port=22, ts=1003.0),
        scan_flow(dst="10.0.0.3", port=22, ts=1004.0),
        scan_flow(dst="10.0.0.4", port=22, ts=1005.0),
    ]
    alerts = feed(detector, flows)

    assert len(alerts) == 1
    assert alerts[0].evidence["scan_type"] == "horizontal"
    assert alerts[0].evidence["horizontal_dst_port"] == 22
    assert alerts[0].evidence["max_hosts_per_port"] == 4
    # unique_dst_ips still counts the portless hosts - it is an observation,
    # not the threshold input.
    assert alerts[0].evidence["unique_dst_ips"] == 6


def test_mixed_present_and_missing_ports(detector):
    flows = [
        scan_flow(port=None, ts=1000.0),
        scan_flow(port=22, ts=1001.0),
        scan_flow(port=23, ts=1002.0),
        scan_flow(port=None, ts=1003.0),
        scan_flow(port=25, ts=1004.0),
        scan_flow(port=80, ts=1005.0),
        scan_flow(port=443, ts=1006.0),
    ]
    alerts = feed(detector, flows)
    assert len(alerts) == 1
    assert alerts[0].evidence["unique_dst_ports"] == 5


# --------------------------------------------------------------------------
# 12 & 13. Alert conformance and score range
# --------------------------------------------------------------------------


@pytest.fixture
def sample_alert(detector) -> ThreatAlert:
    return feed(
        detector,
        [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate([22, 23, 25, 80, 443])],
    )[0]


def test_alert_conforms_to_v1_1(sample_alert):
    assert isinstance(sample_alert, ThreatAlert)
    assert sample_alert.schema_version == "1.1"
    assert sample_alert.threat_class is ThreatClass.PORT_SCAN
    assert sample_alert.event_scope is EventScope.SOURCE_HOST
    assert sample_alert.score_type is ScoreType.RULE_SCORE
    assert sample_alert.flow_id is None
    assert sample_alert.src_ip == SCANNER
    assert sample_alert.detector == "port_scan"
    assert sample_alert.detector_version == "0.3.1"
    assert sample_alert.mitre_techniques == ["T1046"]
    assert sample_alert.incident_id is None


def test_alert_serializes_to_the_wire_contract(sample_alert):
    wire = sample_alert.to_wire()
    assert set(wire) == {
        "alert_id", "schema_version", "event_start", "event_end", "detected_at",
        "event_scope", "flow_id", "src_ip", "dst_ip", "dst_port", "protocol",
        "threat_class", "severity", "score", "score_type", "evidence",
        "detector", "detector_version", "mitre_techniques", "incident_id",
    }
    assert wire["event_start"].endswith("Z")
    assert wire["threat_class"] == "port_scan"
    assert wire["event_scope"] == "source_host"
    assert wire["score_type"] == "rule_score"


def test_alert_window_covers_the_observed_flows(sample_alert):
    assert sample_alert.event_start < sample_alert.event_end
    assert sample_alert.event_start.timestamp() == pytest.approx(1000.0)
    assert sample_alert.event_end.timestamp() == pytest.approx(1004.0)


def test_evidence_contains_required_keys(sample_alert):
    for key in (
        "unique_dst_ports",
        "unique_dst_ips",
        "connection_attempts",
        "window_seconds",
        "scan_type",
    ):
        assert key in sample_alert.evidence


def test_evidence_never_invents_placeholder_targets(detector):
    alert = feed(
        detector,
        [scan_flow(dst=f"10.0.0.{i}", port=20 + i, ts=1000.0 + i) for i in range(5)],
    )[0]
    assert alert.dst_ip is None
    assert alert.dst_port is None
    assert "multiple" not in str(alert.to_wire())


@pytest.mark.parametrize("port_count", [5, 6, 10, 25, 60, 200])
def test_score_stays_within_range(port_count):
    detector = PortScanDetector(
        PortScanConfig(min_unique_ports=5, min_unique_hosts=4, cooldown_seconds=0.0)
    )
    alerts = feed(
        detector,
        [scan_flow(port=1000 + i, ts=1000.0 + i) for i in range(port_count)],
    )
    assert alerts
    for alert in alerts:
        assert 0.0 <= alert.score <= 1.0


def test_score_at_the_threshold_is_one_half(config):
    """Exactly at the threshold scores 0.5, by documented construction."""
    detector = PortScanDetector(config)
    alert = feed(
        detector,
        [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate([22, 23, 25, 80, 443])],
    )[0]
    assert alert.score == pytest.approx(0.5)


def test_score_rises_with_scan_breadth(escalating_config):
    """As the same scan widens, each fresh alert scores higher."""

    def last_score(port_count: int) -> float:
        detector = PortScanDetector(escalating_config)
        return feed(
            detector,
            [scan_flow(port=1000 + i, ts=1000.0 + i) for i in range(port_count)],
        )[-1].score

    assert last_score(5) == pytest.approx(0.5)
    assert last_score(10) > last_score(5)
    assert last_score(15) > last_score(10)


def test_score_saturates_at_one(escalating_config):
    detector = PortScanDetector(escalating_config)
    alert = feed(
        detector,
        [scan_flow(port=1000 + i, ts=1000.0 + i) for i in range(50)],
    )[-1]
    assert alert.score == 1.0
    assert alert.severity is Severity.CRITICAL


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.50, Severity.LOW),
        (0.59, Severity.LOW),
        (0.60, Severity.MEDIUM),
        (0.74, Severity.MEDIUM),
        (0.75, Severity.HIGH),
        (0.89, Severity.HIGH),
        (0.90, Severity.CRITICAL),
        (1.00, Severity.CRITICAL),
    ],
)
def test_severity_mapping_is_deterministic(score, expected):
    assert PortScanDetector._severity(score) is expected


# --------------------------------------------------------------------------
# Severity boundary regressions (binary float noise)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("boundary", "expected"),
    [(0.60, Severity.MEDIUM), (0.75, Severity.HIGH), (0.90, Severity.CRITICAL)],
)
def test_exact_boundary_scores_classify_upward(boundary, expected):
    """A score exactly on a documented cutoff belongs to the higher band."""
    assert PortScanDetector._severity(boundary) is expected


@pytest.mark.parametrize(
    ("drifted", "expected"),
    [
        (0.5999999999999999, Severity.MEDIUM),
        (0.7499999999999999, Severity.HIGH),
        (0.8999999999999999, Severity.CRITICAL),
    ],
)
def test_float_drift_below_a_boundary_still_classifies_upward(drifted, expected):
    """The actual bug: 17 ports over a threshold of 5 computes 0.8999...

    Mathematically that is exactly 0.90, so it must be CRITICAL, not HIGH.
    """
    assert PortScanDetector._severity(drifted) is expected


@pytest.mark.parametrize(
    ("below", "expected"),
    [
        (0.5999, Severity.LOW),
        (0.7499, Severity.MEDIUM),
        (0.8999, Severity.HIGH),
    ],
)
def test_genuinely_below_a_boundary_stays_in_the_lower_band(below, expected):
    """Rounding must not drag real sub-threshold scores up a band."""
    assert PortScanDetector._severity(below) is expected


@pytest.mark.parametrize(
    ("min_ports", "port_count", "expected_score", "expected_severity"),
    [
        (5, 8, 0.60, Severity.MEDIUM),
        (4, 10, 0.75, Severity.HIGH),
        (5, 17, 0.90, Severity.CRITICAL),
    ],
)
def test_boundary_scores_end_to_end(min_ports, port_count, expected_score, expected_severity):
    """Scans landing exactly on each cutoff, through the real detector."""
    detector = PortScanDetector(
        PortScanConfig(
            min_unique_ports=min_ports, min_unique_hosts=999, cooldown_seconds=0.0
        )
    )
    alert = feed(detector, vertical_flows(port_count))[-1]

    assert alert.score == expected_score
    assert alert.severity is expected_severity


def test_emitted_score_is_free_of_float_noise():
    """The wire value is the same rounded number the severity was derived from."""
    detector = PortScanDetector(
        PortScanConfig(min_unique_ports=5, min_unique_hosts=999, cooldown_seconds=0.0)
    )
    alert = feed(detector, vertical_flows(17))[-1]

    assert alert.score == 0.9
    assert alert.to_wire()["score"] == 0.9
    assert alert.severity is Severity.CRITICAL


def test_rounding_never_leaves_the_valid_range():
    detector = PortScanDetector(
        PortScanConfig(min_unique_ports=1, min_unique_hosts=1, cooldown_seconds=0.0)
    )
    for alert in feed(detector, vertical_flows(30)):
        assert 0.0 <= alert.score <= 1.0


def test_alerts_are_valid_even_at_extreme_counts():
    """Whatever the counts, the emitted alert must still validate."""
    detector = PortScanDetector(
        PortScanConfig(min_unique_ports=1, min_unique_hosts=1, cooldown_seconds=0.0)
    )
    alerts = feed(detector, [scan_flow(port=1, ts=1000.0)])
    assert len(alerts) == 1
    assert 0.0 <= alerts[0].score <= 1.0


# --------------------------------------------------------------------------
# 14. process() alerts without flush()
# --------------------------------------------------------------------------


def test_flush_is_not_needed_for_detection(detector):
    alerts = feed(
        detector,
        [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate([22, 23, 25, 80, 443])],
    )
    assert len(alerts) == 1
    assert detector.flush() == []


def test_flush_holds_nothing_back_below_threshold(detector):
    feed(detector, [scan_flow(port=22, ts=1000.0)])
    assert detector.flush() == []


# --------------------------------------------------------------------------
# 15. Engine integration
# --------------------------------------------------------------------------


def test_engine_runs_the_detector(config):
    engine = DetectionEngine([PortScanDetector(config)])
    flows = [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate([22, 23, 25, 80, 443])]

    alerts = list(engine.run(flows))

    assert len(alerts) == 1
    assert alerts[0].threat_class is ThreatClass.PORT_SCAN
    assert engine.stats.flows_processed == 5
    assert engine.stats.detector_errors == 0


def test_engine_runs_port_scan_alongside_other_detectors(config):
    engine = DetectionEngine([PortScanDetector(config), DummyDetector()])
    flows = [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate([22, 23, 25, 80, 443])]

    alerts = list(engine.run(flows))

    # 5 alerts from DummyDetector (one per flow) + 1 port scan alert.
    # Count by detector name: the conftest stub also uses threat_class port_scan.
    assert len(alerts) == 6
    assert sum(a.detector == "port_scan" for a in alerts) == 1
    assert sum(a.detector == "dummy" for a in alerts) == 5


def test_engine_run_isolates_replays(config):
    """run() resets the detector, so a second replay re-detects cleanly."""
    engine = DetectionEngine([PortScanDetector(config)])
    flows = [scan_flow(port=p, ts=1000.0 + i) for i, p in enumerate([22, 23, 25, 80, 443])]

    first = list(engine.run(flows))
    second = list(engine.run(flows))

    assert len(first) == 1
    assert len(second) == 1


def test_detector_never_mutates_the_flow(detector):
    flow = scan_flow(port=22, ts=1000.0)
    detector.process(flow)
    with pytest.raises(ValidationError):
        flow.dst_port = 9999


# --------------------------------------------------------------------------
# Ports a service could live on (the ephemeral-range exclusion)
# --------------------------------------------------------------------------


def _sweep(detector, ports, *, dst=VICTIM, **flow_kwargs):
    """Walk one source across `ports` on one host, one second apart."""
    return feed(
        detector,
        [
            scan_flow(dst=dst, port=port, ts=1000.0 + i, **flow_kwargs)
            for i, port in enumerate(ports)
        ],
    )


def test_a_sweep_of_service_ports_is_a_scan(detector):
    """The baseline the exclusion must not disturb."""
    assert _sweep(detector, [21, 22, 23, 25, 80, 110])


def test_a_sweep_of_ephemeral_ports_is_not_a_scan(detector):
    """One host "touching" many high ports on another is the reply side.

    IANA reserves 49152-65535 for outbound allocation, so nothing is listening
    there to enumerate. On the real benign capture this shape was 94% of the
    vertical false positives: a CDN or cloud host recorded as the initiator of
    flows back to a workstation's ephemeral ports.
    """
    assert _sweep(detector, [49200 + i for i in range(8)]) == []


def test_enough_service_ports_among_ephemeral_ones_still_scans(detector):
    """The rule needs *some* service ports, not *only* service ports."""
    ports = [22, 80, 443] + [50000 + i for i in range(5)]
    assert _sweep(detector, ports)


def test_the_service_port_boundary_is_configurable():
    detector = PortScanDetector(
        PortScanConfig(
            window_seconds=60.0,
            min_unique_ports=5,
            min_unique_hosts=99,
            max_service_port=65535,
        )
    )
    assert _sweep(detector, [49200 + i for i in range(8)])


def test_the_exclusion_does_not_touch_horizontal_scans():
    """A sweep across hosts is judged on its own port, whatever its number.

    A backdoor listening on a high port and swept across a subnet is still a
    subnet sweep; the ephemeral argument is about *enumerating* ports on one
    host, which horizontal fan-out is not doing.
    """
    detector = PortScanDetector(
        PortScanConfig(window_seconds=60.0, min_unique_ports=99, min_unique_hosts=4)
    )
    alerts = feed(
        detector,
        [
            scan_flow(dst=f"10.0.0.{i}", port=51000, ts=1000.0 + i)
            for i in range(5)
        ],
    )
    assert alerts
    assert alerts[0].evidence["scan_type"] == "horizontal"


def test_evidence_reports_the_service_port_count(detector):
    alerts = _sweep(detector, [22, 80, 443, 50001, 50002, 50003])
    evidence = alerts[0].evidence
    # The alert fires on the flow that crosses min_unique_ports (5 here), so
    # the sixth port is not in the window yet.
    assert evidence["unique_dst_ports"] == 5
    assert evidence["service_ports"] == 3
    assert evidence["max_service_port"] == 49151


# --------------------------------------------------------------------------
# Responder engagement
# --------------------------------------------------------------------------


def test_a_window_the_far_side_answered_is_not_a_scan(detector):
    """Ports that reply with real payload were serving, not being probed."""
    assert _sweep(detector, [21, 22, 23, 25, 80, 110], resp_bytes=5_000) == []


def test_a_stub_reply_does_not_count_as_an_answer(detector):
    """A refused connection is a refusal even when the exporter bills it bytes.

    CICFlowMeter reports 6 bytes for a bare RST, so "greater than zero" would
    read a wall of refusals as a wall of conversations.
    """
    assert _sweep(detector, [21, 22, 23, 25, 80, 110], resp_bytes=6)


def test_a_unidirectional_capture_still_detects_scans(detector):
    """The gate may spend reply evidence; it may never require it.

    A capture that never sees the return path has `resp_bytes == 0` on every
    flow, benign and hostile alike. That must read as "nothing to go on" and
    leave the detector exactly as it was - not as "everything is a scan", and
    not as silence.
    """
    assert _sweep(detector, [21, 22, 23, 25, 80, 110], resp_bytes=0, resp_pkts=0)


def test_the_answered_ceiling_is_configurable():
    detector = PortScanDetector(
        PortScanConfig(
            window_seconds=60.0,
            min_unique_ports=5,
            min_unique_hosts=99,
            max_established_fraction=1.0,
        )
    )
    assert _sweep(detector, [21, 22, 23, 25, 80, 110], resp_bytes=5_000)


def test_conn_state_outranks_the_byte_proxy(detector):
    """Once the real connection state arrives, it decides.

    S0 is "attempt, no reply" - a scan - and it stays a scan even if the
    exporter's byte counters suggest otherwise. This is the path that opens up
    the day ingestion stops flattening S0; see INCOMPLETE_CONN_STATES.
    """
    assert _sweep(
        detector, [21, 22, 23, 25, 80, 110], resp_bytes=5_000, conn_state="S0"
    )


def test_completed_connections_are_not_a_scan_even_with_no_bytes(detector):
    """The mirror of the previous test: SF is a completed exchange."""
    assert (
        _sweep(detector, [21, 22, 23, 25, 80, 110], resp_bytes=0, conn_state="SF")
        == []
    )


def test_partial_conn_state_coverage_falls_back_to_bytes(detector):
    """A handful of labelled records cannot speak for the window.

    Below `min_conn_state_coverage` the byte proxy decides, so a mostly
    unlabelled window of answered conversations is still suppressed.
    """
    flows = [
        scan_flow(port=20 + i, ts=1000.0 + i, resp_bytes=5_000, conn_state="S0")
        for i in range(2)
    ] + [
        scan_flow(port=30 + i, ts=1010.0 + i, resp_bytes=5_000) for i in range(6)
    ]
    assert feed(detector, flows) == []


def test_a_horizontal_sweep_the_far_side_answered_is_not_a_scan():
    """The responder gate covers both scan types, not only the vertical one.

    A source reaching many hosts on one port and being answered by all of them
    is a client with a lot of servers - the CDN-heavy browsing shape that
    produced 936 of the 1 636 benign false positives.
    """
    detector = PortScanDetector(
        PortScanConfig(window_seconds=60.0, min_unique_ports=99, min_unique_hosts=4)
    )
    flows = [
        scan_flow(dst=f"10.0.0.{i}", port=443, ts=1000.0 + i, resp_bytes=5_000)
        for i in range(5)
    ]
    assert feed(detector, flows) == []


def test_dropping_the_vertical_half_leaves_the_horizontal_alert():
    """Combined minus its vertical half is a horizontal scan, not silence.

    The window sweeps ephemeral ports (so the vertical signal is withdrawn)
    while still fanning out across hosts on each of them, which is the shape
    the fan-out rule is there to catch.
    """
    detector = PortScanDetector(
        PortScanConfig(window_seconds=60.0, min_unique_ports=5, min_unique_hosts=4)
    )
    flows = [
        scan_flow(dst=f"10.0.0.{host}", port=50_000 + port, ts=1000.0 + i)
        for i, (port, host) in enumerate(
            (p, h) for p in range(5) for h in range(4)
        )
    ]
    alerts = feed(detector, flows)
    assert alerts
    assert {a.evidence["scan_type"] for a in alerts} == {"horizontal"}
    assert alerts[0].evidence["service_ports"] == 0


def test_evidence_names_which_responder_evidence_decided(detector):
    alerts = _sweep(detector, [21, 22, 23, 25, 80, 110])
    assert alerts[0].evidence["responder_evidence"] == "resp_bytes"
    assert alerts[0].evidence["established_fraction"] == 0.0

    with_state = PortScanDetector(
        PortScanConfig(window_seconds=60.0, min_unique_ports=5, min_unique_hosts=99)
    )
    alerts = _sweep(with_state, [21, 22, 23, 25, 80, 110], conn_state="S0")
    assert alerts[0].evidence["responder_evidence"] == "conn_state"
    assert alerts[0].evidence["conn_state_coverage"] == 1.0
    assert alerts[0].evidence["incomplete_fraction"] == 1.0
