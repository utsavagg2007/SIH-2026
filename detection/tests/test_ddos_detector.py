"""DDoSDetector tests.

Numbered comments map to the acceptance list: qualification, isolation,
expiry, edge cases, alert conformance, scoring, cooldown/escalation, reset
and engine integration alongside the port scan detector.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from detection_core import (
    DDoSConfig,
    DDoSDetector,
    DetectionEngine,
    EventScope,
    PortScanConfig,
    PortScanDetector,
    ScoreType,
    Severity,
    ThreatAlert,
    ThreatClass,
)

from .conftest import make_flow

VICTIM = "10.0.0.200"


@pytest.fixture
def config() -> DDoSConfig:
    """Small thresholds so tests stay short and readable."""
    return DDoSConfig(
        window_seconds=10.0,
        min_unique_sources=5,
        min_flows=10,
        min_packets=100,
        cooldown_seconds=60.0,
    )


@pytest.fixture
def detector(config) -> DDoSDetector:
    return DDoSDetector(config)


@pytest.fixture
def flows_only_config() -> DDoSConfig:
    """Packets effectively disabled, so flow count alone drives intensity."""
    return DDoSConfig(
        window_seconds=10.0,
        min_unique_sources=5,
        min_flows=10,
        min_packets=1_000_000,
        cooldown_seconds=60.0,
    )


def ddos_flow(
    *,
    src: str = "10.1.0.1",
    dst: str = VICTIM,
    port: int | None = 80,
    ts: float = 1000.0,
    proto: str = "tcp",
    pkts: int = 1,
    byts: int = 100,
):
    return make_flow(
        src_ip=src,
        dst_ip=dst,
        dst_port=port,
        timestamp=ts,
        proto=proto,
        orig_pkts=pkts,
        resp_pkts=0,
        orig_bytes=byts,
        resp_bytes=0,
    )


def flood(
    sources: int,
    rounds: int,
    *,
    dst: str = VICTIM,
    port: int | None = 80,
    proto: str = "tcp",
    start: float = 1000.0,
    step: float = 0.01,
    pkts: int = 1,
    byts: int = 100,
) -> list:
    """`rounds` passes over `sources` distinct hosts, round-robin."""
    flows = []
    ts = start
    for _ in range(rounds):
        for s in range(sources):
            flows.append(
                ddos_flow(
                    src=f"10.1.0.{s}",
                    dst=dst,
                    port=port,
                    ts=ts,
                    proto=proto,
                    pkts=pkts,
                    byts=byts,
                )
            )
            ts += step
    return flows


def feed(detector, flows):
    alerts = []
    for flow in flows:
        alerts.extend(detector.process(flow))
    return alerts


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------


def test_documented_defaults():
    config = DDoSConfig()
    assert config.window_seconds == 10.0
    assert config.min_unique_sources == 50
    assert config.min_flows == 200
    assert config.min_packets == 1000
    assert config.cooldown_seconds == 60.0


def test_detector_uses_defaults_when_unconfigured():
    assert DDoSDetector().config == DDoSConfig()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"window_seconds": 0},
        {"window_seconds": -1},
        {"min_unique_sources": 0},
        {"min_flows": 0},
        {"min_packets": 0},
        {"cooldown_seconds": -1},
        {"saturation_multiple": 1.0},
    ],
)
def test_invalid_config_rejected(kwargs):
    with pytest.raises(ValueError):
        DDoSConfig(**kwargs)


def test_detector_identity():
    detector = DDoSDetector()
    assert detector.name == "ddos"
    assert detector.version == "0.1.0"


# --------------------------------------------------------------------------
# 1-6. Qualification: breadth AND intensity
# --------------------------------------------------------------------------


def test_normal_low_volume_traffic_produces_no_alert(detector):
    """1."""
    assert feed(detector, flood(sources=3, rounds=1)) == []


def test_one_source_making_many_flows_is_not_ddos(detector):
    """2. Intensity without breadth."""
    flows = [ddos_flow(src="10.1.0.1", ts=1000.0 + i * 0.01) for i in range(200)]
    assert feed(detector, flows) == []


def test_many_sources_with_too_little_traffic_is_not_ddos(detector):
    """3. Breadth without intensity: 6 sources, 6 flows, 6 packets."""
    assert feed(detector, flood(sources=6, rounds=1)) == []


def test_many_sources_and_enough_flows_alerts(detector):
    """4. 5 sources x 2 flows = 10 flows, meeting min_flows."""
    alerts = feed(detector, flood(sources=5, rounds=2))

    assert len(alerts) == 1
    assert alerts[0].threat_class is ThreatClass.DDOS
    assert alerts[0].evidence["unique_src_ips"] == 5
    assert alerts[0].evidence["flow_count"] == 10


def test_many_sources_and_enough_packets_alerts(detector):
    """5. Only 5 flows - under min_flows - but 125 packets."""
    alerts = feed(detector, flood(sources=5, rounds=1, pkts=25))

    assert len(alerts) == 1
    assert alerts[0].evidence["flow_count"] == 5
    assert alerts[0].evidence["packet_count"] == 125


def test_huge_byte_volume_from_one_source_is_not_ddos(detector):
    """6. A large legitimate transfer must not qualify on volume alone."""
    flows = [
        ddos_flow(src="10.1.0.1", ts=1000.0 + i * 0.01, pkts=5000, byts=50_000_000)
        for i in range(20)
    ]
    assert feed(detector, flows) == []


def test_busy_web_server_is_not_ddos_under_default_thresholds():
    """Regression: the victim's own replies must not create intensity.

    60 ordinary clients each fetch one page. Counting orig+resp put 2400
    packets in the window - 2040 of them the server's own responses - which
    crossed min_packets and produced DDoS alerts on entirely normal serving.
    Originator-side counting sees the 360 packets actually aimed at the host.
    """
    detector = DDoSDetector()  # real defaults: 50 sources, 200 flows, 1000 packets
    flows = [
        make_flow(
            timestamp=1000.0 + i * 0.15,
            src_ip=f"203.0.113.{i}",
            dst_ip=VICTIM,
            dst_port=443,
            proto="tcp",
            orig_pkts=6,
            resp_pkts=34,
            orig_bytes=800,
            resp_bytes=48_000,
        )
        for i in range(60)
    ]

    assert feed(detector, flows) == []

    window = detector._windows.get(VICTIM)
    assert len(window.src_ips()) == 60  # breadth alone was satisfied
    assert window.total_orig_packets() == 360  # well under min_packets


def test_heavy_responses_do_not_inflate_reported_volume(detector):
    """Evidence counts traffic at the victim, not traffic from it."""
    flows = []
    ts = 1000.0
    for _ in range(2):
        for s in range(5):
            flows.append(
                make_flow(
                    timestamp=ts,
                    src_ip=f"10.1.0.{s}",
                    dst_ip=VICTIM,
                    dst_port=80,
                    proto="tcp",
                    orig_pkts=1,
                    resp_pkts=900,
                    orig_bytes=100,
                    resp_bytes=1_000_000,
                )
            )
            ts += 0.01

    alerts = feed(detector, flows)

    # Qualifies on flow count (10 >= min_flows), not on the response volume.
    assert len(alerts) == 1
    assert alerts[0].evidence["packet_count"] == 10
    assert alerts[0].evidence["byte_count"] == 1000


def test_bytes_alone_never_gate_the_decision(detector):
    """Enough sources and bytes, but neither flows nor packets are high."""
    flows = [
        ddos_flow(src=f"10.1.0.{i}", ts=1000.0 + i * 0.01, pkts=1, byts=10_000_000)
        for i in range(6)
    ]
    assert feed(detector, flows) == []


# --------------------------------------------------------------------------
# 7-9. State handling
# --------------------------------------------------------------------------


def test_duplicate_sources_do_not_inflate_unique_count(detector):
    """7. 5 sources hammering repeatedly stay 5 sources."""
    alerts = feed(detector, flood(sources=5, rounds=4))

    assert alerts
    assert alerts[0].evidence["unique_src_ips"] == 5
    assert alerts[0].evidence["flow_count"] >= 10


def test_destinations_are_isolated(detector):
    """8. Two victims each below threshold must not pool their sources."""
    flows = flood(sources=4, rounds=3, dst="10.0.0.1")
    flows += flood(sources=4, rounds=3, dst="10.0.0.2", start=1000.5)

    assert feed(detector, flows) == []


def test_only_the_flooded_destination_alerts(detector):
    """Background chatter to another host must not appear in the alert."""
    flows = flood(sources=3, rounds=2, dst="10.0.0.99")
    flows += flood(sources=5, rounds=2, dst=VICTIM, start=1000.5)

    alerts = feed(detector, flows)
    assert len(alerts) == 1
    assert alerts[0].dst_ip == VICTIM
    assert alerts[0].evidence["unique_src_ips"] == 5


def test_old_observations_expire_from_the_window(detector):
    """9. A flood that has aged out cannot combine with fresh traffic."""
    assert feed(detector, flood(sources=5, rounds=1)) == []

    # Far outside the 10s window.
    late = ddos_flow(src="10.1.0.9", ts=5000.0)
    assert detector.process(late) == []
    assert detector._windows.get(VICTIM).attempts == 1


def test_expiry_shrinks_the_unique_source_count(detector):
    feed(detector, flood(sources=5, rounds=1))
    detector.process(ddos_flow(src="10.1.0.9", ts=5000.0))

    assert detector._windows.get(VICTIM).src_ips() == {"10.1.0.9"}


# --------------------------------------------------------------------------
# 10-11. Edge cases
# --------------------------------------------------------------------------


def test_missing_dst_port_handled_safely(detector):
    """10. dst_port is not a gate; the alert simply reports None."""
    alerts = feed(detector, flood(sources=5, rounds=2, port=None))

    assert len(alerts) == 1
    assert alerts[0].dst_port is None


def test_zero_packet_and_byte_flows_handled_safely(detector):
    """11. Flow count alone can still qualify; no division blows up."""
    alerts = feed(detector, flood(sources=5, rounds=2, pkts=0, byts=0))

    assert len(alerts) == 1
    assert alerts[0].evidence["packet_count"] == 0
    assert alerts[0].evidence["byte_count"] == 0
    assert 0.0 <= alerts[0].score <= 1.0


def test_zero_time_span_reports_no_rate_rather_than_a_fake_one(detector):
    """Every flow sharing one timestamp gives no measurable rate."""
    flows = flood(sources=5, rounds=2, step=0.0)
    alerts = feed(detector, flows)

    assert len(alerts) == 1
    assert alerts[0].evidence["observed_span_seconds"] == 0.0
    assert alerts[0].evidence["flows_per_second"] is None
    assert alerts[0].evidence["packets_per_second"] is None


def test_rates_are_computed_when_time_actually_passes(detector):
    alerts = feed(detector, flood(sources=5, rounds=2, step=0.1))

    evidence = alerts[0].evidence
    assert evidence["observed_span_seconds"] == pytest.approx(0.9)
    assert evidence["flows_per_second"] == pytest.approx(10 / 0.9)
    assert evidence["packets_per_second"] == pytest.approx(10 / 0.9)


def test_ipv6_destinations_are_handled(detector):
    alerts = feed(detector, flood(sources=5, rounds=2, dst="2001:db8::200"))

    assert len(alerts) == 1
    assert alerts[0].dst_ip == "2001:db8::200"


# --------------------------------------------------------------------------
# 12-14, 22-26. Alert conformance
# --------------------------------------------------------------------------


@pytest.fixture
def sample_alert(detector) -> ThreatAlert:
    return feed(detector, flood(sources=5, rounds=2))[0]


def test_alert_conforms_to_v1_1(sample_alert):
    """12, 13, 14, 22, 24."""
    assert isinstance(sample_alert, ThreatAlert)
    assert sample_alert.schema_version == "1.1"
    assert sample_alert.threat_class is ThreatClass.DDOS
    assert sample_alert.event_scope is EventScope.DESTINATION_HOST
    assert sample_alert.score_type is ScoreType.RULE_SCORE
    assert sample_alert.flow_id is None
    assert sample_alert.dst_ip == VICTIM
    assert sample_alert.detector == "ddos"
    assert sample_alert.detector_version == "0.1.0"
    assert sample_alert.mitre_techniques == ["T1498", "T1499"]
    assert sample_alert.incident_id is None


def test_src_ip_is_none_when_many_attackers(sample_alert):
    """23. Never a placeholder for "multiple"."""
    assert sample_alert.src_ip is None
    assert "multiple" not in str(sample_alert.to_wire())


def test_src_ip_is_named_when_unambiguous():
    """A single-source config still reports the one attacker honestly."""
    detector = DDoSDetector(
        DDoSConfig(min_unique_sources=1, min_flows=3, min_packets=1_000_000)
    )
    alerts = feed(detector, [ddos_flow(src="10.1.0.7", ts=1000.0 + i) for i in range(3)])

    assert alerts[0].src_ip == "10.1.0.7"


def test_dst_port_and_protocol_only_when_unambiguous(detector):
    """25. One port and one protocol across the window."""
    alert = feed(detector, flood(sources=5, rounds=2, port=443, proto="tcp"))[0]
    assert alert.dst_port == 443
    assert alert.protocol == "tcp"


def test_mixed_ports_and_protocols_report_none():
    """25. A flood spread across ports/protocols names neither."""
    detector = DDoSDetector(
        DDoSConfig(min_unique_sources=5, min_flows=10, min_packets=1_000_000)
    )
    flows = []
    ts = 1000.0
    for round_no in range(2):
        for s in range(5):
            flows.append(
                ddos_flow(
                    src=f"10.1.0.{s}",
                    port=80 + s,
                    proto="tcp" if s % 2 else "udp",
                    ts=ts,
                )
            )
            ts += 0.01
    alerts = feed(detector, flows)

    assert alerts[0].dst_port is None
    assert alerts[0].protocol is None


def test_evidence_contains_required_keys(sample_alert):
    """26."""
    for key in (
        "unique_src_ips",
        "flow_count",
        "packet_count",
        "byte_count",
        "window_seconds",
        "min_unique_sources",
        "min_flows",
        "min_packets",
    ):
        assert key in sample_alert.evidence


def test_evidence_reports_configured_thresholds(sample_alert, config):
    assert sample_alert.evidence["window_seconds"] == config.window_seconds
    assert sample_alert.evidence["min_unique_sources"] == config.min_unique_sources
    assert sample_alert.evidence["min_flows"] == config.min_flows
    assert sample_alert.evidence["min_packets"] == config.min_packets


def test_alert_serializes_to_the_wire_contract(sample_alert):
    wire = sample_alert.to_wire()
    assert set(wire) == {
        "alert_id", "schema_version", "event_start", "event_end", "detected_at",
        "event_scope", "flow_id", "src_ip", "dst_ip", "dst_port", "protocol",
        "threat_class", "severity", "score", "score_type", "evidence",
        "detector", "detector_version", "mitre_techniques", "incident_id",
    }
    assert wire["threat_class"] == "ddos"
    assert wire["event_scope"] == "destination_host"
    assert wire["score_type"] == "rule_score"
    assert wire["event_start"].endswith("Z")


def test_alert_window_covers_the_observed_flows(sample_alert):
    assert sample_alert.event_start <= sample_alert.event_end
    assert sample_alert.event_start.timestamp() == pytest.approx(1000.0)


# --------------------------------------------------------------------------
# 15-16. Scoring and severity
# --------------------------------------------------------------------------


@pytest.mark.parametrize("rounds", [2, 3, 5, 10, 20, 60])
def test_score_stays_within_range(flows_only_config, rounds):
    """15."""
    detector = DDoSDetector(flows_only_config)
    alerts = feed(detector, flood(sources=5, rounds=rounds))

    assert alerts
    for alert in alerts:
        assert 0.0 <= alert.score <= 1.0


def test_score_at_both_thresholds_is_one_half(flows_only_config):
    detector = DDoSDetector(flows_only_config)
    alert = feed(detector, flood(sources=5, rounds=2))[0]
    assert alert.score == pytest.approx(0.5)


def test_a_stronger_flood_scores_higher(flows_only_config):
    """More flows from the same breadth must not score lower."""

    def last_score(rounds: int) -> float:
        detector = DDoSDetector(
            DDoSConfig(
                window_seconds=10.0,
                min_unique_sources=5,
                min_flows=10,
                min_packets=1_000_000,
                cooldown_seconds=0.0,
            )
        )
        return feed(detector, flood(sources=5, rounds=rounds))[-1].score

    assert last_score(4) > last_score(2)
    assert last_score(8) > last_score(4)


def test_broader_flood_scores_higher():
    """More distinct sources at the same flow count must not score lower."""

    def score_for(sources: int) -> float:
        detector = DDoSDetector(
            DDoSConfig(
                window_seconds=10.0,
                min_unique_sources=5,
                min_flows=20,
                min_packets=1_000_000,
                cooldown_seconds=0.0,
            )
        )
        rounds = 20 // sources
        return feed(detector, flood(sources=sources, rounds=rounds))[-1].score

    assert score_for(10) > score_for(5)


def test_score_saturates_at_one(flows_only_config):
    detector = DDoSDetector(
        DDoSConfig(
            window_seconds=10.0,
            min_unique_sources=5,
            min_flows=10,
            min_packets=1_000_000,
            cooldown_seconds=0.0,
        )
    )
    alert = feed(detector, flood(sources=5, rounds=40))[-1]
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
    """16."""
    assert DDoSDetector._severity(score) is expected


@pytest.mark.parametrize(
    ("drifted", "expected"),
    [
        (0.5999999999999999, Severity.MEDIUM),
        (0.7499999999999999, Severity.HIGH),
        (0.8999999999999999, Severity.CRITICAL),
    ],
)
def test_float_drift_below_a_boundary_classifies_upward(drifted, expected):
    """16. Same rounding guarantee the port scan detector relies on."""
    assert DDoSDetector._severity(drifted) is expected


@pytest.mark.parametrize(
    ("below", "expected"),
    [(0.5999, Severity.LOW), (0.7499, Severity.MEDIUM), (0.8999, Severity.HIGH)],
)
def test_genuinely_below_a_boundary_stays_lower(below, expected):
    assert DDoSDetector._severity(below) is expected


# --------------------------------------------------------------------------
# 17-21. Near-real-time, cooldown, escalation, reset
# --------------------------------------------------------------------------


def test_alert_fires_on_the_flow_that_crosses_the_threshold(detector):
    """17. No waiting for flush()."""
    flows = flood(sources=5, rounds=2)
    emitted = [len(detector.process(flow)) for flow in flows]

    assert sum(emitted) == 1
    assert emitted.index(1) == 9  # the 10th flow reaches min_flows
    assert detector.flush() == []


def test_flush_is_not_needed_for_detection(detector):
    alerts = feed(detector, flood(sources=5, rounds=2))
    assert len(alerts) == 1
    assert detector.flush() == []


def test_same_severity_during_cooldown_is_suppressed(flows_only_config):
    """18."""
    detector = DDoSDetector(flows_only_config)
    alerts = feed(detector, flood(sources=5, rounds=3))

    assert len(alerts) == 1
    assert alerts[0].severity is Severity.LOW


def test_severity_escalation_during_cooldown_emits(flows_only_config):
    """19. LOW -> MEDIUM -> HIGH -> CRITICAL, one alert per band."""
    detector = DDoSDetector(flows_only_config)
    alerts = feed(detector, flood(sources=5, rounds=12))

    assert [a.severity for a in alerts] == [
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]


def test_escalation_alerts_are_strictly_increasing(flows_only_config):
    detector = DDoSDetector(flows_only_config)
    ranks = [
        [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL].index(a.severity)
        for a in feed(detector, flood(sources=5, rounds=12))
    ]
    assert ranks == sorted(ranks)
    assert len(ranks) == len(set(ranks))


def test_cooldown_expiry_permits_a_new_alert(flows_only_config):
    """20."""
    detector = DDoSDetector(flows_only_config)
    first = feed(detector, flood(sources=5, rounds=2))
    assert len(first) == 1

    later = 1000.0 + flows_only_config.cooldown_seconds + 10.0
    second = feed(detector, flood(sources=5, rounds=2, start=later))

    assert len(second) == 1
    assert second[0].severity is Severity.LOW


def test_cooldown_is_per_destination(flows_only_config):
    detector = DDoSDetector(flows_only_config)
    first = feed(detector, flood(sources=5, rounds=2, dst="10.0.0.1"))
    second = feed(detector, flood(sources=5, rounds=2, dst="10.0.0.2", start=1000.5))

    assert len(first) == 1 and len(second) == 1
    assert {first[0].dst_ip, second[0].dst_ip} == {"10.0.0.1", "10.0.0.2"}


def test_reset_clears_all_state(detector):
    """21."""
    feed(detector, flood(sources=5, rounds=2))
    assert len(detector._windows) == 1
    assert detector._state

    detector.reset()

    assert len(detector._windows) == 0
    assert detector._state == {}


def test_reset_clears_cooldown_and_escalation(flows_only_config):
    detector = DDoSDetector(flows_only_config)
    feed(detector, flood(sources=5, rounds=12))
    detector.reset()

    alerts = feed(detector, flood(sources=5, rounds=2, start=1100.0))
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.LOW


def test_detector_never_mutates_the_flow(detector):
    flow = ddos_flow()
    detector.process(flow)
    with pytest.raises(ValidationError):
        flow.dst_ip = "10.0.0.1"


# --------------------------------------------------------------------------
# 27-29. Coexistence with the port scan detector
# --------------------------------------------------------------------------


def test_engine_runs_both_detectors(config):
    """27."""
    engine = DetectionEngine([PortScanDetector(), DDoSDetector(config)])
    alerts = list(engine.run(flood(sources=5, rounds=2)))

    assert len(alerts) == 1
    assert alerts[0].detector == "ddos"
    assert engine.stats.detector_errors == 0
    assert engine.stats.flows_processed == 10


def test_port_scan_traffic_is_not_reported_as_ddos(config):
    """28. One source sweeping ports/hosts has no destination breadth."""
    detector = DDoSDetector(config)
    flows = [
        make_flow(
            src_ip="10.0.0.66",
            dst_ip=f"10.0.1.{i}",
            dst_port=1000 + i,
            timestamp=1000.0 + i * 0.01,
        )
        for i in range(60)
    ]
    assert feed(detector, flows) == []


def test_ddos_traffic_is_not_reported_as_a_port_scan(config):
    """29. A flood gives each source one host on one port."""
    port_scan = PortScanDetector(PortScanConfig(min_unique_ports=5, min_unique_hosts=4))
    assert feed(port_scan, flood(sources=5, rounds=4)) == []


def test_both_detectors_keep_independent_state(config):
    """29. Running a flood then a scan through one engine keeps both correct."""
    engine = DetectionEngine(
        [
            PortScanDetector(PortScanConfig(min_unique_ports=5, min_unique_hosts=99)),
            DDoSDetector(config),
        ]
    )

    scan = [
        make_flow(
            src_ip="10.0.0.66",
            dst_ip="10.0.0.80",
            dst_port=p,
            timestamp=2000.0 + i * 0.01,
            # A probed port does not answer with a payload.
            resp_bytes=0,
            resp_pkts=0,
        )
        for i, p in enumerate([22, 23, 25, 80, 443])
    ]
    alerts = list(engine.run(flood(sources=5, rounds=2) + scan))

    by_detector = {a.detector for a in alerts}
    assert by_detector == {"ddos", "port_scan"}
    assert sum(a.detector == "ddos" for a in alerts) == 1
    assert sum(a.detector == "port_scan" for a in alerts) == 1
