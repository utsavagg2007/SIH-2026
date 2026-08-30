"""C2BeaconingDetector tests.

Numbered comments map to the acceptance list: qualification, relationship
isolation, timing edge cases, alert conformance, scoring, cooldown and
escalation, reset, and coexistence with the other two detectors.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from detection_core import (
    BeaconKey,
    C2BeaconingConfig,
    C2BeaconingDetector,
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

SRC = "10.0.0.50"
DST = "203.0.113.10"


@pytest.fixture
def config() -> C2BeaconingConfig:
    return C2BeaconingConfig(
        window_seconds=900.0,
        min_observations=6,
        min_mean_interval_seconds=2.0,
        max_mean_interval_seconds=120.0,
        max_interval_cv=0.20,
        cooldown_seconds=300.0,
    )


@pytest.fixture
def detector(config) -> C2BeaconingDetector:
    return C2BeaconingDetector(config)


@pytest.fixture
def short_cooldown_config(config) -> C2BeaconingConfig:
    return C2BeaconingConfig(
        window_seconds=900.0,
        min_observations=6,
        min_mean_interval_seconds=2.0,
        max_mean_interval_seconds=120.0,
        max_interval_cv=0.20,
        cooldown_seconds=60.0,
    )


def beacon_flows(
    count: int,
    intervals: float | list[float] = 30.0,
    *,
    start: float = 1000.0,
    src: str = SRC,
    dst: str = DST,
    port: int | None = 443,
    proto: str = "tcp",
    orig_bytes: int = 500,
    orig_pkts: int = 5,
) -> list:
    """`count` contacts spaced by a fixed interval, or by a cycled list."""
    steps = [intervals] if isinstance(intervals, (int, float)) else list(intervals)
    flows = []
    ts = start
    for i in range(count):
        flows.append(
            make_flow(
                src_ip=src,
                dst_ip=dst,
                dst_port=port,
                proto=proto,
                timestamp=ts,
                orig_pkts=orig_pkts,
                resp_pkts=0,
                orig_bytes=orig_bytes,
                resp_bytes=0,
            )
        )
        ts += steps[i % len(steps)]
    return flows


def feed(detector, flows):
    alerts = []
    for flow in flows:
        alerts.extend(detector.process(flow))
    return alerts


# Five intervals whose coefficient of variation is exactly 0.20, the default
# regularity bound: mean 20.0, population stddev 4.0. A simple alternating
# pattern will not do it - over an odd number of intervals the two values are
# unbalanced, which shifts the mean and pushes the CV slightly over.
CV_AT_BOUND = [18.0, 18.0, 18.0, 18.0, 28.0]


# --------------------------------------------------------------------------
# Config and key
# --------------------------------------------------------------------------


def test_documented_defaults():
    config = C2BeaconingConfig()
    assert config.window_seconds == 900.0
    assert config.min_observations == 6
    assert config.min_mean_interval_seconds == 2.0
    assert config.max_mean_interval_seconds == 120.0
    assert config.max_interval_cv == 0.20
    assert config.cooldown_seconds == 300.0


def test_detector_uses_defaults_when_unconfigured():
    assert C2BeaconingDetector().config == C2BeaconingConfig()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"window_seconds": 0},
        {"min_observations": 2},
        {"min_mean_interval_seconds": 0},
        {"max_mean_interval_seconds": 1.0},
        {"max_interval_cv": -0.1},
        {"cooldown_seconds": -1},
        {"saturation_multiple": 1.0},
        {"regularity_weight": 1.5},
    ],
)
def test_invalid_config_rejected(kwargs):
    with pytest.raises(ValueError):
        C2BeaconingConfig(**kwargs)


def test_detector_identity():
    detector = C2BeaconingDetector()
    assert detector.name == "c2_beaconing"
    assert detector.version == "0.1.0"


def test_beacon_key_from_flow():
    """2. The key is exactly (src_ip, dst_ip, dst_port, proto)."""
    key = BeaconKey.from_flow(
        make_flow(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp")
    )
    assert key == BeaconKey(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp")


def test_beacon_key_keeps_missing_port_as_none():
    """14. Never invented as port 0."""
    key = BeaconKey.from_flow(make_flow(dst_port=None))
    assert key.dst_port is None
    assert key != BeaconKey(key.src_ip, key.dst_ip, 0, key.proto)


# --------------------------------------------------------------------------
# 1-8. Qualification
# --------------------------------------------------------------------------


@pytest.mark.parametrize("count", [1, 2, 3, 4, 5])
def test_too_few_observations_never_alert(detector, count):
    """1."""
    assert feed(detector, beacon_flows(count)) == []


def test_exactly_min_observations_and_periodic_alerts(detector):
    """2."""
    alerts = feed(detector, beacon_flows(6))

    assert len(alerts) == 1
    assert alerts[0].threat_class is ThreatClass.C2_BEACONING
    assert alerts[0].evidence["observation_count"] == 6
    assert alerts[0].evidence["interval_count"] == 5


def test_perfectly_periodic_sequence_alerts(detector):
    """3."""
    alerts = feed(detector, beacon_flows(6, 30.0))

    assert len(alerts) == 1
    assert alerts[0].evidence["mean_interval_seconds"] == pytest.approx(30.0)
    assert alerts[0].evidence["interval_stddev_seconds"] == pytest.approx(0.0)
    assert alerts[0].evidence["coefficient_of_variation"] == pytest.approx(0.0)


def test_mild_jitter_still_qualifies(detector):
    """4. 27/33s alternating - about 10% CV, inside the 20% bound."""
    alerts = feed(detector, beacon_flows(6, [27.0, 33.0]))

    assert len(alerts) == 1
    assert alerts[0].evidence["coefficient_of_variation"] == pytest.approx(0.1, abs=0.01)


def test_highly_irregular_timings_do_not_alert(detector):
    """5."""
    assert feed(detector, beacon_flows(8, [5.0, 60.0, 8.0, 90.0, 12.0])) == []


def test_repetition_without_regularity_does_not_alert(detector):
    """6. Plenty of contact, ragged timing."""
    intervals = [3.0, 45.0, 7.0, 80.0, 4.0, 100.0, 9.0]
    assert feed(detector, beacon_flows(20, intervals)) == []


def test_interval_below_minimum_does_not_alert(detector):
    """7. Sub-second chatter is a keep-alive, not a check-in."""
    assert feed(detector, beacon_flows(12, 1.0)) == []


def test_interval_above_maximum_does_not_alert(detector):
    """8. Too slow to judge inside the window."""
    assert feed(detector, beacon_flows(6, 150.0)) == []


def test_interval_exactly_on_the_bounds_qualifies(detector, config):
    """The cadence bounds are inclusive."""
    assert len(feed(detector, beacon_flows(6, config.min_mean_interval_seconds))) == 1

    other = C2BeaconingDetector(config)
    assert len(feed(other, beacon_flows(6, config.max_mean_interval_seconds))) == 1


def test_cv_exactly_on_the_bound_qualifies(detector):
    """The regularity bound is inclusive: CV == max_interval_cv passes."""
    alerts = feed(detector, beacon_flows(6, CV_AT_BOUND))

    assert len(alerts) == 1
    assert alerts[0].evidence["coefficient_of_variation"] == 0.2


def test_cv_just_over_the_bound_does_not_qualify(detector):
    """+/-20% alternating over 5 intervals lands at CV 0.204 - rejected."""
    assert feed(detector, beacon_flows(6, [24.0, 36.0])) == []


# --------------------------------------------------------------------------
# 9. Degenerate timing
# --------------------------------------------------------------------------


def test_identical_timestamps_are_safe(detector):
    """9. No intervals at all - must not divide by zero, must not alert."""
    flows = [make_flow(src_ip=SRC, dst_ip=DST, dst_port=443, timestamp=1000.0)] * 10
    assert feed(detector, flows) == []


def test_duplicate_timestamps_mixed_with_real_intervals(detector):
    """3. Zero-length gaps are skipped; the genuine cadence still reads.

    The duplicate delays the alert by one contact: 6 observations yield only
    4 usable intervals, one short of the 5 required, so the verdict waits
    for the 7th.
    """
    flows = beacon_flows(6, 30.0)
    duplicate = flows[2]
    alerts = feed(detector, flows[:3] + [duplicate] + flows[3:])

    assert len(alerts) == 1
    assert alerts[0].evidence["observation_count"] == 7
    assert alerts[0].evidence["interval_count"] == 5
    assert alerts[0].evidence["mean_interval_seconds"] == pytest.approx(30.0)
    assert alerts[0].evidence["coefficient_of_variation"] == pytest.approx(0.0)


def test_enough_observations_but_too_few_valid_intervals(detector):
    """1. 6 contacts, but one duplicate leaves only 4 usable intervals."""
    timestamps = [1000.0, 1000.0, 1030.0, 1060.0, 1090.0, 1120.0]
    flows = [
        make_flow(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp", timestamp=ts)
        for ts in timestamps
    ]

    assert feed(detector, flows) == []


def test_min_observations_with_exactly_enough_intervals_alerts(detector):
    """2. 6 clean contacts give 5 valid intervals - the minimum."""
    alerts = feed(detector, beacon_flows(6, 30.0))

    assert len(alerts) == 1
    assert alerts[0].evidence["observation_count"] == 6
    assert alerts[0].evidence["interval_count"] == 5


def test_duplicates_cannot_pad_a_relationship_over_the_bar(detector, config):
    """4. Repeated same-instant contacts add count but never timing evidence."""
    padded = [1000.0, 1000.0, 1000.0, 1000.0, 1000.0, 1000.0, 1030.0, 1060.0]
    flows = [
        make_flow(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp", timestamp=ts)
        for ts in padded
    ]

    # 8 observations, but only 2 usable intervals - nowhere near the bar.
    assert feed(detector, flows) == []

    key = BeaconKey(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp")
    window = detector._windows.get(key)
    assert window.attempts == 8
    assert len(window.timestamps()) == 8

    # Real contacts continue; the alert arrives only once 5 valid intervals
    # exist, which takes three more.
    more = [
        make_flow(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp", timestamp=ts)
        for ts in (1090.0, 1120.0)
    ]
    assert feed(detector, more) == []

    final = make_flow(
        src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp", timestamp=1150.0
    )
    alerts = detector.process(final)

    assert len(alerts) == 1
    assert alerts[0].evidence["interval_count"] == config.min_observations - 1


def test_interval_count_never_counts_zero_gaps(detector):
    """Reported interval_count is usable intervals, not raw gaps."""
    flows = beacon_flows(8, 30.0)
    alerts = feed(detector, flows[:4] + [flows[3]] + flows[4:])

    assert alerts
    evidence = alerts[0].evidence
    assert evidence["interval_count"] == evidence["observation_count"] - 2


def test_zero_byte_flows_are_safe(detector):
    """Volume gates nothing; a zero-byte beacon still alerts."""
    alerts = feed(detector, beacon_flows(6, orig_bytes=0, orig_pkts=0))

    assert len(alerts) == 1
    assert alerts[0].evidence["total_orig_bytes"] == 0
    assert alerts[0].evidence["average_orig_bytes_per_flow"] == 0


# --------------------------------------------------------------------------
# 10-14. Relationship isolation
# --------------------------------------------------------------------------


def test_different_sources_are_isolated(detector):
    """10."""
    flows = beacon_flows(5, src="10.0.0.1") + beacon_flows(5, src="10.0.0.2")
    assert feed(detector, flows) == []
    assert len(detector._windows) == 2


def test_different_destinations_are_isolated(detector):
    """11."""
    flows = beacon_flows(5, dst="203.0.113.1") + beacon_flows(5, dst="203.0.113.2")
    assert feed(detector, flows) == []
    assert len(detector._windows) == 2


def test_different_destination_ports_are_isolated(detector):
    """12."""
    flows = beacon_flows(5, port=443) + beacon_flows(5, port=8443)
    assert feed(detector, flows) == []
    assert len(detector._windows) == 2


def test_different_protocols_are_isolated(detector):
    """13. TCP and UDP to the same endpoint never pool their timing."""
    flows = beacon_flows(5, proto="tcp") + beacon_flows(5, proto="udp")
    assert feed(detector, flows) == []
    assert len(detector._windows) == 2


def test_missing_port_is_its_own_relationship(detector):
    """14. A portless relationship does not merge with a ported one."""
    flows = beacon_flows(5, port=None) + beacon_flows(5, port=443)
    assert feed(detector, flows) == []
    assert len(detector._windows) == 2


def test_beacon_with_no_port_still_alerts(detector):
    """14. dst_port=None is handled, not skipped."""
    alerts = feed(detector, beacon_flows(6, port=None))

    assert len(alerts) == 1
    assert alerts[0].dst_port is None


def test_ipv6_relationship_is_handled(detector):
    alerts = feed(detector, beacon_flows(6, src="2001:db8::1", dst="2001:db8::99"))

    assert len(alerts) == 1
    assert alerts[0].src_ip == "2001:db8::1"
    assert alerts[0].dst_ip == "2001:db8::99"


def test_only_the_beaconing_relationship_alerts(detector):
    """Background chatter to another endpoint stays out of the alert."""
    flows = beacon_flows(6, dst="203.0.113.99", intervals=[3.0, 47.0, 8.0])
    flows += beacon_flows(6, dst=DST, start=2000.0)

    alerts = feed(detector, flows)
    assert len(alerts) == 1
    assert alerts[0].dst_ip == DST


# --------------------------------------------------------------------------
# 15. Expiry
# --------------------------------------------------------------------------


def test_expired_observations_leave_the_window(detector):
    """15."""
    assert feed(detector, beacon_flows(5)) == []

    # Far outside the 900s window.
    assert detector.process(beacon_flows(1, start=100_000.0)[0]) == []
    key = BeaconKey(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp")
    assert detector._windows.get(key).attempts == 1


def test_a_beacon_split_across_windows_does_not_accumulate(detector):
    """History older than the window cannot help reach min_observations."""
    flows = beacon_flows(3, start=1000.0)
    flows += beacon_flows(3, start=100_000.0)
    assert feed(detector, flows) == []


# --------------------------------------------------------------------------
# 16-18, 23-29. Near-real-time and alert conformance
# --------------------------------------------------------------------------


def test_alert_fires_on_the_observation_that_qualifies(detector):
    """16. The 6th contact, not later."""
    emitted = [len(detector.process(flow)) for flow in beacon_flows(8)]
    assert emitted == [0, 0, 0, 0, 0, 1, 0, 0]


def test_flush_is_not_needed(detector):
    """17."""
    alerts = feed(detector, beacon_flows(6))
    assert len(alerts) == 1
    assert detector.flush() == []


def test_reset_clears_history(detector):
    """18."""
    feed(detector, beacon_flows(6))
    assert len(detector._windows) == 1
    assert detector._state

    detector.reset()

    assert len(detector._windows) == 0
    assert detector._state == {}


def test_reset_clears_cooldown_and_severity(detector):
    """18."""
    feed(detector, beacon_flows(6))
    detector.reset()

    alerts = feed(detector, beacon_flows(6, start=1200.0))
    assert len(alerts) == 1


@pytest.fixture
def sample_alert(detector) -> ThreatAlert:
    return feed(detector, beacon_flows(6))[0]


def test_alert_conforms_to_v1_1(sample_alert):
    """23, 24, 25, 28."""
    assert isinstance(sample_alert, ThreatAlert)
    assert sample_alert.schema_version == "1.1"
    assert sample_alert.threat_class is ThreatClass.C2_BEACONING
    assert sample_alert.event_scope is EventScope.HOST_PAIR
    assert sample_alert.score_type is ScoreType.RULE_SCORE
    assert sample_alert.flow_id is None
    assert sample_alert.detector == "c2_beaconing"
    assert sample_alert.detector_version == "0.1.0"
    assert sample_alert.mitre_techniques == ["T1071.001", "T1029"]
    assert sample_alert.incident_id is None


def test_alert_endpoints_match_the_beacon_relationship(sample_alert):
    """29."""
    assert sample_alert.src_ip == SRC
    assert sample_alert.dst_ip == DST
    assert sample_alert.dst_port == 443
    assert sample_alert.protocol == "tcp"


def test_alert_serializes_to_the_wire_contract(sample_alert):
    wire = sample_alert.to_wire()
    assert set(wire) == {
        "alert_id", "schema_version", "event_start", "event_end", "detected_at",
        "event_scope", "flow_id", "src_ip", "dst_ip", "dst_port", "protocol",
        "threat_class", "severity", "score", "score_type", "evidence",
        "detector", "detector_version", "mitre_techniques", "incident_id",
    }
    assert wire["threat_class"] == "c2_beaconing"
    assert wire["event_scope"] == "host_pair"
    assert wire["score_type"] == "rule_score"
    assert wire["event_start"].endswith("Z")


def test_evidence_contains_timing_metrics_and_thresholds(sample_alert):
    """27."""
    for key in (
        "observation_count",
        "interval_count",
        "mean_interval_seconds",
        "interval_stddev_seconds",
        "coefficient_of_variation",
        "window_seconds",
        "min_observations",
        "min_mean_interval_seconds",
        "max_mean_interval_seconds",
        "max_interval_cv",
    ):
        assert key in sample_alert.evidence


def test_evidence_reports_configured_thresholds(sample_alert, config):
    assert sample_alert.evidence["window_seconds"] == config.window_seconds
    assert sample_alert.evidence["min_observations"] == config.min_observations
    assert sample_alert.evidence["max_interval_cv"] == config.max_interval_cv


def test_evidence_includes_volume_context(sample_alert):
    assert sample_alert.evidence["total_orig_bytes"] == 6 * 500
    assert sample_alert.evidence["total_orig_packets"] == 6 * 5
    assert sample_alert.evidence["average_orig_bytes_per_flow"] == pytest.approx(500.0)


def test_alert_window_covers_the_observed_contacts(sample_alert):
    assert sample_alert.event_start < sample_alert.event_end
    assert sample_alert.event_start.timestamp() == pytest.approx(1000.0)
    assert sample_alert.event_end.timestamp() == pytest.approx(1150.0)


def test_detector_never_mutates_the_flow(detector):
    flow = beacon_flows(1)[0]
    detector.process(flow)
    with pytest.raises(ValidationError):
        flow.dst_ip = "10.0.0.1"


# --------------------------------------------------------------------------
# 26. Scoring and severity
# --------------------------------------------------------------------------


@pytest.mark.parametrize("count", [6, 8, 12, 20, 30])
@pytest.mark.parametrize("intervals", [30.0, [27.0, 33.0], CV_AT_BOUND])
def test_score_stays_within_range(config, count, intervals):
    """26."""
    detector = C2BeaconingDetector(config)
    alerts = feed(detector, beacon_flows(count, intervals))
    assert alerts
    for alert in alerts:
        assert 0.0 <= alert.score <= 1.0


def test_score_at_the_qualification_boundary_is_one_half(detector):
    """Minimum observations and CV exactly at the bound -> exactly 0.5."""
    alert = feed(detector, beacon_flows(6, CV_AT_BOUND))[0]
    assert alert.score == 0.5
    assert alert.severity is Severity.LOW


def test_clean_qualifying_beacon_gets_the_baseline_score(detector):
    """1. Just qualified on both counts and CV at the bound -> exactly 0.5."""
    alert = feed(detector, beacon_flows(6, CV_AT_BOUND))[0]

    assert alert.score == 0.5
    assert alert.evidence["observation_count"] == 6
    assert alert.evidence["interval_count"] == 5


def test_duplicates_do_not_change_the_score(config):
    """2. Same usable timing plus duplicates must score identically."""
    real = [1000.0, 1030.0, 1060.0, 1090.0, 1120.0, 1150.0]
    padded = [1000.0, 1000.0, 1030.0, 1060.0, 1060.0, 1090.0, 1120.0, 1150.0]

    def alert_for(timestamps):
        detector = C2BeaconingDetector(config)
        flows = [
            make_flow(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp", timestamp=ts)
            for ts in timestamps
        ]
        return feed(detector, flows)[0]

    clean, duplicated = alert_for(real), alert_for(padded)

    assert clean.score == duplicated.score
    assert clean.severity is duplicated.severity
    # Both rest on the same 5 intervals; evidence still reports counts honestly.
    assert clean.evidence["interval_count"] == duplicated.evidence["interval_count"] == 5
    assert clean.evidence["observation_count"] == 6
    assert duplicated.evidence["observation_count"] == 8


def test_duplicates_cannot_escalate_severity(detector):
    """3. Twenty same-instant repeats add no timing evidence and no alert.

    Scoring persistence off raw contacts would have driven this to 1.0 and
    fired a spurious CRITICAL escalation inside the cooldown.
    """
    first = feed(detector, beacon_flows(6, 30.0))
    assert len(first) == 1
    baseline = first[0]

    repeats = [
        make_flow(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp", timestamp=1150.0)
        for _ in range(20)
    ]
    assert feed(detector, repeats) == []

    key = BeaconKey(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp")
    assert detector._state[key].last_severity is baseline.severity
    assert detector._windows.get(key).attempts == 26


def test_more_genuine_intervals_raise_persistence():
    """4. Real additional contacts do increase the score.

    Zero cooldown so every qualifying contact re-scores - otherwise the
    intermediate rises are suppressed and invisible from outside.
    """
    config = C2BeaconingConfig(
        window_seconds=900.0,
        min_observations=6,
        min_mean_interval_seconds=2.0,
        max_mean_interval_seconds=120.0,
        max_interval_cv=0.20,
        cooldown_seconds=0.0,
    )

    def score_for(count: int) -> float:
        detector = C2BeaconingDetector(config)
        return feed(detector, beacon_flows(count, 30.0))[-1].score

    assert score_for(12) > score_for(6)
    assert score_for(18) > score_for(12)


def test_duplicates_do_not_raise_persistence_even_without_cooldown():
    """3/4. With cooldown off, duplicates still must not move the score."""
    config = C2BeaconingConfig(
        window_seconds=900.0,
        min_observations=6,
        min_mean_interval_seconds=2.0,
        max_mean_interval_seconds=120.0,
        max_interval_cv=0.20,
        cooldown_seconds=0.0,
    )
    detector = C2BeaconingDetector(config)

    baseline = feed(detector, beacon_flows(6, 30.0))[-1]
    repeats = [
        make_flow(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp", timestamp=1150.0)
        for _ in range(15)
    ]
    after = feed(detector, repeats)

    # Every repeat re-qualifies (cooldown is off) but none scores higher.
    assert after
    for alert in after:
        assert alert.score == baseline.score
        assert alert.severity is baseline.severity


def test_more_regular_beacons_score_higher(config):
    def score_for(intervals) -> float:
        detector = C2BeaconingDetector(config)
        return feed(detector, beacon_flows(6, intervals))[0].score

    assert score_for(30.0) > score_for([27.0, 33.0]) > score_for(CV_AT_BOUND)


def test_longer_beacons_score_higher(config):
    """Persistence raises the score as history accumulates."""
    detector = C2BeaconingDetector(config)
    alerts = feed(detector, beacon_flows(30, 30.0))

    assert len(alerts) >= 2
    assert alerts[-1].score > alerts[0].score


def test_score_saturates_at_one(config):
    detector = C2BeaconingDetector(config)
    alerts = feed(detector, beacon_flows(40, 20.0))
    assert alerts[-1].score == 1.0
    assert alerts[-1].severity is Severity.CRITICAL


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.50, Severity.LOW),
        (0.59, Severity.LOW),
        (0.60, Severity.MEDIUM),
        (0.75, Severity.HIGH),
        (0.90, Severity.CRITICAL),
        (1.00, Severity.CRITICAL),
    ],
)
def test_severity_mapping_is_deterministic(score, expected):
    assert C2BeaconingDetector._severity(score) is expected


@pytest.mark.parametrize(
    ("drifted", "expected"),
    [
        (0.5999999999999999, Severity.MEDIUM),
        (0.7499999999999999, Severity.HIGH),
        (0.8999999999999999, Severity.CRITICAL),
    ],
)
def test_float_drift_below_a_boundary_classifies_upward(drifted, expected):
    assert C2BeaconingDetector._severity(drifted) is expected


# --------------------------------------------------------------------------
# 19-22. Cooldown and escalation
# --------------------------------------------------------------------------


def test_first_qualifying_beacon_alerts_and_enters_cooldown(detector):
    """19."""
    alerts = feed(detector, beacon_flows(6))
    assert len(alerts) == 1

    key = BeaconKey(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp")
    state = detector._state[key]
    assert state.last_alert_at == pytest.approx(1150.0)
    assert state.last_severity is alerts[0].severity


def test_same_severity_during_cooldown_is_suppressed(detector):
    """20. Contacts 7-12 stay in the same band and stay quiet."""
    alerts = feed(detector, beacon_flows(12, 30.0))
    severities = [a.severity for a in alerts]

    assert severities == sorted(set(severities), key=severities.index)
    assert len(severities) == len(set(severities))


def test_higher_severity_during_cooldown_is_allowed(detector):
    """21. A perfect beacon starts HIGH and escalates to CRITICAL."""
    alerts = feed(detector, beacon_flows(20, 30.0))

    assert [a.severity for a in alerts] == [Severity.HIGH, Severity.CRITICAL]
    # The escalation lands well inside the 300s cooldown.
    gap = alerts[1].event_end.timestamp() - alerts[0].event_end.timestamp()
    assert gap < detector.config.cooldown_seconds


def test_escalation_alerts_are_strictly_increasing(detector):
    """Within one cooldown, each alert must outrank the one before it.

    20 contacts at 30s span 570s, so the run stays inside the 300s cooldown
    from the escalation and no ordinary post-cooldown alert joins in.
    """
    ranks = [
        [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL].index(
            a.severity
        )
        for a in feed(detector, beacon_flows(20, 30.0))
    ]
    assert ranks == sorted(ranks)
    assert len(ranks) == len(set(ranks))


def test_a_long_beacon_realerts_once_the_cooldown_lapses(detector):
    """Sustained beaconing keeps reporting - it does not go silent forever."""
    alerts = feed(detector, beacon_flows(30, 30.0))

    assert [a.severity for a in alerts] == [
        Severity.HIGH,
        Severity.CRITICAL,
        Severity.CRITICAL,
    ]
    # The repeat is a fresh post-cooldown alert, not an escalation.
    gap = alerts[2].event_end.timestamp() - alerts[1].event_end.timestamp()
    assert gap >= detector.config.cooldown_seconds


def test_alert_allowed_again_after_cooldown(short_cooldown_config):
    """22. Same severity, but the cooldown has expired."""
    detector = C2BeaconingDetector(short_cooldown_config)
    alerts = feed(detector, beacon_flows(9, 30.0))

    assert len(alerts) >= 2
    assert alerts[0].severity is alerts[1].severity


def test_cooldown_is_per_relationship(detector):
    """State is per relationship, never global."""
    first = feed(detector, beacon_flows(6, dst="203.0.113.1"))
    second = feed(detector, beacon_flows(6, dst="203.0.113.2", start=1010.0))

    assert len(first) == 1 and len(second) == 1
    assert {first[0].dst_ip, second[0].dst_ip} == {"203.0.113.1", "203.0.113.2"}


# --------------------------------------------------------------------------
# 30-32. Coexistence with the other detectors
# --------------------------------------------------------------------------


def test_engine_runs_all_three_detectors(config):
    """30."""
    engine = DetectionEngine(
        [PortScanDetector(), DDoSDetector(), C2BeaconingDetector(config)]
    )
    alerts = list(engine.run(beacon_flows(6)))

    assert len(alerts) == 1
    assert alerts[0].detector == "c2_beaconing"
    assert engine.stats.detector_errors == 0
    assert engine.stats.flows_processed == 6


def test_port_scan_traffic_does_not_trigger_c2(config):
    """31. Each (src, dst, port) is touched once - no repetition at all."""
    detector = C2BeaconingDetector(config)
    flows = [
        make_flow(
            src_ip="10.0.0.66",
            dst_ip=f"10.0.1.{i}",
            dst_port=1000 + i,
            timestamp=1000.0 + i * 0.5,
        )
        for i in range(60)
    ]
    assert feed(detector, flows) == []


def test_ddos_traffic_does_not_trigger_c2(config):
    """32. Flood cadence is far faster than min_mean_interval_seconds."""
    detector = C2BeaconingDetector(config)
    flows = []
    ts = 1000.0
    for _ in range(10):
        for s in range(5):
            flows.append(
                make_flow(
                    src_ip=f"10.1.0.{s}",
                    dst_ip="10.0.0.200",
                    dst_port=80,
                    timestamp=ts,
                )
            )
            ts += 0.01
    assert feed(detector, flows) == []


def test_beacon_traffic_does_not_trigger_the_other_detectors(config):
    """A beacon is one source, one host, one port - neither scan nor flood."""
    port_scan = PortScanDetector(PortScanConfig(min_unique_ports=5, min_unique_hosts=4))
    ddos = DDoSDetector(DDoSConfig(min_unique_sources=5, min_flows=10, min_packets=100))

    flows = beacon_flows(20, 30.0)
    assert feed(port_scan, flows) == []
    assert feed(ddos, flows) == []


def test_three_detectors_keep_independent_state(config):
    """30. A mixed capture routes each pattern to exactly one detector."""
    engine = DetectionEngine(
        [
            PortScanDetector(PortScanConfig(min_unique_ports=5, min_unique_hosts=99)),
            DDoSDetector(DDoSConfig(min_unique_sources=5, min_flows=10, min_packets=10**9)),
            C2BeaconingDetector(config),
        ]
    )

    beacon = beacon_flows(6)
    scan = [
        make_flow(
            src_ip="10.0.0.66", dst_ip="10.0.0.80", dst_port=p, timestamp=2000.0 + i
        )
        for i, p in enumerate([22, 23, 25, 80, 443])
    ]
    flood = []
    ts = 3000.0
    for _ in range(2):
        for s in range(5):
            flood.append(
                make_flow(
                    src_ip=f"10.2.0.{s}",
                    dst_ip="10.0.0.90",
                    dst_port=80,
                    timestamp=ts,
                )
            )
            ts += 0.01

    alerts = list(engine.run(beacon + scan + flood))
    detectors_that_fired = {a.detector for a in alerts}

    assert detectors_that_fired == {"c2_beaconing", "port_scan", "ddos"}
    assert sum(a.detector == "c2_beaconing" for a in alerts) == 1
    assert sum(a.detector == "port_scan" for a in alerts) == 1
    assert sum(a.detector == "ddos" for a in alerts) == 1
