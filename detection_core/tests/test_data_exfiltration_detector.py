"""DataExfiltrationDetector tests.

Numbered comments map to the acceptance list: direction, qualification by
both paths, concentration arithmetic, isolation, expiry, alert conformance,
scoring, cooldown and escalation, reset, and coexistence with the other four
detectors.

The single most important test in this file is
``test_large_download_is_never_exfiltration``: a big download has a huge
``resp_bytes`` and a tiny ``orig_bytes``, and must never be reported as data
leaving the network.
"""

from __future__ import annotations

import pytest

from detection_core import (
    C2BeaconingConfig,
    C2BeaconingDetector,
    DataExfiltrationConfig,
    DataExfiltrationDetector,
    DDoSConfig,
    DDoSDetector,
    DetectionEngine,
    DnsInfo,
    DnsTunnellingConfig,
    DnsTunnellingDetector,
    EventScope,
    ExfilKey,
    PortScanConfig,
    PortScanDetector,
    ScoreType,
    Severity,
    ThreatAlert,
    ThreatClass,
)
from detection_core.detectors.scoring import severity_rank
from detection_core.detectors.data_exfiltration import (
    QUALIFICATION_BOTH,
    QUALIFICATION_SINGLE,
    QUALIFICATION_SUSTAINED,
)

from .conftest import make_flow

MIB = 1024 * 1024
SRC = "10.0.0.30"
DST = "203.0.113.77"


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------


def exfil_flow(
    timestamp: float,
    orig_bytes: int,
    *,
    src: str = SRC,
    dst: str = DST,
    resp_bytes: int = 0,
    orig_pkts: int = 1,
    dst_port: int | None = 443,
    proto: str = "tcp",
    **overrides,
):
    """A flow with explicit directional volume - orig is what left the host."""
    return make_flow(
        timestamp=timestamp,
        src_ip=src,
        dst_ip=dst,
        dst_port=dst_port,
        proto=proto,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
        orig_pkts=orig_pkts,
        **overrides,
    )


def upload_burst(count: int, each: int, *, start: float = 1000.0, step: float = 1.0, **kw):
    """``count`` outbound transfers of ``each`` bytes to one destination."""
    return [exfil_flow(start + i * step, each, **kw) for i in range(count)]


def feed(detector, flows) -> list[ThreatAlert]:
    alerts: list[ThreatAlert] = []
    for flow in flows:
        alerts.extend(detector.process(flow))
    return alerts


@pytest.fixture
def config() -> DataExfiltrationConfig:
    return DataExfiltrationConfig(
        window_seconds=300.0,
        min_total_orig_bytes=50 * MIB,
        min_flows=10,
        min_single_flow_orig_bytes=100 * MIB,
        min_destination_concentration=0.60,
        cooldown_seconds=300.0,
    )


@pytest.fixture
def detector(config) -> DataExfiltrationDetector:
    return DataExfiltrationDetector(config)


# --------------------------------------------------------------------------
# 1-3. Ordinary traffic, downloads, and sub-threshold uploads
# --------------------------------------------------------------------------


def test_ordinary_small_traffic_does_not_alert(detector):
    """Normal browsing-sized flows never approach the byte thresholds."""
    flows = upload_burst(200, 4096, resp_bytes=64 * 1024)
    assert feed(detector, flows) == []


def test_large_download_is_never_exfiltration(detector):
    """THE critical case: huge resp_bytes, tiny orig_bytes -> no alert.

    Somebody pulling a 10 GB dataset sends only small requests. If volume
    were measured as orig+resp this would be the loudest alert in the
    system, and it would be completely wrong.
    """
    flows = upload_burst(50, 1500, resp_bytes=200 * MIB)
    alerts = feed(detector, flows)

    assert alerts == []


def test_enormous_download_still_does_not_alert(detector):
    """Scaling the download up must not eventually trip a threshold."""
    flows = upload_burst(500, 200, resp_bytes=2048 * MIB)
    assert feed(detector, flows) == []


def test_response_bytes_do_not_inflate_outbound_volume(detector, config):
    """A qualifying upload reports resp_bytes as context, never as volume."""
    flows = upload_burst(12, 5 * MIB, resp_bytes=900 * MIB)
    alert = feed(detector, flows)[0]

    # The alert lands on the 10th flow - the one that crossed both bars.
    assert alert.evidence["total_orig_bytes"] == 10 * 5 * MIB
    assert alert.evidence["total_resp_bytes"] == 10 * 900 * MIB
    # The verdict rests entirely on the outbound figure.
    assert alert.evidence["total_orig_bytes"] < alert.evidence["total_resp_bytes"]

    # Identical upload with no response stream at all scores the same: this
    # environment may be genuinely unidirectional.
    quiet = DataExfiltrationDetector(config)
    quiet_alert = feed(quiet, upload_burst(12, 5 * MIB, resp_bytes=0))[0]
    assert quiet_alert.score == alert.score
    assert quiet_alert.evidence["total_resp_bytes"] == 0


def test_large_outbound_below_threshold_does_not_alert(detector):
    """40 MiB out is a lot, but it is under the configured 50 MiB bar."""
    flows = upload_burst(20, 2 * MIB)  # 40 MiB total
    assert feed(detector, flows) == []


# --------------------------------------------------------------------------
# 4. Concentration keeps distributed activity quiet
# --------------------------------------------------------------------------


def test_bytes_spread_across_destinations_do_not_qualify(detector):
    """Each pair clears the byte and flow bars but not concentration.

    Five destinations, 60 MiB and 12 flows each: every pair passes the
    sustained volume test on its own, yet each holds only a fifth of the
    source's outbound traffic, so none of them is where the data went.
    """
    flows = []
    for i in range(12):
        for d in range(5):
            flows.append(
                exfil_flow(1000.0 + i, 5 * MIB, dst=f"203.0.113.{10 + d}")
            )
    alerts = feed(detector, flows)

    assert alerts == []


def test_concentration_rises_as_one_destination_dominates(detector, config):
    """The same total, funnelled at one peer instead of spread, does alert."""
    spread = feed(
        detector,
        [
            exfil_flow(1000.0 + i, 5 * MIB, dst=f"203.0.113.{10 + (i % 5)}")
            for i in range(60)
        ],
    )
    assert spread == []

    focused = DataExfiltrationDetector(config)
    alerts = feed(focused, upload_burst(60, 5 * MIB))
    assert len(alerts) >= 1
    assert alerts[0].evidence["destination_concentration"] == 1.0


# --------------------------------------------------------------------------
# 5-8. The two qualification paths
# --------------------------------------------------------------------------


def test_sustained_transfer_alerts(detector, config):
    """Chunked exfiltration: enough bytes, enough flows, concentrated."""
    alerts = feed(detector, upload_burst(12, 5 * MIB))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.threat_class is ThreatClass.DATA_EXFILTRATION
    assert alert.evidence["qualification_path"] == QUALIFICATION_SUSTAINED
    # Emitted the moment both bars were met: 10 flows, 50 MiB.
    assert alert.evidence["flow_count"] == 10
    assert alert.evidence["total_orig_bytes"] == 50 * MIB


def test_alert_fires_on_the_flow_that_crosses_the_threshold(detector):
    """Emitted immediately from process(), not held for flush()."""
    flows = upload_burst(12, 5 * MIB)
    # 10 flows x 5 MiB = 50 MiB and 10 flows: both bars met exactly here.
    early = feed(detector, flows[:9])
    assert early == []

    crossing = detector.process(flows[9])
    assert len(crossing) == 1
    assert crossing[0].evidence["flow_count"] == 10


def test_enough_bytes_but_too_few_flows_does_not_take_the_sustained_path(detector):
    """60 MiB in 3 flows is not 'sustained', and is under the single bar."""
    flows = upload_burst(3, 20 * MIB)
    assert feed(detector, flows) == []


def test_single_large_transfer_alerts(detector):
    """One bulk upload needs no repetition to be worth seeing."""
    alerts = feed(detector, [exfil_flow(1000.0, 150 * MIB)])

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.evidence["qualification_path"] == QUALIFICATION_SINGLE
    assert alert.evidence["flow_count"] == 1
    assert alert.evidence["max_single_flow_orig_bytes"] == 150 * MIB


def test_single_flow_just_below_threshold_does_not_alert(detector):
    """99 MiB in one flow misses the 100 MiB single-transfer bar."""
    assert feed(detector, [exfil_flow(1000.0, 99 * MIB)]) == []


def test_both_paths_qualifying_is_reported_honestly(detector):
    """When both routes fire the evidence says so rather than picking one.

    The single path fires on the very first 150 MiB flow, so the earliest
    alert is legitimately ``single_large_transfer``; ``both`` appears once
    the flow count has caught up and the severity escalates.
    """
    alerts = feed(detector, upload_burst(11, 150 * MIB))

    assert alerts[0].evidence["qualification_path"] == QUALIFICATION_SINGLE
    paths = [a.evidence["qualification_path"] for a in alerts]
    assert QUALIFICATION_BOTH in paths


def test_single_transfer_path_scores_without_many_flows(detector):
    """The single path must not be penalised for its low flow count."""
    single = feed(detector, [exfil_flow(1000.0, 400 * MIB)])[0]

    assert single.score > 0.5
    assert single.evidence["flow_count"] == 1


# --------------------------------------------------------------------------
# 9-13. Concentration arithmetic
# --------------------------------------------------------------------------


def test_source_and_pair_totals_are_measured_correctly(detector):
    """Explicit hand-checked arithmetic for both numerator and denominator."""
    flows = []
    # 4 flows x 5 MiB elsewhere = 20 MiB, same source, same window. Fed
    # first, so they are already in the denominator when the pair qualifies.
    for i in range(4):
        flows.append(exfil_flow(1000.0 + i, 5 * MIB, dst="198.51.100.4"))
    # 10 flows x 6 MiB to the target; the last one crosses both bars and
    # is the moment the alert measures.
    for i in range(10):
        flows.append(exfil_flow(1010.0 + i, 6 * MIB))

    alerts = feed(detector, flows)
    assert len(alerts) == 1
    evidence = alerts[0].evidence

    assert evidence["flow_count"] == 10
    assert evidence["total_orig_bytes"] == 10 * 6 * MIB
    assert evidence["source_total_orig_bytes"] == 10 * 6 * MIB + 4 * 5 * MIB
    assert evidence["destination_concentration"] == pytest.approx(
        (10 * 6 * MIB) / (10 * 6 * MIB + 4 * 5 * MIB)
    )
    assert evidence["max_single_flow_orig_bytes"] == 6 * MIB
    assert evidence["total_orig_packets"] == 10


def test_concentration_of_a_sole_destination_is_exactly_one(detector):
    """Everything to one peer means concentration 1.0, never 1.0000001."""
    alert = feed(detector, upload_burst(12, 5 * MIB))[0]
    assert alert.evidence["destination_concentration"] == 1.0


def test_concentration_is_never_above_one(detector):
    """Across messy interleaved traffic the ratio stays bounded."""
    flows = []
    for i in range(80):
        flows.append(exfil_flow(1000.0 + i * 0.5, 2 * MIB))
        flows.append(exfil_flow(1000.0 + i * 0.5, 3 * MIB, dst="198.51.100.9"))
        flows.append(exfil_flow(1000.0 + i * 0.5, 1 * MIB, src="10.0.0.31"))
    for alert in feed(detector, flows):
        assert 0.0 <= alert.evidence["destination_concentration"] <= 1.0


def test_zero_byte_flows_are_safe(detector):
    """A source that sent nothing has no concentration - and no crash."""
    flows = [exfil_flow(1000.0 + i, 0, resp_bytes=1024) for i in range(100)]
    assert feed(detector, flows) == []


def test_concentration_denominator_zero_returns_zero(detector):
    """Zero outbound bytes must read as 0.0 concentration, not 1.0.

    0.0 is the reading that cannot qualify. Returning 1.0 - or dividing by
    an epsilon - would let a pair that moved no data clear the gate.
    """
    assert detector._concentration(0, 0) == 0.0
    assert detector._concentration(5, 0) == 0.0


@pytest.mark.parametrize(
    "pair_bytes,source_bytes,expected",
    [
        (0, 100, 0.0),
        (50, 100, 0.5),
        (100, 100, 1.0),
        (100, 0, 0.0),
        # Defence in depth: a broken invariant caps rather than exceeding 1.
        (200, 100, 1.0),
    ],
)
def test_concentration_stays_within_unit_range(detector, pair_bytes, source_bytes, expected):
    assert detector._concentration(pair_bytes, source_bytes) == expected


# --------------------------------------------------------------------------
# 14-17. Isolation and expiry
# --------------------------------------------------------------------------


def test_different_sources_are_isolated(detector):
    """Ten hosts uploading a little is not one host uploading a lot."""
    flows = []
    for host in range(10):
        for i in range(12):
            flows.append(exfil_flow(1000.0 + i, 1 * MIB, src=f"10.0.1.{host}"))
    assert feed(detector, flows) == []


def test_different_destinations_never_pool_their_bytes(detector):
    """Bytes to two peers must not add up into one pair's verdict."""
    flows = []
    for i in range(12):
        flows.append(exfil_flow(1000.0 + i, 3 * MIB, dst="203.0.113.1"))
        flows.append(exfil_flow(1000.0 + i, 3 * MIB, dst="203.0.113.2"))
    # 36 MiB each - under the 50 MiB bar - and 72 MiB combined, which must
    # never be attributed to either destination.
    assert feed(detector, flows) == []


def test_window_expiry_stops_old_bytes_contributing(detector):
    """A slow drip never accumulates: each flow ages out before the next.

    120 MiB total, but spread so only a couple of flows are ever
    co-resident in the 300s window.
    """
    flows = [exfil_flow(1000.0 + i * 200.0, 5 * MIB) for i in range(24)]
    assert feed(detector, flows) == []


def test_bytes_outside_the_window_are_dropped(detector, config):
    """Two bursts either side of the window never merge into one total."""
    flows = upload_burst(6, 5 * MIB, start=1000.0)
    flows += upload_burst(6, 5 * MIB, start=1000.0 + config.window_seconds * 2)
    assert feed(detector, flows) == []


def test_source_window_expires_with_the_pair_window(detector):
    """The concentration denominator ages on the same clock as its numerator.

    Old traffic to another destination must not linger in the source total
    and hold concentration artificially down after it has expired.
    """
    # Long-past traffic elsewhere - deliberately too few flows to qualify
    # on its own - then a concentrated burst long after it has expired.
    flows = [exfil_flow(1000.0 + i, 40 * MIB, dst="198.51.100.7") for i in range(4)]
    flows += upload_burst(12, 5 * MIB, start=5000.0)
    alerts = feed(detector, flows)

    assert len(alerts) == 1
    # The expired 160 MiB is gone from the denominator entirely: the source
    # total equals the pair total at the crossing flow, nothing more.
    assert alerts[0].evidence["source_total_orig_bytes"] == 50 * MIB
    assert alerts[0].evidence["total_orig_bytes"] == 50 * MIB
    assert alerts[0].evidence["destination_concentration"] == 1.0


# --------------------------------------------------------------------------
# 18-23. Alert field conformance
# --------------------------------------------------------------------------


def test_unambiguous_port_and_protocol_are_populated(detector):
    """One port and one protocol across the window - report them."""
    alert = feed(detector, upload_burst(12, 5 * MIB, dst_port=22, proto="tcp"))[0]

    assert alert.dst_port == 22
    assert alert.protocol == "tcp"


def test_mixed_ports_report_none(detector):
    """Several ports contributed, so no single port is the answer."""
    flows = [
        exfil_flow(1000.0 + i, 5 * MIB, dst_port=440 + (i % 3)) for i in range(12)
    ]
    alert = feed(detector, flows)[0]

    assert alert.dst_port is None
    assert alert.protocol == "tcp"


def test_mixed_protocols_report_none(detector):
    """Same for protocol - no placeholder is invented."""
    flows = [
        exfil_flow(1000.0 + i, 5 * MIB, proto="tcp" if i % 2 else "udp")
        for i in range(12)
    ]
    alert = feed(detector, flows)[0]

    assert alert.protocol is None


def test_absent_port_is_safe_and_reported_as_none(detector):
    """A flow with no dst_port must not crash or invent one."""
    flows = upload_burst(12, 5 * MIB, dst_port=None)
    alert = feed(detector, flows)[0]

    assert alert.dst_port is None


def test_alert_conformance(detector):
    """Class, scope, flow_id, endpoints, score type and MITRE mapping."""
    alert = feed(detector, upload_burst(12, 5 * MIB))[0]

    assert isinstance(alert, ThreatAlert)
    assert alert.schema_version == "1.1"
    assert alert.threat_class is ThreatClass.DATA_EXFILTRATION
    assert alert.event_scope is EventScope.HOST_PAIR
    assert alert.flow_id is None
    assert alert.src_ip == SRC
    assert alert.dst_ip == DST
    assert alert.score_type is ScoreType.RULE_SCORE
    assert alert.detector == "data_exfiltration"
    assert alert.detector_version == DataExfiltrationDetector.version
    assert alert.mitre_techniques == ["T1041", "T1048"]
    assert alert.incident_id is None


def test_alert_time_span_covers_the_measured_window(detector):
    """event_start/end bracket the flows the verdict was built on."""
    alert = feed(detector, upload_burst(12, 5 * MIB))[0]

    assert alert.event_start.timestamp() == 1000.0
    assert alert.event_end.timestamp() == 1009.0
    assert alert.event_start <= alert.event_end


# --------------------------------------------------------------------------
# 28-30. Scoring and evidence
# --------------------------------------------------------------------------


def test_a_just_qualified_event_scores_exactly_one_half():
    """Exactly at every threshold is exactly the bottom of the scale.

    60 MiB on the pair against a 60 MiB bar, 10 flows against a 10-flow
    bar, and 40 MiB elsewhere so concentration is exactly 60/100 = 0.60.
    Every ratio is 1.0 and the concentration bonus contributes nothing.
    """
    config = DataExfiltrationConfig(
        window_seconds=300.0,
        min_total_orig_bytes=60 * MIB,
        min_flows=10,
        min_destination_concentration=0.60,
    )
    detector = DataExfiltrationDetector(config)

    flows = [exfil_flow(1000.0 + i, 4 * MIB, dst="198.51.100.2") for i in range(10)]
    flows += [exfil_flow(1010.0 + i, 6 * MIB, dst=DST) for i in range(10)]
    alerts = feed(detector, flows)

    assert len(alerts) == 1
    assert alerts[0].evidence["destination_concentration"] == pytest.approx(0.6)
    assert alerts[0].score == 0.5
    assert alerts[0].severity is Severity.LOW


def test_score_is_within_unit_range_across_magnitudes(detector, config):
    """Every score the detector can produce stays in [0.0, 1.0]."""
    for each in (5 * MIB, 50 * MIB, 500 * MIB, 5000 * MIB):
        fresh = DataExfiltrationDetector(config)
        for alert in feed(fresh, upload_burst(15, each)):
            assert 0.0 <= alert.score <= 1.0


def test_extreme_transfer_saturates_at_one(detector):
    """A massively over-threshold transfer clamps rather than overflowing.

    The path ratio and the concentration bonus would sum past 1.0 here;
    the score must cap instead.
    """
    alerts = feed(detector, [exfil_flow(1000.0, 100_000 * MIB)])

    assert alerts[0].score == 1.0
    assert alerts[0].severity is Severity.CRITICAL


def test_escalation_climbs_through_bands_then_stops(detector):
    """Severity rises band by band, then stays put once at the top."""
    alerts = feed(detector, upload_burst(60, 200 * MIB))

    assert all(0.0 <= a.score <= 1.0 for a in alerts)
    assert alerts[-1].severity is Severity.CRITICAL
    # The cooldown yields only to escalation, so bands strictly increase.
    ranks = [severity_rank(a.severity) for a in alerts]
    assert ranks == sorted(set(ranks))


def test_more_bytes_score_higher(detector, config):
    """Volume moves the score in the expected direction."""
    small = feed(DataExfiltrationDetector(config), upload_burst(10, 5 * MIB))[0]
    large = feed(DataExfiltrationDetector(config), upload_burst(10, 15 * MIB))[0]

    assert large.score > small.score


def test_stronger_concentration_scores_higher(detector, config):
    """Two pairs with identical volume differ only by concentration."""
    focused = feed(DataExfiltrationDetector(config), upload_burst(12, 5 * MIB))[0]

    diluted_detector = DataExfiltrationDetector(config)
    flows = []
    # Interleaved, so the diluting bytes are already in the denominator
    # at the moment the pair crosses its bars.
    for i in range(12):
        flows.append(exfil_flow(1000.0 + i, 5 * MIB))
        flows.append(exfil_flow(1000.0 + i, 2 * MIB, dst="198.51.100.3"))
    diluted = feed(diluted_detector, flows)[0]

    assert focused.evidence["destination_concentration"] == 1.0
    assert diluted.evidence["destination_concentration"] < 1.0
    assert focused.score > diluted.score


def test_a_huge_download_alongside_an_upload_does_not_raise_the_score(detector, config):
    """resp_bytes is inert: it may be reported but never scored."""
    plain = feed(DataExfiltrationDetector(config), upload_burst(12, 5 * MIB))[0]
    with_download = feed(
        DataExfiltrationDetector(config),
        upload_burst(12, 5 * MIB, resp_bytes=4096 * MIB),
    )[0]

    assert with_download.score == plain.score
    assert with_download.severity is plain.severity


def test_severity_bands_are_deterministic(detector, config):
    """Identical input always lands in the same band."""
    runs = [
        feed(DataExfiltrationDetector(config), upload_burst(20, 8 * MIB))[0]
        for _ in range(3)
    ]
    assert len({a.score for a in runs}) == 1
    assert len({a.severity for a in runs}) == 1


def test_evidence_matches_actual_rolling_calculations(detector, config):
    """Every reported statistic recomputed by hand from the input."""
    flows = upload_burst(12, 5 * MIB, resp_bytes=1024, orig_pkts=7, step=2.0)
    alert = feed(detector, flows)[0]
    evidence = alert.evidence

    # The alert fires on the 10th flow, at t=1000+9*2=1018.
    assert evidence["flow_count"] == 10
    assert evidence["total_orig_bytes"] == 10 * 5 * MIB
    assert evidence["total_orig_packets"] == 10 * 7
    assert evidence["max_single_flow_orig_bytes"] == 5 * MIB
    assert evidence["source_total_orig_bytes"] == 10 * 5 * MIB
    assert evidence["destination_concentration"] == 1.0
    assert evidence["total_resp_bytes"] == 10 * 1024
    assert evidence["observed_span_seconds"] == pytest.approx(18.0)
    assert evidence["orig_bytes_per_second"] == pytest.approx(10 * 5 * MIB / 18.0)
    assert evidence["qualification_path"] == QUALIFICATION_SUSTAINED

    # Thresholds echoed so an analyst sees what it was judged against.
    assert evidence["window_seconds"] == config.window_seconds
    assert evidence["min_total_orig_bytes"] == config.min_total_orig_bytes
    assert evidence["min_flows"] == config.min_flows
    assert evidence["min_single_flow_orig_bytes"] == config.min_single_flow_orig_bytes
    assert (
        evidence["min_destination_concentration"]
        == config.min_destination_concentration
    )


def test_rate_is_none_when_the_window_spans_no_time(detector):
    """A single-flow alert has no measurable rate - None, not a fudge."""
    alert = feed(detector, [exfil_flow(1000.0, 150 * MIB)])[0]

    assert alert.evidence["observed_span_seconds"] == 0.0
    assert alert.evidence["orig_bytes_per_second"] is None


# --------------------------------------------------------------------------
# 31-35. Cooldown, escalation and reset
# --------------------------------------------------------------------------


@pytest.fixture
def escalation_config() -> DataExfiltrationConfig:
    return DataExfiltrationConfig(
        window_seconds=3600.0,
        min_total_orig_bytes=50 * MIB,
        min_flows=10,
        min_single_flow_orig_bytes=100 * MIB,
        min_destination_concentration=0.60,
        cooldown_seconds=600.0,
    )


def test_cooldown_suppresses_the_same_severity(escalation_config):
    """A steady transfer alerts once, not once per flow."""
    detector = DataExfiltrationDetector(escalation_config)

    first = feed(detector, upload_burst(10, 5 * MIB))
    assert len(first) == 1

    # More of exactly the same, still inside the cooldown.
    more = feed(detector, upload_burst(2, 5 * MIB, start=1010.0))
    assert more == []


def test_rising_severity_escapes_the_cooldown(escalation_config):
    """Escalation is news worth interrupting for."""
    detector = DataExfiltrationDetector(escalation_config)

    first = feed(detector, upload_burst(10, 5 * MIB))
    assert len(first) == 1
    # Exactly at both bars (0.5) plus the full concentration bonus.
    assert first[0].severity is Severity.MEDIUM

    escalated = feed(detector, upload_burst(30, 40 * MIB, start=1010.0))

    assert escalated, "a strictly higher severity band must escape the cooldown"
    assert all(
        severity_rank(a.severity) > severity_rank(Severity.MEDIUM) for a in escalated
    )


def test_cooldown_expiry_allows_alerting_again(escalation_config):
    """After the cooldown elapses the same behaviour reports again."""
    detector = DataExfiltrationDetector(escalation_config)

    first = feed(detector, upload_burst(10, 5 * MIB))
    assert len(first) == 1
    last_alert_at = 1009.0

    assert feed(detector, upload_burst(1, 5 * MIB, start=1100.0)) == []

    later = feed(
        detector,
        upload_burst(1, 5 * MIB, start=last_alert_at + escalation_config.cooldown_seconds + 1),
    )
    assert len(later) == 1


def test_cooldown_is_per_pair(escalation_config):
    """One pair's cooldown must never silence a different pair."""
    detector = DataExfiltrationDetector(escalation_config)

    assert len(feed(detector, upload_burst(10, 5 * MIB))) == 1

    # Far enough ahead that the first burst has left the window - otherwise
    # it would (correctly) dilute the second pair's concentration.
    other = feed(
        detector, upload_burst(10, 5 * MIB, dst="203.0.113.99", start=90_000.0)
    )
    assert len(other) == 1
    assert other[0].dst_ip == "203.0.113.99"


def test_cooldown_survives_rolling_window_expiry():
    """A pair going quiet must not shed a cooldown that is still running.

    The traffic window empties long before this cooldown ends. If both were
    released together, a pair could fall silent, return, and immediately
    re-alert inside the cooldown it was still serving.
    """
    detector = DataExfiltrationDetector(
        DataExfiltrationConfig(
            window_seconds=60.0,
            min_total_orig_bytes=50 * MIB,
            min_flows=10,
            cooldown_seconds=100_000.0,
        )
    )
    key = ExfilKey(SRC, DST)

    assert len(feed(detector, upload_burst(10, 5 * MIB, step=0.1))) == 1

    # Plenty of unrelated traffic to drive the sweep while the pair is quiet.
    feed(
        detector,
        [exfil_flow(5000.0 + i, 1024, src=f"10.5.{i // 256}.{i % 256}") for i in range(1200)],
    )
    assert key in detector._state, "the live cooldown was swept away"

    # Same behaviour again, still deep inside the cooldown - stays quiet.
    assert feed(detector, upload_burst(10, 5 * MIB, start=9000.0, step=0.1)) == []


def test_expired_cooldowns_are_released():
    """Once a cooldown can no longer suppress anything it is dropped."""
    detector = DataExfiltrationDetector(
        DataExfiltrationConfig(
            window_seconds=60.0,
            min_total_orig_bytes=50 * MIB,
            min_flows=10,
            cooldown_seconds=60.0,
        )
    )
    assert len(feed(detector, upload_burst(10, 5 * MIB, step=0.1))) == 1
    assert detector._state

    feed(
        detector,
        [exfil_flow(90_000.0 + i, 1024, src=f"10.6.{i // 256}.{i % 256}") for i in range(1200)],
    )
    assert ExfilKey(SRC, DST) not in detector._state


def test_reset_clears_pair_source_and_cooldown_state(detector):
    """reset() drops every window and cooldown so a replay starts clean."""
    first = feed(detector, upload_burst(12, 5 * MIB))
    assert len(first) == 1

    detector.reset()
    assert len(detector._pairs) == 0
    assert len(detector._sources) == 0
    assert detector._state == {}

    second = feed(detector, upload_burst(12, 5 * MIB))
    assert len(second) == 1
    assert second[0].evidence["source_total_orig_bytes"] == 50 * MIB


def test_flush_emits_nothing(detector):
    """Detection happens in process(); flush() is not part of the path."""
    feed(detector, upload_burst(12, 5 * MIB))
    assert detector.flush() == []


# --------------------------------------------------------------------------
# 36-40. Coexistence with every other rule detector
# --------------------------------------------------------------------------


def all_rule_detectors() -> DetectionEngine:
    return DetectionEngine(
        [
            PortScanDetector(PortScanConfig()),
            DDoSDetector(DDoSConfig()),
            C2BeaconingDetector(C2BeaconingConfig()),
            DnsTunnellingDetector(DnsTunnellingConfig()),
            DataExfiltrationDetector(DataExfiltrationConfig()),
        ]
    )


def test_all_rule_detectors_run_together():
    """The engine drives all five with no interference or errors."""
    engine = all_rule_detectors()
    alerts = list(engine.run(upload_burst(12, 5 * MIB)))

    assert engine.stats.detector_errors == 0
    assert engine.stats.flows_processed == 12
    assert any(a.threat_class is ThreatClass.DATA_EXFILTRATION for a in alerts)


def test_port_scan_traffic_does_not_become_exfiltration():
    """Scan probes are tiny - lots of flows, almost no bytes."""
    engine = all_rule_detectors()
    flows = [
        make_flow(
            timestamp=1000.0 + i * 0.1,
            src_ip="10.0.0.5",
            dst_ip="10.0.0.9",
            dst_port=1000 + i,
            proto="tcp",
        )
        for i in range(40)
    ]
    alerts = list(engine.run(flows))

    assert any(a.threat_class is ThreatClass.PORT_SCAN for a in alerts)
    assert not any(a.threat_class is ThreatClass.DATA_EXFILTRATION for a in alerts)


def test_ddos_traffic_does_not_become_exfiltration():
    """A flood is many sources at one target - each pair sends almost nothing."""
    engine = all_rule_detectors()
    flows = [
        make_flow(
            timestamp=1000.0 + i * 0.001,
            src_ip=f"198.51.{i // 256}.{i % 256}",
            dst_ip="10.0.0.80",
            dst_port=80,
            proto="tcp",
            orig_pkts=5,
            orig_bytes=200,
        )
        for i in range(300)
    ]
    alerts = list(engine.run(flows))

    assert any(a.threat_class is ThreatClass.DDOS for a in alerts)
    assert not any(a.threat_class is ThreatClass.DATA_EXFILTRATION for a in alerts)


def test_c2_beaconing_traffic_does_not_become_exfiltration():
    """A beacon is a small regular check-in, not a bulk transfer."""
    engine = all_rule_detectors()
    flows = [
        make_flow(
            timestamp=1000.0 + i * 30.0,
            src_ip="10.0.0.50",
            dst_ip="203.0.113.10",
            dst_port=443,
            proto="tcp",
            orig_bytes=512,
        )
        for i in range(12)
    ]
    alerts = list(engine.run(flows))

    assert any(a.threat_class is ThreatClass.C2_BEACONING for a in alerts)
    assert not any(a.threat_class is ThreatClass.DATA_EXFILTRATION for a in alerts)


def test_dns_tunnelling_traffic_does_not_become_exfiltration():
    """Many DNS flows, but a DNS query is a few dozen bytes.

    Volume of *flows* must never stand in for volume of *bytes*.
    """
    engine = all_rule_detectors()
    flows = [
        make_flow(
            timestamp=1000.0 + i,
            src_ip="192.168.1.42",
            dst_ip="192.168.1.1",
            dst_port=53,
            proto="udp",
            orig_bytes=74,
            resp_bytes=190,
            dns=DnsInfo(
                query_length=110,
                query_entropy=4.9,
                subdomain_entropy=4.7,
                label_count=9,
                is_txt=True,
            ),
        )
        for i in range(60)
    ]
    alerts = list(engine.run(flows))

    assert any(a.threat_class is ThreatClass.DNS_TUNNELLING for a in alerts)
    assert not any(a.threat_class is ThreatClass.DATA_EXFILTRATION for a in alerts)


def test_registering_exfil_does_not_change_other_verdicts():
    """The other four produce identical alerts with or without this one."""
    flows = [
        make_flow(
            timestamp=1000.0 + i * 0.1,
            src_ip="10.0.0.5",
            dst_ip="10.0.0.9",
            dst_port=1000 + i,
            proto="tcp",
        )
        for i in range(40)
    ]
    flows += upload_burst(12, 5 * MIB, start=1500.0)

    without = DetectionEngine(
        [
            PortScanDetector(PortScanConfig()),
            DDoSDetector(DDoSConfig()),
            C2BeaconingDetector(C2BeaconingConfig()),
            DnsTunnellingDetector(DnsTunnellingConfig()),
        ]
    )
    baseline = [(a.threat_class, a.src_ip, a.dst_ip, a.score) for a in without.run(flows)]
    combined = [
        (a.threat_class, a.src_ip, a.dst_ip, a.score)
        for a in all_rule_detectors().run(flows)
        if a.threat_class is not ThreatClass.DATA_EXFILTRATION
    ]

    assert combined == baseline


# --------------------------------------------------------------------------
# Config validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"window_seconds": 0},
        {"window_seconds": -1.0},
        {"min_total_orig_bytes": 0},
        {"min_flows": 1},
        {"min_single_flow_orig_bytes": 0},
        {"min_destination_concentration": 0.0},
        {"min_destination_concentration": 1.5},
        {"min_destination_concentration": -0.1},
        {"cooldown_seconds": -1.0},
        {"saturation_multiple": 1.0},
        {"concentration_bonus": -0.1},
        {"concentration_bonus": 1.1},
    ],
)
def test_invalid_config_is_rejected(kwargs):
    """Nonsensical thresholds fail loudly at construction."""
    with pytest.raises(ValueError):
        DataExfiltrationConfig(**kwargs)


def test_default_config_is_valid():
    """The shipped defaults must satisfy their own validation."""
    config = DataExfiltrationConfig()

    assert config.window_seconds == 300.0
    assert config.min_total_orig_bytes == 50 * MIB
    assert config.min_flows == 10
    assert config.min_single_flow_orig_bytes == 100 * MIB
    assert config.min_destination_concentration == 0.60
    assert config.cooldown_seconds == 300.0
    assert config.saturation_multiple == 4.0
    # A single transfer gets no corroboration from repetition, so its bar
    # must sit above the sustained one.
    assert config.min_single_flow_orig_bytes > config.min_total_orig_bytes
