"""DnsTunnellingDetector tests.

Numbered comments map to the acceptance list: non-DNS handling,
qualification, pair isolation, expiry, alert conformance, scoring, cooldown
and escalation, reset, and coexistence with the other three detectors.

Every DNS field used here is one the CURRENT adapter actually produces -
``query_length``, ``query_entropy``, ``subdomain_entropy``, ``label_count``,
``is_txt``. ``dns.query`` is set only by the raw-query tests at the end, which
exist precisely to prove a FUTURE feed emitting it is reported honestly; no
other test sets ``query`` / ``qtype`` / ``rcode``, which ingestion does not
emit today.
"""

from __future__ import annotations

import pytest

from detection_core import (
    C2BeaconingConfig,
    C2BeaconingDetector,
    DDoSConfig,
    DDoSDetector,
    DetectionEngine,
    DnsInfo,
    DnsTunnelKey,
    DnsTunnellingConfig,
    DnsTunnellingDetector,
    EventScope,
    PortScanConfig,
    PortScanDetector,
    ScoreType,
    Severity,
    ThreatAlert,
    ThreatClass,
)

from .conftest import make_flow

SRC = "10.0.0.77"
RESOLVER = "10.0.0.53"


# --------------------------------------------------------------------------
# Builders - three DNS profiles plus a raw escape hatch
# --------------------------------------------------------------------------


def dns_flow(
    timestamp: float,
    *,
    src: str = SRC,
    dst: str = RESOLVER,
    query_length: int | None = 20,
    query_entropy: float | None = 3.0,
    subdomain_entropy: float | None = 0.0,
    label_count: int | None = 2,
    is_txt: bool | None = False,
    dst_port: int | None = 53,
    proto: str = "udp",
    query: str | None = None,
    **overrides,
):
    """A DNS flow carrying the derived features ingestion supplies.

    ``query`` stays ``None`` unless a test is deliberately modelling a
    future feed that emits raw query names.
    """
    return make_flow(
        timestamp=timestamp,
        src_ip=src,
        dst_ip=dst,
        dst_port=dst_port,
        proto=proto,
        dns=DnsInfo(
            uid=f"Cdns{timestamp}",
            query=query,
            query_length=query_length,
            query_entropy=query_entropy,
            subdomain_entropy=subdomain_entropy,
            label_count=label_count,
            is_txt=is_txt,
        ),
        **overrides,
    )


def normal_dns(timestamp: float, **kwargs):
    """Ordinary lookup: short, unremarkable entropy, two labels, not TXT."""
    return dns_flow(timestamp, **kwargs)


def tunnel_dns(timestamp: float, **kwargs):
    """Encoded-looking lookup: long AND high-entropy - two signals."""
    kwargs.setdefault("query_length", 72)
    kwargs.setdefault("query_entropy", 4.6)
    return dns_flow(timestamp, **kwargs)


def blatant_dns(timestamp: float, **kwargs):
    """Every signal at once: long, high entropy, deep labels, TXT."""
    kwargs.setdefault("query_length", 110)
    kwargs.setdefault("query_entropy", 4.9)
    kwargs.setdefault("subdomain_entropy", 4.7)
    kwargs.setdefault("label_count", 9)
    kwargs.setdefault("is_txt", True)
    return dns_flow(timestamp, **kwargs)


def feed(detector, flows) -> list[ThreatAlert]:
    alerts: list[ThreatAlert] = []
    for flow in flows:
        alerts.extend(detector.process(flow))
    return alerts


@pytest.fixture
def config() -> DnsTunnellingConfig:
    return DnsTunnellingConfig(
        window_seconds=300.0,
        min_dns_observations=20,
        min_suspicious_ratio=0.5,
        cooldown_seconds=300.0,
    )


@pytest.fixture
def detector(config) -> DnsTunnellingDetector:
    return DnsTunnellingDetector(config)


# --------------------------------------------------------------------------
# 1. Non-DNS traffic is ignored
# --------------------------------------------------------------------------


def test_non_dns_traffic_is_ignored(detector):
    """A flow with no dns block must not alert or accumulate any state."""
    alerts = feed(detector, [make_flow(timestamp=1000.0 + i) for i in range(200)])
    assert alerts == []
    assert detector._windows == {}


def test_non_dns_traffic_never_dilutes_a_pair(detector):
    """Non-DNS flows on the same pair must not enter the DNS window."""
    flows = []
    for i in range(30):
        flows.append(tunnel_dns(1000.0 + i))
        # Same host pair, no DNS block - must be invisible to this detector.
        flows.append(make_flow(timestamp=1000.0 + i, src_ip=SRC, dst_ip=RESOLVER))
    alerts = feed(detector, flows)

    assert len(alerts) == 1
    assert alerts[0].evidence["observation_count"] == 20
    assert alerts[0].evidence["suspicious_ratio"] == 1.0


def test_tls_or_http_only_flow_is_ignored(detector):
    """Other protocol blocks are not DNS and must not be observed."""
    from detection_core import HttpInfo

    flows = [
        make_flow(timestamp=1000.0 + i, http=HttpInfo(uri_length=200, uri_entropy=4.9))
        for i in range(100)
    ]
    assert feed(detector, flows) == []
    assert detector._windows == {}


# --------------------------------------------------------------------------
# 2-3. One observation, and too few observations, never alert
# --------------------------------------------------------------------------


def test_single_suspicious_observation_does_not_alert(detector):
    """The whole premise is repetition - one abnormal query proves nothing."""
    assert detector.process(blatant_dns(1000.0)) == []


def test_too_few_observations_do_not_alert(detector, config):
    """Below min_dns_observations, even 100% suspicious stays quiet."""
    flows = [blatant_dns(1000.0 + i) for i in range(config.min_dns_observations - 1)]
    assert feed(detector, flows) == []


def test_alert_fires_exactly_at_the_observation_threshold(detector, config):
    """Not one query early: the alert lands on the Nth observation."""
    flows = [tunnel_dns(1000.0 + i) for i in range(config.min_dns_observations)]
    alerts = feed(detector, flows)

    assert len(alerts) == 1
    assert alerts[0].evidence["observation_count"] == config.min_dns_observations


# --------------------------------------------------------------------------
# 4-6. Normal traffic, and each single signal alone, must not alert
# --------------------------------------------------------------------------


def test_many_normal_dns_observations_do_not_alert(detector):
    """200 ordinary lookups are still ordinary."""
    alerts = feed(detector, [normal_dns(1000.0 + i) for i in range(200)])
    assert alerts == []


def test_long_but_low_entropy_queries_do_not_trivially_alert(detector):
    """Length alone is one signal, and one signal is never enough.

    Long-but-boring names are real: cloud storage endpoints and CDN hosts
    are routinely 60+ characters of readable words.
    """
    flows = [
        dns_flow(1000.0 + i, query_length=90, query_entropy=2.4, label_count=3)
        for i in range(200)
    ]
    alerts = feed(detector, flows)

    assert alerts == []


def test_high_entropy_alone_does_not_alert(detector):
    """Entropy alone is one signal - short hashed names look like this."""
    flows = [
        dns_flow(1000.0 + i, query_length=18, query_entropy=4.8, label_count=2)
        for i in range(200)
    ]
    assert feed(detector, flows) == []


def test_deep_labels_alone_do_not_alert(detector):
    """Label depth alone is one signal - some CDNs nest heavily."""
    flows = [
        dns_flow(1000.0 + i, query_length=30, query_entropy=3.0, label_count=8)
        for i in range(200)
    ]
    assert feed(detector, flows) == []


def test_txt_alone_does_not_alert(detector):
    """TXT alone is one signal - SPF/DKIM/reputation lookups are TXT."""
    flows = [
        dns_flow(1000.0 + i, query_length=25, query_entropy=3.1, is_txt=True)
        for i in range(200)
    ]
    assert feed(detector, flows) == []


def test_suspicious_minority_inside_normal_traffic_does_not_alert(detector):
    """A few encoded-looking queries among many normal ones stay below ratio."""
    flows = []
    for i in range(100):
        # 1 suspicious in every 5 -> ratio 0.2, under min_suspicious_ratio.
        flows.append(tunnel_dns(1000.0 + i) if i % 5 == 0 else normal_dns(1000.0 + i))
    assert feed(detector, flows) == []


# --------------------------------------------------------------------------
# 7-8. Genuine tunnelling behaviour, and TXT's contribution
# --------------------------------------------------------------------------


def test_repeated_long_high_entropy_dns_alerts(detector):
    """Two agreeing signals, repeated across the window - the core case."""
    alerts = feed(detector, [tunnel_dns(1000.0 + i) for i in range(20)])

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.threat_class is ThreatClass.DNS_TUNNELLING
    assert alert.evidence["suspicious_observation_count"] == 20
    assert alert.evidence["mean_signals_per_suspicious_observation"] == 2.0


def test_txt_heavy_behaviour_raises_the_score(detector):
    """TXT contributes twice: as a per-query signal and as a score bonus."""
    without_txt = feed(detector, [tunnel_dns(1000.0 + i) for i in range(20)])

    detector.reset()
    with_txt = feed(
        detector, [tunnel_dns(1000.0 + i, is_txt=True) for i in range(20)]
    )

    assert len(without_txt) == 1 and len(with_txt) == 1
    assert with_txt[0].score > without_txt[0].score
    assert with_txt[0].evidence["txt_ratio"] == 1.0
    assert without_txt[0].evidence["txt_ratio"] == 0.0
    assert with_txt[0].evidence["txt_query_count"] == 20


def test_blatant_tunnel_scores_higher_than_a_marginal_one(detector):
    """More signals agreeing, more volume and more TXT must score higher."""
    marginal = feed(detector, [tunnel_dns(1000.0 + i) for i in range(20)])

    detector.reset()
    blatant = feed(detector, [blatant_dns(1000.0 + i) for i in range(60)])

    assert blatant[0].score > marginal[0].score
    assert blatant[0].evidence["mean_signals_per_suspicious_observation"] == 5.0


# --------------------------------------------------------------------------
# 9-11. Aggregation and isolation
# --------------------------------------------------------------------------


def test_repeated_source_to_same_resolver_aggregates(detector):
    """One pair's queries pool into a single window."""
    alerts = feed(detector, [tunnel_dns(1000.0 + i) for i in range(20)])

    assert len(alerts) == 1
    assert alerts[0].evidence["observation_count"] == 20
    assert len(detector._windows) == 1
    assert DnsTunnelKey(SRC, RESOLVER) in detector._windows


def test_different_sources_are_isolated(detector):
    """Ten hosts doing two queries each is not one host doing twenty."""
    flows = []
    for host in range(10):
        for i in range(2):
            flows.append(tunnel_dns(1000.0 + i, src=f"10.0.0.{100 + host}"))

    assert feed(detector, flows) == []
    assert len(detector._windows) == 10


def test_different_resolvers_are_isolated(detector):
    """One host split across four resolvers must not pool into one verdict."""
    flows = [
        tunnel_dns(1000.0 + i, dst=f"10.0.0.{53 + (i % 4)}") for i in range(40)
    ]

    assert feed(detector, flows) == []
    assert len(detector._windows) == 4


def test_the_alerting_pair_is_the_one_that_qualified(detector):
    """Background noise from other pairs must not appear in the alert."""
    flows = [normal_dns(1000.0 + i, src="10.0.0.9", dst="10.0.0.54") for i in range(30)]
    flows += [tunnel_dns(1000.0 + i) for i in range(20)]
    alerts = feed(detector, flows)

    assert len(alerts) == 1
    assert alerts[0].src_ip == SRC
    assert alerts[0].dst_ip == RESOLVER
    assert alerts[0].evidence["observation_count"] == 20


# --------------------------------------------------------------------------
# 12. Expiry
# --------------------------------------------------------------------------


def test_old_observations_expire(detector, config):
    """Queries spread beyond the window never accumulate into an alert."""
    # One query every 60s: only ~5 are ever co-resident in a 300s window.
    flows = [tunnel_dns(1000.0 + i * 60.0) for i in range(40)]
    assert feed(detector, flows) == []


def test_expiry_is_half_open(detector, config):
    """An observation exactly window_seconds old has expired.

    Matches ``aggregators.ActivityWindow`` so both windows age identically.
    """
    detector.process(tunnel_dns(1000.0))
    window = detector._windows[DnsTunnelKey(SRC, RESOLVER)]
    assert len(window) == 1

    detector.process(tunnel_dns(1000.0 + config.window_seconds))
    assert len(window) == 1  # the first one aged out exactly on the boundary


def test_a_lull_resets_the_evidence(detector):
    """A burst, a long silence, then a second burst: neither one alone fires."""
    flows = [tunnel_dns(1000.0 + i) for i in range(15)]
    flows += [tunnel_dns(9000.0 + i) for i in range(15)]
    assert feed(detector, flows) == []


def test_quiet_pairs_are_swept_out(detector):
    """Memory stays bounded across many one-off pairs."""
    flows = [
        tunnel_dns(1000.0 + i * 10.0, src=f"10.1.{i // 256}.{i % 256}")
        for i in range(600)
    ]
    feed(detector, flows)

    # The sweep runs on a fixed cadence, so the exact survivor count depends
    # on when it last fired; the point is that it is bounded well below 600.
    assert len(detector._windows) < 200


def test_window_holds_at_most_max_observations_per_key():
    """A DNS flood cannot grow one pair's window without bound."""
    detector = DnsTunnellingDetector(
        DnsTunnellingConfig(min_dns_observations=10, max_observations_per_key=50)
    )
    feed(detector, [tunnel_dns(1000.0 + i * 0.001) for i in range(500)])

    assert len(detector._windows[DnsTunnelKey(SRC, RESOLVER)]) == 50


# --------------------------------------------------------------------------
# 13-18. Alert conformance
# --------------------------------------------------------------------------


def test_score_is_within_unit_range(detector):
    """Every score the detector can produce stays in [0.0, 1.0]."""
    for count in (20, 40, 80, 200):
        detector.reset()
        alerts = feed(detector, [blatant_dns(1000.0 + i) for i in range(count)])
        for alert in alerts:
            assert 0.0 <= alert.score <= 1.0


def test_extreme_traffic_saturates_without_exceeding_one():
    """The TXT bonus on top of a maxed blend must still clamp to 1.0.

    Every component saturates only once volume has grown well past the
    threshold, which cannot happen on the first qualifying observation
    (volume is 0 there by construction) - so this reads the later,
    post-cooldown alerts.
    """
    detector = DnsTunnellingDetector(
        DnsTunnellingConfig(
            window_seconds=3600.0, min_dns_observations=20, cooldown_seconds=300.0
        )
    )
    alerts = feed(detector, [blatant_dns(1000.0 + i * 5.0) for i in range(100)])

    assert len(alerts) > 1
    assert max(a.score for a in alerts) == 1.0
    assert all(0.0 <= a.score <= 1.0 for a in alerts)
    assert alerts[-1].severity is Severity.CRITICAL


def test_alert_conformance(detector):
    """Scope, class, flow_id, endpoints, score type and MITRE mapping."""
    alert = feed(detector, [tunnel_dns(1000.0 + i) for i in range(20)])[0]

    assert isinstance(alert, ThreatAlert)
    assert alert.schema_version == "1.1"
    assert alert.threat_class is ThreatClass.DNS_TUNNELLING
    assert alert.event_scope is EventScope.HOST_PAIR
    assert alert.flow_id is None
    assert alert.src_ip == SRC
    assert alert.dst_ip == RESOLVER
    assert alert.score_type is ScoreType.RULE_SCORE
    assert alert.detector == "dns_tunnelling"
    assert alert.detector_version == DnsTunnellingDetector.version
    assert alert.mitre_techniques == ["T1071.004", "T1048.003"]
    assert alert.incident_id is None


def test_alert_time_span_covers_the_measured_window(detector):
    """event_start/end bracket the observations the verdict was built on."""
    alert = feed(detector, [tunnel_dns(1000.0 + i) for i in range(20)])[0]

    assert alert.event_start.timestamp() == 1000.0
    assert alert.event_end.timestamp() == 1019.0
    assert alert.event_start <= alert.event_end


def test_a_unanimous_window_reports_its_port_and_protocol(detector):
    """Every contributing query used :53/udp, so the aggregate may say so."""
    alert = feed(detector, [tunnel_dns(1000.0 + i) for i in range(20)])[0]
    assert alert.dst_port == 53
    assert alert.protocol == "udp"


def test_absent_port_is_reported_as_none(detector):
    """No dst_port upstream means no dst_port on the alert."""
    flows = [tunnel_dns(1000.0 + i, dst_port=None) for i in range(20)]
    alert = feed(detector, flows)[0]

    assert alert.dst_port is None
    assert alert.protocol == "udp"


def test_evidence_matches_actual_measurements(detector, config):
    """Every reported statistic is recomputed by hand from the input."""
    flows = [tunnel_dns(1000.0 + i, is_txt=(i % 2 == 0)) for i in range(20)]
    alert = feed(detector, flows)[0]
    evidence = alert.evidence

    assert evidence["observation_count"] == 20
    assert evidence["suspicious_observation_count"] == 20
    assert evidence["suspicious_ratio"] == 1.0
    assert evidence["mean_query_length"] == 72.0
    assert evidence["max_query_length"] == 72
    assert evidence["mean_query_entropy"] == pytest.approx(4.6)
    assert evidence["max_query_entropy"] == pytest.approx(4.6)
    assert evidence["mean_subdomain_entropy"] == 0.0
    assert evidence["mean_label_count"] == 2.0
    assert evidence["max_label_count"] == 2
    # 10 of 20 were TXT, and TXT is the third signal on exactly those.
    assert evidence["txt_query_count"] == 10
    assert evidence["txt_ratio"] == 0.5
    assert evidence["mean_signals_per_suspicious_observation"] == 2.5
    assert evidence["total_orig_bytes"] == 20 * 100

    # Thresholds are echoed so an analyst can see what it was judged against.
    assert evidence["window_seconds"] == config.window_seconds
    assert evidence["min_dns_observations"] == config.min_dns_observations
    assert evidence["min_suspicious_ratio"] == config.min_suspicious_ratio
    assert evidence["suspicious_query_length"] == config.suspicious_query_length
    assert evidence["suspicious_entropy"] == config.suspicious_entropy
    assert evidence["raw_query_available"] is False


def test_evidence_ratios_are_self_consistent(detector):
    """suspicious_ratio must equal the two counts it is derived from."""
    flows = [tunnel_dns(1000.0 + i) if i % 3 else normal_dns(1000.0 + i) for i in range(60)]
    alerts = feed(detector, flows)

    for alert in alerts:
        evidence = alert.evidence
        assert evidence["suspicious_ratio"] == pytest.approx(
            evidence["suspicious_observation_count"] / evidence["observation_count"]
        )
        assert 0.0 <= evidence["suspicious_ratio"] <= 1.0


# --------------------------------------------------------------------------
# 19. Missing / partial DNS fields
# --------------------------------------------------------------------------


def test_empty_dns_block_is_safe(detector):
    """A dns block with every field None must not crash or alert."""
    flows = [
        make_flow(timestamp=1000.0 + i, src_ip=SRC, dst_ip=RESOLVER, dns=DnsInfo())
        for i in range(100)
    ]
    alerts = feed(detector, flows)

    assert alerts == []
    assert len(detector._windows[DnsTunnelKey(SRC, RESOLVER)]) == 100


def test_missing_fields_are_never_defaulted_to_zero(detector):
    """A None query_length must not read as a short query, nor None as 0.

    If absent numerics were coerced to 0 these queries would look tiny and
    boring; if absent flags read as False they would silently vote "not
    TXT". Either way the honest answer is that the field contributed no
    signal, so this stays under the ratio and never alerts.
    """
    flows = [
        dns_flow(
            1000.0 + i,
            query_length=None,
            query_entropy=None,
            subdomain_entropy=None,
            label_count=None,
            is_txt=None,
        )
        for i in range(100)
    ]
    assert feed(detector, flows) == []


def test_partial_fields_still_detect_and_report_only_what_was_measured(detector):
    """Two available signals are enough; absent ones report None, not 0."""
    flows = [
        dns_flow(
            1000.0 + i,
            query_length=80,
            query_entropy=4.7,
            subdomain_entropy=None,
            label_count=None,
            is_txt=None,
        )
        for i in range(20)
    ]
    alert = feed(detector, flows)[0]

    assert alert.evidence["mean_query_length"] == 80.0
    assert alert.evidence["mean_query_entropy"] == pytest.approx(4.7)
    # Never measured -> None, never a fabricated zero.
    assert alert.evidence["mean_subdomain_entropy"] is None
    assert alert.evidence["mean_label_count"] is None
    assert alert.evidence["max_label_count"] is None
    assert alert.evidence["txt_ratio"] is None
    assert alert.evidence["txt_query_count"] == 0


def test_mixed_availability_means_cover_only_reporting_observations(detector):
    """A mean is over the queries that carried the field, not the window."""
    flows = []
    for i in range(20):
        # Half report a length of 100; half report none at all.
        flows.append(
            dns_flow(
                1000.0 + i,
                query_length=100 if i % 2 == 0 else None,
                query_entropy=4.7,
                label_count=7,
            )
        )
    alert = feed(detector, flows)[0]

    assert alert.evidence["mean_query_length"] == 100.0
    assert alert.evidence["max_query_length"] == 100


def test_partially_reported_txt_ratio_ignores_unreported_flags(detector):
    """txt_ratio is over queries that stated is_txt, not the whole window."""
    flows = []
    for i in range(20):
        flows.append(tunnel_dns(1000.0 + i, is_txt=True if i < 5 else None))
    alert = feed(detector, flows)[0]

    assert alert.evidence["txt_query_count"] == 5
    assert alert.evidence["txt_ratio"] == 1.0  # 5 of the 5 that reported


# --------------------------------------------------------------------------
# 20-21. Cooldown and escalation
# --------------------------------------------------------------------------


@pytest.fixture
def escalation_config() -> DnsTunnellingConfig:
    return DnsTunnellingConfig(
        window_seconds=3600.0,
        min_dns_observations=10,
        min_suspicious_ratio=0.5,
        cooldown_seconds=600.0,
    )


def test_cooldown_suppresses_the_same_severity(escalation_config):
    """A steady tunnel alerts once, not once per query."""
    detector = DnsTunnellingDetector(escalation_config)

    flows = [normal_dns(1000.0 + i) for i in range(5)]
    flows += [tunnel_dns(1010.0 + i) for i in range(5)]  # 10th obs -> first alert
    first = feed(detector, flows)
    assert len(first) == 1
    assert first[0].severity is Severity.LOW

    # One more suspicious query nudges the score inside the same band.
    more = feed(detector, [tunnel_dns(1020.0)])
    assert more == []


def test_rising_severity_escapes_the_cooldown(escalation_config):
    """Escalation is news worth interrupting for."""
    detector = DnsTunnellingDetector(escalation_config)

    flows = [normal_dns(1000.0 + i) for i in range(5)]
    flows += [tunnel_dns(1010.0 + i) for i in range(5)]
    first = feed(detector, flows)
    assert len(first) == 1
    assert first[0].severity is Severity.LOW

    # Well inside the cooldown, but the behaviour has clearly worsened.
    escalated = feed(detector, [blatant_dns(1020.0 + i) for i in range(20)])

    assert escalated, "a strictly higher severity band must escape the cooldown"
    assert escalated[0].severity is not Severity.LOW
    ranks = [a.severity for a in escalated]
    assert Severity.LOW not in ranks


def test_cooldown_expiry_allows_alerting_again(escalation_config):
    """After the cooldown elapses the same behaviour reports again."""
    detector = DnsTunnellingDetector(escalation_config)

    flows = [tunnel_dns(1000.0 + i) for i in range(10)]
    assert len(feed(detector, flows)) == 1

    # Still inside the cooldown - silent.
    assert feed(detector, [tunnel_dns(1100.0)]) == []

    # Past it - reports again. The cooldown runs from the observation that
    # alerted (t=1009.0), not from the first flow of the burst.
    later = feed(detector, [tunnel_dns(1009.0 + escalation_config.cooldown_seconds + 1)])
    assert len(later) == 1


def test_cooldown_is_per_pair(escalation_config):
    """One pair's cooldown must never silence a different pair."""
    detector = DnsTunnellingDetector(escalation_config)

    assert len(feed(detector, [tunnel_dns(1000.0 + i) for i in range(10)])) == 1
    second = feed(
        detector, [tunnel_dns(1000.0 + i, src="10.0.0.99") for i in range(10)]
    )
    assert len(second) == 1
    assert second[0].src_ip == "10.0.0.99"


# --------------------------------------------------------------------------
# 22. reset()
# --------------------------------------------------------------------------


def test_reset_clears_windows_and_cooldown(detector):
    """reset() drops rolling state so a replay cannot inherit the last one."""
    first = feed(detector, [tunnel_dns(1000.0 + i) for i in range(20)])
    assert len(first) == 1

    detector.reset()
    assert detector._windows == {}
    assert detector._state == {}

    # Identical traffic alerts again: no cooldown survived the reset.
    second = feed(detector, [tunnel_dns(1000.0 + i) for i in range(20)])
    assert len(second) == 1
    assert second[0].evidence["observation_count"] == 20


def test_flush_emits_nothing(detector):
    """Detection happens in process(); flush() is not part of the path."""
    feed(detector, [tunnel_dns(1000.0 + i) for i in range(20)])
    assert detector.flush() == []


# --------------------------------------------------------------------------
# 23-26. Coexistence with the other detectors
# --------------------------------------------------------------------------


def all_four() -> DetectionEngine:
    return DetectionEngine(
        [
            PortScanDetector(PortScanConfig()),
            DDoSDetector(DDoSConfig()),
            C2BeaconingDetector(C2BeaconingConfig()),
            DnsTunnellingDetector(DnsTunnellingConfig()),
        ]
    )


def test_all_four_detectors_run_together():
    """The engine drives all four with no interference or errors."""
    engine = all_four()
    flows = [tunnel_dns(1000.0 + i) for i in range(20)]
    alerts = list(engine.run(flows))

    assert engine.stats.detector_errors == 0
    assert engine.stats.flows_processed == 20
    classes = {a.threat_class for a in alerts}
    assert ThreatClass.DNS_TUNNELLING in classes


def test_port_scan_scenario_does_not_trigger_dns_tunnelling():
    """A vertical scan carries no DNS blocks - DNS must stay silent."""
    engine = all_four()
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
    assert not any(a.threat_class is ThreatClass.DNS_TUNNELLING for a in alerts)


def test_ddos_scenario_does_not_trigger_dns_tunnelling():
    """A flood from many sources carries no DNS blocks."""
    engine = all_four()
    flows = [
        make_flow(
            timestamp=1000.0 + i * 0.001,
            src_ip=f"198.51.{i // 256}.{i % 256}",
            dst_ip="10.0.0.80",
            dst_port=80,
            proto="tcp",
            orig_pkts=5,
        )
        for i in range(300)
    ]
    alerts = list(engine.run(flows))

    assert any(a.threat_class is ThreatClass.DDOS for a in alerts)
    assert not any(a.threat_class is ThreatClass.DNS_TUNNELLING for a in alerts)


def test_c2_scenario_without_dns_metadata_does_not_trigger_dns_tunnelling():
    """A clean HTTPS beacon has no DNS block, so DNS tunnelling stays quiet."""
    engine = all_four()
    flows = [
        make_flow(
            timestamp=1000.0 + i * 30.0,
            src_ip="10.0.0.50",
            dst_ip="203.0.113.10",
            dst_port=443,
            proto="tcp",
        )
        for i in range(12)
    ]
    alerts = list(engine.run(flows))

    assert any(a.threat_class is ThreatClass.C2_BEACONING for a in alerts)
    assert not any(a.threat_class is ThreatClass.DNS_TUNNELLING for a in alerts)


def test_c2_scenario_with_suspicious_dns_metadata_does_trigger_both():
    """A DNS-based beacon legitimately raises both - they are both true."""
    engine = all_four()
    # 10s cadence: regular enough for the beacon detector, and dense enough
    # that the queries are co-resident in the 300s DNS window.
    flows = [blatant_dns(1000.0 + i * 10.0) for i in range(30)]
    alerts = list(engine.run(flows))

    classes = {a.threat_class for a in alerts}
    assert ThreatClass.DNS_TUNNELLING in classes
    assert ThreatClass.C2_BEACONING in classes


def test_registering_dns_detector_does_not_change_other_verdicts():
    """The other three produce identical alerts with or without this one."""
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
    flows += [tunnel_dns(1500.0 + i) for i in range(20)]

    without = DetectionEngine(
        [
            PortScanDetector(PortScanConfig()),
            DDoSDetector(DDoSConfig()),
            C2BeaconingDetector(C2BeaconingConfig()),
        ]
    )
    baseline = [
        (a.threat_class, a.src_ip, a.dst_ip, a.score) for a in without.run(flows)
    ]
    combined = [
        (a.threat_class, a.src_ip, a.dst_ip, a.score)
        for a in all_four().run(flows)
        if a.threat_class is not ThreatClass.DNS_TUNNELLING
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
        {"min_dns_observations": 2},
        {"suspicious_query_length": 0},
        {"suspicious_entropy": -0.1},
        {"suspicious_subdomain_entropy": -0.1},
        {"suspicious_label_count": 0},
        {"min_signals_per_observation": 1},
        {"min_signals_per_observation": 6},
        {"min_suspicious_ratio": 0.0},
        {"min_suspicious_ratio": 1.5},
        {"suspicious_txt_ratio": 0.0},
        {"suspicious_txt_ratio": 1.1},
        {"txt_bonus": -0.1},
        {"txt_bonus": 1.1},
        {"cooldown_seconds": -1.0},
        {"saturation_multiple": 1.0},
        {"ratio_weight": 0.9},  # weights no longer sum to 1.0
        {"max_observations_per_key": 5},
    ],
)
def test_invalid_config_is_rejected(kwargs):
    """Nonsensical thresholds fail loudly at construction."""
    with pytest.raises(ValueError):
        DnsTunnellingConfig(**kwargs)


def test_single_signal_configuration_is_forbidden():
    """The multi-signal rule is structural, not a tunable to switch off."""
    with pytest.raises(ValueError, match="single metric"):
        DnsTunnellingConfig(min_signals_per_observation=1)


def test_default_config_is_valid():
    """The shipped defaults must satisfy their own validation."""
    config = DnsTunnellingConfig()
    assert config.min_signals_per_observation >= 2
    assert 0.0 < config.min_suspicious_ratio <= 1.0
    assert (
        config.ratio_weight + config.volume_weight + config.agreement_weight
        == pytest.approx(1.0)
    )


def test_observation_requires_a_dns_block():
    """The observation builder refuses a flow with no DNS data."""
    from detection_core import DnsObservation

    with pytest.raises(ValueError, match="no dns block"):
        DnsObservation.from_flow(make_flow())


def test_sweep_does_not_drop_a_live_cooldown():
    """A pair going quiet must not shed a cooldown that is still running.

    The window empties after ``window_seconds``, but the cooldown here is
    much longer. If the sweep released both together, a pair could fall
    silent, return, and re-alert inside the cooldown it was still serving.
    """
    detector = DnsTunnellingDetector(
        DnsTunnellingConfig(
            window_seconds=60.0, min_dns_observations=10, cooldown_seconds=100_000.0
        )
    )
    key = DnsTunnelKey(SRC, RESOLVER)

    assert len(feed(detector, [tunnel_dns(1000.0 + i) for i in range(10)])) == 1

    # Force many sweeps' worth of unrelated traffic while the pair is quiet.
    feed(detector, [tunnel_dns(2000.0 + i, src=f"10.2.{i // 256}.{i % 256}")
                    for i in range(1200)])

    assert key in detector._state, "the live cooldown was swept away"
    # Same behaviour again, still deep inside the cooldown - must stay quiet.
    assert feed(detector, [tunnel_dns(3000.0 + i) for i in range(10)]) == []


def test_sweep_releases_an_expired_cooldown():
    """Once a cooldown can no longer suppress anything it is released."""
    detector = DnsTunnellingDetector(
        DnsTunnellingConfig(
            window_seconds=60.0, min_dns_observations=10, cooldown_seconds=60.0
        )
    )
    assert len(feed(detector, [tunnel_dns(1000.0 + i) for i in range(10)])) == 1
    assert detector._state

    feed(detector, [tunnel_dns(9000.0 + i, src=f"10.3.{i // 256}.{i % 256}")
                    for i in range(1200)])

    assert DnsTunnelKey(SRC, RESOLVER) not in detector._state


# --------------------------------------------------------------------------
# Alert-state ordering: state is written only after the alert exists
# --------------------------------------------------------------------------


def test_a_failed_alert_records_no_cooldown(escalation_config, monkeypatch):
    """A ThreatAlert that never got built must not start a cooldown.

    With the state write ahead of ``_build_alert``, a validation error left
    the pair muted for a full cooldown despite nothing being emitted - the
    detector going silent precisely when it had found something.
    """
    detector = DnsTunnellingDetector(escalation_config)
    key = DnsTunnelKey(SRC, RESOLVER)

    def explode(*args, **kwargs):
        raise ValueError("simulated ThreatAlert validation failure")

    monkeypatch.setattr(detector, "_build_alert", explode)
    with pytest.raises(ValueError, match="simulated"):
        feed(detector, [tunnel_dns(1000.0 + i) for i in range(10)])

    assert key not in detector._state, "cooldown recorded for an unemitted alert"

    # The next qualifying query still reports, and cools down normally.
    monkeypatch.undo()
    alerts = feed(detector, [tunnel_dns(1010.0)])

    assert alerts, "a failed alert silenced the pair for a full cooldown"
    assert detector._state[key].last_alert_at == 1010.0
    assert detector._state[key].last_severity is alerts[0].severity


# --------------------------------------------------------------------------
# Aggregate port / protocol - the alert describes the window, not one flow
# --------------------------------------------------------------------------


def test_mixed_destination_ports_report_no_port(detector):
    """A pair split across two resolvers' ports may not claim either.

    The alert is HOST_PAIR scoped over the whole window, so naming the port
    of whichever flow happened to cross the threshold would be a coin toss
    presented as a fact.
    """
    flows = [
        tunnel_dns(1000.0 + i, dst_port=53 if i % 2 else 5353) for i in range(20)
    ]
    alert = feed(detector, flows)[0]

    assert alert.dst_port is None
    # Protocol was unanimous, so it survives independently.
    assert alert.protocol == "udp"


def test_mixed_protocols_report_no_protocol(detector):
    """DNS over both udp and tcp in one window: neither is the answer."""
    flows = [
        tunnel_dns(1000.0 + i, proto="udp" if i % 2 else "tcp") for i in range(20)
    ]
    alert = feed(detector, flows)[0]

    assert alert.protocol is None
    # Port was unanimous, so it survives independently.
    assert alert.dst_port == 53


def test_an_unknown_port_does_not_make_a_known_one_ambiguous(detector):
    """A missing port is not a port, so it cannot disagree with one.

    The project's convention throughout - ``ActivityWindow.dst_ports`` skips
    ``None`` for the other detectors - is that unsupplied means "not
    measured", never a distinct value. So a window whose known ports all say
    53 reports 53, even though one record arrived without one.
    """
    flows = [
        tunnel_dns(1000.0 + i, dst_port=None if i == 0 else 53) for i in range(20)
    ]
    alert = feed(detector, flows)[0]

    assert alert.dst_port == 53


def test_an_expired_port_no_longer_makes_the_window_ambiguous(detector, config):
    """Only the live window decides ambiguity."""
    feed(detector, [tunnel_dns(1000.0 + i, dst_port=5353) for i in range(20)])

    # A second, wholly separate window: the :5353 burst has expired out.
    later = 1000.0 + config.window_seconds + 100.0
    alerts = feed(detector, [tunnel_dns(later + i) for i in range(20)])

    assert alerts, "the second window must qualify on its own"
    assert alerts[0].dst_port == 53
    assert alerts[0].evidence["observation_count"] == 20


# --------------------------------------------------------------------------
# raw_query_available describes the contributing window
# --------------------------------------------------------------------------


def test_raw_query_availability_follows_the_window(detector):
    """False without raw names, true with them - and it changes no verdict."""
    plain = feed(detector, [tunnel_dns(1000.0 + i) for i in range(20)])[0]
    assert plain.evidence["raw_query_available"] is False
    assert plain.evidence["raw_query_observation_count"] == 0

    detector.reset()
    with_names = feed(
        detector,
        [
            tunnel_dns(2000.0 + i, query=f"{'q7x2m9' * 7}{i}.example.com")
            for i in range(20)
        ],
    )[0]

    assert with_names.evidence["raw_query_available"] is True
    assert with_names.evidence["raw_query_observation_count"] == 20
    # The raw name is evidence for the analyst, NOT an input to the rule:
    # identical derived features must still produce an identical verdict.
    assert with_names.score == plain.score
    assert with_names.severity is plain.severity
    assert with_names.evidence["suspicious_ratio"] == plain.evidence["suspicious_ratio"]


def test_a_blank_raw_query_does_not_count_as_available(detector):
    """Whitespace is not a query name."""
    alert = feed(detector, [tunnel_dns(1000.0 + i, query="   ") for i in range(20)])[0]

    assert alert.evidence["raw_query_available"] is False
    assert alert.evidence["raw_query_observation_count"] == 0


def test_an_expired_raw_query_no_longer_counts_as_available(detector, config):
    """A name that has rolled out of the window cannot back a later alert."""
    feed(
        detector,
        [tunnel_dns(1000.0 + i, query=f"payload{i}.tunnel.example") for i in range(20)],
    )

    later = 1000.0 + config.window_seconds + 100.0
    alerts = feed(detector, [tunnel_dns(later + i) for i in range(20)])

    assert alerts, "the second window must qualify on its own"
    assert alerts[0].evidence["raw_query_available"] is False
    assert alerts[0].evidence["raw_query_observation_count"] == 0


def test_partial_raw_query_coverage_is_counted_honestly(detector):
    """Some records carrying a name is still "available", and says how many."""
    flows = [
        tunnel_dns(1000.0 + i, query=f"payload{i}.tunnel.example" if i < 5 else None)
        for i in range(20)
    ]
    alert = feed(detector, flows)[0]

    assert alert.evidence["raw_query_available"] is True
    assert alert.evidence["raw_query_observation_count"] == 5


# --------------------------------------------------------------------------
# Today's ingestion-style records are completely unaffected
# --------------------------------------------------------------------------


def test_current_ingestion_records_keep_their_exact_verdict(detector):
    """The known-positive fixture: same threshold, same score, same severity.

    These records carry only the derived features today's ingestion emits -
    no ``dns.query`` anywhere - and must behave exactly as they did before
    port/protocol and raw-query evidence became window-derived.
    """
    assert feed(detector, [tunnel_dns(1000.0 + i) for i in range(19)]) == []

    alerts = feed(detector, [tunnel_dns(1019.0)])
    assert len(alerts) == 1

    alert = alerts[0]
    assert alert.evidence["observation_count"] == 20
    assert alert.evidence["suspicious_ratio"] == 1.0
    assert alert.score == 0.75
    assert alert.severity is Severity.HIGH
    assert alert.dst_port == 53
    assert alert.protocol == "udp"
    assert alert.evidence["raw_query_available"] is False
