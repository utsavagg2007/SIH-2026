"""Source-level correlation of DGA findings, and the alert storm it prevents.

One infected host walks a generated domain list until something resolves, so
per-domain alerting produces one alert per name tried - twenty alerts for one
event. Classification is still per domain; reporting is now per source.

Two suppressions now run together and this file is mostly about their
interaction:

* **per (src_ip, domain)** - unchanged. A name queried in a loop contributes
  once. This is what stops query volume inflating the distinct-domain count.
* **per src_ip** - new. A source reports at most once per
  ``cooldown_seconds``, so many *different* positive domains do not become
  many alerts.

Both use the existing ``cooldown_seconds``; no new tuning constant and no new
"how many domains make it real" threshold were introduced, because inventing
a detection threshold to reduce alert volume would be changing what counts as
DGA in order to change how it is reported.

The model is stubbed so scores are exact and the tests are about correlation,
not about classification quality.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from detection_core import (
    DGAConfig,
    DGADetector,
    DnsInfo,
    EventScope,
    ScoreType,
    Severity,
    ThreatClass,
)
from detection_core.detectors.dga import MAX_SAMPLE_DOMAINS

from .conftest import make_flow

SRC = "10.0.0.7"
RESOLVER = "10.0.0.53"


@dataclass(frozen=True)
class StubPrediction:
    domain: str
    normalized_domain: str
    label: int
    dga_score: float


class ScriptedModel:
    """Returns a chosen score, so the threshold boundary is exact."""

    is_fitted = True

    def __init__(self, score: float = 0.95, scores: dict[str, float] | None = None):
        self.score = score
        self.scores = scores or {}

    def predict_domain(self, domain: str) -> StubPrediction:
        value = self.scores.get(domain, self.score)
        return StubPrediction(domain, domain, 1 if value >= 0.75 else 0, value)


def detector(score: float = 0.95, scores=None, **config) -> DGADetector:
    return DGADetector(model=ScriptedModel(score, scores), config=DGAConfig(**config))


def dns_flow(timestamp: float, query: str, *, src: str = SRC, dst: str = RESOLVER,
             port: int | None = 53, proto: str = "udp"):
    return make_flow(
        src_ip=src, dst_ip=dst, dst_port=port, proto=proto, timestamp=timestamp,
        dns=DnsInfo(uid=f"C{timestamp}", query=query),
    )


def feed(det, flows):
    alerts = []
    for flow in flows:
        alerts.extend(det.process(flow))
    return alerts


def generated(index: int) -> str:
    """A deterministic generated-looking name."""
    return f"kq3v9x2mzt7wp{index:03d}.com"


# --------------------------------------------------------------------------
# Phase 11: the acceptance case
# --------------------------------------------------------------------------


def test_one_source_with_twenty_distinct_positives_does_not_storm():
    """The defect this batch exists to fix: 20 alerts became 1."""
    det = detector()

    alerts = feed(det, [dns_flow(1000.0 + i, generated(i)) for i in range(20)])

    assert len(alerts) == 1, f"alert storm: {len(alerts)} alerts for one source"
    alert = alerts[0]
    assert alert.event_scope is EventScope.SOURCE_HOST
    assert alert.src_ip == SRC
    assert alert.threat_class is ThreatClass.DGA_DOMAIN

    # Every domain was still classified and correlated - nothing was dropped.
    assert len(det._sources[SRC].findings) == 20


def test_the_emitted_alert_keeps_useful_domain_and_model_evidence():
    det = detector()
    alert = feed(det, [dns_flow(1000.0 + i, generated(i)) for i in range(20)])[0]
    evidence = alert.evidence

    # The triggering domain and its model output survive intact.
    assert evidence["domain"] == generated(0)
    assert evidence["normalized_domain"] == generated(0)
    assert evidence["dga_model_score"] == 0.95
    assert evidence["score_threshold"] == 0.75
    assert evidence["model_score_is_calibrated"] is False
    assert "uncalibrated" in evidence["score_note"]

    # And the aggregate view exists alongside it.
    assert evidence["distinct_dga_domain_count"] == 1  # at emission time
    assert evidence["aggregation_window_seconds"] == 300.0
    assert evidence["sample_domains"] == [generated(0)]


def test_a_sustained_infection_reports_the_accumulated_picture():
    """The count is what makes the aggregate evidence worth having."""
    det = detector()
    # A new generated name every 30s for half an hour.
    alerts = feed(det, [dns_flow(1000.0 + i * 30.0, generated(i)) for i in range(60)])

    # One per source cooldown, not sixty.
    assert len(alerts) == 6
    counts = [a.evidence["distinct_dga_domain_count"] for a in alerts]
    assert counts[0] == 1  # nothing had accumulated yet
    assert all(count == 10 for count in counts[1:]), counts
    # Each later alert spans the window it summarizes.
    for alert in alerts[1:]:
        span = alert.event_end.timestamp() - alert.event_start.timestamp()
        assert 0 < span <= 300.0


# --------------------------------------------------------------------------
# Phase 7: the two cooldowns, case by case
# --------------------------------------------------------------------------


def test_case1_the_same_domain_repeated_does_not_inflate_anything():
    det = detector()

    alerts = feed(det, [dns_flow(1000.0 + i, generated(0)) for i in range(20)])

    assert len(alerts) == 1
    assert det._sources[SRC].findings.keys() == {generated(0)}
    assert alerts[0].evidence["distinct_dga_domain_count"] == 1


def test_case3_many_sources_alert_independently():
    det = detector()

    alerts = feed(
        det,
        [dns_flow(1000.0 + i, generated(i), src=f"10.1.0.{i}") for i in range(20)],
    )

    assert len(alerts) == 20
    assert {a.src_ip for a in alerts} == {f"10.1.0.{i}" for i in range(20)}


def test_case4_one_domain_from_two_sources_is_two_findings():
    det = detector()

    alerts = feed(
        det,
        [dns_flow(1000.0, generated(0), src="10.1.0.1"),
         dns_flow(1001.0, generated(0), src="10.1.0.2")],
    )

    assert len(alerts) == 2
    assert set(det._sources) == {"10.1.0.1", "10.1.0.2"}


def test_case5_the_source_may_report_again_once_its_cooldown_lapses():
    det = detector()
    first = feed(det, [dns_flow(1000.0, generated(0))])
    assert len(first) == 1

    # Inside the cooldown: silent.
    assert feed(det, [dns_flow(1200.0, generated(1))]) == []
    # Past it: reports again.
    again = feed(det, [dns_flow(1000.0 + 300.0, generated(2))])
    assert len(again) == 1


def test_case6_domain_cooldown_lapse_still_obeys_source_suppression():
    """Both policies apply; neither overrides the other."""
    det = detector()
    assert len(feed(det, [dns_flow(1000.0, generated(0))])) == 1

    # The domain's own cooldown has lapsed (300s), but so has the source's,
    # so the same domain may report the source again.
    assert len(feed(det, [dns_flow(1300.0, generated(0))])) == 1

    # Immediately after, the source is suppressed even for a fresh domain.
    assert feed(det, [dns_flow(1301.0, generated(9))]) == []


def test_case7_source_cooldown_lapse_does_not_bypass_domain_suppression():
    """A domain still inside its own cooldown cannot trigger a report."""
    det = detector()
    assert len(feed(det, [dns_flow(1000.0, generated(0))])) == 1

    # 250s later the source cooldown has not lapsed and neither has the
    # domain's; nothing is emitted and nothing new is recorded.
    assert feed(det, [dns_flow(1250.0, generated(0))]) == []
    assert det._sources[SRC].findings[generated(0)].timestamp == 1000.0


def test_a_repeat_inside_the_domain_cooldown_does_not_refresh_the_finding():
    det = detector()
    feed(det, [dns_flow(1000.0, generated(0))])

    feed(det, [dns_flow(1100.0, generated(0))])

    # The recorded finding is still the one that actually contributed.
    assert det._sources[SRC].findings[generated(0)].timestamp == 1000.0


# --------------------------------------------------------------------------
# Model decisions must not have moved
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score,expected_alerts",
    [(0.7499, 0), (0.75, 1), (0.7501, 1), (0.95, 1), (1.0, 1)],
)
def test_the_decision_threshold_is_untouched(score, expected_alerts):
    det = detector(score=score)

    alerts = feed(det, [dns_flow(1000.0, generated(0))])

    assert len(alerts) == expected_alerts


def test_a_negative_domain_contributes_nothing():
    det = detector(scores={generated(0): 0.10, generated(1): 0.95})

    alerts = feed(det, [dns_flow(1000.0, generated(0)), dns_flow(1001.0, generated(1))])

    assert len(alerts) == 1
    assert det._sources[SRC].findings.keys() == {generated(1)}
    assert alerts[0].evidence["domain"] == generated(1)


def test_mixed_positive_and_negative_domains_count_only_positives():
    det = detector(scores={generated(i): (0.95 if i % 2 == 0 else 0.20) for i in range(10)})

    feed(det, [dns_flow(1000.0 + i, generated(i)) for i in range(10)])

    assert det._sources[SRC].findings.keys() == {generated(i) for i in range(0, 10, 2)}


def test_threat_score_and_severity_are_unchanged():
    """The triggering domain's existing transformation, untouched."""
    det = detector(score=0.95)
    alert = feed(det, [dns_flow(1000.0, generated(0))])[0]

    # 0.5 + 0.5 * (0.95 - 0.75) / (1 - 0.75) = 0.9
    assert alert.score == pytest.approx(0.9)
    assert alert.severity is Severity.CRITICAL
    assert alert.score_type is ScoreType.RULE_SCORE

    at_threshold = detector(score=0.75)
    boundary = feed(at_threshold, [dns_flow(1000.0, generated(0))])[0]
    assert boundary.score == pytest.approx(0.5)


def test_severity_is_not_boosted_by_the_number_of_domains():
    """More names is more of the same finding, not a worse one."""
    one = feed(detector(), [dns_flow(1000.0, generated(0))])[0]

    many = detector()
    feed(many, [dns_flow(1000.0 + i, generated(i)) for i in range(20)])
    later = feed(many, [dns_flow(1400.0, generated(50))])[0]

    assert later.score == one.score
    assert later.severity is one.severity


# --------------------------------------------------------------------------
# Alert contract: no invented aggregate fields
# --------------------------------------------------------------------------


def test_a_single_truthful_destination_is_reported():
    det = detector()
    alert = feed(det, [dns_flow(1000.0, generated(0))])[0]

    assert alert.dst_ip == RESOLVER
    assert alert.dst_port == 53
    assert alert.protocol == "udp"


def test_several_destinations_report_none_rather_than_a_placeholder():
    det = detector()
    feed(det, [
        dns_flow(1000.0, generated(0), dst="10.0.0.53", port=53),
        dns_flow(1001.0, generated(1), dst="10.0.0.54", port=5353, proto="tcp"),
    ])
    alert = feed(det, [dns_flow(1400.0, generated(2), dst="10.0.0.55")])[0]
    # Force a window holding two different resolvers.
    det2 = detector()
    feed(det2, [
        dns_flow(2000.0, generated(0), dst="10.0.0.53"),
        dns_flow(2001.0, generated(1), dst="10.0.0.54"),
    ])
    mixed = feed(det2, [dns_flow(2000.0 + 300.0, generated(2), dst="10.0.0.55")])[0]

    for field in (mixed.dst_ip, mixed.dst_port, mixed.protocol):
        assert field is None or isinstance(field, (str, int))
    assert mixed.dst_ip is None, "several destinations must not collapse to one"
    assert mixed.dst_ip != "multiple" and mixed.dst_port != 0
    assert alert.flow_id is None


def test_event_span_covers_the_correlated_findings():
    det = detector()
    feed(det, [dns_flow(1000.0 + i * 30.0, generated(i)) for i in range(6)])
    alert = feed(det, [dns_flow(1000.0 + 300.0, generated(99))])[0]

    assert alert.event_start.timestamp() == 1030.0
    assert alert.event_end.timestamp() == 1300.0
    assert alert.event_start <= alert.event_end


# --------------------------------------------------------------------------
# Evidence bounds and ordering
# --------------------------------------------------------------------------


def test_sample_domains_are_bounded_and_deterministically_ordered():
    det = detector()
    feed(det, [dns_flow(1000.0 + i, generated(i)) for i in range(50)])
    alert = feed(det, [dns_flow(1000.0 + 300.0, generated(99))])[0]

    sample = alert.evidence["sample_domains"]
    assert len(sample) == MAX_SAMPLE_DOMAINS
    assert sample == sorted(sample), "ordering must be deterministic"
    assert alert.evidence["sample_domain_limit"] == MAX_SAMPLE_DOMAINS
    # The count is the truth; the sample is only a sample.
    assert alert.evidence["distinct_dga_domain_count"] > len(sample)


def test_the_same_input_yields_the_same_sample_every_run():
    def run():
        det = detector()
        feed(det, [dns_flow(1000.0 + i, generated(i)) for i in range(40)])
        return feed(det, [dns_flow(1400.0, generated(99))])[0].evidence["sample_domains"]

    assert run() == run()


# --------------------------------------------------------------------------
# Phase 8: expiry, reset and memory
# --------------------------------------------------------------------------


def test_findings_expire_on_event_time():
    det = detector()
    feed(det, [dns_flow(1000.0 + i, generated(i)) for i in range(5)])
    assert len(det._sources[SRC].findings) == 5

    # A later eligible domain expires everything older than the window.
    feed(det, [dns_flow(1000.0 + 400.0, generated(99))])

    assert det._sources[SRC].findings.keys() == {generated(99)}


def test_reset_clears_every_kind_of_state():
    det = detector()
    feed(det, [dns_flow(1000.0 + i, generated(i)) for i in range(5)])
    assert det._sources and det._last_alert_at

    det.reset()

    assert det._sources == {}
    assert det._last_alert_at == {}
    assert det._since_sweep == 0
    # And the detector is usable again immediately.
    assert len(feed(det, [dns_flow(2000.0, generated(0))])) == 1


def test_flush_still_emits_nothing():
    det = detector()
    feed(det, [dns_flow(1000.0, generated(0))])

    assert det.flush() == []


def test_idle_sources_are_swept_out():
    """Historical sources must not accumulate forever."""
    det = detector()
    for index in range(600):
        # Each source queries once, far apart in event time.
        feed(det, [dns_flow(1000.0 + index * 1000.0, generated(index),
                            src=f"10.2.{index // 256}.{index % 256}")])

    # The sweep releases sources with nothing recent and no live suppression.
    assert len(det._sources) < 600, f"{len(det._sources)} sources retained"
    assert len(det._last_alert_at) < 600


def test_repeated_queries_do_not_grow_memory():
    det = detector()
    for index in range(500):
        feed(det, [dns_flow(1000.0 + index, generated(0))])

    assert len(det._sources[SRC].findings) == 1
    assert len(det._last_alert_at) == 1


def test_many_distinct_domains_are_bounded_by_the_window():
    det = detector()
    # 400 distinct names, one per second: the window holds 300s of them.
    feed(det, [dns_flow(1000.0 + i, generated(i)) for i in range(400)])

    findings = det._sources[SRC].findings
    assert len(findings) <= 301, f"{len(findings)} findings retained"
    assert all(f.timestamp > 1399.0 - 300.0 for f in findings.values())


# --------------------------------------------------------------------------
# Phase 12: multi-source isolation at scale
# --------------------------------------------------------------------------


def test_a_hundred_sources_stay_independent():
    det = detector()
    alerts = []
    for index in range(100):
        src = f"10.3.{index // 256}.{index % 256}"
        # Each source queries five distinct positive domains in quick succession.
        alerts.extend(
            feed(det, [dns_flow(1000.0 + step, generated(step), src=src)
                       for step in range(5)])
        )

    # One alert per source, not five.
    assert len(alerts) == 100
    assert len({a.src_ip for a in alerts}) == 100
    for correlation in det._sources.values():
        assert len(correlation.findings) == 5


def test_one_source_reporting_never_suppresses_another():
    det = detector()
    feed(det, [dns_flow(1000.0, generated(0), src="10.4.0.1")])

    other = feed(det, [dns_flow(1001.0, generated(0), src="10.4.0.2")])

    assert len(other) == 1
    assert other[0].src_ip == "10.4.0.2"


# --------------------------------------------------------------------------
# Input handling is unchanged
# --------------------------------------------------------------------------


def test_a_flow_without_dns_is_ignored():
    det = detector()

    assert det.process(make_flow(timestamp=1000.0)) == []
    assert det._sources == {}


def test_a_blank_or_missing_query_is_ignored():
    det = detector()

    assert det.process(dns_flow(1000.0, "   ")) == []
    assert det.process(make_flow(timestamp=1001.0, dns=DnsInfo(uid="x"))) == []
    assert det._sources == {}


def test_out_of_order_timestamps_do_not_break_correlation():
    """Existing semantics: no reorder buffer, events land where they land."""
    det = detector()
    alerts = feed(det, [
        dns_flow(1000.0, generated(0)),
        dns_flow(995.0, generated(1)),
        dns_flow(1002.0, generated(2)),
    ])

    assert len(alerts) == 1
    assert len(det._sources[SRC].findings) == 3
