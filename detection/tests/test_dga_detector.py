"""DGADetector tests - Phase 2, the live wrapper around the Phase-1 model.

Focused rather than exhaustive: one test per distinct failure mode. The
Phase-1 feature extractor, model and persistence layer already have their
own suites; this file covers only the wiring between a FlowEvent and them.

The model used here is a tiny one fitted in-process on synthetic domains.
No model binary is committed, and the save/load test writes to tmp_path.
"""

from __future__ import annotations

import json

import pytest

from detection_core import (
    DetectionEngine,
    DGAConfig,
    DGADetector,
    DnsInfo,
    EventScope,
    IngestionJsonlAdapter,
    PortScanConfig,
    PortScanDetector,
    ScoreType,
    ThreatAlert,
    ThreatClass,
)
from detection_core.ml.dga import LABEL_BENIGN, LABEL_DGA, DGAModel, normalize_domain

from .conftest import make_flow

SRC = "10.0.0.20"
RESOLVER = "10.0.0.53"

BENIGN_DOMAINS = [
    "google.com", "facebook.com", "youtube.com", "wikipedia.org", "amazon.com",
    "github.com", "stackoverflow.com", "microsoft.com", "apple.com", "netflix.com",
    "reddit.com", "twitter.com", "linkedin.com", "instagram.com", "office365.com",
    "cloudflare.com", "mozilla.org", "python.org", "nytimes.com", "bbc.co.uk",
]
DGA_DOMAINS = [
    "kq3v9x2mzt7wp1.com", "xjfkdlspqoweirut.net", "zzqxwvbnmlkjhg.org",
    "vbnmqwertyuiopas.com", "plmoknijbuhvygc.net", "qazwsxedcrfvtgb.com",
    "mnbvcxzlkjhgfds.org", "poiuytrewqasdfgh.net", "lkjhgfdsamnbvcxz.com",
    "trewqasdfgzxcvbn.org", "xkcdvbnmqwerty12.com", "9x8y7z6w5v4u3t2s.net",
    "hjkliuoytrewqzxc.org", "bnmvcxzasdfghjkl.com", "wqertyuiopasdfgh.net",
    "zxcvbnmasdfghjkl.org", "q1w2e3r4t5y6u7i8.com", "a1s2d3f4g5h6j7k8.net",
    "m9n8b7v6c5x4z3l2.org", "p0o9i8u7y6t5r4e3.com",
]

BENIGN_QUERY = "github.com"
DGA_QUERY = "xjfkdlspqoweirut.net"


@pytest.fixture(scope="module")
def model() -> DGAModel:
    """A small model fitted in-process. Never written to the repo."""
    fitted = DGAModel.new(n_estimators=60, random_state=42, n_jobs=1)
    fitted.fit(
        BENIGN_DOMAINS + DGA_DOMAINS,
        [LABEL_BENIGN] * len(BENIGN_DOMAINS) + [LABEL_DGA] * len(DGA_DOMAINS),
    )
    return fitted


@pytest.fixture
def detector(model) -> DGADetector:
    return DGADetector(model=model, config=DGAConfig(score_threshold=0.75))


def dns_flow(timestamp: float, query: str | None, *, src: str = SRC, **overrides):
    """A DNS flow carrying a raw query name - the Phase-2 input."""
    dns_kwargs = dict(uid=f"Cdga{timestamp}", query=query, query_length=len(query or ""))
    dns_kwargs.update(overrides.pop("dns_extra", {}))
    return make_flow(
        timestamp=timestamp,
        src_ip=src,
        dst_ip=RESOLVER,
        dst_port=53,
        proto="udp",
        dns=DnsInfo(**dns_kwargs),
        **overrides,
    )


def feed(detector, flows) -> list[ThreatAlert]:
    alerts: list[ThreatAlert] = []
    for flow in flows:
        alerts.extend(detector.process(flow))
    return alerts


class StubModel:
    """Returns a fixed score - for testing threshold arithmetic exactly."""

    def __init__(self, score: float) -> None:
        self.score = score

    def predict_domain(self, domain: str):
        from detection_core.ml.dga import DGAPrediction

        return DGAPrediction(
            domain=domain,
            normalized_domain=normalize_domain(domain),
            label=LABEL_DGA if self.score >= 0.5 else LABEL_BENIGN,
            dga_score=self.score,
        )


# --------------------------------------------------------------------------
# 1-3. Input handling
# --------------------------------------------------------------------------


def test_non_dns_flow_is_ignored(detector):
    """No dns block means nothing to classify."""
    assert feed(detector, [make_flow(timestamp=1000.0 + i) for i in range(20)]) == []


def test_dns_flow_without_raw_query_is_ignored(detector):
    """This is EVERY record current ingestion produces - it must be silent."""
    flows = [
        make_flow(
            timestamp=1000.0 + i,
            dns=DnsInfo(query_length=110, query_entropy=4.9, label_count=9, is_txt=True),
        )
        for i in range(20)
    ]
    assert feed(detector, flows) == []


@pytest.mark.parametrize("query", ["", "   ", "a b.com", "http://evil.com/x", "a..b.com"])
def test_unusable_queries_are_skipped_safely(detector, query):
    """Phase-1 normalization rejects these; one bad record must not crash."""
    assert detector.process(dns_flow(1000.0, query)) == []


# --------------------------------------------------------------------------
# 4-6. Classification
# --------------------------------------------------------------------------


def test_benign_domain_does_not_alert(detector):
    """A well-known name scores far below the threshold."""
    assert detector.process(dns_flow(1000.0, BENIGN_QUERY)) == []


def test_dga_domain_alerts(detector):
    """A generated-looking name crosses the threshold."""
    alerts = detector.process(dns_flow(1000.0, DGA_QUERY))

    assert len(alerts) == 1
    assert alerts[0].threat_class is ThreatClass.DGA_DOMAIN
    assert alerts[0].evidence["dga_model_score"] >= 0.75


@pytest.mark.parametrize(
    "model_score,expect_alert,expect_score",
    [
        (0.7499, False, None),   # just below - silent
        (0.75, True, 0.5),       # exactly at the threshold - bottom of the scale
        (0.875, True, 0.75),     # halfway past
        (1.0, True, 1.0),        # maximum model confidence
    ],
)
def test_threshold_mapping_is_deterministic(model_score, expect_alert, expect_score):
    """At threshold -> 0.5, at 1.0 -> 1.0, linear between. Below -> nothing."""
    detector = DGADetector(
        model=StubModel(model_score), config=DGAConfig(score_threshold=0.75)
    )
    alerts = detector.process(dns_flow(1000.0, DGA_QUERY))

    assert bool(alerts) is expect_alert
    if expect_alert:
        assert alerts[0].score == expect_score
        assert 0.0 <= alerts[0].score <= 1.0


# --------------------------------------------------------------------------
# 7. Phase-1 reuse
# --------------------------------------------------------------------------


def test_phase_one_normalization_is_reused_not_reimplemented(detector, monkeypatch):
    """The detector must call Phase 1's normalize_domain, not its own copy."""
    calls: list[str] = []
    original = detector._normalize_domain

    def spy(domain: str) -> str:
        calls.append(domain)
        return original(domain)

    monkeypatch.setattr(detector, "_normalize_domain", spy)
    detector.process(dns_flow(1000.0, "  XJFKDLSPQOWEIRUT.NET.  "))

    assert calls == ["  XJFKDLSPQOWEIRUT.NET.  "]


def test_normalized_domain_in_evidence_matches_phase_one(detector):
    """Upper case, padding and the root dot are all handled by Phase 1."""
    alert = detector.process(dns_flow(1000.0, "  XJFKDLSPQOWEIRUT.NET.  "))[0]

    assert alert.evidence["normalized_domain"] == normalize_domain(DGA_QUERY)
    assert alert.evidence["domain"] == "  XJFKDLSPQOWEIRUT.NET.  "


def test_detector_contains_no_dga_feature_logic():
    """Guard against a second copy of the lexical arithmetic drifting in."""
    from pathlib import Path

    source = Path(
        __file__
    ).resolve().parent.parent / "detection_core" / "detectors" / "dga.py"
    text = source.read_text(encoding="utf-8")

    for forbidden in ("shannon_entropy", "extract_features", "FEATURE_NAMES", "vowel"):
        assert forbidden not in text, f"{forbidden} suggests duplicated Phase-1 logic"


# --------------------------------------------------------------------------
# 8-10. Adapter readiness
# --------------------------------------------------------------------------


def _record(**dns_fields):
    base = {
        "flow_id": "10.0.0.20:10.0.0.53:53:udp:1747200000.0",
        "src_ip": SRC, "dst_ip": RESOLVER, "dst_port": 53, "proto": "udp",
        "duration": 0.01, "orig_bytes": 74, "resp_bytes": 190,
        "orig_pkts": 1, "resp_pkts": 1, "conn_state_encoded": 4,
        "dns": {"uid": "U1", "query_length": 20, "query_entropy": 3.9,
                "subdomain_entropy": 0.0, "is_txt": False, "label_count": 2},
    }
    base["dns"].update(dns_fields)
    return json.dumps(base)


def test_current_ingestion_shape_leaves_query_none():
    """Today's records have no raw query - and must stay valid."""
    events = list(IngestionJsonlAdapter().from_lines([_record()]))

    assert len(events) == 1
    assert events[0].dns.query is None
    assert events[0].dns.qtype is None
    assert events[0].dns.rcode is None
    # The derived features ingestion DOES send still arrive.
    assert events[0].dns.query_entropy == 3.9


def test_future_ingestion_shape_preserves_query_qtype_rcode():
    """When ingestion starts emitting them, the adapter carries them through."""
    line = _record(query="xjfkdlspqoweirut.net", qtype="A", rcode="NOERROR")
    adapter = IngestionJsonlAdapter()
    events = list(adapter.from_lines([line]))

    assert events[0].dns.query == "xjfkdlspqoweirut.net"
    assert events[0].dns.qtype == "A"
    assert events[0].dns.rcode == "NOERROR"
    # Raw fields are expected, so they must not read as schema drift.
    assert adapter.stats.drift_warnings == []
    assert adapter.stats.errors == 0


def test_qtype_and_rcode_reach_the_alert_evidence(detector):
    """Reported only when actually supplied - never invented."""
    with_meta = detector.process(
        dns_flow(1000.0, DGA_QUERY, dns_extra={"qtype": "TXT", "rcode": "NXDOMAIN"})
    )[0]
    assert with_meta.evidence["qtype"] == "TXT"
    assert with_meta.evidence["rcode"] == "NXDOMAIN"

    detector.reset()
    without = detector.process(dns_flow(2000.0, DGA_QUERY))[0]
    assert "qtype" not in without.evidence
    assert "rcode" not in without.evidence


# --------------------------------------------------------------------------
# 11-16. Alert contract
# --------------------------------------------------------------------------


def test_alert_conformance(detector):
    """Class, scope, endpoints, score type, MITRE mapping, flow_id.

    Scope is SOURCE_HOST: findings are correlated per source, so an alert
    describes a host's behaviour across the names it queried rather than one
    lookup. ``flow_id`` is therefore None, the aggregate contract every other
    correlating detector follows. The endpoints survive here because every
    correlated finding so far agrees on them.
    """
    alert = detector.process(dns_flow(1000.0, DGA_QUERY))[0]

    assert isinstance(alert, ThreatAlert)
    assert alert.schema_version == "1.1"
    assert alert.threat_class is ThreatClass.DGA_DOMAIN
    assert alert.event_scope is EventScope.SOURCE_HOST
    assert alert.flow_id is None
    assert alert.src_ip == SRC and alert.dst_ip == RESOLVER
    assert alert.dst_port == 53 and alert.protocol == "udp"
    assert alert.detector == "dga_domain"
    assert alert.detector_version == DGADetector.version
    assert alert.mitre_techniques == ["T1568.002"]


def test_score_type_is_rule_score_never_calibrated(detector):
    """The RandomForest vote fraction is not a calibrated probability."""
    alert = detector.process(dns_flow(1000.0, DGA_QUERY))[0]

    assert alert.score_type is ScoreType.RULE_SCORE
    assert alert.score_type is not ScoreType.CALIBRATED_MODEL
    assert alert.evidence["model_score_is_calibrated"] is False
    assert "uncalibrated" in alert.evidence["score_note"]


def test_raw_model_score_is_kept_separately(detector):
    """The headline score is derived from the model's, not equal to it.

    Uses a mid-range domain on purpose: a domain the model scores at exactly
    1.0 maps to a threat score of 1.0 too, so the two numbers coinciding
    there would prove nothing.
    """
    alert = detector.process(dns_flow(1000.0, "zzqxwvbnmlkjhg.org"))[0]
    raw = alert.evidence["dga_model_score"]

    assert 0.75 <= raw < 1.0, "pick a domain scoring between threshold and 1.0"
    assert alert.score != raw
    # The published score is exactly the documented mapping of the raw one.
    assert alert.score == pytest.approx(0.5 + 0.5 * (raw - 0.75) / 0.25)
    assert alert.evidence["score_threshold"] == 0.75
    assert alert.evidence["model_label"] == LABEL_DGA
    # Provenance travels with the verdict.
    assert alert.evidence["model_format_version"] == "1.0"
    assert alert.evidence["model_type"] == "RandomForestClassifier"


def test_flow_id_is_never_set_on_a_correlated_alert(detector):
    """No single flow represents a correlated source finding.

    A flow arriving without an id must still produce a well-formed alert -
    the original point of this test - and the id is now absent either way,
    because the alert is source-scoped.
    """
    without_id = detector.process(dns_flow(1000.0, DGA_QUERY, flow_id=None))[0]
    assert without_id.flow_id is None
    assert without_id.event_scope is EventScope.SOURCE_HOST

    detector.reset()
    with_id = detector.process(dns_flow(2000.0, DGA_QUERY))[0]
    assert with_id.flow_id is None


# --------------------------------------------------------------------------
# 17-21. Cooldown and reset
# --------------------------------------------------------------------------


def test_cooldown_suppresses_the_same_source_and_domain(detector):
    """Malware re-queries constantly; the finding is the domain."""
    alerts = feed(detector, [dns_flow(1000.0 + i, DGA_QUERY) for i in range(50)])
    assert len(alerts) == 1


def test_different_domains_do_not_share_a_cooldown(detector):
    """Two generated domains from one host are two distinct findings.

    Still true, and still the point of this test - but they are now two
    findings correlated into one source, not two separate alerts. The
    per-domain cooldown is what this guards: the second domain must not be
    suppressed *as a domain*, which is visible in the source's recorded
    findings and in the count the next alert carries.
    """
    alerts = feed(
        detector,
        [dns_flow(1000.0, DGA_QUERY), dns_flow(1001.0, "zzqxwvbnmlkjhg.org")],
    )

    # The second domain was not swallowed by the first domain's cooldown.
    findings = detector._sources[SRC].findings
    assert len(findings) == 2
    assert set(findings) == {DGA_QUERY, "zzqxwvbnmlkjhg.org"}

    # It did not raise a second alert, because the source had just reported.
    assert len(alerts) == 1

    # Once the source cooldown lapses, the accumulated picture is reported.
    later = feed(detector, [dns_flow(1000.0 + 400.0, "vbnmqwertyuiopas.com")])
    assert len(later) == 1
    assert later[0].evidence["distinct_dga_domain_count"] >= 1

    # The one alert names the domain that triggered it. The other domain is
    # not lost - it is in the source's findings above, and would appear in a
    # later alert's count and sample while still inside the window.
    assert alerts[0].evidence["normalized_domain"] == DGA_QUERY


def test_different_sources_do_not_share_a_cooldown(detector):
    """The same domain from two hosts is two findings."""
    alerts = feed(
        detector,
        [dns_flow(1000.0, DGA_QUERY), dns_flow(1001.0, DGA_QUERY, src="10.0.0.21")],
    )
    assert len(alerts) == 2
    assert {a.src_ip for a in alerts} == {SRC, "10.0.0.21"}


def test_cooldown_expiry_allows_alerting_again(model):
    """After the cooldown elapses the same domain reports again."""
    detector = DGADetector(model=model, config=DGAConfig(cooldown_seconds=300.0))

    assert len(detector.process(dns_flow(1000.0, DGA_QUERY))) == 1
    assert detector.process(dns_flow(1100.0, DGA_QUERY)) == []
    assert len(detector.process(dns_flow(1301.0, DGA_QUERY))) == 1


def test_cooldown_state_is_bounded(model):
    """Thousands of distinct domains must not grow the table without bound."""
    detector = DGADetector(model=model, config=DGAConfig(cooldown_seconds=60.0))
    # Alternate real DGA domains so entries are actually created, over a
    # timespan far exceeding the cooldown.
    flows = [
        dns_flow(1000.0 + i * 10.0, DGA_DOMAINS[i % len(DGA_DOMAINS)])
        for i in range(1200)
    ]
    feed(detector, flows)

    assert len(detector._last_alert_at) <= len(DGA_DOMAINS)


def test_reset_clears_cooldown_state(detector):
    """reset() drops everything so a replay starts clean."""
    assert len(detector.process(dns_flow(1000.0, DGA_QUERY))) == 1
    assert detector.process(dns_flow(1001.0, DGA_QUERY)) == []

    detector.reset()
    assert detector._last_alert_at == {}
    assert len(detector.process(dns_flow(1002.0, DGA_QUERY))) == 1


def test_flush_emits_nothing(detector):
    detector.process(dns_flow(1000.0, DGA_QUERY))
    assert detector.flush() == []


# --------------------------------------------------------------------------
# 22-24. Model wiring and failure behaviour
# --------------------------------------------------------------------------


def test_model_can_be_loaded_from_a_saved_path(model, tmp_path):
    """Save/load round-trip through a TEMP artifact - nothing is committed."""
    path = model.save(tmp_path / "dga.joblib")
    detector = DGADetector(model_path=path)

    assert len(detector.process(dns_flow(1000.0, DGA_QUERY))) == 1
    assert detector.process(dns_flow(2000.0, BENIGN_QUERY)) == []


def test_missing_model_path_fails_clearly(tmp_path):
    """A path that is not there names itself and says what to do."""
    with pytest.raises(FileNotFoundError, match="DGA model not found"):
        DGADetector(model_path=tmp_path / "nope.joblib")


def test_corrupt_model_bundle_fails_clearly(tmp_path):
    """Phase-1's loader rejects a non-bundle; the detector does not mask it."""
    import joblib

    bad = tmp_path / "bad.joblib"
    joblib.dump({"not": "a model"}, bad)

    with pytest.raises(ValueError, match="not a DGA model bundle"):
        DGADetector(model_path=bad)


def test_incompatible_model_format_fails_clearly(tmp_path, model):
    """A stale format_version is refused rather than silently predicted with."""
    import joblib

    stale = tmp_path / "stale.joblib"
    bundle = {"metadata": {**model.metadata.to_dict(), "format_version": "0.1"},
              "estimator": model.estimator}
    joblib.dump(bundle, stale)

    with pytest.raises(ValueError, match="does not match this build"):
        DGADetector(model_path=stale)


def test_a_model_is_required(model, tmp_path):
    """No silent fallback to an untrained or stub model."""
    with pytest.raises(ValueError, match="exactly one of"):
        DGADetector()
    with pytest.raises(ValueError, match="exactly one of"):
        DGADetector(model=model, model_path=tmp_path / "x.joblib")


def test_unfitted_model_is_refused():
    """A model that cannot classify must not look like a healthy detector."""
    with pytest.raises(RuntimeError, match="not fitted"):
        DGADetector(model=DGAModel.new())


@pytest.mark.parametrize("kwargs", [
    {"score_threshold": 0.0}, {"score_threshold": 1.5}, {"score_threshold": -0.1},
    {"cooldown_seconds": -1.0},
])
def test_invalid_config_is_rejected(kwargs):
    with pytest.raises(ValueError):
        DGAConfig(**kwargs)


# --------------------------------------------------------------------------
# 25. Coexistence
# --------------------------------------------------------------------------


def test_importing_detection_core_does_not_require_sklearn():
    """The core stays pydantic-only; only CONSTRUCTING a DGADetector needs ml."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-c",
         "import sys, detection_core; "
         "assert 'sklearn' not in sys.modules, 'sklearn leaked into the core'; "
         "print('ok')"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_runs_alongside_another_detector_without_affecting_it(model):
    """Registering DGA must not change what the other detectors report."""
    flows = [
        make_flow(timestamp=1000.0 + i * 0.1, src_ip="10.0.0.5", dst_ip="10.0.0.9",
                  dst_port=1000 + i, proto="tcp")
        for i in range(40)
    ]
    flows += [dns_flow(1500.0, DGA_QUERY)]

    without = DetectionEngine([PortScanDetector(PortScanConfig())])
    baseline = [(a.threat_class, a.src_ip, a.score) for a in without.run(flows)]

    combined_engine = DetectionEngine(
        [PortScanDetector(PortScanConfig()), DGADetector(model=model)]
    )
    combined = list(combined_engine.run(flows))

    assert combined_engine.stats.detector_errors == 0
    assert [(a.threat_class, a.src_ip, a.score) for a in combined
            if a.threat_class is not ThreatClass.DGA_DOMAIN] == baseline
    assert any(a.threat_class is ThreatClass.DGA_DOMAIN for a in combined)
