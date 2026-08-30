"""Deduplication, correlation, and the evidence/visual projection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.fusion.correlate import IncidentEngine, pivot_host
from app.fusion.dedup import Deduplicator, dedup_key
from app.projection.evidence import build_evidence
from app.projection.visuals import OBSERVED, RECONSTRUCTED, build_visual
from app.schemas.alert_v11 import ThreatAlertV11
from app.schemas.enums import KillChainStage, Severity, ThreatClass

# Anchored to the real clock, not a fixed calendar date.
#
# The deduplicator and the incident engine both expire state relative to
# time.time(), so a hardcoded T0 silently stops exercising them the moment wall
# time drifts more than one window away from it: every entry is evicted on
# insert and every "is this a repeat" assertion fails for the wrong reason.
# Anchoring here keeps these tests meaningful whenever they happen to run.
#
# Tests that pass an explicit `now=` are already time-independent and do not
# rely on this.
T0 = datetime.now(timezone.utc) - timedelta(seconds=60)


def make(
    *,
    offset: float = 0.0,
    threat_class: str = "c2_beaconing",
    scope: str = "host_pair",
    src: str | None = "10.4.2.19",
    dst: str | None = "185.62.11.4",
    port: int | None = 443,
    severity: str = "high",
    score: float = 0.9,
    detector: str = "beacon_periodicity",
    evidence: dict | None = None,
    alert_id: str | None = None,
    flow_id: str | None = None,
) -> ThreatAlertV11:
    start = T0 + timedelta(seconds=offset)
    # A flow-scope alert has to name its flow; the schema enforces that, so the
    # helper supplies one rather than every caller having to.
    if scope == "flow" and flow_id is None:
        flow_id = f"{src}:{dst}:{port}:tcp:{start.timestamp():.3f}"
    return ThreatAlertV11.model_validate(
        {
            "alert_id": alert_id or f"a-{threat_class}-{offset}-{src}-{detector}",
            "schema_version": "1.1",
            "event_start": start.isoformat().replace("+00:00", "Z"),
            "event_end": (start + timedelta(seconds=2)).isoformat().replace("+00:00", "Z"),
            "detected_at": (start + timedelta(seconds=2.2)).isoformat().replace("+00:00", "Z"),
            "event_scope": scope,
            "flow_id": flow_id,
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": port,
            "protocol": "tcp",
            "threat_class": threat_class,
            "severity": severity,
            "score": score,
            "score_type": "rule_score",
            "evidence": evidence or {"connection_count": 12, "interval_cv": 0.04},
            "detector": detector,
            "detector_version": "1.0.0",
            "mitre_techniques": ["T1071"],
            "incident_id": None,
        }
    )


class TestDedup:
    def test_sixty_beacons_become_one_alert(self):
        """Build Plan layer 5's literal completion test."""
        d = Deduplicator(window_s=300.0)
        created = duplicates = 0
        for i in range(60):
            # 60s apart, inside the 300s window relative to the previous one.
            r = d.observe(make(offset=i * 60), now=T0.timestamp() + i * 60)
            if r.is_duplicate:
                duplicates += 1
            else:
                created += 1
        assert created == 1
        assert duplicates == 59
        assert len(d) == 1

    def test_occurrence_count_and_first_seen(self):
        d = Deduplicator(window_s=300.0)
        first = d.observe(make(offset=0))
        for i in range(1, 10):
            last = d.observe(make(offset=i * 30))
        assert last.state.occurrences == 10
        assert last.state.first_seen == first.state.first_seen
        assert last.state.alert_id == first.state.alert_id

    def test_window_extends_to_cover_the_whole_span(self):
        d = Deduplicator(window_s=300.0)
        d.observe(make(offset=0))
        r = d.observe(make(offset=200))
        assert r.state.event_start == pytest.approx(T0.timestamp())
        assert r.state.event_end == pytest.approx(T0.timestamp() + 202)

    def test_keeps_max_score(self):
        d = Deduplicator()
        d.observe(make(offset=0, score=0.62))
        r = d.observe(make(offset=30, score=0.94))
        assert r.state.max_score == 0.94
        r = d.observe(make(offset=60, score=0.70))
        assert r.state.max_score == 0.94

    def test_gap_beyond_window_opens_a_new_alert(self):
        d = Deduplicator(window_s=60.0)
        d.observe(make(offset=0))
        r = d.observe(make(offset=600))
        assert r.is_duplicate is False
        assert r.state.occurrences == 1

    def test_different_detectors_dedup_separately(self):
        """Two detectors finding the same thing is corroboration, not noise."""
        d = Deduplicator()
        d.observe(make(detector="beacon_periodicity"))
        r = d.observe(make(detector="ja3_matcher", offset=1))
        assert r.is_duplicate is False

    def test_different_destination_ports_are_distinct(self):
        d = Deduplicator()
        d.observe(make(scope="destination_host", src=None, dst="10.0.0.80", port=80,
                       threat_class="ddos", detector="ddos_detector"))
        r = d.observe(make(scope="destination_host", src=None, dst="10.0.0.80", port=443,
                           threat_class="ddos", detector="ddos_detector", offset=1))
        assert r.is_duplicate is False

    def test_key_is_stable_across_identical_alerts(self):
        assert dedup_key(make(alert_id="x")) == dedup_key(make(alert_id="y"))

    def test_memory_is_bounded(self):
        d = Deduplicator(window_s=3600.0, max_keys=100)
        for i in range(500):
            d.observe(make(offset=i, src=f"10.0.{i // 256}.{i % 256}"))
        assert len(d) <= 100


class TestCorrelation:
    def test_kill_chain_forms_one_incident(self):
        e = IncidentEngine(window_s=1800.0)
        host = "10.4.2.19"
        e.correlate(make(offset=0, threat_class="port_scan", scope="source_host",
                         src=host, dst=None, port=None, detector="portscan_detector"))
        e.correlate(make(offset=300, threat_class="c2_beaconing", src=host))
        inc = e.correlate(make(offset=900, threat_class="data_exfiltration",
                               src=host, dst="198.51.100.14", detector="exfil_anomaly"))
        assert inc is not None
        assert len(inc.members) == 3
        assert inc.stages == [
            KillChainStage.RECON,
            KillChainStage.C2,
            KillChainStage.EXFIL,
        ]

    def test_multi_stage_incident_escalates(self):
        e = IncidentEngine(escalate_stages=2)
        host = "10.4.2.19"
        e.correlate(make(offset=0, threat_class="port_scan", scope="source_host",
                         src=host, dst=None, port=None, severity="medium",
                         detector="portscan_detector"))
        inc = e.correlate(make(offset=60, threat_class="c2_beaconing", src=host,
                               severity="high"))
        severity, escalated = e.effective_severity(inc)
        assert escalated is True
        assert severity is Severity.CRITICAL  # high, escalated one step

    def test_single_stage_does_not_escalate(self):
        e = IncidentEngine(escalate_stages=2)
        e.correlate(make(offset=0, severity="high"))
        inc = e.correlate(make(offset=60, severity="high", detector="other"))
        severity, escalated = e.effective_severity(inc)
        assert escalated is False
        assert severity is Severity.HIGH

    def test_narrative_orders_by_kill_chain(self):
        e = IncidentEngine()
        host = "10.4.2.19"
        # Deliberately out of chain order in time.
        e.correlate(make(offset=0, threat_class="data_exfiltration", src=host,
                         dst="198.51.100.14", detector="exfil_anomaly"))
        inc = e.correlate(make(offset=60, threat_class="port_scan",
                               scope="source_host", src=host, dst=None, port=None,
                               detector="portscan_detector"))
        view = e.to_view(inc)
        assert [m.stage for m in view.members] == [
            KillChainStage.RECON,
            KillChainStage.EXFIL,
        ]
        assert "port scanning" in view.narrative
        assert view.narrative.index("port scanning") < view.narrative.index("exfiltration")

    def test_quiet_gap_opens_a_new_incident(self):
        e = IncidentEngine(window_s=600.0)
        first = e.correlate(make(offset=0))
        second = e.correlate(make(offset=5000, detector="other"))
        assert first.incident_id != second.incident_id

    def test_ddos_pivots_on_the_victim(self):
        """Spoofed sources are useless as a correlation key; the target is stable."""
        alert = make(threat_class="ddos", scope="destination_host", src=None,
                     dst="10.0.0.80", port=80, detector="ddos_detector")
        assert pivot_host(alert) == "10.0.0.80"

    def test_scan_pivots_on_the_source(self):
        alert = make(threat_class="port_scan", scope="source_host",
                     src="10.4.2.77", dst=None, port=None, detector="portscan_detector")
        assert pivot_host(alert) == "10.4.2.77"

    def test_network_scope_without_addresses_has_no_incident(self):
        e = IncidentEngine()
        alert = make(scope="network", src=None, dst=None, port=None,
                     threat_class="ddos", detector="ddos_detector")
        assert e.correlate(alert) is None


class TestEvidenceProjection:
    def test_threshold_features_get_bars(self):
        items = build_evidence(
            ThreatClass.PORT_SCAN,
            {"unique_dst_ports": 1024, "syn_no_ack_ratio": 0.99},
        )
        by_name = {i.feature: i for i in items}
        bar = by_name["unique_dst_ports"]
        assert bar.threshold == 100
        assert bar.direction == "above"
        assert bar.exceeded is True
        assert bar.scale is not None and bar.scale[1] >= 1024

    def test_below_direction_for_beaconing(self):
        """interval_cv is the one where LOW is bad."""
        items = build_evidence(ThreatClass.C2_BEACONING, {"interval_cv": 0.041})
        item = items[0]
        assert item.direction == "below"
        assert item.exceeded is True

    def test_uncrossed_threshold_is_marked_not_exceeded(self):
        items = build_evidence(ThreatClass.C2_BEACONING, {"interval_cv": 0.42})
        assert items[0].exceeded is False

    def test_context_features_have_no_bar(self):
        """Spec 5.1: do not invent a scale to make them look uniform."""
        items = build_evidence(ThreatClass.DGA_DOMAIN, {"query": "abc.com"})
        item = items[0]
        assert item.threshold is None
        assert item.scale is None
        assert item.direction is None

    def test_unknown_feature_still_renders(self):
        items = build_evidence(ThreatClass.DDOS, {"brand_new_key": 42})
        assert items[0].label == "Brand new key"
        assert items[0].threshold is None

    def test_detector_threshold_overrides_registry(self):
        items = build_evidence(
            ThreatClass.PORT_SCAN,
            {"unique_dst_ports": 60, "unique_dst_ports_threshold": 50},
        )
        bar = next(i for i in items if i.feature == "unique_dst_ports")
        assert bar.threshold == 50
        assert bar.exceeded is True
        # The threshold key itself must not appear as its own row.
        assert not any(i.feature.endswith("_threshold") for i in items)

    def test_ordering_puts_most_decisive_first(self):
        items = build_evidence(
            ThreatClass.PORT_SCAN,
            {
                "window_seconds": 12.4,
                "unique_dst_ports": 1024,
                "connection_attempts": 1300,
                "unique_dst_ips": 254,
            },
        )
        assert items[0].feature == "unique_dst_ports"
        assert items[-1].feature == "window_seconds"

    def test_series_are_summarised_not_dumped(self):
        items = build_evidence(ThreatClass.C2_BEACONING, {"timestamps": [1.0] * 400})
        # timestamps is visual-only, so it produces no evidence row at all.
        assert not items

    def test_boolean_flag_renders_as_crossed_threshold(self):
        items = build_evidence(
            ThreatClass.DATA_EXFILTRATION, {"destination_novel": True}
        )
        assert items[0].exceeded is True


class TestVisuals:
    def test_beacon_comb_from_observed_timestamps(self):
        stamps = [T0.timestamp() + i * 60 for i in range(20)]
        v = build_visual(
            make(evidence={"timestamps": stamps, "mean_interval_sec": 60.0,
                           "interval_cv": 0.02})
        )
        assert v is not None
        assert v["kind"] == "beacon_comb"
        assert v["source"] == OBSERVED
        assert len(v["timestamps"]) == 20
        assert len(v["interval_histogram"]) >= 1

    def test_beacon_comb_reconstruction_is_flagged(self):
        """Without a timestamp series we say so rather than implying observation."""
        v = build_visual(
            make(evidence={"mean_interval_sec": 60.0, "connection_count": 10})
        )
        assert v is not None
        assert v["source"] == RECONSTRUCTED

    def test_no_visual_when_data_is_absent(self):
        v = build_visual(make(evidence={"some_unrelated_key": 1}))
        assert v is None

    def test_fanout_matrix_names_the_pattern(self):
        v = build_visual(
            make(
                threat_class="port_scan",
                scope="source_host",
                src="10.4.2.77",
                dst=None,
                port=None,
                detector="portscan_detector",
                evidence={"unique_dst_ports": 1024, "unique_dst_ips": 2,
                          "syn_no_ack_ratio": 0.99},
            )
        )
        assert v["kind"] == "fanout_matrix"
        assert v["pattern"] == "vertical"

    def test_rate_entropy_identifies_spoofed_flood(self):
        v = build_visual(
            make(
                threat_class="ddos",
                scope="destination_host",
                src=None,
                dst="10.0.0.80",
                port=80,
                detector="ddos_detector",
                evidence={"flows_per_sec": 8400.0, "source_ip_entropy": 9.7,
                          "syn_no_ack_ratio": 0.98, "unique_sources": 5200},
            )
        )
        assert v["signature"] == "spoofed_flood"

    def test_rate_entropy_identifies_direct_flood(self):
        v = build_visual(
            make(
                threat_class="ddos",
                scope="destination_host",
                src=None,
                dst="10.0.0.80",
                port=80,
                detector="ddos_detector",
                evidence={"flows_per_sec": 8400.0, "source_ip_entropy": 1.2,
                          "syn_no_ack_ratio": 0.4, "unique_sources": 12},
            )
        )
        assert v["signature"] == "direct_flood"

    def test_amplification_overrides_signature(self):
        v = build_visual(
            make(
                threat_class="ddos",
                scope="destination_host",
                src=None,
                dst="10.0.0.80",
                port=53,
                detector="amplification_detector",
                evidence={"flows_per_sec": 2100.0, "amplification_factor": 54.2,
                          "reflector_port": 53, "source_ip_entropy": 2.1},
            )
        )
        assert v["signature"] == "amplification"

    def test_string_inspector_heat_matches_query_length(self):
        v = build_visual(
            make(
                threat_class="dga_domain",
                scope="flow",
                src="10.0.0.5",
                dst="8.8.8.8",
                port=53,
                detector="dga_classifier",
                evidence={"query": "x7k2p9qz3v1m.com", "ngram_score": 0.02},
            )
        )
        assert v["kind"] == "string_inspector"
        assert len(v["ngram_heat"]) == len(v["characters"])

    def test_non_finite_values_are_stripped(self):
        """inf is not valid JSON and would cost the dashboard the whole frame."""
        v = build_visual(
            make(
                threat_class="data_exfiltration",
                src="10.0.0.5",
                dst="198.51.100.14",
                detector="exfil_anomaly",
                evidence={"outbound_bytes": 512000000, "inbound_bytes": 0},
            )
        )
        assert v["out_in_byte_ratio"] is None


class TestReplayTimeShift:
    """A replayed capture must stay internally consistent.

    The engine rewrites a capture's timestamps onto the current clock. If it
    shifts the alert but not the absolute-time series inside its evidence, the
    beacon comb ends up plotting hour-old ticks against a one-second window and
    renders an empty axis - a silent failure of the single most convincing
    visual in the product.
    """

    def test_evidence_epoch_series_shift_with_the_alert(self):
        from datetime import timedelta as td

        from app.replay.engine import _shift_evidence

        shifted = _shift_evidence(
            {
                "timestamps": [1000.0, 1060.0, 1120.0],
                "series_start": 1000.0,
                "mean_interval_sec": 60.0,
                "record_type": "TXT",
            },
            td(seconds=500),
        )
        assert shifted["timestamps"] == [1500.0, 1560.0, 1620.0]
        assert shifted["series_start"] == 1500.0
        # Relative values carry no absolute time; shifting them would corrupt
        # them.
        assert shifted["mean_interval_sec"] == 60.0
        assert shifted["record_type"] == "TXT"

    def test_shift_preserves_relative_spacing(self):
        from datetime import timedelta as td

        from app.replay.engine import _shift_evidence

        original = [0.0, 60.0, 119.0, 181.0]
        shifted = _shift_evidence({"timestamps": original}, td(seconds=9e5))[
            "timestamps"
        ]
        gaps = lambda s: [b - a for a, b in zip(s, s[1:])]  # noqa: E731
        assert gaps(shifted) == gaps(original)

    def test_comb_axis_covers_a_series_wider_than_the_window(self):
        """An hour of ticks reported with a 1.2s event window still plots."""
        base = T0.timestamp()
        stamps = [base + i * 60 for i in range(60)]
        alert = make(
            offset=0,
            evidence={
                "timestamps": stamps,
                "connection_count": 60,
                "mean_interval_sec": 60.0,
            },
        )
        v = build_visual(alert)
        assert v is not None
        assert v["window_start"] <= stamps[0]
        assert v["window_end"] >= stamps[-1]
        span = v["window_end"] - v["window_start"]
        # Every tick must land inside the axis, or the comb renders blank.
        assert all(v["window_start"] <= t <= v["window_end"] for t in stamps)
        assert span >= 3540


class TestLatencyWindowing:
    """Percentiles must be scopeable to a short recent window.

    The registry keeps a 60s rolling window. A caller measuring a 12s burst that
    follows a saturated one would otherwise read the saturated numbers and
    attribute them to the wrong phase - which is how a load harness ends up
    reporting a fast run as catastrophically slow.
    """

    def _registry(self):
        from app.core.metrics import MetricsRegistry

        return MetricsRegistry(window_s=60.0)

    def _feed(self, reg, now, latency_ms, count, detector="d"):
        for i in range(count):
            reg.record_alert(
                detector=detector,
                detector_version="1.0.0",
                threat_class="port_scan",
                detector_latency_ms=1.0,
                pipeline_latency_ms=latency_ms,
                deduplicated=False,
                now=now + i * 0.01,
            )

    def test_narrow_window_excludes_older_samples(self):
        import time as _t

        reg = self._registry()
        now = _t.time()
        # An old, slow burst 40s ago, then a recent fast one.
        self._feed(reg, now - 40, 9000.0, 50)
        self._feed(reg, now - 2, 20.0, 50)

        wide = reg.latency_percentiles(now)
        narrow = reg.latency_percentiles(now, window_s=5.0)

        assert wide[1] > 1000.0, "full window should still see the slow burst"
        assert narrow[1] < 100.0, "narrow window must exclude it"
        assert narrow[2] <= 20.0

    def test_window_with_no_samples_returns_zeros(self):
        import time as _t

        reg = self._registry()
        now = _t.time()
        self._feed(reg, now - 40, 500.0, 10)
        assert reg.latency_percentiles(now, window_s=1.0) == (0.0, 0.0, 0.0)

    def test_detector_latency_is_not_pipeline_latency(self):
        """The System view's per-detector column is mean scoring time.

        Feeding it pipeline latency would make a slow network look like a slow
        model.
        """
        import time as _t

        reg = self._registry()
        now = _t.time()
        reg.record_alert(
            detector="beacon_periodicity",
            detector_version="0.3.1",
            threat_class="c2_beaconing",
            detector_latency_ms=200.0,
            pipeline_latency_ms=5000.0,
            deduplicated=False,
            now=now,
        )
        rec = reg.detectors["beacon_periodicity"]
        assert rec.mean_detector_latency_ms == pytest.approx(200.0)
        assert reg.latency_percentiles(now)[0] == pytest.approx(5000.0)
