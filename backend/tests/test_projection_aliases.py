"""Projection against REAL detector output.

Every evidence bag in this file was captured verbatim from
``detection_core.runner`` running over a labelled synthetic capture. That is the
whole point: the existing fusion tests use fixtures written in the contract's
own vocabulary, so they passed green while five of seven threat classes
rendered no class visual and almost no thresholded evidence against the alerts
the detection layer actually emits.

A test that invents its input cannot catch a disagreement about input.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.fusion.dedup import Deduplicator
from app.projection.aliases import canonicalise_evidence
from app.projection.project import project_alert
from app.schemas.alert_v11 import ThreatAlertV11
from app.schemas.enums import ThreatClass

BASE = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)


# --- captured from a real detection_core run ------------------------------

REAL_EVIDENCE: dict[str, dict] = {
    "c2_beaconing": {
        "observation_count": 6, "interval_count": 5,
        "mean_interval_seconds": 44.76294159889221,
        "interval_stddev_seconds": 1.5385606580099862,
        "coefficient_of_variation": 0.03437130365105546,
        "window_seconds": 900.0, "min_observations": 6,
        "min_mean_interval_seconds": 2.0, "max_mean_interval_seconds": 120.0,
        "max_interval_cv": 0.2, "total_orig_bytes": 5280,
        "total_orig_packets": 36, "average_orig_bytes_per_flow": 880.0,
    },
    "data_exfiltration": {
        "qualification_path": "sustained", "flow_count": 12,
        "total_orig_bytes": 52515241, "total_orig_packets": 37507,
        "max_single_flow_orig_bytes": 5892621,
        "source_total_orig_bytes": 52515241, "destination_concentration": 1.0,
        "total_resp_bytes": 25261, "observed_span_seconds": 62.61597394943237,
        "orig_bytes_per_second": 838687.6013844397, "window_seconds": 300.0,
        "min_total_orig_bytes": 52428800, "min_flows": 10,
        "min_single_flow_orig_bytes": 104857600,
        "min_destination_concentration": 0.6,
    },
    "ddos": {
        "unique_src_ips": 173, "flow_count": 173, "packet_count": 1003,
        "byte_count": 0, "window_seconds": 10.0,
        "observed_span_seconds": 3.4399969577789307,
        "flows_per_second": 50.290742149870745,
        "packets_per_second": 291.5700252966495, "min_unique_sources": 50,
        "min_flows": 200, "min_packets": 1000,
    },
    "dns_tunnelling": {
        "observation_count": 20, "suspicious_observation_count": 20,
        "suspicious_ratio": 1.0, "mean_signals_per_suspicious_observation": 4.0,
        "mean_query_length": 69.0, "max_query_length": 69,
        "mean_query_entropy": 4.8212265, "max_query_entropy": 4.948912,
        "mean_subdomain_entropy": 4.59543225, "mean_label_count": 4.0,
        "max_label_count": 4, "txt_query_count": 20, "txt_ratio": 1.0,
        "total_orig_bytes": 2200, "window_seconds": 300.0,
        "min_dns_observations": 20, "min_suspicious_ratio": 0.5,
        "min_signals_per_observation": 2, "suspicious_query_length": 50,
        "suspicious_entropy": 4.0, "suspicious_subdomain_entropy": 3.5,
        "suspicious_label_count": 5, "suspicious_txt_ratio": 0.3,
        "raw_query_available": True, "raw_query_observation_count": 20,
    },
    "port_scan": {
        "scan_type": "vertical", "unique_dst_ports": 40, "unique_dst_ips": 1,
        "connection_attempts": 40, "window_seconds": 60.0,
        "horizontal_dst_port": None, "max_hosts_per_port": 1,
        "min_unique_ports": 15, "min_unique_hosts": 20,
    },
    # These two produced no alert on the synthetic capture, so their bags are
    # transcribed from the detectors' own _build_alert methods rather than
    # captured. Marked as such so nobody mistakes them for observed output.
    "encrypted_malware": {
        "fingerprint": "51c64c77e60f3980eea90869b68c58a8",
        "fingerprint_type": "ja3", "tls_observation_count": 12,
        "suspicious_observation_count": 9, "suspicious_ratio": 0.75,
        "mean_sni_entropy": 4.1, "max_sni_entropy": 4.6,
        "obsolete_tls_version_ratio": 1.0, "tls_version": "TLSv12",
        "window_seconds": 300.0, "min_tls_observations": 6,
        "min_suspicious_ratio": 0.6,
    },
    "dga_domain": {
        "domain": "kq3v9x2mzt7wp00.com", "dga_model_score": 0.95,
        "score_threshold": 0.75, "model_score_is_calibrated": False,
        "distinct_dga_domain_count": 6,
        "sample_domains": ["kq3v9x2mzt7wp00.com", "kq3v9x2mzt7wp01.com"],
    },
}

SCOPES = {
    "c2_beaconing": ("host_pair", "10.4.2.19", "185.62.11.4", 443, "tcp"),
    "data_exfiltration": ("host_pair", "10.4.2.31", "91.219.236.18", 443, "tcp"),
    "ddos": ("destination_host", None, "10.4.1.10", 80, "tcp"),
    "dns_tunnelling": ("host_pair", "10.4.2.44", "10.4.0.53", 53, "udp"),
    "port_scan": ("source_host", "10.4.2.77", None, None, None),
    "encrypted_malware": ("host_pair", "10.4.2.19", "45.134.26.9", 443, "tcp"),
    "dga_domain": ("source_host", "10.4.2.19", None, None, None),
}


def _alert(threat_class: str, *, alert_id: str | None = None, offset: float = 0.0):
    scope, src, dst, port, proto = SCOPES[threat_class]
    start = BASE + timedelta(seconds=offset)
    return ThreatAlertV11.model_validate(
        {
            "alert_id": alert_id or str(uuid.uuid4()),
            "schema_version": "1.1",
            "event_start": start.isoformat().replace("+00:00", "Z"),
            "event_end": (start + timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
            "detected_at": (start + timedelta(seconds=11)).isoformat().replace("+00:00", "Z"),
            "event_scope": scope,
            "flow_id": None,
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": port,
            "protocol": proto,
            "threat_class": threat_class,
            "severity": "high",
            "score": 0.8,
            "score_type": "rule_score",
            "evidence": REAL_EVIDENCE[threat_class],
            "detector": threat_class,
            "detector_version": "0.1.0",
            "mitre_techniques": [],
            "incident_id": None,
        }
    )


def _project(threat_class: str):
    alert = _alert(threat_class)
    result = Deduplicator().observe(alert)
    return project_alert(alert, dedup=result.state, incident_id=None)


# --- the mismatch this file exists to prevent -----------------------------

#: dns_tunnelling is absent on purpose: its visual needs subdomain samples, and
#: the detector does not currently emit any. Listing it here would mean
#: fabricating one. Its evidence bars are covered by the test below.
CLASSES_WITH_VISUALS = [
    "port_scan", "ddos", "c2_beaconing", "data_exfiltration",
    "encrypted_malware", "dga_domain",
]


@pytest.mark.parametrize("threat_class", CLASSES_WITH_VISUALS)
def test_real_detector_evidence_builds_a_class_visual(threat_class):
    view = _project(threat_class)
    assert view.visual is not None, (
        f"{threat_class} rendered no class visual from real detector evidence"
    )
    assert view.visual.get("kind")


@pytest.mark.parametrize("threat_class", sorted(REAL_EVIDENCE))
def test_real_detector_evidence_produces_thresholded_bars(threat_class):
    view = _project(threat_class)
    bars = [item for item in view.evidence if item.threshold is not None]
    assert bars, (
        f"{threat_class} produced no thresholded evidence bar; the supporting-"
        "evidence requirement is graded on exactly this"
    )


@pytest.mark.parametrize("threat_class", sorted(REAL_EVIDENCE))
def test_at_least_one_bar_is_actually_crossed(threat_class):
    """A bar nobody crossed does not explain why the detector fired."""
    view = _project(threat_class)
    assert any(item.exceeded for item in view.evidence if item.threshold is not None)


def test_detector_operating_point_wins_over_the_registry_table():
    """The threshold shown is the line the detector actually drew.

    port_scan ships ``min_unique_ports: 15``; the static registry's fallback for
    that feature is 100. Showing 100 would misreport the detector's operating
    point by nearly an order of magnitude.
    """
    view = _project("port_scan")
    ports = next(i for i in view.evidence if i.feature == "unique_dst_ports")
    assert ports.threshold == 15
    assert ports.exceeded is True


def test_beacon_cv_is_a_below_threshold_and_reads_as_crossed():
    """Near-zero coefficient of variation IS the beacon detection."""
    view = _project("c2_beaconing")
    cv = next(i for i in view.evidence if i.feature == "interval_cv")
    assert cv.direction == "below"
    assert cv.threshold == 0.2
    assert cv.exceeded is True


def test_conditional_fingerprint_alias_respects_its_declared_type():
    """A JA4 hash must not be filed under ``ja3``."""
    ja3 = canonicalise_evidence(
        ThreatClass.ENCRYPTED_MALWARE,
        {"fingerprint": "abc", "fingerprint_type": "ja3"},
    )
    assert ja3["ja3"] == "abc" and "ja4" not in ja3

    ja4 = canonicalise_evidence(
        ThreatClass.ENCRYPTED_MALWARE,
        {"fingerprint": "abc", "fingerprint_type": "ja4"},
    )
    assert ja4["ja4"] == "abc" and "ja3" not in ja4


def test_operating_point_does_not_also_render_as_its_own_row():
    """``min_unique_ports`` is a threshold, not an observation."""
    view = _project("port_scan")
    assert not any(i.feature == "min_unique_ports" for i in view.evidence)


def test_unknown_evidence_keys_still_reach_the_dashboard():
    """The contract keeps evidence open-ended; a new key must not be dropped."""
    canonical = canonicalise_evidence(
        ThreatClass.PORT_SCAN, {"something_brand_new": 42, "unique_dst_ports": 30}
    )
    assert canonical["something_brand_new"] == 42


def test_raw_evidence_is_never_mutated_by_the_alias_pass():
    """The detector's own words survive verbatim for the raw expander."""
    alert = _alert("c2_beaconing")
    view = project_alert(
        alert, dedup=Deduplicator().observe(alert).state, incident_id=None
    )
    assert view.evidence_raw == REAL_EVIDENCE["c2_beaconing"]
    assert view.raw["evidence"] == REAL_EVIDENCE["c2_beaconing"]
    assert "coefficient_of_variation" in view.evidence_raw


# --- the deduplication blocker --------------------------------------------


def test_sixty_beacon_repeats_collapse_into_one_alert():
    """Build Plan layer 5's completion test, as an assertion.

    "A one-hour replay containing a persistent beacon produces one incident
    with an occurrence count, not sixty alerts."

    Every consumer downstream keys on alert_id - storage upserts on it, the
    dashboard's reducer maps on it - so a repeat that arrives under a fresh id
    appends a row instead of updating one, and the dedup layer collapses
    nothing that anyone can see.
    """
    dedup = Deduplicator(window_s=3600.0)
    views = []
    for i in range(60):
        alert = _alert("c2_beaconing", offset=i * 60.0)
        result = dedup.observe(alert)
        views.append(project_alert(alert, dedup=result.state, incident_id=None))

    assert len({v.alert_id for v in views}) == 1, "sixty rows, not one"
    assert views[-1].occurrences == 60
    assert views[-1].dedup_key == views[0].dedup_key
    # The window spans the whole hour, not just the last check-in.
    assert views[-1].event_start == views[0].event_start
    assert views[-1].event_end > views[0].event_end
    assert views[-1].first_seen == views[0].first_seen


def test_the_original_arrival_id_is_preserved_in_raw():
    """Folding must not lose which emission produced this update."""
    dedup = Deduplicator(window_s=3600.0)
    first = _alert("c2_beaconing", alert_id="11111111-1111-4111-8111-111111111111")
    second = _alert(
        "c2_beaconing", alert_id="22222222-2222-4222-8222-222222222222", offset=60
    )

    project_alert(first, dedup=dedup.observe(first).state, incident_id=None)
    view = project_alert(second, dedup=dedup.observe(second).state, incident_id=None)

    assert view.alert_id == first.alert_id
    assert view.raw["alert_id"] == second.alert_id


def test_folded_alert_keeps_the_strongest_score_seen():
    dedup = Deduplicator(window_s=3600.0)
    strong = _alert("c2_beaconing")
    strong = strong.model_copy(update={"score": 0.91})
    weak = _alert("c2_beaconing", offset=60).model_copy(update={"score": 0.51})

    project_alert(strong, dedup=dedup.observe(strong).state, incident_id=None)
    view = project_alert(weak, dedup=dedup.observe(weak).state, incident_id=None)

    assert view.score == 0.91
    assert view.confidence == 0.91


def test_a_resent_alert_does_not_inflate_the_occurrence_count():
    """The integration guide asks the backend to be safe to replay.

    Detection resends after a failed POST, so a byte-identical redelivery is a
    normal event, not an anomaly. Counting it would inflate the number the
    dashboard shows as "this has happened N times".
    """
    dedup = Deduplicator(window_s=3600.0)
    alert = _alert("c2_beaconing", alert_id="33333333-3333-4333-8333-333333333333")

    first = dedup.observe(alert)
    again = dedup.observe(alert)

    assert first.state.occurrences == 1
    assert again.is_duplicate is True
    assert again.state.occurrences == 1


def test_a_genuine_repeat_still_counts():
    dedup = Deduplicator(window_s=3600.0)
    dedup.observe(_alert("c2_beaconing", alert_id="44444444-4444-4444-8444-444444444444"))
    result = dedup.observe(
        _alert("c2_beaconing", alert_id="55555555-5555-4555-8555-555555555555", offset=60)
    )
    assert result.state.occurrences == 2


def test_dedup_survives_a_capture_replayed_from_the_past():
    """Event time, not wall time.

    Every alert here is dated well before now. Evicting against the wall clock
    would expire each state on the call that created it, and deduplication would
    silently do nothing on exactly the path the demo runs.
    """
    dedup = Deduplicator(window_s=3600.0)
    for i in range(10):
        result = dedup.observe(_alert("c2_beaconing", offset=i * 60.0))
    assert result.state.occurrences == 10
    assert len(dedup) == 1
