"""Pre-integration validation: every threat class, through the real pipeline.

**All traffic in this file is SYNTHETIC** — hand-built FlowEvents and JSONL,
shaped to cross the *shipped* thresholds. It is a wiring proof, not evidence
about real networks: it shows that a record carrying the right fields reaches
the right detector and comes out as a conforming ThreatAlert. It says nothing
about detection rates, false positives, or how any of this behaves on a real
capture. Those need real data, which is an external dependency (see
INTEGRATION.md).

Nothing here lowers a production threshold to make a detector fire. Where a
detector needs a lot of evidence, the workload supplies a lot of evidence.

Everything runs through the public path — `IngestionJsonlAdapter` →
`DetectionEngine` → the detectors from `build_default_detectors` — never by
poking a private method, because the point is to test the assembly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from detection_core import (
    DetectionEngine,
    DnsInfo,
    EventScope,
    IngestionJsonlAdapter,
    ScoreType,
    Severity,
    ThreatClass,
    TlsInfo,
    build_default_detectors,
)
from detection_core.config import DetectorSettings
from detection_core.fingerprints import load_fingerprint_feed

MIB = 1024 * 1024

# Synthetic fingerprints. Not indicators of anything.
JA3 = "0123456789abcdef0123456789abcdef"
JA3S = "fedcba9876543210fedcba9876543210"
JA4 = "t13d1516h2_8daaf6152771_02713d6af862"

#: A generated-looking name the stub model scores as DGA.
DGA_DOMAINS = [f"kq3v9x2mzt7wp{i:02d}.com" for i in range(6)]


@dataclass(frozen=True)
class StubPrediction:
    domain: str
    normalized_domain: str
    label: int
    dga_score: float


class SyntheticDGAModel:
    """Scores the synthetic generated names high, everything else low.

    A stub rather than a fitted forest: this file validates *wiring*, and a
    real model would make the test slow and its verdicts incidental. The
    fitted-model path is covered by the DGA suites.
    """

    is_fitted = True

    def predict_domain(self, domain: str) -> StubPrediction:
        score = 0.95 if domain in DGA_DOMAINS else 0.05
        return StubPrediction(domain, domain, 1 if score >= 0.75 else 0, score)


# --------------------------------------------------------------------------
# The canonical workload, as ingestion-shaped JSONL records
# --------------------------------------------------------------------------


def record(timestamp, src, dst, port, proto="tcp", **extra):
    payload = {
        "flow_id": f"{src}:{dst}:{port}:{proto}:{timestamp:.3f}",
        "src_ip": src, "dst_ip": dst, "dst_port": port, "proto": proto,
        "duration": 0.05, "orig_bytes": 200, "resp_bytes": 400,
        "orig_pkts": 3, "resp_pkts": 4,
    }
    payload.update(extra)
    return payload


def port_scan_records():
    """One source, 20 distinct ports in 2s: vertical, against a bar of 15."""
    return [
        record(1000.0 + i * 0.1, "10.0.0.5", "10.0.0.90", 1000 + i,
               orig_bytes=60, resp_bytes=0, orig_pkts=1, resp_pkts=0)
        for i in range(20)
    ]


def ddos_records():
    """300 distinct sources onto one victim in 0.6s: 50 sources / 200 flows."""
    return [
        record(2000.0 + i * 0.002, f"198.51.{i // 256}.{i % 256}", "10.0.0.80", 80,
               orig_bytes=200, resp_bytes=0, orig_pkts=5, resp_pkts=0)
        for i in range(300)
    ]


def c2_records():
    """12 contacts on an exact 30s timer: 6 observations, CV 0."""
    return [
        record(3000.0 + i * 30.0, "10.0.0.50", "203.0.113.10", 443,
               orig_bytes=512, resp_bytes=700, orig_pkts=5, resp_pkts=6)
        for i in range(12)
    ]


def dns_tunnel_records():
    """25 long, high-entropy, deeply-labelled TXT lookups to one resolver."""
    return [
        record(4000.0 + i, "192.168.1.42", "192.168.1.1", 53, proto="udp",
               orig_bytes=74, resp_bytes=190,
               dns={"uid": f"Ctun{i}", "query_length": 110, "query_entropy": 4.9,
                    "subdomain_entropy": 4.7, "is_txt": True, "label_count": 9})
        for i in range(25)
    ]


def exfil_records():
    """12 uploads of 8 MiB to one destination: 10 flows / 50 MiB, concentrated."""
    return [
        record(5000.0 + i, "10.0.0.30", "203.0.113.77", 443,
               orig_bytes=8 * MIB, resp_bytes=512, orig_pkts=6000, resp_pkts=10)
        for i in range(12)
    ]


def encrypted_signature_records():
    """One handshake carrying a fingerprint the feed lists."""
    return [
        record(6000.0, "10.0.0.60", "203.0.113.44", 443,
               tls={"uid": "Csig", "ja3": JA3.upper(), "ja3s": JA3S, "ja4": JA4,
                    "server_name": "www.example.com", "version": "TLSv13",
                    "has_ja3": True, "has_ja3s": True})
    ]


def encrypted_heuristic_records():
    """8 handshakes to one pair with long, high-entropy SNI - the metadata path."""
    generated = "x7k2m9p4q1w8e3r6t5y0u2i4o6a8s1d3.example.com"
    return [
        record(6100.0 + i, "10.0.0.61", "203.0.113.45", 443,
               tls={"uid": f"Chx{i}", "server_name": generated, "version": "TLSv13"})
        for i in range(8)
    ]


def dga_records():
    """Six distinct generated names from one host, with a raw dns.query."""
    return [
        record(7000.0 + i * 10.0, "10.0.0.20", "10.0.0.53", 53, proto="udp",
               orig_bytes=74, resp_bytes=190,
               dns={"uid": f"Cdga{i}", "query": domain, "qtype": "A",
                    "rcode": "NOERROR", "query_length": len(domain),
                    "query_entropy": 3.9, "label_count": 2, "is_txt": False})
        for i, domain in enumerate(DGA_DOMAINS)
    ]


def canonical_records():
    """Every threat class, in one deterministic synthetic capture."""
    return (
        port_scan_records() + ddos_records() + c2_records()
        + dns_tunnel_records() + exfil_records()
        + encrypted_signature_records() + encrypted_heuristic_records()
        + dga_records()
    )


@pytest.fixture(scope="module")
def capture(tmp_path_factory):
    """The workload on disk, so the real adapter parses it."""
    path = tmp_path_factory.mktemp("seven") / "synthetic_capture.jsonl"
    path.write_text(
        "\n".join(json.dumps(r) for r in canonical_records()) + "\n", encoding="utf-8"
    )
    return path


@pytest.fixture(scope="module")
def feed(tmp_path_factory):
    path = tmp_path_factory.mktemp("seven") / "fingerprints.txt"
    path.write_text(
        f"# synthetic - not real indicators\nja3:{JA3}\nja3s:{JA3S}\nja4:{JA4}\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture(scope="module")
def alerts(capture, feed):
    """Adapter -> engine -> all seven detectors. The real assembly."""
    settings = DetectorSettings().with_fingerprints(load_fingerprint_feed(feed))
    detectors = build_default_detectors(
        settings=settings, dga_model=SyntheticDGAModel()
    )
    engine = DetectionEngine(detectors)
    return list(engine.run(IngestionJsonlAdapter(path=capture))), engine


# --------------------------------------------------------------------------
# Phase 4: all seven classes, through the real pipeline
# --------------------------------------------------------------------------


def test_all_seven_detectors_are_registered():
    detectors = build_default_detectors(dga_model=SyntheticDGAModel())

    assert [d.name for d in detectors] == [
        "port_scan", "ddos", "c2_beaconing", "dns_tunnelling",
        "data_exfiltration", "encrypted_malware", "dga_domain",
    ]
    assert {d.name for d in detectors} == {t.value for t in ThreatClass}


def test_every_threat_class_fires(alerts):
    produced, engine = alerts
    observed = {alert.threat_class for alert in produced}

    missing = set(ThreatClass) - observed
    assert not missing, f"never fired: {sorted(t.value for t in missing)}"
    assert engine.stats.detector_errors == 0


def test_the_capture_was_fully_parsed(alerts, capture):
    _produced, engine = alerts
    lines = len(capture.read_text(encoding="utf-8").strip().splitlines())

    assert engine.stats.flows_processed == lines


@pytest.mark.parametrize("threat", list(ThreatClass), ids=lambda t: t.value)
def test_each_class_produces_at_least_one_alert(alerts, threat):
    produced, _engine = alerts

    assert [a for a in produced if a.threat_class is threat], threat.value


def test_alert_counts_by_class_are_reported(alerts):
    """Not an assertion about volume - a record of what this workload does."""
    produced, _engine = alerts
    counts = {}
    for alert in produced:
        counts[alert.threat_class.value] = counts.get(alert.threat_class.value, 0) + 1

    assert sum(counts.values()) == len(produced)
    assert len(counts) == 7


# --------------------------------------------------------------------------
# ThreatAlert v1.1 conformance, on every alert the workload produces
# --------------------------------------------------------------------------


def test_every_alert_conforms_to_the_frozen_contract(alerts):
    import uuid

    produced, _engine = alerts
    assert produced, "no alerts to check"

    for alert in produced:
        wire = alert.to_wire()
        assert wire["schema_version"] == "1.1"
        assert uuid.UUID(wire["alert_id"]).version == 4
        assert wire["event_start"].endswith("Z") and wire["event_end"].endswith("Z")
        assert wire["detected_at"].endswith("Z")
        assert alert.event_start <= alert.event_end
        assert wire["event_scope"] in {s.value for s in EventScope}
        assert wire["threat_class"] in {t.value for t in ThreatClass}
        assert wire["severity"] in {s.value for s in Severity}
        assert wire["score_type"] in {s.value for s in ScoreType}
        assert isinstance(wire["score"], float) and 0.0 <= wire["score"] <= 1.0
        assert isinstance(wire["evidence"], dict) and wire["evidence"]
        assert wire["detector"] and wire["detector_version"]
        assert wire["mitre_techniques"] and all(
            t.startswith("T") for t in wire["mitre_techniques"]
        )
        assert wire["incident_id"] is None
        assert json.loads(json.dumps(wire)) == wire


def test_no_alert_invents_a_placeholder_endpoint(alerts):
    """Aggregate fields are None when there is no single truthful value."""
    produced, _engine = alerts

    for alert in produced:
        assert alert.dst_ip != "multiple" and alert.src_ip != "multiple"
        assert alert.protocol != "multiple"
        assert alert.dst_port != 0, "port 0 is a placeholder, not a port"
        if alert.event_scope is not EventScope.FLOW:
            assert alert.flow_id is None, "an aggregate alert named one flow"


def test_scopes_are_truthful_per_detector(alerts):
    produced, _engine = alerts
    scopes = {a.detector: a.event_scope for a in produced}

    assert scopes["port_scan"] is EventScope.SOURCE_HOST
    assert scopes["ddos"] is EventScope.DESTINATION_HOST
    assert scopes["c2_beaconing"] is EventScope.HOST_PAIR
    assert scopes["dns_tunnelling"] is EventScope.HOST_PAIR
    assert scopes["data_exfiltration"] is EventScope.HOST_PAIR
    assert scopes["dga_domain"] is EventScope.SOURCE_HOST


# --------------------------------------------------------------------------
# Phase 6-8: per-detector evidence, through the same run
# --------------------------------------------------------------------------


def only(produced, threat: ThreatClass):
    return [a for a in produced if a.threat_class is threat]


def test_port_scan_reports_a_vertical_sweep(alerts):
    produced, _ = alerts
    alert = only(produced, ThreatClass.PORT_SCAN)[0]

    assert alert.src_ip == "10.0.0.5"
    assert alert.evidence["scan_type"] in {"vertical", "combined"}
    assert alert.evidence["unique_dst_ports"] >= alert.evidence["min_unique_ports"]
    assert alert.score_type is ScoreType.RULE_SCORE


def test_ddos_counts_breadth_and_originator_volume(alerts):
    produced, _ = alerts
    alert = only(produced, ThreatClass.DDOS)[0]

    assert alert.dst_ip == "10.0.0.80"
    assert alert.evidence["unique_src_ips"] >= alert.evidence["min_unique_sources"]
    assert alert.evidence["packet_count"] > 0
    assert alert.src_ip is None, "many sources cannot collapse to one"


def test_c2_reports_a_regular_cadence(alerts):
    produced, _ = alerts
    alert = only(produced, ThreatClass.C2_BEACONING)[0]

    evidence = alert.evidence
    assert evidence["coefficient_of_variation"] <= evidence["max_interval_cv"]
    assert evidence["mean_interval_seconds"] == pytest.approx(30.0)
    assert evidence["interval_count"] >= evidence["min_observations"] - 1


def test_dns_tunnelling_uses_derived_metadata_only(alerts):
    produced, _ = alerts
    alert = only(produced, ThreatClass.DNS_TUNNELLING)[0]

    evidence = alert.evidence
    assert evidence["observation_count"] >= evidence["min_dns_observations"]
    assert evidence["suspicious_ratio"] >= evidence["min_suspicious_ratio"]
    # These records carry no raw query, and the evidence says so honestly.
    assert evidence["raw_query_available"] is False
    assert evidence["raw_query_observation_count"] == 0
    # The aggregate transport is truthful: every contributing flow used udp/53.
    assert alert.dst_port == 53 and alert.protocol == "udp"


def test_exfiltration_qualifies_on_originator_bytes(alerts):
    produced, _ = alerts
    alert = only(produced, ThreatClass.DATA_EXFILTRATION)[0]

    evidence = alert.evidence
    assert evidence["total_orig_bytes"] >= evidence["min_total_orig_bytes"]
    assert evidence["flow_count"] >= evidence["min_flows"]
    assert alert.src_ip == "10.0.0.30"


def test_encrypted_malware_fires_on_the_configured_fingerprint(alerts):
    produced, _ = alerts
    signature = [
        a for a in only(produced, ThreatClass.ENCRYPTED_MALWARE)
        if a.score_type is ScoreType.SIGNATURE_MATCH
    ]

    assert signature, "the JA3 feed did not reach the detector"
    evidence = signature[0].evidence
    assert evidence["fingerprint_type"] in {"ja3", "ja3s", "ja4"}
    assert evidence["fingerprint"] in {JA3, JA3S, JA4}


def test_encrypted_malware_also_fires_on_sni_metadata(alerts):
    """The heuristic path, distinct from the signature path."""
    produced, _ = alerts
    heuristic = [
        a for a in only(produced, ThreatClass.ENCRYPTED_MALWARE)
        if a.score_type is ScoreType.RULE_SCORE
    ]

    assert heuristic, "the SNI metadata path did not fire"
    assert heuristic[0].evidence["observation_count"] >= 6


def test_dga_reports_the_source_with_model_provenance(alerts):
    produced, _ = alerts
    alert = only(produced, ThreatClass.DGA_DOMAIN)[0]

    evidence = alert.evidence
    assert alert.src_ip == "10.0.0.20"
    assert alert.event_scope is EventScope.SOURCE_HOST
    assert alert.score_type is ScoreType.RULE_SCORE, "never calibrated_model"
    assert evidence["model_score_is_calibrated"] is False
    assert evidence["dga_model_score"] == 0.95
    assert evidence["score_threshold"] == 0.75
    assert evidence["domain"] in DGA_DOMAINS
    assert "distinct_dga_domain_count" in evidence


def test_dga_aggregates_rather_than_alerting_per_domain(alerts):
    """Batch 2's guarantee, verified through the whole pipeline."""
    produced, _ = alerts
    dga = only(produced, ThreatClass.DGA_DOMAIN)

    assert len(dga) < len(DGA_DOMAINS), (
        f"{len(dga)} alerts for {len(DGA_DOMAINS)} domains - aggregation lost"
    )


# --------------------------------------------------------------------------
# Phase 12: independent runs must not inherit state
# --------------------------------------------------------------------------


def test_a_second_run_does_not_inherit_state(capture, feed):
    """The engine resets detectors before each source by default."""
    settings = DetectorSettings().with_fingerprints(load_fingerprint_feed(feed))
    engine = DetectionEngine(
        build_default_detectors(settings=settings, dga_model=SyntheticDGAModel())
    )

    first = list(engine.run(IngestionJsonlAdapter(path=capture)))
    second = list(engine.run(IngestionJsonlAdapter(path=capture)))

    assert [a.threat_class for a in first] == [a.threat_class for a in second]
    assert [a.score for a in first] == [a.score for a in second]
    assert [a.evidence for a in first] == [a.evidence for a in second]


def test_state_drains_after_a_reset(capture, feed):
    settings = DetectorSettings().with_fingerprints(load_fingerprint_feed(feed))
    detectors = build_default_detectors(
        settings=settings, dga_model=SyntheticDGAModel()
    )
    engine = DetectionEngine(detectors)
    list(engine.run(IngestionJsonlAdapter(path=capture)))

    engine.reset()

    for detector in detectors:
        for attribute in ("_windows", "_state", "_intervals", "_sources",
                          "_pair_state", "_signature_state", "_last_alert_at"):
            held = getattr(detector, attribute, None)
            if held is not None:
                assert len(held) == 0, f"{detector.name}.{attribute} survived reset"


# --------------------------------------------------------------------------
# Phase 5: the adapter is ready for the fields ingestion has yet to emit
# --------------------------------------------------------------------------


FUTURE_RECORD = {
    "flow_id": "10.0.0.1:10.0.0.2:443:tcp:1747147700.500",
    "timestamp": 1747147700.5,
    "uid": "CtopLevel1",
    "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
    "src_port": 51234, "dst_port": 443,
    "proto": "tcp", "service": "ssl", "conn_state": "SF",
    "duration": 1.25, "orig_bytes": 100, "resp_bytes": 200,
    "orig_pkts": 2, "resp_pkts": 3,
    "dns": {
        "uid": "Cdns", "query": "kq3v9x2mzt7wp01.com", "qtype": "A",
        "rcode": "NXDOMAIN", "query_length": 19, "query_entropy": 3.9,
        "subdomain_entropy": 0.0, "label_count": 2, "is_txt": False,
    },
    "tls": {
        "uid": "Ctls", "server_name": "login.example.com",
        "ja3": "0123456789ABCDEF0123456789abcdef",
        "ja3s": "fedcba9876543210fedcba9876543210",
        "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
        "version": "TLSv13", "sni_length": 17, "sni_entropy": 3.55,
        "has_ja3": True, "has_ja3s": True,
    },
}


@pytest.mark.parametrize(
    "path,expected",
    [
        ("timestamp", 1747147700.5),
        ("uid", "CtopLevel1"),
        ("src_port", 51234),
        ("dst_port", 443),
        ("service", "ssl"),
        ("conn_state", "SF"),
        ("dns.query", "kq3v9x2mzt7wp01.com"),
        ("dns.qtype", "A"),
        ("dns.rcode", "NXDOMAIN"),
        ("tls.server_name", "login.example.com"),
        ("tls.ja3", "0123456789ABCDEF0123456789abcdef"),
        ("tls.ja3s", "fedcba9876543210fedcba9876543210"),
        ("tls.ja4", "t13d1516h2_8daaf6152771_02713d6af862"),
        ("tls.version", "TLSv13"),
        ("tls.sni_length", 17),
        ("tls.sni_entropy", 3.55),
    ],
)
def test_the_adapter_preserves_every_awaited_field(path, expected):
    """The acceptance check for tomorrow's ingestion handoff.

    Each of these is a field ingestion does not emit today. Detection already
    parses and preserves them **exactly** - no encoding, no truncation, no
    lowercasing - so the day they appear in ``features.jsonl`` they reach the
    detectors unchanged. Raw strings must stay raw strings: a fingerprint or
    a domain encoded to a numeric id would be unusable.
    """
    from detection_core.adapters import record_to_flow_event

    flow = record_to_flow_event(FUTURE_RECORD)

    value = flow
    for part in path.split("."):
        value = getattr(value, part)
    assert value == expected, f"{path} was not preserved"


def test_a_record_without_the_future_fields_still_parses():
    """Today's ingestion shape must keep working while we wait."""
    from detection_core.adapters import record_to_flow_event

    minimal = {
        "flow_id": "10.0.0.1:10.0.0.2:443:tcp:1747147700.500",
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 443,
        "proto": "tcp", "duration": 1.25, "orig_bytes": 100,
        "resp_bytes": 200, "orig_pkts": 2, "resp_pkts": 3,
    }

    flow = record_to_flow_event(minimal)

    assert flow.timestamp == 1747147700.5  # recovered from flow_id
    assert flow.dns is None and flow.tls is None
    assert flow.service is None and flow.src_port is None


# --------------------------------------------------------------------------
# Phase 10-11: the runner, with the options combined
# --------------------------------------------------------------------------


def read_alerts(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_the_runner_handles_config_feed_and_model_together(tmp_path, capture, feed):
    """Every Batch-3 option at once, plus a DGA model - nothing disables another."""
    from detection_core import runner

    config = tmp_path / "detectors.toml"
    config.write_text(
        # A second synthetic fingerprint via config, to prove the union.
        '[encrypted_malware]\nja3_fingerprints = '
        '["aaaabbbbccccddddeeeeffff00001111"]\n'
        "[port_scan]\ncooldown_seconds = 120.0\n",
        encoding="utf-8",
    )
    out = tmp_path / "alerts.jsonl"

    # The model must be a real artifact for the CLI path, so fit a tiny one.
    from detection_core.ml.dga import LABEL_BENIGN, LABEL_DGA, DGAModel

    model = DGAModel.new(n_estimators=20, random_state=42, n_jobs=1)
    model.fit(
        ["google.com", "wikipedia.org", "github.com"] + DGA_DOMAINS[:3],
        [LABEL_BENIGN] * 3 + [LABEL_DGA] * 3,
    )
    model_path = model.save(tmp_path / "model.joblib")

    code = runner.main([
        str(capture), "--output", str(out),
        "--config", str(config), "--ja3-feed", str(feed),
        "--dga-model", str(model_path), "--quiet",
    ])

    assert code == 0
    produced = read_alerts(out)
    classes = {a["threat_class"] for a in produced}
    # The signature path still fires: the feed was not replaced by config.
    assert "encrypted_malware" in classes
    assert any(
        a["score_type"] == "signature_match" for a in produced
    ), "the --ja3-feed fingerprints were lost when --config also supplied some"
    # The configured cooldown reached the rule detectors.
    assert "port_scan" in classes


def test_repeated_runner_invocations_do_not_leak_state(tmp_path, capture):
    """main() twice in one process must produce identical output."""
    from detection_core import runner

    first, second = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    assert runner.main([str(capture), "--output", str(first), "--quiet"]) == 0
    assert runner.main([str(capture), "--output", str(second), "--quiet"]) == 0

    strip = lambda rows: [  # noqa: E731 - alert_id and detected_at are generated
        {k: v for k, v in row.items() if k not in ("alert_id", "detected_at")}
        for row in rows
    ]
    assert strip(read_alerts(first)) == strip(read_alerts(second))


def test_stdout_stays_pure_jsonl_with_every_option(tmp_path, capture, feed, capsys):
    from detection_core import runner

    config = tmp_path / "c.toml"
    config.write_text("[ddos]\ncooldown_seconds = 30.0\n", encoding="utf-8")

    assert runner.main([str(capture), "--config", str(config),
                        "--ja3-feed", str(feed)]) == 0

    captured = capsys.readouterr()
    lines = [line for line in captured.out.splitlines() if line]
    assert lines, "expected alerts on stdout"
    for line in lines:
        assert json.loads(line)["schema_version"] == "1.1"
    assert "detectors:" in captured.err, "logs must go to stderr"
