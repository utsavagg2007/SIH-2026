"""The generator must produce records detection can actually read.

A synthetic capture that drifts from the real ingestion contract is worse than
no capture at all: it would make every layer above it look healthy while the
seam it stands in for was broken. So these tests validate the generated records
against ``detection_core``'s own adapter - the same code path the real
``features.jsonl`` goes through - rather than against a copy of the field list.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import synth_flows  # noqa: E402
from evaluate import ClassScore, evaluate  # noqa: E402

detection_core = pytest.importorskip(
    "detection_core", reason="detection_core is not installed in this environment"
)
from detection_core.adapters import record_to_flow_event  # noqa: E402


@pytest.fixture(scope="module")
def capture():
    records, scenario = synth_flows.generate(seed=26145, duration=600.0, base_time=1_800_000_000.0)
    return records, scenario


# -- the contract with detection -------------------------------------------


def test_every_record_converts_to_a_flow_event(capture):
    records, _ = capture
    for record in records:
        record_to_flow_event(record)  # raises if the contract is broken


def test_records_are_in_non_decreasing_event_time(capture):
    records, _ = capture
    stamps = [r["timestamp"] for r in records]
    assert stamps == sorted(stamps)


def test_dns_records_carry_the_raw_query(capture):
    """Without this the DGA model cannot run at all."""
    records, _ = capture
    events = [record_to_flow_event(r) for r in records if "dns" in r]
    assert events
    assert any(e.dns and e.dns.query for e in events)


def test_tls_records_carry_raw_fingerprints_and_sni(capture):
    records, _ = capture
    events = [record_to_flow_event(r) for r in records if "tls" in r]
    assert any(e.tls and e.tls.ja3 for e in events)
    assert any(e.tls and e.tls.server_name for e in events)


def test_scan_flows_carry_raw_s0(capture):
    """S0 is the primary port-scan and SYN-flood signal."""
    records, _ = capture
    assert any(record_to_flow_event(r).conn_state == "S0" for r in records)


def test_nxdomain_and_txt_survive_as_names_not_numbers(capture):
    records, _ = capture
    dns = [record_to_flow_event(r).dns for r in records if "dns" in r]
    assert any(d and d.rcode == "NXDOMAIN" for d in dns)
    assert any(d and d.qtype == "TXT" for d in dns)


# -- determinism -----------------------------------------------------------


def test_the_same_seed_produces_the_same_capture():
    """Build Plan layer 1: "the same input file must produce the same alerts"."""
    a, _ = synth_flows.generate(seed=7, duration=120.0, base_time=1_000_000.0)
    b, _ = synth_flows.generate(seed=7, duration=120.0, base_time=1_000_000.0)
    assert [r["flow_id"] for r in a] == [r["flow_id"] for r in b]


def test_a_different_seed_produces_a_different_capture():
    a, _ = synth_flows.generate(seed=7, duration=120.0, base_time=1_000_000.0)
    b, _ = synth_flows.generate(seed=8, duration=120.0, base_time=1_000_000.0)
    assert [r["flow_id"] for r in a] != [r["flow_id"] for r in b]


# -- the manifest ----------------------------------------------------------


def test_all_seven_threat_classes_are_generated(capture):
    _, scenario = capture
    labels = {i.label for i in scenario.intervals}
    for threat_class in (
        "port_scan", "ddos", "c2_beaconing", "dga_domain",
        "dns_tunnelling", "encrypted_malware", "data_exfiltration",
    ):
        assert threat_class in labels, f"{threat_class} is not exercised"


def test_confounders_are_planted_and_labelled_with_what_they_mimic(capture):
    """A precision figure measured without these is meaningless."""
    _, scenario = capture
    mimicked = {i.mimics for i in scenario.intervals if i.label == "benign_confounder"}
    assert {"c2_beaconing", "data_exfiltration", "dga_domain", "port_scan"} <= mimicked


def test_one_host_walks_the_kill_chain(capture):
    """The incident ribbon needs a host that went recon -> c2 -> exfil."""
    _, scenario = capture
    host = synth_flows.COMPROMISED_HOST
    stages = {
        i.label
        for i in scenario.intervals
        if host in i.src_ips and i.label not in ("benign", "benign_confounder")
    }
    assert "port_scan" in stages
    assert "c2_beaconing" in stages
    assert "data_exfiltration" in stages


def test_every_interval_names_its_participants(capture):
    _, scenario = capture
    for interval in scenario.intervals:
        assert interval.src_ips, f"{interval.label} names no source"


# -- the evaluator ---------------------------------------------------------


def _manifest(**interval):
    base = {
        "label": "c2_beaconing", "src_ip": "10.0.0.1", "dst_ip": "1.2.3.4",
        "start": 100.0, "end": 200.0, "flows": 10, "note": "", "mimics": None,
        "src_ips": ["10.0.0.1"], "dst_ips": ["1.2.3.4"],
    }
    base.update(interval)
    return {"duration_seconds": 600.0, "intervals": [base]}


def _alert(**fields):
    base = {
        "threat_class": "c2_beaconing", "src_ip": "10.0.0.1", "dst_ip": "1.2.3.4",
        "event_start": 120.0, "event_end": 180.0, "severity": "high", "score": 0.9,
    }
    base.update(fields)
    return base


def test_a_matching_alert_scores_as_a_true_positive():
    scores, unmatched = evaluate([_alert()], _manifest(), slack_seconds=10.0)
    assert scores["c2_beaconing"].true_positives == 1
    assert unmatched == []


def test_a_different_source_is_not_credited_to_the_interval():
    """The over-crediting bug this rule exists to prevent.

    Every DNS finding on a network shares one destination - the resolver - so
    matching on any shared endpoint would credit an alert about an innocent host
    against the real attack, and the confounder planted to expose it would score
    as a true positive.
    """
    scores, unmatched = evaluate([_alert(src_ip="10.0.0.99")], _manifest(), slack_seconds=10.0)
    assert scores["c2_beaconing"].true_positives == 0
    assert scores["c2_beaconing"].false_positives == 1


def test_a_missed_attack_scores_as_a_false_negative():
    scores, _ = evaluate([], _manifest(), slack_seconds=10.0)
    assert scores["c2_beaconing"].false_negatives == 1
    assert scores["c2_beaconing"].recall == 0.0


def test_a_false_positive_is_attributed_to_its_confounder():
    manifest = {
        "duration_seconds": 600.0,
        "intervals": [
            {
                "label": "benign_confounder", "mimics": "c2_beaconing",
                "src_ip": "10.0.0.50", "dst_ip": None, "start": 0.0, "end": 600.0,
                "flows": 20, "note": "time daemon", "src_ips": ["10.0.0.50"],
                "dst_ips": ["10.0.0.1"],
            }
        ],
    }
    scores, unmatched = evaluate(
        [_alert(src_ip="10.0.0.50", dst_ip="10.0.0.1")], manifest, slack_seconds=10.0
    )
    assert scores["c2_beaconing"].false_positives == 1
    assert unmatched[0]["confounder"] == "time daemon"


def test_precision_and_recall_are_none_rather_than_zero_when_unexercised():
    """A class nothing tested must not report 0.000 as if it had failed."""
    score = ClassScore("port_scan")
    assert score.precision is None
    assert score.recall is None
    assert score.f1 is None
