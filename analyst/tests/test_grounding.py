"""The grounding layer is where truthfulness is enforced, so it is where the
tests concentrate. Nothing here touches the network or a model.
"""

from __future__ import annotations

from analyst.grounding import (
    describe_alert,
    describe_corpus,
    describe_incident,
    render_plain,
    unsupported_numbers,
)

ALERT = {
    "alert_id": "a7f3c210-0000-4000-8000-000000000001",
    "schema_version": "1.1",
    "ts": 1735689612.88,
    "event_start": 1735689600.0,
    "event_end": 1735689612.0,
    "detected_at": 1735689612.88,
    "event_scope": "host_pair",
    "flow_id": None,
    "src_ip": "10.4.2.19",
    "dst_ip": "185.62.11.4",
    "dst_port": 443,
    "protocol": "tcp",
    "threat_class": "c2_beaconing",
    "threat_label": "C2 Beaconing",
    "threat_code": "BC",
    "severity": "critical",
    "score": 0.91,
    "score_type": "rule_score",
    "detector": "c2_beaconing",
    "detector_version": "0.1.0",
    "mitre_techniques": ["T1071.001"],
    "incident_id": "i2c9f004",
    "kill_chain_stage": "command_and_control",
    "occurrences": 42,
    "first_seen": 1735688100.1,
    "evidence": [
        {
            "feature": "coefficient_of_variation",
            "label": "Interval coefficient of variation",
            "value": 0.041,
            "threshold": 0.15,
            "direction": "below",
            "exceeded": True,
            "rank": 0,
        },
        {
            "feature": "observation_count",
            "label": "Observed periods",
            "value": 42,
            "threshold": 8,
            "direction": "above",
            "exceeded": True,
            "rank": 10,
        },
        {
            "feature": "mean_interval_seconds",
            "label": "Mean interval",
            "value": 60.2,
            "unit": "s",
            "rank": 20,
        },
    ],
}


def test_every_fact_carries_a_source():
    sheet = describe_alert(ALERT)
    assert sheet.facts
    assert all(fact.source for fact in sheet.facts)


def test_evidence_becomes_cited_facts_with_thresholds():
    sheet = describe_alert(ALERT)
    sources = {fact.source for fact in sheet.facts}
    assert "evidence.coefficient_of_variation" in sources
    assert "evidence.observation_count" in sources

    cv = next(f for f in sheet.facts if f.source == "evidence.coefficient_of_variation")
    assert "0.041" in cv.text
    assert "0.15" in cv.text
    assert "crossed" in cv.text


def test_rule_score_is_never_called_a_probability():
    text = render_plain(describe_alert(ALERT))
    assert "not a probability" in text
    assert "threat score" in text.lower()


def test_null_destination_is_labelled_not_invented():
    aggregate = dict(ALERT, dst_ip=None, dst_port=None, event_scope="source_host")
    text = render_plain(describe_alert(aggregate))
    assert "multiple destinations" in text
    # The stored value stays null; only the label is derived.
    assert aggregate["dst_ip"] is None


def test_occurrences_are_reported_when_deduplicated():
    text = render_plain(describe_alert(ALERT))
    assert "repeated 42 times" in text


def test_unsupported_numbers_flags_an_invented_figure():
    sheet = describe_alert(ALERT)
    good = "The beacon repeated 42 times with a mean interval of 60.2 seconds."
    assert unsupported_numbers(good, sheet) == []

    bad = "The host transferred 4.7 GB to the command server."
    assert "4.7" in unsupported_numbers(bad, sheet)


def test_unsupported_numbers_allows_small_ordinals():
    sheet = describe_alert(ALERT)
    assert unsupported_numbers("There are 3 stages in this sequence.", sheet) == []


def test_empty_corpus_sets_a_refusal_reason():
    sheet = describe_corpus("what beaconed in the last hour", [], window="in the last 1 hour")
    assert sheet.is_empty
    assert sheet.empty_reason is not None
    assert "in the last 1 hour" in sheet.empty_reason


def test_incident_orders_the_kill_chain():
    incident = {
        "incident_id": "i2c9f004",
        "pivot_host": "10.4.2.19",
        "opened_at": 1735688100.0,
        "updated_at": 1735689612.0,
        "severity": "critical",
        "confidence": 0.91,
        "escalated": True,
        "alert_count": 3,
        "elapsed_sec": 1512.0,
        "stages": ["exfiltration", "reconnaissance", "command_and_control"],
        "threat_classes": ["data_exfiltration", "port_scan", "c2_beaconing"],
        "narrative": "Host 10.4.2.19 scanned, then beaconed, then uploaded.",
        "members": [
            {"alert_id": "x1", "ts": 1735688100.0, "threat_class": "port_scan",
             "severity": "high", "confidence": 0.88, "stage": "reconnaissance", "occurrences": 1},
            {"alert_id": "x2", "ts": 1735688464.0, "threat_class": "c2_beaconing",
             "severity": "critical", "confidence": 0.91, "stage": "command_and_control", "occurrences": 42},
        ],
    }
    sheet = describe_incident(incident, [ALERT])
    text = render_plain(sheet)
    stage_fact = next(f for f in sheet.facts if f.source == "stages")
    assert stage_fact.value == ["reconnaissance", "command_and_control", "exfiltration"]
    assert "escalated" in text
    assert sheet.alert_ids == ["x1", "x2"]
