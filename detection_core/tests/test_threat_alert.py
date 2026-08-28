"""ThreatAlert v1.1 contract tests.

These lock the frozen wire contract: vocabularies, the always-normalized
0.0-1.0 score, and ISO-8601 UTC time serialization.
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from detection_core import (
    ALERT_SCHEMA_VERSION,
    EventScope,
    ScoreType,
    Severity,
    ThreatAlert,
    ThreatClass,
)

from .conftest import EPOCH, make_alert

ALL_SCORE_TYPES = list(ScoreType)


# --------------------------------------------------------------------------
# Frozen vocabularies
# --------------------------------------------------------------------------


def test_threat_class_vocabulary_exact():
    assert {member.value for member in ThreatClass} == {
        "dga_domain",
        "dns_tunnelling",
        "c2_beaconing",
        "encrypted_malware",
        "ddos",
        "port_scan",
        "data_exfiltration",
    }


def test_severity_vocabulary_exact():
    assert {member.value for member in Severity} == {
        "low",
        "medium",
        "high",
        "critical",
    }


def test_score_type_vocabulary_exact():
    assert {member.value for member in ScoreType} == {
        "calibrated_model",
        "rule_score",
        "anomaly_score",
        "signature_match",
    }


def test_event_scope_vocabulary_exact():
    assert {member.value for member in EventScope} == {
        "flow",
        "source_host",
        "destination_host",
        "host_pair",
        "network",
    }


def test_schema_version_is_pinned():
    assert ALERT_SCHEMA_VERSION == "1.1"
    assert make_alert().schema_version == "1.1"
    with pytest.raises(ValidationError):
        make_alert(schema_version="1.0")


# --------------------------------------------------------------------------
# Score: always finite, always 0.0-1.0, for EVERY score_type
# --------------------------------------------------------------------------


@pytest.mark.parametrize("score_type", ALL_SCORE_TYPES)
@pytest.mark.parametrize("score", [0.0, 0.25, 0.5, 0.999, 1.0])
def test_score_accepts_normalized_range(score_type, score):
    alert = make_alert(score=score, score_type=score_type)
    assert alert.score == score


@pytest.mark.parametrize("score_type", ALL_SCORE_TYPES)
@pytest.mark.parametrize(
    "score",
    [-0.0001, -1.0, 1.0001, 2.0, 100.0, math.nan, math.inf, -math.inf],
)
def test_score_rejects_out_of_range_for_every_score_type(score_type, score):
    """No score_type gets an exemption from the 0.0-1.0 normalized contract."""
    with pytest.raises(ValidationError):
        make_alert(score=score, score_type=score_type)


# --------------------------------------------------------------------------
# Time representation
# --------------------------------------------------------------------------


def test_naive_datetime_rejected():
    naive = datetime(2026, 8, 29, 0, 20, 10)
    with pytest.raises(ValidationError):
        make_alert(event_start=naive, event_end=naive)


def test_non_utc_offset_normalized_to_utc():
    ist = timezone(timedelta(hours=5, minutes=30))
    local = datetime(2026, 8, 29, 5, 50, 10, tzinfo=ist)
    alert = make_alert(event_start=local, event_end=local)
    assert alert.event_start.utcoffset() == timedelta(0)
    assert alert.event_start == EPOCH


def test_iso8601_z_serialization():
    alert = make_alert(event_start=EPOCH, event_end=EPOCH, detected_at=EPOCH)
    wire = alert.to_wire()
    assert wire["event_start"] == "2026-08-29T00:20:10Z"
    assert wire["event_end"] == "2026-08-29T00:20:10Z"
    assert wire["detected_at"] == "2026-08-29T00:20:10Z"


def test_json_dump_uses_z_suffix():
    alert = make_alert(event_start=EPOCH, event_end=EPOCH, detected_at=EPOCH)
    payload = alert.model_dump_json()
    assert '"event_start":"2026-08-29T00:20:10Z"' in payload
    assert "+00:00" not in payload


def test_sub_second_precision_preserved():
    precise = EPOCH.replace(microsecond=123456)
    alert = make_alert(event_start=precise, event_end=precise)
    assert alert.to_wire()["event_start"] == "2026-08-29T00:20:10.123456Z"


def test_no_epoch_floats_on_the_wire():
    wire = make_alert().to_wire()
    for field in ("event_start", "event_end", "detected_at"):
        assert isinstance(wire[field], str)


def test_event_end_before_start_rejected():
    with pytest.raises(ValidationError):
        make_alert(event_start=EPOCH, event_end=EPOCH - timedelta(seconds=1))


def test_detected_at_defaults_to_aware_now():
    alert = make_alert()
    assert alert.detected_at.tzinfo is not None
    assert alert.detected_at.utcoffset() == timedelta(0)


# --------------------------------------------------------------------------
# Remaining field rules
# --------------------------------------------------------------------------


def test_alert_id_is_unique_by_default():
    assert make_alert().alert_id != make_alert().alert_id


def test_generated_alert_id_is_uuid4():
    parsed = uuid.UUID(make_alert().alert_id)
    assert parsed.version == 4


def test_supplied_uuid4_accepted():
    supplied = str(uuid.uuid4())
    assert make_alert(alert_id=supplied).alert_id == supplied


def test_supplied_uuid4_is_canonicalized():
    """Same id must not reach the wire in two spellings."""
    canonical = str(uuid.uuid4())
    assert make_alert(alert_id=canonical.upper()).alert_id == canonical
    assert make_alert(alert_id="{" + canonical + "}").alert_id == canonical


@pytest.mark.parametrize(
    "value",
    [
        "not-a-uuid",
        "",
        "12345",
        "550e8400-e29b-41d4-a716",
        "zzzzzzzz-e29b-41d4-a716-446655440000",
    ],
)
def test_invalid_alert_id_rejected(value):
    with pytest.raises(ValidationError):
        make_alert(alert_id=value)


@pytest.mark.parametrize(
    ("value", "version"),
    [
        (str(uuid.uuid1()), 1),
        (str(uuid.uuid3(uuid.NAMESPACE_DNS, "example.com")), 3),
        (str(uuid.uuid5(uuid.NAMESPACE_DNS, "example.com")), 5),
        ("00000000-0000-0000-0000-000000000000", None),
    ],
)
def test_non_v4_uuid_rejected(value, version):
    assert uuid.UUID(value).version == version
    with pytest.raises(ValidationError):
        make_alert(alert_id=value)


def test_alert_id_stays_a_string_on_the_wire():
    assert isinstance(make_alert().to_wire()["alert_id"], str)


@pytest.mark.parametrize("techniques", [["T1046"], ["T1568.002"], ["T1041", "T1048"]])
def test_valid_mitre_techniques(techniques):
    assert make_alert(mitre_techniques=techniques).mitre_techniques == techniques


@pytest.mark.parametrize("techniques", [["1046"], ["T104"], ["T1046.12"], ["nope"]])
def test_invalid_mitre_techniques_rejected(techniques):
    with pytest.raises(ValidationError):
        make_alert(mitre_techniques=techniques)


@pytest.mark.parametrize("field", ["detector", "detector_version"])
def test_detector_provenance_required(field):
    with pytest.raises(ValidationError):
        make_alert(**{field: "  "})


def test_aggregate_scope_may_omit_flow_id():
    alert = make_alert(event_scope=EventScope.NETWORK, flow_id=None)
    assert alert.flow_id is None


def test_alert_is_frozen():
    alert = make_alert()
    with pytest.raises(ValidationError):
        alert.score = 0.9


def test_unknown_field_forbidden():
    with pytest.raises(ValidationError):
        make_alert(unexpected_field="nope")


def test_all_contract_fields_present_on_the_wire():
    expected = {
        "alert_id",
        "schema_version",
        "event_start",
        "event_end",
        "detected_at",
        "event_scope",
        "flow_id",
        "src_ip",
        "dst_ip",
        "dst_port",
        "protocol",
        "threat_class",
        "severity",
        "score",
        "score_type",
        "evidence",
        "detector",
        "detector_version",
        "mitre_techniques",
        "incident_id",
    }
    assert set(make_alert().to_wire()) == expected
