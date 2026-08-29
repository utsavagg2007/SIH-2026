"""The frozen contract must actually be frozen.

These tests are the executable half of the freeze checklist in alert spec
section 20.  If one of them fails, either a detector has drifted from the
contract or somebody has changed the contract without bumping the version.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.alert_v11 import ThreatAlertV11
from app.schemas.enums import EventScope, ScoreType, Severity, ThreatClass

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def base_alert(**overrides) -> dict:
    alert = {
        "alert_id": "11111111-1111-4111-8111-111111111111",
        "schema_version": "1.1",
        "event_start": "2026-08-28T23:44:03Z",
        "event_end": "2026-08-28T23:44:15Z",
        "detected_at": "2026-08-28T23:44:15.300Z",
        "event_scope": "source_host",
        "flow_id": None,
        "src_ip": "10.0.0.5",
        "dst_ip": None,
        "dst_port": None,
        "protocol": "tcp",
        "threat_class": "port_scan",
        "severity": "high",
        "score": 0.90,
        "score_type": "rule_score",
        "evidence": {"unique_dst_ports": 1024, "syn_no_ack_ratio": 0.99},
        "detector": "portscan_detector",
        "detector_version": "1.0.0",
        "mitre_techniques": ["T1046"],
        "incident_id": None,
    }
    alert.update(overrides)
    return alert


class TestFrozenEnums:
    """Spec section 20: seven threat classes, four severities, four score types."""

    def test_threat_classes(self):
        assert {t.value for t in ThreatClass} == {
            "dga_domain",
            "dns_tunnelling",
            "c2_beaconing",
            "encrypted_malware",
            "ddos",
            "port_scan",
            "data_exfiltration",
        }

    def test_severities(self):
        assert [s.value for s in Severity] == ["low", "medium", "high", "critical"]

    def test_score_types(self):
        assert {s.value for s in ScoreType} == {
            "calibrated_model",
            "rule_score",
            "anomaly_score",
            "signature_match",
        }

    def test_event_scopes(self):
        assert {s.value for s in EventScope} == {
            "flow",
            "source_host",
            "destination_host",
            "host_pair",
            "network",
        }


class TestSpecExamples:
    """Every sample alert in spec section 8 must validate unchanged."""

    @pytest.mark.parametrize(
        "path", sorted(FIXTURES.glob("*.jsonl")), ids=lambda p: p.name
    )
    def test_fixture_file_validates(self, path: Path):
        count = 0
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                ThreatAlertV11.model_validate_json(line)
            except ValidationError as exc:
                pytest.fail(f"{path.name}:{lineno} failed validation: {exc}")
            count += 1
        assert count > 0

    def test_ddos_example_with_null_source(self):
        """Spec section 5's correct DDoS shape: null src_ip, real dst."""
        alert = ThreatAlertV11.model_validate(
            base_alert(
                event_scope="destination_host",
                threat_class="ddos",
                severity="critical",
                src_ip=None,
                dst_ip="10.0.0.80",
                dst_port=80,
                evidence={"flows_per_sec": 8400.0, "unique_sources": 5200},
                detector="ddos_detector",
                mitre_techniques=["T1498"],
            )
        )
        assert alert.src_ip is None
        assert alert.dst_ip == "10.0.0.80"


class TestValidation:
    def test_rejects_wrong_schema_version(self):
        with pytest.raises(ValidationError, match="unsupported schema_version"):
            ThreatAlertV11.model_validate(base_alert(schema_version="1.0"))

    def test_rejects_unknown_top_level_field(self):
        """Spec section 18: a new top-level field is a breaking change."""
        with pytest.raises(ValidationError):
            ThreatAlertV11.model_validate(base_alert(confidence=0.9))

    def test_rejects_missing_nullable_field(self):
        """Spec section 3 marks every field required - including nullable ones."""
        payload = base_alert()
        del payload["dst_ip"]
        with pytest.raises(ValidationError):
            ThreatAlertV11.model_validate(payload)

    def test_accepts_explicit_null(self):
        assert ThreatAlertV11.model_validate(base_alert(dst_ip=None)).dst_ip is None

    @pytest.mark.parametrize("score", [-0.01, 1.01, 2.0])
    def test_rejects_out_of_range_score(self, score):
        with pytest.raises(ValidationError):
            ThreatAlertV11.model_validate(base_alert(score=score))

    def test_rejects_naive_timestamp(self):
        with pytest.raises(ValidationError, match="missing a timezone"):
            ThreatAlertV11.model_validate(
                base_alert(detected_at="2026-08-28T23:44:15.300")
            )

    def test_normalises_offset_to_utc(self):
        alert = ThreatAlertV11.model_validate(
            base_alert(
                event_start="2026-08-29T05:14:03+05:30",
                event_end="2026-08-29T05:14:15+05:30",
                detected_at="2026-08-29T05:14:15.300+05:30",
            )
        )
        assert alert.event_start.isoformat() == "2026-08-28T23:44:03+00:00"

    def test_rejects_empty_evidence(self):
        with pytest.raises(ValidationError, match="at least one supporting feature"):
            ThreatAlertV11.model_validate(base_alert(evidence={}))

    def test_rejects_reversed_event_window(self):
        with pytest.raises(ValidationError, match="precedes event_start"):
            ThreatAlertV11.model_validate(
                base_alert(
                    event_start="2026-08-28T23:44:15Z",
                    event_end="2026-08-28T23:44:03Z",
                )
            )

    def test_rejects_detection_before_event(self):
        with pytest.raises(ValidationError, match="cannot happen before"):
            ThreatAlertV11.model_validate(
                base_alert(detected_at="2026-08-28T23:00:00Z")
            )

    def test_rejects_scope_without_its_entity(self):
        """A source_host alert with no src_ip names no host."""
        with pytest.raises(ValidationError, match="requires src_ip"):
            ThreatAlertV11.model_validate(
                base_alert(event_scope="source_host", src_ip=None)
            )

    def test_host_pair_requires_both_ends(self):
        with pytest.raises(ValidationError, match="requires dst_ip"):
            ThreatAlertV11.model_validate(
                base_alert(
                    event_scope="host_pair", src_ip="10.0.0.5", dst_ip=None
                )
            )

    def test_network_scope_needs_no_identifier(self):
        alert = ThreatAlertV11.model_validate(
            base_alert(event_scope="network", src_ip=None, dst_ip=None)
        )
        assert alert.event_scope is EventScope.NETWORK

    def test_rejects_invalid_port(self):
        with pytest.raises(ValidationError):
            ThreatAlertV11.model_validate(base_alert(dst_port=70000))

    def test_normalises_protocol_case(self):
        assert ThreatAlertV11.model_validate(base_alert(protocol="TCP")).protocol == "tcp"

    def test_evidence_rejects_nested_objects(self):
        """The frontend renders evidence as a flat key/value list (spec 6)."""
        with pytest.raises(ValidationError):
            ThreatAlertV11.model_validate(
                base_alert(evidence={"nested": {"a": 1}})
            )

    def test_evidence_accepts_scalar_lists(self):
        alert = ThreatAlertV11.model_validate(
            base_alert(evidence={"timestamps": [1.0, 2.0, 3.0]})
        )
        assert alert.evidence["timestamps"] == [1.0, 2.0, 3.0]


class TestDerivedValues:
    def test_detector_latency(self):
        alert = ThreatAlertV11.model_validate(base_alert())
        # event_end 23:44:15.000 -> detected_at 23:44:15.300
        assert alert.detector_latency_ms == pytest.approx(300.0)

    def test_duration(self):
        assert ThreatAlertV11.model_validate(base_alert()).duration_sec == 12.0


def test_roundtrip_is_stable():
    """Our own JSON output must re-validate. Guards the ISO-8601 Z formatting."""
    alert = ThreatAlertV11.model_validate(base_alert())
    again = ThreatAlertV11.model_validate(json.loads(alert.model_dump_json()))
    assert again == alert
