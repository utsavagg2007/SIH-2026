"""Audited consumer invocation, null-safe shared windows, and real DDoS alerts."""

import json
from pathlib import Path

import pytest

from detection_core.adapters.canonical_flow import canonical_flow_to_flow_event
from detection_core.aggregators import ActivityWindow, FlowObservation
from detection_core.compatibility import canonical_skip_reason
from detection_core.detectors import DDoSConfig, DDoSDetector, DGADetector
from detection_core.engine import DetectionEngine, Detector
from detection_core.pipeline import _RateWindow, build_default_detectors

ROOT = Path(__file__).resolve().parents[2]


def flow(packets=5):
    record = json.loads((ROOT / "ingestion/tests/fixtures/export/netflow_v9_canonical/golden/tcp_min.jsonl").read_text())
    record["data"]["counters"]["src_to_dst"]["packets"] = packets
    return canonical_flow_to_flow_event(record)


@pytest.mark.parametrize("detector", build_default_detectors(), ids=lambda d: d.name)
def test_each_production_consumer_has_explicit_policy(detector):
    engine = DetectionEngine([detector], raise_on_detector_error=True)
    assert engine.process(flow()) == []
    if detector.name == "ddos":
        assert engine.stats.detector_invocations == {"ddos": 1}
        assert engine.stats.detector_skips == {}
    else:
        assert engine.stats.detector_invocations == {}
        assert "missing_required_features" in next(iter(engine.stats.detector_skips[detector.name]))


def test_missing_packets_skip_ddos_instead_of_exception():
    engine = DetectionEngine([DDoSDetector()], raise_on_detector_error=True)
    assert engine.process(flow(None)) == []
    assert engine.stats.detector_skips == {"ddos": {"missing_required_features:src_to_dst.packets": 1}}
    assert engine.stats.detector_errors == 0


class UnreviewedConsumer(Detector):
    name = "ddos"  # impersonating a name is insufficient
    version = "test"

    def process(self, flow):
        raise AssertionError("must never receive canonical input")

    def reset(self):
        pass


def test_unknown_consumer_is_fail_closed():
    engine = DetectionEngine([UnreviewedConsumer()], raise_on_detector_error=True)
    assert engine.process(flow()) == []
    assert engine.stats.detector_skips == {"ddos": {"unsupported_canonical_consumer": 1}}


def test_dga_requirement_explicit_without_loading_a_model(tmp_path):
    # No trained artifact is needed to determine that NetFlow lacks DNS queries.
    detector = object.__new__(DGADetector)
    assert canonical_skip_reason(detector, flow()) == "missing_required_features:dns.query"
    from detection_core.netflow_run import detect_canonical_run

    class RegisteredDgaSentinel(UnreviewedConsumer):
        name = "dga_domain"

    # A negative gate/status check, never positive model-execution evidence.
    (tmp_path / "canonical_observations.jsonl").write_bytes(
        (ROOT / "ingestion/tests/fixtures/export/netflow_v9_canonical/golden/tcp_min.jsonl").read_bytes()
    )
    result = detect_canonical_run(tmp_path, detectors=[RegisteredDgaSentinel()])
    assert result["dga_status"] == "registered_but_gated:NetFlow_has_no_DNS_queries"
    assert result["detector_invocations"] == {}


def test_unknown_source_not_silently_supported():
    event = flow().model_copy(update={"source": "ipfix"})
    assert canonical_skip_reason(DDoSDetector(), event) == "unsupported_telemetry_source"


def test_null_window_totals_expire_and_restore_exact_measurements():
    window = ActivityWindow(10)
    window.observe(FlowObservation(timestamp=1, dst_ip="x", orig_packets=2**64-1,
                                   orig_bytes=None, resp_bytes=None))
    assert window.total_orig_packets() == 2**64 - 1
    assert window.total_orig_bytes() is None and window.total_resp_bytes() is None
    assert window.max_orig_bytes() is None
    assert window.established_fraction() is None
    assert window.endpoint_established_fraction() is None
    assert window.established_endpoint_count() is None
    window.observe(FlowObservation(timestamp=11, dst_ip="x", orig_packets=0, orig_bytes=0, resp_bytes=100))
    assert window.total_orig_packets() == 0 and window.total_orig_bytes() == 0
    assert window.total_resp_bytes() == 100 and window.max_orig_bytes() == 0
    assert window.established_fraction() == 1.0
    window.observe(FlowObservation(timestamp=12, dst_ip="x", orig_packets=None))
    assert window.total_orig_packets() is None
    window.clear()
    assert window.total_orig_packets() == 0 and window.total_orig_bytes() == 0


def test_real_ddos_alert_preserves_trigger_and_null_byte_evidence():
    # Exercise the actual production rule with explicit test thresholds, not
    # a substitute detector/model. The manual benign demonstrations use defaults.
    detector = DDoSDetector(DDoSConfig(min_unique_sources=2, min_flows=2, min_packets=10))
    engine = DetectionEngine([detector], raise_on_detector_error=True)
    first = flow()
    second = first.model_copy(update={"src_ip": "192.0.2.9", "timestamp": first.timestamp + 1,
                                     "flow_id": "canonical-trigger-2",
                                     "canonical": {**first.canonical, "record_id": "canonical-trigger-2"}})
    assert engine.process(first) == []
    alerts = engine.process(second)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.evidence["packet_count"] == 10
    assert alert.evidence["byte_count"] is None
    assert alert.evidence["canonical_trigger"]["record_id"] == second.flow_id
    assert alert.evidence["canonical_trigger"]["quality"]["fidelity"] == "unknown"
    assert alert.flow_id is None  # aggregate identity is not one source flow
    assert alert.to_wire()["schema_version"] == "1.1"


def test_huge_packet_counter_is_exact_until_existing_rule_score_boundary():
    detector = DDoSDetector(DDoSConfig(min_unique_sources=1))
    alerts = DetectionEngine([detector], raise_on_detector_error=True).process(flow(2**64 - 1))
    assert len(alerts) == 1
    assert alerts[0].evidence["packet_count"] == 2**64 - 1
    assert alerts[0].score == 1.0
    assert alerts[0].evidence["packets_per_second"] is None  # zero-span window


def test_legacy_numeric_telemetry_refuses_missing_canonical_values():
    with pytest.raises(ValueError, match="throughput telemetry"):
        _RateWindow().add(flow())
