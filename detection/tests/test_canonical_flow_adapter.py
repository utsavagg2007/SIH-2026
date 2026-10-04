"""Canonical boundary invariants, using unchanged F3/F7 serialized fixtures."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from detection_core.adapters.canonical_flow import (
    CanonicalFlowAdapter, canonical_flow_to_flow_event,
)
from detection_core.schemas import FlowEvent

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "ingestion/tests/fixtures/export"


def record():
    return json.loads((FIXTURES / "netflow_v9_canonical/golden/tcp_min.jsonl").read_text())


@pytest.mark.parametrize("path", sorted((FIXTURES / "netflow_v9_canonical/golden").glob("*.jsonl")) +
                         sorted((FIXTURES / "netflow_v5/canonical").glob("*.jsonl")))
def test_all_frozen_flow_goldens_adapt(path):
    for line in path.read_text().splitlines():
        raw = json.loads(line)
        flow = canonical_flow_to_flow_event(raw)
        assert flow.flow_id == raw["record_id"]
        assert flow.source == raw["telemetry_source"]
        assert flow.orig_pkts == raw["data"]["counters"]["src_to_dst"].get("packets")
        assert flow.canonical["quality"] == raw["quality"]


def test_direction_byte_basis_identity_and_metadata():
    raw = record()
    raw["data"]["counters"]["src_to_dst"]["ip_bytes"] = 123456
    flow = canonical_flow_to_flow_event(raw)
    assert flow.orig_ip_bytes == 123456
    assert flow.orig_bytes is None
    assert flow.resp_bytes is None and flow.resp_pkts is None
    assert flow.total_pkts is None and flow.total_bytes is None
    assert flow.dns is None and flow.tls is None and flow.http is None
    assert flow.uid is None and flow.service is None
    assert flow.canonical["direction_mode"] == "unidirectional"
    assert flow.canonical["source_record_id"] == raw["source_record_id"]
    assert flow.canonical["provenance"] == raw["provenance"]
    raw["quality"]["fidelity"] = "exact"
    assert flow.canonical["quality"]["fidelity"] == "unknown"


@pytest.mark.parametrize("value", [0, 2**53 + 1, 2**64 - 1])
def test_integer_counters_never_round_through_float(value):
    raw = record()
    raw["data"]["counters"]["src_to_dst"]["packets"] = value
    flow = canonical_flow_to_flow_event(raw)
    assert type(flow.orig_pkts) is int and flow.orig_pkts == value


@pytest.mark.parametrize("change", [
    {"schema_version": "2.0"}, {"observation_type": "dns"},
    {"telemetry_source": "zeek"}, {"telemetry_source": "ipfix"}, {"telemetry_source": []},
    {"record_id": ""}, {"record_id": None}, {"sensor_id": ""},
    {"observed_at": "2026-02-30T00:00:00Z"}, {"observed_at": "2026-01-01T00:00:00+00:00"},
    {"quality": {}}, {"provenance": {}}, {"unknown_field": True},
    {"quality": {"fidelity": "exact", "truncated": False, "loss_detected": False, "sampling_rate": 1}},
    {"quality": {"fidelity": "unknown", "truncated": 0, "loss_detected": False}},
    {"quality": {"fidelity": "sampled", "truncated": False, "loss_detected": False, "sampling_probability": float("nan")}},
])
def test_bad_envelopes_fail(change):
    raw = record()
    raw.update(change)
    with pytest.raises(ValueError):
        canonical_flow_to_flow_event(raw)


@pytest.mark.parametrize("field", ["schema_version", "record_id", "sensor_id", "observed_at",
                                   "quality", "provenance", "data", "telemetry_source", "observation_type"])
def test_missing_envelope_fields_fail(field):
    raw = record()
    del raw[field]
    with pytest.raises(ValueError):
        canonical_flow_to_flow_event(raw)


@pytest.mark.parametrize("change", [
    {"src_ip": "999.0.0.1"}, {"dst_ip": "host.example"}, {"src_port": True},
    {"dst_port": 65536}, {"ip_protocol": "6"}, {"ip_protocol": False},
    {"ip_protocol": 256}, {"direction_mode": "bidirectional"},
    {"end_time": "1970-01-01T00:00:00Z"}, {"start_time": "not-a-time"},
    {"counters": {"src_to_dst": {}}},
    {"counters": {"src_to_dst": {"packets": -1}}},
    {"counters": {"src_to_dst": {"packets": 2**64}}},
    {"counters": {"src_to_dst": {"packets": "5"}}},
    {"counters": {"src_to_dst": {"packets": True}}},
    {"counters": {"src_to_dst": {"packets": 5.0}}},
    {"counters": {"src_to_dst": {"packets": float("inf")}}},
    {"counters": {"src_to_dst": {"packets": 5}, "dst_to_src": {"packets": 0}}},
    {"tcp_flags": ["syn", "syn"]}, {"extra_flow_field": 1},
])
def test_bad_flow_fields_fail(change):
    raw = record()
    raw["data"].update(change)
    with pytest.raises(ValueError):
        canonical_flow_to_flow_event(raw)


@pytest.mark.parametrize("field", ["start_time", "src_ip", "dst_ip", "ip_protocol", "direction_mode", "counters"])
def test_missing_flow_fields_fail(field):
    raw = record()
    del raw["data"][field]
    with pytest.raises(ValueError):
        canonical_flow_to_flow_event(raw)


def test_timestamp_duration_zero_and_absent_end():
    raw = record()
    raw["observed_at"] = "2026-10-04T12:00:00Z"
    raw["data"]["start_time"] = "2026-10-01T01:02:03.000000001Z"
    raw["data"]["end_time"] = "2026-10-01T01:02:03.000000003Z"
    flow = canonical_flow_to_flow_event(raw)
    assert flow.duration == 0.000000002
    assert flow.timestamp != 1791115200.0  # receipt is not event time
    raw["data"]["end_time"] = raw["data"]["start_time"]
    assert canonical_flow_to_flow_event(raw).duration == 0.0
    del raw["data"]["end_time"]
    assert canonical_flow_to_flow_event(raw).duration is None


def test_icmp_ipv6_no_port_and_unknown_protocol_no_guess():
    raw = record()
    raw["data"].update(src_ip="2001:db8::1", dst_ip="2001:db8::2", ip_protocol=58)
    raw["data"].pop("src_port", None)
    raw["data"].pop("dst_port", None)
    assert canonical_flow_to_flow_event(raw).proto == "icmp6"
    raw["data"]["src_port"] = 0
    with pytest.raises(ValueError):
        canonical_flow_to_flow_event(raw)
    del raw["data"]["src_port"]
    raw["data"]["ip_protocol"] = 132
    assert canonical_flow_to_flow_event(raw).proto == "ip_protocol_132"


def test_null_and_measured_reverse_values_are_distinct():
    raw = record()
    raw["data"]["counters"]["src_to_dst"]["packets"] = None
    assert canonical_flow_to_flow_event(raw).orig_pkts is None
    raw["data"]["direction_mode"] = "originator_responder"
    raw["data"]["counters"]["dst_to_src"] = {"packets": 0, "payload_bytes": 0}
    flow = canonical_flow_to_flow_event(raw)
    assert flow.resp_pkts == 0 and flow.resp_bytes == 0


def test_sampled_quality_is_metadata_not_a_counter_multiplier():
    raw = record()
    raw["quality"].update(fidelity="sampled", sampling_rate=100, sampling_probability=0.01)
    flow = canonical_flow_to_flow_event(raw)
    assert flow.orig_pkts == 5
    assert flow.canonical["quality"] == raw["quality"]
    assert flow.canonical["quality"]["fidelity"] == "sampled"


@pytest.mark.parametrize("body", [b'{"record_id":"a","record_id":"b"}\n', b'NaN\n',
                                   b'{}\n', b'\xef\xbb\xbf{}\n', b'\xff\n', b'\n', b'[]\n'])
def test_invalid_jsonl_fails_closed(tmp_path, body):
    path = tmp_path / "invalid.jsonl"
    path.write_bytes(body)
    with pytest.raises(ValueError, match="line 1"):
        list(CanonicalFlowAdapter(path))


def test_line_and_record_caps(tmp_path):
    path = tmp_path / "input.jsonl"
    path.write_text(json.dumps(record()) + "\n" + json.dumps(record()) + "\n")
    with pytest.raises(ValueError, match="record limit"):
        list(CanonicalFlowAdapter(path, max_records=1))
    with pytest.raises(ValueError, match="line limit"):
        list(CanonicalFlowAdapter(path, max_line_bytes=5))
    path.write_bytes(b"")
    assert list(CanonicalFlowAdapter(path)) == []


def test_legacy_contract_did_not_become_nullable():
    raw = dict(timestamp=1, src_ip="1.2.3.4", dst_ip="5.6.7.8", proto="tcp",
               duration=0, orig_pkts=1, resp_pkts=0, orig_bytes=None, resp_bytes=0)
    with pytest.raises(ValidationError):
        FlowEvent(**raw)
