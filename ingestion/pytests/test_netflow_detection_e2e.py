"""Real Rust executable/file boundary + actual production Python Detection.

Build first: cargo build --locked --manifest-path ingestion/Cargo.toml --bin netflow_export
NETFLOW_EXPORT_BINARY can identify a separately built Linux executable.
"""

import json
import os
import subprocess
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "detection"))

from detection_core import netflow_run
from detection_core.detectors import DDoSDetector

FIXTURES = ROOT / "ingestion/tests/fixtures/export"
BINARY = Path(os.environ.get("NETFLOW_EXPORT_BINARY", str(ROOT / "ingestion/target/debug" /
              ("netflow_export.exe" if os.name == "nt" else "netflow_export"))))


def arguments(tmp_path, version, fixture=None):
    v5 = version == "netflow-v5"
    fixture = fixture or ("netflow_v5/repeated_5tuple_distinct_rows.bin" if v5 else
                          "netflow_v9_canonical/wire/tcp_min.hex")
    args = ["--source", version, "--input", str(FIXTURES / fixture), "--output-dir", str(tmp_path / "result"),
            "--sensor-id", "sensor-netflow-golden" if v5 else "sensor-v9-a",
            "--exporter-id", "exporter-golden" if v5 else "exporter-a",
            "--observed-at", "2026-09-18T00:00:00Z" if v5 else "2026-10-03T00:00:00Z",
            "--rust-binary", str(BINARY)]
    if not v5:
        args.extend(["--session-id", "collector-a.udp.epoch-1"])
    if fixture.endswith(".hex"):
        args.extend(["--wire-format", "hex"])
    return netflow_run.parser().parse_args(args)


@pytest.mark.parametrize("version,count,golden", [
    ("netflow-v5", 3, "netflow_v5/canonical/repeated_5tuple_distinct_rows.canonical.jsonl"),
    ("netflow-v9", 1, "netflow_v9_canonical/golden/tcp_min.jsonl"),
])
def test_actual_input_to_production_detector_and_trace(tmp_path, version, count, golden):
    assert BINARY.is_file(), "build the real Rust integration executable first"
    args = arguments(tmp_path, version)
    report = netflow_run.run_netflow(args)
    output = Path(args.output_dir)
    assert report["ingestion"]["records_emitted"] == count
    assert report["detection"]["flows"] == count
    assert report["detection"]["detector_invocations"] == {"ddos": count}
    assert report["detection"]["alerts"] == 0
    assert report["detection"]["detector_errors"] == 0
    assert (output / "run_complete.json").is_file()
    assert (output / "canonical_observations.jsonl").read_bytes() == (FIXTURES / golden).read_bytes()
    records = [json.loads(line) for line in (output / "canonical_observations.jsonl").read_text().splitlines()]
    events = [json.loads(line) for line in (output / "detection_events.jsonl").read_text().splitlines()]
    for raw, trace in zip(records, events, strict=True):
        event = trace["event"]
        assert event["flow_id"] == raw["record_id"]
        assert event["source"] == raw["telemetry_source"]
        assert event["canonical"]["sensor_id"] == raw["sensor_id"]
        assert event["canonical"]["source_record_id"] == raw["source_record_id"]
        assert event["orig_bytes"] is None and event["resp_pkts"] is None and event["resp_bytes"] is None
        assert event["canonical"]["direction_mode"] == "unidirectional"
        assert event["canonical"]["quality"] == raw["quality"]
        assert trace["consumers"]["ddos"] == "invoked"
    assert len({e["event"]["flow_id"] for e in events}) == count


@pytest.mark.parametrize("version", ["netflow-v5", "netflow-v9"])
def test_full_replay_is_byte_identical_for_benign_production_results(tmp_path, version):
    first = arguments(tmp_path, version)
    second = arguments(tmp_path, version)
    second.output_dir = str(tmp_path / "second")
    netflow_run.run_netflow(first)
    netflow_run.run_netflow(second)
    for path in Path(first.output_dir).iterdir():
        assert path.read_bytes() == (Path(second.output_dir) / path.name).read_bytes(), path.name


@pytest.mark.parametrize("fixture", ["netflow_v5/minimal_valid_one_record.bin",
                                      "netflow_v9_canonical/wire/missing_src.hex"])
def test_canonical_rejection_is_explicit_not_fatal_input_success(tmp_path, fixture):
    args = arguments(tmp_path, "netflow-v5" if "v5" in fixture else "netflow-v9", fixture)
    report = netflow_run.run_netflow(args)
    assert report["detection"]["flows"] == 0
    assert report["ingestion"]["records_rejected"] == 1
    assert report["completion"]["ingestion_review_required"] is True
    assert report["detection"]["detector_invocations"] == {}


def test_reset_and_inconclusive_remain_actionable(tmp_path):
    args = arguments(tmp_path, "netflow-v9", "netflow_v9/malformed/untrusted_template_extent.bin")
    report = netflow_run.run_netflow(args)
    assert report["ingestion"]["count_validation"]["state"] == "Inconclusive"
    assert report["ingestion"]["reset_required"] is True
    assert report["ingestion"]["parse_completion"] == "StoppedForReset"
    assert report["ingestion"]["reset_action"] == "DiscardRegistryAndUseNewSessionEpoch"
    assert report["ingestion"]["registry_reused"] is False
    assert report["completion"]["reset_required"] is True
    assert report["completion"]["ingestion_review_required"] is True


def test_malformed_wire_publishes_no_success(tmp_path):
    bad = tmp_path / "malformed.bin"
    bad.write_bytes(b"not NetFlow")
    args = arguments(tmp_path, "netflow-v9")
    args.input = str(bad)
    with pytest.raises(RuntimeError, match="Rust ingestion failed"):
        netflow_run.run_netflow(args)
    assert not Path(args.output_dir).exists()


def test_invalid_canonical_fails_before_completed_result(tmp_path):
    (tmp_path / "canonical_observations.jsonl").write_text('{}\n')
    with pytest.raises(ValueError, match="invalid observation"):
        netflow_run.detect_canonical_run(tmp_path)
    assert not (tmp_path / "detection_status.json").exists()


def test_production_detection_error_is_not_success(tmp_path, monkeypatch):
    def failure(self, flow):
        raise RuntimeError("test operational failure")
    monkeypatch.setattr(DDoSDetector, "process", failure)
    args = arguments(tmp_path, "netflow-v9")
    with pytest.raises(RuntimeError, match="detection failed"):
        netflow_run.run_netflow(args)
    assert not Path(args.output_dir).exists()


def test_existing_output_and_write_failure_never_overwrite(tmp_path, monkeypatch):
    args = arguments(tmp_path, "netflow-v9")
    output = Path(args.output_dir)
    output.mkdir()
    sentinel = output / "owned-by-user"
    sentinel.write_bytes(b"preserve")
    with pytest.raises(FileExistsError):
        netflow_run.run_netflow(args)
    assert sentinel.read_bytes() == b"preserve"
    args.output_dir = str(tmp_path / "failure-output")
    def failure(*_):
        raise OSError("injected write failure")
    monkeypatch.setattr(netflow_run, "_write", failure)
    with pytest.raises(OSError):
        netflow_run.run_netflow(args)
    assert not Path(args.output_dir).exists()


def test_real_cli_exit_and_artifacts(tmp_path):
    args = arguments(tmp_path, "netflow-v9")
    command = [sys.executable, "-m", "detection_core.netflow_run"]
    for key, value in vars(args).items():
        if value is not None:
            command.extend(["--" + key.replace("_", "-"), str(value)])
    env = {**os.environ, "PYTHONPATH": str(ROOT / "detection"), "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["detection"]["detector_invocations"] == {"ddos": 1}


def test_wire_to_real_default_ddos_threat_alert(tmp_path):
    # Explicit synthetic flood, not claimed exporter/production attack evidence.
    # 200 actual wire records with distinct sources, each with 20 packets.
    fields = [(8, 4), (12, 4), (4, 1), (22, 4), (21, 4), (2, 4)]
    template = struct.pack("!HH", 256, len(fields)) + b"".join(struct.pack("!HH", *x) for x in fields)
    rows = b"".join(struct.pack("!IIBIII", 0xc0000200 + i, 0xc6336402, 17, 8000, 9000, 20)
                    for i in range(1, 201))
    def flowset(identity, content):
        padded = content + b"\0" * ((-len(content)) % 4)
        return struct.pack("!HH", identity, len(padded) + 4) + padded
    wire = struct.pack("!HHIIII", 9, 201, 10000, 1700000000, 123, 42)
    wire += flowset(0, template) + flowset(256, rows)
    input_path = tmp_path / "synthetic-flood.bin"
    input_path.write_bytes(wire)
    args = arguments(tmp_path, "netflow-v9")
    args.input = str(input_path)
    args.wire_format = "raw"
    report = netflow_run.run_netflow(args)
    assert report["detection"]["flows"] == 200
    assert report["detection"]["detector_invocations"] == {"ddos": 200}
    assert report["detection"]["alerts"] == 4  # low -> medium -> high -> critical
    output = Path(args.output_dir)
    alerts = [json.loads(line) for line in (output / "alerts.jsonl").read_text().splitlines()]
    canonical_ids = {json.loads(line)["record_id"] for line in
                     (output / "canonical_observations.jsonl").read_text().splitlines()}
    for alert in alerts:
        assert alert["schema_version"] == "1.1" and alert["detector"] == "ddos"
        assert alert["evidence"]["canonical_trigger"]["record_id"] in canonical_ids
        assert alert["evidence"]["canonical_trigger"]["telemetry_source"] == "netflow_v9"
        assert alert["evidence"]["byte_count"] is None
        assert alert["evidence"]["packets_per_second"] is None  # equal event starts
    args.output_dir = str(tmp_path / "synthetic-flood-replay")
    second = netflow_run.run_netflow(args)
    replay_alerts = [json.loads(line) for line in
                     (Path(args.output_dir) / "alerts.jsonl").read_text().splitlines()]
    assert second["detection"] == report["detection"]
    def deterministic_alert(alert):
        return {k: v for k, v in alert.items() if k not in ("alert_id", "detected_at")}
    assert [deterministic_alert(a) for a in alerts] == [deterministic_alert(a) for a in replay_alerts]


def test_measurement_unavailable_gates_real_pipeline_explicitly(tmp_path):
    args = arguments(tmp_path, "netflow-v9", "netflow_v9_canonical/wire/byte_only.hex")
    args.byte_basis = "ip"  # independently specified qualified fixture profile
    report = netflow_run.run_netflow(args)
    assert report["detection"]["flows"] == 1
    assert report["detection"]["detector_invocations"] == {}
    assert report["detection"]["detector_skips"]["ddos"] == {"missing_required_features:src_to_dst.packets": 1}
    assert report["completion"]["ingestion_review_required"] is True


def test_publication_failure_has_no_completion_marker(tmp_path, monkeypatch):
    args = arguments(tmp_path, "netflow-v9")
    def failure(*_):
        raise OSError("injected atomic link failure")
    monkeypatch.setattr(netflow_run.os, "link", failure)
    with pytest.raises(OSError):
        netflow_run.run_netflow(args)
    output = Path(args.output_dir)
    assert output.is_dir()  # an explicitly failed, incomplete reservation
    assert not (output / "run_complete.json").exists()
