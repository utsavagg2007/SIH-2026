"""Offline NetFlow -> Rust canonical JSONL -> production Detection command.

The run is published only after ingestion and detection succeed. Every artifact
is no-overwrite; run_complete.json is the last publication / commit marker.
Canonical data is never rewritten as features.jsonl. No PyO3 or model loader is
needed by this additional path; the existing Zeek command remains unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .adapters.canonical_flow import CanonicalFlowAdapter
from .compatibility import canonical_skip_reason
from .config import load_detector_settings
from .engine import Detector
from .pipeline import JsonlAlertSink, build_default_detectors, run_detection
from .schemas.canonical_flow import CanonicalFlowEvent

REPOSITORY = Path(__file__).resolve().parents[2]


def _json(stream, value: object) -> None:
    json.dump(value, stream, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
    stream.write("\n")


def _write(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        _json(stream, value)
        stream.flush()
        os.fsync(stream.fileno())


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65_536):
            digest.update(chunk)
    return digest.hexdigest()


def detect_canonical_run(directory: Path, *, detectors: list[Detector] | None = None) -> dict:
    """Execute the same production factory/engine/sink used by the legacy CLI.

    Stream the actual adapted inputs and per-consumer decisions as an audit
    trace. This bounds memory even on a benign run with no ThreatAlerts.
    """
    consumers = build_default_detectors() if detectors is None else detectors
    adapter = CanonicalFlowAdapter(directory / "canonical_observations.jsonl")
    with (directory / "detection_events.jsonl").open("x", encoding="utf-8", newline="\n") as trace:
        def source() -> Iterable[CanonicalFlowEvent]:
            for flow in adapter:
                _json(trace, {
                    "event": flow.model_dump(mode="json"),
                    "consumers": {d.name: canonical_skip_reason(d, flow) or "invoked" for d in consumers},
                })
                yield flow

        with (directory / "alerts.jsonl").open("x", encoding="utf-8", newline="\n") as alerts:
            stats = run_detection(source(), JsonlAlertSink(alerts), consumers)
            alerts.flush()
            os.fsync(alerts.fileno())
        trace.flush()
        os.fsync(trace.fileno())
    if stats.detector_errors or stats.delivery_failures or stats.alerts_dropped:
        raise RuntimeError("detection failed; no successful run will be published")
    result = {
        "status_version": "1.0", "result_type": "DetectionRunStats", **asdict(stats),
        "registered_detectors": [d.name for d in consumers],
        "dga_status": ("registered_but_gated:NetFlow_has_no_DNS_queries"
                       if any(d.name == "dga_domain" for d in consumers)
                       else "not_loaded:NetFlow_has_no_DNS_queries"),
        "compatibility_policy": "netflow-canonical-v1-audited-consumers",
        "event_time_basis": "canonical_start_time",
        "counter_scaling": "none",
    }
    _write(directory / "detection_status.json", result)
    return result


def run_netflow(args: argparse.Namespace) -> dict:
    output = Path(args.output_dir).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("output directory already exists; use a fresh run path")
    if not output.parent.is_dir():
        raise ValueError("output parent must already exist")
    binary = Path(args.rust_binary).resolve(strict=True)
    if not binary.is_file():
        raise ValueError("Rust exporter must be an explicitly trusted local executable")
    with tempfile.TemporaryDirectory(prefix=".netflow-e2e-", dir=output.parent) as temporary:
        staging = Path(temporary)
        run = staging / "run"
        command = [str(binary), "--source", args.source, "--input", str(Path(args.input).absolute()),
                   "--output-dir", str(run), "--sensor-id", args.sensor_id,
                   "--exporter-id", args.exporter_id, "--observed-at", args.observed_at,
                   "--wire-format", args.wire_format, "--byte-basis", args.byte_basis]
        if args.source == "netflow-v9":
            if not args.session_id:
                raise ValueError("NetFlow v9 requires an explicit session epoch identity")
            command.extend(["--session-id", args.session_id])
        with (staging / "ingestion.stderr").open("wb") as errors:
            completed = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=errors,
                                       timeout=120, check=False)
        if completed.returncode:
            # Rust errors are bounded too, but do not expose input-dependent
            # diagnostics or paths on arbitrary malformed input to logs.
            raise RuntimeError(f"Rust ingestion failed (exit {completed.returncode}); no run published")
        if not (run / "ingestion_complete.json").is_file():
            raise RuntimeError("Rust ingestion did not publish its completion marker")
        with (run / "ingestion_status.json").open("rb") as stream:
            status_bytes = stream.read(8_388_609)
        if len(status_bytes) > 8_388_608:
            raise ValueError("ingestion status resource limit")
        ingestion = json.loads(status_bytes)
        settings = load_detector_settings(args.detector_config) if args.detector_config else None
        result = detect_canonical_run(run, detectors=build_default_detectors(settings=settings))
        if result["flows"] != ingestion["records_emitted"]:
            raise RuntimeError("ingestion/detection count mismatch; no run published")
        review_required = bool(ingestion.get("warnings")) or not result["detector_invocations"]
        completion = {
            "status_version": "1.0", "complete": True,
            "ingestion_review_required": review_required,
            "reset_required": ingestion.get("reset_required", False),
            "canonical_observations": result["flows"], "alerts": result["alerts"],
            "artifact_sha256": {p.name: _digest(p) for p in sorted(run.iterdir()) if p.is_file()},
        }
        _write(run / "run_complete.json", completion)
        # Exclusive final claim. Per-file hard links publish whole files with
        # no overwrite, including on POSIX. Never rename over a racing target.
        output.mkdir()
        for path in sorted(run.iterdir(), key=lambda p: (p.name == "run_complete.json", p.name)):
            os.link(path, output / path.name)
        if os.name != "nt":
            fd = os.open(output, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return {"ingestion": ingestion, "detection": result, "completion": completion}


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--source", required=True, choices=("netflow-v5", "netflow-v9"))
    command.add_argument("--input", required=True)
    command.add_argument("--output-dir", required=True)
    command.add_argument("--sensor-id", required=True)
    command.add_argument("--exporter-id", required=True)
    command.add_argument("--observed-at", required=True, help="Explicit receipt time; never detection event time")
    command.add_argument("--session-id", help="v9 logical exporter/transport epoch; no live reuse")
    command.add_argument("--wire-format", choices=("raw", "hex"), default="raw")
    command.add_argument("--byte-basis", choices=("unknown", "ip"), default="unknown",
                         help="v9 only: ip requires independently verified exporter configuration")
    command.add_argument("--detector-config", help="Existing Detection TOML threshold configuration")
    command.add_argument("--rust-binary", default=str(REPOSITORY / "ingestion/target/debug" /
                                                     ("netflow_export.exe" if os.name == "nt" else "netflow_export")))
    return command


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = run_netflow(args)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print("NetFlow E2E failed; do not assume output completion/durability. "
              "Check run_complete.json and the failure before consuming any published files.")
        return 1
    print(json.dumps(result, ensure_ascii=False, allow_nan=False, sort_keys=True))
    # A valid partial prefix is usable but must not look like unqualified success.
    return 2 if result["completion"]["ingestion_review_required"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
