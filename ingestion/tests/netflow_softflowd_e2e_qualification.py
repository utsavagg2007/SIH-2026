"""Opt-in pinned producer qualification, not a collector or fixture generator.

Use an independently built irino/softflowd v1.1.1 at the pinned commit below.
Only synthetic capture bytes are replayed. Frozen negative evidence is untouched.
All generated artifacts live in an explicitly supplied new evidence directory.
"""

import argparse
import hashlib
import json
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "detection"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from detection_core.netflow_run import parser, run_netflow
from netflow_v9_fixture_oracle import decode

COMMIT = "8f83c2c4a784a72bf6eb2604e73d4029b21b7925"
ARCHIVE_SHA256 = "111c4b2c841c7143552d77fc7bbe5ab7d7f4604bc1d7acf522afb0ce8e00fccb"


def adjusted_synthetic_capture():
    """Keep every packet byte; anchor replay capture times shortly before boot.

    softflowd's offline relative-uptime export and an old synthetic capture
    otherwise produce the frozen F7 negative time-ordering evidence. This
    independent positive input has documented current capture timestamps,
    not rewritten exported NetFlow fields or relaxed normalizer semantics.
    """
    source = ROOT / "ingestion/tests/fixtures/pcap/m1d_synthetic.pcap"
    data = bytearray(source.read_bytes())
    assert data[:4] == b"\xd4\xc3\xb2\xa1", "expected classic little-endian microsecond PCAP"
    offsets = []
    index = 24
    while index < len(data):
        sec, usec, caplen, _ = struct.unpack_from("<IIII", data, index)
        offsets.append((index, sec * 1_000_000 + usec))
        index += 16 + caplen
    assert index == len(data) and offsets
    latest = max(t for _, t in offsets)
    anchor = int((time.time() - 2) * 1_000_000)
    for offset, original in offsets:
        seconds, microseconds = divmod(anchor + original - latest, 1_000_000)
        struct.pack_into("<II", data, offset, seconds, microseconds)
    return source, bytes(data), anchor


def qualify(args):
    executable = Path(args.softflowd).resolve(strict=True)
    source = Path(args.producer_source).resolve(strict=True)
    directory = Path(args.evidence_dir).absolute()
    directory.mkdir()  # explicit no-overwrite evidence root
    original, pcap_bytes, anchor = adjusted_synthetic_capture()
    pcap = directory / "synthetic-current-time.pcap"
    pcap.write_bytes(pcap_bytes)
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(0.2)
    command = [str(executable), "-d", "-r", str(pcap), "-v", "9", "-P", "udp",
               "-n", f"127.0.0.1:{receiver.getsockname()[1]}",
               "-p", str(directory / "producer.pid"), "-c", str(directory / "producer.ctl")]
    producer = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    captures = []
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            try:
                blob, peer = receiver.recvfrom(65_536)
                assert peer[0] == "127.0.0.1"
                captures.append(blob)
                assert len(captures) <= 64, "capture budget exceeded"
            except socket.timeout:
                if producer.poll() is not None:
                    break
        assert producer.wait(timeout=2) == 0 and captures, "producer failed or exported no input"
    finally:
        receiver.close()
        if producer.poll() is None:
            producer.kill()
            producer.wait(timeout=2)
    observed = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    runs = []
    for ordinal, blob in enumerate(captures):
        decoded = decode(blob)
        assert "error" not in decoded and not decoded["reset"]
        raw = directory / f"softflowd_{ordinal:03}.bin"
        raw.write_bytes(blob)
        argv = ["--source", "netflow-v9", "--input", str(raw), "--output-dir", str(directory / f"run-{ordinal}"),
                "--sensor-id", "softflowd-e2e-sensor", "--exporter-id", "softflowd-loopback",
                "--session-id", "softflowd-e2e-epoch-1", "--observed-at", observed,
                "--rust-binary", args.rust_binary]
        report = run_netflow(parser().parse_args(argv))
        runs.append(report)
        # Replay the same actual datagram (not a copied Python dictionary).
        replay = parser().parse_args(argv)
        replay.output_dir = str(directory / f"replay-{ordinal}")
        second = run_netflow(replay)
        assert report == second, "real-export replay is not deterministic"
    result = {
        "producer": "irino/softflowd v1.1.1", "producer_commit": COMMIT,
        "source_archive_sha256": ARCHIVE_SHA256,
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "license_sha256": hashlib.sha256((source / "LICENSE").read_bytes()).hexdigest(),
        "source_pcap_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
        "temporary_adjusted_pcap_sha256": hashlib.sha256(pcap_bytes).hexdigest(),
        "temporary_capture_anchor_microseconds": anchor,
        "time_adjustment": "PCAP timestamps only; packet bytes unchanged; actual exported datagrams unmodified",
        "frozen_negative_evidence_modified": False, "sensitive_data": False,
        "datagrams": len(captures), "runs": runs, "replay_identical": True,
    }
    assert sum(r["detection"]["detector_invocations"].get("ddos", 0) for r in runs) > 0
    assert sum(r["ingestion"]["records_emitted"] for r in runs) > 0
    with (directory / "qualification.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, allow_nan=False, sort_keys=True)
        stream.write("\n")
    print(json.dumps(result, allow_nan=False, sort_keys=True))


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--softflowd", required=True)
    cli.add_argument("--producer-source", required=True)
    cli.add_argument("--rust-binary", required=True)
    cli.add_argument("--evidence-dir", required=True)
    qualify(cli.parse_args())
