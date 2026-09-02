#!/usr/bin/env python3
"""
pcap_dataset/ingest.py — deterministic PCAP → features workflow.

Usage (from repo root):
  .venv/bin/python pcap_dataset/ingest.py --pcap pcap_dataset/raw/<file>.pcap --label ddos
  .venv/bin/python pcap_dataset/ingest.py --batch pcap_dataset/raw --label dga_domain

Directory layout expected (at repo root):
  pcap_dataset/
    raw/                # raw .pcap files (ignored)
    output/<replay_id>/ # features.jsonl + meta.json (ignored)
    metadata.json       # central registry (tracked)
    ingest.py           # this script (tracked)

Versioned vs ignored contract is in pcap_dataset/README.md and root .gitignore.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET_ROOT = REPO_ROOT / "pcap_dataset"
INGESTION_ROOT = REPO_ROOT / "injestion_core"

# Deterministic namespace for replay_id = uuid5(DATASET_NS, f"{sha256}:{label}")
# Derived once at import so it is stable across machines/commits.
DATASET_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "sih2026:pcap_dataset:v1")

ALLOWED_LABELS = {
    "benign",
    "port_scan",
    "ddos",
    "dns_tunnelling",
    "encrypted_malware",
    "data_exfiltration",
    "c2_beaconing",
    "dga_domain",
}

# ---------------------------------------------------------------------------
# Helpers: metadata.json
# ---------------------------------------------------------------------------

def _load_metadata(dataset_root: Path) -> dict:
    meta_path = dataset_root / "metadata.json"
    if not meta_path.exists():
        return {"replays": {}}
    with open(meta_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if "replays" not in data:
        data["replays"] = {}
    return data


def _save_metadata_atomic(dataset_root: Path, data: dict) -> None:
    meta_path = dataset_root / "metadata.json"
    tmp = meta_path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, meta_path)


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def replay_id_for(sha256: str, label: str) -> str:
    """Deterministic replay_id from sha256 + label."""
    return str(uuid.uuid5(DATASET_NS, f"{sha256}:{label}"))


# ---------------------------------------------------------------------------
# Core: single PCAP ingestion
# ---------------------------------------------------------------------------

def ingest_one(
    pcap_path: Path,
    label: str,
    dataset_root: Path,
    window_secs: float = 60.0,
    force: bool = False,
) -> dict:
    if label not in ALLOWED_LABELS:
        sys.exit(f"ERROR: label must be one of {sorted(ALLOWED_LABELS)} (got {label!r})")

    if not pcap_path.is_file():
        sys.exit(f"ERROR: PCAP not found: {pcap_path}")

    # Ensure dataset layout exists
    raw_dir = dataset_root / "raw"
    output_root = dataset_root / "output"
    raw_dir.mkdir(parents=True, exist_ok=True)
    output_root.mkdir(parents=True, exist_ok=True)

    # Resolve pcap to a path relative to dataset_root/raw if inside, else keep absolute
    # For metadata we store relative to dataset_root when possible for portability
    try:
        rel_pcap = str(pcap_path.resolve().relative_to(dataset_root.resolve()))
    except ValueError:
        rel_pcap = str(pcap_path.resolve())

    # SHA256 via Rust (streaming, 64KB chunks) — same as pipeline
    try:
        sys.path.insert(0, str(INGESTION_ROOT))
        import ingestion_core  # type: ignore

        if not hasattr(ingestion_core, "sha256_input_file"):
            raise ImportError("ingestion_core wheel is stale — run: bash -c 'source .venv/bin/activate && maturin develop --manifest-path injestion_core/Cargo.toml'")
        sha256 = ingestion_core.sha256_input_file(str(pcap_path))
    except Exception as exc:
        sys.exit(f"ERROR: failed to hash PCAP {pcap_path}: {exc}")
    finally:
        # keep sys.path clean
        if str(INGESTION_ROOT) in sys.path:
            sys.path.remove(str(INGESTION_ROOT))

    replay_id = replay_id_for(sha256, label)
    replay_dir = output_root / replay_id
    features_path = replay_dir / "features.jsonl"
    meta_path = replay_dir / "meta.json"

    # Load central registry
    meta = _load_metadata(dataset_root)

    # Idempotency: same pcap+label → same replay_id
    if replay_id in meta["replays"] and not force:
        existing = meta["replays"][replay_id]
        # If output already exists and matches sha, skip re-processing
        if features_path.exists() and meta_path.exists():
            print(f"[=] Replay {replay_id} already exists for {pcap_path.name} label={label} — idempotent, skipping. Use --force to re-run.")
            return existing
        # If registry has it but output missing (e.g., after git pull without binaries), re-run

    replay_dir.mkdir(parents=True, exist_ok=True)
    created_at = _utc_now_iso()

    # Run ingestion pipeline (legacy features) via direct import to avoid extra subprocess
    # We create a temp Zeek workspace so pcap_dataset/output stays clean (only features+meta)
    tmp_zeek = tempfile.mkdtemp(prefix="pcap_dataset_zeek_", dir=str(dataset_root))
    try:
        # Import pipeline lazily so PYTHONPATH is correct
        sys.path.insert(0, str(INGESTION_ROOT))
        import pipeline  # type: ignore

        # pipeline.run_pipeline(pcap, out_dir, output_path, window, use_ja4, skip_zeek, canonical...)
        # For dataset we use normal mode (skip_zeek=False, no canonical)
        # out_dir is the temp Zeek workspace; output_path is our features path
        pipeline.run_pipeline(
            str(pcap_path),
            tmp_zeek,
            str(features_path),
            window_secs=window_secs,
            use_ja4=False,
            skip_zeek=False,
        )
    except SystemExit as exc:
        # pipeline calls sys.exit on failure — clean up partial output then re-raise
        # Remove partial features/meta if created
        for p in (features_path, meta_path):
            if p.exists():
                p.unlink()
        # Remove empty replay dir if we created it and it is now empty
        try:
            replay_dir.rmdir()
        except OSError:
            pass
        # Also roll back metadata entry if we had inserted it (we insert after success, so nothing to roll back yet)
        raise
    except Exception as exc:
        for p in (features_path, meta_path):
            if p.exists():
                p.unlink()
        try:
            replay_dir.rmdir()
        except OSError:
            pass
        sys.exit(f"ERROR: ingestion pipeline failed for {pcap_path.name}: {exc}")
    finally:
        if str(INGESTION_ROOT) in sys.path:
            sys.path.remove(str(INGESTION_ROOT))
        shutil.rmtree(tmp_zeek, ignore_errors=True)

    # Write per-replay meta.json (binding)
    per_meta = {
        "replay_id": replay_id,
        "pcap_source": rel_pcap,
        "sha256": sha256,
        "label": label,
        "created_at": created_at,
        "pipeline": {
            "window_secs": window_secs,
            "sensor_id": "sensor/pcap-dataset",
            "zeek_image": "zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3",
        },
        "artifacts": {
            "features": "features.jsonl",
            "meta": "meta.json",
        },
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(per_meta, f, indent=2, sort_keys=True)
        f.write("\n")

    # Update central metadata.json atomically
    meta = _load_metadata(dataset_root)  # re-load in case of concurrent writers
    meta["replays"][replay_id] = {
        "replay_id": replay_id,
        "pcap_source": rel_pcap,
        "sha256": sha256,
        "label": label,
        "created_at": created_at,
        "features_path": str(features_path.relative_to(dataset_root)),
    }
    _save_metadata_atomic(dataset_root, meta)

    print(f"[+] Replay {replay_id} label={label} sha256={sha256[:8]}... -> {features_path}")
    return meta["replays"][replay_id]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Dataset manager: PCAP → features (deterministic replay_id)")
    ap.add_argument("--pcap", type=str, help="Path to a single .pcap file")
    ap.add_argument("--label", type=str, choices=sorted(ALLOWED_LABELS), help="Threat class label (one of the 7 detection classes)")
    ap.add_argument("--batch", type=str, help="Directory of .pcap files to ingest with the same --label")
    ap.add_argument("--dataset-root", type=str, default=str(DEFAULT_DATASET_ROOT), help="Dataset root (default: pcap_dataset/)")
    ap.add_argument("--window", type=float, default=60.0, help="Sliding window seconds for pipeline (default 60)")
    ap.add_argument("--force", action="store_true", help="Re-run even if replay_id already exists")
    args = ap.parse_args()

    dataset_root = Path(args.dataset_root).resolve()
    if not dataset_root.exists():
        dataset_root.mkdir(parents=True, exist_ok=True)
        (dataset_root / "raw").mkdir(exist_ok=True)
        (dataset_root / "output").mkdir(exist_ok=True)
        if not (dataset_root / "metadata.json").exists():
            with open(dataset_root / "metadata.json", "w", encoding="utf-8") as f:
                json.dump({"replays": {}}, f, indent=2)
                f.write("\n")

    if args.batch and args.pcap:
        ap.error("--batch and --pcap are mutually exclusive")

    if args.batch:
        if not args.label:
            ap.error("--batch requires --label")
        batch_dir = Path(args.batch)
        if not batch_dir.is_dir():
            sys.exit(f"ERROR: --batch directory not found: {batch_dir}")
        pcaps = sorted(batch_dir.glob("*.pcap")) + sorted(batch_dir.glob("*.pcapng"))
        if not pcaps:
            sys.exit(f"ERROR: no .pcap files in {batch_dir}")
        for p in pcaps:
            ingest_one(p, args.label, dataset_root, window_secs=args.window, force=args.force)
        print(f"[+] Batch done: {len(pcaps)} files → {dataset_root / 'output'}")
        return

    if args.pcap:
        if not args.label:
            ap.error("--pcap requires --label")
        ingest_one(Path(args.pcap), args.label, dataset_root, window_secs=args.window, force=args.force)
        return

    ap.error("provide --pcap or --batch")


if __name__ == "__main__":
    main()
