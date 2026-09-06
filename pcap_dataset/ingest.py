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
import re
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
INGESTION_ROOT = REPO_ROOT / "ingestion"

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

# pcap_dataset defaults to detector-v2 so raw fields (query, ja3/s, server_name, S0)
# survive to Detection. The frozen legacy M1D projection remains available via
# --feature-profile legacy-m1d for byte-for-byte comparison.
DATASET_FEATURE_PROFILE = "detector-v2"
# Must stay identical to ingestion.pipeline FEATURE_PROFILES vocabulary.
FEATURE_PROFILES = ("legacy-m1d", "detector-v2")
JA4_RUNTIME_LOCK = INGESTION_ROOT / "runtime" / "ja4-runtime.lock"

# ---------------------------------------------------------------------------
# Helpers: metadata.json
# ---------------------------------------------------------------------------

def _load_metadata(dataset_root: Path) -> dict:
    meta_path = dataset_root / "metadata.json"
    if not meta_path.exists():
        return {"replays": {}}
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"ERROR: invalid dataset metadata {meta_path}: {exc}")
    if not isinstance(data, dict):
        sys.exit(f"ERROR: invalid dataset metadata {meta_path}: root must be an object")
    if "replays" not in data:
        data["replays"] = {}
    if not isinstance(data["replays"], dict):
        sys.exit(f"ERROR: invalid dataset metadata {meta_path}: replays must be an object")
    for replay_id, entry in data["replays"].items():
        if not isinstance(entry, dict):
            sys.exit(
                f"ERROR: invalid dataset metadata {meta_path}: replay {replay_id!r} must be an object"
            )
        sha256 = entry.get("sha256")
        label = entry.get("label")
        features_path = entry.get("features_path")
        if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
            sys.exit(
                f"ERROR: invalid dataset metadata {meta_path}: replay {replay_id!r} has invalid sha256"
            )
        if label not in ALLOWED_LABELS:
            sys.exit(
                f"ERROR: invalid dataset metadata {meta_path}: replay {replay_id!r} has invalid label"
            )
        if entry.get("replay_id") != replay_id or replay_id_for(sha256, label) != replay_id:
            sys.exit(
                f"ERROR: invalid dataset metadata {meta_path}: replay identity does not match sha256+label"
            )
        if not isinstance(features_path, str) or not features_path:
            sys.exit(
                f"ERROR: invalid dataset metadata {meta_path}: replay {replay_id!r} has invalid features_path"
            )
        relative = Path(features_path)
        if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("output",):
            sys.exit(
                f"ERROR: invalid dataset metadata {meta_path}: replay {replay_id!r} features_path must stay under output/"
            )
        # Configuration the replay was produced with. Entries written before
        # these fields existed came from the frozen legacy default without JA4.
        profile = entry.get("feature_profile", "legacy-m1d")
        if profile not in FEATURE_PROFILES:
            sys.exit(
                f"ERROR: invalid dataset metadata {meta_path}: replay {replay_id!r} has invalid feature_profile"
            )
        entry["feature_profile"] = profile
        ja4_flag = entry.get("use_ja4", False)
        if not isinstance(ja4_flag, bool):
            sys.exit(
                f"ERROR: invalid dataset metadata {meta_path}: replay {replay_id!r} has invalid use_ja4"
            )
        entry["use_ja4"] = ja4_flag
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

def _ja4_image_for_meta(use_ja4: bool) -> str:
    if not use_ja4:
        return "zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"
    # When JA4 is requested, record the actually qualified local image, not the base.
    # Fallback to the lock's digest if the lock is unreadable (should not happen on a built checkout).
    try:
        lock = JA4_RUNTIME_LOCK.read_text(encoding="utf-8")
        for line in lock.splitlines():
            if line.startswith("JA4_IMAGE_DIGEST="):
                return line.split("=", 1)[1].strip()
            if line.startswith("JA4_IMAGE_TAG=") and "sih-zeek-ja4" in line:
                # Tag is human-readable but digest is canonical; prefer digest.
                pass
        for line in lock.splitlines():
            if line.startswith("JA4_IMAGE_TAG="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return "sih-zeek-ja4:8.0.10-d03721fc (unresolved lock)"


def ingest_one(
    pcap_path: Path,
    label: str,
    dataset_root: Path,
    window_secs: float = 60.0,
    force: bool = False,
    feature_profile: str = DATASET_FEATURE_PROFILE,
    use_ja4: bool = False,
) -> dict:
    if label not in ALLOWED_LABELS:
        sys.exit(f"ERROR: label must be one of {sorted(ALLOWED_LABELS)} (got {label!r})")

    if feature_profile not in FEATURE_PROFILES:
        sys.exit(
            f"ERROR: unsupported feature profile {feature_profile!r}; "
            f"expected one of {', '.join(FEATURE_PROFILES)}."
        )

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
            raise ImportError("ingestion_core wheel is stale — run: bash -c 'source .venv/bin/activate && maturin develop --manifest-path ingestion/Cargo.toml'")
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

    # F4: warn when the same bytes are ingested under a new label (label noise)
    for existing_id, entry in meta["replays"].items():
        if entry.get("sha256") == sha256 and entry.get("label") != label and existing_id != replay_id:
            print(
                f"[warn] same PCAP bytes already registered as {entry.get('label')} "
                f"({existing_id[:8]}...); new label {label} will create a second replay "
                f"with identical features but contradictory training signal.",
                file=sys.stderr,
            )
            break

    # Idempotency: same pcap+label+configuration → same replay_id.
    # A stored replay produced under a different feature profile or JA4 runtime
    # must never be silently reused: its bytes would not honor this request.
    if replay_id in meta["replays"] and not force:
        existing = meta["replays"][replay_id]
        stored_profile = existing.get("feature_profile", "legacy-m1d")
        stored_ja4 = existing.get("use_ja4", False)
        if stored_profile != feature_profile or stored_ja4 != use_ja4:
            sys.exit(
                f"ERROR: replay {replay_id} already exists with "
                f"feature_profile={stored_profile} use_ja4={stored_ja4}, "
                f"but requested feature_profile={feature_profile} use_ja4={use_ja4}. "
                "Reusing it would silently mix runtimes; use --force to explicitly "
                "rebuild this replay with the requested configuration."
            )
        # If output already exists and matches sha, skip re-processing
        if features_path.exists() and meta_path.exists():
            print(f"[=] Replay {replay_id} already exists for {pcap_path.name} label={label} — idempotent, skipping. Use --force to re-run.")
            return existing
        # If registry has it but output missing (e.g., after git pull without binaries), re-run

    replay_dir.mkdir(parents=True, exist_ok=True)
    created_at = _utc_now_iso()

    # Run ingestion pipeline via direct import to avoid extra subprocess
    # We create a temp Zeek workspace so pcap_dataset/output stays clean (only features+meta)
    tmp_zeek = tempfile.mkdtemp(prefix="pcap_dataset_zeek_", dir=str(dataset_root))
    try:
        # Import pipeline lazily so PYTHONPATH is correct
        sys.path.insert(0, str(INGESTION_ROOT))
        import pipeline  # type: ignore

        # pipeline.run_pipeline(pcap, out_dir, output_path, window, use_ja4, skip_zeek, canonical...)
        # For dataset we use detector-v2 so raw fields survive; pass through feature_profile + ja4.
        pipeline.run_pipeline(
            str(pcap_path),
            tmp_zeek,
            str(features_path),
            window_secs=window_secs,
            use_ja4=use_ja4,
            skip_zeek=False,
            feature_profile=feature_profile,
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
            "zeek_image": _ja4_image_for_meta(use_ja4),
            "feature_profile": feature_profile,
            "use_ja4": use_ja4,
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
        "feature_profile": feature_profile,
        "use_ja4": use_ja4,
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
    ap.add_argument("--label", type=str, choices=sorted(ALLOWED_LABELS), help="Threat class label (7 detection classes plus benign)")
    ap.add_argument("--batch", type=str, help="Directory of .pcap files to ingest with the same --label")
    ap.add_argument("--dataset-root", type=str, default=str(DEFAULT_DATASET_ROOT), help="Dataset root (default: pcap_dataset/)")
    ap.add_argument("--window", type=float, default=60.0, help="Sliding window seconds for pipeline (default 60)")
    ap.add_argument(
        "--feature-profile",
        choices=FEATURE_PROFILES,
        default=DATASET_FEATURE_PROFILE,
        help="Feature contract: detector-v2 (default, carries raw query/ja3/sni) or legacy-m1d frozen",
    )
    ap.add_argument("--ja4", action="store_true", help="Use the pinned, locally qualified JA4 Zeek runtime (requires built sih-zeek-ja4 image)")
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
            ingest_one(p, args.label, dataset_root, window_secs=args.window, force=args.force, feature_profile=args.feature_profile, use_ja4=args.ja4)
        print(f"[+] Batch done: {len(pcaps)} files → {dataset_root / 'output'}")
        return

    if args.pcap:
        if not args.label:
            ap.error("--pcap requires --label")
        ingest_one(Path(args.pcap), args.label, dataset_root, window_secs=args.window, force=args.force, feature_profile=args.feature_profile, use_ja4=args.ja4)
        return

    ap.error("provide --pcap or --batch")


if __name__ == "__main__":
    main()
