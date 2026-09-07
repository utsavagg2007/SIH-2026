#!/usr/bin/env python3
"""
Ingestion pipeline: PCAP -> Zeek -> Rust parsers -> feature vectors (JSON lines).

Two modes:
  * Default: runs Zeek via scripts/run_zeek.sh (Docker), then parses + extracts.
  * --skip-zeek: assumes Zeek already ran and reads logs from --keep-logs.
    Use this when you run Zeek yourself as root, e.g.:
        sudo ./scripts/run_zeek.sh pcaps/capture.pcap zeek_output
        .venv/bin/python ingestion/pipeline.py --skip-zeek -o features.jsonl
        # or from ingestion/: ../.venv/bin/python pipeline.py --skip-zeek -o features.jsonl

Steps (parse/extract, both modes):
  1. Parse each Zeek log with the Rust library (ingestion_core).
  2. Join conn/dns/ssl/http records by `uid` (Python side).
  3. Extract feature vectors with the Rust library.
  4. Write one JSON object per line to the output file.

Usage:
  .venv/bin/python ingestion/pipeline.py pcaps/capture.pcap -o features.jsonl --tls-fingerprints
  .venv/bin/python ingestion/pipeline.py --skip-zeek -o features.jsonl
  # from ingestion/: ../.venv/bin/python pipeline.py ...
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import detector_profile

from ingestion_core import (
    parse_conn_log,
    parse_dns_log,
    parse_dns_log_detector,
    parse_ssl_log,
    parse_ssl_log_detector,
    parse_http_log,
    parse_http_log_detector,
    extract_flow_features,
    extract_window_features,
    extract_dns_features,
    extract_tls_features,
    extract_http_features,
    sha256_input_file,
    write_canonical_observations_from_zeek_logs,
)

# Map of log kind -> (Rust parser, Zeek filename).
_LOG_MAP = {
    "conn": (parse_conn_log, "conn.log"),
    "dns": (parse_dns_log, "dns.log"),
    "ssl": (parse_ssl_log, "ssl.log"),
    "http": (parse_http_log, "http.log"),
}

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
LEGACY_FEATURE_PROFILE = "legacy-m1d"
DETECTOR_FEATURE_PROFILE = detector_profile.PROFILE_NAME
FEATURE_PROFILES = (LEGACY_FEATURE_PROFILE, DETECTOR_FEATURE_PROFILE)


def run_zeek(
    pcap_path: str,
    out_dir: str,
    use_ja4: bool = False,
    canonical_mode: bool = False,
    deterministic_mode: bool = False,
    *,
    use_tls_fingerprints: bool = False,
) -> None:
    """Run Zeek on a PCAP via the run_zeek.sh wrapper (Docker-based)."""
    script = Path(__file__).parent / "scripts" / "run_zeek.sh"
    if not script.exists():
        raise FileNotFoundError(f"run_zeek.sh not found at {script}")
    cmd = [str(script)]
    if os.name == "nt":
        candidates = [
            Path(os.environ.get("ProgramFiles", "")) / "Git" / "bin" / "bash.exe",
            Path(os.environ.get("LOCALAPPDATA", ""))
            / "Programs"
            / "Git"
            / "bin"
            / "bash.exe",
        ]
        git_bash = next((path for path in candidates if path.is_file()), None)
        if git_bash is None:
            raise SystemExit(
                "ERROR: Git Bash is required to run the Docker-backed Zeek "
                "wrapper on Windows."
            )
        # Git for Windows only prepends its bundled POSIX utilities (dirname,
        # realpath, basename, and friends) when Bash reads its login profile.
        # The wrapper relies on those utilities, so make that initialization
        # explicit instead of depending on the caller's Windows PATH.
        cmd = [str(git_bash), "--login", str(script)]
    cmd.extend([pcap_path, out_dir])
    if use_ja4 and use_tls_fingerprints:
        raise SystemExit("ERROR: --ja4 and --tls-fingerprints are mutually exclusive.")
    if use_tls_fingerprints:
        cmd.append("--tls-fingerprints")
    elif use_ja4:
        cmd.append("--ja4")
    elif canonical_mode:
        cmd.append("--canonical")
    elif deterministic_mode:
        cmd.append("--deterministic")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        sys.exit(
            "ERROR: Zeek (Docker) step failed.\n"
            "The most common cause is the Docker socket permission:\n"
            "  - add your user to the docker group and re-login, or\n"
            "  - run Zeek manually as root (sudo ./scripts/run_zeek.sh ...) and\n"
            "    re-run this pipeline with --skip-zeek.\n"
            f"Underlying error: {exc}"
        )
    except OSError as exc:
        sys.exit(
            "ERROR: unable to launch the Docker-backed Zeek wrapper; run normal "
            "mode from Linux/WSL2 or another supported POSIX host.\n"
            f"Underlying error: {exc}"
        )


def parse_logs(
    out_dir: str,
    allow_empty_log_set: bool = False,
    feature_profile: str = LEGACY_FEATURE_PROFILE,
) -> dict[str, list[dict]]:
    """Parse every Zeek log present into a dict of record lists."""
    parsed: dict[str, list[dict]] = {}
    missing = []
    found_supported_log = False
    for kind, (fn, fname) in _LOG_MAP.items():
        if feature_profile == DETECTOR_FEATURE_PROFILE:
            if kind == "dns":
                fn = parse_dns_log_detector
            elif kind == "ssl":
                fn = parse_ssl_log_detector
            elif kind == "http":
                fn = parse_http_log_detector
        path = Path(out_dir) / fname
        if path.exists():
            found_supported_log = True
            parsed[kind] = json.loads(fn(str(path)))
        elif kind == "conn":
            missing.append(fname)
    if missing:
        if allow_empty_log_set and not found_supported_log:
            return parsed
        sys.exit(
            f"ERROR: required Zeek log(s) not found in {out_dir}: {missing}.\n"
            "Run Zeek first (or with --skip-zeek, ensure logs exist)."
        )
    return parsed


def join_by_uid(parsed: dict[str, list[dict]]) -> list[dict]:
    """Enrich conn records with dns/ssl/http fields, keyed by uid."""
    by_uid: dict[str, dict] = {c["uid"]: dict(c) for c in parsed.get("conn", [])}

    for d in parsed.get("dns", []):
        rec = by_uid.get(d["uid"])
        if rec is not None:
            rec["dns_query"] = d.get("query")
            rec["dns_qtype"] = d.get("qtype")
            rec["dns_rcode"] = d.get("rcode")

    for s in parsed.get("ssl", []):
        rec = by_uid.get(s["uid"])
        if rec is not None:
            rec["ja3_hash"] = s.get("ja3")
            rec["ja3s_hash"] = s.get("ja3s")
            rec["ssl_version"] = s.get("version")
            rec["ssl_cipher"] = s.get("cipher")
            rec["ssl_server_name"] = s.get("server_name")

    for h in parsed.get("http", []):
        rec = by_uid.get(h["uid"])
        if rec is not None:
            rec["http_method"] = h.get("method")
            rec["http_host"] = h.get("host")
            rec["http_uri"] = h.get("uri")
            rec["http_user_agent"] = h.get("user_agent")
            rec["http_status_code"] = h.get("status_code")

    return list(by_uid.values())


def extract_features(
    joined: list[dict], parsed: dict[str, list[dict]], window_secs: float = 60.0
) -> list[dict]:
    """Build one merged feature vector per flow.

    Flow + window features come from the joined conn records. DNS and TLS
    features are computed from the original DnsRecord/SslRecord JSON (keyed by
    uid) and nested under `dns`/`tls` so the ML team can flatten as needed.
    """
    conn_json = json.dumps(joined)
    flow_feats = json.loads(extract_flow_features(conn_json))
    window_feats = json.loads(extract_window_features(conn_json, window_secs))

    dns_by_uid: dict[str, dict] = {}
    if parsed.get("dns"):
        for r, f in zip(
            parsed["dns"], json.loads(extract_dns_features(json.dumps(parsed["dns"])))
        ):
            dns_by_uid[r["uid"]] = f

    tls_by_uid: dict[str, dict] = {}
    if parsed.get("ssl"):
        for r, f in zip(
            parsed["ssl"], json.loads(extract_tls_features(json.dumps(parsed["ssl"])))
        ):
            tls_by_uid[r["uid"]] = f

    http_by_uid: dict[str, dict] = {}
    if parsed.get("http"):
        for r, f in zip(
            parsed["http"], json.loads(extract_http_features(json.dumps(parsed["http"])))
        ):
            http_by_uid[r["uid"]] = f

    vectors: list[dict] = []
    for i, rec in enumerate(joined):
        vec = dict(flow_feats[i])
        vec.update(window_feats[i])
        if rec["uid"] in dns_by_uid:
            vec["dns"] = dns_by_uid[rec["uid"]]
        if rec["uid"] in tls_by_uid:
            vec["tls"] = tls_by_uid[rec["uid"]]
        if rec["uid"] in http_by_uid:
            vec["http"] = http_by_uid[rec["uid"]]
        vectors.append(vec)
    return vectors


def _normalize_input_sha256(value: str) -> str:
    if _SHA256_RE.fullmatch(value) is None:
        raise ValueError("input SHA-256 must contain exactly 64 hexadecimal characters")
    return value.lower()


def _normalized_path(path: str) -> str:
    return os.path.normcase(str(Path(path).resolve(strict=False)))


def _validate_canonical_request(
    canonical_output_path: str,
    legacy_output_path: str,
    sensor_id: str | None,
    input_sha256: str | None,
    use_ja4: bool,
) -> str | None:
    if sensor_id is None or sensor_id == "":
        sys.exit("ERROR: --sensor-id is required and must be nonempty in canonical mode.")
    if _normalized_path(canonical_output_path) == _normalized_path(legacy_output_path):
        sys.exit("ERROR: canonical output and legacy output must be different files.")

    target = Path(canonical_output_path)
    if target.exists():
        sys.exit(
            f"ERROR: canonical output already exists and will not be overwritten: {target}"
        )
    parent = target.parent if str(target.parent) else Path(".")
    if not parent.is_dir():
        sys.exit(f"ERROR: canonical output parent directory does not exist: {parent}")

    if input_sha256 is None:
        return None
    try:
        return _normalize_input_sha256(input_sha256)
    except ValueError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc


def _hash_original_pcap(pcap_path: str) -> str:
    path = Path(pcap_path)
    if not path.is_file():
        sys.exit(f"ERROR: PCAP file not found: {pcap_path}")
    try:
        return sha256_input_file(str(path))
    except OSError as exc:
        raise SystemExit(
            f"ERROR: failed to hash original PCAP {pcap_path}: {exc}"
        ) from exc


def _resolve_input_identity(
    pcap_path: str | None, supplied_sha256: str | None, skip_zeek: bool
) -> str:
    if pcap_path is not None:
        computed = _hash_original_pcap(pcap_path)
        if supplied_sha256 is not None and supplied_sha256 != computed:
            sys.exit(
                "ERROR: --input-sha256 does not match the SHA-256 of the supplied PCAP."
            )
        return computed
    if skip_zeek and supplied_sha256 is not None:
        return supplied_sha256
    if not skip_zeek:
        sys.exit("ERROR: --skip-zeek not set, so a PCAP argument is required.")
    sys.exit(
        "ERROR: canonical --skip-zeek mode requires either a readable PCAP or "
        "--input-sha256."
    )


def _canonical_observed_at() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _publish_fresh_logs(source_dir: str, requested_dir: str) -> None:
    source = Path(source_dir)
    destination = Path(requested_dir)
    destination.mkdir(parents=True, exist_ok=True)
    for path in source.iterdir():
        if path.is_file():
            try:
                shutil.copy2(path, destination / path.name)
            except OSError as exc:
                raise SystemExit(
                    "ERROR: failed to copy fresh Zeek log "
                    f"{path.name} into --keep-logs destination {destination}: {exc}. "
                    "The destination may contain a partial set of current-run copies; "
                    "unrelated pre-existing files were not removed."
                ) from exc


def _write_legacy_output(
    log_dir: str,
    output_path: str,
    window_secs: float,
    allow_empty_log_set: bool = False,
) -> list[dict]:
    parsed = parse_logs(log_dir, allow_empty_log_set=allow_empty_log_set)
    joined = join_by_uid(parsed)
    vectors = extract_features(joined, parsed, window_secs)
    with open(output_path, "w") as f:
        for v in vectors:
            f.write(json.dumps(v) + "\n")
    return vectors


def _write_feature_output(
    log_dir: str,
    output_path: str,
    window_secs: float,
    allow_empty_log_set: bool,
    feature_profile: str,
    emit_window: bool,
) -> list[dict] | detector_profile.PipelineStats:
    """Write exactly one explicitly selected feature-interface profile."""

    if feature_profile == LEGACY_FEATURE_PROFILE:
        if emit_window:
            raise SystemExit(
                "ERROR: --window-features requires --feature-profile detector-v2."
            )
        return _write_legacy_output(
            log_dir,
            output_path,
            window_secs,
            allow_empty_log_set=allow_empty_log_set,
        )
    if feature_profile == DETECTOR_FEATURE_PROFILE:
        parsed = parse_logs(
            log_dir,
            allow_empty_log_set=allow_empty_log_set,
            feature_profile=feature_profile,
        )
        return detector_profile.write_output(
            parsed,
            output_path,
            window_secs,
            emit_window,
        )
    raise SystemExit(
        f"ERROR: unsupported feature profile {feature_profile!r}; "
        f"expected one of {', '.join(FEATURE_PROFILES)}."
    )


def _write_canonical_output(
    log_dir: str,
    canonical_output_path: str,
    sensor_id: str,
    input_sha256: str,
    observed_at: str,
    allow_empty_log_set: bool,
) -> dict:
    try:
        summary = json.loads(
            write_canonical_observations_from_zeek_logs(
                log_dir,
                canonical_output_path,
                sensor_id,
                input_sha256,
                observed_at,
                allow_empty_log_set,
            )
        )
    except (OSError, ValueError) as exc:
        raise SystemExit(f"ERROR: canonical production failed: {exc}") from exc

    for diagnostic in summary.get("diagnostics", []):
        coordinates = [f"log={diagnostic['log_type']}"]
        if diagnostic.get("row_ordinal") is not None:
            coordinates.append(f"row={diagnostic['row_ordinal']}")
        if diagnostic.get("source_record_id") is not None:
            coordinates.append(f"uid={diagnostic['source_record_id']}")
        if diagnostic.get("field") is not None:
            coordinates.append(f"field={diagnostic['field']}")
        coordinates.append(f"kind={diagnostic['kind']}")
        print(
            f"[canonical] diagnostic {' '.join(coordinates)}: {diagnostic['message']}",
            file=sys.stderr,
        )
    if summary.get("diagnostics_truncated"):
        print(
            "[canonical] additional diagnostics omitted from CLI output",
            file=sys.stderr,
        )
    missing = ",".join(summary.get("missing_optional_logs", [])) or "none"
    print(
        "[canonical] "
        f"flow_emitted={summary['flow_emitted']} "
        f"dns_emitted={summary['dns_emitted']} "
        f"tls_emitted={summary['tls_emitted']} "
        f"http_emitted={summary['http_emitted']} "
        f"rows_skipped={summary['rows_skipped']} "
        f"diagnostics={summary['diagnostics_count']} "
        f"missing_optional_logs={missing} "
        f"output={canonical_output_path}",
        file=sys.stderr,
    )
    return summary


def run_pipeline(
    pcap_path: str | None,
    out_dir: str,
    output_path: str,
    window_secs: float = 60.0,
    use_ja4: bool = False,
    skip_zeek: bool = False,
    *,
    use_tls_fingerprints: bool = False,
    canonical_output_path: str | None = None,
    sensor_id: str | None = None,
    input_sha256: str | None = None,
    observed_at: str | None = None,
    feature_profile: str = LEGACY_FEATURE_PROFILE,
    emit_window: bool = False,
    deterministic_zeek: bool = False,
) -> list[dict] | detector_profile.PipelineStats:
    if use_ja4 and use_tls_fingerprints:
        raise SystemExit("ERROR: --ja4 and --tls-fingerprints are mutually exclusive.")
    if skip_zeek and (use_ja4 or use_tls_fingerprints):
        if use_tls_fingerprints:
            raise SystemExit(
                "ERROR: --skip-zeek cannot verify the qualified "
                "--tls-fingerprints runtime; omit --tls-fingerprints to parse "
                "already-produced logs."
            )
        raise SystemExit(
            "ERROR: --skip-zeek cannot verify the qualified JA4 runtime; "
            "omit --ja4 to parse already-produced logs."
        )
    if feature_profile not in FEATURE_PROFILES:
        raise SystemExit(
            f"ERROR: unsupported feature profile {feature_profile!r}; "
            f"expected one of {', '.join(FEATURE_PROFILES)}."
        )
    if emit_window and feature_profile != DETECTOR_FEATURE_PROFILE:
        raise SystemExit(
            "ERROR: --window-features requires --feature-profile detector-v2."
        )
    if canonical_output_path is None:
        if sensor_id is not None or input_sha256 is not None:
            sys.exit(
                "ERROR: --sensor-id and --input-sha256 require --canonical-output."
            )
        if not skip_zeek:
            if pcap_path is None:
                sys.exit("ERROR: --skip-zeek not set, so a PCAP argument is required.")
            if deterministic_zeek:
                if use_tls_fingerprints:
                    run_zeek(
                        pcap_path,
                        out_dir,
                        use_tls_fingerprints=True,
                        deterministic_mode=True,
                    )
                else:
                    run_zeek(
                        pcap_path,
                        out_dir,
                        use_ja4,
                        deterministic_mode=True,
                    )
            else:
                # Preserve the frozen global/default invocation exactly.
                if use_tls_fingerprints:
                    run_zeek(pcap_path, out_dir, use_tls_fingerprints=True)
                else:
                    run_zeek(pcap_path, out_dir, use_ja4)
        return _write_feature_output(
            out_dir,
            output_path,
            window_secs,
            False,
            feature_profile,
            emit_window,
        )

    normalized_supplied_sha = _validate_canonical_request(
        canonical_output_path,
        output_path,
        sensor_id,
        input_sha256,
        use_ja4,
    )
    assert sensor_id is not None
    resolved_sha = _resolve_input_identity(
        pcap_path, normalized_supplied_sha, skip_zeek
    )

    if skip_zeek:
        vectors = _write_feature_output(
            out_dir,
            output_path,
            window_secs,
            False,
            feature_profile,
            emit_window,
        )
        run_observed_at = observed_at or _canonical_observed_at()
        _write_canonical_output(
            out_dir,
            canonical_output_path,
            sensor_id,
            resolved_sha,
            run_observed_at,
            False,
        )
        return vectors

    if pcap_path is None:
        sys.exit("ERROR: --skip-zeek not set, so a PCAP argument is required.")

    with tempfile.TemporaryDirectory(prefix="sih-m1d-zeek-") as fresh_log_dir:
        runtime_args = {"canonical_mode": True}
        if use_tls_fingerprints:
            runtime_args["use_tls_fingerprints"] = True
        else:
            runtime_args["use_ja4"] = use_ja4
        run_zeek(pcap_path, fresh_log_dir, **runtime_args)
        post_zeek_sha = _hash_original_pcap(pcap_path)
        if post_zeek_sha != resolved_sha:
            sys.exit("ERROR: original PCAP changed while Zeek was processing it.")
        _publish_fresh_logs(fresh_log_dir, out_dir)
        vectors = _write_feature_output(
            fresh_log_dir,
            output_path,
            window_secs,
            True,
            feature_profile,
            emit_window,
        )
        run_observed_at = observed_at or _canonical_observed_at()
        _write_canonical_output(
            fresh_log_dir,
            canonical_output_path,
            sensor_id,
            resolved_sha,
            run_observed_at,
            True,
        )
        return vectors


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Ingestion pipeline: PCAP -> Zeek -> feature vectors"
    )
    ap.add_argument("pcap", nargs="?", help="Path to input PCAP (omit with --skip-zeek)")
    ap.add_argument("-o", "--output", default="features.jsonl", help="JSON-lines output")
    ap.add_argument(
        "-w", "--window", type=float, default=60.0, help="Sliding window size (seconds)"
    )
    fingerprint_group = ap.add_mutually_exclusive_group()
    fingerprint_group.add_argument(
        "--ja4",
        action="store_true",
        help="use the pinned, locally qualified JA4 Zeek runtime",
    )
    fingerprint_group.add_argument(
        "--tls-fingerprints",
        action="store_true",
        help="use the pinned JA3/JA3S/JA4 Zeek runtime",
    )
    ap.add_argument(
        "--skip-zeek", action="store_true", help="Skip Zeek; read logs from --keep-logs"
    )
    ap.add_argument(
        "--keep-logs", default="zeek_output", help="Directory for Zeek logs"
    )
    ap.add_argument(
        "--canonical-output",
        help="Opt-in CanonicalObservation v1 JSON-lines sidecar output",
    )
    ap.add_argument(
        "--sensor-id",
        help="Explicit sensor identity (required with --canonical-output)",
    )
    ap.add_argument(
        "--input-sha256",
        help="Original PCAP SHA-256 for canonical --skip-zeek without a PCAP",
    )
    ap.add_argument(
        "--feature-profile",
        choices=FEATURE_PROFILES,
        default=LEGACY_FEATURE_PROFILE,
        help=(
            "feature JSONL contract: frozen legacy-m1d (default) or the "
            "explicit detector-v2 integration profile"
        ),
    )
    ap.add_argument(
        "--window-features",
        action="store_true",
        help=(
            "include the legacy global window block in detector-v2 output; "
            "off by default because detectors compute entity-keyed windows"
        ),
    )
    ap.add_argument(
        "--stats",
        action="store_true",
        help="print detector-v2 parse/enrichment availability counters to stderr",
    )
    args = ap.parse_args()

    if args.canonical_output is None and (
        args.sensor_id is not None or args.input_sha256 is not None
    ):
        ap.error("--sensor-id and --input-sha256 require --canonical-output")
    if args.canonical_output is not None and args.sensor_id is None:
        ap.error("--sensor-id is required with --canonical-output")
    if args.window_features and args.feature_profile != DETECTOR_FEATURE_PROFILE:
        ap.error("--window-features requires --feature-profile detector-v2")
    if args.stats and args.feature_profile != DETECTOR_FEATURE_PROFILE:
        ap.error("--stats requires --feature-profile detector-v2")

    vectors = run_pipeline(
        args.pcap,
        args.keep_logs,
        args.output,
        args.window,
        args.ja4,
        args.skip_zeek,
        use_tls_fingerprints=args.tls_fingerprints,
        canonical_output_path=args.canonical_output,
        sensor_id=args.sensor_id,
        input_sha256=args.input_sha256,
        feature_profile=args.feature_profile,
        emit_window=args.window_features,
    )
    if isinstance(vectors, detector_profile.PipelineStats):
        print(f"[+] Processed {vectors.emitted} flows -> {args.output}", file=sys.stderr)
        if args.stats:
            print(vectors.render(), file=sys.stderr)
    else:
        # Preserve the frozen M1D default CLI stream exactly.
        print(f"[+] Processed {len(vectors)} flows -> {args.output}")


if __name__ == "__main__":
    main()
