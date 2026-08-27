#!/usr/bin/env python3
"""
Ingestion pipeline: PCAP -> Zeek -> Rust parsers -> feature vectors (JSON lines).

Two modes:
  * Default: runs Zeek via scripts/run_zeek.sh (Docker), then parses + extracts.
  * --skip-zeek: assumes Zeek already ran and reads logs from --keep-logs.
    Use this when you run Zeek yourself as root, e.g.:
        sudo ./scripts/run_zeek.sh pcaps/capture.pcap zeek_output
        .venv/bin/python pipeline.py --skip-zeek -o features.jsonl

Steps (parse/extract, both modes):
  1. Parse each Zeek log with the Rust library (ingestion_core).
  2. Join conn/dns/ssl/http records by `uid` (Python side).
  3. Extract feature vectors with the Rust library.
  4. Write one JSON object per line to the output file.

Usage:
  .venv/bin/python pipeline.py pcaps/capture.pcap -o features.jsonl --ja4
  .venv/bin/python pipeline.py --skip-zeek -o features.jsonl
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from ingestion_core import (
    parse_conn_log,
    parse_dns_log,
    parse_ssl_log,
    parse_http_log,
    extract_flow_features,
    extract_window_features,
    extract_dns_features,
    extract_tls_features,
    extract_http_features,
)

# Map of log kind -> (Rust parser, Zeek filename).
_LOG_MAP = {
    "conn": (parse_conn_log, "conn.log"),
    "dns": (parse_dns_log, "dns.log"),
    "ssl": (parse_ssl_log, "ssl.log"),
    "http": (parse_http_log, "http.log"),
}


def run_zeek(pcap_path: str, out_dir: str, use_ja4: bool = False) -> None:
    """Run Zeek on a PCAP via the run_zeek.sh wrapper (Docker-based)."""
    script = Path(__file__).parent / "scripts" / "run_zeek.sh"
    if not script.exists():
        raise FileNotFoundError(f"run_zeek.sh not found at {script}")
    cmd = [str(script), pcap_path, out_dir]
    if use_ja4:
        cmd.append("--ja4")
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


def parse_logs(out_dir: str) -> dict[str, list[dict]]:
    """Parse every Zeek log present into a dict of record lists."""
    parsed: dict[str, list[dict]] = {}
    missing = []
    for kind, (fn, fname) in _LOG_MAP.items():
        path = Path(out_dir) / fname
        if path.exists():
            parsed[kind] = json.loads(fn(str(path)))
        elif kind == "conn":
            missing.append(fname)
    if missing:
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


def run_pipeline(
    pcap_path: str | None,
    out_dir: str,
    output_path: str,
    window_secs: float = 60.0,
    use_ja4: bool = False,
    skip_zeek: bool = False,
) -> list[dict]:
    if not skip_zeek:
        if pcap_path is None:
            sys.exit("ERROR: --skip-zeek not set, so a PCAP argument is required.")
        run_zeek(pcap_path, out_dir, use_ja4)
    parsed = parse_logs(out_dir)
    joined = join_by_uid(parsed)
    vectors = extract_features(joined, parsed, window_secs)
    with open(output_path, "w") as f:
        for v in vectors:
            f.write(json.dumps(v) + "\n")
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
    ap.add_argument("--ja4", action="store_true", help="Use JA3/JA4 Zeek image")
    ap.add_argument(
        "--skip-zeek", action="store_true", help="Skip Zeek; read logs from --keep-logs"
    )
    ap.add_argument(
        "--keep-logs", default="zeek_output", help="Directory for Zeek logs"
    )
    args = ap.parse_args()

    vectors = run_pipeline(
        args.pcap, args.keep_logs, args.output, args.window, args.ja4, args.skip_zeek
    )
    print(f"[+] Processed {len(vectors)} flows -> {args.output}")


if __name__ == "__main__":
    main()
