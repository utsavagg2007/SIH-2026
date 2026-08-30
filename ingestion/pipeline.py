#!/usr/bin/env python3
"""
Ingestion pipeline: PCAP -> Zeek -> Rust parsers -> flow records (JSON lines).

    PCAP / live      Zeek            ingestion_core (Rust)        detection_core
        |              |                      |                        |
        +--- capture --+--- conn/dns/ssl ---- + --- features.jsonl --- +

Two modes:
  * Default: runs Zeek via scripts/run_zeek.sh (Docker), then parses + extracts.
  * --skip-zeek: assumes Zeek already ran and reads logs from --keep-logs.
    Use this when you run Zeek yourself as root, e.g.:
        sudo ./scripts/run_zeek.sh pcaps/capture.pcap zeek_output
        python pipeline.py --skip-zeek -o features.jsonl

Usage:
  python pipeline.py pcaps/capture.pcap -o features.jsonl --ja4
  python pipeline.py --skip-zeek -o features.jsonl
  python pipeline.py --skip-zeek -o -   | python -m detection_core.runner - --api-url ...

WHAT CHANGED HERE, AND WHY
--------------------------
This file used to emit a feature vector that had quietly thrown away most of
what Zeek observed. Four defects, all of them silent, all fixed below without
touching the Rust crate:

1. **Window features were attached to the wrong flows.** ``extract_flow_features``
   returns results in input order while ``extract_window_features`` sorts its
   input by timestamp internally, and the two were merged by index. They agree
   only when conn.log is already sorted - and Zeek writes a connection record
   when the connection *closes* while ``ts`` is when it *opened*, so a long-lived
   connection lands in the file after short ones that started later. On real
   traffic every window feature was joined to a different flow. The records are
   now sorted once, here, before either extractor runs, so one canonical
   ordering serves both. Sorting is also what detection_core documents it needs:
   event time must be non-decreasing.

2. **The raw observables never reached the output.** ``join_by_uid`` carefully
   attached ``dns_query``, ``ja3_hash``, ``ssl_server_name`` and friends to each
   conn record - and then handed those records to ``extract_flow_features``,
   which deserialises them into a Rust ``FlowRecord`` that has no such fields.
   Serde drops unknown fields without complaint, so the enrichment evaporated.
   The DGA model needs the exact domain string and the encrypted-session path
   needs the exact JA3/JA3S/SNI strings; both were structurally unable to fire.
   The nested blocks are now composed here from the parsed protocol records, so
   the raw values survive alongside the derived ones.

3. **qtype and rcode were numbers wearing a string's name.** Zeek's dns.log
   carries both ``qtype`` (numeric, 16) and ``qtype_name`` (``TXT``); the parser
   reads the numeric one. So the crate's ``is_txt`` check, which compares that
   field against the literal ``"TXT"``, was false for every record ever parsed,
   and NXDOMAIN - the strongest behavioural DGA signal there is - was invisible
   as the string ``"3"``. Both are decoded to their names below, with the
   numeric form preserved beside them.

4. **The window block was globally scoped, and shipped a 1e6 artefact.**
   ``SlidingWindow`` holds every flow on the wire rather than one entity's, so
   ``unique_dst_ports`` counts the whole network and beacon periodicity is
   invisible at that granularity; and ``flow_rate`` divides by the observed span,
   which is zero on a single-flow window and yields exactly 1000000.0 - a value
   visible in the committed sample output, and one any model trained on it would
   learn as a window-boundary marker. detection_core already refuses to read
   these fields for that reason. They are now opt-in behind ``--window-features``
   rather than emitted by default; keying them per entity is a Rust change.

The remaining known gap is JA4: ``--ja4`` selects a Zeek image that produces the
column, but ``SslRecord`` has no field for it, so it cannot be emitted without a
change to the crate. It is absent rather than faked.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, TextIO

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

#: DNS resource-record types, numeric to name. Zeek's dns.log exposes both
#: ``qtype`` and ``qtype_name``; the Rust parser reads the numeric column, so
#: the mapping happens here. Only the types that carry detection signal are
#: listed - anything else is passed through as its own number, which is
#: truthful and keeps an unexpected type visible rather than mislabelled.
_QTYPE_NAMES = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR", "15": "MX",
    "16": "TXT", "28": "AAAA", "33": "SRV", "35": "NAPTR", "43": "DS",
    "46": "RRSIG", "47": "NSEC", "48": "DNSKEY", "50": "NSEC3", "52": "TLSA",
    "65": "HTTPS", "99": "SPF", "251": "IXFR", "252": "AXFR", "255": "ANY",
}

#: DNS response codes. NXDOMAIN (3) is the one that matters most: a burst of
#: failed resolutions from one host is often a stronger DGA indicator than the
#: entropy of any single domain string.
_RCODE_NAMES = {
    "0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL", "3": "NXDOMAIN",
    "4": "NOTIMP", "5": "REFUSED", "6": "YXDOMAIN", "7": "YXRRSET",
    "8": "NXRRSET", "9": "NOTAUTH", "10": "NOTZONE",
}

#: Zeek writes these for a field it did not observe. They are not values.
_UNSET = {"", "-", "(empty)"}


@dataclass
class PipelineStats:
    """What the run actually produced, for the operator and for the README."""

    conn_records: int = 0
    dns_records: int = 0
    ssl_records: int = 0
    http_records: int = 0
    emitted: int = 0
    with_dns: int = 0
    with_tls: int = 0
    with_http: int = 0
    with_raw_query: int = 0
    with_ja3: int = 0
    with_sni: int = 0
    #: uids carrying more than one row of the same protocol log. Reported
    #: rather than hidden - see ``_protocol_index``.
    multi_row_uids: dict[str, int] = field(default_factory=dict)

    def render(self) -> str:
        lines = [
            f"parsed   conn={self.conn_records} dns={self.dns_records} "
            f"ssl={self.ssl_records} http={self.http_records}",
            f"emitted  {self.emitted} flow record(s)",
            f"enriched dns={self.with_dns} tls={self.with_tls} http={self.with_http}",
            f"raw      dns.query={self.with_raw_query} tls.ja3={self.with_ja3} "
            f"tls.server_name={self.with_sni}",
        ]
        for kind, count in sorted(self.multi_row_uids.items()):
            lines.append(
                f"note     {count} uid(s) carried multiple {kind} rows; the "
                f"earliest is inlined and the rest are counted in "
                f"{kind}.transaction_count"
            )
        if not self.with_raw_query and self.dns_records:
            lines.append(
                "warning  DNS rows were parsed but no raw query survived - "
                "the DGA detector will stay silent"
            )
        if not self.with_ja3 and self.ssl_records:
            lines.append(
                "warning  TLS rows were parsed but no JA3 hash was present - "
                "run Zeek with --ja4 (the activecm image) to produce it"
            )
        return "\n".join(lines)


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


# --------------------------------------------------------------------------
# Normalisation helpers
# --------------------------------------------------------------------------


def _clean(value: Any) -> Any:
    """Zeek's unset sentinels become None rather than an empty string.

    An empty string is a value; ``-`` is Zeek saying it saw nothing. Carrying
    the difference matters downstream, where detection_core treats ``None`` as
    "not available" and refuses to invent a substitute.
    """
    if isinstance(value, str) and value.strip() in _UNSET:
        return None
    return value


def _qtype_name(raw: Any) -> str | None:
    """``16`` -> ``TXT``. A name already in hand is returned unchanged."""
    value = _clean(raw)
    if value is None:
        return None
    text = str(value).strip()
    if text.isdigit():
        return _QTYPE_NAMES.get(text, text)
    return text.upper()


def _rcode_name(raw: Any) -> str | None:
    """``3`` -> ``NXDOMAIN``."""
    value = _clean(raw)
    if value is None:
        return None
    text = str(value).strip()
    if text.isdigit():
        return _RCODE_NAMES.get(text, text)
    return text.upper()


def _protocol_index(
    records: list[dict], features: list[dict], kind: str, stats: PipelineStats
) -> dict[str, tuple[dict, dict, int]]:
    """Index protocol rows by uid: (raw record, derived features, row count).

    One Zeek connection uid can carry several protocol rows - most commonly a
    UDP DNS conversation that resolves many names before the connection ages
    out. The previous implementation kept whichever row happened to be last,
    silently. This keeps the *earliest* row, which is deterministic, and counts
    the rest so the loss is visible in the output and in ``--stats`` rather than
    invisible.

    The proper fix is one observation per DNS transaction rather than one per
    flow, which is exactly what ``contracts/canonical_observation_v1.schema.json``
    already models with ``observation_type: "dns"``. Until the canonical
    producer covers DNS, this reports what it is dropping.
    """
    index: dict[str, tuple[dict, dict, int]] = {}
    for record, derived in zip(records, features):
        uid = record.get("uid")
        if not uid:
            continue
        existing = index.get(uid)
        if existing is None:
            index[uid] = (record, derived, 1)
            continue
        previous_record, previous_derived, count = existing
        stats.multi_row_uids[kind] = stats.multi_row_uids.get(kind, 0) + (
            1 if count == 1 else 0
        )
        # Earliest wins, so the choice does not depend on file order.
        if record.get("timestamp", 0.0) < previous_record.get("timestamp", 0.0):
            index[uid] = (record, derived, count + 1)
        else:
            index[uid] = (previous_record, previous_derived, count + 1)
    return index


# --------------------------------------------------------------------------
# Block builders
# --------------------------------------------------------------------------


def _dns_block(raw: dict, derived: dict, transactions: int) -> dict:
    """Derived DNS features plus the raw strings the DGA model needs.

    ``is_txt`` is recomputed rather than passed through: the crate compares the
    numeric qtype against the literal "TXT", so its answer is always False.
    """
    qtype = _qtype_name(raw.get("qtype"))
    block = {
        "uid": raw.get("uid"),
        "query": _clean(raw.get("query")),
        "qtype": qtype,
        "qtype_num": _clean(raw.get("qtype")),
        "rcode": _rcode_name(raw.get("rcode")),
        "rcode_num": _clean(raw.get("rcode")),
        "query_length": derived.get("query_length"),
        "query_entropy": derived.get("query_entropy"),
        "subdomain_entropy": derived.get("subdomain_entropy"),
        "is_txt": qtype == "TXT",
        "label_count": derived.get("label_count"),
    }
    if transactions > 1:
        block["transaction_count"] = transactions
    return block


def _tls_block(raw: dict, derived: dict) -> dict:
    """Derived TLS features plus the raw fingerprints and SNI.

    ``cipher_encoded`` is deliberately not carried. The crate computes it as
    ``(cipher_name_length % 16) + 1`` - a function of how long the cipher's
    *name* happens to be, not of which cipher was negotiated - and the crate's
    own README marks it a placeholder. The real cipher string is emitted
    instead, which is both smaller and true.

    ``sni_length``/``sni_entropy`` are computed here rather than left absent:
    the encrypted-session heuristic reads them, they are a pure function of a
    string we now have, and detection_core would otherwise have to derive them
    itself from the same input.
    """
    server_name = _clean(raw.get("server_name"))
    block = {
        "uid": raw.get("uid"),
        "ja3": _clean(raw.get("ja3")),
        "ja3s": _clean(raw.get("ja3s")),
        # JA4 is not parsed by the crate; absent rather than faked.
        "ja4": None,
        "server_name": server_name,
        "version": _clean(raw.get("version")),
        "cipher": _clean(raw.get("cipher")),
        "has_ja3": derived.get("has_ja3"),
        "has_ja3s": derived.get("has_ja3s"),
        "ssl_version_encoded": derived.get("ssl_version_encoded"),
    }
    if server_name:
        block["sni_length"] = len(server_name)
        block["sni_entropy"] = _shannon(server_name)
    return block


def _http_block(raw: dict, derived: dict) -> dict:
    return {
        "uid": raw.get("uid"),
        "host": _clean(raw.get("host")),
        "uri": _clean(raw.get("uri")),
        "user_agent": _clean(raw.get("user_agent")),
        "method": _clean(raw.get("method")),
        "status_code": raw.get("status_code"),
        "host_length": derived.get("host_length"),
        "uri_length": derived.get("uri_length"),
        "uri_entropy": derived.get("uri_entropy"),
        "has_user_agent": derived.get("has_user_agent"),
        "user_agent_length": derived.get("user_agent_length"),
        "request_body_len": derived.get("request_body_len"),
        "response_body_len": derived.get("response_body_len"),
    }


def _shannon(text: str) -> float:
    """Shannon entropy over the characters of *text*, in bits."""
    if not text:
        return 0.0
    from collections import Counter
    from math import log2

    total = len(text)
    return -sum(
        (n / total) * log2(n / total) for n in Counter(text).values()
    )


# --------------------------------------------------------------------------
# Join
# --------------------------------------------------------------------------


def join_by_uid(parsed: dict[str, list[dict]]) -> list[dict]:
    """Conn records keyed by uid, in the file's own order.

    Deliberately no longer decorates the conn record with flattened protocol
    fields. Those decorations were dropped by serde the moment the record
    crossed into Rust, so they read as if they did something and did not. The
    protocol data is joined in :func:`build_records` instead, where it survives.
    """
    by_uid: dict[str, dict] = {}
    for conn in parsed.get("conn", []):
        uid = conn.get("uid")
        if uid:
            by_uid.setdefault(uid, dict(conn))
    return list(by_uid.values())


def build_records(
    joined: list[dict],
    parsed: dict[str, list[dict]],
    *,
    window_secs: float = 60.0,
    emit_window: bool = False,
    stats: PipelineStats | None = None,
) -> Iterator[dict]:
    """Yield one flow record per connection, in event-time order.

    Generator rather than list-returning: the caller writes each record as it
    is produced, so a long capture does not have to fit in memory twice and the
    output is usable by a downstream reader before the run finishes.
    """
    stats = stats or PipelineStats()
    stats.conn_records = len(parsed.get("conn", []))
    stats.dns_records = len(parsed.get("dns", []))
    stats.ssl_records = len(parsed.get("ssl", []))
    stats.http_records = len(parsed.get("http", []))

    # ONE canonical ordering, established before either extractor runs. This is
    # the fix for the index-merge misalignment described in the module
    # docstring: sliding_window_features sorts by timestamp internally, so the
    # only way index i means the same flow in both results is to hand both the
    # already-sorted list. Python's sort and Rust's are both stable, so ties
    # keep file order in both.
    ordered = sorted(joined, key=lambda r: r.get("timestamp", 0.0))

    conn_json = json.dumps(ordered)
    flow_feats = json.loads(extract_flow_features(conn_json))
    window_feats = (
        json.loads(extract_window_features(conn_json, window_secs))
        if emit_window
        else None
    )

    dns_index = _protocol_index(
        parsed.get("dns", []),
        json.loads(extract_dns_features(json.dumps(parsed["dns"])))
        if parsed.get("dns")
        else [],
        "dns",
        stats,
    )
    tls_index = _protocol_index(
        parsed.get("ssl", []),
        json.loads(extract_tls_features(json.dumps(parsed["ssl"])))
        if parsed.get("ssl")
        else [],
        "tls",
        stats,
    )
    http_index = _protocol_index(
        parsed.get("http", []),
        json.loads(extract_http_features(json.dumps(parsed["http"])))
        if parsed.get("http")
        else [],
        "http",
        stats,
    )

    for index, conn in enumerate(ordered):
        uid = conn.get("uid")
        vector: dict[str, Any] = dict(flow_feats[index])

        # The identity and event-time fields the crate's FlowFeatures struct
        # drops. Every one of these is already on the conn record; none of them
        # needs a Rust change. detection_core prefers an explicit numeric
        # timestamp over the one embedded in flow_id, and its adapter reads
        # every name used here.
        vector["uid"] = uid
        vector["timestamp"] = conn.get("timestamp")
        vector["src_port"] = conn.get("src_port")
        vector["service"] = _clean(conn.get("service"))
        # The RAW connection state, not just the encoded one. Zeek's S0 - a
        # connection attempt with no reply - has no arm in the crate's encoder
        # and collapses to 0/unknown, which is precisely the signal a port scan
        # and a SYN flood are made of.
        vector["conn_state"] = _clean(conn.get("conn_state"))
        vector["orig_ip_bytes"] = conn.get("orig_ip_bytes")
        vector["resp_ip_bytes"] = conn.get("resp_ip_bytes")

        if window_feats is not None:
            vector.update(window_feats[index])

        if uid in dns_index:
            raw, derived, count = dns_index[uid]
            vector["dns"] = _dns_block(raw, derived, count)
            stats.with_dns += 1
            if vector["dns"]["query"]:
                stats.with_raw_query += 1
        if uid in tls_index:
            raw, derived, _ = tls_index[uid]
            vector["tls"] = _tls_block(raw, derived)
            stats.with_tls += 1
            if vector["tls"]["ja3"]:
                stats.with_ja3 += 1
            if vector["tls"]["server_name"]:
                stats.with_sni += 1
        if uid in http_index:
            raw, derived, _ = http_index[uid]
            vector["http"] = _http_block(raw, derived)
            stats.with_http += 1

        stats.emitted += 1
        yield vector


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------


@contextmanager
def _open_output(path: str) -> Iterator[TextIO]:
    """``-`` means stdout, so the pipeline can be piped into detection."""
    if path == "-":
        yield sys.stdout
        return
    handle = open(path, "w", encoding="utf-8")
    try:
        yield handle
    finally:
        handle.close()


def run_pipeline(
    pcap_path: str | None,
    out_dir: str,
    output_path: str,
    window_secs: float = 60.0,
    use_ja4: bool = False,
    skip_zeek: bool = False,
    emit_window: bool = False,
) -> PipelineStats:
    if not skip_zeek:
        if pcap_path is None:
            sys.exit("ERROR: --skip-zeek not set, so a PCAP argument is required.")
        run_zeek(pcap_path, out_dir, use_ja4)

    parsed = parse_logs(out_dir)
    joined = join_by_uid(parsed)
    stats = PipelineStats()

    with _open_output(output_path) as handle:
        for record in build_records(
            joined,
            parsed,
            window_secs=window_secs,
            emit_window=emit_window,
            stats=stats,
        ):
            handle.write(json.dumps(record) + "\n")
            # Flushed per record so a downstream reader on the other end of a
            # pipe sees each flow as it is produced rather than at process
            # exit. This is what makes `pipeline.py -o - | detection_core.runner -`
            # a streaming pipeline rather than two batch jobs in a trench coat.
            handle.flush()
    return stats


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Ingestion pipeline: PCAP -> Zeek -> flow records"
    )
    ap.add_argument("pcap", nargs="?", help="Path to input PCAP (omit with --skip-zeek)")
    ap.add_argument(
        "-o",
        "--output",
        default="features.jsonl",
        help="JSON-lines output; '-' writes to stdout for piping",
    )
    ap.add_argument(
        "-w", "--window", type=float, default=60.0, help="Sliding window size (seconds)"
    )
    ap.add_argument("--ja4", action="store_true", help="Use JA3/JA4 Zeek image")
    ap.add_argument(
        "--skip-zeek", action="store_true", help="Skip Zeek; read logs from --keep-logs"
    )
    ap.add_argument("--keep-logs", default="zeek_output", help="Directory for Zeek logs")
    ap.add_argument(
        "--window-features",
        action="store_true",
        help=(
            "also emit the global sliding-window block. Off by default: the "
            "window is not keyed by entity, so its counts describe the whole "
            "wire rather than one host, and detection_core recomputes its own "
            "keyed windows and refuses to read these"
        ),
    )
    ap.add_argument(
        "--stats",
        action="store_true",
        help="print a summary of what was parsed and what survived to the output",
    )
    args = ap.parse_args()

    stats = run_pipeline(
        args.pcap,
        args.keep_logs,
        args.output,
        args.window,
        args.ja4,
        args.skip_zeek,
        args.window_features,
    )

    # Never to stdout: stdout may be carrying the records themselves.
    print(f"[+] Processed {stats.emitted} flows -> {args.output}", file=sys.stderr)
    if args.stats:
        print(stats.render(), file=sys.stderr)


if __name__ == "__main__":
    main()
