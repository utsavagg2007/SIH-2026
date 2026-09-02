#!/usr/bin/env python3
"""What the detectors need, and what actually arrives through the adapter.

    python tools/ingestion_field_audit.py data/features.jsonl

This is written for the ingestion team. It does not read the ingestion source;
it reads whatever JSONL you point it at, pushes it through the **real**
``detection_core`` adapter, and reports, per field, how many FlowEvents came
out with a usable value. A field that is `None` on every flow is a field a
detector cannot use, whatever the schema promises.

Three sections:

  1. ARRIVAL   - per FlowEvent field: present / null / coverage, measured on
                 the flows where that protocol block exists at all (a TLS field
                 missing on a DNS flow is not a gap).
  2. DETECTOR  - which detector needs which field, and whether the run had it.
  3. DRIFT     - top-level keys the adapter did not recognise. These are not
                 dropped (they land in ``FlowEvent.extra``), but the adapter
                 warns about each one and nothing reads them.

The DETECTOR->field map below is transcribed from the frozen detector sources.
It is documentation, not detection logic; if a detector changes, update it here.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detection"))

from detection_core.adapters import IngestionJsonlAdapter  # noqa: E402
from detection_core.adapters.encodings import (  # noqa: E402
    CONN_STATE_BY_CODE,
    IGNORED_WINDOW_FIELDS,
    KNOWN_TOP_LEVEL_FIELDS,
)
from detection_core.aggregators import INCOMPLETE_CONN_STATES  # noqa: E402

CORE_FIELDS = [
    "flow_id", "uid", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
    "proto", "service", "duration", "orig_bytes", "resp_bytes", "orig_pkts",
    "resp_pkts", "conn_state",
]
DNS_FIELDS = [
    "uid", "query", "qtype", "rcode", "query_length", "query_entropy",
    "subdomain_entropy", "is_txt", "label_count",
]
TLS_FIELDS = [
    "uid", "ja3", "ja3s", "ja4", "server_name", "version", "has_ja3",
    "has_ja3s", "sni_length", "sni_entropy",
]
HTTP_FIELDS = [
    "uid", "host", "uri", "user_agent", "method", "host_length", "uri_length",
    "uri_entropy", "has_user_agent", "user_agent_length", "request_body_len",
    "response_body_len", "status_code",
]

#: Fields a detector does not *require*, but is measurably worse without.
#: Reported separately so "OK - every field it reads arrived" cannot be read as
#: "this detector is at full strength".
DETECTOR_DEGRADED_WITHOUT: dict[str, list[str]] = {
    # Measured on UNSW-NB15: with conn_state, port_scan scores recall 1.000 /
    # precision 1.000 on the four Reconnaissance episodes. Without it the
    # responder-payload proxy has to stand in, and recall falls to 0.500 -
    # banner-grabbing recon completes its connections, so only the connection
    # state distinguishes it from ordinary traffic. See docs/REAL_DATA_EVAL.md.
    "port_scan": ["conn_state"],
}

#: detector -> the FlowEvent fields it reads to decide. Dotted names are inside
#: a protocol block. Transcribed from the frozen detector sources and from
#: ``aggregators/sliding_window.py``, which is what the four window-based
#: detectors read the flow through. Doc-comment mentions were excluded; only
#: fields the code actually dereferences are listed.
DETECTOR_NEEDS: dict[str, list[str]] = {
    # via SlidingWindow: unique dst_port / dst_ip counts per source, plus the
    # responder-engagement check. `resp_bytes` is the proxy that runs today;
    # `conn_state` is what it stands in for, and is listed separately in
    # DETECTOR_DEGRADED_WITHOUT because its absence degrades the detector
    # rather than breaking it.
    "port_scan": ["src_ip", "dst_ip", "dst_port", "timestamp", "resp_bytes"],
    # via SlidingWindow keyed on the target: source cardinality + orig volume
    "ddos": ["src_ip", "dst_ip", "dst_port", "timestamp", "orig_pkts", "orig_bytes"],
    "c2_beaconing": ["src_ip", "dst_ip", "dst_port", "proto", "timestamp",
                     "orig_bytes"],
    "data_exfiltration": ["src_ip", "dst_ip", "timestamp", "orig_bytes",
                          "resp_bytes"],
    "dns_tunnelling": ["src_ip", "dst_ip", "dst_port", "proto", "timestamp",
                       "orig_bytes", "dns.query", "dns.qtype", "dns.rcode",
                       "dns.is_txt", "dns.query_length", "dns.query_entropy",
                       "dns.subdomain_entropy", "dns.label_count"],
    "dga_domain": ["src_ip", "dst_ip", "dst_port", "proto", "timestamp",
                   "dns.query", "dns.qtype", "dns.rcode"],
    "encrypted_malware": ["src_ip", "dst_ip", "dst_port", "proto", "timestamp",
                          "flow_id", "tls.ja3", "tls.ja3s", "tls.ja4",
                          "tls.server_name", "tls.version", "tls.sni_length",
                          "tls.sni_entropy"],
}


def _coverage(values: list[Any]) -> tuple[int, int]:
    present = sum(1 for v in values if v is not None and v != "")
    return present, len(values)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("input", nargs="?", default=str(ROOT / "data" / "features.jsonl"))
    ap.add_argument("-o", "--output", default=None)
    args = ap.parse_args()

    logging.basicConfig(level=logging.CRITICAL, stream=sys.stderr)
    path = Path(args.input)
    if not path.is_file():
        print(f"no such capture: {path}", file=sys.stderr)
        return 1

    adapter = IngestionJsonlAdapter()
    flows = list(adapter.from_path(path))
    stats = adapter.stats

    raw_keys: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        for key in json.loads(line):
            raw_keys[key] = raw_keys.get(key, 0) + 1

    core = {f: _coverage([getattr(fl, f) for fl in flows]) for f in CORE_FIELDS}
    with_dns = [fl for fl in flows if fl.dns is not None]
    with_tls = [fl for fl in flows if fl.tls is not None]
    with_http = [fl for fl in flows if fl.http is not None]
    dns = {f: _coverage([getattr(fl.dns, f) for fl in with_dns]) for f in DNS_FIELDS}
    tls = {f: _coverage([getattr(fl.tls, f) for fl in with_tls]) for f in TLS_FIELDS}
    http = {f: _coverage([getattr(fl.http, f) for fl in with_http]) for f in HTTP_FIELDS}

    lookup = {f"{f}": core[f] for f in core}
    lookup.update({f"dns.{f}": dns[f] for f in dns})
    lookup.update({f"tls.{f}": tls[f] for f in tls})
    lookup.update({f"http.{f}": http[f] for f in http})

    unknown_keys = sorted(
        k for k in raw_keys
        if k not in KNOWN_TOP_LEVEL_FIELDS and k not in IGNORED_WINDOW_FIELDS
    )
    window_keys = sorted(k for k in raw_keys if k in IGNORED_WINDOW_FIELDS)

    print()
    print(f"INGESTION FIELD AUDIT - {path}")
    print("=" * 92)
    print(f"  lines {stats.total_lines}   parsed {stats.parsed}   "
          f"json errors {stats.json_errors}   validation errors {stats.validation_errors}")
    print(f"  flows with dns={len(with_dns)}  tls={len(with_tls)}  http={len(with_http)}")
    print()

    def block(title: str, table: dict[str, tuple[int, int]], denom_note: str) -> None:
        print(f"  --- {title}  ({denom_note}) ---")
        for name, (present, total) in table.items():
            pct = (100.0 * present / total) if total else 0.0
            mark = "MISSING (always null)" if present == 0 and total else ""
            print(f"    {name:22s} {present:6d}/{total:<6d} {pct:6.1f}%  {mark}")
        print()

    block("core flow fields", core, f"denominator = all {len(flows)} flows")
    block("dns block", dns, f"denominator = {len(with_dns)} flows carrying a dns block")
    block("tls block", tls, f"denominator = {len(with_tls)} flows carrying a tls block")
    block("http block", http, f"denominator = {len(with_http)} flows carrying an http block")

    print("  --- what each detector needs, and whether it arrived ---")
    gaps: dict[str, list[str]] = {}
    degraded_by: dict[str, list[str]] = {}
    for detector, needs in DETECTOR_NEEDS.items():
        missing = []
        for field in needs:
            present, total = lookup.get(field, (0, 0))
            if total and present == 0:
                missing.append(field)
            elif total == 0:
                missing.append(f"{field} (no such block in this capture)")
        gaps[detector] = missing
        verdict = "OK - every field it reads arrived" if not missing else "MISSING: " + ", ".join(missing)
        print(f"    {detector:20s} {verdict}")
        # Immediately under the verdict, so "OK" is never read on its own: a
        # detector can have every field it dereferences and still be running
        # at reduced strength.
        absent = [
            field
            for field in DETECTOR_DEGRADED_WITHOUT.get(detector, [])
            if lookup.get(field, (0, 0))[0] == 0
        ]
        degraded_by[detector] = absent
        for field in absent:
            print(f"    {'':20s} DEGRADED: no {field} - runs on a proxy, "
                  f"at reduced recall")

    # --- connection states actually observed --------------------------------
    # A field being "present" is not the same as a field being *usable*. The
    # scan-relevant states are the ones that say the responder never engaged,
    # and ingestion's integer encoding has no code for the most important of
    # them, so no capture run through it can ever produce one.
    observed = Counter(f.conn_state for f in flows if f.conn_state is not None)
    print()
    print("  --- conn_state values observed ---")
    if not observed:
        print("    (none - no flow carried a connection state)")
    else:
        for state, count in observed.most_common():
            mark = "  <- incomplete (scan signal)" if state in INCOMPLETE_CONN_STATES else ""
            print(f"    {state:8s} {count:8d}  {100*count/len(flows):5.1f}%{mark}")
    unrepresentable = sorted(INCOMPLETE_CONN_STATES - set(CONN_STATE_BY_CODE.values()))
    if unrepresentable:
        print(f"    NOT REPRESENTABLE by ingestion's encoding: {', '.join(unrepresentable)}")
        print("      encode_conn_state (ingestion/src/features/flow.rs) has no arm for")
        print("      these, so they arrive as 0 - the same code as 'unknown'. S0 is the")
        print("      primary port-scan signal; see docs/REAL_DATA_EVAL.md for what it costs.")
    print()
    print("  --- schema drift: top-level keys the adapter does not know ---")
    if unknown_keys:
        for key in unknown_keys:
            print(f"    {key:22s} on {raw_keys[key]}/{stats.total_lines} lines "
                  f"-> kept in FlowEvent.extra, nothing reads it")
    else:
        print("    (none)")
    print()
    print("  --- window fields present but deliberately ignored by the adapter ---")
    print("    " + (", ".join(window_keys) if window_keys else "(none)"))
    print()
    print("  drift warnings raised by the adapter:")
    for warning in stats.drift_warnings or ["(none)"]:
        print(f"    {warning}")

    payload = {
        "kind": "ingestion_field_audit",
        "capture": str(path),
        "flows": len(flows),
        "adapter_stats": {
            "total_lines": stats.total_lines,
            "parsed": stats.parsed,
            "json_errors": stats.json_errors,
            "validation_errors": stats.validation_errors,
            "drift_warnings": list(stats.drift_warnings),
        },
        "blocks_present": {"dns": len(with_dns), "tls": len(with_tls), "http": len(with_http)},
        "coverage": {k: {"present": v[0], "total": v[1]} for k, v in lookup.items()},
        "detector_gaps": gaps,
        # Fields present in DETECTOR_NEEDS terms but absent in practice, which
        # cost recall rather than breaking the detector. Serialised as well as
        # printed: the ingestion team reads this file, not the terminal.
        "detector_degraded_by_missing": {k: v for k, v in degraded_by.items() if v},
        "conn_state_observed": dict(observed.most_common()),
        "conn_state_unrepresentable_by_ingestion": unrepresentable,
        "unknown_top_level_keys": unknown_keys,
        "ignored_window_keys": window_keys,
    }
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\n[+] -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
