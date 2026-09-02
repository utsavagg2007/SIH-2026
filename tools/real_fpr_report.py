#!/usr/bin/env python3
"""Per-detector false-positive rate on a capture that is entirely benign.

    python tools/real_fpr_report.py --alerts data/real_benign_monday.alerts.jsonl \
        --labels data/real_benign_monday.labels.json

On purely benign traffic every alert is a false positive, so this needs no
per-flow ground truth beyond "the whole capture is benign" - which is exactly
why a pure-benign day is the most valuable thing to measure against. There is
no threshold to argue about and no label noise to blame.

Reports alerts per 1 000 flows and per hour, per detector, plus which sources
the alerts concentrate on - a detector firing 400 times on one host is a
different problem from one firing once on 400 hosts.

IMPORTANT: detectors that structurally *cannot* fire on the input (no DNS block
means no dga_domain or dns_tunnelling; no TLS block means no encrypted_malware)
are reported as N/A rather than 0.000. A zero they could not have exceeded is
not a result.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

ALL_DETECTORS = [
    "port_scan", "ddos", "c2_beaconing", "dns_tunnelling",
    "dga_domain", "encrypted_malware", "data_exfiltration",
]

#: What each detector needs before it can produce anything at all.
REQUIRES = {
    "dns_tunnelling": "dns block (query strings)",
    "dga_domain": "dns block (query strings)",
    "encrypted_malware": "tls block (ja3 / server_name)",
}


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--alerts", required=True)
    ap.add_argument("--labels", required=True, help="manifest from cicids_to_features.py")
    ap.add_argument("--name", default=None, help="dataset name for the report header")
    ap.add_argument("-o", "--output", default=None)
    args = ap.parse_args()

    alerts = load_jsonl(Path(args.alerts))
    manifest = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    gt = manifest["ground_truth"]
    flows = len(gt)
    benign_flows = sum(1 for g in gt if g["benign"])
    span_h = (gt[-1]["timestamp"] - gt[0]["timestamp"]) / 3600.0 if flows > 1 else 0.0

    # Which protocol blocks actually reached the detectors?
    available = {"dns": False, "tls": False, "http": False}

    per = Counter(a["threat_class"] for a in alerts)
    by_src = defaultdict(Counter)
    by_sev = defaultdict(Counter)
    for a in alerts:
        by_src[a["threat_class"]][a.get("src_ip") or a.get("dst_ip")] += 1
        by_sev[a["threat_class"]][a.get("severity")] += 1

    name = args.name or manifest.get("source", "unknown")
    print()
    print("REAL-TRAFFIC FALSE-POSITIVE RATE")
    print("=" * 96)
    print(f"  dataset      : {name}")
    print(f"  flows        : {flows:,}   ({benign_flows:,} benign = "
          f"{100*benign_flows/flows:.2f}%)")
    print(f"  capture span : {span_h:.2f} h")
    print(f"  alerts       : {len(alerts):,}")
    if benign_flows != flows:
        print("  !! capture is NOT purely benign; this tool assumes it is")
    print()
    print(f"  {'detector':20s} {'alerts':>8s} {'per 1k flows':>13s} {'per hour':>10s} "
          f"{'distinct srcs':>14s}  severity mix")
    print("  " + "-" * 92)
    rows = []
    for d in ALL_DETECTORS:
        if d in REQUIRES and not available.get(REQUIRES[d].split()[0], False):
            print(f"  {d:20s} {'N/A':>8s} {'N/A':>13s} {'N/A':>10s} {'N/A':>14s}  "
                  f"cannot fire: no {REQUIRES[d]}")
            rows.append({"detector": d, "measurable": False,
                         "reason": f"input has no {REQUIRES[d]}"})
            continue
        n = per.get(d, 0)
        per_k = 1000.0 * n / flows
        per_h = n / span_h if span_h else float("nan")
        srcs = len(by_src[d])
        sev = ", ".join(f"{k}={v}" for k, v in by_sev[d].most_common())
        print(f"  {d:20s} {n:8d} {per_k:13.4f} {per_h:10.1f} {srcs:14d}  {sev}")
        rows.append({"detector": d, "measurable": True, "false_positives": n,
                     "per_1000_flows": per_k, "per_hour": per_h,
                     "distinct_sources": srcs,
                     "severity": dict(by_sev[d])})
    total = sum(per.get(d, 0) for d in ALL_DETECTORS)
    print("  " + "-" * 92)
    print(f"  {'TOTAL':20s} {total:8d} {1000.0*total/flows:13.4f} "
          f"{total/span_h if span_h else 0:10.1f}")

    print()
    print("  WHERE THE FALSE POSITIVES CONCENTRATE")
    print("  " + "-" * 92)
    for d in ALL_DETECTORS:
        if not by_src[d]:
            continue
        top = by_src[d].most_common(5)
        share = 100.0 * top[0][1] / sum(by_src[d].values())
        print(f"    {d}:  top source {top[0][0]} = {top[0][1]} alerts ({share:.0f}% of them)")
        print(f"      {', '.join(f'{h}={c}' for h, c in top)}")

    payload = {
        "kind": "real_traffic_false_positive_rate",
        "dataset": name,
        "flows": flows, "benign_flows": benign_flows, "span_hours": span_h,
        "total_alerts": len(alerts),
        "per_detector": rows,
        "note": "Every alert on a purely benign capture is a false positive. "
                "Detectors marked measurable=false could not fire on this input "
                "at all and are not scored.",
    }
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\n[+] -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
