#!/usr/bin/env python3
"""Score detector alerts against a real labelled capture.

    python tools/real_eval.py --alerts data/real_unsw.alerts.jsonl \
        --labels data/real_unsw.labels.json

Unit of evaluation: the ATTACKING ENTITY, not the flow
------------------------------------------------------
These detectors alert per source host, per host pair or per targeted host, with
cooldowns - one alert deliberately covers many flows. Scoring them per flow
would punish a detector for the aggregation it is designed to do, and would let
a chatty detector inflate recall by repeating itself. So:

* an **episode** is (threat_class, entity) where entity is the attacking source
  for source-scoped classes and the victim for ``ddos`` (which is scoped to the
  destination). Recall = episodes with at least one matching alert / episodes.
* a **true positive** is an alert whose class matches an attack episode the
  named entity actually participated in, within the alert's own time window
  widened by ``--slack``.
* a **false positive** is an alert whose entity/window carries only BENIGN
  flows. This is the number that matters and it is not threshold-dependent.
* an alert landing on an attack the suite does not claim (``out_of_scope`` in
  the manifest - exploits, fuzzers, web attacks) is counted separately. It is
  not a benign false positive: something genuinely malicious was there. Nor is
  it a true positive: the alert names the wrong thing. Reported in its own
  column rather than silently folded into either.

Precision here is computed against benign false positives only
(TP / (TP + FP_benign + FP_cross)), with out-of-scope hits excluded from the
denominator and reported separately, because folding them in would make the
number depend on how much unrelated attack traffic a dataset happens to carry.
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
REQUIRES = {
    "dns_tunnelling": "dns block (query strings)",
    "dga_domain": "dns block (query strings)",
    "encrypted_malware": "tls block (ja3 / server_name)",
}
#: ddos is scoped to the victim; everything else to the source.
VICTIM_SCOPED = {"ddos"}


def epoch(alert: dict, key: str) -> float:
    v = alert.get(key + "_epoch")
    if v is not None:
        return float(v)
    raw = alert.get(key)
    if raw is None:
        return 0.0
    from datetime import datetime
    return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--alerts", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--slack", type=float, default=300.0,
                    help="seconds to widen each alert window when matching (default 300)")
    ap.add_argument("--name", default=None)
    ap.add_argument("-o", "--output", default=None)
    args = ap.parse_args()

    alerts = [json.loads(l) for l in Path(args.alerts).read_text(encoding="utf-8").splitlines() if l.strip()]
    man = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    gt = man["ground_truth"]
    name = args.name or man.get("source", "?")

    # entity -> sorted [(ts, threat_class or None, benign, out_of_scope)]
    by_src: dict[str, list] = defaultdict(list)
    by_dst: dict[str, list] = defaultdict(list)
    for g in gt:
        rec = (g["timestamp"], g.get("threat_class"), g["benign"], g.get("out_of_scope", False))
        by_src[g["src_ip"]].append(rec)
        by_dst[g["dst_ip"]].append(rec)
    for d in (by_src, by_dst):
        for k in d:
            d[k].sort(key=lambda r: r[0])

    # ---- episodes (what recall is measured against) ----------------------
    episodes: dict[tuple[str, str], list[float]] = defaultdict(list)
    for g in gt:
        cls = g.get("threat_class")
        if not cls:
            continue
        entity = g["dst_ip"] if cls in VICTIM_SCOPED else g["src_ip"]
        episodes[(cls, entity)].append(g["timestamp"])

    # ---- classify every alert -------------------------------------------
    tp = Counter(); fp_benign = Counter(); fp_cross = Counter(); oos = Counter()
    matched_eps: set[tuple[str, str]] = set()
    fp_examples = defaultdict(list)

    for a in alerts:
        cls = a["threat_class"]
        entity = a.get("dst_ip") if cls in VICTIM_SCOPED else a.get("src_ip")
        if entity is None:
            entity = a.get("src_ip") or a.get("dst_ip")
        start = epoch(a, "event_start") - args.slack
        end = epoch(a, "event_end") + args.slack
        table = by_dst if cls in VICTIM_SCOPED else by_src
        window = [r for r in table.get(entity, []) if start <= r[0] <= end]

        if any(r[1] == cls for r in window):
            tp[cls] += 1
            matched_eps.add((cls, entity))
        elif any(r[1] is not None and r[1] != cls for r in window):
            fp_cross[cls] += 1
            if len(fp_examples[cls]) < 3:
                fp_examples[cls].append((entity, "cross-attack"))
        elif any(r[3] for r in window):
            oos[cls] += 1
        elif window and all(r[2] for r in window):
            fp_benign[cls] += 1
            if len(fp_examples[cls]) < 3:
                fp_examples[cls].append((entity, "benign"))
        else:
            fp_benign[cls] += 1  # no flows matched -> nothing malicious was there

    # ---- render ----------------------------------------------------------
    flows = len(gt)
    benign_flows = sum(1 for g in gt if g["benign"])
    span_h = (gt[-1]["timestamp"] - gt[0]["timestamp"]) / 3600.0

    print()
    print("REAL-TRAFFIC PER-DETECTOR EVALUATION")
    print("=" * 108)
    print(f"  dataset : {name}")
    print(f"  flows   : {flows:,}  ({benign_flows:,} benign = {100*benign_flows/flows:.2f}%)"
          f"   span {span_h:.2f} h   alerts {len(alerts):,}   slack ±{args.slack:.0f}s")
    print()
    print(f"  {'detector':19s} {'episodes':>9s} {'found':>6s} {'recall':>7s} "
          f"{'TP':>5s} {'FP-ben':>7s} {'FP-x':>5s} {'OOS':>5s} {'precision':>10s} {'F1':>7s} "
          f"{'FP/1k flows':>12s}")
    print("  " + "-" * 104)

    rows = []
    for d in ALL_DETECTORS:
        eps = [k for k in episodes if k[0] == d]
        if d in REQUIRES:
            print(f"  {d:19s} {'N/A':>9s} {'N/A':>6s} {'N/A':>7s} {'N/A':>5s} {'N/A':>7s} "
                  f"{'N/A':>5s} {'N/A':>5s} {'N/A':>10s} {'N/A':>7s} {'N/A':>12s}   "
                  f"<- no {REQUIRES[d]}")
            rows.append({"detector": d, "measurable": False, "reason": REQUIRES[d]})
            continue
        found = len([k for k in eps if k in matched_eps])
        recall = found / len(eps) if eps else None
        t, fb, fx, o = tp[d], fp_benign[d], fp_cross[d], oos[d]
        denom = t + fb + fx
        prec = t / denom if denom else None
        f1 = (2 * prec * recall / (prec + recall)) if (prec and recall) else None
        fpk = 1000.0 * (fb + fx) / flows

        def f(v, w=7, p=3):
            return f"{'-':>{w}}" if v is None else f"{v:{w}.{p}f}"

        print(f"  {d:19s} {len(eps):9d} {found:6d} {f(recall)} "
              f"{t:5d} {fb:7d} {fx:5d} {o:5d} {f(prec,10)} {f(f1)} {fpk:12.4f}")
        rows.append({
            "detector": d, "measurable": True,
            "episodes": len(eps), "episodes_found": found, "recall": recall,
            "true_positives": t, "false_positives_benign": fb,
            "false_positives_cross_attack": fx, "out_of_scope_hits": o,
            "precision": prec, "f1": f1, "fp_per_1000_flows": fpk,
        })

    print()
    print("  episodes = distinct (class, attacking entity) pairs in the ground truth;")
    print("  recall is over episodes, not flows - these detectors aggregate by design.")
    print("  FP-ben = alert window carried only benign flows.  FP-x = wrong attack class.")
    print("  OOS    = landed on an attack this suite does not claim (not scored either way).")

    payload = {
        "kind": "real_traffic_detector_evaluation",
        "dataset": name, "flows": flows, "benign_flows": benign_flows,
        "span_hours": span_h, "alerts": len(alerts), "slack_seconds": args.slack,
        "per_detector": rows,
        "caveats": man.get("caveats", []),
    }
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\n[+] -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
