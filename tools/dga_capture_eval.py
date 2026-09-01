#!/usr/bin/env python3
"""Score the DGA model on the domains that actually appear in a capture.

    python tools/dga_capture_eval.py --model artifacts/dga_model.joblib --seeds 20

Why this is a different number from the training report
-------------------------------------------------------
``detection_core.ml.dga.training`` reports PR-AUC / ROC-AUC on a held-out,
*family-disjoint* slice of the training CSV: Tranco top-sites as the negative
class, real malware-family domains as the positive class. That measures the
model's generalization to unseen DGA families, which is the right question to
ask about the model.

It is not the question to ask about the *detector*. On the wire the negative
class is not Tranco - it is whatever this network looks up, which here includes
the CDN confounder (``d3f7k2mq9xz1lp.cloudfront.test``: long, high-entropy and
entirely legitimate) and 48-character DNS-tunnel subdomains. Those are the hard
negatives that decide whether the DGA panel is usable, and none of them is in
the training distribution.

So this scores **every DNS query in the capture**, labelled by which
``synth_flows`` producer emitted it, and reports both the threshold-free
ranking metrics and the decision metrics at the detector's own operating
threshold (``DGAConfig.score_threshold``, 0.75). Per-source-slice breakdowns
say *where* the errors are.

SYNTHETIC. The negatives are six benign hostnames plus four CDN names plus
generated tunnel subdomains - not a real network's DNS. Read this as detector
separation on labelled traffic, not as a production false-positive rate.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "detection"))

from detector_matrix import SLICES, sliced_capture  # noqa: E402

DEFAULT_THRESHOLD = 0.75


def collect_domains(slices: dict[str, list[dict]]) -> list[tuple[str, str, int]]:
    """(domain, slice_key, label) for every DNS query in the capture."""
    rows: list[tuple[str, str, int]] = []
    for key, records in slices.items():
        label = 1 if SLICES[key][0] == "dga_domain" else 0
        for record in records:
            dns = record.get("dns")
            if not dns:
                continue
            query = dns.get("query")
            if isinstance(query, str) and query.strip():
                rows.append((query, key, label))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--model", default=str(ROOT / "artifacts" / "dga_model.joblib"))
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--first-seed", type=int, default=26145)
    ap.add_argument("--duration", type=float, default=600.0)
    ap.add_argument("--base-time", type=float, default=1788203858.0)
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--dedupe", action="store_true",
                    help="score each distinct domain once instead of once per query")
    ap.add_argument("-o", "--output", default=None)
    args = ap.parse_args()

    model_path = Path(args.model)
    if not model_path.is_file():
        print(f"no model at {model_path}", file=sys.stderr)
        return 1

    from sklearn.metrics import average_precision_score, roc_auc_score  # noqa: E402

    from detection_core.ml.dga.model import DGAModel  # noqa: E402

    model = DGAModel.load(model_path)

    rows: list[tuple[str, str, int]] = []
    for i in range(args.seeds):
        slices = sliced_capture(
            seed=args.first_seed + i, duration=args.duration, base_time=args.base_time
        )
        rows.extend(collect_domains(slices))

    if args.dedupe:
        seen: dict[str, tuple[str, int]] = {}
        for domain, key, label in rows:
            seen.setdefault(domain, (key, label))
        rows = [(d, k, l) for d, (k, l) in seen.items()]

    domains = [r[0] for r in rows]
    labels = [r[2] for r in rows]
    scores = model.predict_scores(domains)

    thr = args.threshold
    tp = sum(1 for s, y in zip(scores, labels) if s >= thr and y == 1)
    fp = sum(1 for s, y in zip(scores, labels) if s >= thr and y == 0)
    fn = sum(1 for s, y in zip(scores, labels) if s < thr and y == 1)
    tn = sum(1 for s, y in zip(scores, labels) if s < thr and y == 0)
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision and recall
        else None
    )

    per_slice: dict[str, dict[str, Any]] = {}
    for (domain, key, label), score in zip(rows, scores):
        bucket = per_slice.setdefault(
            key,
            {"queries": 0, "label": label, "over_threshold": 0,
             "score_min": 1.0, "score_max": 0.0, "score_sum": 0.0,
             "examples": []},
        )
        bucket["queries"] += 1
        bucket["score_sum"] += score
        bucket["score_min"] = min(bucket["score_min"], score)
        bucket["score_max"] = max(bucket["score_max"], score)
        if score >= thr:
            bucket["over_threshold"] += 1
            if len(bucket["examples"]) < 3:
                bucket["examples"].append({"domain": domain, "score": round(score, 4)})
    for bucket in per_slice.values():
        bucket["score_mean"] = round(bucket["score_sum"] / bucket["queries"], 4)
        bucket["score_min"] = round(bucket["score_min"], 4)
        bucket["score_max"] = round(bucket["score_max"], 4)
        del bucket["score_sum"]

    payload = {
        "kind": "dga_model_on_capture_domains",
        "honesty_note": (
            "SYNTHETIC capture domains. Negatives are six benign hostnames, four CDN "
            "confounder names and generated DNS-tunnel subdomains - not real network "
            "DNS. Separation measure, not a production false-positive rate."
        ),
        "model": str(model_path),
        "seeds": args.seeds,
        "deduped": args.dedupe,
        "threshold": thr,
        "n_scored": len(rows),
        "n_positive": sum(labels),
        "n_negative": len(labels) - sum(labels),
        "roc_auc": roc_auc_score(labels, scores),
        "pr_auc": average_precision_score(labels, scores),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "per_slice": per_slice,
        "distinct_domains": len(set(domains)),
        "distinct_by_slice": dict(Counter(k for _, k, _ in rows)),
    }

    print()
    print("DGA MODEL ON CAPTURE DOMAINS (threshold-free ranking + decision @ %.2f)" % thr)
    print("=" * 92)
    print(f"  scored            : {payload['n_scored']} queries "
          f"({payload['distinct_domains']} distinct) over {args.seeds} capture(s)"
          + ("  [deduped]" if args.dedupe else ""))
    print(f"  positives/negatives: {payload['n_positive']} / {payload['n_negative']}")
    print(f"  ROC-AUC           : {payload['roc_auc']:.4f}")
    print(f"  PR-AUC (avg prec) : {payload['pr_auc']:.4f}")
    print(f"  @ {thr:.2f}  precision={precision if precision is None else round(precision,4)}"
          f"  recall={recall if recall is None else round(recall,4)}"
          f"  f1={f1 if f1 is None else round(f1,4)}")
    print(f"  tp/fp/tn/fn       : {tp}/{fp}/{tn}/{fn}")
    print()
    print(f"  {'slice':26s} {'label':6s} {'queries':>8s} {'>=thr':>7s} "
          f"{'min':>7s} {'mean':>7s} {'max':>7s}   example over threshold")
    print("  " + "-" * 96)
    for key in SLICES:
        if key not in per_slice:
            continue
        b = per_slice[key]
        example = b["examples"][0]["domain"] if b["examples"] else ""
        print(f"  {key:26s} {('DGA' if b['label'] else 'benign'):6s} {b['queries']:8d} "
              f"{b['over_threshold']:7d} {b['score_min']:7.3f} {b['score_mean']:7.3f} "
              f"{b['score_max']:7.3f}   {example[:34]}")
    print()
    print("  " + payload["honesty_note"])

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\n[+] -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
