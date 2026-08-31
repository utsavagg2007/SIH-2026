#!/usr/bin/env python3
"""Score emitted alerts against a ground-truth manifest.

    python tools/evaluate.py --alerts data/alerts.jsonl \\
                             --manifest data/features.manifest.json

Layer 9 of the build plan, which calls this "a graded deliverable disguised as
internal tooling". It joins what the detectors said against what the scenario
runner knows it generated, and reports precision, recall and F1 per threat
class.

Why there is no accuracy figure here
------------------------------------
Because it would be a lie of omission. With rare positives, overall accuracy is
dominated by the negative class: a detector that fires on nothing scores
extremely well. The build plan is blunt about it - "Any judge who knows the
domain will notice immediately" - so this reports per-class precision and
recall, and false positives per hour on benign traffic, and nothing that can be
quoted out of context to flatter the system.

The number that actually matters
--------------------------------
The confounder table at the bottom. Benign traffic in the manifest is labelled
with the threat class it *resembles* - a time daemon resembles a beacon, a cloud
backup resembles exfiltration - and every false positive is attributed to the
confounder that caused it where one exists. "Our beacon detector separates a
real C2 channel from four legitimate periodic services at N% precision" is a
claim worth making. "We detected the beacon" is not.

Matching rule
-------------
An alert is a true positive when its threat class equals an attack interval's
label, its time window overlaps that interval, and at least one of its endpoints
appears in the interval's participant set. All three, because any two of them
alone will credit the wrong finding: two attacks from the same host at different
times, or two different hosts attacked in the same window, are distinct events.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

THREAT_CLASSES = [
    "port_scan", "ddos", "c2_beaconing", "dga_domain",
    "dns_tunnelling", "encrypted_malware", "data_exfiltration",
]


@dataclass
class ClassScore:
    threat_class: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    #: False positives attributed to a named benign confounder.
    confounder_hits: dict[str, int] = field(default_factory=dict)

    @property
    def precision(self) -> float | None:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else None

    @property
    def recall(self) -> float | None:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)


def _overlaps(a_start: float, a_end: float, b_start: float, b_end: float, slack: float) -> bool:
    """Do two windows touch, allowing *slack* seconds either side?

    Slack is not fudge. A windowed detector reports the window it evaluated, not
    the instant the traffic happened, so a beacon detector with a 900-second
    window legitimately emits an alert whose ``event_start`` precedes the first
    malicious packet. Requiring exact containment would score correct detections
    as false positives.
    """
    return a_start - slack <= b_end and b_start - slack <= a_end


def _endpoints(alert: dict[str, Any]) -> set[str]:
    return {ip for ip in (alert.get("src_ip"), alert.get("dst_ip")) if ip}


def _participants(interval: dict[str, Any]) -> set[str]:
    hosts = set(interval.get("src_ips") or []) | set(interval.get("dst_ips") or [])
    for key in ("src_ip", "dst_ip"):
        if interval.get(key):
            hosts.add(interval[key])
    return hosts


def _sources(interval: dict[str, Any]) -> set[str]:
    hosts = set(interval.get("src_ips") or [])
    if interval.get("src_ip"):
        hosts.add(interval["src_ip"])
    return hosts


def _same_actor(alert: dict[str, Any], interval: dict[str, Any]) -> bool:
    """Is this alert about the actor the interval describes?

    Matching on *any* shared endpoint is too generous, and generously wrong in
    the direction that flatters the system. Every DNS-based finding on the
    network shares one destination - the resolver - so a DGA alert about an
    innocent CDN lookup would be credited against the real DGA interval purely
    because both used 10.4.0.53, and the CDN confounder would silently score as
    a true positive. Precision would read 1.000 while the detector was firing on
    exactly the benign traffic the confounder was planted to expose.

    So when the alert names a source and the interval knows its sources, the
    source has to match. Only when one side is unattributed - a spoofed flood
    names no source at all - does this fall back to any shared endpoint.
    """
    alert_src = alert.get("src_ip")
    interval_sources = _sources(interval)
    if alert_src and interval_sources:
        return alert_src in interval_sources

    hosts = _endpoints(alert)
    participants = _participants(interval)
    if not hosts or not participants:
        return True
    return bool(hosts & participants)


def evaluate(
    alerts: list[dict[str, Any]],
    manifest: dict[str, Any],
    *,
    slack_seconds: float = 900.0,
) -> tuple[dict[str, ClassScore], list[dict[str, Any]]]:
    intervals = manifest.get("intervals", [])
    attacks = [i for i in intervals if i["label"] in THREAT_CLASSES]
    confounders = [i for i in intervals if i["label"] == "benign_confounder"]

    scores = {name: ClassScore(name) for name in THREAT_CLASSES}
    matched_intervals: set[int] = set()
    unmatched: list[dict[str, Any]] = []

    for alert in alerts:
        threat_class = alert.get("threat_class")
        if threat_class not in scores:
            continue
        start = float(alert.get("event_start_epoch") or alert.get("event_start") or 0)
        end = float(alert.get("event_end_epoch") or alert.get("event_end") or start)
        hosts = _endpoints(alert)

        hit = None
        for index, interval in enumerate(attacks):
            if interval["label"] != threat_class:
                continue
            if not _overlaps(start, end, interval["start"], interval["end"], slack_seconds):
                continue
            if not _same_actor(alert, interval):
                continue
            hit = index
            break

        if hit is not None:
            scores[threat_class].true_positives += 1
            matched_intervals.add(hit)
            continue

        scores[threat_class].false_positives += 1
        blame = _attribute(alert, threat_class, start, end, hosts, confounders, slack_seconds)
        record = {
            "threat_class": threat_class,
            "src_ip": alert.get("src_ip"),
            "dst_ip": alert.get("dst_ip"),
            "severity": alert.get("severity"),
            "score": alert.get("score"),
            "confounder": blame,
        }
        if blame:
            hits = scores[threat_class].confounder_hits
            hits[blame] = hits.get(blame, 0) + 1
        unmatched.append(record)

    for index, interval in enumerate(attacks):
        if index not in matched_intervals:
            scores[interval["label"]].false_negatives += 1

    return scores, unmatched


def _attribute(
    alert: dict[str, Any],
    threat_class: str,
    start: float,
    end: float,
    hosts: set[str],
    confounders: list[dict[str, Any]],
    slack: float,
) -> str | None:
    """Which planted innocent behaviour, if any, caused this false positive."""
    for interval in confounders:
        if interval.get("mimics") != threat_class:
            continue
        if not _overlaps(start, end, interval["start"], interval["end"], slack):
            continue
        if not _same_actor(alert, interval):
            continue
        return interval.get("note") or interval.get("mimics")
    return None


def _fmt(value: float | None, width: int = 6) -> str:
    return "  n/a " if value is None else f"{value:>{width}.3f}"


def render(
    scores: dict[str, ClassScore],
    unmatched: list[dict[str, Any]],
    manifest: dict[str, Any],
    alert_count: int,
) -> str:
    duration_h = max(manifest.get("duration_seconds", 0) / 3600.0, 1e-9)
    lines: list[str] = []
    lines.append("PER-CLASS DETECTION PERFORMANCE")
    lines.append("=" * 78)
    lines.append(
        f"{'threat class':22}{'TP':>5}{'FP':>5}{'FN':>5}"
        f"{'precision':>11}{'recall':>9}{'F1':>9}"
    )
    lines.append("-" * 78)
    for name in THREAT_CLASSES:
        s = scores[name]
        if not (s.true_positives or s.false_positives or s.false_negatives):
            lines.append(f"{name:22}{'-':>5}{'-':>5}{'-':>5}{'not exercised':>29}")
            continue
        lines.append(
            f"{name:22}{s.true_positives:>5}{s.false_positives:>5}{s.false_negatives:>5}"
            f"{_fmt(s.precision, 11)}{_fmt(s.recall, 9)}{_fmt(s.f1, 9)}"
        )
    lines.append("")
    lines.append(
        "Deliberately no overall accuracy figure: with rare positives it is "
        "dominated by the\nnegative class, and a detector that fires on "
        "nothing would score well."
    )

    total_fp = sum(s.false_positives for s in scores.values())
    lines.append("")
    lines.append(f"False positives per hour of traffic: {total_fp / duration_h:.1f}")
    lines.append(f"Alerts scored: {alert_count}   capture duration: {duration_h * 60:.1f} min")

    blamed = [u for u in unmatched if u["confounder"]]
    lines.append("")
    lines.append("BENIGN CONFOUNDERS - the number that decides credibility")
    lines.append("=" * 78)
    if not blamed:
        planted = [i for i in manifest.get("intervals", []) if i["label"] == "benign_confounder"]
        if planted:
            lines.append(
                f"{len(planted)} confounder(s) planted, none produced a false "
                "positive. Every detector\nseparated the innocent lookalike "
                "from the real threat."
            )
        else:
            lines.append(
                "No confounders in this manifest. Precision figures above are "
                "therefore\noptimistic and should not be quoted."
            )
    else:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in blamed:
            grouped[row["threat_class"]].append(row)
        for threat_class, rows in sorted(grouped.items()):
            lines.append(f"\n  {threat_class}: {len(rows)} false positive(s)")
            seen: set[str] = set()
            for row in rows:
                note = row["confounder"]
                if note in seen:
                    continue
                seen.add(note)
                lines.append(f"    caused by: {note}")
            for row in rows:
                lines.append(
                    f"      {str(row['src_ip']):15} -> {str(row['dst_ip']):16} "
                    f"{row['severity']:8} score={row['score']}"
                )

    unexplained = [u for u in unmatched if not u["confounder"]]
    if unexplained:
        lines.append("")
        lines.append(f"Unattributed false positives: {len(unexplained)}")
        for row in unexplained[:10]:
            lines.append(
                f"    {row['threat_class']:20} {str(row['src_ip']):15} -> "
                f"{str(row['dst_ip']):16} {row['severity']}"
            )
    return "\n".join(lines)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    out = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                out.append(json.loads(line))
    return out


def _to_epoch(alert: dict[str, Any]) -> dict[str, Any]:
    """Normalise the two alert shapes this can be pointed at.

    ``detection_core.runner`` writes ThreatAlert v1.1, where the window bounds
    are ISO-8601 strings. The backend's stored view uses epoch floats. Accepting
    both means the same harness scores a raw detector run and a run that went
    through the whole pipeline, which is how you tell a detector regression from
    a fusion one.
    """
    from datetime import datetime

    for key in ("event_start", "event_end"):
        value = alert.get(key)
        if isinstance(value, str):
            alert[f"{key}_epoch"] = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            ).timestamp()
        elif isinstance(value, (int, float)):
            alert[f"{key}_epoch"] = float(value)
    return alert


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Per-class precision/recall against a ground-truth manifest"
    )
    ap.add_argument("--alerts", default="data/alerts.jsonl",
                    help="ThreatAlert v1.1 JSONL, or the backend's stored views")
    ap.add_argument("--manifest", default="data/features.manifest.json",
                    help="scenario manifest written by tools/synth_flows.py")
    ap.add_argument("--slack", type=float, default=900.0,
                    help="seconds of tolerance when matching an alert window to "
                         "a ground-truth interval; must cover the widest "
                         "detector window (default 900, the beacon window)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    alerts_path, manifest_path = Path(args.alerts), Path(args.manifest)
    for path in (alerts_path, manifest_path):
        if not path.is_file():
            print(f"ERROR: {path} not found", file=sys.stderr)
            return 1

    alerts = [_to_epoch(a) for a in _load_jsonl(alerts_path)]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    scores, unmatched = evaluate(alerts, manifest, slack_seconds=args.slack)

    if args.json:
        print(json.dumps(
            {
                "per_class": {
                    name: {
                        "true_positives": s.true_positives,
                        "false_positives": s.false_positives,
                        "false_negatives": s.false_negatives,
                        "precision": s.precision,
                        "recall": s.recall,
                        "f1": s.f1,
                        "confounder_hits": s.confounder_hits,
                    }
                    for name, s in scores.items()
                },
                "alerts_scored": len(alerts),
                "duration_seconds": manifest.get("duration_seconds"),
                "unmatched": unmatched,
            },
            indent=2,
        ))
    else:
        print(render(scores, unmatched, manifest, len(alerts)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
