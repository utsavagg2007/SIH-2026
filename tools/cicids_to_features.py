#!/usr/bin/env python3
"""Convert CIC-IDS2017 flow records into the ingestion features.jsonl shape.

    python tools/cicids_to_features.py CICIDS_Flow.parquet \
        --day 03/07/2017 -o data/real_benign.jsonl -m data/real_benign.labels.json

WHAT THIS IS, AND WHAT IT IS NOT
--------------------------------
This is **not** the ingestion pipeline. The real path is
PCAP -> Zeek -> ingestion_core (Rust) -> features.jsonl, and it cannot run in
every environment (it needs cargo, Zeek and Docker). This script substitutes for
it by mapping an already-flow-level public dataset onto the same record shape,
so the **real** detection runner can consume real captured traffic.

The consequence, stated plainly rather than buried: field fidelity is mine, not
Zeek's. Where CIC-IDS2017 and Zeek would disagree about what a "flow" is, these
numbers follow CIC-IDS2017. Specifically:

* CICFlowMeter emits **bidirectional** flows keyed on the 5-tuple with a 120 s
  timeout; Zeek's conn.log is also bidirectional but with different timeouts and
  a real `conn_state`. Flow *counts* are therefore not comparable between the
  two, only per-flow behaviour is.
* `Flow Duration` is **microseconds** in CICFlowMeter and seconds in the
  ingestion schema; converted here.
* There is **no `conn_state`** in this dataset. No detector currently reads it
  (verified), so nothing is lost today - but a future scan detector that keys on
  S0 would silently see nothing.
* There is **no DNS, TLS or HTTP block**. `dga_domain`, `dns_tunnelling` and
  `encrypted_malware` therefore *cannot* fire on this data at all. That is a
  property of the dataset, not a result about those detectors, and the
  evaluation must not report a "0 false positives" for them as if it were one.
* Timestamps are **1-second resolution on 03/07/2017 and 1-MINUTE resolution on
  every other day** (a known artefact of how the published CSVs were written).
  Minute quantisation destroys inter-arrival structure, so `c2_beaconing` is not
  measurable on the attack days, and window-density detectors see traffic
  compressed into instants. `--require-seconds` refuses to emit minute-only
  rows so this cannot be forgotten.

Directionality: CICFlowMeter's "Fwd" is the initiator direction, which is what
the ingestion schema calls `orig_`. Mapped accordingly.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

#: CIC-IDS2017 column -> what it becomes. Kept explicit so the mapping is
#: reviewable rather than implied by code.
COLUMNS = [
    "flow_id", "source_ip", "source_port", "destination_ip", "destination_port",
    "protocol", "Timestamp", "Flow Duration",
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "attack_label",
]

#: CIC-IDS2017 label -> the ThreatAlert threat_class it should produce, where a
#: correspondence genuinely exists. Labels absent from this map are attacks the
#: detector suite does not claim to cover; they are counted separately rather
#: than scored as misses.
LABEL_TO_CLASS = {
    "PortScan": "port_scan",
    "DDoS": "ddos",
    "Bot": "c2_beaconing",
    "Infiltration": "data_exfiltration",
}

#: Attacks present in the capture that no detector in this suite targets. Alerts
#: overlapping these are neither true positives nor benign false positives, and
#: are reported in their own column.
OUT_OF_SCOPE = {
    "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest",
    "FTP-Patator", "SSH-Patator", "Heartbleed",
}


def parse_timestamp(raw: str) -> tuple[float | None, bool]:
    """(epoch_seconds, had_seconds). ``None`` when unparseable.

    The published CSVs mix ``dd/MM/yyyy HH:mm:ss`` with ``d/M/yyyy H:mm``. Both
    are day-first; treating them as month-first would silently reorder the
    capture, so the format list is explicit and there is no dateutil guess.
    """
    raw = raw.strip()
    for fmt, had_sec in (("%d/%m/%Y %H:%M:%S", True), ("%d/%m/%Y %H:%M", False)):
        try:
            dt = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp(), had_sec
        except ValueError:
            continue
    return None, False


def convert(
    parquet: Path,
    *,
    day: str | None,
    labels: set[str] | None,
    require_seconds: bool,
    limit: int | None,
) -> tuple[list[dict], dict]:
    import pyarrow.parquet as pq

    table = pq.ParquetFile(parquet).read(columns=COLUMNS)
    n = table.num_rows
    col = {c: table.column(c).to_pylist() for c in COLUMNS}

    records: list[dict] = []
    ground_truth: list[dict] = []
    stats = Counter()
    label_counts = Counter()

    for i in range(n):
        raw_ts = col["Timestamp"][i]
        ts, had_sec = parse_timestamp(raw_ts)
        if ts is None:
            stats["unparseable_timestamp"] += 1
            continue

        if day is not None:
            d = raw_ts.split(" ")[0].split("/")
            if len(d) != 3 or f"{int(d[0]):02d}/{int(d[1]):02d}/{d[2]}" != day:
                continue
        if require_seconds and not had_sec:
            stats["dropped_minute_only"] += 1
            continue

        label = col["attack_label"][i]
        if labels is not None and label not in labels:
            continue

        proto = (col["protocol"][i] or "").lower()
        if proto not in ("tcp", "udp", "icmp"):
            proto = "tcp" if proto == "other" else proto or "tcp"

        duration_us = col["Flow Duration"][i] or 0
        duration = max(duration_us, 0) / 1_000_000.0

        orig_bytes = max(int(col["Total Length of Fwd Packets"][i] or 0), 0)
        resp_bytes = max(int(col["Total Length of Bwd Packets"][i] or 0), 0)
        orig_pkts = max(int(col["Total Fwd Packets"][i] or 0), 0)
        resp_pkts = max(int(col["Total Backward Packets"][i] or 0), 0)
        src_ip = col["source_ip"][i]
        dst_ip = col["destination_ip"][i]
        dst_port = int(col["destination_port"][i] or 0)
        src_port = int(col["source_port"][i] or 0)

        uid = f"C{i}"
        records.append({
            "flow_id": f"{src_ip}:{dst_ip}:{dst_port}:{proto}:{ts}",
            "uid": uid,
            "timestamp": ts,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": proto,
            "service": None,
            "duration": duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
            "byte_ratio": (resp_bytes / orig_bytes) if orig_bytes else 0.0,
            "pkt_ratio": (resp_pkts / orig_pkts) if orig_pkts else 0.0,
            "conn_state_encoded": 0,
        })
        ground_truth.append({
            "uid": uid, "timestamp": ts, "src_ip": src_ip, "dst_ip": dst_ip,
            "label": label, "threat_class": LABEL_TO_CLASS.get(label),
            "in_scope": label in LABEL_TO_CLASS,
            "out_of_scope": label in OUT_OF_SCOPE,
            "benign": label == "BENIGN",
        })
        label_counts[label] += 1
        stats["emitted"] += 1
        if not had_sec:
            stats["minute_only_kept"] += 1
        if limit and len(records) >= limit:
            break

    # detection_core requires non-decreasing event time.
    order = sorted(range(len(records)), key=lambda k: records[k]["timestamp"])
    records = [records[k] for k in order]
    ground_truth = [ground_truth[k] for k in order]

    manifest = {
        "source": "CIC-IDS2017 (rdpahalavan/CIC-IDS2017 mirror, Network-Flows/CICIDS_Flow.parquet)",
        "kind": "real_capture_flow_level",
        "day_filter": day,
        "require_seconds": require_seconds,
        "flows": len(records),
        "label_counts": dict(label_counts),
        "stats": dict(stats),
        "label_to_threat_class": LABEL_TO_CLASS,
        "out_of_scope_labels": sorted(OUT_OF_SCOPE),
        "caveats": [
            "Not produced by the ingestion pipeline; mapped from CICFlowMeter flows.",
            "No dns/tls/http block: dga_domain, dns_tunnelling and encrypted_malware "
            "cannot fire and must not be scored on this data.",
            "No conn_state: CICFlowMeter does not export one. port_scan 0.3.0 "
            "reads it when present and falls back to responder payload bytes, "
            "which is the path this data exercises.",
            "Timestamps: 1s resolution on 03/07/2017, 1-minute elsewhere.",
        ],
        "ground_truth": ground_truth,
    }
    return records, manifest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("parquet", help="CICIDS_Flow.parquet")
    ap.add_argument("-o", "--output", required=True, help="features.jsonl to write")
    ap.add_argument("-m", "--manifest", default=None, help="ground-truth JSON")
    ap.add_argument("--day", default=None, help="keep only this dd/mm/yyyy")
    ap.add_argument("--labels", default=None,
                    help="comma-separated attack_label values to keep")
    ap.add_argument("--require-seconds", action="store_true",
                    help="drop rows whose timestamp has only minute resolution")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    labels = set(x.strip() for x in args.labels.split(",")) if args.labels else None
    records, manifest = convert(
        Path(args.parquet), day=args.day, labels=labels,
        require_seconds=args.require_seconds, limit=args.limit,
    )
    if not records:
        print("no records matched the filters", file=sys.stderr)
        return 1

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")

    man = Path(args.manifest) if args.manifest else out.with_suffix(".labels.json")
    man.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    span = records[-1]["timestamp"] - records[0]["timestamp"]
    print(f"[+] {len(records)} flows -> {out}", file=sys.stderr)
    print(f"[+] ground truth      -> {man}", file=sys.stderr)
    print(f"    span {span/3600:.2f} h   labels: "
          f"{dict(sorted(manifest['label_counts'].items(), key=lambda kv: -kv[1]))}",
          file=sys.stderr)
    print(f"    stats: {manifest['stats']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
