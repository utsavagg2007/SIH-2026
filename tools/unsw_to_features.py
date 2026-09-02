#!/usr/bin/env python3
"""Convert UNSW-NB15 flow records into the ingestion features.jsonl shape.

    python tools/unsw_to_features.py UNSW-NB15_1.csv -o data/real_unsw.jsonl \
        -m data/real_unsw.labels.json

Companion to ``cicids_to_features.py``; the same disclaimer applies - this is
NOT the ingestion pipeline, it maps an already-flow-level public dataset onto
the same record shape so the real detection runner can consume real traffic.

Why this dataset in addition to CIC-IDS2017
-------------------------------------------
Two reasons, both about the weaknesses of the other one:

* **Timestamps.** CIC-IDS2017's published CSVs carry second resolution only on
  the Monday (benign) capture; every attack day is quantised to the minute,
  which destroys the inter-arrival structure ``c2_beaconing`` exists to measure.
  UNSW-NB15 carries ``Stime``/``Ltime`` as Unix epoch **seconds** throughout, so
  attack-side recall is measurable here and is not there.
* **A second network.** A false-positive rate from one testbed is an anecdote.
  UNSW-NB15 is a different testbed (ACCS, 2015) with a different benign
  generator, so its benign half is an independent second measurement.

Columns are positional: the published CSVs ship **without a header row** and
the field order comes from the dataset's own ``NUSW-NB15_features.csv``.
Indices are named below rather than left as magic numbers.

Honest limitation shared with every public labelled IDS set: the attack traffic
is **tool-generated** (IXIA PerfectStorm here, scripted tools in CIC-IDS2017),
not malware captured in the wild. It is real traffic on a real network stack,
which is what makes it far better than synthetic flow records - but it is not
evidence about traffic from an actual intrusion.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

# Positional layout of the UNSW-NB15 CSVs (0-based).
SRCIP, SPORT, DSTIP, DSPORT, PROTO, STATE, DUR = 0, 1, 2, 3, 4, 5, 6
SBYTES, DBYTES, SERVICE = 7, 8, 13
SPKTS, DPKTS = 16, 17
STIME, LTIME = 28, 29
ATTACK_CAT, LABEL = 47, 48
N_FIELDS = 49

#: UNSW attack_cat -> the ThreatAlert threat_class this suite claims to cover.
#: Deliberately conservative: only categories whose *mechanism* matches what a
#: detector looks for are mapped. Everything else is counted out-of-scope rather
#: than scored as a miss, because failing to detect an exploit payload is not a
#: failure of a port-scan detector.
CATEGORY_TO_CLASS = {
    "Reconnaissance": "port_scan",
    "DoS": "ddos",
    "Backdoors": "c2_beaconing",
    "Backdoor": "c2_beaconing",
}

OUT_OF_SCOPE = {
    "Generic", "Exploits", "Fuzzers", "Analysis", "Shellcode", "Worms",
}

#: UNSW's ``state`` column -> the Zeek ``conn_state`` spelling with the same
#: meaning. **This mapping is mine, not Zeek's**: UNSW-NB15 was produced by
#: Argus/Bro-era tooling with its own state vocabulary, and only the states
#: whose semantics genuinely correspond are translated. It exists so the
#: detection layer can be measured against a real, labelled approximation of
#: the field ingestion does not yet emit (see ``encode_conn_state`` in
#: ``ingestion/src/features/flow.rs``, which has no ``S0`` arm at all).
#:
#: The one that matters is ``INT`` -> ``S0``: a connection was initiated and
#: nothing came back. In this capture that state covers 1.4% of benign flows
#: against 41.7% of Reconnaissance and 90.6% of Backdoors, which is the whole
#: argument for asking ingestion to preserve it.
UNSW_STATE_TO_ZEEK = {
    "INT": "S0",      # initiated, no reply seen - Zeek's S0
    "REQ": "S0",      # request sent, no response - same shape
    "FIN": "SF",      # normal establishment and teardown
    "CLO": "SF",      # closed
    "CON": "S1",      # established, never terminated in the capture
    "RST": "RSTO",    # reset by the originator
    "ACC": "S2",      # responder SYN-ACK only
    "CLS": "SF",
    "ECO": "OTH", "ECR": "OTH", "MAS": "OTH", "PAR": "OTH",
    "TST": "OTH", "TXD": "OTH", "URH": "OTH", "URN": "OTH", "no": "OTH",
}


def norm_cat(raw: str) -> str:
    """attack_cat is inconsistently spelled/padded in the published CSVs."""
    c = (raw or "").strip()
    return {"Backdoors": "Backdoors", "Backdoor": "Backdoors"}.get(c, c)


def convert(path: Path, *, limit: int | None, keep: set[str] | None):
    records: list[dict] = []
    truth: list[dict] = []
    cats = Counter()
    skipped = Counter()

    with path.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
        for i, row in enumerate(csv.reader(fh)):
            if not row or len(row) < N_FIELDS:
                skipped["short_row"] += 1
                continue
            cat = norm_cat(row[ATTACK_CAT])
            label_is_attack = (row[LABEL].strip() == "1")
            name = cat if cat else ("attack" if label_is_attack else "BENIGN")
            if keep is not None and name not in keep:
                continue
            try:
                ts = float(row[STIME])
                dur = max(float(row[DUR] or 0.0), 0.0)
                sbytes = max(int(float(row[SBYTES] or 0)), 0)
                dbytes = max(int(float(row[DBYTES] or 0)), 0)
                spkts = max(int(float(row[SPKTS] or 0)), 0)
                dpkts = max(int(float(row[DPKTS] or 0)), 0)
                dsport = int(float(row[DSPORT]), )
                sport = int(float(row[SPORT]))
            except (ValueError, TypeError):
                skipped["unparseable"] += 1
                continue
            if not (0 <= dsport <= 65535 and 0 <= sport <= 65535):
                skipped["bad_port"] += 1
                continue

            state = (row[STATE] or "").strip()
            proto = (row[PROTO] or "tcp").strip().lower()
            service = (row[SERVICE] or "").strip()
            service = None if service in ("", "-") else service
            uid = f"U{i}"
            records.append({
                "flow_id": f"{row[SRCIP]}:{row[DSTIP]}:{dsport}:{proto}:{ts}",
                "uid": uid,
                "timestamp": ts,
                "src_ip": row[SRCIP],
                "src_port": sport,
                "dst_ip": row[DSTIP],
                "dst_port": dsport,
                "proto": proto,
                "service": service,
                "duration": dur,
                "orig_bytes": sbytes,
                "resp_bytes": dbytes,
                "orig_pkts": spkts,
                "resp_pkts": dpkts,
                "byte_ratio": (dbytes / sbytes) if sbytes else 0.0,
                "pkt_ratio": (dpkts / spkts) if spkts else 0.0,
                # Carried as the RAW Zeek spelling, not ingestion's integer
                # encoding: that encoding has no code for S0, so round-tripping
                # through it would destroy the one state this measurement is
                # about. The adapter reads a raw `conn_state` in preference to
                # `conn_state_encoded`, so this is the honest field to fill.
                "conn_state": UNSW_STATE_TO_ZEEK.get(state, "OTH") if state else None,
            })
            truth.append({
                "uid": uid, "timestamp": ts,
                "src_ip": row[SRCIP], "dst_ip": row[DSTIP],
                "label": name,
                "threat_class": CATEGORY_TO_CLASS.get(name),
                "in_scope": name in CATEGORY_TO_CLASS,
                "out_of_scope": name in OUT_OF_SCOPE,
                "benign": not label_is_attack,
                "unsw_state": state,
                "conn_state": UNSW_STATE_TO_ZEEK.get(state, "OTH") if state else None,
            })
            cats[name] += 1
            if limit and len(records) >= limit:
                break

    order = sorted(range(len(records)), key=lambda k: records[k]["timestamp"])
    records = [records[k] for k in order]
    truth = [truth[k] for k in order]

    manifest = {
        "source": f"UNSW-NB15 ({path.name}, Zenodo record 10140548)",
        "kind": "real_capture_flow_level",
        "flows": len(records),
        "label_counts": dict(cats),
        "skipped": dict(skipped),
        "label_to_threat_class": CATEGORY_TO_CLASS,
        "out_of_scope_labels": sorted(OUT_OF_SCOPE),
        "caveats": [
            "Not produced by the ingestion pipeline; mapped from the published flow CSVs.",
            "No dns/tls/http block: dga_domain, dns_tunnelling and encrypted_malware "
            "cannot fire and must not be scored on this data.",
            "Timestamps are epoch SECONDS (Stime) - full second resolution throughout.",
            "Attack traffic is tool-generated (IXIA PerfectStorm) on a real network, "
            "not malware captured in the wild.",
            "conn_state is UNSW's own 'state' column translated to Zeek spellings "
            "by UNSW_STATE_TO_ZEEK - a stand-in for the field ingestion does not "
            "emit, not Zeek output.",
        ],
        "unsw_state_to_zeek": UNSW_STATE_TO_ZEEK,
        "ground_truth": truth,
    }
    return records, manifest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("csv", help="UNSW-NB15_N.csv (no header row)")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("-m", "--manifest", default=None)
    ap.add_argument("--labels", default=None,
                    help="comma-separated attack_cat values to keep (plus BENIGN)")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    keep = set(x.strip() for x in args.labels.split(",")) if args.labels else None
    records, manifest = convert(Path(args.csv), limit=args.limit, keep=keep)
    if not records:
        print("no records matched", file=sys.stderr)
        return 1

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    man = Path(args.manifest) if args.manifest else out.with_suffix(".labels.json")
    man.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    span = (records[-1]["timestamp"] - records[0]["timestamp"]) / 3600.0
    print(f"[+] {len(records)} flows -> {out}", file=sys.stderr)
    print(f"[+] ground truth      -> {man}", file=sys.stderr)
    print(f"    span {span:.2f} h   labels: "
          f"{dict(sorted(manifest['label_counts'].items(), key=lambda kv: -kv[1]))}",
          file=sys.stderr)
    if manifest["skipped"]:
        print(f"    skipped: {manifest['skipped']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
