#!/usr/bin/env python3
"""Per-detector behaviour matrix: every detector against every traffic type.

    python tools/detector_matrix.py --dga-model artifacts/dga_model.joblib \
        --ja3-feed tools/ja3_feed.example.txt --seeds 10 -o data/detector_matrix.json

Why this exists
---------------
``tools/evaluate.py`` scores a whole *run*: all seven detectors over one mixed
capture, alerts attributed to manifest intervals. That answers "did the system
find the attacks", which is the demo question.

It does not answer the question a reviewer actually asks about an ML/heuristic
detector: **what does this detector do when it is shown something that is not
its attack?** A detector that fires on everything scores perfect recall in a
mixed capture and is useless. So this harness runs each detector *alone*
against each traffic type *alone*:

    for detector D, for traffic slice S:  fresh engine([D]).run(S) -> alerts

with three kinds of slice per detector:

    (a) its target attack        -> a fire is a TRUE POSITIVE
    (b) benign / confounders     -> a fire is a FALSE POSITIVE
    (c) the other six attacks    -> a fire is CROSS-CONTAMINATION (also an FP)

The slices come from ``tools/synth_flows.py`` and are labelled *by
construction* - this module replays ``synth_flows.generate``'s exact sequence
of RNG calls and keeps each producer's output separately, so the concatenated
slices are byte-identical to the capture ``synth_flows`` writes. That identity
is asserted at startup (``--verify-against``), because a labelling harness that
has silently drifted from the generator is worse than no harness.

Trials are repeated over N seeds so each cell has a denominator larger than one.

HONEST DENOMINATOR
------------------
Every number this produces is measured on SYNTHETIC traffic. It characterises
detector *behaviour and separation* - does it fire on its target, does it stay
quiet on the confounders built to fool it. It is NOT a production false
positive rate: a real network's benign traffic is far more varied than four
confounders, and no synthetic generator can stand in for it. Report these as
what they are.
"""
from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "detection"))

import synth_flows as sf  # noqa: E402

from detection_core.adapters import record_to_flow_event  # noqa: E402
from detection_core.config import DetectorSettings, load_detector_settings  # noqa: E402
from detection_core.detectors import (  # noqa: E402
    C2BeaconingDetector,
    DataExfiltrationDetector,
    DDoSDetector,
    DGADetector,
    DnsTunnellingDetector,
    EncryptedMalwareDetector,
    PortScanDetector,
)
from detection_core.engine import DetectionEngine  # noqa: E402
from detection_core.fingerprints import load_fingerprint_feed  # noqa: E402

THREAT_CLASSES = [
    "port_scan",
    "ddos",
    "c2_beaconing",
    "dns_tunnelling",
    "dga_domain",
    "encrypted_malware",
    "data_exfiltration",
]

#: slice key -> (ground-truth class or None for benign, human description)
SLICES: dict[str, tuple[str | None, str]] = {
    "benign_web": (None, "ordinary browsing (DNS + TLS), 13 hosts"),
    "conf_ntp": (None, "CONFOUNDER: NTP time daemon, 64s period ~ looks like a beacon"),
    "conf_backup": (None, "CONFOUNDER: nightly cloud backup, ~99% outbound ~ looks like exfil"),
    "conf_cdn": (None, "CONFOUNDER: long high-entropy CDN hostnames ~ look like DGA"),
    "conf_authorised_scan": (None, "CONFOUNDER: authorised inventory sweep ~ looks like recon"),
    "attack_intrusion_recon": ("port_scan", "compromised host recon, 18 ports x 3 hosts, S0"),
    "attack_port_scan": ("port_scan", "vertical scan, 40 ports, all S0"),
    "attack_ddos": ("ddos", "spoofed SYN flood, 320 sources in ~6s"),
    "attack_beacon": ("c2_beaconing", "C2 check-in every 45s, 6% jitter"),
    "attack_dga": ("dga_domain", "30 generated domains, 90% NXDOMAIN"),
    "attack_dns_tunnel": ("dns_tunnelling", "60 unique 48-char TXT subdomains"),
    "attack_encrypted_malware": ("encrypted_malware", "malware JA3 + high-entropy SNI on obsolete TLS"),
    "attack_exfiltration": ("data_exfiltration", "16 bulk uploads to a novel destination"),
}


# --------------------------------------------------------------------------
# Slicing: replay generate()'s RNG sequence, keep each producer separate
# --------------------------------------------------------------------------


def sliced_capture(
    *, seed: int, duration: float, base_time: float
) -> dict[str, list[dict]]:
    """The same capture ``synth_flows.generate`` produces, kept per producer.

    The order of calls below is the order in ``generate``; a single
    ``random.Random`` is threaded through all of them, so every draw lands in
    the same place and the concatenation reproduces the capture exactly.
    """
    rng = random.Random(seed)
    base = base_time
    out: dict[str, list[dict]] = {}

    out["benign_web"] = list(sf.benign_web(base, duration, rng))
    out["conf_ntp"] = list(sf.confounder_ntp(base, duration, rng))
    out["conf_backup"] = list(sf.confounder_backup(base, duration, rng))
    out["conf_cdn"] = list(sf.confounder_cdn(base, duration, rng))
    out["conf_authorised_scan"] = list(sf.confounder_authorised_scan(base, duration, rng))

    out["attack_intrusion_recon"] = sf.attack_intrusion_recon(base, rng)[0]
    out["attack_port_scan"] = sf.attack_port_scan(base, rng)[0]
    out["attack_ddos"] = sf.attack_ddos(base, rng)[0]
    out["attack_beacon"] = sf.attack_beacon(base, duration, rng)[0]
    out["attack_dga"] = sf.attack_dga(base, rng)[0]
    out["attack_dns_tunnel"] = sf.attack_dns_tunnel(base, rng)[0]
    out["attack_encrypted_malware"] = sf.attack_encrypted_malware(base, rng)[0]
    out["attack_exfiltration"] = sf.attack_exfiltration(base, rng)[0]

    assert set(out) == set(SLICES), "slice table and producer list disagree"
    return out


def verify_identical(slices: dict[str, list[dict]], capture: Path) -> tuple[bool, str]:
    """Assert the slices really are the committed capture, re-partitioned."""
    mine = sorted(
        (r for records in slices.values() for r in records),
        key=lambda r: r["timestamp"],
    )
    theirs = [json.loads(line) for line in capture.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(mine) != len(theirs):
        return False, f"flow count {len(mine)} != {len(theirs)}"
    for i, (a, b) in enumerate(zip(mine, theirs)):
        if a != b:
            return False, f"flow {i} differs (flow_id {a.get('flow_id')} vs {b.get('flow_id')})"
    return True, f"{len(mine)} flows identical to {capture.name}"


# --------------------------------------------------------------------------
# Detector construction - one at a time, each with its shipped defaults
# --------------------------------------------------------------------------


def detector_factories(
    *, dga_model_path: Path | None, ja3_feed: Path | None, config: Path | None = None
) -> dict[str, Callable[[], Any]]:
    # ``config`` is the same TOML the runner takes via --config, so a threshold
    # measured here is a threshold the runner can actually be given. Only the
    # values the file names are overridden; everything else keeps its default.
    settings = load_detector_settings(config) if config else DetectorSettings()
    if ja3_feed:
        settings = settings.with_fingerprints(load_fingerprint_feed(ja3_feed))


    factories: dict[str, Callable[[], Any]] = {
        "port_scan": lambda: PortScanDetector(settings.port_scan),
        "ddos": lambda: DDoSDetector(settings.ddos),
        "c2_beaconing": lambda: C2BeaconingDetector(settings.c2_beaconing),
        "dns_tunnelling": lambda: DnsTunnellingDetector(settings.dns_tunnelling),
        "data_exfiltration": lambda: DataExfiltrationDetector(settings.data_exfiltration),
        "encrypted_malware": lambda: EncryptedMalwareDetector(settings.encrypted_malware),
    }
    if dga_model_path is not None:
        # Load once; DGADetector accepts a preloaded bundle, so 130 trials do
        # not each pay a 12 MB joblib read.
        from detection_core.ml.dga.model import DGAModel

        model = DGAModel.load(dga_model_path)
        factories["dga_domain"] = lambda: DGADetector(model=model, config=settings.dga_domain)
    return factories


def run_trial(detector_factory: Callable[[], Any], records: Iterable[dict]) -> list[Any]:
    """One detector, alone, over one slice. Returns its alerts."""
    engine = DetectionEngine([detector_factory()])
    flows = [record_to_flow_event(r) for r in sorted(records, key=lambda r: r["timestamp"])]
    return list(engine.run(flows))


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------


def _rate(num: int, den: int) -> float | None:
    return num / den if den else None


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or (precision + recall) == 0:
        return None
    return 2 * precision * recall / (precision + recall)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dga-model", default=str(ROOT / "artifacts" / "dga_model.joblib"))
    ap.add_argument("--ja3-feed", default=str(ROOT / "tools" / "ja3_feed.example.txt"))
    ap.add_argument("--config", default=None,
                    help="detector-settings TOML, same file the runner takes via --config")
    ap.add_argument("--detectors", default=None,
                    help="comma-separated subset to run (default: all that can be built). "
                         "Only the named detectors are scored; useful when a change can "
                         "only affect one of them and the other six would just be re-run")
    ap.add_argument("--seeds", type=int, default=10, help="number of independent captures")
    ap.add_argument("--first-seed", type=int, default=26145)
    ap.add_argument("--duration", type=float, default=600.0)
    ap.add_argument("--base-time", type=float, default=None)
    ap.add_argument("--verify-against", default=None,
                    help="a features.jsonl the first seed's slices must reproduce exactly")
    ap.add_argument("-o", "--output", default=None, help="write the full result as JSON")
    args = ap.parse_args()

    logging.basicConfig(level=logging.ERROR, stream=sys.stderr)

    dga_path = Path(args.dga_model) if args.dga_model and Path(args.dga_model).is_file() else None
    ja3_path = Path(args.ja3_feed) if args.ja3_feed and Path(args.ja3_feed).is_file() else None
    if dga_path is None:
        print("!! no DGA model artifact - dga_domain will be absent from the matrix",
              file=sys.stderr)
    config_path = Path(args.config) if args.config else None
    factories = detector_factories(
        dga_model_path=dga_path, ja3_feed=ja3_path, config=config_path
    )
    detectors = [name for name in THREAT_CLASSES if name in factories]
    if args.detectors:
        wanted = [d.strip() for d in args.detectors.split(",") if d.strip()]
        unknown = [d for d in wanted if d not in factories]
        if unknown:
            print(f"!! not buildable here: {', '.join(unknown)}", file=sys.stderr)
            return 1
        detectors = [name for name in detectors if name in wanted]

    base_time = args.base_time if args.base_time is not None else time.time() - args.duration
    seeds = [args.first_seed + i for i in range(args.seeds)]

    # cell[(detector, slice)] = {"trials": n, "fired": n, "alerts": n}
    cells: dict[tuple[str, str], dict[str, int]] = {
        (d, s): {"trials": 0, "fired": 0, "alerts": 0} for d in detectors for s in SLICES
    }
    #: every alert class a detector emitted, to catch a detector labelling its
    #: alert as somebody else's threat class.
    emitted_classes: dict[str, dict[str, int]] = {d: {} for d in detectors}
    samples: dict[tuple[str, str], dict[str, Any]] = {}
    slice_flows: dict[str, int] = {}
    verification = None

    for seed_index, seed in enumerate(seeds):
        slices = sliced_capture(seed=seed, duration=args.duration, base_time=base_time)
        if seed_index == 0:
            for key, records in slices.items():
                slice_flows[key] = len(records)
            if args.verify_against:
                ok, detail = verify_identical(slices, Path(args.verify_against))
                verification = {"ok": ok, "detail": detail}
                print(f"[{'ok' if ok else 'FAIL'}] slice identity: {detail}", file=sys.stderr)
                if not ok:
                    return 1

        for detector_name in detectors:
            for slice_key, records in slices.items():
                alerts = run_trial(factories[detector_name], records)
                cell = cells[(detector_name, slice_key)]
                cell["trials"] += 1
                cell["alerts"] += len(alerts)
                if alerts:
                    cell["fired"] += 1
                for alert in alerts:
                    payload = alert.model_dump(mode="json") if hasattr(alert, "model_dump") else dict(alert)
                    klass = payload["threat_class"]
                    emitted_classes[detector_name][klass] = (
                        emitted_classes[detector_name].get(klass, 0) + 1
                    )
                    samples.setdefault((detector_name, slice_key), payload)
        print(f"    seed {seed} done ({seed_index + 1}/{len(seeds)})", file=sys.stderr)

    # ---- aggregate into a per-detector confusion matrix -------------------
    results: dict[str, Any] = {}
    for detector_name in detectors:
        target_slices = [k for k, (klass, _) in SLICES.items() if klass == detector_name]
        benign_slices = [k for k, (klass, _) in SLICES.items() if klass is None]
        other_slices = [
            k for k, (klass, _) in SLICES.items()
            if klass is not None and klass != detector_name
        ]

        tp = sum(cells[(detector_name, k)]["fired"] for k in target_slices)
        fn = sum(
            cells[(detector_name, k)]["trials"] - cells[(detector_name, k)]["fired"]
            for k in target_slices
        )
        fp_benign = sum(cells[(detector_name, k)]["fired"] for k in benign_slices)
        fp_cross = sum(cells[(detector_name, k)]["fired"] for k in other_slices)
        fp = fp_benign + fp_cross
        tn = sum(
            cells[(detector_name, k)]["trials"] - cells[(detector_name, k)]["fired"]
            for k in benign_slices + other_slices
        )

        precision = _rate(tp, tp + fp)
        recall = _rate(tp, tp + fn)
        results[detector_name] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "fp_on_benign": fp_benign,
            "fp_cross_attack": fp_cross,
            "precision": precision,
            "recall": recall,
            "f1": _f1(precision, recall),
            "target_slices": target_slices,
            "fired_on_benign": {
                k: cells[(detector_name, k)] for k in benign_slices
                if cells[(detector_name, k)]["fired"]
            },
            "fired_on_other_attacks": {
                k: cells[(detector_name, k)] for k in other_slices
                if cells[(detector_name, k)]["fired"]
            },
            "missed_target_slices": {
                k: cells[(detector_name, k)] for k in target_slices
                if cells[(detector_name, k)]["fired"] < cells[(detector_name, k)]["trials"]
            },
            "alert_classes_emitted": emitted_classes[detector_name],
            "per_slice": {
                k: cells[(detector_name, k)] for k in SLICES
            },
        }

    payload = {
        "kind": "synthetic_detector_behaviour_matrix",
        "honesty_note": (
            "Synthetic traffic only. These figures measure detector behaviour and "
            "separation against labelled generated flows, including four confounders "
            "built to imitate the threats. They are NOT a production false-positive "
            "rate and must not be quoted as one."
        ),
        "seeds": seeds,
        "duration_seconds": args.duration,
        "base_time": base_time,
        "dga_model": str(dga_path) if dga_path else None,
        "ja3_feed": str(ja3_path) if ja3_path else None,
        "config": str(config_path) if config_path else None,
        "slice_flows_first_seed": slice_flows,
        "slice_labels": {k: {"class": v[0], "note": v[1]} for k, v in SLICES.items()},
        "verification": verification,
        "detectors": results,
        "samples": {f"{d}|{s}": a for (d, s), a in samples.items()},
    }

    render(payload)
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\n[+] full matrix -> {out}", file=sys.stderr)
    return 0


def _fmt(value: float | None) -> str:
    return "   -  " if value is None else f"{value:6.3f}"


def render(payload: dict[str, Any]) -> None:
    n_seeds = len(payload["seeds"])
    print()
    print("PER-DETECTOR BEHAVIOUR MATRIX - each detector run ALONE on each traffic type")
    print("=" * 100)
    print(f"{n_seeds} independent captures (seeds {payload['seeds'][0]}-{payload['seeds'][-1]}), "
          f"{payload['duration_seconds']:.0f}s each. One trial = one detector over one slice.")
    print("SYNTHETIC TRAFFIC - measures behaviour/separation, NOT a production false-positive rate.")
    print()

    slice_keys = list(payload["slice_labels"])

    # Thirteen slices will not fit across a terminal, so the matrix is printed
    # transposed: one block per detector, one line per traffic type.
    for name, res in payload["detectors"].items():
        print(f"--- {name} " + "-" * (95 - len(name)))
        target = set(res["target_slices"])
        for key in slice_keys:
            cell = res["per_slice"][key]
            klass = payload["slice_labels"][key]["class"]
            if key in target:
                verdict = "TP" if cell["fired"] == cell["trials"] else ("PARTIAL/FN" if cell["fired"] else "FN (MISS)")
            elif cell["fired"] == 0:
                verdict = "ok (silent)"
            elif klass is None:
                verdict = "FP on benign"
            else:
                verdict = "FP cross-attack"
            bar = f"{cell['fired']}/{cell['trials']}"
            print(f"    {key:26s} {bar:>7s} runs fired  {cell['alerts']:5d} alerts   {verdict}")
        print()

    print("SUMMARY")
    print("=" * 100)
    print(f"{'detector':20s} {'TP':>4s} {'FP':>4s} {'FN':>4s} {'TN':>4s} "
          f"{'FP-benign':>10s} {'FP-cross':>9s} {'precision':>10s} {'recall':>8s} {'F1':>8s}")
    print("-" * 100)
    for name, res in payload["detectors"].items():
        print(f"{name:20s} {res['tp']:4d} {res['fp']:4d} {res['fn']:4d} {res['tn']:4d} "
              f"{res['fp_on_benign']:10d} {res['fp_cross_attack']:9d} "
              f"{_fmt(res['precision']):>10s} {_fmt(res['recall']):>8s} {_fmt(res['f1']):>8s}")
    print()
    print("TP/FN denominator = target-slice trials; FP/TN denominator = benign + other-attack trials.")
    print(payload["honesty_note"])


if __name__ == "__main__":
    raise SystemExit(main())
