"""One evaluation CLI, three modes.

    python -m detection_core.evaluation benign --input ../injestion_core/features.jsonl
    python -m detection_core.evaluation benign --synthetic 10000
    python -m detection_core.evaluation throughput --flows 10000 --jsonl --latency
    python -m detection_core.evaluation profile --flows 20000

Reporting only. This does not replace ``detection_core.runner``, does not
deliver alerts anywhere, and changes no detector setting. ``--json`` prints a
machine-readable report for reproducibility; everything else goes to stdout
as plain text.

Every report states whether its input was ``real`` or ``synthetic``, because
a number from generated traffic answers a different question from a number
from a capture.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from .benchmark import (
    benchmark_detectors,
    benchmark_jsonl,
    environment,
    sample_latency,
)
from .benign import evaluate_benign, evaluate_benign_jsonl
from .profiling import profile_detectors
from .workloads import REAL, SYNTHETIC, benign_flows, mixed_flows, write_jsonl


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m detection_core.evaluation",
        description=(
            "Offline evaluation of the detection layer: benign-traffic noise, "
            "throughput/latency, and profiling. Measurement only - no detector "
            "setting is changed and no alert is delivered."
        ),
    )
    parser.add_argument("--json", action="store_true", help="print a JSON report")
    modes = parser.add_subparsers(dest="mode", required=True)

    benign = modes.add_parser(
        "benign", help="count alerts on traffic believed to be benign"
    )
    source = benign.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path, help="ingestion JSONL (labelled real)")
    source.add_argument(
        "--synthetic",
        type=int,
        metavar="N",
        help="N generated benign flows (labelled synthetic)",
    )
    benign.add_argument(
        "--dga-model",
        type=Path,
        default=None,
        help="include dga_domain using this bundle; omitted means six detectors",
    )

    throughput = modes.add_parser("throughput", help="flows/second and latency")
    throughput.add_argument("--flows", type=int, default=10_000)
    throughput.add_argument(
        "--workload",
        choices=("benign", "mixed"),
        default="benign",
        help="mixed folds in periodic scan bursts so the alert path is exercised",
    )
    throughput.add_argument("--warmup", type=int, default=200)
    throughput.add_argument(
        "--jsonl", action="store_true", help="also benchmark the adapter path"
    )
    throughput.add_argument(
        "--latency",
        action="store_true",
        help="also sample per-flow latency, in a separate run",
    )

    profile = modes.add_parser("profile", help="rank the hot paths")
    profile.add_argument("--flows", type=int, default=20_000)
    profile.add_argument(
        "--workload", choices=("benign", "mixed"), default="benign"
    )
    profile.add_argument("--top", type=int, default=15)
    return parser


def _workload(name: str, count: int):
    return mixed_flows(count) if name == "mixed" else benign_flows(count)


def _run_benign(args: argparse.Namespace) -> dict[str, Any]:
    if args.input is not None:
        evaluation = evaluate_benign_jsonl(
            args.input, data_source_type=REAL, dga_model_path=args.dga_model
        )
    else:
        evaluation = evaluate_benign(
            benign_flows(args.synthetic),
            input_label=f"workloads.benign_flows({args.synthetic})",
            data_source_type=SYNTHETIC,
            dga_model_path=args.dga_model,
            notes=[
                "synthetic traffic: evidence about the generator, not a "
                "real-world false-positive rate"
            ],
        )
    return evaluation.to_dict()


def _run_throughput(args: argparse.Namespace) -> dict[str, Any]:
    flows = _workload(args.workload, args.flows)
    source_type = SYNTHETIC
    report: dict[str, Any] = {
        "environment": environment(),
        "detectors_only": benchmark_detectors(
            flows,
            workload=args.workload,
            data_source_type=source_type,
            warmup=args.warmup,
        ).to_dict(),
    }

    if args.jsonl:
        # Written to a temporary directory and removed: a benchmark must not
        # leave a generated dataset behind in the repository.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workload.jsonl"
            write_jsonl(flows, path)
            report["jsonl_pipeline"] = benchmark_jsonl(
                path, workload=args.workload, data_source_type=source_type
            ).to_dict()

    if args.latency:
        report["latency"] = sample_latency(
            flows,
            workload=args.workload,
            data_source_type=source_type,
            warmup=args.warmup,
        ).to_dict()
    return report


def _run_profile(args: argparse.Namespace) -> dict[str, Any]:
    report = profile_detectors(
        _workload(args.workload, args.flows),
        workload=args.workload,
        top=args.top,
    )
    return {"environment": environment(), "profile": report.to_dict()}


def _print_benign(report: dict[str, Any]) -> None:
    print("BENIGN EVALUATION")
    print(f"  input             : {report['input_label']}")
    print(f"  data source       : {report['data_source_type'].upper()}")
    print(f"  detectors         : {', '.join(report['detectors'])}")
    print(f"  flows processed   : {report['total_flows']}")
    print(f"  alerts emitted    : {report['total_alerts']}")
    print(f"  alerts / 1k flows : {report['alerts_per_1000_flows']:.4f}")
    print("  per detector      :")
    for name, stats in report["by_detector"].items():
        print(
            f"    {name:<20} {stats['alerts_emitted']:>6} alert(s)"
            f"   {stats['alerts_per_1000_flows']:.4f} / 1k flows"
        )
    for note in report["notes"]:
        print(f"  NOTE: {note}")


def _print_benchmark(title: str, result: dict[str, Any]) -> None:
    print(title)
    print(f"  workload          : {result['workload']} ({result['data_source_type']})")
    print(f"  flows processed   : {result['flows_processed']}")
    print(f"  alerts emitted    : {result['alerts_emitted']}")
    print(f"  elapsed           : {result['elapsed_seconds']:.4f}s")
    print(f"  throughput        : {result['flows_per_second']:,.0f} flows/s")
    print(f"  mean per flow     : {result['mean_microseconds_per_flow']:.2f}us")


def _print_throughput(report: dict[str, Any]) -> None:
    _print_benchmark("THROUGHPUT - MODE 1 (detectors only)", report["detectors_only"])
    if "jsonl_pipeline" in report:
        _print_benchmark(
            "THROUGHPUT - MODE 2 (jsonl -> adapter -> detectors)",
            report["jsonl_pipeline"],
        )
    if "latency" in report:
        latency = report["latency"]
        print("LATENCY (separate run - per-flow timing adds overhead)")
        print(f"  samples           : {latency['samples']}")
        print(f"  mean              : {latency['mean_microseconds']:.2f}us")
        print(f"  p50               : {latency['p50_microseconds']:.2f}us")
        print(f"  p95               : {latency['p95_microseconds']:.2f}us")
        print(f"  p99               : {latency['p99_microseconds']:.2f}us")
    print("NOTE: benchmark throughput on this workload and machine, not a "
          "production capacity figure.")


def _print_profile(report: dict[str, Any]) -> None:
    profile = report["profile"]
    print("PROFILE (cProfile inflates absolute time; ranking only)")
    print(f"  workload          : {profile['workload']}")
    print(f"  flows processed   : {profile['flows_processed']}")
    print(f"  profiled seconds  : {profile['profiled_seconds']:.4f}")
    print("  top by cumulative time:")
    for entry in profile["by_cumulative"]:
        print(
            f"    {entry['cumulative_seconds']:8.4f}s  {entry['calls']:>10} calls  "
            f"{entry['function']}"
        )
    print("  top by self time:")
    for entry in profile["by_total"]:
        print(
            f"    {entry['total_seconds']:8.4f}s  {entry['calls']:>10} calls  "
            f"{entry['function']}"
        )


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        if args.mode == "benign":
            report = _run_benign(args)
            printer = _print_benign
        elif args.mode == "throughput":
            report = _run_throughput(args)
            printer = _print_throughput
        else:
            report = _run_profile(args)
            printer = _print_profile
    except (OSError, ValueError, RuntimeError, TypeError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        printer(report)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
