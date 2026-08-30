"""Part B: how fast does the detection layer actually process flows?

Three separate measurements, kept separate on purpose:

* :func:`benchmark_detectors` - **MODE 1**, engine and detectors only. Flows
  are already ``FlowEvent`` objects in memory, so nothing but detection is
  inside the timer.
* :func:`benchmark_jsonl` - **MODE 2**, JSONL through the real adapter into
  the engine, into a sink that only counts. The difference between the two is
  the parsing and validation cost.
* :func:`sample_latency` - per-flow timings for percentiles. **A separate
  run**, because timing every individual call adds two ``perf_counter_ns``
  calls per flow to a loop whose body is measured in microseconds. Mixing it
  into the throughput number would tax the very thing being measured, so the
  two are never taken from the same run.

**No network is ever inside a timed section.** HTTP delivery is not measured
here at all; if it is ever benchmarked it belongs in its own number, because
one slow POST would dominate everything above.

**What is excluded from every timed section**: workload generation, JSONL
writing, detector construction, model loading, imports, and report
formatting. A warm-up may be run first, on throwaway detectors, so
first-call overhead is not attributed to the workload.

Numbers produced here are *benchmark throughput on the stated workload and
environment*, recorded in :func:`environment`. They are not a production
capacity figure: real traffic has different key cardinality, different window
occupancy, and arrives at its own rate rather than as fast as a loop can push
it.
"""

from __future__ import annotations

import platform
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from ..adapters import IngestionJsonlAdapter
from ..engine import DetectionEngine, Detector
from ..pipeline import build_default_detectors
from ..schemas import FlowEvent
from .workloads import SYNTHETIC

__all__ = [
    "BenchmarkResult",
    "LatencyResult",
    "benchmark_detectors",
    "benchmark_jsonl",
    "environment",
    "sample_latency",
]

DetectorFactory = Callable[[], list[Detector]]


def environment() -> dict[str, Any]:
    """What the numbers were measured on. No network, no shelling out."""
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "cpu_count": __import__("os").cpu_count(),
        # perf_counter is monotonic; its resolution bounds what any single
        # per-flow timing below can mean.
        "perf_counter_resolution_ns": time.get_clock_info("perf_counter").resolution
        * 1e9,
        "max_recursion": sys.getrecursionlimit(),
    }


@dataclass(frozen=True)
class BenchmarkResult:
    """One throughput run."""

    mode: str
    workload: str
    data_source_type: str
    flows_processed: int
    alerts_emitted: int
    elapsed_seconds: float
    detector_errors: int = 0
    detectors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def flows_per_second(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return self.flows_processed / self.elapsed_seconds

    @property
    def mean_seconds_per_flow(self) -> float:
        if self.flows_processed == 0:
            return 0.0
        return self.elapsed_seconds / self.flows_processed

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "workload": self.workload,
            "data_source_type": self.data_source_type,
            "flows_processed": self.flows_processed,
            "alerts_emitted": self.alerts_emitted,
            "elapsed_seconds": self.elapsed_seconds,
            "flows_per_second": self.flows_per_second,
            "mean_seconds_per_flow": self.mean_seconds_per_flow,
            "mean_microseconds_per_flow": self.mean_seconds_per_flow * 1e6,
            "detector_errors": self.detector_errors,
            "detectors": list(self.detectors),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class LatencyResult:
    """Per-flow processing latency, sampled in its own run."""

    mode: str
    workload: str
    data_source_type: str
    samples: int
    alerts_emitted: int
    mean_ns: float
    p50_ns: float
    p95_ns: float
    p99_ns: float
    max_ns: float
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "workload": self.workload,
            "data_source_type": self.data_source_type,
            "samples": self.samples,
            "alerts_emitted": self.alerts_emitted,
            "mean_ns": self.mean_ns,
            "p50_ns": self.p50_ns,
            "p95_ns": self.p95_ns,
            "p99_ns": self.p99_ns,
            "max_ns": self.max_ns,
            "mean_microseconds": self.mean_ns / 1000,
            "p50_microseconds": self.p50_ns / 1000,
            "p95_microseconds": self.p95_ns / 1000,
            "p99_microseconds": self.p99_ns / 1000,
            "notes": list(self.notes),
        }


def percentile(sorted_values: list[float], fraction: float) -> float:
    """Nearest-rank percentile of an already-sorted list.

    Nearest-rank rather than interpolated: every reported value is a
    measurement that actually happened, which is the honest thing to publish
    for a latency figure.
    """
    if not sorted_values:
        raise ValueError("cannot take a percentile of an empty sample")
    if not 0.0 < fraction <= 1.0:
        raise ValueError("fraction must be within (0.0, 1.0]")
    rank = max(1, min(len(sorted_values), int(-(-fraction * len(sorted_values) // 1))))
    return sorted_values[rank - 1]


def _warm_up(factory: DetectorFactory, flows: list[FlowEvent], count: int) -> None:
    """Run a slice through throwaway detectors, outside any timer."""
    if count <= 0 or not flows:
        return
    engine = DetectionEngine(factory())
    for alert in engine.run(flows[:count]):
        pass


def benchmark_detectors(
    flows: list[FlowEvent],
    *,
    workload: str = "benign",
    data_source_type: str = SYNTHETIC,
    detector_factory: DetectorFactory = build_default_detectors,
    warmup: int = 0,
) -> BenchmarkResult:
    """MODE 1: engine + detectors only, on flows already in memory.

    ``flows`` must be a materialized list. Passing a generator would put its
    own cost inside the timer and quietly measure the workload instead of
    the detectors.
    """
    if not isinstance(flows, list):
        raise TypeError(
            "pass a materialized list: a lazy source would be generated inside "
            "the timed section and measured as detection cost"
        )
    _warm_up(detector_factory, flows, warmup)

    engine = DetectionEngine(detector_factory())
    alerts = 0

    # --- timed section: detection only, nothing else -----------------------
    started = time.perf_counter()
    for _alert in engine.run(flows):
        alerts += 1
    elapsed = time.perf_counter() - started
    # --- end timed section -------------------------------------------------

    return BenchmarkResult(
        mode="detectors_only",
        workload=workload,
        data_source_type=data_source_type,
        flows_processed=engine.stats.flows_processed,
        alerts_emitted=alerts,
        elapsed_seconds=elapsed,
        detector_errors=engine.stats.detector_errors,
        detectors=[d.name for d in engine.detectors],
        notes=[
            "timed: DetectionEngine.run over in-memory FlowEvents",
            "excluded: workload generation, detector construction, reporting",
            "no i/o and no network inside the timed section",
        ],
    )


def benchmark_jsonl(
    path: str | Path,
    *,
    workload: str = "benign",
    data_source_type: str = SYNTHETIC,
    detector_factory: DetectorFactory = build_default_detectors,
) -> BenchmarkResult:
    """MODE 2: JSONL -> adapter -> engine -> counting sink.

    The sink only increments a counter, so the difference against MODE 1 is
    parsing, validation and file reading - not alert delivery. Writing the
    file is the caller's job and is not timed.
    """
    path = Path(path)
    adapter = IngestionJsonlAdapter(path=path)
    engine = DetectionEngine(detector_factory())
    alerts = 0

    # --- timed section: read + parse + validate + detect --------------------
    started = time.perf_counter()
    for _alert in engine.run(adapter):
        alerts += 1
    elapsed = time.perf_counter() - started
    # --- end timed section --------------------------------------------------

    notes = [
        "timed: IngestionJsonlAdapter -> DetectionEngine, counting sink only",
        "excluded: writing the JSONL, detector construction, reporting",
        "no network inside the timed section",
    ]
    if adapter.stats.skipped:
        notes.append(f"{adapter.stats.skipped} record(s) skipped as unparseable")

    return BenchmarkResult(
        mode="jsonl_pipeline",
        workload=workload,
        data_source_type=data_source_type,
        flows_processed=engine.stats.flows_processed,
        alerts_emitted=alerts,
        elapsed_seconds=elapsed,
        detector_errors=engine.stats.detector_errors,
        detectors=[d.name for d in engine.detectors],
        notes=notes,
    )


def sample_latency(
    flows: list[FlowEvent],
    *,
    workload: str = "benign",
    data_source_type: str = SYNTHETIC,
    detector_factory: DetectorFactory = build_default_detectors,
    warmup: int = 0,
) -> LatencyResult:
    """Per-flow latency percentiles, measured in a run of their own.

    Each sample is one ``DetectionEngine.process`` call: every detector's
    verdict on one flow, including any alert it builds. The two
    ``perf_counter_ns`` calls per flow are real overhead, which is exactly
    why this does not double as the throughput number - see the module
    docstring.

    Percentiles are nearest-rank over the sorted samples, so p50 <= p95 <=
    p99 holds by construction.
    """
    if not isinstance(flows, list):
        raise TypeError("pass a materialized list; see benchmark_detectors")
    if not flows:
        raise ValueError("cannot sample latency with no flows")
    _warm_up(detector_factory, flows, warmup)

    engine = DetectionEngine(detector_factory())
    durations: list[float] = []
    alerts = 0

    for flow in flows:
        started = time.perf_counter_ns()
        produced = engine.process(flow)
        durations.append(time.perf_counter_ns() - started)
        alerts += len(produced)

    durations.sort()
    return LatencyResult(
        mode="latency_sampling",
        workload=workload,
        data_source_type=data_source_type,
        samples=len(durations),
        alerts_emitted=alerts,
        mean_ns=statistics.fmean(durations),
        p50_ns=percentile(durations, 0.50),
        p95_ns=percentile(durations, 0.95),
        p99_ns=percentile(durations, 0.99),
        max_ns=durations[-1],
        notes=[
            "separate run: per-flow timing adds overhead and must not be "
            "reported as throughput",
            "one sample = DetectionEngine.process for one flow, all detectors",
            f"clock resolution: {time.get_clock_info('perf_counter').resolution * 1e9:.0f}ns",
        ],
    )
