"""Offline evaluation and benchmarking for the detection layer.

Three questions, three modules:

* :mod:`.benign` - how much does each detector say on traffic believed benign?
* :mod:`.benchmark` - how fast does detection process flows?
* :mod:`.profiling` - where does that time actually go?

Measurement only. Everything here builds detectors through the ordinary
:func:`~detection_core.pipeline.build_default_detectors` factory and drives
them through the ordinary :class:`~detection_core.engine.DetectionEngine`, so
it reports on the detection layer without being a second copy of it. No
threshold, config or detector implementation is touched.

Importing this package costs nothing beyond the core: scikit-learn is pulled
in only if a caller explicitly supplies a DGA model.
"""

from __future__ import annotations

from .benchmark import (
    BenchmarkResult,
    LatencyResult,
    benchmark_detectors,
    benchmark_jsonl,
    environment,
    percentile,
    sample_latency,
)
from .benign import (
    BenignEvaluation,
    DetectorBenignStats,
    evaluate_benign,
    evaluate_benign_jsonl,
)
from .profiling import ProfileEntry, ProfileReport, profile_detectors
from .workloads import REAL, SYNTHETIC, benign_flows, mixed_flows, write_jsonl

__all__ = [
    "REAL",
    "SYNTHETIC",
    "BenchmarkResult",
    "BenignEvaluation",
    "DetectorBenignStats",
    "LatencyResult",
    "ProfileEntry",
    "ProfileReport",
    "benchmark_detectors",
    "benchmark_jsonl",
    "benign_flows",
    "environment",
    "evaluate_benign",
    "evaluate_benign_jsonl",
    "mixed_flows",
    "percentile",
    "profile_detectors",
    "sample_latency",
    "write_jsonl",
]
