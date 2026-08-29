"""Part C: where does detection actually spend its time?

Diagnosis only. Nothing here changes a detector, a window or a threshold -
it builds the ordinary detectors through the ordinary factory and watches
them work.

The specific question this exists to answer: ``ActivityWindow`` derives its
counts by scanning the deque on every call (``dst_ports()``, ``src_ips()``,
``hosts_by_port()``, ``total_orig_packets()`` ...), so each flow costs O(N) in
the window's current occupancy. That is a real complexity claim, and it is
cheap to *assume* it matters. This module measures whether it does, before
anyone rewrites a correct data structure on the strength of a hunch.

``cProfile`` and ``pstats`` are standard library - no profiling dependency is
added. Profiling inflates absolute times substantially, so the numbers here
are for *ranking* hot paths against each other, never for quoting as
throughput; :mod:`.benchmark` is the place for that.
"""

from __future__ import annotations

import cProfile
import pstats
from dataclasses import dataclass, field
from typing import Any, Callable

from ..engine import DetectionEngine, Detector
from ..pipeline import build_default_detectors
from ..schemas import FlowEvent

__all__ = ["ProfileEntry", "ProfileReport", "profile_detectors"]

DetectorFactory = Callable[[], list[Detector]]


@dataclass(frozen=True)
class ProfileEntry:
    """One function's share of a profiled run."""

    function: str
    calls: int
    total_seconds: float
    cumulative_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "calls": self.calls,
            "total_seconds": self.total_seconds,
            "cumulative_seconds": self.cumulative_seconds,
        }


@dataclass(frozen=True)
class ProfileReport:
    """A ranked view of where a profiled run spent its time."""

    workload: str
    flows_processed: int
    alerts_emitted: int
    profiled_seconds: float
    by_cumulative: list[ProfileEntry] = field(default_factory=list)
    by_total: list[ProfileEntry] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workload": self.workload,
            "flows_processed": self.flows_processed,
            "alerts_emitted": self.alerts_emitted,
            "profiled_seconds": self.profiled_seconds,
            "by_cumulative": [entry.to_dict() for entry in self.by_cumulative],
            "by_total": [entry.to_dict() for entry in self.by_total],
            "notes": list(self.notes),
        }


def _entries(stats: pstats.Stats, key: int, limit: int) -> list[ProfileEntry]:
    """Top ``limit`` functions by ``key`` (2 = tottime, 3 = cumtime).

    Read from ``Stats.stats`` directly rather than parsing printed output,
    so the numbers are the profiler's own and not a scrape of a text table.
    """
    rows = []
    for (filename, line, name), values in stats.stats.items():  # type: ignore[attr-defined]
        _calls, primitive_calls, total_time, cumulative_time = values[:4]
        short = filename.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        rows.append(
            (
                values[key],
                ProfileEntry(
                    function=f"{short}:{line}({name})",
                    calls=primitive_calls,
                    total_seconds=total_time,
                    cumulative_seconds=cumulative_time,
                ),
            )
        )
    rows.sort(key=lambda row: row[0], reverse=True)
    return [entry for _value, entry in rows[:limit]]


def profile_detectors(
    flows: list[FlowEvent],
    *,
    workload: str = "benign",
    detector_factory: DetectorFactory = build_default_detectors,
    top: int = 15,
) -> ProfileReport:
    """Profile one engine run and return the hot paths, ranked.

    Detector construction happens outside the profiler, so the report
    describes processing rather than start-up. Detectors are built by the
    supplied factory with their shipped configuration - this function never
    passes a config of its own, so a profiled run is the same run the runner
    would do.
    """
    if not isinstance(flows, list):
        raise TypeError("pass a materialized list so generation is not profiled")

    engine = DetectionEngine(detector_factory())
    alerts = 0

    profiler = cProfile.Profile()
    profiler.enable()
    for _alert in engine.run(flows):
        alerts += 1
    profiler.disable()

    stats = pstats.Stats(profiler)
    return ProfileReport(
        workload=workload,
        flows_processed=engine.stats.flows_processed,
        alerts_emitted=alerts,
        profiled_seconds=stats.total_tt,
        by_cumulative=_entries(stats, 3, top),
        by_total=_entries(stats, 2, top),
        notes=[
            "cProfile inflates absolute time; use these to rank hot paths, "
            "not to quote throughput",
            "detector construction and workload generation are outside the "
            "profiled section",
            "detectors use their shipped configuration - nothing is tuned here",
        ],
    )
