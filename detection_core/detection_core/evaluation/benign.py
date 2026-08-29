"""Part A: how noisy is each detector on traffic believed to be benign?

The question this answers is "if I hand the detectors traffic nobody thinks
is an attack, how much do they say?" - per detector, so one noisy rule is
visible rather than averaged away.

**On the arithmetic.** The headline number is ``alerts_per_1000_flows``, not
a percentage, and that is deliberate. A "false-positive rate" implies one
independent binary decision per flow, which is not what these detectors do:
they are aggregate and windowed, one alert can summarize forty flows, and a
cooldown suppresses the next several. Alerts per thousand flows makes no such
claim - it is a rate of output against input, which is exactly what was
measured.

**On labelling.** Every result carries ``data_source_type``, either
:data:`~.workloads.REAL` or :data:`~.workloads.SYNTHETIC`. Synthetic results
describe the generator as much as the detectors, and must never be presented
as real-world false-positive validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..adapters import IngestionJsonlAdapter
from ..engine import DetectionEngine, Detector
from ..pipeline import build_default_detectors
from ..schemas import FlowEvent, ThreatClass
from .workloads import REAL, SYNTHETIC

__all__ = ["DetectorBenignStats", "BenignEvaluation", "evaluate_benign", "evaluate_benign_jsonl"]

#: Detector names double as threat-class values throughout this project, and
#: a test in the pipeline suite pins that. So a detector's class is known
#: even when it emitted nothing to read one off.
_THREAT_CLASSES = {threat.value for threat in ThreatClass}


@dataclass(frozen=True)
class DetectorBenignStats:
    """One detector's output on one benign capture."""

    detector: str
    #: ``None`` only if a detector's name is not a threat-class value.
    threat_class: str | None
    flows_processed: int
    alerts_emitted: int

    @property
    def alerts_per_1000_flows(self) -> float:
        """Output rate against input. 0.0 on an empty capture, not undefined."""
        if self.flows_processed == 0:
            return 0.0
        return self.alerts_emitted / self.flows_processed * 1000

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "threat_class": self.threat_class,
            "flows_processed": self.flows_processed,
            "alerts_emitted": self.alerts_emitted,
            "alerts_per_1000_flows": self.alerts_per_1000_flows,
        }


@dataclass(frozen=True)
class BenignEvaluation:
    """What every registered detector did on one capture believed benign."""

    #: What was fed in, in words - a path, a generator name, a capture id.
    input_label: str
    #: :data:`~.workloads.REAL` or :data:`~.workloads.SYNTHETIC`. Never mixed.
    data_source_type: str
    total_flows: int
    total_alerts: int
    detectors: list[str]
    by_detector: dict[str, DetectorBenignStats]
    by_threat_class: dict[str, int]
    detector_errors: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def alerts_per_1000_flows(self) -> float:
        if self.total_flows == 0:
            return 0.0
        return self.total_alerts / self.total_flows * 1000

    @property
    def false_positive_alerts(self) -> int:
        """Alias for :attr:`total_alerts`, valid only because the capture was
        *designated* benign by whoever supplied it. It is an assumption about
        the input, never something measured here."""
        return self.total_alerts

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_label": self.input_label,
            "data_source_type": self.data_source_type,
            "total_flows": self.total_flows,
            "total_alerts": self.total_alerts,
            "false_positive_alerts": self.false_positive_alerts,
            "alerts_per_1000_flows": self.alerts_per_1000_flows,
            "detectors": list(self.detectors),
            "detector_errors": self.detector_errors,
            "by_detector": {
                name: stats.to_dict() for name, stats in self.by_detector.items()
            },
            "by_threat_class": dict(self.by_threat_class),
            "notes": list(self.notes),
        }


def evaluate_benign(
    flows: Iterable[FlowEvent],
    *,
    input_label: str,
    data_source_type: str = SYNTHETIC,
    detectors: list[Detector] | None = None,
    dga_model_path: str | Path | None = None,
    notes: Iterable[str] = (),
) -> BenignEvaluation:
    """Run every detector over ``flows`` and count what each one said.

    Detectors come from the ordinary :func:`build_default_detectors`, so this
    measures the same line-up the runner would use - **six** detectors, or
    seven when ``dga_model_path`` names a real bundle. Without one, DGA is
    simply absent: no stand-in model is fabricated, and scikit-learn is never
    imported, so a core-only install can run this.

    ``flush()`` is called at the end, exactly as a bounded replay does, so a
    detector holding state back is not credited with silence it did not earn.
    """
    if data_source_type not in (REAL, SYNTHETIC):
        raise ValueError(f"data_source_type must be {REAL!r} or {SYNTHETIC!r}")

    if detectors is None:
        detectors = build_default_detectors(dga_model_path=dga_model_path)
    engine = DetectionEngine(detectors)

    names = [detector.name for detector in engine.detectors]
    counts = {name: 0 for name in names}
    by_class: dict[str, int] = {}
    total_alerts = 0

    for alert in engine.run(flows):
        total_alerts += 1
        counts[alert.detector] = counts.get(alert.detector, 0) + 1
        key = alert.threat_class.value
        by_class[key] = by_class.get(key, 0) + 1

    flows_processed = engine.stats.flows_processed
    return BenignEvaluation(
        input_label=input_label,
        data_source_type=data_source_type,
        total_flows=flows_processed,
        total_alerts=total_alerts,
        detectors=names,
        by_detector={
            name: DetectorBenignStats(
                detector=name,
                threat_class=name if name in _THREAT_CLASSES else None,
                # Every detector sees every flow.
                flows_processed=flows_processed,
                alerts_emitted=counts[name],
            )
            for name in names
        },
        by_threat_class=by_class,
        detector_errors=engine.stats.detector_errors,
        notes=list(notes),
    )


def evaluate_benign_jsonl(
    path: str | Path,
    *,
    data_source_type: str = REAL,
    input_label: str | None = None,
    dga_model_path: str | Path | None = None,
    notes: Iterable[str] = (),
) -> BenignEvaluation:
    """Same evaluation, reading ingestion-format JSONL through the real adapter.

    Defaults to :data:`~.workloads.REAL` because a JSONL file on disk is
    normally ingestion output - but the caller owns that claim and can say
    otherwise. Skipped malformed records are reported in ``notes`` rather
    than being quietly absent from the denominator.
    """
    path = Path(path)
    adapter = IngestionJsonlAdapter(path=path)
    evaluation = evaluate_benign(
        adapter,
        input_label=input_label or str(path),
        data_source_type=data_source_type,
        dga_model_path=dga_model_path,
        notes=notes,
    )
    if adapter.stats.skipped:
        evaluation.notes.append(
            f"{adapter.stats.skipped} of {adapter.stats.total_lines} record(s) "
            "were unparseable and never reached a detector"
        )
    return evaluation
