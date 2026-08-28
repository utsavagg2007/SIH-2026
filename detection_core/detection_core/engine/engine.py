"""DetectionEngine: fan FlowEvents out to registered detectors.

Deliberately synchronous and single-process - the right size for this
project. The value it adds is isolation: one detector raising must never
take down a run.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from ..schemas import FlowEvent, ThreatAlert
from .detector import Detector

__all__ = ["DetectionEngine", "EngineStats"]

logger = logging.getLogger(__name__)


@dataclass
class EngineStats:
    """Counters for one engine run."""

    flows_processed: int = 0
    alerts_emitted: int = 0
    detector_errors: int = 0

    def reset(self) -> None:
        self.flows_processed = 0
        self.alerts_emitted = 0
        self.detector_errors = 0


class DetectionEngine:
    """Registers detectors and routes FlowEvents through them."""

    def __init__(
        self,
        detectors: Iterable[Detector] | None = None,
        *,
        raise_on_detector_error: bool = False,
        log: logging.Logger | None = None,
    ) -> None:
        self._detectors: list[Detector] = []
        self.raise_on_detector_error = raise_on_detector_error
        self.log = log or logger
        self.stats = EngineStats()
        for detector in detectors or ():
            self.register(detector)

    # --- registration ---------------------------------------------------

    def register(self, detector: Detector) -> DetectionEngine:
        """Add a detector. Returns self so calls can be chained."""
        if not isinstance(detector, Detector):
            raise TypeError(
                f"expected a Detector subclass instance, got {type(detector).__name__}"
            )
        if any(existing.name == detector.name for existing in self._detectors):
            raise ValueError(f"a detector named {detector.name!r} is already registered")
        self._detectors.append(detector)
        return self

    @property
    def detectors(self) -> tuple[Detector, ...]:
        return tuple(self._detectors)

    # --- execution ------------------------------------------------------

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        """Send one flow to every detector and collect their alerts."""
        alerts: list[ThreatAlert] = []
        for detector in self._detectors:
            alerts.extend(self._invoke(detector, "process", flow))
        self.stats.flows_processed += 1
        self.stats.alerts_emitted += len(alerts)
        return alerts

    def flush(self) -> list[ThreatAlert]:
        """Ask every detector to finalize state left pending at end of stream.

        Not the normal alerting path - detectors emit from ``process()`` as
        soon as their condition is met. See ``Detector.flush``.
        """
        alerts: list[ThreatAlert] = []
        for detector in self._detectors:
            alerts.extend(self._invoke(detector, "flush"))
        self.stats.alerts_emitted += len(alerts)
        return alerts

    def run(
        self, source: Iterable[FlowEvent], *, reset_first: bool = True
    ) -> Iterator[ThreatAlert]:
        """Stream alerts for every flow in ``source``, then flush.

        ``source`` is any iterable of FlowEvents - an adapter, a list, a
        generator. Alerts are yielded as soon as a detector produces them, so
        a live source stays near-real-time; flush alerts arrive last, once the
        source is exhausted.

        By default each run starts clean: detector state is reset before the
        source is consumed, so replaying a second PCAP through the same engine
        cannot inherit state from the first. Pass ``reset_first=False`` to
        deliberately continue accumulating across successive calls (e.g.
        feeding one live stream in chunks).
        """
        if reset_first:
            self.reset()
        else:
            self.stats.reset()
        for flow in source:
            yield from self.process(flow)
        yield from self.flush()

    def reset(self) -> None:
        """Reset engine counters and every detector's accumulated state."""
        self.stats.reset()
        for detector in self._detectors:
            self._invoke(detector, "reset")

    # --- internals ------------------------------------------------------

    def _invoke(self, detector: Detector, method: str, *args: object) -> list[ThreatAlert]:
        """Call a detector hook, containing any failure to that detector."""
        try:
            result = getattr(detector, method)(*args)
        except Exception:
            self.stats.detector_errors += 1
            self.log.exception(
                "detector %r raised in %s(); skipping it for this call",
                detector.name,
                method,
            )
            if self.raise_on_detector_error:
                raise
            return []

        if method == "reset":
            return []
        return self._validate_alerts(detector, method, result)

    def _validate_alerts(
        self, detector: Detector, method: str, result: object
    ) -> list[ThreatAlert]:
        """Reject anything that is not a list of ThreatAlerts."""
        if result is None:
            return []
        if not isinstance(result, (list, tuple)):
            self.stats.detector_errors += 1
            self.log.error(
                "detector %r returned %s from %s(); expected a list of ThreatAlert",
                detector.name,
                type(result).__name__,
                method,
            )
            if self.raise_on_detector_error:
                raise TypeError(f"detector {detector.name!r} returned a non-list")
            return []

        alerts: list[ThreatAlert] = []
        for item in result:
            if isinstance(item, ThreatAlert):
                alerts.append(item)
            else:
                self.stats.detector_errors += 1
                self.log.error(
                    "detector %r emitted a %s from %s(); expected ThreatAlert",
                    detector.name,
                    type(item).__name__,
                    method,
                )
                if self.raise_on_detector_error:
                    raise TypeError(
                        f"detector {detector.name!r} emitted a non-ThreatAlert"
                    )
        return alerts
