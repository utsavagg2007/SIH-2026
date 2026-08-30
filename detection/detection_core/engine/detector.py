"""The Detector interface.

Every detector - statistical, rule-based or ML - implements this. The
engine knows nothing else about them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..schemas import FlowEvent, ThreatAlert

__all__ = ["Detector"]


class Detector(ABC):
    """Base class for all detectors.

    Subclasses set ``name`` and ``version``; both end up on every emitted
    alert (``ThreatAlert.detector`` / ``detector_version``) so results stay
    traceable to the exact detector build that produced them.
    """

    # Class-level defaults; an instance may override either (e.g. two
    # differently-configured instances of the same detector class).
    name: str = "unnamed_detector"
    version: str = "0.0.0"

    @abstractmethod
    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        """Handle one flow. Return zero or more alerts.

        This is where detection happens. The target system is near-real-time
        streaming, so a detector MUST emit an alert here the moment its
        condition is satisfied - as soon as a sliding window, threshold or
        statistical test crosses its bound. Do not sit on a finding waiting
        for the stream to end; a stream may never end.

        Stateful detectors (beaconing, port scan, DDoS) keep their own
        rolling state across calls and still alert from here.

        Must not mutate ``flow`` - the same instance goes to every detector.
        (FlowEvent is frozen, so this is enforced rather than trusted.)
        """
        raise NotImplementedError

    def flush(self) -> list[ThreatAlert]:
        """Finalize pending state when a finite stream ends.

        Called once after the last flow of a bounded source - a PCAP replay,
        a test, or a stream that closed. Its only job is to settle state that
        was still incomplete at that point: a window that never filled, a
        candidate that had not yet reached its threshold.

        It is NOT the normal path for emitting alerts. Anything that can be
        decided while the stream is running belongs in ``process()``.
        Stateless detectors keep the default no-op.
        """
        return []

    def reset(self) -> None:
        """Drop accumulated state so the detector can be reused.

        ``DetectionEngine.run()`` calls this before consuming a source, so
        one replay cannot contaminate the next. Any detector holding rolling
        state must clear it here.
        """
        return None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} name={self.name!r} version={self.version!r}>"
