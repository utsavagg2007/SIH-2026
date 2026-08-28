"""DDoS detector - many sources converging on one destination.

Where port scanning asks "what has this *source* touched?", DDoS asks "who
has been hitting this *destination*?", so the rolling state is keyed by
``dst_ip``.

Near-real-time: every decision is made inside :meth:`DDoSDetector.process`
and the alert is emitted the moment the conditions are met. ``flush()`` is
not part of normal detection.

Detection is deliberately multi-signal. A destination must see both a broad
set of distinct sources *and* real traffic intensity. Volume alone is not
enough: one host pulling a large file is not a DDoS, and a handful of
sources idling is not either.

Volume is counted **originator-side only** (``orig_pkts`` / ``orig_bytes``) -
what the sources sent *at* the victim. Counting the victim's own replies
would let an ordinary busy server cross the packet threshold on the strength
of the pages it is serving.

Rolling destination-keyed state is computed here (via ``aggregators``),
never taken from ingestion's global window features.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..aggregators import FlowObservation, WindowIndex
from ..engine import Detector
from ..schemas import (
    MITRE_BY_CLASS,
    EventScope,
    FlowEvent,
    ScoreType,
    Severity,
    ThreatAlert,
    ThreatClass,
    epoch_to_utc,
)
from .scoring import normalize_score, severity_for, severity_rank

__all__ = ["DDoSConfig", "DDoSDetector"]


@dataclass(frozen=True)
class DDoSConfig:
    """Thresholds for :class:`DDoSDetector`. Every value is tunable.

    These defaults are **initial heuristics for demo traffic, not tuned
    values**. They were picked to fire on an obvious flood while staying
    clear of a busy-but-normal server, and they must be re-derived against
    real captures of this network's normal and attack traffic before anyone
    trusts them operationally.
    """

    #: Rolling window, in seconds of event time (not wall clock). Short,
    #: because a flood is a burst - a long window would dilute it.
    window_seconds: float = 10.0

    #: Distinct source IPs hitting one destination before it can qualify.
    min_unique_sources: int = 50

    #: Flow count on one destination that counts as high intensity.
    min_flows: int = 200

    #: Packet count on one destination that counts as high intensity.
    min_packets: int = 1000

    #: After alerting on a destination, stay quiet this long for it - unless
    #: the severity band rises, which always gets through.
    cooldown_seconds: float = 60.0

    #: Multiple of a threshold at which the rule score saturates at 1.0.
    saturation_multiple: float = 4.0

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.min_unique_sources < 1:
            raise ValueError("min_unique_sources must be at least 1")
        if self.min_flows < 1:
            raise ValueError("min_flows must be at least 1")
        if self.min_packets < 1:
            raise ValueError("min_packets must be at least 1")
        if self.cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")
        if self.saturation_multiple <= 1:
            raise ValueError("saturation_multiple must be greater than 1")


@dataclass
class _DestinationState:
    """Per-destination bookkeeping the window itself does not hold."""

    last_alert_at: float | None = None
    last_severity: Severity | None = None


class DDoSDetector(Detector):
    """Flags a destination being hit by many sources at high intensity.

    A destination qualifies only when **both** hold inside the window:

    * **breadth** - ``unique_src_ips >= min_unique_sources``
    * **intensity** - ``flow_count >= min_flows`` OR
      ``packet_count >= min_packets``

    Requiring breadth stops a single heavy transfer from looking like an
    attack; requiring intensity stops a merely popular host from doing so.
    Bytes are tracked and reported as evidence but deliberately do not gate
    the decision - one large legitimate download would otherwise qualify.
    """

    name = "ddos"
    version = "0.1.0"

    def __init__(self, config: DDoSConfig | None = None) -> None:
        self.config = config or DDoSConfig()
        self._windows = WindowIndex(self.config.window_seconds)
        self._state: dict[str, _DestinationState] = {}

    # --- detection ------------------------------------------------------

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        """Update this destination's window and alert immediately if flooded."""
        window = self._windows.observe(flow.dst_ip, FlowObservation.from_flow(flow))

        sources = window.src_ips()
        flows = window.attempts
        packets = window.total_orig_packets()

        broad = len(sources) >= self.config.min_unique_sources
        intense = flows >= self.config.min_flows or packets >= self.config.min_packets
        if not (broad and intense):
            return []

        score = self._rule_score(len(sources), flows, packets)
        severity = severity_for(score)
        if not self._should_emit(flow.dst_ip, flow.timestamp, severity):
            return []

        state = self._state.setdefault(flow.dst_ip, _DestinationState())
        state.last_alert_at = flow.timestamp
        state.last_severity = severity

        return [
            self._build_alert(
                flow=flow,
                window=window,
                sources=sources,
                flows=flows,
                packets=packets,
                score=score,
                severity=severity,
            )
        ]

    def flush(self) -> list[ThreatAlert]:
        """Nothing is ever held back - ``process()`` already alerted."""
        return []

    def reset(self) -> None:
        """Drop every destination's window, cooldown and escalation state."""
        self._windows.clear()
        self._state.clear()

    # --- internals ------------------------------------------------------

    def _should_emit(self, dst_ip: str, now: float, severity: Severity) -> bool:
        """Cooldown, with an escape hatch for genuine escalation.

        A destination that has just alerted stays quiet for
        ``cooldown_seconds`` - unless the flood has grown into a strictly
        higher severity band, which is news worth interrupting for. A rising
        score inside the same band is not: that would be the alert spam the
        cooldown exists to stop.
        """
        state = self._state.get(dst_ip)
        if state is None or state.last_alert_at is None:
            return True
        if (now - state.last_alert_at) >= self.config.cooldown_seconds:
            return True
        if state.last_severity is None:
            return True
        return severity_rank(severity) > severity_rank(state.last_severity)

    def _rule_score(self, sources: int, flows: int, packets: int) -> float:
        """Deterministic 0.0-1.0 rule score. Not a calibrated probability.

        Averages two ratios - how far past ``min_unique_sources`` the breadth
        is, and how far past its threshold the stronger intensity signal is -
        then maps the result onto the project's usual curve: exactly at both
        thresholds scores 0.5, ``saturation_multiple`` times them scores 1.0,
        linear in between.

        Averaging means a wider flood or a heavier one both raise the score,
        but neither alone can saturate it.
        """
        breadth_ratio = sources / self.config.min_unique_sources
        intensity_ratio = max(
            flows / self.config.min_flows,
            packets / self.config.min_packets,
        )
        ratio = (breadth_ratio + intensity_ratio) / 2.0

        span = self.config.saturation_multiple - 1.0
        return normalize_score(0.5 + 0.5 * (ratio - 1.0) / span)

    @staticmethod
    def _severity(score: float) -> Severity:
        """Project-standard severity bands - see ``scoring.severity_for``."""
        return severity_for(score)

    @staticmethod
    def _only(values: set) -> object | None:
        """The single member of a set, or None when it is not unambiguous.

        Keeps us honest: an attack from many sources reports ``src_ip: None``
        rather than inventing a placeholder.
        """
        return next(iter(values)) if len(values) == 1 else None

    @staticmethod
    def _rate(count: int, duration: float) -> float | None:
        """Events per second, or None when the window spans no time.

        A window holding a single flow - or several sharing one timestamp -
        has no measurable rate. Reporting ``None`` is the honest answer;
        dividing by a fudged epsilon is how ingestion ends up publishing
        ``flow_rate: 1000000.0`` on its first record.
        """
        if duration <= 0:
            return None
        return count / duration

    def _build_alert(
        self,
        *,
        flow: FlowEvent,
        window,
        sources: set[str],
        flows: int,
        packets: int,
        score: float,
        severity: Severity,
    ) -> ThreatAlert:
        span = window.time_span() or (flow.timestamp, flow.timestamp)
        duration = window.duration()
        byte_count = window.total_orig_bytes()

        return ThreatAlert(
            event_start=epoch_to_utc(span[0]),
            event_end=epoch_to_utc(span[1]),
            event_scope=EventScope.DESTINATION_HOST,
            flow_id=None,
            src_ip=self._only(sources),
            dst_ip=flow.dst_ip,
            dst_port=self._only(window.dst_ports()),
            protocol=self._only(window.protocols()),
            threat_class=ThreatClass.DDOS,
            severity=severity,
            score=score,
            score_type=ScoreType.RULE_SCORE,
            evidence={
                "unique_src_ips": len(sources),
                "flow_count": flows,
                # Originator-side only: traffic arriving at the victim.
                "packet_count": packets,
                "byte_count": byte_count,
                "window_seconds": self.config.window_seconds,
                "observed_span_seconds": duration,
                # None when the window spans no event time - not a fake rate.
                "flows_per_second": self._rate(flows, duration),
                "packets_per_second": self._rate(packets, duration),
                "min_unique_sources": self.config.min_unique_sources,
                "min_flows": self.config.min_flows,
                "min_packets": self.config.min_packets,
            },
            detector=self.name,
            detector_version=self.version,
            mitre_techniques=list(MITRE_BY_CLASS[ThreatClass.DDOS]),
        )
