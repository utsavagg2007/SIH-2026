"""Port scan detector - vertical and horizontal.

Near-real-time: every decision is made inside :meth:`PortScanDetector.process`
and the alert is emitted the moment a threshold is crossed. ``flush()`` is
not part of normal detection.

Horizontal fan-out is measured per destination port, so one source touching
many hosts on assorted unrelated ports - ordinary CDN-heavy browsing - is not
mistaken for a subnet sweep.

Rolling per-source state is computed here (via ``aggregators``), never taken
from ingestion's global window features.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..aggregators import FlowObservation, SourceWindowIndex
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

__all__ = ["PortScanConfig", "PortScanDetector"]


# Decimal places the rule score is rounded to before anything compares it.
# Without this, a score that is mathematically exactly 0.9 arrives as
# 0.8999999999999999 (e.g. 17 ports against a threshold of 5) and silently
# lands one severity band too low. Six places is far finer than a rule score
# can meaningfully resolve, so this only removes binary-float noise.
_SCORE_PRECISION = 6

# Score -> Severity. Deterministic and documented; the enum is unchanged.
# A score of exactly 0.5 means "the threshold was just met".
_SEVERITY_CUTOFFS: tuple[tuple[float, Severity], ...] = (
    (0.90, Severity.CRITICAL),
    (0.75, Severity.HIGH),
    (0.60, Severity.MEDIUM),
)


def _normalize_score(value: float) -> float:
    """Clamp to [0.0, 1.0] and round, so boundary comparisons are exact."""
    return round(min(max(value, 0.0), 1.0), _SCORE_PRECISION)

# Ordering for escalation checks. Local to this detector - the Severity enum
# itself is a frozen part of the v1.1 contract and is not modified.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass(frozen=True)
class PortScanConfig:
    """Thresholds for :class:`PortScanDetector`. Every value is tunable."""

    #: Rolling window, in seconds of event time (not wall clock).
    window_seconds: float = 60.0

    #: Distinct destination ports on one source before a vertical scan fires.
    min_unique_ports: int = 15

    #: Distinct destination hosts *on a single destination port* before a
    #: horizontal scan fires.
    min_unique_hosts: int = 20

    #: After alerting on a source, stay quiet this long for that source -
    #: unless the severity band rises, which always gets through.
    cooldown_seconds: float = 300.0

    #: Multiple of a threshold at which the rule score saturates at 1.0.
    saturation_multiple: float = 4.0

    #: Added to the score when both scan types fire together.
    combined_bonus: float = 0.10

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.min_unique_ports < 1:
            raise ValueError("min_unique_ports must be at least 1")
        if self.min_unique_hosts < 1:
            raise ValueError("min_unique_hosts must be at least 1")
        if self.cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")
        if self.saturation_multiple <= 1:
            raise ValueError("saturation_multiple must be greater than 1")
        if not 0.0 <= self.combined_bonus <= 1.0:
            raise ValueError("combined_bonus must be within [0.0, 1.0]")


@dataclass
class _SourceState:
    """Per-source bookkeeping the window itself does not hold."""

    last_alert_at: float | None = None
    last_severity: Severity | None = None


class PortScanDetector(Detector):
    """Flags a source sweeping many ports (vertical) or many hosts (horizontal).

    Both signals are evaluated over the same rolling per-source window:

    * **vertical** - ``unique_dst_ports >= min_unique_ports``: one source
      touching many different ports.
    * **horizontal** - some single destination port reaches
      ``min_unique_hosts`` distinct destination hosts. Fan-out is measured
      *per port*, so contacting many hosts on assorted unrelated ports (ordinary
      CDN-heavy browsing) is not a scan; sweeping ``:22`` across a subnet is.
    * **combined** - both, in the same window.

    Repeats do not inflate anything: counts are over distinct values, so
    hammering one host on one port never trips either threshold. A flow with
    no ``dst_port`` contributes a host to ``unique_dst_ips`` but counts toward
    neither threshold - there is no port to correlate it across hosts.
    """

    name = "port_scan"
    # 0.2.0: horizontal fan-out is measured per destination port, and a rising
    # severity band escapes the cooldown.
    version = "0.2.0"

    def __init__(self, config: PortScanConfig | None = None) -> None:
        self.config = config or PortScanConfig()
        self._windows = SourceWindowIndex(self.config.window_seconds)
        self._state: dict[str, _SourceState] = {}

    # --- detection ------------------------------------------------------

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        """Update this source's window and alert immediately if it scans."""
        window = self._windows.observe(flow.src_ip, FlowObservation.from_flow(flow))

        ports = window.dst_ports()
        hosts = window.dst_ips()
        scanned_port, fanout = self._widest_fanout(window.hosts_by_port())

        vertical = len(ports) >= self.config.min_unique_ports
        horizontal = fanout >= self.config.min_unique_hosts
        if not (vertical or horizontal):
            return []

        score = self._rule_score(len(ports), fanout, vertical, horizontal)
        severity = self._severity(score)
        if not self._should_emit(flow.src_ip, flow.timestamp, severity):
            return []

        state = self._state.setdefault(flow.src_ip, _SourceState())
        state.last_alert_at = flow.timestamp
        state.last_severity = severity

        return [
            self._build_alert(
                flow=flow,
                window=window,
                ports=ports,
                hosts=hosts,
                scanned_port=scanned_port if horizontal else None,
                fanout=fanout,
                vertical=vertical,
                horizontal=horizontal,
                score=score,
                severity=severity,
            )
        ]

    def flush(self) -> list[ThreatAlert]:
        """Nothing is ever held back - ``process()`` already alerted."""
        return []

    def reset(self) -> None:
        """Drop every source's window and cooldown."""
        self._windows.clear()
        self._state.clear()

    # --- internals ------------------------------------------------------

    @staticmethod
    def _widest_fanout(grouped: dict[int, set[str]]) -> tuple[int | None, int]:
        """The destination port reaching the most distinct hosts.

        Ties break on the lowest port number so the same traffic always
        produces the same alert.
        """
        if not grouped:
            return None, 0
        port = max(grouped, key=lambda p: (len(grouped[p]), -p))
        return port, len(grouped[port])

    def _should_emit(self, src_ip: str, now: float, severity: Severity) -> bool:
        """Cooldown, with an escape hatch for genuine escalation.

        A source that has just alerted stays quiet for ``cooldown_seconds`` -
        unless the scan has grown into a strictly higher severity band, which
        is news worth interrupting for. A rising score inside the same band is
        not: that would be the alert spam the cooldown exists to stop.
        """
        state = self._state.get(src_ip)
        if state is None or state.last_alert_at is None:
            return True
        if (now - state.last_alert_at) >= self.config.cooldown_seconds:
            return True
        if state.last_severity is None:
            return True
        return _SEVERITY_RANK[severity] > _SEVERITY_RANK[state.last_severity]

    def _scan_type(self, vertical: bool, horizontal: bool) -> str:
        if vertical and horizontal:
            return "combined"
        return "vertical" if vertical else "horizontal"

    def _rule_score(self, ports: int, hosts: int, vertical: bool, horizontal: bool) -> float:
        """Deterministic 0.0-1.0 rule score. Not a calibrated probability.

        How far past its threshold the strongest triggered signal is:
        exactly at the threshold scores 0.5, ``saturation_multiple`` times the
        threshold (default 4x) scores 1.0, linear in between. Tripping both
        signals adds ``combined_bonus``. The result is clamped to [0.0, 1.0].

        ``hosts`` is the fan-out on the single widest destination port, not
        the source's total distinct host count.
        """
        ratios = []
        if vertical:
            ratios.append(ports / self.config.min_unique_ports)
        if horizontal:
            ratios.append(hosts / self.config.min_unique_hosts)

        ratio = max(ratios)
        span = self.config.saturation_multiple - 1.0
        score = 0.5 + 0.5 * (ratio - 1.0) / span
        if vertical and horizontal:
            score += self.config.combined_bonus
        return _normalize_score(score)

    @staticmethod
    def _severity(score: float) -> Severity:
        """Map a rule score to a band: >=0.90 critical, >=0.75 high, >=0.60 medium.

        Normalizes first so a score sitting exactly on a documented boundary
        classifies the same way however the arithmetic that produced it
        rounded.
        """
        score = _normalize_score(score)
        for cutoff, severity in _SEVERITY_CUTOFFS:
            if score >= cutoff:
                return severity
        return Severity.LOW

    @staticmethod
    def _only(values: set) -> object | None:
        """The single member of a set, or None when it is not unambiguous.

        Keeps us honest: an alert spanning many hosts reports ``dst_ip: None``
        rather than inventing a placeholder.
        """
        return next(iter(values)) if len(values) == 1 else None

    def _build_alert(
        self,
        *,
        flow: FlowEvent,
        window,
        ports: set[int],
        hosts: set[str],
        scanned_port: int | None,
        fanout: int,
        vertical: bool,
        horizontal: bool,
        score: float,
        severity: Severity,
    ) -> ThreatAlert:
        span = window.time_span() or (flow.timestamp, flow.timestamp)

        return ThreatAlert(
            event_start=epoch_to_utc(span[0]),
            event_end=epoch_to_utc(span[1]),
            event_scope=EventScope.SOURCE_HOST,
            flow_id=None,
            src_ip=flow.src_ip,
            dst_ip=self._only(hosts),
            dst_port=self._only(ports),
            protocol=self._only(window.protocols()),
            threat_class=ThreatClass.PORT_SCAN,
            severity=severity,
            score=score,
            score_type=ScoreType.RULE_SCORE,
            evidence={
                "scan_type": self._scan_type(vertical, horizontal),
                "unique_dst_ports": len(ports),
                "unique_dst_ips": len(hosts),
                "connection_attempts": window.attempts,
                "window_seconds": self.config.window_seconds,
                # The port being swept across hosts; None unless horizontal fired.
                "horizontal_dst_port": scanned_port,
                # Widest observed host fan-out on any single port.
                "max_hosts_per_port": fanout,
                "min_unique_ports": self.config.min_unique_ports,
                "min_unique_hosts": self.config.min_unique_hosts,
            },
            detector=self.name,
            detector_version=self.version,
            mitre_techniques=list(MITRE_BY_CLASS[ThreatClass.PORT_SCAN]),
        )
