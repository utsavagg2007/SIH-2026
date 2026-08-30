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

__all__ = ["PortScanConfig", "PortScanDetector"]


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
        self._windows = WindowIndex(self.config.window_seconds)
        self._state: dict[str, _SourceState] = {}
        self._since_sweep = 0

    # --- detection ------------------------------------------------------

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        """Update this source's window and alert immediately if it scans."""
        window = self._windows.observe(flow.src_ip, FlowObservation.from_flow(flow))
        # On every flow, not only when alerting: a source that alerts once and
        # then goes quiet must still have its cooldown released eventually.
        self._sweep_cooldowns(flow.timestamp)

        # Counts, not collections. A scan's defining feature is that every
        # flow brings a port nobody has seen, so materializing the set of
        # ports on every flow costs 1 + 2 + 3 + ... - quadratic in exactly
        # the traffic this detector exists to catch. The window already
        # maintains these numbers; the ports themselves are only needed if
        # an alert is actually built, below.
        port_count = window.unique_dst_port_count()
        fanout = window.max_hosts_per_port()

        vertical = port_count >= self.config.min_unique_ports
        horizontal = fanout >= self.config.min_unique_hosts
        if not (vertical or horizontal):
            return []

        score = self._rule_score(port_count, fanout, vertical, horizontal)
        severity = self._severity(score)
        if not self._should_emit(flow.src_ip, flow.timestamp, severity):
            return []

        # The alert path, reached far less often than the qualification path,
        # is where the actual values are worth building.
        ports = window.dst_ports()
        hosts = window.dst_ips()
        scanned_port, _ = self._widest_fanout(window.hosts_by_port())

        alert = self._build_alert(
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

        # Only once the alert exists. If building or validating it raises,
        # nothing was emitted, so nothing may enter the cooldown - otherwise
        # the failure would also silence the next several real scans.
        state = self._state.setdefault(flow.src_ip, _SourceState())
        state.last_alert_at = flow.timestamp
        state.last_severity = severity
        return [alert]

    def flush(self) -> list[ThreatAlert]:
        """Nothing is ever held back - ``process()`` already alerted."""
        return []

    def reset(self) -> None:
        """Drop every source's window and cooldown."""
        self._windows.clear()
        self._state.clear()
        self._since_sweep = 0

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
        return severity_rank(severity) > severity_rank(state.last_severity)

    def _sweep_cooldowns(self, now: float, every: int = 500) -> None:
        """Release cooldowns that can no longer suppress anything.

        A source's cooldown deliberately outlives its traffic window - it is
        five times longer by default - so a scanner could otherwise go quiet,
        come back, and immediately re-alert inside the cooldown it was still
        serving. Entries are therefore dropped on elapsed cooldown, never on
        an empty window. That still bounds the dict, since only sources that
        actually alerted ever get an entry. (``WindowIndex`` sweeps the far
        larger window dict itself.)

        Event time only, from ``FlowEvent.timestamp``: a PCAP replay must
        expire state exactly as the live stream did.
        """
        self._since_sweep += 1
        if self._since_sweep < every:
            return
        self._since_sweep = 0
        for key, state in list(self._state.items()):
            if (
                state.last_alert_at is not None
                and (now - state.last_alert_at) >= self.config.cooldown_seconds
            ):
                del self._state[key]

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
        return normalize_score(score)

    @staticmethod
    def _severity(score: float) -> Severity:
        """Project-standard severity bands - see ``scoring.severity_for``."""
        return severity_for(score)

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
