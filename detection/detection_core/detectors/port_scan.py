"""Port scan detector - vertical and horizontal.

Near-real-time: every decision is made inside :meth:`PortScanDetector.process`
and the alert is emitted the moment a threshold is crossed. ``flush()`` is
not part of normal detection.

Horizontal fan-out is measured per destination port, so one source touching
many hosts on assorted unrelated ports - ordinary CDN-heavy browsing - is not
mistaken for a subnet sweep.

Two further conditions separate a scan from busy-but-normal traffic, both
added after measuring this detector against 529k flows of a real benign
capture (CIC-IDS2017 Monday), where it produced 1,636 false positives:

* **Ports a service could live on.** A vertical alert needs at least
  ``min_service_ports`` distinct ports at or below ``max_service_port``.
  Above that boundary is IANA's dynamic/private range, which hosts hand out
  to *outbound* connections. 87.5% of the benign vertical false positives
  held fewer than three such ports and 83.4% held **none at all** - one CDN
  or cloud host "touching" a workstation's ephemeral ports, which is the
  reply side of ordinary browsing, not an enumeration.
* **The responder has to be refusing.** A scan's connections do not complete;
  a browsing session's do. Measured from ``conn_state`` when ingestion
  supplies it for the endpoints being judged, and from responder payload
  bytes when it does not. Both readings are scoped per ``(host, port)``
  endpoint rather than per flow, so answered browsing sharing a window with a
  sweep can neither dilute the sweep's evidence nor stand in for it.

Rolling per-source state is computed here (via ``aggregators``), never taken
from ingestion's global window features.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..aggregators import DEFAULT_ESTABLISHED_RESP_BYTES, FlowObservation, WindowIndex
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

    #: Highest port number a service is expected to be *found* on. IANA
    #: reserves 49152-65535 as the dynamic/private range: hosts allocate those
    #: to outbound connections, so nothing is listening there to enumerate.
    max_service_port: int = 49151

    #: Distinct ports at or below :attr:`max_service_port` a **vertical**
    #: alert needs. A scan sweeps service ports; the reply side of ordinary
    #: client traffic sweeps ephemeral ones. On the real benign capture the
    #: median vertical false positive had **zero** service ports in its
    #: window. The weakest window of either labelled real scan had **13** -
    #: the same figure on CIC-IDS2017's nmap sweep and on UNSW-NB15's
    #: Reconnaissance - so 3 discriminates with a wide margin at both ends.
    #: Horizontal fan-out is judged on its own port and is unaffected.
    min_service_ports: int = 3

    #: Responder payload bytes at or above which a flow counts as a completed
    #: exchange rather than a probe. Not "greater than zero": some exporters
    #: bill a bare RST a few bytes.
    established_resp_bytes: int = DEFAULT_ESTABLISHED_RESP_BYTES

    #: Suppress when more than this share of the window came back with real
    #: payload. A scan is refused; browsing is answered.
    #:
    #: **Safe on a unidirectional capture.** With no reverse direction there
    #: are no responder bytes, the measured share is 0.0 for every window, and
    #: nothing is ever suppressed - the detector behaves exactly as it did
    #: before this gate existed. The gate can only *use* reply evidence that
    #: is genuinely present; it never *requires* it.
    max_established_fraction: float = 0.20

    #: Used instead of the byte proxy once ``conn_state`` actually arrives:
    #: the share of the window's **endpoints** that failed to establish must
    #: reach this. Endpoint-scoped for the same reason
    #: :attr:`max_established_fraction` is - see
    #: :meth:`ActivityWindow.endpoint_incomplete_fraction`.
    #:
    #: On UNSW-NB15 - the one real dataset carrying a usable connection state -
    #: the separation is one-sided and wide. Across the **1 171** benign
    #: windows this detector used to alert on, the highest incomplete share was
    #: **0.0235**, and not one reached 0.05. Across the 14 windows of the four
    #: labelled Reconnaissance episodes, 9 did, with a median of 0.163. So the
    #: threshold sits above every benign window measured while still leaving
    #: every real episode with qualifying windows: recall 1.000, precision
    #: 1.000. Some scan windows do fall below it - a scan that gets answered in
    #: a given minute looks like traffic in that minute - which is why this is
    #: a per-window test feeding a per-episode result, not a per-flow verdict.
    min_incomplete_fraction: float = 0.05

    #: How many of a window's **endpoints** must carry a classified
    #: ``conn_state`` before it is trusted over the byte proxy. Ingestion's
    #: ``detector-v2`` profile carries the raw string, so this path runs
    #: there; the frozen ``legacy-m1d`` profile supplies none and falls to the
    #: proxy. See ``CLASSIFIED_CONN_STATES``.
    #:
    #: Measured over endpoints rather than flows so that a window can only
    #: take the ``conn_state`` branch on the strength of states attached to
    #: the endpoints being judged. A per-flow reading let a couple of chatty
    #: labelled endpoints carry the whole window over this floor while every
    #: swept endpoint in it was unlabelled - see
    #: :meth:`ActivityWindow.endpoint_conn_state_coverage`.
    min_conn_state_coverage: float = 0.50

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
        if not 0 <= self.max_service_port <= 65535:
            raise ValueError("max_service_port must be within [0, 65535]")
        if self.min_service_ports < 0:
            raise ValueError("min_service_ports must not be negative")
        if self.established_resp_bytes < 0:
            raise ValueError("established_resp_bytes must not be negative")
        if not 0.0 <= self.max_established_fraction <= 1.0:
            raise ValueError("max_established_fraction must be within [0.0, 1.0]")
        if not 0.0 <= self.min_incomplete_fraction <= 1.0:
            raise ValueError("min_incomplete_fraction must be within [0.0, 1.0]")
        if not 0.0 <= self.min_conn_state_coverage <= 1.0:
            raise ValueError("min_conn_state_coverage must be within [0.0, 1.0]")


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

    A qualifying window then has to survive two credibility checks, in this
    order:

    * **service ports** (vertical only) - the window must hold at least
      ``min_service_ports`` distinct ports at or below ``max_service_port``.
    * **responder engagement** (both) - the window must not look like a
      conversation that the far side answered. See
      :meth:`_responder_refused`.

    Repeats do not inflate anything: counts are over distinct values, so
    hammering one host on one port never trips either threshold. A flow with
    no ``dst_port`` contributes a host to ``unique_dst_ips`` but counts toward
    neither threshold - there is no port to correlate it across hosts.
    """

    name = "port_scan"
    # 0.3.0: a vertical alert needs ports a service could live on, and any
    # alert needs a window the responder did not answer. Both were derived
    # from real captures; see the module docstring.
    # 0.3.1: two corrections to that responder check, both of which could
    # silence a real scan. Coverage now counts only *classified* conn_states,
    # so an OTH / unrecognised / empty window falls back to the byte proxy
    # instead of concluding "answered"; and the proxy is scoped per endpoint,
    # so answered browsing sharing the window cannot dilute a sweep below the
    # gate. Alerts carry two new evidence keys - see `_build_alert`.
    # 0.3.2: the third case of the same defect, and the last one left. The
    # conn_state branch was still selected on a *per-flow* coverage reading,
    # so under `legacy-m1d` - where a sweep arrives unlabelled and browsing
    # arrives SF - enough browsing handed the verdict to a branch holding no
    # evidence about the sweep, which then read 0.0 incomplete as "answered".
    # Coverage and the incomplete share are now endpoint-scoped, matching the
    # proxy. Two further evidence keys; see `_build_alert`.
    version = "0.3.2"

    def __init__(self, config: PortScanConfig | None = None) -> None:
        self.config = config or PortScanConfig()
        self._windows = WindowIndex(
            self.config.window_seconds,
            established_resp_bytes=self.config.established_resp_bytes,
            # Pinned so unique_service_port_count() is an O(1) read on the
            # hot qualification path rather than a scan over every port.
            service_port_max=self.config.max_service_port,
        )
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

        # A vertical sweep over ports nothing listens on is the reply side of
        # ordinary client traffic. Dropped from the vertical signal only -
        # a horizontal sweep is judged on its own port, which the fan-out
        # already identified.
        service_ports = window.unique_service_port_count(self.config.max_service_port)
        if vertical and service_ports < self.config.min_service_ports:
            vertical = False
            if not horizontal:
                return []

        if not self._responder_refused(window):
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
            service_ports=service_ports,
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

    def _responder_refused(self, window) -> bool:
        """Does this window look like connections that did not complete?

        A scan is a wall of attempts nobody answers. A busy workstation's
        window is the opposite: pages, DNS answers and TLS handshakes coming
        back. That difference is what ``conn_state`` encodes, and it is the
        single strongest discriminator this detector has - on the real benign
        capture the median alerting window had 73% of its flows answered
        (86% among the horizontal ones, which are the browsing shape), against
        a maximum of **9.5%** across the sixteen windows of the labelled nmap
        scan on CIC-IDS2017 Friday.

        Two ways to read it, best available first:

        * **``conn_state``** - authoritative, used once enough of the window's
          *endpoints* carry a *classified* state. ``S0`` (attempt, no reply)
          is the classic scan state. Coverage counts only states that actually
          answer "did the responder engage" - ``OTH``, an unrecognised value
          and an empty string are **uncovered**, not answered, so they route
          the decision to the proxy below instead of concluding from nothing.
        * **responder payload bytes** - the proxy, and still the path under
          the frozen ``legacy-m1d`` feature profile, which flattens ``S0`` to
          the same code as "unknown" (``encode_conn_state``,
          ``ingestion/src/features/flow.rs``). Nothing came back means
          nothing was serving.

        **Both readings are scoped per endpoint, not per flow** - see
        :meth:`ActivityWindow.endpoint_established_fraction` and
        :meth:`ActivityWindow.endpoint_conn_state_coverage`. Divided across
        the whole window either one measures traffic volume rather than scan
        evidence, and answered browsing sharing the window could then decide
        the verdict for a sweep it has nothing to do with. That was true of
        the byte proxy first, and separately of the ``conn_state`` branch:
        under the frozen ``legacy-m1d`` profile a real sweep arrives
        *unlabelled* while ordinary browsing arrives ``SF``, so enough
        browsing pushed per-flow coverage over the floor, handed the verdict
        to a branch that had no evidence about the sweep at all, and read the
        resulting 0.0 incomplete share as "the responder answered". Thirty SF
        browsing flows were enough to silence a thirty-port sweep outright.

        **A capture with no reverse direction is not penalised.** With no
        responder bytes anywhere the measured share is 0.0, which is below
        any ceiling, so every window passes and the detector behaves as it
        did before this check existed. The gate spends reply evidence when it
        exists and asks for none when it does not - which is the only reading
        compatible with a genuinely unidirectional deployment.

        **The ``conn_state`` branch only ever decides on evidence about the
        endpoints it is deciding about.** It is taken only when the window's
        endpoints themselves carry classified states; a window whose swept
        endpoints are unlabelled falls through to the proxy however much
        labelled traffic sits beside them. What it may still do - and is
        meant to do - is suppress a window whose own endpoints are labelled
        complete: there ingestion is asserting those exchanges finished, and
        preferring that assertion to the byte proxy is the entire reason the
        branch exists.
        """
        config = self.config
        if (
            window.endpoint_conn_state_coverage()
            >= config.min_conn_state_coverage
        ):
            return (
                window.endpoint_incomplete_fraction()
                >= config.min_incomplete_fraction
            )
        return (
            window.endpoint_established_fraction()
            <= config.max_established_fraction
        )

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
        service_ports: int,
        vertical: bool,
        horizontal: bool,
        score: float,
        severity: Severity,
    ) -> ThreatAlert:
        span = window.time_span() or (flow.timestamp, flow.timestamp)
        coverage = window.conn_state_coverage()
        endpoint_coverage = window.endpoint_conn_state_coverage()
        # The branch `_responder_refused` actually took - endpoint-scoped, so
        # the reported evidence names the reasoning that ran.
        by_conn_state = endpoint_coverage >= self.config.min_conn_state_coverage

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
                # Ports a service could actually be found on, of
                # `unique_dst_ports`. The rest are the dynamic/private range.
                "service_ports": service_ports,
                "min_service_ports": self.config.min_service_ports,
                "max_service_port": self.config.max_service_port,
                # How the responder-engagement check was decided, so an analyst
                # can see whether it ran on real connection states or on the
                # byte proxy that stands in for them today.
                "responder_evidence": "conn_state" if by_conn_state else "resp_bytes",
                # Per-flow, kept for continuity with earlier alerts.
                "conn_state_coverage": round(coverage, 4),
                "incomplete_fraction": round(window.incomplete_fraction(), 4),
                # Per-endpoint - what the conn_state branch actually gates on.
                "endpoint_conn_state_coverage": round(endpoint_coverage, 4),
                "endpoint_incomplete_fraction": round(
                    window.endpoint_incomplete_fraction(), 4
                ),
                # Per-flow, kept for continuity with earlier alerts.
                "established_fraction": round(window.established_fraction(), 4),
                # Per-endpoint - what the byte proxy actually gates on.
                "endpoint_established_fraction": round(
                    window.endpoint_established_fraction(), 4
                ),
                "established_endpoints": window.established_endpoint_count(),
                "unique_endpoints": window.unique_endpoint_count(),
            },
            detector=self.name,
            detector_version=self.version,
            mitre_techniques=list(MITRE_BY_CLASS[ThreatClass.PORT_SCAN]),
        )
