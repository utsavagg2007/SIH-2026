"""Data exfiltration detector - a lot of data leaving for one destination.

The question here is not "how busy is this host?" but "how much did this host
*send*, and did it nearly all go to one place?". Those are different
questions, and the second one is what separates a machine shipping a
database out of the network from a machine having a normal day.

State is keyed by :class:`ExfilKey` - ``(src_ip, dst_ip)`` - so bytes bound
for different destinations are never pooled into one verdict. A second
window keyed by ``src_ip`` alone gives the denominator for *destination
concentration*: of everything this host uploaded, what share went here.

Near-real-time: the decision happens inside
:meth:`DataExfiltrationDetector.process` and fires the moment a pair
qualifies. ``flush()`` is not part of normal detection.

**Direction is the whole point.** Volume is measured with ``orig_bytes`` -
originator to responder - and never ``total_bytes``. Somebody downloading a
500 MB film has a huge ``resp_bytes`` and a tiny ``orig_bytes``; folding the
two together would report that download as half a gigabyte of exfiltration.
``resp_bytes`` is carried as context and reported in the evidence, but it
gates nothing and can never raise the score. The target environment may be
genuinely unidirectional, so nothing here requires a response stream to
exist at all - ``resp_bytes`` may legitimately be zero throughout.

**This is a heuristic signal, and a large upload is not proof of theft.**
Cloud backups, Drive and Dropbox syncs, big ``git push`` operations, video
uploads, database replication and software deployment all look exactly like
this. An alert means "this host sent a lot of data, concentrated on one
destination", which is a lead to investigate, not a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..aggregators import ActivityWindow, FlowObservation, WindowIndex
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

__all__ = [
    "DataExfiltrationConfig",
    "DataExfiltrationDetector",
    "ExfilKey",
    "ExfilStats",
    "QUALIFICATION_BOTH",
    "QUALIFICATION_SINGLE",
    "QUALIFICATION_SUSTAINED",
]

# Values for the ``qualification_path`` evidence field.
QUALIFICATION_SUSTAINED = "sustained"
QUALIFICATION_SINGLE = "single_large_transfer"
QUALIFICATION_BOTH = "both"


@dataclass(frozen=True)
class ExfilKey:
    """One sender/receiver pair.

    Frozen, so it hashes. Bytes to two different destinations are two
    different keys and are never added together - that is what stops a busy
    host's total upload from being attributed to whichever destination it
    happened to talk to last.
    """

    src_ip: str
    dst_ip: str

    @classmethod
    def from_flow(cls, flow: FlowEvent) -> ExfilKey:
        return cls(src_ip=flow.src_ip, dst_ip=flow.dst_ip)


@dataclass(frozen=True)
class ExfilStats:
    """What one pair's window looks like, measured against its source."""

    flow_count: int
    #: Originator-side only. Never includes a single responder byte.
    pair_orig_bytes: int
    pair_orig_packets: int
    max_single_flow_orig_bytes: int
    #: Everything this source sent anywhere in the same window - the
    #: denominator of ``destination_concentration``.
    source_orig_bytes: int
    #: ``pair_orig_bytes / source_orig_bytes``, always within [0.0, 1.0].
    destination_concentration: float
    #: Context only. Reported, never scored.
    pair_resp_bytes: int
    time_span: tuple[float, float]
    observed_span_seconds: float


@dataclass(frozen=True)
class DataExfiltrationConfig:
    """Thresholds for :class:`DataExfiltrationDetector`. Every value is tunable.

    **THESE ARE UNTUNED DEMO HEURISTICS.** They were picked so that an
    obvious bulk transfer fires while ordinary browsing does not, on traffic
    nobody has measured yet. They must be re-derived against real captures
    of this network's normal uploads - cloud backups, Drive/Dropbox syncs,
    ``git push``, video uploads, database replication, deployment pipelines -
    *and* against simulated exfiltration, before anyone trusts them
    operationally. Expect the byte thresholds in particular to be wrong for
    any specific network by an order of magnitude in one direction or the
    other.
    """

    #: Rolling window per pair and per source, in seconds of event time.
    window_seconds: float = 300.0

    #: Originator-side bytes on one pair before the sustained path can fire.
    min_total_orig_bytes: int = 50 * 1024 * 1024  # 50 MiB

    #: Flows on one pair before the sustained path can fire. Chunked
    #: exfiltration is many transfers; this is what makes it "sustained".
    min_flows: int = 10

    #: Originator-side bytes in ONE flow before the single-transfer path
    #: fires. Deliberately far above ``min_total_orig_bytes``: a lone
    #: transfer gets no corroboration from repetition, so it has to be big
    #: enough to stand on its own.
    min_single_flow_orig_bytes: int = 100 * 1024 * 1024  # 100 MiB

    #: Share of the source's total outbound bytes that must go to this one
    #: destination. Required on BOTH paths - a host uploading widely is
    #: doing something ordinary; a host funnelling nearly everything to one
    #: place is the shape worth looking at.
    min_destination_concentration: float = 0.60

    #: After alerting on a pair, stay quiet this long for it - unless the
    #: severity band rises, which always gets through.
    cooldown_seconds: float = 300.0

    #: Multiple of a threshold at which the rule score saturates at 1.0.
    saturation_multiple: float = 4.0

    #: Added to the score at total concentration, scaled from 0 at
    #: ``min_destination_concentration``.
    concentration_bonus: float = 0.10

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.min_total_orig_bytes < 1:
            raise ValueError("min_total_orig_bytes must be at least 1")
        # Two flows are not a "sustained" transfer pattern.
        if self.min_flows < 2:
            raise ValueError("min_flows must be at least 2")
        if self.min_single_flow_orig_bytes < 1:
            raise ValueError("min_single_flow_orig_bytes must be at least 1")
        if not 0.0 < self.min_destination_concentration <= 1.0:
            raise ValueError(
                "min_destination_concentration must be within (0.0, 1.0]"
            )
        if self.cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")
        if self.saturation_multiple <= 1:
            raise ValueError("saturation_multiple must be greater than 1")
        if not 0.0 <= self.concentration_bonus <= 1.0:
            raise ValueError("concentration_bonus must be within [0.0, 1.0]")


@dataclass
class _PairState:
    """Per-pair bookkeeping the windows themselves do not hold."""

    last_alert_at: float | None = None
    last_severity: Severity | None = None


class DataExfiltrationDetector(Detector):
    """Flags a host sending a lot of data, concentrated on one destination.

    A pair qualifies by either route, and both require concentration:

    * **sustained** - ``pair_orig_bytes >= min_total_orig_bytes`` AND
      ``flow_count >= min_flows`` AND concentration. Data leaving in chunks.
    * **single large transfer** -
      ``max_single_flow_orig_bytes >= min_single_flow_orig_bytes`` AND
      concentration. One bulk upload, which needs no repetition to be worth
      seeing.

    Concentration gates both paths because volume alone is a poor signal:
    a backup client legitimately moves gigabytes, and so does a developer
    pushing a repository. What is less ordinary is a host whose outbound
    traffic is overwhelmingly aimed at a single peer.

    Nothing here reads ``resp_bytes`` for any threshold or score, so a large
    download cannot qualify a pair no matter how big it is.
    """

    name = "data_exfiltration"
    version = "0.1.0"

    def __init__(self, config: DataExfiltrationConfig | None = None) -> None:
        self.config = config or DataExfiltrationConfig()
        # Two views of the same flows, on the same window length, so the
        # ratio between them is always measured over the same time span.
        self._pairs = WindowIndex(self.config.window_seconds)
        self._sources = WindowIndex(self.config.window_seconds)
        self._state: dict[ExfilKey, _PairState] = {}
        self._since_sweep = 0

    # --- detection ------------------------------------------------------

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        """Update this pair's and this source's windows, then judge the pair."""
        key = ExfilKey.from_flow(flow)
        observation = FlowObservation.from_flow(flow)

        pair_window = self._pairs.observe(key, observation)
        source_window = self._sources.observe(flow.src_ip, observation)
        # On every flow, not only when alerting: a pair that alerts once and
        # then goes quiet must still have its cooldown released eventually.
        self._sweep_cooldowns(flow.timestamp)

        stats = self._aggregate(flow, pair_window, source_window)
        sustained, single = self._qualifies(stats)
        if not (sustained or single):
            return []

        score = self._rule_score(stats, sustained, single)
        severity = severity_for(score)
        if not self._should_emit(key, flow.timestamp, severity):
            return []

        state = self._state.setdefault(key, _PairState())
        state.last_alert_at = flow.timestamp
        state.last_severity = severity

        return [
            self._build_alert(
                key=key,
                pair_window=pair_window,
                stats=stats,
                sustained=sustained,
                single=single,
                score=score,
                severity=severity,
            )
        ]

    def flush(self) -> list[ThreatAlert]:
        """Nothing is ever held back - ``process()`` already alerted."""
        return []

    def reset(self) -> None:
        """Drop every pair window, source window, cooldown and escalation."""
        self._pairs.clear()
        self._sources.clear()
        self._state.clear()
        self._since_sweep = 0

    # --- aggregation ----------------------------------------------------

    def _aggregate(
        self, flow: FlowEvent, pair_window: ActivityWindow, source_window: ActivityWindow
    ) -> ExfilStats:
        """Measure the pair, and the source that contains it.

        Both windows are expired to the *same* instant before anything is
        read. ``WindowIndex.observe`` has already trimmed each one to this
        flow's timestamp, so these calls are no-ops today - they are here to
        keep the invariant local and enforced rather than inherited from
        another module's internals. If the two windows were ever trimmed to
        different instants, the pair could hold bytes the source had already
        dropped and ``destination_concentration`` would exceed 1.0.
        """
        pair_window.expire(flow.timestamp)
        source_window.expire(flow.timestamp)

        pair_bytes = pair_window.total_orig_bytes()
        source_bytes = source_window.total_orig_bytes()
        span = pair_window.time_span() or (flow.timestamp, flow.timestamp)

        return ExfilStats(
            flow_count=pair_window.attempts,
            pair_orig_bytes=pair_bytes,
            pair_orig_packets=pair_window.total_orig_packets(),
            max_single_flow_orig_bytes=pair_window.max_orig_bytes(),
            source_orig_bytes=source_bytes,
            destination_concentration=self._concentration(pair_bytes, source_bytes),
            pair_resp_bytes=pair_window.total_resp_bytes(),
            time_span=span,
            observed_span_seconds=pair_window.duration(),
        )

    @staticmethod
    def _concentration(pair_bytes: int, source_bytes: int) -> float:
        """Share of a source's outbound bytes aimed at one destination.

        Zero when the source sent nothing: with no outbound data there is no
        concentration to measure, and 0.0 is the reading that cannot
        qualify. Returning 1.0 - or dividing by an epsilon - would let a
        pair that moved no data at all clear the concentration gate, which
        is precisely backwards.

        The result is clamped as well as being structurally bounded: every
        byte on the pair is also on the source, over windows trimmed to the
        same instant, so the ratio cannot exceed 1.0. The clamp is there so
        that if that invariant is ever broken upstream, the failure is a
        capped score rather than a concentration of 1.4.
        """
        if source_bytes <= 0:
            return 0.0
        return min(pair_bytes / source_bytes, 1.0)

    def _qualifies(self, stats: ExfilStats) -> tuple[bool, bool]:
        """``(sustained, single_large_transfer)``. Concentration gates both."""
        config = self.config
        concentrated = (
            stats.destination_concentration >= config.min_destination_concentration
        )
        if not concentrated:
            return False, False

        sustained = (
            stats.pair_orig_bytes >= config.min_total_orig_bytes
            and stats.flow_count >= config.min_flows
        )
        single = (
            stats.max_single_flow_orig_bytes >= config.min_single_flow_orig_bytes
        )
        return sustained, single

    @staticmethod
    def _path(sustained: bool, single: bool) -> str:
        if sustained and single:
            return QUALIFICATION_BOTH
        return QUALIFICATION_SUSTAINED if sustained else QUALIFICATION_SINGLE

    # --- scoring --------------------------------------------------------

    def _rule_score(self, stats: ExfilStats, sustained: bool, single: bool) -> float:
        """Deterministic 0.0-1.0 rule score. Not a calibrated probability.

        Explicit threshold logic, hence ``rule_score``: nothing here models a
        distribution of normal upload behaviour.

        Each qualifying path contributes how far past its thresholds it sits.
        The sustained path averages its two ratios - bytes and flow count -
        so a bigger transfer or a longer-running one both raise the score
        while neither alone can saturate it. The single-transfer path uses
        its one ratio directly, so it scores sensibly without ever needing
        many flows. The stronger path wins.

        Component ratios are capped at ``saturation_multiple`` *before* being
        averaged, so a pair with a huge flow count but borderline volume
        cannot ride one runaway component to critical.

        That maps onto the project's usual curve - exactly at threshold
        scores 0.5, ``saturation_multiple`` times it scores 1.0 - and
        concentration then adds up to ``concentration_bonus`` on top, scaled
        from 0 at ``min_destination_concentration`` to full at 1.0. Nothing
        in this calculation reads ``resp_bytes``.
        """
        config = self.config
        cap = config.saturation_multiple

        ratios: list[float] = []
        if sustained:
            byte_ratio = min(stats.pair_orig_bytes / config.min_total_orig_bytes, cap)
            flow_ratio = min(stats.flow_count / config.min_flows, cap)
            ratios.append((byte_ratio + flow_ratio) / 2.0)
        if single:
            ratios.append(
                min(
                    stats.max_single_flow_orig_bytes
                    / config.min_single_flow_orig_bytes,
                    cap,
                )
            )

        ratio = max(ratios)
        score = 0.5 + 0.5 * (ratio - 1.0) / (cap - 1.0)

        headroom = 1.0 - config.min_destination_concentration
        if headroom <= 0:
            # Threshold is 1.0, so qualifying already means total concentration.
            concentration_strength = 1.0
        else:
            concentration_strength = (
                stats.destination_concentration - config.min_destination_concentration
            ) / headroom
        score += config.concentration_bonus * min(max(concentration_strength, 0.0), 1.0)

        return normalize_score(score)

    @staticmethod
    def _severity(score: float) -> Severity:
        """Project-standard severity bands - see ``scoring.severity_for``."""
        return severity_for(score)

    # --- cooldown -------------------------------------------------------

    def _should_emit(self, key: ExfilKey, now: float, severity: Severity) -> bool:
        """Cooldown, with an escape hatch for genuine escalation.

        A pair that has just alerted stays quiet for ``cooldown_seconds`` -
        unless the transfer has grown into a strictly higher severity band,
        which is news worth interrupting for. A rising score inside the same
        band is not: that would be the alert spam the cooldown exists to
        stop.
        """
        state = self._state.get(key)
        if state is None or state.last_alert_at is None:
            return True
        if (now - state.last_alert_at) >= self.config.cooldown_seconds:
            return True
        if state.last_severity is None:
            return True
        return severity_rank(severity) > severity_rank(state.last_severity)

    def _sweep_cooldowns(self, now: float, every: int = 500) -> None:
        """Release cooldowns that can no longer suppress anything.

        A pair's cooldown deliberately outlives its traffic window: with
        ``cooldown_seconds`` longer than ``window_seconds`` a pair could
        otherwise go quiet, come back, and immediately re-alert inside the
        cooldown it was still serving. So entries are dropped on elapsed
        cooldown, not on an empty window - which still bounds the dict,
        since only pairs that actually alerted ever get an entry.
        (``WindowIndex`` sweeps the far larger window dicts itself.)
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

    # --- alert ----------------------------------------------------------

    @staticmethod
    def _only(values: set) -> object | None:
        """The single member of a set, or None when it is not unambiguous.

        Keeps us honest: a transfer spread over several ports reports
        ``dst_port: None`` rather than inventing a placeholder.
        """
        return next(iter(values)) if len(values) == 1 else None

    @staticmethod
    def _rate(count: int, duration: float) -> float | None:
        """Bytes per second, or None when the window spans no event time.

        A window holding one flow - or several sharing a timestamp - has no
        measurable rate. ``None`` is the honest answer; dividing by a fudged
        epsilon is how ingestion ends up publishing ``flow_rate: 1000000.0``
        on its first record.
        """
        if duration <= 0:
            return None
        return count / duration

    def _build_alert(
        self,
        *,
        key: ExfilKey,
        pair_window: ActivityWindow,
        stats: ExfilStats,
        sustained: bool,
        single: bool,
        score: float,
        severity: Severity,
    ) -> ThreatAlert:
        config = self.config

        return ThreatAlert(
            event_start=epoch_to_utc(stats.time_span[0]),
            event_end=epoch_to_utc(stats.time_span[1]),
            event_scope=EventScope.HOST_PAIR,
            flow_id=None,
            # Straight off the key - the alert describes exactly the pair
            # whose bytes were counted.
            src_ip=key.src_ip,
            dst_ip=key.dst_ip,
            # Populated only when every contributing flow agrees.
            dst_port=self._only(pair_window.dst_ports()),
            protocol=self._only(pair_window.protocols()),
            threat_class=ThreatClass.DATA_EXFILTRATION,
            severity=severity,
            score=score,
            score_type=ScoreType.RULE_SCORE,
            evidence={
                # --- why it fired -----------------------------------------
                "qualification_path": self._path(sustained, single),
                "flow_count": stats.flow_count,
                # Originator-side only - see the module docstring.
                "total_orig_bytes": stats.pair_orig_bytes,
                "total_orig_packets": stats.pair_orig_packets,
                "max_single_flow_orig_bytes": stats.max_single_flow_orig_bytes,
                "source_total_orig_bytes": stats.source_orig_bytes,
                "destination_concentration": stats.destination_concentration,
                # --- context: reported, never scored ----------------------
                # Present so an analyst can see a big upload for what it is.
                # A large value here is a *download* and gates nothing; it
                # may legitimately be 0 on unidirectional traffic.
                "total_resp_bytes": stats.pair_resp_bytes,
                "observed_span_seconds": stats.observed_span_seconds,
                "orig_bytes_per_second": self._rate(
                    stats.pair_orig_bytes, stats.observed_span_seconds
                ),
                # --- thresholds this verdict was measured against ---------
                "window_seconds": config.window_seconds,
                "min_total_orig_bytes": config.min_total_orig_bytes,
                "min_flows": config.min_flows,
                "min_single_flow_orig_bytes": config.min_single_flow_orig_bytes,
                "min_destination_concentration": config.min_destination_concentration,
            },
            detector=self.name,
            detector_version=self.version,
            mitre_techniques=list(MITRE_BY_CLASS[ThreatClass.DATA_EXFILTRATION]),
        )
