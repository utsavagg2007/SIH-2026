"""C2 beaconing detector - repeated, unusually regular outbound contact.

Malware checking in with a controller tends to do so on a timer. This
detector looks for one source contacting one remote endpoint over and over
at suspiciously even intervals.

State is keyed by the full communication relationship
``(src_ip, dst_ip, dst_port, proto)``, so two different conversations never
pool their timing. Near-real-time: the decision happens inside
:meth:`C2BeaconingDetector.process` and fires as soon as the relationship
becomes both long enough and regular enough. ``flush()`` is not part of
normal detection.

Intervals are computed here from ``FlowEvent.timestamp``, never from
ingestion's ``inter_arrival_mean`` / ``inter_arrival_stddev`` (which are
global, not per-relationship, and still being corrected upstream).

**This is a heuristic signal, not proof of malware.** Plenty of benign
software beacons: health checks, update pollers, telemetry agents,
keep-alives, monitoring probes. An alert here means "this relationship looks
machine-timed", which is a lead to investigate, not a verdict.
"""

from __future__ import annotations

import statistics
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

__all__ = ["BeaconKey", "C2BeaconingConfig", "C2BeaconingDetector"]


@dataclass(frozen=True)
class BeaconKey:
    """One communication relationship.

    Frozen, so it hashes - two relationships differing in any field are
    different keys and never share timing state. ``dst_port`` and ``proto``
    stay ``None`` when unknown rather than collapsing onto a fake port 0.
    """

    src_ip: str
    dst_ip: str
    dst_port: int | None
    proto: str | None

    @classmethod
    def from_flow(cls, flow: FlowEvent) -> BeaconKey:
        return cls(
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            proto=flow.proto,
        )


@dataclass(frozen=True)
class IntervalStats:
    """Timing summary for one relationship's rolling history."""

    observation_count: int
    interval_count: int
    mean_interval: float
    stddev_interval: float
    #: stddev / mean. Lower means more regular, so *more* suspicious.
    coefficient_of_variation: float


@dataclass(frozen=True)
class C2BeaconingConfig:
    """Thresholds for :class:`C2BeaconingDetector`. Every value is tunable.

    These defaults are **initial heuristics, not operationally tuned
    values**. They were chosen so an obvious fixed-interval beacon fires
    while ordinary bursty traffic does not, and they must be re-evaluated
    against captures of this network's benign periodic services *and* real
    C2 traffic before anyone trusts them.
    """

    #: Rolling history per relationship, in seconds of event time.
    window_seconds: float = 900.0

    #: Contacts needed before periodicity is assessed at all.
    min_observations: int = 6

    #: Faster than this and it is more likely a keep-alive, a protocol timer
    #: or streaming than a controller check-in.
    min_mean_interval_seconds: float = 2.0

    #: Slower than this cannot accumulate enough history in the window to
    #: judge, and drifts into ordinary scheduled-task territory.
    max_mean_interval_seconds: float = 120.0

    #: Maximum coefficient of variation still considered "regular".
    #: 0.20 means the spread of intervals is within ~20% of their mean.
    max_interval_cv: float = 0.20

    #: After alerting on a relationship, stay quiet this long for it -
    #: unless the severity band rises, which always gets through.
    cooldown_seconds: float = 300.0

    #: Multiple of ``min_observations`` at which persistence saturates.
    saturation_multiple: float = 4.0

    #: How much of the score regularity carries versus persistence.
    #: Periodicity is the core signal, so it weighs more.
    regularity_weight: float = 0.6

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        # 3 observations give 2 intervals - the minimum for a spread to mean
        # anything at all. A CV over a single interval is always 0.
        if self.min_observations < 3:
            raise ValueError("min_observations must be at least 3")
        if self.min_mean_interval_seconds <= 0:
            raise ValueError("min_mean_interval_seconds must be positive")
        if self.max_mean_interval_seconds <= self.min_mean_interval_seconds:
            raise ValueError(
                "max_mean_interval_seconds must exceed min_mean_interval_seconds"
            )
        if self.max_interval_cv < 0:
            raise ValueError("max_interval_cv must not be negative")
        if self.cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")
        if self.saturation_multiple <= 1:
            raise ValueError("saturation_multiple must be greater than 1")
        if not 0.0 <= self.regularity_weight <= 1.0:
            raise ValueError("regularity_weight must be within [0.0, 1.0]")


@dataclass
class _BeaconState:
    """Per-relationship bookkeeping the window itself does not hold."""

    last_alert_at: float | None = None
    last_severity: Severity | None = None


class C2BeaconingDetector(Detector):
    """Flags one source contacting one endpoint on a suspiciously even timer.

    A relationship qualifies only when all of these hold inside the window:

    * **persistence** - ``observation_count >= min_observations``, *and*
      ``interval_count >= min_observations - 1`` genuinely usable intervals.
      Duplicate timestamps therefore cannot pad a relationship over the bar.
    * **plausible cadence** - the mean interval sits within
      ``[min_mean_interval_seconds, max_mean_interval_seconds]``
    * **regularity** - ``coefficient_of_variation <= max_interval_cv``

    Repetition alone is never enough; a chatty relationship with ragged
    timing does not qualify. Volume is reported as evidence but deliberately
    does not gate anything - real C2 transfers vary, and requiring small
    payloads would miss it.
    """

    name = "c2_beaconing"
    version = "0.1.0"

    def __init__(self, config: C2BeaconingConfig | None = None) -> None:
        self.config = config or C2BeaconingConfig()
        self._windows = WindowIndex(self.config.window_seconds)
        self._state: dict[BeaconKey, _BeaconState] = {}
        self._since_sweep = 0

    # --- detection ------------------------------------------------------

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        """Update this relationship's history and alert if it looks timed."""
        key = BeaconKey.from_flow(flow)
        window = self._windows.observe(key, FlowObservation.from_flow(flow))
        # On every flow, not only when alerting: a relationship that alerts
        # once and then goes quiet must still have its cooldown released.
        self._sweep_cooldowns(flow.timestamp)

        stats = self._interval_stats(window.timestamps())
        if stats is None or not self._qualifies(stats):
            return []

        score = self._rule_score(stats)
        severity = severity_for(score)
        if not self._should_emit(key, flow.timestamp, severity):
            return []

        alert = self._build_alert(key, window, stats, score, severity)

        # Only once the alert exists. If building or validating it raises,
        # nothing was emitted, so nothing may enter the cooldown - otherwise
        # the failure would also silence the next several real beacons.
        state = self._state.setdefault(key, _BeaconState())
        state.last_alert_at = flow.timestamp
        state.last_severity = severity
        return [alert]

    def flush(self) -> list[ThreatAlert]:
        """Nothing is ever held back - ``process()`` already alerted."""
        return []

    def reset(self) -> None:
        """Drop every relationship's history, cooldown and escalation state."""
        self._windows.clear()
        self._state.clear()
        self._since_sweep = 0

    # --- timing ---------------------------------------------------------

    def _interval_stats(self, timestamps: list[float]) -> IntervalStats | None:
        """Summarize the gaps between consecutive contacts.

        Only strictly positive gaps are used, so duplicate timestamps (and
        any mildly out-of-order arrival) are skipped rather than producing a
        zero or negative interval. Returns ``None`` when there is not enough
        left to say anything - which is also what keeps the CV division
        safe, since a positive mean is guaranteed by construction.
        """
        if len(timestamps) < 2:
            return None

        intervals = [
            later - earlier
            for earlier, later in zip(timestamps, timestamps[1:])
            if later - earlier > 0
        ]
        if len(intervals) < 2:
            return None

        mean = statistics.fmean(intervals)
        if mean <= 0:  # unreachable given the filter above, but never divide blind
            return None

        stddev = statistics.pstdev(intervals)
        return IntervalStats(
            observation_count=len(timestamps),
            interval_count=len(intervals),
            mean_interval=mean,
            stddev_interval=stddev,
            coefficient_of_variation=stddev / mean,
        )

    def _qualifies(self, stats: IntervalStats) -> bool:
        """Persistence, usable timing, plausible cadence, and regularity.

        Persistence is checked twice on purpose. Raw contacts must reach
        ``min_observations``, *and* they must yield
        ``min_observations - 1`` genuinely usable intervals. Zero-length gaps
        (duplicate timestamps) are dropped from the interval list, so without
        the second check a relationship could clear the bar on contact count
        while the timing verdict rested on fewer measurements than intended -
        and this is a timing detector, so the intervals are the evidence.
        """
        config = self.config
        return (
            stats.observation_count >= config.min_observations
            and stats.interval_count >= config.min_observations - 1
            and config.min_mean_interval_seconds
            <= stats.mean_interval
            <= config.max_mean_interval_seconds
            and stats.coefficient_of_variation <= config.max_interval_cv
        )

    # --- scoring --------------------------------------------------------

    def _rule_score(self, stats: IntervalStats) -> float:
        """Deterministic 0.0-1.0 rule score. Not a calibrated probability.

        Two components, each 0 at the qualification boundary and 1 at its
        strongest:

        * **regularity** - 0 at ``max_interval_cv``, 1 at a perfectly even
          interval (CV 0).
        * **persistence** - 0 at ``min_observations``, 1 once the history
          reaches ``saturation_multiple`` times that.

        Their weighted blend is mapped onto the project's usual curve, so a
        relationship that has only just qualified scores 0.5 and the
        strongest possible beacon scores 1.0.

        Persistence counts *usable* observations - the ones that actually
        produced an interval - not raw contacts. A duplicate timestamp
        contributes no timing evidence, so it must not raise the score or
        push a relationship into a higher severity band. For a clean beacon
        ``interval_count + 1`` is exactly ``observation_count``, so this
        leaves ordinary scoring untouched.
        """
        config = self.config

        if config.max_interval_cv <= 0:
            regularity = 1.0 if stats.coefficient_of_variation == 0 else 0.0
        else:
            regularity = 1.0 - stats.coefficient_of_variation / config.max_interval_cv
        regularity = min(max(regularity, 0.0), 1.0)

        usable_observations = stats.interval_count + 1
        growth = usable_observations / config.min_observations - 1.0
        persistence = growth / (config.saturation_multiple - 1.0)
        persistence = min(max(persistence, 0.0), 1.0)

        weight = config.regularity_weight
        strength = weight * regularity + (1.0 - weight) * persistence
        return normalize_score(0.5 + 0.5 * strength)

    @staticmethod
    def _severity(score: float) -> Severity:
        """Project-standard severity bands - see ``scoring.severity_for``."""
        return severity_for(score)

    # --- cooldown -------------------------------------------------------

    def _should_emit(self, key: BeaconKey, now: float, severity: Severity) -> bool:
        """Cooldown, with an escape hatch for genuine escalation.

        A relationship that has just alerted stays quiet for
        ``cooldown_seconds`` - unless the beacon has grown into a strictly
        higher severity band. A rising score inside the same band is not
        news: that would be the alert spam the cooldown exists to stop.
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

        A relationship's cooldown can outlive its own history: a beacon that
        stops leaves an entry no window expiry would ever clear, and a key
        here is a full ``(src, dst, port, proto)`` tuple - the widest key
        space of the three rolling detectors. Entries are therefore dropped
        on elapsed cooldown, never on an empty window, which still bounds the
        dict since only relationships that actually alerted ever get an entry.
        (``WindowIndex`` sweeps the far larger window dict itself.)

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

    # --- alert ----------------------------------------------------------

    def _build_alert(
        self,
        key: BeaconKey,
        window,
        stats: IntervalStats,
        score: float,
        severity: Severity,
    ) -> ThreatAlert:
        span = window.time_span()
        orig_bytes = window.total_orig_bytes()
        orig_packets = window.total_orig_packets()
        config = self.config

        return ThreatAlert(
            event_start=epoch_to_utc(span[0]),
            event_end=epoch_to_utc(span[1]),
            event_scope=EventScope.HOST_PAIR,
            flow_id=None,
            # Straight off the beacon key - the alert describes exactly the
            # relationship whose timing was measured.
            src_ip=key.src_ip,
            dst_ip=key.dst_ip,
            dst_port=key.dst_port,
            protocol=key.proto,
            threat_class=ThreatClass.C2_BEACONING,
            severity=severity,
            score=score,
            score_type=ScoreType.RULE_SCORE,
            evidence={
                "observation_count": stats.observation_count,
                "interval_count": stats.interval_count,
                "mean_interval_seconds": stats.mean_interval,
                "interval_stddev_seconds": stats.stddev_interval,
                "coefficient_of_variation": stats.coefficient_of_variation,
                "window_seconds": config.window_seconds,
                "min_observations": config.min_observations,
                "min_mean_interval_seconds": config.min_mean_interval_seconds,
                "max_mean_interval_seconds": config.max_mean_interval_seconds,
                "max_interval_cv": config.max_interval_cv,
                # Context only - volume gates nothing here.
                "total_orig_bytes": orig_bytes,
                "total_orig_packets": orig_packets,
                "average_orig_bytes_per_flow": (
                    orig_bytes / stats.observation_count
                    if stats.observation_count
                    else None
                ),
            },
            detector=self.name,
            detector_version=self.version,
            mitre_techniques=list(MITRE_BY_CLASS[ThreatClass.C2_BEACONING]),
        )
