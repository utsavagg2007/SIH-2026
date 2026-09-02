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

import ipaddress
import math
import statistics
from collections import deque
from collections.abc import Sequence
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


def _is_multicast_or_broadcast(address: str) -> bool:
    """Is this an address no single host owns?

    Multicast groups (``224.0.0.0/4``, ``ff00::/8``) and the all-ones IPv4
    broadcast are destinations you *announce to*, not endpoints you hold a
    session with. A controller cannot live at one.

    An unparseable address is not treated as multicast: it is unknown, and
    guessing would silence a relationship on the strength of a typo.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_multicast or (parsed.version == 4 and parsed == _IPV4_BROADCAST)


_IPV4_BROADCAST = ipaddress.IPv4Address("255.255.255.255")


def _population_stddev(values: Sequence[float], mean: float) -> float:
    """Population standard deviation of ``values``, given their mean.

    The textbook two-pass formula, and it replaced ``statistics.pstdev``
    purely for speed: profiling put ``statistics._ss`` and its
    ``_exact_ratio`` / ``as_integer_ratio`` machinery among the hottest
    functions in the whole detection layer. ``pstdev`` converts every value
    to an exact Fraction to guarantee a correctly-rounded result - excellent
    for a statistics library, far more than a coefficient of variation
    compared against 0.20 needs.

    Two-pass, not the ``sum(x^2)/n - mean^2`` shortcut: that shortcut
    subtracts two large nearly-equal numbers and loses most of its
    significant digits on tightly-clustered intervals, which is exactly the
    input this detector cares about. Summing squared deviations from the
    mean has no such cancellation.

    ``tests/test_c2_interval_equivalence.py`` compares this against
    ``statistics.pstdev`` across beacon shapes and pins that the CV
    boundary decision never differs.
    """
    count = len(values)
    total = 0.0
    for value in values:
        deviation = value - mean
        total += deviation * deviation
    return math.sqrt(total / count)


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

    #: Destination ports whose traffic is periodic by design. A time daemon
    #: polls its server every 64 seconds forever, which is a *more* perfect
    #: beacon than most real C2 - measured here at CV 0.003 against 0.034 for
    #: the genuine channel - so no timing threshold can separate them. The
    #: service is what separates them.
    #:
    #: Widened past NTP after measuring against 529k flows of a real benign
    #: capture, where 67 of 156 false positives were one of these services:
    #:
    #: * ``123`` NTP - a time daemon on a fixed poll.
    #: * ``1900`` SSDP / UPnP, ``5353`` mDNS, ``5355`` LLMNR - announcement
    #:   and link-local name protocols, periodic by specification.
    #: * ``137`` / ``138`` NetBIOS name and datagram service - broadcast name
    #:   resolution on a timer.
    #: * ``389`` / ``636`` LDAP(S) and ``3268`` / ``3269`` Global Catalog -
    #:   workstations polling a directory controller. A single domain
    #:   controller accounted for 38 false positives - 37 of them on these
    #:   ports, plus one on ``445``, which is deliberately not excluded.
    #: * ``67`` / ``68`` DHCP - lease renewal, a timer by definition.
    #:
    #: **Deliberately absent**, though they also produced false positives:
    #: ``53`` (DNS) and ``445`` (SMB). Both are real C2 and lateral-movement
    #: channels, and the cost of excluding them was measured rather than
    #: argued: re-scoring the labelled Ares-bot capture with port 53 removed
    #: drops 36 of the 90 true positives and a whole episode with them
    #: (recall 0.750 -> 0.625); removing ``445`` costs two more. That is a
    #: genuine detection traded for a cosmetic false-positive count.
    ignored_dst_ports: frozenset[int] = frozenset(
        {67, 68, 123, 137, 138, 389, 636, 1900, 3268, 3269, 5353, 5355}
    )

    #: Skip multicast and broadcast destinations. A controller is a host you
    #: hold a session with; a multicast group is an address nobody owns and
    #: everyone receives. SSDP, mDNS and LLMNR announce on a timer to
    #: ``239.255.255.250`` and friends forever, which is a textbook beacon
    #: shape with no controller behind it - 30 false positives on the real
    #: benign capture were exactly this.
    #:
    #: **Measured contribution on that capture: zero.** All 30 were SSDP, so
    #: ``1900`` had already excluded them. Kept anyway, because it says
    #: something the port list cannot: a multicast group is not a controller
    #: whatever port it uses, and the port list is meant to be edited per site
    #: while that fact is not.
    ignore_multicast_destinations: bool = True

    #: A controller check-in is small: it asks for work and gets a short
    #: answer. Scheduled bulk transfer - a nightly backup, or exfiltration on
    #: a timer - is just as regular and orders of magnitude larger, and it is
    #: the exfiltration detector's finding, not this one's.
    max_mean_orig_bytes_per_flow: float = 65_536.0

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
        if self.max_mean_orig_bytes_per_flow <= 0:
            raise ValueError("max_mean_orig_bytes_per_flow must be positive")
        if self.cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")
        if self.saturation_multiple <= 1:
            raise ValueError("saturation_multiple must be greater than 1")
        if not 0.0 <= self.regularity_weight <= 1.0:
            raise ValueError("regularity_weight must be within [0.0, 1.0]")
        # Checked because this list is meant to be edited per site: which
        # services count as periodic-by-design is a property of the network,
        # not of the detector. A typo'd port should fail at startup rather
        # than quietly exclude nothing.
        if any(not 0 <= port <= 65535 for port in self.ignored_dst_ports):
            raise ValueError("ignored_dst_ports must all be within [0, 65535]")


#: Mirrors are only pruned once they exceed twice the live windows plus this
#: slack, so a small or steady key set never pays for a scan.
_MIRROR_SLACK = 64


class _IntervalState:
    """One relationship's timestamps and the gaps between them.

    A mirror of the resident timestamps in that relationship's
    :class:`~detection_core.aggregators.ActivityWindow`, carried alongside
    the adjacent intervals derived from them, so a new flow appends one
    interval instead of rebuilding the whole sequence. Profiling after the
    window optimization left this reconstruction as the last per-flow O(n)
    cost in the detection layer.

    Three sequences, kept in step:

    * ``timestamps`` - what the window holds, in arrival order.
    * ``raw`` - the gap between each adjacent pair, so ``len(raw)`` is
      ``len(timestamps) - 1``. **Every** gap is kept, including the zero and
      negative ones, because expiry needs to know which interval a departing
      timestamp owned. Dropping them would lose exactly the structural
      knowledge that keeps the two sequences aligned.
    * ``positive`` - only the gaps greater than zero, in the same order.
      This is the sequence the statistics are computed over, and it is
      element-for-element what the previous implementation rebuilt on every
      flow: duplicate timestamps (gap 0) and out-of-order arrivals (gap < 0)
      are excluded here exactly as the old filter excluded them.

    Nothing is sorted and nothing is reordered - arrival order is the
    detector's existing semantics and this class preserves it verbatim.
    """

    __slots__ = ("timestamps", "raw", "positive")

    def __init__(self) -> None:
        self.timestamps: deque[float] = deque()
        self.raw: deque[float] = deque()
        self.positive: deque[float] = deque()

    def rebuild(self, timestamps: list[float]) -> None:
        """Recompute everything from the window. The resynchronization path."""
        self.timestamps = deque(timestamps)
        self.raw = deque()
        self.positive = deque()
        for earlier, later in zip(timestamps, timestamps[1:]):
            gap = later - earlier
            self.raw.append(gap)
            if gap > 0:
                self.positive.append(gap)

    def append(self, timestamp: float) -> None:
        """Add one contact, creating exactly one new adjacent interval."""
        if self.timestamps:
            gap = timestamp - self.timestamps[-1]
            self.raw.append(gap)
            if gap > 0:
                self.positive.append(gap)
        self.timestamps.append(timestamp)

    def expire(self, cutoff: float) -> None:
        """Drop timestamps at or before ``cutoff``, and their intervals.

        Removing the oldest timestamp removes exactly the interval joining it
        to the next one - the leftmost entry in ``raw`` - and, when that gap
        was positive, the leftmost entry in ``positive``. The intervals
        between the survivors are untouched, so no gap is ever recomputed
        between two timestamps that were never adjacent.

        The boundary is ``<= cutoff``, matching ``ActivityWindow.expire``
        exactly: half-open, so a timestamp precisely ``window_seconds`` old
        has left.
        """
        while self.timestamps and self.timestamps[0] <= cutoff:
            self.timestamps.popleft()
            if self.raw:
                if self.raw.popleft() > 0:
                    self.positive.popleft()

    def clear(self) -> None:
        self.timestamps.clear()
        self.raw.clear()
        self.positive.clear()


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
    # 0.2.0: the periodic-by-design exclusion covers the directory, name and
    # announcement services as well as NTP, and multicast destinations are
    # skipped outright. Both from real-capture measurement; see the config.
    version = "0.2.0"

    def __init__(self, config: C2BeaconingConfig | None = None) -> None:
        self.config = config or C2BeaconingConfig()
        self._windows = WindowIndex(self.config.window_seconds)
        self._state: dict[BeaconKey, _BeaconState] = {}
        self._intervals: dict[BeaconKey, _IntervalState] = {}
        self._since_sweep = 0

    # --- detection ------------------------------------------------------

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        """Update this relationship's history and alert if it looks timed."""
        key = BeaconKey.from_flow(flow)
        if self._never_a_controller(key):
            # Before the window, not after: a relationship that can never
            # alert should not cost state either.
            return []
        window = self._windows.observe(key, FlowObservation.from_flow(flow))
        # On every flow, not only when alerting: a relationship that alerts
        # once and then goes quiet must still have its cooldown released.
        self._sweep_cooldowns(flow.timestamp)

        stats = self._interval_stats(self._interval_state(key, window, flow.timestamp))
        if stats is None or not self._qualifies(stats):
            return []
        if not self._plausible_check_in_size(window, stats):
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
        self._intervals.clear()
        self._since_sweep = 0

    # --- timing ---------------------------------------------------------

    def _interval_state(
        self, key: BeaconKey, window, now: float
    ) -> _IntervalState:
        """This relationship's intervals, advanced to include ``now``.

        The window remains the authority on what is resident; this only
        mirrors it. The mirror is maintained incrementally - one append and
        whatever expiry the new timestamp forces - and then checked against
        the window's own count. They can legitimately diverge: ``WindowIndex``
        sweeps empty windows out entirely, so a relationship that goes quiet
        long enough gets a *new* window on its next flow while this state
        still remembers the old one. A length mismatch is that case, and the
        answer is simply to rebuild from the window.
        """
        state = self._intervals.get(key)
        if state is None:
            state = self._intervals[key] = _IntervalState()
            state.rebuild(window.timestamps())
            return state

        state.append(now)
        state.expire(now - self.config.window_seconds)
        if len(state.timestamps) != window.attempts:
            state.rebuild(window.timestamps())
        return state

    def _interval_stats(self, state: _IntervalState) -> IntervalStats | None:
        """Summarize the gaps between consecutive contacts.

        Only strictly positive gaps are used, so duplicate timestamps (and
        any mildly out-of-order arrival) are skipped rather than producing a
        zero or negative interval. ``state.positive`` already holds exactly
        those gaps, in the same order the previous implementation produced by
        filtering a freshly-built list, so ``fmean`` and
        :func:`_population_stddev` see identical input and return identical
        values.

        Returns ``None`` when the relationship cannot qualify, which
        includes - but is no longer limited to - having too little to say.
        The gates below are the cheap conjuncts of :meth:`_qualifies`,
        checked in increasing order of cost so that a window failing on
        counts or on cadence never pays for a standard deviation it cannot
        use. ``_qualifies`` still makes the final decision on the completed
        stats, so the thresholds live in exactly one place; ordering the
        checks cannot change the outcome because they are all ANDed.
        """
        config = self.config
        observation_count = len(state.timestamps)
        if observation_count < 2:
            return None

        intervals = state.positive
        interval_count = len(intervals)
        if interval_count < 2:
            return None

        # Persistence, from counts alone - no arithmetic over the window.
        if observation_count < config.min_observations:
            return None
        if interval_count < config.min_observations - 1:
            return None

        mean = statistics.fmean(intervals)
        if mean <= 0:  # unreachable given the filter above, but never divide blind
            return None
        # Cadence, before the spread: a relationship beaconing every 20ms or
        # every hour is out regardless of how regular it is.
        if not (
            config.min_mean_interval_seconds
            <= mean
            <= config.max_mean_interval_seconds
        ):
            return None

        stddev = _population_stddev(intervals, mean)
        return IntervalStats(
            observation_count=observation_count,
            interval_count=interval_count,
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

    def _never_a_controller(self, key: BeaconKey) -> bool:
        """Can this relationship be a controller check-in at all?

        Two structural exclusions, neither of which looks at timing - because
        timing cannot settle them. A time daemon and a beacon are both perfect
        timers, and the benign one is often the *more* regular of the two.

        These suppress rather than rescore: a periodic LDAP poll is not a weak
        beacon, it is not a beacon.

        **A third exclusion was measured and rejected: destination
        popularity.** The idea was that a controller is a private endpoint
        while a benign periodic destination is one many hosts share, so
        suppressing destinations with a wide internal fan-in would cut the
        remainder. It does not survive the data. On CIC-IDS2017 the real Ares
        controller (``205.174.165.73``) was contacted by **5** internal hosts -
        every infected workstation in the lab - while the benign destinations
        this detector still fires on span a fan-in of **1 to 25**. The
        controller sits inside the benign distribution, not beside it, so the
        only cut that preserves the true positives is "6 or more", and that
        number is a fact about a ten-host lab rather than about C2. On a real
        network fan-in scales with the population, and a botnet's does too. The
        measurement is in ``docs/REAL_DATA_EVAL.md``; it is recorded so the
        experiment is not repeated blind.
        """
        config = self.config
        if key.dst_port is not None and key.dst_port in config.ignored_dst_ports:
            return True
        if config.ignore_multicast_destinations and _is_multicast_or_broadcast(
            key.dst_ip
        ):
            return True
        return False

    def _plausible_check_in_size(self, window, stats: IntervalStats) -> bool:
        """Is the average transfer the size of a check-in rather than a payload?

        Regularity alone cannot tell a controller check-in from a nightly
        backup or a transfer on a timer - both are periodic, and the backup is
        often the more regular of the two. Size can: a check-in asks for work
        and gets a short answer, in hundreds of bytes.

        This suppresses rather than rescores, because a large regular transfer
        is not a weak beacon - it is a different finding, and
        ``data_exfiltration`` is the detector that owns it.
        """
        if stats.observation_count <= 0:
            return False
        mean_bytes = window.total_orig_bytes() / stats.observation_count
        return mean_bytes <= self.config.max_mean_orig_bytes_per_flow

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
        # Interval mirrors follow their windows: once ``WindowIndex`` has
        # swept a relationship's window away there is nothing left to mirror,
        # and holding the timestamps would be a slow leak on a long capture.
        #
        # Only when the mirrors have actually outgrown the windows, though.
        # Walking every mirror on every sweep is O(keys) work charged to a
        # capture with many relationships - measurably so at 50k flows - and
        # it buys nothing while the two dicts are the same size. Each pass
        # that does run removes at least half the entries, so the pruning
        # cost stays amortized O(1) per key while memory stays bounded at
        # roughly twice the live window count.
        if len(self._intervals) > 2 * len(self._windows) + _MIRROR_SLACK:
            for key in list(self._intervals):
                if key not in self._windows:
                    del self._intervals[key]

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
