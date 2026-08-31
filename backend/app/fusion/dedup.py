"""Deduplication.

Build Plan layer 5 states the requirement plainly: "A one-hour replay containing
a persistent beacon produces one incident with an occurrence count, not sixty
alerts."  A beacon that fires every sixty seconds for an hour otherwise fills
the dashboard with sixty identical rows and buries everything else.

The rule: repeat findings for the same *entity*, *threat class* and *detector*
inside ``dedup_window_s`` fold into the first alert.  The surviving alert keeps
its original ``alert_id`` and ``first_seen``, and gains an occurrence count, an
extended ``event_end``, and the highest score seen.

Two deliberate choices:

* **Entity, not flow.** Keying on ``flow_id`` would defeat the purpose - every
  beacon check-in is a different flow.  The key is whatever identifies the thing
  the alert is about, which is what ``event_scope`` already tells us.
* **Detector included.** Two detectors independently finding the same beacon is
  corroboration, and collapsing them would hide that.  They dedup separately and
  correlate into one incident downstream.
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict, deque
from dataclasses import dataclass, field

#: How many contributing alert_ids each finding remembers, so a redelivery can
#: be told from a new occurrence.  Bounded on purpose: an hour-long beacon
#: contributes sixty ids and there may be a hundred thousand live findings, so
#: remembering all of them would trade a correctness bug for a memory one.  A
#: retry follows its original closely - detection resends on POST failure - so a
#: short memory catches the case that actually happens, and the ceiling is
#: stated rather than hoped for.
_RECENT_ID_MEMORY = 16

from ..schemas.alert_v11 import ThreatAlertV11
from ..schemas.enums import EventScope


def dedup_key(alert: ThreatAlertV11) -> str:
    """Stable hash identifying "the same finding again".

    Reserved as ``dedup_key`` in a future v1.2 of the alert spec (section 17).
    Computing it here means we get the behaviour now without waiting for the
    contract to change, and a detector that later ships its own can override it.
    """
    scope = alert.event_scope
    if scope is EventScope.FLOW:
        entity = f"flow:{alert.flow_id}"
    elif scope is EventScope.SOURCE_HOST:
        entity = f"src:{alert.src_ip}"
    elif scope is EventScope.DESTINATION_HOST:
        # Port matters here: a flood against :80 and one against :443 are
        # different events on the same host.
        entity = f"dst:{alert.dst_ip}:{alert.dst_port}"
    elif scope is EventScope.HOST_PAIR:
        entity = f"pair:{alert.src_ip}>{alert.dst_ip}:{alert.dst_port}"
    else:
        entity = "network"

    raw = f"{alert.threat_class.value}|{scope.value}|{entity}|{alert.detector}"
    return hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:32]


@dataclass(slots=True)
class DedupState:
    """Everything we remember about one deduplicated finding."""

    alert_id: str
    key: str
    first_seen: float
    last_seen: float
    occurrences: int
    max_score: float
    event_start: float
    event_end: float
    #: Evidence from the most recent occurrence.  The newest observation is the
    #: most useful one to show; the counts below preserve the history that
    #: matters.
    latest_evidence: dict = field(default_factory=dict)
    #: The most recent alert_ids folded into this finding, newest last, capped
    #: at :data:`_RECENT_ID_MEMORY`.  Used to recognise a *resend* of an alert
    #: already counted, as distinct from a genuine new occurrence.
    recent_alert_ids: deque[str] = field(default_factory=lambda: deque(maxlen=_RECENT_ID_MEMORY))


@dataclass(slots=True)
class DedupResult:
    is_duplicate: bool
    state: DedupState


class Deduplicator:
    """Bounded LRU of recent findings.

    Memory is capped by ``max_keys`` with oldest-first eviction.  Unbounded
    growth here would be the same mistake the Downstream Architecture document
    flags in the feature store: under a spoofed flood the key space explodes,
    and the process dies at exactly the moment it is being graded.
    """

    def __init__(self, window_s: float = 300.0, max_keys: int = 100_000) -> None:
        self._window = window_s
        self._max_keys = max_keys
        self._states: OrderedDict[str, DedupState] = OrderedDict()
        #: Highest event time seen. Eviction runs against this rather than the
        #: wall clock - see :meth:`_evict`.
        self._clock: float = 0.0

    def __len__(self) -> int:
        return len(self._states)

    def observe(self, alert: ThreatAlertV11, now: float | None = None) -> DedupResult:
        """Record an alert and say whether it folded into an existing one.

        ``now`` is accepted for callers that want to drive the clock explicitly;
        it is interpreted as *event* time, not wall time, for the reason given
        in :meth:`_evict`.
        """
        key = dedup_key(alert)
        ts = alert.detected_at.timestamp()
        # Event time only. Advancing monotonically means a capture replayed out
        # of order cannot rewind the clock and expire live state.
        self._clock = max(self._clock, ts if now is None else now)

        existing = self._states.get(key)
        if existing is not None and (ts - existing.last_seen) <= self._window:
            if alert.alert_id in existing.recent_alert_ids:
                # A redelivery of an alert already counted, not a new
                # occurrence.  The integration guide states that detection
                # resends after a failed POST and asks the backend to be safe to
                # replay; counting the resend would inflate the number the
                # dashboard shows as "this has happened N times" and the count
                # the incident narrative quotes.  Nothing about the finding has
                # changed, so nothing about the state changes either.
                self._states.move_to_end(key)
                return DedupResult(is_duplicate=True, state=existing)

            existing.recent_alert_ids.append(alert.alert_id)
            existing.occurrences += 1
            existing.last_seen = ts
            existing.max_score = max(existing.max_score, alert.score)
            # The window grows to cover the full span of the repeated activity,
            # so the dashboard shows "this has been going on since 23:30" rather
            # than only the last five seconds of it.
            existing.event_start = min(
                existing.event_start, alert.event_start.timestamp()
            )
            existing.event_end = max(existing.event_end, alert.event_end.timestamp())
            existing.latest_evidence = dict(alert.evidence)
            self._states.move_to_end(key)
            return DedupResult(is_duplicate=True, state=existing)

        state = DedupState(
            alert_id=alert.alert_id,
            key=key,
            first_seen=ts,
            last_seen=ts,
            occurrences=1,
            max_score=alert.score,
            event_start=alert.event_start.timestamp(),
            event_end=alert.event_end.timestamp(),
            latest_evidence=dict(alert.evidence),
        )
        state.recent_alert_ids.append(alert.alert_id)
        self._states[key] = state
        self._states.move_to_end(key)
        self._evict()
        return DedupResult(is_duplicate=False, state=state)

    def _evict(self) -> None:
        """Drop expired entries, then trim to the hard ceiling.

        Time-based expiry runs first because it is the predictable rule; the
        size cap is the backstop for when arrival rate outpaces expiry.  Build
        Plan layer 3: "Expire state on a timer, not on memory pressure.
        Predictable eviction beats clever eviction."

        **Event time, not wall time.**  ``last_seen`` is taken from the alert's
        ``detected_at``, so comparing it against ``time.time()`` mixes two
        clocks that only agree on live traffic.  Replay a capture recorded
        yesterday and every entry is already older than the cutoff the moment it
        is written: the state is evicted on the same call that created it, the
        next repeat finds nothing to fold into, and deduplication silently does
        nothing at all - on precisely the path the demo runs.  The window
        comparison in :meth:`observe` was always event-time; this now matches
        it.
        """
        cutoff = self._clock - self._window
        while self._states:
            oldest_key = next(iter(self._states))
            if self._states[oldest_key].last_seen >= cutoff:
                break
            del self._states[oldest_key]

        while len(self._states) > self._max_keys:
            self._states.popitem(last=False)
