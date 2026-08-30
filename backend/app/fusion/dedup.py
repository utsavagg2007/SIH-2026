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
import time
from collections import OrderedDict
from dataclasses import dataclass, field

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

    def __len__(self) -> int:
        return len(self._states)

    def observe(self, alert: ThreatAlertV11, now: float | None = None) -> DedupResult:
        """Record an alert and say whether it folded into an existing one."""
        now = time.time() if now is None else now
        key = dedup_key(alert)
        ts = alert.detected_at.timestamp()

        existing = self._states.get(key)
        if existing is not None and (ts - existing.last_seen) <= self._window:
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
        self._states[key] = state
        self._states.move_to_end(key)
        self._evict(now)
        return DedupResult(is_duplicate=False, state=state)

    def _evict(self, now: float) -> None:
        """Drop expired entries, then trim to the hard ceiling.

        Time-based expiry runs first because it is the predictable rule; the
        size cap is the backstop for when arrival rate outpaces expiry.  Build
        Plan layer 3: "Expire state on a timer, not on memory pressure.
        Predictable eviction beats clever eviction."
        """
        cutoff = now - self._window
        while self._states:
            oldest_key = next(iter(self._states))
            if self._states[oldest_key].last_seen >= cutoff:
                break
            del self._states[oldest_key]

        while len(self._states) > self._max_keys:
            self._states.popitem(last=False)
