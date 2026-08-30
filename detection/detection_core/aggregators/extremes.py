"""Sliding-window extremes that never rescan.

Every rolling window in this package needs a largest-or-smallest value over
whatever it currently holds: the newest and oldest timestamp for a time
span, the longest query, the highest entropy. Those cannot be undone by
subtraction the way a sum can, so they were cached and recomputed whenever
the cached extreme expired.

That is O(1) right up to the moment a window fills, and then it is not.
Once occupancy reaches the cap - or once the capture simply runs longer
than the window - the oldest observation leaves on *every* flow, so the
cached extreme is invalidated on every flow and the "occasional" rescan
becomes a full scan per flow. Measured on the DNS window at its 5000
observation cap, that was 15 million elements rescanned over 8000 flows,
against zero for the same run at 4000. It is the same O(N^2) shape the
incremental windows exist to remove, hiding one level down.

:class:`WindowExtreme` removes it for good.
"""

from __future__ import annotations

from collections import deque

__all__ = ["WindowExtreme"]


class WindowExtreme:
    """The largest (or smallest) value still resident in a window.

    Keeps a *monotonic* deque of candidates rather than a cache. When a
    value arrives, every queued value it dominates is discarded on the
    spot: an older value that is smaller than the newcomer leaves the
    window first *and* is smaller while both are resident, so it can never
    be the maximum again. What survives is a decreasing run whose front is
    the current maximum, and expiry only ever has to check whether the
    departing observation is that front.

    This is correct only because observations leave in arrival order, which
    is what every window here does - both ``expire`` and the occupancy cap
    drop from the left. The *values* may arrive in any order; nothing here
    assumes timestamps are sorted.

    Amortized O(1) for both operations: each value is appended once and
    discarded once, so the total work over N observations is O(N) however
    the values are arranged. Memory is bounded by the number of resident
    observations, and in practice far below it - a rising series keeps one
    candidate.

    Callers supply a sequence number per observation. Because observations
    leave in arrival order, a plain counter on each side is enough; see
    :class:`~detection_core.aggregators.ActivityWindow` for the pattern.
    """

    __slots__ = ("_entries", "_largest")

    def __init__(self, *, largest: bool = True) -> None:
        # (sequence, value), values monotonic from front to back.
        self._entries: deque[tuple[int, float]] = deque()
        self._largest = largest

    def push(self, sequence: int, value: float) -> None:
        """Record ``value``, arriving as observation ``sequence``."""
        entries = self._entries
        if self._largest:
            while entries and entries[-1][1] <= value:
                entries.pop()
        else:
            while entries and entries[-1][1] >= value:
                entries.pop()
        entries.append((sequence, value))

    def pop(self, sequence: int) -> None:
        """Release observation ``sequence``, if it is still a candidate.

        A no-op when it is not, which is the common case: most values are
        discarded on arrival by a later one that dominates them, and an
        observation that never carried the field never pushed at all. That
        is why this is safe to call unconditionally.
        """
        entries = self._entries
        if entries and entries[0][0] == sequence:
            entries.popleft()

    @property
    def value(self) -> float | None:
        """The current extreme, or ``None`` when nothing is resident."""
        return self._entries[0][1] if self._entries else None

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        """How many candidates are queued - for tests, not for callers."""
        return len(self._entries)
