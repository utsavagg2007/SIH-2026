"""Rolling per-source sliding windows.

Reusable state for any detector that needs "what has this source done
recently?". Deliberately computed here rather than taken from ingestion's
global window features, which are still being corrected upstream and are
not keyed per source (see SCHEMA.md).

Time comes from ``FlowEvent.timestamp`` (epoch seconds), never wall clock,
so a PCAP replay behaves exactly like a live stream.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from ..schemas import FlowEvent

__all__ = ["FlowObservation", "SourceActivityWindow", "SourceWindowIndex"]


@dataclass(frozen=True)
class FlowObservation:
    """The slice of a flow that windowed detection cares about."""

    timestamp: float
    dst_ip: str
    dst_port: int | None = None
    proto: str | None = None

    @classmethod
    def from_flow(cls, flow: FlowEvent) -> FlowObservation:
        return cls(
            timestamp=flow.timestamp,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            proto=flow.proto,
        )


class SourceActivityWindow:
    """Recent observations for ONE source, trimmed to ``window_seconds``.

    The window is half-open: an observation is kept while
    ``now - timestamp < window_seconds``, so one exactly ``window_seconds``
    old has expired.

    Counts are derived by scanning the window rather than maintained
    incrementally. The window is small by construction, and it keeps the
    expiry logic in one place instead of spread across counter bookkeeping.
    """

    def __init__(self, window_seconds: float) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self._events: deque[FlowObservation] = deque()

    def observe(self, observation: FlowObservation) -> None:
        """Record an observation and drop anything it pushed out of the window."""
        self._events.append(observation)
        self.expire(observation.timestamp)

    def expire(self, now: float) -> None:
        """Drop observations older than the window, keeping memory bounded."""
        cutoff = now - self.window_seconds
        while self._events and self._events[0].timestamp <= cutoff:
            self._events.popleft()

    # --- derived views --------------------------------------------------

    @property
    def attempts(self) -> int:
        """Connection attempts still inside the window."""
        return len(self._events)

    def dst_ports(self) -> set[int]:
        """Distinct destination ports. A missing port is not a port."""
        return {e.dst_port for e in self._events if e.dst_port is not None}

    def dst_ips(self) -> set[str]:
        """Distinct destination hosts."""
        return {e.dst_ip for e in self._events}

    def hosts_by_port(self) -> dict[int, set[str]]:
        """Distinct destination hosts, grouped by destination port.

        This is the shape horizontal scanning needs: one source sweeping the
        *same* port across many hosts. Observations without a ``dst_port`` are
        excluded - there is no port to correlate them across hosts.
        """
        grouped: dict[int, set[str]] = {}
        for event in self._events:
            if event.dst_port is None:
                continue
            grouped.setdefault(event.dst_port, set()).add(event.dst_ip)
        return grouped

    def protocols(self) -> set[str]:
        return {e.proto for e in self._events if e.proto is not None}

    def time_span(self) -> tuple[float, float] | None:
        """(earliest, latest) timestamp in the window, or None if empty."""
        if not self._events:
            return None
        timestamps = [e.timestamp for e in self._events]
        return min(timestamps), max(timestamps)

    def is_empty(self) -> bool:
        return not self._events

    def clear(self) -> None:
        self._events.clear()

    def __len__(self) -> int:
        return len(self._events)


class SourceWindowIndex:
    """One :class:`SourceActivityWindow` per source key.

    Sources are fully isolated - one source's traffic can never influence
    another's counts.
    """

    def __init__(self, window_seconds: float, *, sweep_every: int = 500) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self.sweep_every = sweep_every
        self._windows: dict[str, SourceActivityWindow] = {}
        self._since_sweep = 0

    def observe(self, key: str, observation: FlowObservation) -> SourceActivityWindow:
        """Record an observation for ``key`` and return that source's window."""
        window = self._windows.get(key)
        if window is None:
            window = SourceActivityWindow(self.window_seconds)
            self._windows[key] = window
        window.observe(observation)

        # Sources that go quiet still hold an (empty) window; sweep them out
        # periodically so a long capture with many one-off sources stays bounded.
        self._since_sweep += 1
        if self._since_sweep >= self.sweep_every:
            self._sweep(observation.timestamp)
        return window

    def get(self, key: str) -> SourceActivityWindow | None:
        return self._windows.get(key)

    def clear(self) -> None:
        self._windows.clear()
        self._since_sweep = 0

    def _sweep(self, now: float) -> None:
        self._since_sweep = 0
        for key in list(self._windows):
            window = self._windows[key]
            window.expire(now)
            if window.is_empty():
                del self._windows[key]

    def __len__(self) -> int:
        return len(self._windows)

    def __contains__(self, key: object) -> bool:
        return key in self._windows
