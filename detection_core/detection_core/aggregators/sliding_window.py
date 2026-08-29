"""Rolling sliding windows, keyed by whatever a detector needs.

Reusable state for any detector asking "what has this key done recently?".
The key is deliberately just a string: port scanning keys by ``src_ip``
("what has this source touched?"), DDoS keys by ``dst_ip`` ("who has been
hitting this host?"). Keys are fully isolated from each other.

Deliberately computed here rather than taken from ingestion's global window
features, which are still being corrected upstream and are not keyed per
entity at all (see SCHEMA.md).

Time comes from ``FlowEvent.timestamp`` (epoch seconds), never wall clock,
so a PCAP replay behaves exactly like a live stream.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Hashable
from dataclasses import dataclass

from ..schemas import FlowEvent

__all__ = ["FlowObservation", "ActivityWindow", "WindowIndex"]


@dataclass(frozen=True)
class FlowObservation:
    """The slice of a flow that windowed detection cares about.

    Volume is stored **originator-side only** - what ``src_ip`` sent toward
    ``dst_ip`` - mirroring ``FlowEvent.orig_bytes`` / ``orig_pkts``. The
    responder counters are deliberately excluded: they are the destination's
    own outbound replies, so folding them in would let a busy-but-normal
    server inflate its way past a volume threshold on the strength of the
    traffic it is serving.

    ``resp_bytes`` is carried too, but strictly as **context**: it is never
    folded into ``total_orig_bytes`` and no volume threshold reads it. It
    exists so a detector can *report* what came back - "this host uploaded
    2 GB and received 4 KB" is a far more legible alert than the upload
    figure alone - without ever letting a download inflate an outbound
    measurement.

    ``FlowEvent`` already guarantees these counters are non-negative
    integers, so they cannot go negative.
    """

    timestamp: float
    dst_ip: str
    dst_port: int | None = None
    proto: str | None = None
    src_ip: str | None = None
    orig_packets: int = 0
    orig_bytes: int = 0
    #: Responder-side volume. Context only - see the class docstring.
    resp_bytes: int = 0

    @classmethod
    def from_flow(cls, flow: FlowEvent) -> FlowObservation:
        return cls(
            timestamp=flow.timestamp,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            proto=flow.proto,
            src_ip=flow.src_ip,
            orig_packets=flow.orig_pkts,
            orig_bytes=flow.orig_bytes,
            resp_bytes=flow.resp_bytes,
        )


class ActivityWindow:
    """Recent observations for ONE key, trimmed to ``window_seconds``.

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

    def src_ips(self) -> set[str]:
        """Distinct source hosts."""
        return {e.src_ip for e in self._events if e.src_ip is not None}

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

    def total_orig_packets(self) -> int:
        """Originator-side packets across every flow still in the window.

        Keyed by destination, this is the packet volume *arriving at* that
        host - not what it sent back. See :class:`FlowObservation`.
        """
        return sum(e.orig_packets for e in self._events)

    def total_orig_bytes(self) -> int:
        """Originator-side bytes across every flow still in the window."""
        return sum(e.orig_bytes for e in self._events)

    def max_orig_bytes(self) -> int:
        """Largest single flow's originator-side bytes, 0 when empty.

        One huge transfer and the same volume dribbled across many small
        flows are different behaviours; a total alone cannot tell them
        apart, so exfiltration-style detection needs the peak as well.
        """
        return max((e.orig_bytes for e in self._events), default=0)

    def total_resp_bytes(self) -> int:
        """Responder-side bytes across the window - **context only**.

        Deliberately separate from :meth:`total_orig_bytes` and never
        summed into it. A 500 MB download must never read as 500 MB of
        outbound data; see :class:`FlowObservation`.
        """
        return sum(e.resp_bytes for e in self._events)

    def protocols(self) -> set[str]:
        return {e.proto for e in self._events if e.proto is not None}

    def timestamps(self) -> list[float]:
        """Observation timestamps, in arrival order.

        Timing analysis (beacon periodicity) reads this. Order is arrival
        order, which the project assumes is roughly non-decreasing event
        time - see the module docstring.
        """
        return [e.timestamp for e in self._events]

    def time_span(self) -> tuple[float, float] | None:
        """(earliest, latest) timestamp in the window, or None if empty."""
        if not self._events:
            return None
        timestamps = [e.timestamp for e in self._events]
        return min(timestamps), max(timestamps)

    def duration(self) -> float:
        """Event-time seconds spanned by the window's contents.

        Zero when the window holds one observation, or several sharing a
        timestamp. Callers computing rates must treat zero as "not
        measurable" rather than dividing by it.
        """
        span = self.time_span()
        return 0.0 if span is None else span[1] - span[0]

    def is_empty(self) -> bool:
        return not self._events

    def clear(self) -> None:
        self._events.clear()

    def __len__(self) -> int:
        return len(self._events)


class WindowIndex:
    """One :class:`ActivityWindow` per key.

    Keys are fully isolated - one key's traffic can never influence another's
    counts. What the key *means* is the detector's choice: source IP for port
    scanning, destination IP for DDoS, a (src, dst, port, proto) tuple for
    beaconing. Any hashable value works, so a composite key needs no
    stringly-typed encoding - which also keeps a ``None`` port distinct from
    every real port instead of collapsing it onto something like 0.
    """

    def __init__(self, window_seconds: float, *, sweep_every: int = 500) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self.sweep_every = sweep_every
        self._windows: dict[Hashable, ActivityWindow] = {}
        self._since_sweep = 0

    def observe(self, key: Hashable, observation: FlowObservation) -> ActivityWindow:
        """Record an observation for ``key`` and return that key's window."""
        window = self._windows.get(key)
        if window is None:
            window = ActivityWindow(self.window_seconds)
            self._windows[key] = window
        window.observe(observation)

        # Keys that go quiet still hold an (empty) window; sweep them out
        # periodically so a long capture with many one-off keys stays bounded.
        self._since_sweep += 1
        if self._since_sweep >= self.sweep_every:
            self._sweep(observation.timestamp)
        return window

    def get(self, key: Hashable) -> ActivityWindow | None:
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
