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

:class:`ActivityWindow` maintains its counts incrementally rather than
rescanning its deque per call. That is a performance change only: every
observation is still retained until it expires on event time, and every
derived value is exactly what a full scan would return.
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

    Every derived count is maintained **incrementally**: an observation
    updates the aggregates as it enters and reverses those updates as it
    expires, so a read is O(distinct values) instead of O(observations).
    The deque still holds the observations themselves - nothing is dropped,
    approximated or capped - it is only no longer rescanned to answer
    questions it has already answered.

    This replaced a scan-per-call design after profiling showed the rescans
    dominating at high per-key occupancy: repeated ``sum()`` over the deque,
    and ``hosts_by_port`` rebuilding a dict of sets on every flow. The
    observable results are unchanged, which
    ``tests/test_sliding_window_equivalence.py`` pins against a reference
    implementation of the original logic.

    **Distinct values are reference-counted, never stored as a plain set.**
    Two live observations can carry the same ``src_ip``; when one expires the
    address must stay counted, and only disappear when the last one goes. A
    set would forget that.
    """

    def __init__(self, window_seconds: float) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.window_seconds = window_seconds
        self._events: deque[FlowObservation] = deque()
        self._reset_aggregates()

    def _reset_aggregates(self) -> None:
        """Zero every incremental aggregate. The deque is the caller's job."""
        # Additive totals: exact, O(1) to update and to read.
        self._orig_packets_total = 0
        self._orig_bytes_total = 0
        self._resp_bytes_total = 0
        # Reference counts: value -> how many live observations carry it.
        # A zero count is deleted, so the key set is exactly the live values.
        self._dst_port_counts: dict[int, int] = {}
        self._dst_ip_counts: dict[str, int] = {}
        self._src_ip_counts: dict[str, int] = {}
        self._proto_counts: dict[str, int] = {}
        # port -> host -> occurrences. Emptied containers are removed.
        self._hosts_by_port: dict[int, dict[str, int]] = {}
        # How many ports currently reach exactly N distinct hosts, so the
        # widest fanout is a lookup rather than a scan over every port. An
        # emptied bucket is deleted, so the keys are exactly the live fanouts.
        self._fanout_buckets: dict[int, int] = {}
        self._max_fanout: int | None = 0
        # Extremes cannot be undone by subtraction, so they are cached with
        # lazy invalidation: recomputed only when the extreme itself leaves.
        self._orig_bytes_counts: dict[int, int] = {}
        self._max_orig_bytes: int | None = 0
        self._timestamp_counts: dict[float, int] = {}
        self._min_timestamp: float | None = None
        self._max_timestamp: float | None = None

    # --- incremental bookkeeping ----------------------------------------

    @staticmethod
    def _increment(counts: dict, key) -> None:
        counts[key] = counts.get(key, 0) + 1

    @staticmethod
    def _decrement(counts: dict, key) -> None:
        """Drop one reference, deleting the key when the last one goes."""
        remaining = counts[key] - 1
        if remaining:
            counts[key] = remaining
        else:
            del counts[key]

    def _fanout_moved(self, previous: int, current: int) -> None:
        """Record that one port's distinct-host count moved.

        Only called when it really moved: a repeat of a ``(port, host)`` pair
        already seen leaves the port's fanout alone, and so must leave these
        buckets alone.
        """
        if previous:
            self._decrement(self._fanout_buckets, previous)
        if current:
            self._increment(self._fanout_buckets, current)

        if current > previous:
            # Growth can only raise the maximum, and only to this value.
            if self._max_fanout is not None and current > self._max_fanout:
                self._max_fanout = current
        elif previous == self._max_fanout and previous not in self._fanout_buckets:
            # The last port holding the record just lost a host. What the new
            # maximum is depends on the other ports, so recompute on demand.
            self._max_fanout = None

    def _add(self, observation: FlowObservation) -> None:
        """Fold one observation into every aggregate."""
        self._orig_packets_total += observation.orig_packets
        self._orig_bytes_total += observation.orig_bytes
        self._resp_bytes_total += observation.resp_bytes

        self._increment(self._dst_ip_counts, observation.dst_ip)
        if observation.dst_port is not None:
            self._increment(self._dst_port_counts, observation.dst_port)
            # Only ports the observation actually carried: there is no port
            # to correlate a portless flow across hosts.
            hosts = self._hosts_by_port.get(observation.dst_port)
            if hosts is None:
                hosts = self._hosts_by_port[observation.dst_port] = {}
            before = len(hosts)
            self._increment(hosts, observation.dst_ip)
            if len(hosts) != before:  # a host this port had not seen
                self._fanout_moved(before, len(hosts))
        if observation.src_ip is not None:
            self._increment(self._src_ip_counts, observation.src_ip)
        if observation.proto is not None:
            self._increment(self._proto_counts, observation.proto)

        self._increment(self._orig_bytes_counts, observation.orig_bytes)
        if self._max_orig_bytes is not None and observation.orig_bytes > self._max_orig_bytes:
            self._max_orig_bytes = observation.orig_bytes

        self._increment(self._timestamp_counts, observation.timestamp)
        if self._min_timestamp is None or observation.timestamp < self._min_timestamp:
            self._min_timestamp = observation.timestamp
        if self._max_timestamp is None or observation.timestamp > self._max_timestamp:
            self._max_timestamp = observation.timestamp

    def _remove(self, observation: FlowObservation) -> None:
        """Exactly reverse :meth:`_add` for an observation that has expired."""
        self._orig_packets_total -= observation.orig_packets
        self._orig_bytes_total -= observation.orig_bytes
        self._resp_bytes_total -= observation.resp_bytes

        self._decrement(self._dst_ip_counts, observation.dst_ip)
        if observation.dst_port is not None:
            self._decrement(self._dst_port_counts, observation.dst_port)
            hosts = self._hosts_by_port[observation.dst_port]
            before = len(hosts)
            self._decrement(hosts, observation.dst_ip)
            after = len(hosts)
            if after != before:  # that host's last occurrence on this port
                self._fanout_moved(before, after)
            if not hosts:
                del self._hosts_by_port[observation.dst_port]
        if observation.src_ip is not None:
            self._decrement(self._src_ip_counts, observation.src_ip)
        if observation.proto is not None:
            self._decrement(self._proto_counts, observation.proto)

        self._decrement(self._orig_bytes_counts, observation.orig_bytes)
        if observation.orig_bytes not in self._orig_bytes_counts:
            # The largest value may have just left; recompute on next read.
            if self._max_orig_bytes == observation.orig_bytes:
                self._max_orig_bytes = None

        self._decrement(self._timestamp_counts, observation.timestamp)
        if observation.timestamp not in self._timestamp_counts:
            if self._min_timestamp == observation.timestamp:
                self._min_timestamp = None
            if self._max_timestamp == observation.timestamp:
                self._max_timestamp = None

    def observe(self, observation: FlowObservation) -> None:
        """Record an observation and drop anything it pushed out of the window."""
        self._events.append(observation)
        self._add(observation)
        self.expire(observation.timestamp)

    def expire(self, now: float) -> None:
        """Drop observations older than the window, keeping memory bounded."""
        cutoff = now - self.window_seconds
        while self._events and self._events[0].timestamp <= cutoff:
            self._remove(self._events.popleft())

    # --- derived views --------------------------------------------------

    @property
    def attempts(self) -> int:
        """Connection attempts still inside the window."""
        return len(self._events)

    def unique_dst_port_count(self) -> int:
        """How many distinct destination ports are live, without building a set.

        The scalar counterpart to :meth:`dst_ports`, and always equal to
        ``len(self.dst_ports())``. It exists because a detector deciding
        "has this source touched enough ports?" needs the number, not the
        ports - and materializing a set of every port on every flow is
        exactly the work a port scan makes expensive, since a scan's whole
        character is that each flow brings a port nobody has seen.
        """
        return len(self._dst_port_counts)

    def unique_dst_ip_count(self) -> int:
        """Distinct destination hosts, as a number. See above."""
        return len(self._dst_ip_counts)

    def unique_src_ip_count(self) -> int:
        """Distinct source hosts, as a number - what a flood grows."""
        return len(self._src_ip_counts)

    def unique_protocol_count(self) -> int:
        """Distinct protocols, as a number."""
        return len(self._proto_counts)

    def max_hosts_per_port(self) -> int:
        """Widest distinct-host fanout reached by any single port, 0 if none.

        Always equal to ``max((len(h) for h in self.hosts_by_port().values()),
        default=0)``, but without rebuilding that mapping. Maintained through
        :meth:`_fanout_moved`: growth updates the cached maximum directly,
        and only losing the last port at the top forces a recomputation -
        over the distinct fanout values, not over every port.
        """
        if self._max_fanout is None:
            self._max_fanout = max(self._fanout_buckets, default=0)
        return self._max_fanout

    def dst_ports(self) -> set[int]:
        """Distinct destination ports. A missing port is not a port."""
        return set(self._dst_port_counts)

    def dst_ips(self) -> set[str]:
        """Distinct destination hosts."""
        return set(self._dst_ip_counts)

    def src_ips(self) -> set[str]:
        """Distinct source hosts."""
        return set(self._src_ip_counts)

    def hosts_by_port(self) -> dict[int, set[str]]:
        """Distinct destination hosts, grouped by destination port.

        This is the shape horizontal scanning needs: one source sweeping the
        *same* port across many hosts. Observations without a ``dst_port`` are
        excluded - there is no port to correlate them across hosts.

        A fresh dict of fresh sets, so a caller cannot reach into the
        window's own bookkeeping - the previous implementation built one from
        scratch each call and callers may rely on it being theirs.
        """
        return {port: set(hosts) for port, hosts in self._hosts_by_port.items()}

    def total_orig_packets(self) -> int:
        """Originator-side packets across every flow still in the window.

        Keyed by destination, this is the packet volume *arriving at* that
        host - not what it sent back. See :class:`FlowObservation`.
        """
        return self._orig_packets_total

    def total_orig_bytes(self) -> int:
        """Originator-side bytes across every flow still in the window."""
        return self._orig_bytes_total

    def max_orig_bytes(self) -> int:
        """Largest single flow's originator-side bytes, 0 when empty.

        One huge transfer and the same volume dribbled across many small
        flows are different behaviours; a total alone cannot tell them
        apart, so exfiltration-style detection needs the peak as well.

        A maximum cannot be maintained by subtraction, so it is cached and
        recomputed only when the largest value itself expires - over the
        distinct byte counts held, not over every observation.
        """
        if self._max_orig_bytes is None:
            self._max_orig_bytes = max(self._orig_bytes_counts, default=0)
        return self._max_orig_bytes

    def total_resp_bytes(self) -> int:
        """Responder-side bytes across the window - **context only**.

        Deliberately separate from :meth:`total_orig_bytes` and never
        summed into it. A 500 MB download must never read as 500 MB of
        outbound data; see :class:`FlowObservation`.
        """
        return self._resp_bytes_total

    def protocols(self) -> set[str]:
        return set(self._proto_counts)

    def timestamps(self) -> list[float]:
        """Observation timestamps, in arrival order.

        Timing analysis (beacon periodicity) reads this. Order is arrival
        order, which the project assumes is roughly non-decreasing event
        time - see the module docstring. Genuinely O(n): the *order* is the
        information a caller wants, and no aggregate can stand in for it.
        """
        return [e.timestamp for e in self._events]

    def time_span(self) -> tuple[float, float] | None:
        """(earliest, latest) timestamp in the window, or None if empty.

        Deliberately still min/max rather than the deque's two ends: the
        project only assumes event time is *approximately* ordered, and a
        record arriving slightly out of order must not silently widen or
        narrow the span. Both extremes are cached, and recomputed over the
        distinct timestamps only when one of them expires.
        """
        if not self._events:
            return None
        if self._min_timestamp is None:
            self._min_timestamp = min(self._timestamp_counts)
        if self._max_timestamp is None:
            self._max_timestamp = max(self._timestamp_counts)
        return self._min_timestamp, self._max_timestamp

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
        self._reset_aggregates()

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
