"""Differential test: the incremental ActivityWindow against the old scans.

The optimization replaced per-call rescans of the deque with incrementally
maintained aggregates. That is only safe if the two agree on *every* input,
so this file keeps a deliberately slow reference implementation of the
original scan-based logic and compares the two over long deterministic
sequences.

The reference lives here, in test code, on purpose. A second implementation
inside the package would be dead weight that drifts; here it is a fixture
whose only job is to disagree loudly if the fast path ever gets it wrong.

Sequences are generated with a fixed seed and deliberately include the cases
that break naive bookkeeping: repeated values, repeated (host, port) pairs,
missing ports, missing source IPs, duplicate timestamps, exact window-edge
expiry, and complete drain-and-refill.
"""

from __future__ import annotations

import random

import pytest

from detection_core.aggregators import (
    CLASSIFIED_CONN_STATES,
    COMPLETE_CONN_STATES,
    DEFAULT_ESTABLISHED_RESP_BYTES,
    INCOMPLETE_CONN_STATES,
    ActivityWindow,
    FlowObservation,
)

SEED = 20260829


# --------------------------------------------------------------------------
# The reference: the original scan-based logic, verbatim in spirit
# --------------------------------------------------------------------------


class ReferenceWindow:
    """What ``ActivityWindow`` did before: hold observations, scan on demand.

    Expiry is byte-for-byte the original loop, so the two implementations
    must always hold identical observations as well as identical aggregates.
    """

    def __init__(
        self,
        window_seconds: float,
        *,
        established_resp_bytes: int = DEFAULT_ESTABLISHED_RESP_BYTES,
    ) -> None:
        self.window_seconds = window_seconds
        self.established_resp_bytes = established_resp_bytes
        self._events: list[FlowObservation] = []

    def observe(self, observation: FlowObservation) -> None:
        self._events.append(observation)
        self.expire(observation.timestamp)

    def expire(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._events and self._events[0].timestamp <= cutoff:
            self._events.pop(0)

    @property
    def attempts(self) -> int:
        return len(self._events)

    def dst_ports(self) -> set[int]:
        return {e.dst_port for e in self._events if e.dst_port is not None}

    def dst_ips(self) -> set[str]:
        return {e.dst_ip for e in self._events}

    def src_ips(self) -> set[str]:
        return {e.src_ip for e in self._events if e.src_ip is not None}

    def hosts_by_port(self) -> dict[int, set[str]]:
        grouped: dict[int, set[str]] = {}
        for event in self._events:
            if event.dst_port is None:
                continue
            grouped.setdefault(event.dst_port, set()).add(event.dst_ip)
        return grouped

    def total_orig_packets(self) -> int:
        return sum(e.orig_packets for e in self._events)

    def total_orig_bytes(self) -> int:
        return sum(e.orig_bytes for e in self._events)

    def max_orig_bytes(self) -> int:
        return max((e.orig_bytes for e in self._events), default=0)

    def unique_service_port_count(self, max_service_port: int) -> int:
        return len(
            {
                e.dst_port
                for e in self._events
                if e.dst_port is not None and e.dst_port <= max_service_port
            }
        )

    def conn_state_coverage(self) -> float:
        if not self._events:
            return 0.0
        # Classified, not merely present: OTH and any unrecognised value are
        # the absence of a verdict. See CLASSIFIED_CONN_STATES.
        return sum(
            e.conn_state in CLASSIFIED_CONN_STATES for e in self._events
        ) / len(self._events)

    def unique_endpoint_count(self) -> int:
        return len({(e.dst_ip, e.dst_port) for e in self._events})

    def established_endpoint_count(self) -> int:
        return len(
            {
                (e.dst_ip, e.dst_port)
                for e in self._events
                if e.resp_bytes >= self.established_resp_bytes
            }
        )

    def endpoint_established_fraction(self) -> float:
        if not self._events:
            return 0.0
        return self.established_endpoint_count() / self.unique_endpoint_count()

    def _classified_endpoints(self) -> set[tuple[str, int | None]]:
        return {
            (e.dst_ip, e.dst_port)
            for e in self._events
            if e.conn_state in CLASSIFIED_CONN_STATES
        }

    def _complete_endpoints(self) -> set[tuple[str, int | None]]:
        return {
            (e.dst_ip, e.dst_port)
            for e in self._events
            if e.conn_state in COMPLETE_CONN_STATES
        }

    def endpoint_conn_state_coverage(self) -> float:
        if not self._events:
            return 0.0
        return len(self._classified_endpoints()) / self.unique_endpoint_count()

    def endpoint_incomplete_fraction(self) -> float:
        if not self._events:
            return 0.0
        # An endpoint is incomplete when it carried state and none of it
        # completed - the set difference, spelled out.
        incomplete = self._classified_endpoints() - self._complete_endpoints()
        return len(incomplete) / self.unique_endpoint_count()

    def incomplete_fraction(self) -> float:
        if not self._events:
            return 0.0
        return sum(
            e.conn_state in INCOMPLETE_CONN_STATES for e in self._events
        ) / len(self._events)

    def established_fraction(self) -> float:
        if not self._events:
            return 0.0
        return sum(
            e.resp_bytes >= self.established_resp_bytes for e in self._events
        ) / len(self._events)

    def total_resp_bytes(self) -> int:
        return sum(e.resp_bytes for e in self._events)

    def protocols(self) -> set[str]:
        return {e.proto for e in self._events if e.proto is not None}

    def timestamps(self) -> list[float]:
        return [e.timestamp for e in self._events]

    def time_span(self) -> tuple[float, float] | None:
        if not self._events:
            return None
        stamps = [e.timestamp for e in self._events]
        return min(stamps), max(stamps)

    def duration(self) -> float:
        span = self.time_span()
        return 0.0 if span is None else span[1] - span[0]

    def is_empty(self) -> bool:
        return not self._events

    def clear(self) -> None:
        self._events.clear()

    def __len__(self) -> int:
        return len(self._events)


def assert_equivalent(fast: ActivityWindow, reference: ReferenceWindow, context: str) -> None:
    """Every observable value must match, not just the ones under test."""
    assert len(fast) == len(reference), context
    assert fast.attempts == reference.attempts, context
    assert fast.is_empty() == reference.is_empty(), context
    assert fast.dst_ports() == reference.dst_ports(), context
    assert fast.dst_ips() == reference.dst_ips(), context
    assert fast.src_ips() == reference.src_ips(), context
    assert fast.protocols() == reference.protocols(), context
    assert fast.hosts_by_port() == reference.hosts_by_port(), context
    assert fast.total_orig_packets() == reference.total_orig_packets(), context
    assert fast.total_orig_bytes() == reference.total_orig_bytes(), context
    assert fast.total_resp_bytes() == reference.total_resp_bytes(), context
    # The responder-engagement counters are maintained the same way - added on
    # entry, reversed on expiry - so they belong in the same differential net.
    assert fast.conn_state_coverage() == reference.conn_state_coverage(), context
    assert fast.incomplete_fraction() == reference.incomplete_fraction(), context
    assert fast.established_fraction() == reference.established_fraction(), context
    # Endpoint scoping is maintained the same way, so it joins the same net.
    assert fast.unique_endpoint_count() == reference.unique_endpoint_count(), context
    assert fast.established_endpoint_count() == (
        reference.established_endpoint_count()
    ), context
    assert fast.endpoint_established_fraction() == (
        reference.endpoint_established_fraction()
    ), context
    assert fast.endpoint_conn_state_coverage() == (
        reference.endpoint_conn_state_coverage()
    ), context
    assert fast.endpoint_incomplete_fraction() == (
        reference.endpoint_incomplete_fraction()
    ), context
    # Every boundary, including whichever one this window pinned: the O(1)
    # counter and the scan must agree, and the scan must still answer the
    # boundaries it was not built for.
    for boundary in (0, 1023, 49151, 65535, fast.service_port_max):
        if boundary is None:
            continue
        assert fast.unique_service_port_count(boundary) == (
            reference.unique_service_port_count(boundary)
        ), f"{context} boundary={boundary}"
    assert fast.max_orig_bytes() == reference.max_orig_bytes(), context
    assert fast.timestamps() == reference.timestamps(), context
    assert fast.time_span() == reference.time_span(), context
    assert fast.duration() == reference.duration(), context


def observation(
    timestamp: float,
    *,
    dst_ip: str = "10.0.0.1",
    dst_port: int | None = 443,
    proto: str | None = "tcp",
    src_ip: str | None = "10.0.0.9",
    orig_packets: int = 1,
    orig_bytes: int = 100,
    resp_bytes: int = 200,
    conn_state: str | None = None,
) -> FlowObservation:
    return FlowObservation(
        timestamp=timestamp,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto=proto,
        src_ip=src_ip,
        orig_packets=orig_packets,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
        conn_state=conn_state,
    )


# --------------------------------------------------------------------------
# 1-14. Randomized differential comparison
# --------------------------------------------------------------------------


@pytest.mark.parametrize("service_port_max", [None, 1023, 49151])
@pytest.mark.parametrize("window_seconds", [1.0, 10.0, 60.0])
@pytest.mark.parametrize("run", range(4))
def test_randomized_sequences_agree_at_every_step(
    window_seconds, run, service_port_max
):
    """Deterministic pseudo-random traffic, compared after every observation.

    The pools are small on purpose: repeated hosts, repeated ports, repeated
    byte counts and colliding timestamps are the inputs where reference
    counting is easy to get wrong, so they must be common rather than rare.

    ``service_port_max`` is parametrized so the incremental service-port
    counter is compared against the materialized reference on both sides of
    its boundary as well as when no boundary is pinned at all.
    """
    rng = random.Random(SEED + run * 17 + int(window_seconds))
    fast = ActivityWindow(window_seconds, service_port_max=service_port_max)
    reference = ReferenceWindow(window_seconds)

    hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    sources = ["192.168.0.5", "192.168.0.6", None]
    # Ports straddle both pinned boundaries, and repeat, so a port entering
    # and leaving the window has to move the counter exactly once each way.
    ports = [22, 80, 443, 1023, 1024, 49151, 49152, 60_000, None]
    protocols = ["tcp", "udp", None]
    byte_values = [0, 100, 100, 5_000]
    # None dominates on purpose: under the frozen legacy-m1d profile ingestion
    # supplies no conn_state, so the mixed-coverage window is the case that
    # has to stay correct. OTH and an unrecognised value are in the pool
    # because they are *uncovered* rather than absent, and the fast path and
    # the reference must agree on that too.
    conn_states = ["S0", "SF", "REJ", "OTH", "ZZ", "", None, None, None]

    timestamp = 1_000.0
    for step in range(400):
        # Frequent zero gaps, so duplicate timestamps really occur.
        timestamp += rng.choice([0.0, 0.0, 0.1, 0.5, 1.0, 3.0, 25.0])
        candidate = observation(
            timestamp,
            dst_ip=rng.choice(hosts),
            dst_port=rng.choice(ports),
            proto=rng.choice(protocols),
            src_ip=rng.choice(sources),
            orig_packets=rng.choice([0, 1, 7]),
            orig_bytes=rng.choice(byte_values),
            resp_bytes=rng.choice([0, 200, 9_000]),
            conn_state=rng.choice(conn_states),
        )
        fast.observe(candidate)
        reference.observe(candidate)
        assert_equivalent(fast, reference, f"run={run} w={window_seconds} step={step}")


def test_a_standalone_expire_call_agrees():
    """``expire`` is also called directly, outside ``observe``."""
    rng = random.Random(SEED)
    fast, reference = ActivityWindow(10.0), ReferenceWindow(10.0)

    timestamp = 500.0
    for step in range(120):
        timestamp += rng.choice([0.0, 0.5, 2.0])
        candidate = observation(timestamp, dst_port=rng.choice([80, 443, None]))
        fast.observe(candidate)
        reference.observe(candidate)

        # Advance the clock without new traffic, the way DataExfiltration does.
        later = timestamp + rng.choice([0.0, 3.0, 11.0])
        fast.expire(later)
        reference.expire(later)
        assert_equivalent(fast, reference, f"step={step}")


# --------------------------------------------------------------------------
# Named edge cases, stated explicitly rather than left to the random walk
# --------------------------------------------------------------------------


def test_empty_window_matches():
    assert_equivalent(ActivityWindow(60.0), ReferenceWindow(60.0), "empty")


def test_single_observation_matches():
    fast, reference = ActivityWindow(60.0), ReferenceWindow(60.0)
    fast.observe(observation(1000.0))
    reference.observe(observation(1000.0))

    assert_equivalent(fast, reference, "single")
    assert fast.duration() == 0.0


def test_the_exact_window_edge_expires_identically():
    """Half-open: an observation exactly ``window_seconds`` old is gone."""
    fast, reference = ActivityWindow(10.0), ReferenceWindow(10.0)
    for window in (fast, reference):
        window.observe(observation(1000.0))
        window.observe(observation(1005.0))

    # 1010.0 - 10.0 = 1000.0, and the boundary is `<= cutoff`.
    fast.expire(1010.0)
    reference.expire(1010.0)
    assert_equivalent(fast, reference, "exact edge")
    assert fast.attempts == 1

    # Just inside: nothing more should go.
    fast.expire(1014.999)
    reference.expire(1014.999)
    assert_equivalent(fast, reference, "just inside")
    assert fast.attempts == 1

    # Just beyond.
    fast.expire(1015.0)
    reference.expire(1015.0)
    assert_equivalent(fast, reference, "just beyond")
    assert fast.is_empty()


def test_duplicate_timestamps_expire_together():
    fast, reference = ActivityWindow(5.0), ReferenceWindow(5.0)
    for window in (fast, reference):
        for _ in range(4):
            window.observe(observation(2000.0))
        window.observe(observation(2001.0))

    assert_equivalent(fast, reference, "duplicates present")
    fast.expire(2005.0)
    reference.expire(2005.0)
    assert_equivalent(fast, reference, "duplicates expired")


def test_repeated_values_survive_a_partial_expiry():
    """The case a plain set gets wrong.

    Two live observations carry the same source; when the older expires the
    address must still be counted, because the newer one still carries it.
    """
    fast, reference = ActivityWindow(10.0), ReferenceWindow(10.0)
    for window in (fast, reference):
        window.observe(observation(1000.0, src_ip="10.9.9.9", dst_port=443))
        window.observe(observation(1005.0, src_ip="10.9.9.9", dst_port=443))

    fast.expire(1011.0)
    reference.expire(1011.0)

    assert fast.src_ips() == {"10.9.9.9"}, "the surviving observation was forgotten"
    assert fast.dst_ports() == {443}
    assert_equivalent(fast, reference, "partial expiry")


def test_repeated_host_port_pairs_are_reference_counted():
    fast, reference = ActivityWindow(10.0), ReferenceWindow(10.0)
    for window in (fast, reference):
        window.observe(observation(1000.0, dst_ip="10.0.0.7", dst_port=22))
        window.observe(observation(1001.0, dst_ip="10.0.0.7", dst_port=22))
        window.observe(observation(1002.0, dst_ip="10.0.0.8", dst_port=22))

    assert fast.hosts_by_port() == {22: {"10.0.0.7", "10.0.0.8"}}

    # cutoff 1000.5 drops only the first of the two 10.0.0.7 observations.
    fast.expire(1010.5)
    reference.expire(1010.5)
    assert fast.hosts_by_port() == {22: {"10.0.0.7", "10.0.0.8"}}, (
        "a duplicate (host, port) pair was forgotten while one was still live"
    )
    assert_equivalent(fast, reference, "one of a duplicate pair expired")

    # cutoff 1001.5 now drops the second 10.0.0.7 as well.
    fast.expire(1011.5)
    reference.expire(1011.5)
    assert fast.hosts_by_port() == {22: {"10.0.0.8"}}
    assert_equivalent(fast, reference, "host fully expired")


def test_missing_ports_and_ips_are_excluded_identically():
    fast, reference = ActivityWindow(60.0), ReferenceWindow(60.0)
    for window in (fast, reference):
        window.observe(observation(1000.0, dst_port=None, src_ip=None, proto=None))
        window.observe(observation(1001.0, dst_port=443, src_ip="10.1.1.1"))

    assert fast.dst_ports() == {443}
    assert fast.src_ips() == {"10.1.1.1"}
    assert fast.hosts_by_port() == {443: {"10.0.0.1"}}
    # dst_ip is required, so a portless observation still counts as a host.
    assert fast.dst_ips() == {"10.0.0.1"}
    assert_equivalent(fast, reference, "missing optionals")


def test_complete_expiry_then_refill():
    fast, reference = ActivityWindow(5.0), ReferenceWindow(5.0)
    for window in (fast, reference):
        for offset in range(4):
            window.observe(observation(1000.0 + offset, orig_bytes=1000 * offset))

    fast.expire(9999.0)
    reference.expire(9999.0)
    assert_equivalent(fast, reference, "fully drained")
    assert fast.max_orig_bytes() == 0
    assert fast.time_span() is None

    for window in (fast, reference):
        window.observe(observation(10_000.0, orig_bytes=42))
    assert_equivalent(fast, reference, "refilled after drain")
    assert fast.max_orig_bytes() == 42


def test_the_maximum_is_recomputed_when_it_expires():
    """The peak cannot be undone by subtraction, so it is the risky one."""
    fast, reference = ActivityWindow(10.0), ReferenceWindow(10.0)
    for window in (fast, reference):
        window.observe(observation(1000.0, orig_bytes=9_000))  # the peak
        window.observe(observation(1005.0, orig_bytes=100))
        window.observe(observation(1008.0, orig_bytes=500))

    assert fast.max_orig_bytes() == 9_000
    fast.expire(1011.0)
    reference.expire(1011.0)

    assert fast.max_orig_bytes() == 500, "stale maximum after the peak expired"
    assert_equivalent(fast, reference, "peak expired")


def test_the_time_span_is_recomputed_when_an_extreme_expires():
    fast, reference = ActivityWindow(10.0), ReferenceWindow(10.0)
    for window in (fast, reference):
        window.observe(observation(1000.0))
        window.observe(observation(1004.0))
        window.observe(observation(1009.0))

    assert fast.time_span() == (1000.0, 1009.0)
    fast.expire(1010.5)
    reference.expire(1010.5)

    assert fast.time_span() == (1004.0, 1009.0), "stale minimum after expiry"
    assert_equivalent(fast, reference, "minimum expired")


def test_out_of_order_arrival_still_reports_min_and_max():
    """time_span is min/max, not the deque's ends - so order cannot fool it."""
    fast, reference = ActivityWindow(600.0), ReferenceWindow(600.0)
    for window in (fast, reference):
        window.observe(observation(1000.0))
        window.observe(observation(1050.0))
        window.observe(observation(1020.0))  # arrives late

    assert fast.time_span() == (1000.0, 1050.0)
    assert_equivalent(fast, reference, "out of order")


def test_clear_resets_every_aggregate():
    fast, reference = ActivityWindow(60.0), ReferenceWindow(60.0)
    for window in (fast, reference):
        for offset in range(20):
            window.observe(observation(1000.0 + offset, orig_bytes=offset * 10))
        window.clear()

    assert_equivalent(fast, reference, "cleared")
    assert fast.total_orig_bytes() == 0
    assert fast.max_orig_bytes() == 0
    assert fast.time_span() is None
    assert fast.hosts_by_port() == {}


# --------------------------------------------------------------------------
# Phase 8: the incremental state must not leak
# --------------------------------------------------------------------------


def assert_no_residue(window: ActivityWindow) -> None:
    """Test-only invariant: an empty window holds no bookkeeping at all."""
    assert window._dst_port_counts == {}
    assert window._dst_ip_counts == {}
    assert window._src_ip_counts == {}
    assert window._proto_counts == {}
    assert window._hosts_by_port == {}
    assert len(window._max_orig_bytes) == 0
    assert len(window._min_timestamp) == 0
    assert len(window._max_timestamp) == 0
    assert window._orig_bytes_total == 0
    assert window._resp_bytes_total == 0
    assert window._orig_packets_total == 0
    assert window._conn_state_known == 0
    assert window._incomplete_total == 0
    assert window._established_total == 0


def test_high_cardinality_history_leaves_nothing_behind():
    """5,000 distinct values through a short window must not accumulate."""
    window = ActivityWindow(1.0)
    for index in range(5_000):
        window.observe(
            observation(
                1000.0 + index * 2.0,  # every observation expires the previous
                dst_ip=f"10.{index // 256 % 256}.{index % 256}.1",
                dst_port=1024 + index % 4000,
                src_ip=f"192.168.{index // 256 % 256}.{index % 256}",
                orig_bytes=index,
                # Cycled so the residue assertions on the responder counters
                # are answering a real question rather than a window that
                # never carried a connection state at all.
                conn_state=["S0", "SF", None][index % 3],
                resp_bytes=[0, 5_000][index % 2],
            )
        )
        # Only the newest observation is ever resident.
        assert window.attempts == 1

    # Every counter holds exactly the one live observation.
    assert len(window._dst_ip_counts) == 1
    assert len(window._dst_port_counts) == 1
    assert len(window._src_ip_counts) == 1
    assert len(window._hosts_by_port) == 1
    # The extreme trackers keep candidates, not history: an observation is
    # dropped as soon as a later one dominates it or it leaves the window.
    assert len(window._max_orig_bytes) == 1
    assert len(window._min_timestamp) == 1
    assert len(window._max_timestamp) == 1

    window.expire(1_000_000.0)
    assert window.is_empty()
    assert_no_residue(window)


def test_zero_count_keys_are_deleted_not_kept_at_zero():
    window = ActivityWindow(10.0)
    window.observe(observation(1000.0, dst_port=443, src_ip="10.5.5.5"))
    window.observe(observation(1005.0, dst_port=22, src_ip="10.6.6.6"))

    window.expire(1011.0)

    assert 443 not in window._dst_port_counts
    assert "10.5.5.5" not in window._src_ip_counts
    assert 443 not in window._hosts_by_port
    assert all(count > 0 for count in window._dst_port_counts.values())
    assert all(count > 0 for count in window._src_ip_counts.values())


def test_nested_port_host_containers_are_removed_when_dead():
    window = ActivityWindow(10.0)
    window.observe(observation(1000.0, dst_ip="10.0.0.4", dst_port=8080))
    window.observe(observation(1005.0, dst_ip="10.0.0.5", dst_port=9090))

    assert set(window._hosts_by_port) == {8080, 9090}
    window.expire(1011.0)

    assert set(window._hosts_by_port) == {9090}, "dead port container retained"
    assert window._hosts_by_port[9090] == {"10.0.0.5": 1}

    window.expire(1_000_000.0)
    assert window._hosts_by_port == {}
    assert_no_residue(window)


def test_counters_shrink_as_observations_expire():
    window = ActivityWindow(10.0)
    for offset in range(10):
        window.observe(observation(1000.0 + offset, dst_ip=f"10.0.0.{offset}"))

    assert len(window._dst_ip_counts) == 10
    window.expire(1005.0)  # cutoff 995.0 - nothing yet
    assert len(window._dst_ip_counts) == 10

    window.expire(1015.0)  # cutoff 1005.0 - drops offsets 0..5
    assert window.attempts == 4
    assert len(window._dst_ip_counts) == 4
    assert window.time_span() == (1006.0, 1009.0)
