"""``WindowExtreme``: the extreme, exactly, without a rescan.

Every rolling window here needs a largest-or-smallest value over what it
currently holds. The previous design cached it and recomputed when the
cached extreme expired - which is free until the window fills, and then
costs a full scan on *every* flow, because after that the oldest
observation leaves on every flow. These tests pin both halves: the answers
match brute force, and the scans do not come back.
"""

from __future__ import annotations

import random

import pytest

from detection_core.aggregators import ActivityWindow
from detection_core.aggregators.extremes import WindowExtreme
from detection_core.aggregators.sliding_window import FlowObservation
from detection_core.detectors.dns_tunnelling import DnsObservation, _DnsWindow
from detection_core.detectors.encrypted_malware import TlsObservation, _TlsWindow


class Reference:
    """The obvious implementation, kept only to disagree with."""

    def __init__(self, largest: bool) -> None:
        self.largest = largest
        self.resident: list[float] = []

    def push(self, value: float) -> None:
        self.resident.append(value)

    def pop(self) -> None:
        self.resident.pop(0)

    @property
    def value(self):
        if not self.resident:
            return None
        return max(self.resident) if self.largest else min(self.resident)


def drive(values, capacity, largest):
    """Push every value, evicting oldest-first, comparing after each step."""
    tracker = WindowExtreme(largest=largest)
    reference = Reference(largest)
    added = removed = 0

    for value in values:
        tracker.push(added, value)
        reference.push(value)
        added += 1
        while len(reference.resident) > capacity:
            tracker.pop(removed)
            reference.pop()
            removed += 1
        assert tracker.value == reference.value, (values, capacity)

    while reference.resident:
        tracker.pop(removed)
        reference.pop()
        removed += 1
        assert tracker.value == reference.value

    assert len(tracker) == 0, "candidates outlived every observation"


# --------------------------------------------------------------------------
# Agreement with brute force
# --------------------------------------------------------------------------


@pytest.mark.parametrize("largest", [True, False])
@pytest.mark.parametrize(
    "values",
    [
        pytest.param([], id="empty"),
        pytest.param([5], id="single"),
        pytest.param([1, 2, 3, 4, 5], id="ascending"),
        pytest.param([5, 4, 3, 2, 1], id="descending"),
        pytest.param([7, 7, 7, 7], id="all-equal"),
        pytest.param([3, 1, 4, 1, 5, 9, 2, 6], id="mixed"),
        pytest.param([1, 9, 1, 9, 1, 9], id="alternating"),
        pytest.param([2.5, -1.0, 0.0, -1.0, 2.5], id="negatives-and-duplicates"),
        pytest.param([1000.0, 1000.0, 999.0, 1001.0], id="out-of-order-timestamps"),
    ],
)
@pytest.mark.parametrize("capacity", [1, 2, 3, 100])
def test_named_sequences_match_brute_force(values, capacity, largest):
    drive(values, capacity, largest)


@pytest.mark.parametrize("largest", [True, False])
def test_randomized_sequences_match_brute_force(largest):
    rng = random.Random(20260830)
    for _ in range(400):
        length = rng.randint(0, 40)
        # A small value range on purpose: duplicates are where a
        # dominated-candidate rule is easiest to get wrong.
        values = [rng.randint(0, 6) for _ in range(length)]
        drive(values, rng.randint(1, 8), largest)


def test_a_gap_in_the_sequence_is_not_a_departure():
    """Observations that never carried the field never pushed.

    Their ``pop`` must be a harmless no-op rather than releasing somebody
    else's candidate.
    """
    tracker = WindowExtreme(largest=True)
    tracker.push(0, 10.0)
    # Observation 1 had no value at all - nothing was pushed for it.
    tracker.pop(1)

    assert tracker.value == 10.0

    tracker.pop(0)
    assert tracker.value is None


def test_an_empty_tracker_reports_nothing():
    assert WindowExtreme(largest=True).value is None
    assert WindowExtreme(largest=False).value is None


def test_clear_drops_every_candidate():
    tracker = WindowExtreme(largest=True)
    for index in range(10):
        tracker.push(index, float(index))

    tracker.clear()

    assert tracker.value is None
    assert len(tracker) == 0


# --------------------------------------------------------------------------
# The rescan must not come back
# --------------------------------------------------------------------------


def test_candidates_never_exceed_residency():
    """Memory is bounded by occupancy, and normally far below it."""
    tracker = WindowExtreme(largest=True)
    for index in range(5000):
        tracker.push(index, float(index))  # a rising series dominates as it goes
        assert len(tracker) == 1


class CountingScan:
    """Counts elements visited by ``min``/``max`` in a module."""

    def __init__(self, module):
        self.module = module
        self.scanned = 0
        self._min, self._max = min, max

    def __enter__(self):
        def counting_min(arg, *rest, **kwargs):
            if not rest and hasattr(arg, "__len__"):
                self.scanned += len(arg)
            return self._min(arg, *rest, **kwargs)

        def counting_max(arg, *rest, **kwargs):
            if not rest and hasattr(arg, "__len__"):
                self.scanned += len(arg)
            return self._max(arg, *rest, **kwargs)

        self.module.min, self.module.max = counting_min, counting_max
        return self

    def __exit__(self, *exc):
        # Restore by deleting the shadowing globals rather than reassigning:
        # these names are builtins, and rebinding them at module scope would
        # leave the module permanently patched.
        del self.module.min, self.module.max
        return False


def test_a_full_dns_window_rescans_nothing():
    """At the occupancy cap the oldest leaves on every flow.

    That is precisely when the old cache-and-recompute design degraded to a
    full scan per flow. Measured before the fix: 15 million elements over
    8000 flows.
    """
    import detection_core.detectors.dns_tunnelling as module

    window = _DnsWindow(300.0, 50)
    with CountingScan(module) as counter:
        for index in range(400):  # 8x the cap, so 350 evictions
            window.observe(
                DnsObservation(
                    timestamp=1000.0 + index * 0.001,
                    query_length=index % 17,
                    query_entropy=(index % 13) / 3.0,
                    subdomain_entropy=None,
                    label_count=index % 5,
                    is_txt=True,
                    orig_bytes=100,
                    dst_port=53,
                    proto="udp",
                    has_raw_query=True,
                ),
                3,
                2,
            )
            window.time_span()
            window.max_query_length()
            window.max_query_entropy()
            window.max_label_count()

    assert len(window) == 50
    assert counter.scanned == 0


def test_a_draining_activity_window_rescans_nothing():
    """Ordinary steady-state expiry, which any long capture reaches."""
    import detection_core.aggregators.sliding_window as module

    window = ActivityWindow(1.0)
    with CountingScan(module) as counter:
        for index in range(400):
            window.observe(
                FlowObservation(
                    timestamp=1000.0 + index * 0.05,  # 20 resident, one out per flow
                    dst_ip=f"10.0.0.{index % 7}",
                    dst_port=1024 + index % 11,
                    src_ip=f"192.168.0.{index % 5}",
                    proto="tcp",
                    orig_bytes=index % 31,
                    resp_bytes=1,
                    orig_packets=1,
                )
            )
            window.time_span()
            window.max_orig_bytes()

    assert counter.scanned == 0


def test_a_full_tls_window_rescans_nothing():
    import detection_core.detectors.encrypted_malware as module

    window = _TlsWindow(300.0, 50, frozenset({"TLSv1.0"}))
    with CountingScan(module) as counter:
        for index in range(400):
            window.observe(
                TlsObservation(
                    timestamp=1000.0 + index * 0.001,
                    sni_length=index % 19,
                    sni_entropy=(index % 7) / 2.0,
                    server_name_available=True,
                    version="TLSv1.0",
                    dst_port=443,
                    proto="tcp",
                ),
                True,
                True,
            )
            window.time_span()
            window.max_sni_length()
            window.max_sni_entropy()

    assert len(window) == 50
    assert counter.scanned == 0
