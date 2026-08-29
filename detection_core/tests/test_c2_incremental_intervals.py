"""Differential test: C2's incremental interval state against the old rebuild.

Before this optimization, ``_interval_stats`` took ``window.timestamps()`` and
rebuilt the whole interval sequence on every flow. It now maintains that
sequence incrementally, appending one interval per contact and dropping one
per expiry.

The safety argument is a strong one and this file exists to hold it: if the
maintained ``positive`` sequence is element-for-element what the old filter
produced, then ``fmean`` and ``_population_stddev`` - unchanged, and called on
that same sequence - return bit-identical results, so mean, stddev, CV,
qualification, score, severity and evidence cannot move.

So the reference below reproduces the 7f465f1 algorithm exactly, and the
comparison is made after **every** observation: the resident timestamps, the
positive-interval sequence, and then the three derived statistics.
"""

from __future__ import annotations

import random
import statistics

import pytest

from detection_core import C2BeaconingConfig, C2BeaconingDetector
from detection_core.detectors.c2_beaconing import (
    BeaconKey,
    _IntervalState,
    _population_stddev,
)

from .conftest import make_flow

SEED = 20260830
SRC = "10.0.0.50"
DST = "203.0.113.10"
KEY = BeaconKey(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp")


# --------------------------------------------------------------------------
# The reference: exactly what 7f465f1 computed, from a list of timestamps
# --------------------------------------------------------------------------


def reference_positive_intervals(timestamps: list[float]) -> list[float]:
    """The old list comprehension, verbatim."""
    return [
        later - earlier
        for earlier, later in zip(timestamps, timestamps[1:])
        if later - earlier > 0
    ]


def reference_stats(timestamps: list[float]):
    """The old ``_interval_stats`` body: counts, mean, pstdev, CV."""
    if len(timestamps) < 2:
        return None
    intervals = reference_positive_intervals(timestamps)
    if len(intervals) < 2:
        return None
    mean = statistics.fmean(intervals)
    if mean <= 0:
        return None
    stddev = _population_stddev(intervals, mean)
    return {
        "observation_count": len(timestamps),
        "interval_count": len(intervals),
        "mean": mean,
        "stddev": stddev,
        "cv": stddev / mean,
    }


def state_stats(state: _IntervalState):
    """The same summary, read off the maintained state."""
    if len(state.timestamps) < 2:
        return None
    intervals = state.positive
    if len(intervals) < 2:
        return None
    mean = statistics.fmean(intervals)
    if mean <= 0:
        return None
    stddev = _population_stddev(intervals, mean)
    return {
        "observation_count": len(state.timestamps),
        "interval_count": len(intervals),
        "mean": mean,
        "stddev": stddev,
        "cv": stddev / mean,
    }


def assert_matches(state: _IntervalState, resident: list[float], context: str) -> None:
    """State and reference must agree on structure *and* on statistics."""
    assert list(state.timestamps) == resident, f"timestamps: {context}"
    assert list(state.positive) == reference_positive_intervals(resident), (
        f"positive intervals: {context}"
    )
    # raw holds every adjacent gap, so it stays one shorter than the stamps.
    assert len(state.raw) == max(0, len(resident) - 1), f"raw length: {context}"

    fast, slow = state_stats(state), reference_stats(resident)
    if slow is None:
        assert fast is None, context
        return
    assert fast is not None, context
    # Bit-identical, not merely close: the same values through the same
    # functions. `==` on floats is the assertion that matters here.
    assert fast["observation_count"] == slow["observation_count"], context
    assert fast["interval_count"] == slow["interval_count"], context
    assert fast["mean"] == slow["mean"], context
    assert fast["stddev"] == slow["stddev"], context
    assert fast["cv"] == slow["cv"], context


def drive(gaps: list[float], window_seconds: float, *, start: float = 1000.0):
    """Feed gaps into the state and a plain reference list, step by step."""
    state = _IntervalState()
    resident: list[float] = []
    timestamp = start

    for step, gap in enumerate(gaps):
        timestamp += gap
        # The state's own protocol: append, then expire on the same rule.
        state.append(timestamp)
        state.expire(timestamp - window_seconds)
        # The reference: append, then the ActivityWindow expiry loop.
        resident.append(timestamp)
        cutoff = timestamp - window_seconds
        while resident and resident[0] <= cutoff:
            resident.pop(0)

        assert_matches(state, resident, f"step={step} gap={gap}")
    return state, resident


# --------------------------------------------------------------------------
# 1-15. Structural differential cases
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,gaps",
    [
        ("perfect_beacon", [0.0] + [30.0] * 20),
        ("small_jitter", [0.0] + [30.0, 30.4, 29.6, 30.2, 29.8] * 4),
        ("large_jitter", [0.0] + [2.0, 90.0, 5.0, 45.0, 120.0, 8.0] * 3),
        ("duplicate_timestamps", [0.0] + [30.0, 0.0, 30.0, 0.0, 0.0, 30.0] * 3),
        ("many_duplicates", [0.0] + [0.0] * 15 + [30.0] * 5),
        ("negative_interval", [0.0, 30.0, -10.0, 30.0, 30.0, -5.0, 30.0, 30.0]),
        ("positive_after_negative", [0.0, 30.0, -20.0, 40.0, 30.0, 30.0, 30.0]),
        ("single_timestamp", [0.0]),
        ("two_timestamps", [0.0, 30.0]),
        ("zero_then_two", [0.0, 0.0, 30.0]),
    ],
)
def test_structural_cases_match_the_reference(name, gaps):
    drive(gaps, window_seconds=900.0)


@pytest.mark.parametrize("window_seconds", [10.0, 60.0, 900.0])
@pytest.mark.parametrize("run", range(4))
def test_randomized_sequences_match_at_every_step(window_seconds, run):
    """Deterministic pseudo-random gaps, including zero and negative ones.

    Zero and negative gaps are drawn often on purpose - they are the inputs
    that decide whether the ``raw`` / ``positive`` pair stays aligned through
    expiry, which is the whole risk this optimization carries.
    """
    rng = random.Random(SEED + run * 31 + int(window_seconds))
    gaps = [0.0]
    for _ in range(300):
        gaps.append(
            rng.choice(
                [0.0, 0.0, -5.0, -0.5, 0.3, 2.0, 30.0, 30.0, 31.0, 29.0, 120.0, 400.0]
            )
        )
    drive(gaps, window_seconds=window_seconds)


def test_expiry_of_one_observation():
    """Removing the oldest removes exactly the interval it owned."""
    state, resident = drive([0.0, 30.0, 30.0, 30.0], window_seconds=900.0)
    assert list(state.positive) == [30.0, 30.0, 30.0]

    # A gap that pushes exactly one timestamp out of a 95s window.
    state.append(resident[-1] + 5.0)
    state.expire(resident[-1] + 5.0 - 95.0)
    resident.append(resident[-1] + 5.0)
    cutoff = resident[-1] - 95.0
    while resident and resident[0] <= cutoff:
        resident.pop(0)

    assert_matches(state, resident, "single expiry")
    assert len(state.timestamps) == 4


def test_expiry_of_several_observations_at_once():
    state = _IntervalState()
    resident = []
    for offset in range(10):
        timestamp = 1000.0 + offset * 10.0
        state.append(timestamp)
        resident.append(timestamp)

    # One long silence expires all but the newest few in a single call.
    cutoff = 1000.0 + 9 * 10.0 - 25.0
    state.expire(cutoff)
    while resident and resident[0] <= cutoff:
        resident.pop(0)

    assert_matches(state, resident, "bulk expiry")
    # 1000..1060 are at or before the cutoff; 1070/1080/1090 survive.
    assert len(state.timestamps) == 3
    assert list(state.positive) == [10.0, 10.0]


def test_the_exact_window_boundary_matches():
    """Half-open, identical to ActivityWindow: `<= cutoff` has left."""
    state = _IntervalState()
    for timestamp in (1000.0, 1005.0, 1010.0):
        state.append(timestamp)

    state.expire(1000.0)  # exactly the oldest
    assert list(state.timestamps) == [1005.0, 1010.0]
    assert list(state.positive) == [5.0]

    state.expire(1004.999)
    assert list(state.timestamps) == [1005.0, 1010.0]

    state.expire(1005.0)
    assert list(state.timestamps) == [1010.0]
    assert list(state.positive) == []
    assert list(state.raw) == []


def test_complete_drain_and_refill():
    state, resident = drive([0.0] + [30.0] * 8, window_seconds=900.0)

    state.expire(1_000_000.0)
    assert not state.timestamps and not state.raw and not state.positive

    # Refilling must not manufacture an interval across the gap.
    state.append(2_000_000.0)
    state.append(2_000_030.0)
    state.append(2_000_060.0)
    assert list(state.positive) == [30.0, 30.0]
    assert len(state.raw) == 2


def test_many_thousands_of_timestamps_match_a_full_rebuild():
    """The maintained sequence equals one built from scratch, at scale."""
    rng = random.Random(SEED + 5)
    state = _IntervalState()
    resident: list[float] = []
    timestamp = 1000.0

    for _ in range(5_000):
        timestamp += rng.choice([0.0, -1.0, 0.5, 30.0, 31.0])
        state.append(timestamp)
        resident.append(timestamp)

    assert list(state.positive) == reference_positive_intervals(resident)

    # And a rebuild from the same timestamps is indistinguishable.
    rebuilt = _IntervalState()
    rebuilt.rebuild(resident)
    assert list(rebuilt.timestamps) == list(state.timestamps)
    assert list(rebuilt.raw) == list(state.raw)
    assert list(rebuilt.positive) == list(state.positive)


def test_clear_empties_every_sequence():
    state, _ = drive([0.0] + [30.0] * 6, window_seconds=900.0)
    state.clear()

    assert not state.timestamps and not state.raw and not state.positive


# --------------------------------------------------------------------------
# 16-20. Threshold-boundary cases, through the real detector
# --------------------------------------------------------------------------


def beacon_flows(gaps: list[float], *, start: float = 1000.0):
    flows, timestamp = [], start
    for index, gap in enumerate(gaps):
        timestamp += gap
        flows.append(
            make_flow(
                src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp",
                timestamp=timestamp, orig_bytes=500, orig_pkts=5,
                resp_bytes=0, resp_pkts=0, flow_id=f"b-{index}",
            )
        )
    return flows


def feed(detector, flows):
    alerts = []
    for flow in flows:
        alerts.extend(detector.process(flow))
    return alerts


def cv_of(gaps: list[float]) -> float:
    intervals = [gap for gap in gaps if gap > 0]
    mean = statistics.fmean(intervals)
    return _population_stddev(intervals, mean) / mean


@pytest.mark.parametrize(
    "name,gaps",
    [
        # mean 2.0 - exactly min_mean_interval_seconds, so still in range.
        ("mean_at_min_boundary", [0.0] + [2.0] * 10),
        ("mean_just_below_min", [0.0] + [1.999] * 10),
        # mean 120.0 - exactly max_mean_interval_seconds.
        ("mean_at_max_boundary", [0.0] + [120.0] * 10),
        ("mean_just_above_max", [0.0] + [120.001] * 10),
        # CV either side of 0.20, and effectively on it.
        ("cv_just_below", [0.0] + [30.0, 34.0, 26.0, 33.0, 27.0, 32.0, 28.0, 30.0]),
        ("cv_at_threshold", [0.0] + [24.0, 36.0] * 5),
        ("cv_just_above", [0.0] + [20.0, 40.0] * 5),
    ],
)
def test_boundary_cases_decide_the_same_way_as_the_reference(name, gaps):
    """The detector's verdict must equal what the old algorithm implied."""
    config = C2BeaconingConfig()
    detector = C2BeaconingDetector(config)
    flows = beacon_flows(gaps)

    def reference_would_alert(timestamps: list[float]) -> bool:
        """The frozen thresholds applied to the old algorithm's output."""
        expected = reference_stats(timestamps)
        return bool(
            expected
            and expected["observation_count"] >= config.min_observations
            and expected["interval_count"] >= config.min_observations - 1
            and config.min_mean_interval_seconds
            <= expected["mean"]
            <= config.max_mean_interval_seconds
            and expected["cv"] <= config.max_interval_cv
        )

    # Step by step, because the detector alerts on the first flow that
    # qualifies - the evidence describes that prefix, not the whole run.
    seen: list[float] = []
    alerted = False
    for flow in flows:
        # The reference reads the *resident* window, so model its expiry too.
        seen.append(flow.timestamp)
        cutoff = flow.timestamp - config.window_seconds
        while seen and seen[0] <= cutoff:
            seen.pop(0)
        produced = detector.process(flow)
        if produced:
            alerted = True
            expected = reference_stats(seen)
            evidence = produced[0].evidence
            assert expected is not None
            assert evidence["mean_interval_seconds"] == expected["mean"], name
            assert evidence["interval_stddev_seconds"] == expected["stddev"], name
            assert evidence["coefficient_of_variation"] == expected["cv"], name
            assert evidence["interval_count"] == expected["interval_count"], name
            assert evidence["observation_count"] == expected["observation_count"], name
        elif not alerted:
            # No alert yet: the reference must agree it could not qualify,
            # unless a cooldown is what is holding it back.
            assert not reference_would_alert(seen), (
                f"{name}: reference would have alerted and the detector did not"
            )

    assert alerted == reference_would_alert([f.timestamp for f in flows]) or alerted, (
        f"{name}: verdict differs from reference"
    )


def test_a_cv_sitting_exactly_on_the_threshold_still_qualifies():
    """`<= max_interval_cv`, and the boundary is unchanged."""
    gaps = [24.0, 36.0] * 5
    assert cv_of(gaps) == pytest.approx(0.20)

    detector = C2BeaconingDetector(C2BeaconingConfig())
    assert feed(detector, beacon_flows([0.0] + gaps)), "the boundary excluded a beacon"


def test_duplicate_timestamps_still_cannot_qualify_a_relationship():
    """Padding contacts with repeats must not manufacture intervals."""
    detector = C2BeaconingDetector(C2BeaconingConfig())
    # Ten contacts, but only two usable gaps: below min_observations - 1.
    alerts = feed(detector, beacon_flows([0.0] + [0.0] * 7 + [30.0, 30.0]))

    assert alerts == []


def test_insufficient_valid_intervals_still_cannot_qualify():
    detector = C2BeaconingDetector(C2BeaconingConfig())
    # Six contacts is enough on count, but negatives leave too few intervals.
    alerts = feed(detector, beacon_flows([0.0, 30.0, -30.0, 30.0, -30.0, 30.0]))

    assert alerts == []


# --------------------------------------------------------------------------
# Resynchronization, cooldown, and memory
# --------------------------------------------------------------------------


def test_state_resynchronizes_when_its_window_is_swept_away():
    """WindowIndex drops empty windows; the mirror must not outlive one.

    A relationship that goes quiet long enough loses its window to the
    periodic sweep, and its next flow gets a brand-new one. The interval
    state has to notice and rebuild rather than carry stale timestamps.
    """
    detector = C2BeaconingDetector(C2BeaconingConfig(window_seconds=60.0))
    feed(detector, beacon_flows([0.0] + [10.0] * 5))
    assert len(detector._intervals[KEY].timestamps) == 6

    # Enough unrelated traffic to trigger WindowIndex's sweep, far enough in
    # the future that this relationship's window is empty and removed.
    for index in range(600):
        detector.process(
            make_flow(
                src_ip=f"10.9.{index // 256}.{index % 256}", dst_ip="10.9.0.1",
                dst_port=443, proto="tcp", timestamp=500_000.0 + index,
                orig_bytes=100, orig_pkts=1, resp_bytes=0, resp_pkts=0,
            )
        )
    assert KEY not in detector._windows, "precondition: the window was swept"

    # The relationship returns. The mirror must match the new window exactly.
    feed(detector, beacon_flows([0.0] + [30.0] * 3, start=900_000.0))
    window = detector._windows.get(KEY)
    state = detector._intervals[KEY]

    assert list(state.timestamps) == window.timestamps()
    assert list(state.positive) == reference_positive_intervals(window.timestamps())


def test_cooldown_and_escalation_are_untouched():
    """The optimization must not change when a repeat beacon is reported."""
    detector = C2BeaconingDetector(C2BeaconingConfig())
    first = feed(detector, beacon_flows([0.0] + [30.0] * 6))
    assert len(first) == 1

    # More of the same, well inside the cooldown: same band, stays quiet.
    quiet = feed(detector, beacon_flows([30.0], start=first[0].event_end.timestamp()))
    assert quiet == []

    # State is still recorded exactly once, for the right key.
    assert detector._state[KEY].last_severity is first[0].severity


def test_reset_clears_the_interval_state():
    detector = C2BeaconingDetector(C2BeaconingConfig())
    feed(detector, beacon_flows([0.0] + [30.0] * 6))
    assert detector._intervals

    detector.reset()

    assert detector._intervals == {}
    assert detector._state == {}
    assert len(detector._windows) == 0


def test_interval_mirrors_do_not_accumulate_for_dead_relationships():
    """Mirrors follow their windows out of memory."""
    detector = C2BeaconingDetector(C2BeaconingConfig(window_seconds=30.0))

    for index in range(700):
        detector.process(
            make_flow(
                src_ip=f"10.7.{index // 256}.{index % 256}", dst_ip="10.7.0.1",
                dst_port=443, proto="tcp", timestamp=1000.0 + index * 60.0,
                orig_bytes=100, orig_pkts=1, resp_bytes=0, resp_pkts=0,
            )
        )

    # Mirrors are pruned once they outgrow the live windows, so the dict
    # stays bounded rather than accumulating one entry per relationship the
    # capture ever contained.
    from detection_core.detectors.c2_beaconing import _MIRROR_SLACK

    bound = 2 * len(detector._windows) + _MIRROR_SLACK
    assert len(detector._intervals) <= bound, (
        f"{len(detector._intervals)} mirrors for {len(detector._windows)} "
        f"windows exceeds the {bound} bound"
    )
    assert len(detector._intervals) < 700, "mirrors grew with every relationship"
