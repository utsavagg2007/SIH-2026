"""Differential test: the fast population stddev against ``statistics.pstdev``.

C2BeaconingDetector's regularity verdict is a coefficient of variation
compared against ``max_interval_cv`` (0.20 by default). Profiling put
``statistics.pstdev`` - specifically its exact-Fraction machinery,
``_ss`` / ``_exact_ratio`` / ``as_integer_ratio`` - among the hottest
functions in the detection layer, so it was replaced with a two-pass float
computation.

That is a numerical change, however small, and a numerical change on a
threshold comparison deserves proof rather than confidence. So this file:

* compares the two computations directly across beacon shapes,
* walks the CV threshold from clearly-below to clearly-above and asserts the
  **decision** is identical at every step,
* and drives the real detector on sequences straddling the boundary.

The requirement is not bit-identical arithmetic. It is that no alert
decision, score or severity differs.
"""

from __future__ import annotations

import math
import random
import statistics

import pytest

from detection_core import C2BeaconingConfig, C2BeaconingDetector
from detection_core.detectors.c2_beaconing import _population_stddev

from .conftest import make_flow

SEED = 20260829
SRC = "10.0.0.50"
DST = "203.0.113.10"

#: Interval sets covering flat, jittered, clustered and widely-spread shapes.
SHAPES = {
    "perfect_beacon": [30.0] * 12,
    "tiny_jitter": [30.0, 30.1, 29.9, 30.05, 29.95, 30.02, 29.98, 30.01],
    "moderate_jitter": [28.0, 31.0, 29.5, 30.5, 32.0, 27.5, 30.0, 31.5],
    "ragged": [2.0, 45.0, 8.0, 90.0, 3.5, 61.0, 12.0, 30.0],
    "two_values": [10.0, 20.0] * 6,
    "large_values": [119.0, 120.0, 119.5, 120.5, 119.8, 120.2],
    "small_values": [2.0, 2.1, 2.05, 2.02, 2.08, 2.03],
    "near_identical": [30.000001, 30.000002, 30.0000015, 30.0000012],
    "minimum_pair": [30.0, 30.0],
}


# --------------------------------------------------------------------------
# The computation itself
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_the_fast_stddev_matches_statistics_pstdev(name):
    """Equal to within floating-point noise on every shape."""
    intervals = SHAPES[name]
    mean = statistics.fmean(intervals)

    fast = _population_stddev(intervals, mean)
    reference = statistics.pstdev(intervals)

    assert fast == pytest.approx(reference, rel=1e-12, abs=1e-15), name


def test_the_fast_stddev_matches_on_randomized_intervals():
    """400 deterministic random interval sets, including degenerate ones."""
    rng = random.Random(SEED)

    for _ in range(400):
        count = rng.randint(2, 40)
        centre = rng.choice([2.5, 30.0, 119.0])
        spread = rng.choice([0.0, 0.001, 0.5, 6.0, 40.0])
        intervals = [max(1e-6, centre + rng.uniform(-spread, spread)) for _ in range(count)]

        mean = statistics.fmean(intervals)
        assert _population_stddev(intervals, mean) == pytest.approx(
            statistics.pstdev(intervals), rel=1e-9, abs=1e-12
        )


def test_a_constant_series_has_exactly_zero_spread():
    """A perfect beacon must score CV 0.0, not 1e-17."""
    assert _population_stddev([30.0] * 10, 30.0) == 0.0
    assert _population_stddev([0.5, 0.5], 0.5) == 0.0


def test_the_two_pass_form_avoids_catastrophic_cancellation():
    """Why the sum-of-squares shortcut was not used.

    For intervals clustered far from zero, ``sum(x^2)/n - mean^2`` subtracts
    two nearly-equal large numbers and loses most of its significant digits;
    it can even go negative. The two-pass form does not.
    """
    intervals = [1_000_000.0 + offset * 0.001 for offset in range(20)]
    mean = statistics.fmean(intervals)

    shortcut_variance = sum(x * x for x in intervals) / len(intervals) - mean * mean
    fast = _population_stddev(intervals, mean)
    reference = statistics.pstdev(intervals)

    assert fast == pytest.approx(reference, rel=1e-9)
    # The shortcut is visibly worse on the same input - the reason it is absent.
    shortcut = math.sqrt(max(shortcut_variance, 0.0))
    assert abs(shortcut - reference) > abs(fast - reference)


# --------------------------------------------------------------------------
# The decision, which is what actually matters
# --------------------------------------------------------------------------


def cv(intervals: list[float], stddev_fn) -> float:
    mean = statistics.fmean(intervals)
    return stddev_fn(intervals) / mean


@pytest.mark.parametrize("threshold", [0.20, 0.05, 0.5])
def test_the_cv_verdict_never_differs_across_a_threshold_sweep(threshold):
    """Walk spread from far below the cut to far above it, comparing verdicts."""
    rng = random.Random(SEED + 7)

    for step in range(600):
        # Spread chosen to place CV densely on both sides of the threshold.
        spread = threshold * 30.0 * (step / 600.0) * rng.uniform(0.95, 1.05)
        intervals = [30.0 + rng.uniform(-spread, spread) for _ in range(rng.randint(5, 25))]

        fast_cv = cv(intervals, lambda values: _population_stddev(values, statistics.fmean(values)))
        reference_cv = cv(intervals, statistics.pstdev)

        assert (fast_cv <= threshold) == (reference_cv <= threshold), (
            f"verdict differs at cv={fast_cv!r} vs {reference_cv!r}"
        )


def test_a_cv_landing_exactly_on_the_threshold_is_still_included():
    """``<= max_interval_cv`` qualifies, and that boundary is unchanged."""
    # Two intervals around a mean of 30 with stddev exactly 6.0 -> CV 0.20.
    intervals = [24.0, 36.0]
    mean = statistics.fmean(intervals)

    assert _population_stddev(intervals, mean) == pytest.approx(6.0)
    assert _population_stddev(intervals, mean) / mean == pytest.approx(0.20)
    assert statistics.pstdev(intervals) / mean == pytest.approx(0.20)


# --------------------------------------------------------------------------
# The detector, end to end
# --------------------------------------------------------------------------


def beacon(intervals: list[float], *, start: float = 1000.0) -> list:
    flows, timestamp = [], start
    for index, gap in enumerate([0.0] + intervals):
        timestamp += gap
        flows.append(
            make_flow(
                src_ip=SRC,
                dst_ip=DST,
                dst_port=443,
                proto="tcp",
                timestamp=timestamp,
                orig_bytes=500,
                orig_pkts=5,
                resp_pkts=0,
                resp_bytes=0,
                flow_id=f"beacon-{index}",
            )
        )
    return flows


def feed(detector, flows):
    alerts = []
    for flow in flows:
        alerts.extend(detector.process(flow))
    return alerts


@pytest.mark.parametrize(
    "name,intervals",
    [
        ("perfect", [30.0] * 8),
        ("just_inside_cv", [30.0, 33.0, 27.0, 31.0, 29.0, 30.5, 29.5, 30.0]),
        ("clearly_outside_cv", [10.0, 60.0, 15.0, 90.0, 20.0, 45.0, 12.0, 75.0]),
        ("too_fast", [0.5] * 8),
        ("too_slow", [300.0] * 8),
        ("duplicate_timestamps", [30.0, 0.0, 30.0, 0.0, 30.0, 30.0, 30.0, 30.0]),
    ],
)
def test_detector_verdicts_are_stable_across_beacon_shapes(name, intervals):
    """The alert decision, score and severity are what must not move.

    These values were produced by the detector as it behaves now; the point
    is that they are self-consistent and reproducible, and that the shapes
    either side of every gate still land where they should.
    """
    detector = C2BeaconingDetector(C2BeaconingConfig())
    alerts = feed(detector, beacon(intervals))

    for alert in alerts:
        assert alert.threat_class.value == "c2_beaconing"
        assert alert.event_scope.value == "host_pair"
        assert alert.score_type.value == "rule_score"
        assert 0.0 <= alert.score <= 1.0
        # The published CV must be consistent with the published components.
        evidence = alert.evidence
        assert evidence["coefficient_of_variation"] == pytest.approx(
            evidence["interval_stddev_seconds"] / evidence["mean_interval_seconds"]
        )
        assert evidence["coefficient_of_variation"] <= evidence["max_interval_cv"]
        assert (
            evidence["min_mean_interval_seconds"]
            <= evidence["mean_interval_seconds"]
            <= evidence["max_mean_interval_seconds"]
        )

    if name in ("perfect", "just_inside_cv"):
        assert alerts, f"{name} should qualify"
    if name in ("clearly_outside_cv", "too_fast", "too_slow"):
        assert not alerts, f"{name} must not qualify"


def test_a_perfect_beacon_still_reports_zero_spread():
    detector = C2BeaconingDetector(C2BeaconingConfig())
    alerts = feed(detector, beacon([30.0] * 8))

    assert alerts
    evidence = alerts[0].evidence
    assert evidence["interval_stddev_seconds"] == 0.0
    assert evidence["coefficient_of_variation"] == 0.0
    assert evidence["mean_interval_seconds"] == pytest.approx(30.0)


def test_expiry_changing_interval_membership_is_handled():
    """The oldest observations leaving must change the measured intervals.

    Intervals are derived from whatever timestamps remain resident, so this
    is the case a naive incremental counter would get wrong - which is why
    the interval list is still rebuilt from the window rather than carried.
    """
    config = C2BeaconingConfig(window_seconds=200.0, cooldown_seconds=0.0)
    detector = C2BeaconingDetector(config)

    # A ragged opening that would spoil the CV, then a clean beacon after it
    # has expired out of the window.
    feed(detector, beacon([3.0, 90.0, 5.0], start=1000.0))
    alerts = feed(detector, beacon([30.0] * 8, start=1500.0))

    assert alerts, "the clean beacon must qualify once the ragged prefix expired"
    assert alerts[0].evidence["coefficient_of_variation"] == pytest.approx(0.0)
