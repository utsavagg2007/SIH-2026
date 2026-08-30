"""Cooldown/escalation state must not outlive the cooldown it represents.

The three rolling detectors - port scan, DDoS, C2 beaconing - each keep a
small ``_state`` dict of "when did this key last alert, and how badly". The
rolling *windows* behind them are swept by ``WindowIndex``, but these entries
were only ever cleared by ``reset()``, so a long-running process accumulated
one entry per key that had ever alerted, forever.

The fix is the sweep the other three detectors already use: drop an entry once
``now - last_alert_at >= cooldown_seconds``, on event time, never on an empty
window - because a cooldown deliberately outlives the traffic that caused it.

Every scenario below is written against all three detectors, since the bug and
the fix are identical in each. Cooldown *behaviour* (same-severity suppression,
severity escalation) is already covered per detector in
``test_port_scan_detector.py``, ``test_ddos_detector.py`` and
``test_c2_beaconing_detector.py`` and is deliberately not duplicated here; what
these tests add is retention.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Hashable

import pytest

from detection_core import (
    BeaconKey,
    C2BeaconingConfig,
    C2BeaconingDetector,
    DDoSConfig,
    DDoSDetector,
    FlowEvent,
    PortScanConfig,
    PortScanDetector,
)

from .conftest import make_flow

#: Matches the ``every`` cadence of every detector's cooldown sweep. Feeding
#: this many flows guarantees at least one sweep actually runs.
SWEEP_EVERY = 500


# --------------------------------------------------------------------------
# One scenario per affected detector
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Scenario:
    """How to make one detector alert, and how to keep it busy afterwards."""

    name: str
    #: Rolling window length, always shorter than ``cooldown``.
    window: float
    cooldown: float
    #: Event-time gap between two batches of qualifying traffic - short
    #: enough to land well inside the cooldown.
    gap: float
    build: Callable[[], object]
    #: The ``_state`` key an entity id maps to.
    key_of: Callable[[str], Hashable]
    #: Qualifying traffic for one entity; the LAST flow triggers the alert.
    alerting: Callable[[str, float], list[FlowEvent]]
    #: Traffic that must never alert, used only to drive the sweep counter.
    filler: Callable[[int, float], FlowEvent]


# --- port scan: keyed by src_ip -------------------------------------------


def _port_scan_detector() -> PortScanDetector:
    return PortScanDetector(
        PortScanConfig(
            window_seconds=60.0,
            min_unique_ports=5,
            # Horizontal disabled, so only the vertical sweep can fire.
            min_unique_hosts=99,
            cooldown_seconds=300.0,
        )
    )


def _port_scan_alerting(entity: str, start: float) -> list[FlowEvent]:
    """Five distinct ports on one host - a vertical scan."""
    return [
        make_flow(
            src_ip=entity,
            dst_ip="10.0.0.80",
            dst_port=1000 + i,
            timestamp=start + i * 0.1,
            proto="tcp",
        )
        for i in range(5)
    ]


def _port_scan_filler(index: int, ts: float) -> FlowEvent:
    """A different source each time, one port each: never a scan."""
    return make_flow(
        src_ip=f"172.16.{index // 256}.{index % 256}",
        dst_ip="10.0.0.80",
        dst_port=443,
        timestamp=ts,
        proto="tcp",
    )


# --- DDoS: keyed by dst_ip ------------------------------------------------


def _ddos_detector() -> DDoSDetector:
    return DDoSDetector(
        DDoSConfig(
            window_seconds=10.0,
            min_unique_sources=5,
            min_flows=5,
            # Packets effectively disabled: flow count drives intensity.
            min_packets=1_000_000,
            cooldown_seconds=60.0,
        )
    )


def _ddos_alerting(entity: str, start: float) -> list[FlowEvent]:
    """Five distinct sources converging on one destination."""
    return [
        make_flow(
            src_ip=f"10.1.0.{i}",
            dst_ip=entity,
            dst_port=80,
            timestamp=start + i * 0.01,
            proto="tcp",
            orig_pkts=1,
            resp_pkts=0,
            orig_bytes=100,
            resp_bytes=0,
        )
        for i in range(5)
    ]


def _ddos_filler(index: int, ts: float) -> FlowEvent:
    """A different destination each time: one flow can never be a flood."""
    return make_flow(
        src_ip="10.1.0.1",
        dst_ip=f"192.168.{index // 256}.{index % 256}",
        dst_port=80,
        timestamp=ts,
        proto="tcp",
    )


# --- C2 beaconing: keyed by the whole relationship ------------------------


def _c2_detector() -> C2BeaconingDetector:
    return C2BeaconingDetector(
        C2BeaconingConfig(
            # Shorter than the default 900s so the cooldown outlives the
            # window here too; thresholds themselves are untouched.
            window_seconds=200.0,
            min_observations=6,
            min_mean_interval_seconds=2.0,
            max_mean_interval_seconds=120.0,
            max_interval_cv=0.20,
            cooldown_seconds=600.0,
        )
    )


def _c2_alerting(entity: str, start: float) -> list[FlowEvent]:
    """Six contacts on an exact 30s timer - textbook beaconing."""
    return [
        make_flow(
            src_ip=entity,
            dst_ip="203.0.113.10",
            dst_port=443,
            proto="tcp",
            timestamp=start + i * 30.0,
            orig_pkts=5,
            resp_pkts=0,
            orig_bytes=500,
            resp_bytes=0,
        )
        for i in range(6)
    ]


def _c2_filler(index: int, ts: float) -> FlowEvent:
    """A different relationship each time: one contact is never a beacon."""
    return make_flow(
        src_ip=f"172.16.{index // 256}.{index % 256}",
        dst_ip="203.0.113.10",
        dst_port=443,
        proto="tcp",
        timestamp=ts,
    )


SCENARIOS = [
    Scenario(
        name="port_scan",
        window=60.0,
        cooldown=300.0,
        gap=10.0,
        build=_port_scan_detector,
        key_of=lambda entity: entity,
        alerting=_port_scan_alerting,
        filler=_port_scan_filler,
    ),
    Scenario(
        name="ddos",
        window=10.0,
        cooldown=60.0,
        gap=1.0,
        build=_ddos_detector,
        key_of=lambda entity: entity,
        alerting=_ddos_alerting,
        filler=_ddos_filler,
    ),
    Scenario(
        name="c2_beaconing",
        window=200.0,
        cooldown=600.0,
        # Exactly one beacon interval, so the second batch continues the
        # same even cadence instead of breaking its regularity.
        gap=30.0,
        build=_c2_detector,
        key_of=lambda entity: BeaconKey(
            src_ip=entity, dst_ip="203.0.113.10", dst_port=443, proto="tcp"
        ),
        alerting=_c2_alerting,
        filler=_c2_filler,
    ),
]

scenarios = pytest.mark.parametrize(
    "scenario", SCENARIOS, ids=[s.name for s in SCENARIOS]
)

ENTITY = "10.0.0.66"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def raise_alert(detector, scenario: Scenario, start: float, entity: str = ENTITY):
    """Drive one entity into an alert; return (key, event time of the alert)."""
    flows = scenario.alerting(entity, start)
    alerts = []
    for flow in flows:
        alerts.extend(detector.process(flow))

    assert alerts, f"{scenario.name}: expected a qualifying alert"
    return scenario.key_of(entity), flows[-1].timestamp


def drive(detector, scenario: Scenario, ts: float, count: int = SWEEP_EVERY) -> None:
    """Feed non-alerting traffic at event time ``ts`` until a sweep runs."""
    for index in range(count):
        alerts = detector.process(scenario.filler(index, ts))
        assert not alerts, f"{scenario.name}: filler traffic must not alert"


def still_suppressed(detector, key: Hashable, now: float) -> bool:
    """Whether a same-severity repeat on ``key`` would still be held back."""
    state = detector._state[key]
    return not detector._should_emit(key, now, state.last_severity)


# --------------------------------------------------------------------------
# 1. An active cooldown is never swept
# --------------------------------------------------------------------------


@scenarios
def test_an_active_cooldown_survives_a_sweep(scenario):
    detector = scenario.build()
    key, alerted_at = raise_alert(detector, scenario, 1000.0)

    # Busy traffic, still inside the cooldown.
    inside = alerted_at + scenario.cooldown / 2.0
    drive(detector, scenario, inside)

    assert key in detector._state, "an unexpired cooldown was swept away"
    assert detector._state[key].last_alert_at == alerted_at
    assert detector._state[key].last_severity is not None
    assert not detector._should_emit(key, inside, detector._state[key].last_severity)


# --------------------------------------------------------------------------
# 2. An expired cooldown is eventually removed
# --------------------------------------------------------------------------


@scenarios
def test_an_expired_cooldown_is_swept(scenario):
    detector = scenario.build()
    key, alerted_at = raise_alert(detector, scenario, 1000.0)
    assert key in detector._state

    # Same busy traffic, but now past the cooldown.
    drive(detector, scenario, alerted_at + scenario.cooldown + 1.0)

    assert key not in detector._state, "expired cooldown state was retained"


@scenarios
def test_the_sweep_is_driven_by_event_time_not_wall_clock(scenario):
    """A replay whose timestamps never advance must expire nothing."""
    detector = scenario.build()
    key, alerted_at = raise_alert(detector, scenario, 1000.0)

    # Thousands of flows, all at the instant of the alert.
    drive(detector, scenario, alerted_at, count=SWEEP_EVERY * 3)

    assert key in detector._state
    assert detector._state[key].last_alert_at == alerted_at


# --------------------------------------------------------------------------
# 3. A cooldown outliving its traffic window is kept
# --------------------------------------------------------------------------


@scenarios
def test_cooldown_outlives_the_traffic_window(scenario):
    """Window expiry must not be mistaken for cooldown expiry.

    Every scenario here configures ``cooldown_seconds`` longer than
    ``window_seconds``, so there is a stretch where the key's rolling window
    is gone but its cooldown is still owed. Dropping the entry then would let
    the same key re-alert immediately on its next burst.
    """
    detector = scenario.build()
    key, alerted_at = raise_alert(detector, scenario, 1000.0)

    # Past the window, well inside the cooldown.
    between = alerted_at + scenario.window + 1.0
    assert between < alerted_at + scenario.cooldown
    drive(detector, scenario, between)

    assert key not in detector._windows, "the traffic window should have expired"
    assert key in detector._state, "cooldown dropped with the window"
    assert still_suppressed(detector, key, between)


@scenarios
def test_a_repeat_burst_after_window_expiry_is_still_suppressed(scenario):
    """The end-to-end consequence of the test above."""
    detector = scenario.build()
    _, alerted_at = raise_alert(detector, scenario, 1000.0)

    later = alerted_at + scenario.window + 1.0
    drive(detector, scenario, later)

    repeat = []
    for flow in scenario.alerting(ENTITY, later + scenario.gap):
        repeat.extend(detector.process(flow))

    # Only a rise in severity may escape the cooldown, and a repeat of the
    # same burst scores identically.
    assert not repeat, "re-alerted inside a cooldown that was still owed"


# --------------------------------------------------------------------------
# 4. Many historical keys do not accumulate
# --------------------------------------------------------------------------


@scenarios
def test_many_alerted_keys_do_not_leave_expired_state_forever(scenario):
    detector = scenario.build()
    entities = [f"10.9.{i}.1" for i in range(20)]

    last_alert = 0.0
    for entity in entities:
        _, last_alert = raise_alert(detector, scenario, 1000.0, entity=entity)
    assert len(detector._state) == len(entities)

    drive(detector, scenario, last_alert + scenario.cooldown + 1.0)

    assert detector._state == {}, "state grew with every key that ever alerted"


# --------------------------------------------------------------------------
# 5. reset() still clears everything, including the new counter
# --------------------------------------------------------------------------


@scenarios
def test_reset_clears_state_windows_and_the_sweep_counter(scenario):
    detector = scenario.build()
    raise_alert(detector, scenario, 1000.0)
    drive(detector, scenario, 1000.0, count=10)  # leave a partial sweep pending
    assert detector._since_sweep > 0

    detector.reset()

    assert detector._state == {}
    assert len(detector._windows) == 0
    assert detector._since_sweep == 0


# --------------------------------------------------------------------------
# 8. A failed alert must not record a cooldown
# --------------------------------------------------------------------------


@scenarios
def test_failed_alert_construction_records_no_cooldown(scenario, monkeypatch):
    """State is written only after the ThreatAlert exists.

    With the old ordering the cooldown was stamped first, so a validation
    error inside ``_build_alert`` left the key muted for a full cooldown
    despite nothing having been emitted - the detector would go quiet
    precisely when it had found something.
    """
    detector = scenario.build()

    def explode(*args, **kwargs):
        raise ValueError("simulated ThreatAlert validation failure")

    monkeypatch.setattr(detector, "_build_alert", explode)

    with pytest.raises(ValueError, match="simulated"):
        for flow in scenario.alerting(ENTITY, 1000.0):
            detector.process(flow)

    key = scenario.key_of(ENTITY)
    assert key not in detector._state, "cooldown recorded for an alert never emitted"

    # And the very next qualifying burst is not suppressed.
    monkeypatch.undo()
    alerts = []
    for flow in scenario.alerting(ENTITY, 1000.0 + scenario.gap):
        alerts.extend(detector.process(flow))

    assert alerts, "a failed alert silenced the detector for a full cooldown"
    assert key in detector._state
