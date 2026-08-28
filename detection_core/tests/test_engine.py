"""DetectionEngine tests.

Uses the stub detectors in conftest - there is no detection logic here.
"""

from __future__ import annotations

import logging

import pytest

from detection_core import DetectionEngine, Detector, IngestionJsonlAdapter, ThreatAlert

from .conftest import (
    BadItemDetector,
    BadReturnDetector,
    DummyDetector,
    ExplodingDetector,
    SilentDetector,
    StatefulDetector,
    make_flow,
)


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------


def test_register_returns_self_for_chaining():
    engine = DetectionEngine()
    result = engine.register(DummyDetector()).register(SilentDetector())
    assert result is engine
    assert len(engine.detectors) == 2


def test_detectors_can_be_passed_to_constructor():
    engine = DetectionEngine([DummyDetector(), SilentDetector()])
    assert [d.name for d in engine.detectors] == ["dummy", "silent"]


def test_duplicate_detector_name_rejected():
    engine = DetectionEngine([DummyDetector()])
    with pytest.raises(ValueError, match="already registered"):
        engine.register(DummyDetector())


def test_non_detector_rejected():
    with pytest.raises(TypeError):
        DetectionEngine().register(object())


def test_detectors_property_is_immutable_snapshot():
    engine = DetectionEngine([DummyDetector()])
    assert isinstance(engine.detectors, tuple)


# --------------------------------------------------------------------------
# Fan-out
# --------------------------------------------------------------------------


def test_process_fans_out_to_every_detector(flow):
    first, second = DummyDetector("first"), DummyDetector("second")
    engine = DetectionEngine([first, second])

    alerts = engine.process(flow)

    assert len(alerts) == 2
    assert all(isinstance(alert, ThreatAlert) for alert in alerts)
    assert first.seen == [flow] and second.seen == [flow]
    assert engine.stats.flows_processed == 1
    assert engine.stats.alerts_emitted == 2


def test_engine_with_no_detectors_emits_nothing(flow):
    engine = DetectionEngine()
    assert engine.process(flow) == []
    assert engine.stats.flows_processed == 1


def test_same_flow_instance_reaches_all_detectors(flow):
    first, second = DummyDetector("first"), DummyDetector("second")
    DetectionEngine([first, second]).process(flow)
    assert first.seen[0] is second.seen[0]


# --------------------------------------------------------------------------
# Exception isolation
# --------------------------------------------------------------------------


def test_failing_detector_does_not_stop_the_others(flow, caplog):
    good = DummyDetector("good")
    engine = DetectionEngine([ExplodingDetector(), good])

    with caplog.at_level(logging.ERROR):
        alerts = engine.process(flow)

    assert len(alerts) == 1
    assert good.seen == [flow]
    assert engine.stats.detector_errors == 1


def test_failing_flush_is_isolated(caplog):
    engine = DetectionEngine([ExplodingDetector(), StatefulDetector()])
    engine.process(make_flow())

    with caplog.at_level(logging.ERROR):
        alerts = engine.flush()

    assert len(alerts) == 1
    assert engine.stats.detector_errors >= 1


def test_raise_on_detector_error_propagates(flow):
    engine = DetectionEngine([ExplodingDetector()], raise_on_detector_error=True)
    with pytest.raises(RuntimeError, match="boom"):
        engine.process(flow)


def test_non_list_return_is_rejected(flow, caplog):
    engine = DetectionEngine([BadReturnDetector()])
    with caplog.at_level(logging.ERROR):
        alerts = engine.process(flow)
    assert alerts == []
    assert engine.stats.detector_errors == 1


def test_non_alert_item_is_dropped(flow, caplog):
    engine = DetectionEngine([BadItemDetector()])
    with caplog.at_level(logging.ERROR):
        alerts = engine.process(flow)
    assert alerts == []
    assert engine.stats.detector_errors == 1


# --------------------------------------------------------------------------
# flush / reset
# --------------------------------------------------------------------------


def test_flush_collects_held_back_alerts():
    stateful = StatefulDetector()
    engine = DetectionEngine([stateful])

    for _ in range(3):
        assert engine.process(make_flow()) == []

    alerts = engine.flush()
    assert len(alerts) == 1
    assert alerts[0].evidence == {"flows_seen": 3}


def test_flush_with_no_state_emits_nothing():
    assert DetectionEngine([StatefulDetector()]).flush() == []


def test_reset_clears_engine_and_detector_state(flow):
    dummy, stateful = DummyDetector(), StatefulDetector()
    engine = DetectionEngine([dummy, stateful])
    engine.process(flow)

    engine.reset()

    assert engine.stats.flows_processed == 0
    assert engine.stats.alerts_emitted == 0
    assert dummy.seen == []
    assert stateful.count == 0


# --------------------------------------------------------------------------
# run()
# --------------------------------------------------------------------------


def test_run_streams_process_then_flush_alerts():
    engine = DetectionEngine([DummyDetector(), StatefulDetector()])
    flows = [make_flow(), make_flow(), make_flow()]

    alerts = list(engine.run(flows))

    # 3 per-flow alerts from DummyDetector + 1 flush alert from StatefulDetector.
    assert len(alerts) == 4
    assert alerts[-1].evidence == {"flows_seen": 3}
    assert engine.stats.flows_processed == 3


def test_run_accepts_any_iterable_of_flows():
    engine = DetectionEngine([DummyDetector()])
    generator = (make_flow() for _ in range(2))
    assert len(list(engine.run(generator))) == 2


def test_run_resets_stats_each_time():
    engine = DetectionEngine([DummyDetector()])
    list(engine.run([make_flow()]))
    list(engine.run([make_flow()]))
    assert engine.stats.flows_processed == 1


def test_independent_runs_do_not_share_detector_state():
    """Replaying a second PCAP must not inherit state from the first."""
    engine = DetectionEngine([StatefulDetector()])

    first = list(engine.run([make_flow()]))
    second = list(engine.run([make_flow()]))

    assert first[-1].evidence == {"flows_seen": 1}
    assert second[-1].evidence == {"flows_seen": 1}


def test_run_can_opt_out_of_resetting():
    """reset_first=False deliberately continues one stream across chunks."""
    engine = DetectionEngine([StatefulDetector()])

    list(engine.run([make_flow()]))
    second = list(engine.run([make_flow()], reset_first=False))

    assert second[-1].evidence == {"flows_seen": 2}


def test_run_clears_detector_state_before_consuming(flow):
    dummy = DummyDetector()
    engine = DetectionEngine([dummy])

    engine.process(flow)
    assert dummy.seen == [flow]

    list(engine.run([make_flow()]))
    assert len(dummy.seen) == 1  # the pre-run flow was cleared


# --------------------------------------------------------------------------
# End to end: file -> adapter -> engine -> alerts
# --------------------------------------------------------------------------


def test_end_to_end_from_ingestion_file(sample_path):
    engine = DetectionEngine([DummyDetector()])
    source = IngestionJsonlAdapter(path=sample_path)

    alerts = list(engine.run(source))

    assert len(alerts) == 2
    assert all(alert.schema_version == "1.1" for alert in alerts)
    assert source.stats.parsed == 2
    assert engine.stats.flows_processed == 2


def test_end_to_end_survives_malformed_lines(malformed_path, sample_path, caplog):
    lines = malformed_path.read_text(encoding="utf-8").splitlines()
    lines += sample_path.read_text(encoding="utf-8").splitlines()

    adapter = IngestionJsonlAdapter()
    engine = DetectionEngine([DummyDetector()])

    with caplog.at_level(logging.WARNING):
        alerts = list(engine.run(adapter.from_lines(lines)))

    assert len(alerts) == 2
    assert adapter.stats.errors == 8


# --------------------------------------------------------------------------
# Detector interface
# --------------------------------------------------------------------------


def test_detector_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        Detector()


def test_detector_defaults():
    detector = SilentDetector()
    assert detector.flush() == []
    assert detector.reset() is None


def test_only_the_port_scan_detector_is_shipped():
    """Port scan is the first and so far only real detector."""
    from detection_core import detectors, ml

    assert detectors.__all__ == ["PortScanConfig", "PortScanDetector"]
    assert ml.__all__ == []
