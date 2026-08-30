"""Shared pytest fixtures and stub detectors.

The stub detectors here exist to exercise the engine. They are NOT real
detectors and contain no detection logic.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from detection_core import (
    Detector,
    EventScope,
    FlowEvent,
    ScoreType,
    Severity,
    ThreatAlert,
    ThreatClass,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"

EPOCH = datetime(2026, 8, 29, 0, 20, 10, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# Fixture files
# --------------------------------------------------------------------------


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def sample_path() -> Path:
    return FIXTURES_DIR / "features_sample.jsonl"


@pytest.fixture
def edge_cases_path() -> Path:
    return FIXTURES_DIR / "features_edge_cases.jsonl"


@pytest.fixture
def malformed_path() -> Path:
    return FIXTURES_DIR / "features_malformed.jsonl"


# --------------------------------------------------------------------------
# Object factories
# --------------------------------------------------------------------------


def make_flow(**overrides: Any) -> FlowEvent:
    """A minimal valid FlowEvent, with overrides applied."""
    payload: dict[str, Any] = {
        "flow_id": "10.0.0.1:10.0.0.2:443:tcp:1747147700.500",
        "timestamp": 1747147700.5,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "proto": "tcp",
        "duration": 1.25,
        "orig_bytes": 100,
        "resp_bytes": 200,
        "orig_pkts": 2,
        "resp_pkts": 3,
    }
    payload.update(overrides)
    return FlowEvent(**payload)


def make_alert(**overrides: Any) -> ThreatAlert:
    """A minimal valid ThreatAlert, with overrides applied."""
    payload: dict[str, Any] = {
        "event_start": EPOCH,
        "event_end": EPOCH,
        "event_scope": EventScope.FLOW,
        "threat_class": ThreatClass.PORT_SCAN,
        "severity": Severity.MEDIUM,
        "score": 0.5,
        "score_type": ScoreType.RULE_SCORE,
        "detector": "stub",
        "detector_version": "0.0.1",
    }
    payload.update(overrides)
    return ThreatAlert(**payload)


@pytest.fixture
def flow() -> FlowEvent:
    return make_flow()


@pytest.fixture
def alert() -> ThreatAlert:
    return make_alert()


# --------------------------------------------------------------------------
# Stub detectors (engine plumbing only - no detection logic)
# --------------------------------------------------------------------------


class DummyDetector(Detector):
    """Emits exactly one canned alert per flow."""

    name = "dummy"
    version = "1.0.0"

    def __init__(self, name: str | None = None) -> None:
        if name is not None:
            self.name = name
        self.seen: list[FlowEvent] = []

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        self.seen.append(flow)
        return [make_alert(detector=self.name, detector_version=self.version)]

    def reset(self) -> None:
        self.seen.clear()


class SilentDetector(Detector):
    """Never emits anything."""

    name = "silent"
    version = "1.0.0"

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        return []


class ExplodingDetector(Detector):
    """Always raises - used to prove exception isolation."""

    name = "exploding"
    version = "1.0.0"

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        raise RuntimeError("boom")

    def flush(self) -> list[ThreatAlert]:
        raise RuntimeError("boom on flush")


class StatefulDetector(Detector):
    """Holds everything back until flush() - the beaconing/scan shape."""

    name = "stateful"
    version = "1.0.0"

    def __init__(self) -> None:
        self.count = 0

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        self.count += 1
        return []

    def flush(self) -> list[ThreatAlert]:
        if self.count == 0:
            return []
        return [make_alert(detector=self.name, evidence={"flows_seen": self.count})]

    def reset(self) -> None:
        self.count = 0


class BadReturnDetector(Detector):
    """Returns something that is not a list of ThreatAlerts."""

    name = "bad_return"
    version = "1.0.0"

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        return "not a list"  # type: ignore[return-value]


class BadItemDetector(Detector):
    """Returns a list containing a non-ThreatAlert."""

    name = "bad_item"
    version = "1.0.0"

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        return ["not an alert"]  # type: ignore[list-item]
