"""detection_core - the detection / ML layer.

    ingestion output
        -> adapter
        -> normalized FlowEvent
        -> DetectionEngine
        -> statistical detectors / ML models
        -> standardized ThreatAlert v1.1

This package never imports ``ingestion_core`` and never reads Zeek logs or
PCAPs. Its only contact with the ingestion team is the JSONL file format,
handled entirely inside ``detection_core.adapters``.
"""

from __future__ import annotations

from .adapters import FlowSource, IngestionJsonlAdapter
from .detectors import PortScanConfig, PortScanDetector
from .engine import DetectionEngine, Detector
from .schemas import (
    ALERT_SCHEMA_VERSION,
    DnsInfo,
    EventScope,
    FlowEvent,
    HttpInfo,
    ScoreType,
    Severity,
    ThreatAlert,
    ThreatClass,
    TlsInfo,
)

__version__ = "0.1.0"

__all__ = [
    "ALERT_SCHEMA_VERSION",
    "DetectionEngine",
    "Detector",
    "DnsInfo",
    "EventScope",
    "FlowEvent",
    "FlowSource",
    "HttpInfo",
    "IngestionJsonlAdapter",
    "PortScanConfig",
    "PortScanDetector",
    "ScoreType",
    "Severity",
    "ThreatAlert",
    "ThreatClass",
    "TlsInfo",
    "__version__",
]
