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
from .detectors import (
    BeaconKey,
    C2BeaconingConfig,
    C2BeaconingDetector,
    DataExfiltrationConfig,
    DataExfiltrationDetector,
    DDoSConfig,
    DDoSDetector,
    DGAConfig,
    DGADetector,
    DnsAggregate,
    DnsObservation,
    DnsTunnelKey,
    DnsTunnellingConfig,
    DnsTunnellingDetector,
    DomainClassifier,
    EncryptedMalwareConfig,
    EncryptedMalwareDetector,
    ExfilKey,
    ExfilStats,
    FingerprintKey,
    PortScanConfig,
    PortScanDetector,
    TlsAggregate,
    TlsObservation,
    TlsPairKey,
)
from .engine import DetectionEngine, Detector
from .pipeline import (
    AlertDeliveryError,
    AlertSink,
    HttpAlertSink,
    JsonlAlertSink,
    MultiSink,
    RunStats,
    build_default_detectors,
    run_detection,
)
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
    "AlertDeliveryError",
    "AlertSink",
    "BeaconKey",
    "C2BeaconingConfig",
    "C2BeaconingDetector",
    "DataExfiltrationConfig",
    "DataExfiltrationDetector",
    "DDoSConfig",
    "DDoSDetector",
    "DGAConfig",
    "DGADetector",
    "DetectionEngine",
    "Detector",
    "DnsAggregate",
    "DnsInfo",
    "DnsObservation",
    "DnsTunnelKey",
    "DnsTunnellingConfig",
    "DnsTunnellingDetector",
    "DomainClassifier",
    "EncryptedMalwareConfig",
    "EncryptedMalwareDetector",
    "EventScope",
    "ExfilKey",
    "ExfilStats",
    "FingerprintKey",
    "FlowEvent",
    "FlowSource",
    "HttpAlertSink",
    "HttpInfo",
    "IngestionJsonlAdapter",
    "JsonlAlertSink",
    "MultiSink",
    "PortScanConfig",
    "PortScanDetector",
    "RunStats",
    "ScoreType",
    "Severity",
    "ThreatAlert",
    "ThreatClass",
    "TlsAggregate",
    "TlsInfo",
    "TlsObservation",
    "TlsPairKey",
    "__version__",
    "build_default_detectors",
    "run_detection",
]
