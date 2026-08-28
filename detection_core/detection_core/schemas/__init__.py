"""Schemas shared across the detection layer.

``FlowEvent`` is the normalized input contract; ``ThreatAlert`` is the
frozen v1.1 output contract.
"""

from __future__ import annotations

from .enums import MITRE_BY_CLASS, EventScope, ScoreType, Severity, ThreatClass
from .flow_event import DnsInfo, FlowEvent, HttpInfo, TlsInfo
from .threat_alert import ALERT_SCHEMA_VERSION, ThreatAlert
from .timeutil import ensure_utc, epoch_to_utc, now_utc, to_iso8601_z

__all__ = [
    "ALERT_SCHEMA_VERSION",
    "DnsInfo",
    "EventScope",
    "FlowEvent",
    "HttpInfo",
    "MITRE_BY_CLASS",
    "ScoreType",
    "Severity",
    "ThreatAlert",
    "ThreatClass",
    "TlsInfo",
    "ensure_utc",
    "epoch_to_utc",
    "now_utc",
    "to_iso8601_z",
]
