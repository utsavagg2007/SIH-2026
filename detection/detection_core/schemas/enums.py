"""Frozen vocabularies for the ThreatAlert v1.1 contract.

These four enums are part of the wire contract agreed with the full-stack
team. Do not add, rename or remove members without bumping the alert
``schema_version``.
"""

from __future__ import annotations

from enum import Enum

__all__ = [
    "ThreatClass",
    "Severity",
    "ScoreType",
    "EventScope",
    "MITRE_BY_CLASS",
]


class ThreatClass(str, Enum):
    """What kind of threat an alert asserts."""

    DGA_DOMAIN = "dga_domain"
    DNS_TUNNELLING = "dns_tunnelling"
    C2_BEACONING = "c2_beaconing"
    ENCRYPTED_MALWARE = "encrypted_malware"
    DDOS = "ddos"
    PORT_SCAN = "port_scan"
    DATA_EXFILTRATION = "data_exfiltration"


class Severity(str, Enum):
    """Analyst-facing urgency. Chosen by the detector, never auto-derived."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScoreType(str, Enum):
    """How ``ThreatAlert.score`` was produced.

    The semantics differ per member, but the wire value is always a
    normalized 0.0-1.0 threat score so the UI can render it consistently.
    """

    CALIBRATED_MODEL = "calibrated_model"
    RULE_SCORE = "rule_score"
    ANOMALY_SCORE = "anomaly_score"
    SIGNATURE_MATCH = "signature_match"


class EventScope(str, Enum):
    """What entity the alert is about.

    Aggregate scopes (anything other than ``flow``) may legitimately leave
    ``flow_id`` unset.
    """

    FLOW = "flow"
    SOURCE_HOST = "source_host"
    DESTINATION_HOST = "destination_host"
    HOST_PAIR = "host_pair"
    NETWORK = "network"


# Non-normative default ATT&CK hints, so detectors do not each hardcode IDs.
# Not part of the wire contract; a detector may override per alert.
MITRE_BY_CLASS: dict[ThreatClass, tuple[str, ...]] = {
    ThreatClass.DGA_DOMAIN: ("T1568.002",),
    ThreatClass.DNS_TUNNELLING: ("T1071.004", "T1048.003"),
    ThreatClass.C2_BEACONING: ("T1071.001", "T1029"),
    ThreatClass.ENCRYPTED_MALWARE: ("T1573.002",),
    ThreatClass.DDOS: ("T1498", "T1499"),
    ThreatClass.PORT_SCAN: ("T1046",),
    ThreatClass.DATA_EXFILTRATION: ("T1041", "T1048"),
}
