"""Frozen enum vocabulary.

Every value here comes from SIH26_Alert_Output_Spec_v1.1_FINAL.md sections 4
and 12.  Adding a member is a compatible change; renaming or removing one is a
breaking change that requires a ``schema_version`` bump (spec section 18).
"""

from __future__ import annotations

from enum import Enum


class ThreatClass(str, Enum):
    """Spec section 4 - `threat_class`."""

    DGA_DOMAIN = "dga_domain"
    DNS_TUNNELLING = "dns_tunnelling"
    C2_BEACONING = "c2_beaconing"
    ENCRYPTED_MALWARE = "encrypted_malware"
    DDOS = "ddos"
    PORT_SCAN = "port_scan"
    DATA_EXFILTRATION = "data_exfiltration"


class Severity(str, Enum):
    """Spec section 4 - `severity`.

    Emitted by the detection layer.  The backend never recalculates it
    (spec section 4: "backend/frontend must not calculate severity
    independently").
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScoreType(str, Enum):
    """Spec section 4 - `score_type`. Explains what `score` means."""

    CALIBRATED_MODEL = "calibrated_model"
    RULE_SCORE = "rule_score"
    ANOMALY_SCORE = "anomaly_score"
    SIGNATURE_MATCH = "signature_match"


class EventScope(str, Enum):
    """Spec section 4 - `event_scope`. What entity the alert describes."""

    FLOW = "flow"
    SOURCE_HOST = "source_host"
    DESTINATION_HOST = "destination_host"
    HOST_PAIR = "host_pair"
    NETWORK = "network"


class KillChainStage(str, Enum):
    """Ordering for incident narratives (Build Plan layer 5, Frontend 6.1).

    Not part of the frozen alert contract - this is a backend-side derivation
    used only to order alerts inside an incident ribbon.
    """

    RECON = "recon"
    C2 = "c2"
    EXFIL = "exfil"
    IMPACT = "impact"


#: Rank used for "is this incident escalating" comparisons and for picking the
#: dominant severity of a group.  Higher is worse.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

#: Kill-chain position of each threat class.  Reconnaissance precedes command
#: and control, which precedes exfiltration (Build Plan layer 5).  DDoS is
#: terminal impact rather than a step toward anything, so it sorts last.
THREAT_STAGE: dict[ThreatClass, KillChainStage] = {
    ThreatClass.PORT_SCAN: KillChainStage.RECON,
    ThreatClass.DGA_DOMAIN: KillChainStage.C2,
    ThreatClass.DNS_TUNNELLING: KillChainStage.C2,
    ThreatClass.C2_BEACONING: KillChainStage.C2,
    ThreatClass.ENCRYPTED_MALWARE: KillChainStage.C2,
    ThreatClass.DATA_EXFILTRATION: KillChainStage.EXFIL,
    ThreatClass.DDOS: KillChainStage.IMPACT,
}

STAGE_ORDER: dict[KillChainStage, int] = {
    KillChainStage.RECON: 0,
    KillChainStage.C2: 1,
    KillChainStage.EXFIL: 2,
    KillChainStage.IMPACT: 3,
}

#: Two-letter codes for dense listings and Wire marks (Frontend spec 2.2).
#: The spec lists eight codes for eight detectors; the frozen schema carries
#: seven threat classes, with amplification (AM) folded into `ddos`.  We key on
#: the frozen enum and let the projection layer promote AM when the evidence
#: shows a reflector ratio.
THREAT_CODE: dict[ThreatClass, str] = {
    ThreatClass.DDOS: "DF",
    ThreatClass.DGA_DOMAIN: "DG",
    ThreatClass.DNS_TUNNELLING: "DT",
    ThreatClass.PORT_SCAN: "PS",
    ThreatClass.ENCRYPTED_MALWARE: "EC",
    ThreatClass.C2_BEACONING: "BC",
    ThreatClass.DATA_EXFILTRATION: "EX",
}

#: Full names for headings.  Frontend spec section 9: threat classes are
#: written out in full in headings, shortened to the code only in dense lists.
THREAT_LABEL: dict[ThreatClass, str] = {
    ThreatClass.DDOS: "DDoS Flood",
    ThreatClass.DGA_DOMAIN: "DGA Domain",
    ThreatClass.DNS_TUNNELLING: "DNS Tunnelling",
    ThreatClass.PORT_SCAN: "Port Scanning",
    ThreatClass.ENCRYPTED_MALWARE: "Encrypted-Session Malware",
    ThreatClass.C2_BEACONING: "Beaconing",
    ThreatClass.DATA_EXFILTRATION: "Exfiltration",
}
