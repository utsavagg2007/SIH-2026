"""Concrete detectors.

Each detector subclasses ``detection_core.engine.Detector`` and implements::

    process(flow: FlowEvent) -> list[ThreatAlert]

``process()`` alerts immediately, the moment its condition is satisfied -
this is a near-real-time streaming system. A detector holding rolling state
also implements ``reset()`` to clear it, and ``flush()`` only to settle
state still pending when a finite replay ends.

Rule scores and severity bands come from ``scoring`` so every detector's
output lands on one comparable scale.

Implemented:
    port_scan     - vertical and horizontal port scanning (source-keyed)
    ddos          - many sources flooding one destination (destination-keyed)
    c2_beaconing  - regular timed contact on one relationship
                    (src, dst, port, proto)-keyed
    dns_tunnelling - repeatedly abnormal DNS to one resolver
                    (src, dst)-keyed
    data_exfiltration - bulk outbound bytes concentrated on one
                    destination (src, dst)-keyed
    encrypted_malware - malicious TLS fingerprints, and repeatedly
                    generated-looking SNI (src, dst)-keyed
    dga_domain    - Phase-2 live wrapper around the ml/dga model

All threat classes now have a detector. The integrated detector-v2 profile
supplies the formerly missing raw protocol fields; DGA still requires an
operator-provided trained model and fingerprint matching still requires a
trusted local indicator feed.

Note: ``dga`` imports ``detection_core.ml`` (scikit-learn) only when a
DGADetector is CONSTRUCTED, so importing this package stays dependency-free.

"""

from __future__ import annotations

from .c2_beaconing import BeaconKey, C2BeaconingConfig, C2BeaconingDetector
from .data_exfiltration import (
    QUALIFICATION_BOTH,
    QUALIFICATION_SINGLE,
    QUALIFICATION_SUSTAINED,
    DataExfiltrationConfig,
    DataExfiltrationDetector,
    ExfilKey,
    ExfilStats,
)
from .ddos import DDoSConfig, DDoSDetector
from .dga import DGAConfig, DGADetector, DomainClassifier
from .encrypted_malware import (
    DETECTION_FINGERPRINT,
    DETECTION_METADATA,
    EncryptedMalwareConfig,
    EncryptedMalwareDetector,
    FingerprintKey,
    TlsAggregate,
    TlsObservation,
    TlsPairKey,
)
from .dns_tunnelling import (
    DnsAggregate,
    DnsObservation,
    DnsTunnelKey,
    DnsTunnellingConfig,
    DnsTunnellingDetector,
)
from .port_scan import PortScanConfig, PortScanDetector

__all__ = [
    "DETECTION_FINGERPRINT",
    "DETECTION_METADATA",
    "QUALIFICATION_BOTH",
    "QUALIFICATION_SINGLE",
    "QUALIFICATION_SUSTAINED",
    "BeaconKey",
    "C2BeaconingConfig",
    "C2BeaconingDetector",
    "DataExfiltrationConfig",
    "DataExfiltrationDetector",
    "DDoSConfig",
    "DDoSDetector",
    "DGAConfig",
    "DGADetector",
    "DnsAggregate",
    "DnsObservation",
    "DnsTunnelKey",
    "DnsTunnellingConfig",
    "DnsTunnellingDetector",
    "DomainClassifier",
    "EncryptedMalwareConfig",
    "EncryptedMalwareDetector",
    "ExfilKey",
    "ExfilStats",
    "FingerprintKey",
    "PortScanConfig",
    "PortScanDetector",
    "TlsAggregate",
    "TlsObservation",
    "TlsPairKey",
]
