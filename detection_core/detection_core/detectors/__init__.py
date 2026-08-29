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

Planned, one module per remaining threat class:
    dga_domain, encrypted_malware

Note: several of those are blocked on raw fields current ingestion does not
emit (see SCHEMA.md "Integration TODOs").
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
from .dns_tunnelling import (
    DnsAggregate,
    DnsObservation,
    DnsTunnelKey,
    DnsTunnellingConfig,
    DnsTunnellingDetector,
)
from .port_scan import PortScanConfig, PortScanDetector

__all__ = [
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
    "DnsAggregate",
    "DnsObservation",
    "DnsTunnelKey",
    "DnsTunnellingConfig",
    "DnsTunnellingDetector",
    "ExfilKey",
    "ExfilStats",
    "PortScanConfig",
    "PortScanDetector",
]
