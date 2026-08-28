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
    port_scan - vertical and horizontal port scanning (source-keyed state)
    ddos      - many sources flooding one destination (destination-keyed state)

Planned, one module per remaining threat class:
    dga_domain, dns_tunnelling, c2_beaconing, encrypted_malware,
    data_exfiltration

Note: several of those are blocked on raw fields current ingestion does not
emit (see SCHEMA.md "Integration TODOs").
"""

from __future__ import annotations

from .ddos import DDoSConfig, DDoSDetector
from .port_scan import PortScanConfig, PortScanDetector

__all__ = ["DDoSConfig", "DDoSDetector", "PortScanConfig", "PortScanDetector"]
