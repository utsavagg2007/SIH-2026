"""Concrete detectors. RESERVED - nothing implemented yet.

Each future detector subclasses ``detection_core.engine.Detector`` and
implements::

    process(flow: FlowEvent) -> list[ThreatAlert]

``process()`` alerts immediately, the moment its condition is satisfied -
this is a near-real-time streaming system. A detector holding rolling state
also implements ``reset()`` to clear it, and ``flush()`` only to settle
state still pending when a finite replay ends.

Planned, one module per threat class:
    dga_domain, dns_tunnelling, c2_beaconing, encrypted_malware,
    ddos, port_scan, data_exfiltration

Note: several of these are blocked on raw fields current ingestion does not
emit (see SCHEMA.md "Integration TODOs").
"""

from __future__ import annotations

__all__: list[str] = []
