"""Cross-flow state and alert correlation.

Holds the rolling per-source window state detectors need. Computed here on
purpose: ingestion's global window features (flow_rate, byte_rate,
unique_dst_ports, unique_dst_ips, inter_arrival_mean, inter_arrival_stddev,
src_ip_entropy) are still being corrected upstream and are not keyed per
source, so the adapter ignores them entirely. See SCHEMA.md.

Still reserved: grouping related ThreatAlerts into incidents by populating
``ThreatAlert.incident_id``.
"""

from __future__ import annotations

from .sliding_window import FlowObservation, SourceActivityWindow, SourceWindowIndex

__all__ = ["FlowObservation", "SourceActivityWindow", "SourceWindowIndex"]
