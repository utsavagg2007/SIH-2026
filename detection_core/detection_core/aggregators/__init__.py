"""Cross-flow state and alert correlation.

Holds the rolling window state detectors need, keyed by whatever entity the
detector cares about - source IP for port scanning, destination IP for DDoS.
Computed here on purpose: ingestion's global window features (flow_rate,
byte_rate, unique_dst_ports, unique_dst_ips, inter_arrival_mean,
inter_arrival_stddev, src_ip_entropy) are still being corrected upstream and
are not keyed per entity at all, so the adapter ignores them entirely.
See SCHEMA.md.

Still reserved: grouping related ThreatAlerts into incidents by populating
``ThreatAlert.incident_id``.
"""

from __future__ import annotations

from .extremes import WindowExtreme
from .sliding_window import ActivityWindow, FlowObservation, WindowIndex

__all__ = ["ActivityWindow", "FlowObservation", "WindowExtreme", "WindowIndex"]
