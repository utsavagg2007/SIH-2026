"""Cross-flow state and alert correlation. RESERVED - nothing implemented yet.

Two future jobs:

1. Correct source/destination/pair-keyed windowed state. Ingestion's current
   global window features (flow_rate, byte_rate, unique_dst_ports,
   unique_dst_ips, inter_arrival_mean, inter_arrival_stddev, src_ip_entropy)
   are deliberately NOT consumed by the adapter - that logic is still being
   corrected upstream. Correct state is computed here, or comes from
   corrected ingestion later.

2. Grouping related ThreatAlerts into incidents by populating
   ``ThreatAlert.incident_id``.
"""

from __future__ import annotations

__all__: list[str] = []
