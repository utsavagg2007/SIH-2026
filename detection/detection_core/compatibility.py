"""Explicit, conservative policy for the currently audited NetFlow consumers."""

from __future__ import annotations

from .schemas.canonical_flow import CanonicalFlowEvent

# Requirements reflect production decision paths, not all evidence fields.
# Payload bytes cannot be replaced by IP bytes. DNS/TLS cannot be inferred.
NETFLOW_MISSING = {
    "port_scan": ("classified_connection_state_or_responder_payload",),
    "c2_beaconing": ("src_to_dst.payload_bytes",),
    "data_exfiltration": ("src_to_dst.payload_bytes",),
    "dns_tunnelling": ("dns_observations",),
    "encrypted_malware": ("tls_observations",),
    "dga_domain": ("dns.query",),
}


def canonical_skip_reason(detector: object, flow: CanonicalFlowEvent) -> str | None:
    # Import lazily: detector modules themselves depend on the engine.
    from .detectors.ddos import DDoSDetector

    if flow.source not in ("netflow_v5", "netflow_v9"):
        return "unsupported_telemetry_source"
    # Names alone cannot authorize an unaudited custom consumer.
    if type(detector) is DDoSDetector:
        return "missing_required_features:src_to_dst.packets" if flow.orig_pkts is None else None
    name = getattr(detector, "name", "unknown")
    if name in NETFLOW_MISSING:
        return "missing_required_features:" + ",".join(NETFLOW_MISSING[name])
    return "unsupported_canonical_consumer"
