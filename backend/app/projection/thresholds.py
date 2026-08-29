"""The evidence threshold registry.

The Frontend Design Specification section 5.1 asks each evidence row to show
"how far past the line the value landed" - which needs three things the frozen
v1.1 alert does not carry: a threshold, which side of it is bad, and a scale to
draw the bar against.

The detection layer *could* have shipped these, but the alert spec deliberately
keeps ``evidence`` as a flat bag so detectors can add keys without a schema
bump.  So the knowledge lives here instead, keyed by evidence feature name and
scoped by threat class where the same name means different things.

Two honesty rules govern this file:

1. A feature with no registry entry renders as a plain label/value pair with no
   bar.  Spec 5.1: "Do not invent a scale to make them look uniform."  We never
   fabricate a threshold to make a row look decisive.
2. If a detector ships its own threshold inside evidence - a key like
   ``<feature>_threshold`` - that wins over the registry, because the detector
   knows its own operating point and this table is only a fallback.

The default thresholds below are the operating points the detectors are
expected to use; they are documented in docs/DETECTION_THRESHOLDS.md and should
be reconciled with the detection team's tuned values before demo day.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..schemas.enums import ThreatClass


@dataclass(frozen=True, slots=True)
class ThresholdSpec:
    """How one evidence feature should be rendered."""

    label: str
    #: Which side of the threshold indicates the threat.  "above" means a value
    #: greater than the threshold is suspicious.
    direction: Literal["above", "below"]
    threshold: float
    #: [min, max] for the bar track.  Chosen so a typical alerting value sits
    #: visibly - but not pinned - at the far end.
    scale: tuple[float, float]
    unit: str | None = None
    #: Lower sorts earlier.  Spec 5.1: most decisive feature first.
    rank: int = 50


@dataclass(frozen=True, slots=True)
class ContextSpec:
    """A feature that is informative but has no threshold.

    Rendered as a plain label/value pair.  Registering one here does nothing
    except give it a nicer label, a unit, and a sort position.
    """

    label: str
    unit: str | None = None
    rank: int = 80


Spec = ThresholdSpec | ContextSpec


# ---------------------------------------------------------------------------
# Per-threat-class registries.  Keys are evidence feature names from alert spec
# section 7 ("Recommended Evidence Keys by Threat").
# ---------------------------------------------------------------------------

_PORT_SCAN: dict[str, Spec] = {
    "unique_dst_ports": ThresholdSpec(
        "Distinct destination ports", "above", 100, (0, 1500), rank=10
    ),
    "unique_dst_ips": ThresholdSpec(
        "Distinct destination hosts", "above", 25, (0, 300), rank=20
    ),
    "syn_no_ack_ratio": ThresholdSpec(
        "SYN without ACK", "above", 0.7, (0, 1), rank=30
    ),
    "rejected_connections": ThresholdSpec(
        "Rejected connections", "above", 50, (0, 1500), rank=40
    ),
    "connection_attempts": ContextSpec("Connection attempts", rank=60),
    "window_seconds": ContextSpec("Observation window", "s", rank=90),
    "duration_sec": ContextSpec("Duration", "s", rank=90),
}

_DDOS: dict[str, Spec] = {
    "flows_per_sec": ThresholdSpec(
        "Flow rate", "above", 1000, (0, 10_000), "flows/s", rank=10
    ),
    # Source-IP entropy is the feature that separates the two flood shapes, and
    # it is the one a judge is most likely to ask about.  High entropy with no
    # completed handshakes means spoofed sources; low entropy with high volume
    # means a direct flood from a real botnet.  The registry threshold marks the
    # spoofing side, which is the more common case.
    "source_ip_entropy": ThresholdSpec(
        "Source-IP entropy", "above", 6.0, (0, 12), "bits", rank=20
    ),
    "unique_sources": ThresholdSpec(
        "Distinct sources", "above", 500, (0, 10_000), rank=30
    ),
    "syn_no_ack_ratio": ThresholdSpec(
        "SYN without ACK", "above", 0.8, (0, 1), rank=40
    ),
    "bytes_per_sec": ThresholdSpec(
        "Byte rate", "above", 12_500_000, (0, 250_000_000), "B/s", rank=50
    ),
    "amplification_factor": ThresholdSpec(
        "Response/request byte ratio", "above", 10, (0, 200), "x", rank=15
    ),
    "reflector_port": ContextSpec("Reflector port", rank=70),
    "window_seconds": ContextSpec("Observation window", "s", rank=90),
}

_C2_BEACONING: dict[str, Spec] = {
    # Coefficient of variation is the decisive one: near zero is near-perfect
    # regularity, and this is the only class where *low* is bad.
    "interval_cv": ThresholdSpec(
        "Interval coefficient of variation", "below", 0.15, (0, 0.5), rank=10
    ),
    "periodicity_score": ThresholdSpec(
        "Periodicity score", "above", 0.75, (0, 1), rank=15
    ),
    "connection_count": ThresholdSpec(
        "Observed connections", "above", 8, (0, 60), rank=20
    ),
    "observed_periods": ThresholdSpec(
        "Observed periods", "above", 8, (0, 60), rank=20
    ),
    "interval_stddev_sec": ThresholdSpec(
        "Interval std. deviation", "below", 5.0, (0, 60), "s", rank=30
    ),
    "jitter_pct": ThresholdSpec(
        "Jitter", "below", 25.0, (0, 100), "%", rank=35
    ),
    "autocorrelation_peak": ThresholdSpec(
        "Autocorrelation at dominant lag", "above", 0.6, (0, 1), rank=40
    ),
    "payload_size_cv": ThresholdSpec(
        "Payload-size variation", "below", 0.1, (0, 1), rank=45
    ),
    "destination_repetition": ContextSpec("Destination repetition", rank=60),
    "mean_interval_sec": ContextSpec("Mean interval", "s", rank=70),
}

_DGA: dict[str, Spec] = {
    "ngram_score": ThresholdSpec(
        "N-gram likelihood vs. legitimate corpus", "below", 0.2, (0, 1), rank=10
    ),
    "query_entropy": ThresholdSpec(
        "Query entropy", "above", 3.5, (0, 5), "bits/char", rank=20
    ),
    "nxdomain_rate": ThresholdSpec(
        "NXDOMAIN rate for this host", "above", 0.4, (0, 1), rank=15
    ),
    "nxdomain_count": ThresholdSpec(
        "NXDOMAIN responses in window", "above", 20, (0, 200), rank=25
    ),
    "query_length": ThresholdSpec(
        "Query length", "above", 20, (0, 80), "chars", rank=40
    ),
    "digit_ratio": ThresholdSpec("Digit ratio", "above", 0.2, (0, 1), rank=50),
    "consonant_run": ThresholdSpec(
        "Longest consonant run", "above", 4, (0, 15), rank=55
    ),
    "subdomain_entropy": ThresholdSpec(
        "Subdomain entropy", "above", 3.5, (0, 5), "bits/char", rank=45
    ),
    "query": ContextSpec("Queried domain", rank=1),
    "label_count": ContextSpec("Label count", rank=70),
}

_DNS_TUNNELLING: dict[str, Spec] = {
    "query_length": ThresholdSpec(
        "Query length", "above", 60, (0, 255), "chars", rank=10
    ),
    "unique_subdomains": ThresholdSpec(
        "Distinct subdomains under parent", "above", 50, (0, 1000), rank=15
    ),
    "queries_per_sec": ThresholdSpec(
        "Query rate to this authority", "above", 5, (0, 100), "q/s", rank=20
    ),
    "query_entropy": ThresholdSpec(
        "Query entropy", "above", 4.0, (0, 5), "bits/char", rank=30
    ),
    "subdomain_entropy": ThresholdSpec(
        "Subdomain entropy", "above", 4.0, (0, 5), "bits/char", rank=35
    ),
    "txt_ratio": ThresholdSpec(
        "TXT/NULL record share", "above", 0.3, (0, 1), rank=40
    ),
    "record_type": ContextSpec("Record type", rank=50),
    "parent_domain": ContextSpec("Parent domain", rank=1),
    "query": ContextSpec("Sample query", rank=2),
}

_ENCRYPTED_MALWARE: dict[str, Spec] = {
    # Rarity against the learned baseline is the feature that matters, per the
    # Downstream Architecture model 2 discussion.  A boolean "has JA3" carries
    # nothing - nearly every TLS connection has one.
    "ja3_rarity": ThresholdSpec(
        "JA3 rarity vs. baseline", "above", 0.9, (0, 1), rank=10
    ),
    "ja3_frequency": ThresholdSpec(
        "JA3 occurrences in baseline", "below", 5, (0, 1000), rank=15
    ),
    "ja3_novel_for_host": ThresholdSpec(
        "New fingerprint for this host", "above", 0.5, (0, 1), rank=20
    ),
    "sni_absent": ThresholdSpec("SNI absent", "above", 0.5, (0, 1), rank=30),
    "self_signed": ThresholdSpec(
        "Self-signed certificate", "above", 0.5, (0, 1), rank=35
    ),
    "cert_validity_days": ThresholdSpec(
        "Certificate validity window", "below", 30, (0, 400), "days", rank=40
    ),
    "sni_entropy": ThresholdSpec(
        "SNI entropy", "above", 3.5, (0, 5), "bits/char", rank=45
    ),
    "periodicity_score": ThresholdSpec(
        "Session periodicity", "above", 0.75, (0, 1), rank=50
    ),
    "ja3": ContextSpec("JA3 fingerprint", rank=1),
    "ja3s": ContextSpec("JA3S fingerprint", rank=2),
    "ja4": ContextSpec("JA4 fingerprint", rank=3),
    "matched_family": ContextSpec("Matched family", rank=4),
    "ssl_version": ContextSpec("TLS version", rank=60),
    "sni": ContextSpec("SNI", rank=5),
    "mean_pkt_size_orig": ContextSpec("Mean packet size out", "B", rank=65),
    "mean_pkt_size_resp": ContextSpec("Mean packet size in", "B", rank=65),
}

_DATA_EXFILTRATION: dict[str, Spec] = {
    "out_in_byte_ratio": ThresholdSpec(
        "Outbound/inbound byte ratio", "above", 5.0, (0, 100), "x", rank=10
    ),
    "robust_z_score": ThresholdSpec(
        "Deviation from host baseline", "above", 3.5, (0, 20), "sigma", rank=15
    ),
    "anomaly_score": ThresholdSpec(
        "Anomaly score", "above", 0.7, (0, 1), rank=20
    ),
    # Destination novelty deserves prominence: volume alone false-positives on
    # backups, volume to somewhere never seen before is the real signal
    # (Frontend spec 5.2, EX).
    "destination_rarity": ThresholdSpec(
        "Destination rarity", "above", 0.8, (0, 1), rank=12
    ),
    "destination_novel": ThresholdSpec(
        "Destination never contacted before", "above", 0.5, (0, 1), rank=12
    ),
    "outbound_bytes": ThresholdSpec(
        "Outbound volume", "above", 100_000_000, (0, 1_000_000_000), "B", rank=25
    ),
    "time_of_day_deviation": ThresholdSpec(
        "Outside typical active hours", "above", 0.5, (0, 1), rank=40
    ),
    "inbound_bytes": ContextSpec("Inbound volume", "B", rank=60),
    "baseline_ratio": ContextSpec("Baseline ratio", "x", rank=65),
    "baseline_outbound_bytes": ContextSpec("Baseline outbound", "B", rank=66),
    "transfer_duration_sec": ContextSpec("Transfer duration", "s", rank=70),
}


REGISTRY: dict[ThreatClass, dict[str, Spec]] = {
    ThreatClass.PORT_SCAN: _PORT_SCAN,
    ThreatClass.DDOS: _DDOS,
    ThreatClass.C2_BEACONING: _C2_BEACONING,
    ThreatClass.DGA_DOMAIN: _DGA,
    ThreatClass.DNS_TUNNELLING: _DNS_TUNNELLING,
    ThreatClass.ENCRYPTED_MALWARE: _ENCRYPTED_MALWARE,
    ThreatClass.DATA_EXFILTRATION: _DATA_EXFILTRATION,
}

# Features that mean the same thing regardless of which detector emitted them.
# Consulted only when the threat-class registry has no entry.
_SHARED: dict[str, Spec] = {
    "window_seconds": ContextSpec("Observation window", "s", rank=90),
    "duration_sec": ContextSpec("Duration", "s", rank=90),
    "flow_count": ContextSpec("Flows observed", rank=85),
    "model_version": ContextSpec("Model version", rank=95),
    "baseline_samples": ContextSpec("Baseline samples", rank=95),
}


def lookup(threat_class: ThreatClass, feature: str) -> Spec | None:
    """Return the rendering spec for one evidence key, or None if unregistered.

    None is a meaningful answer, not a failure: it means "render this as a plain
    value with no bar", which is exactly what the frontend spec asks for.
    """
    return REGISTRY.get(threat_class, {}).get(feature) or _SHARED.get(feature)


def humanise(feature: str) -> str:
    """Fallback label for an unregistered key: ``out_in_ratio`` -> ``Out in ratio``.

    Deliberately dumb.  A new detector key should still read acceptably on the
    dashboard the day it appears, without anyone editing this file first.
    """
    return feature.replace("_", " ").strip().capitalize()
