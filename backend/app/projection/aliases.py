"""Reconciling the detector's evidence vocabulary with the contract's.

The frozen alert contract (section 7) lists *recommended* evidence keys per
threat class and says in as many words that they are "recommended, not globally
mandatory". The detection layer took that at its word and named its keys after
what it measures - ``coefficient_of_variation``, ``mean_interval_seconds``,
``unique_src_ips`` - while this backend's threshold registry and visual builders
were written against the contract's spelling: ``interval_cv``,
``mean_interval_sec``, ``unique_sources``.

Neither side is wrong, and neither should have to move. What was wrong was the
consequence: an unrecognised key falls through to a plain label/value row with
no bar, and a visual builder that cannot find the number it needs returns None.
Measured against real detector output, five of seven threat classes rendered no
class visual and almost no thresholded evidence - the two things the
supporting-evidence requirement is actually graded on.

So the vocabularies are reconciled here, in one file, explicitly.

Two kinds of mapping, and the difference matters
------------------------------------------------
**Feature aliases** rename an observed value onto the contract's spelling. Pure
renaming; the number is unchanged.

**Operating points** are the more valuable half. The detectors already ship
their own thresholds inside evidence - ``min_unique_ports``, ``max_interval_cv``,
``min_suspicious_ratio`` - but under a ``min_``/``max_`` prefix convention,
while ``evidence.py`` looks for a ``<feature>_threshold`` suffix. So the real
operating point sat unused beside a fallback from a static table. Mapping them
across means the bar on the dashboard shows the line the detector actually
drew, which is what ``thresholds.py``'s own second honesty rule asks for: "If a
detector ships its own threshold inside evidence... that wins over the registry,
because the detector knows its own operating point and this table is only a
fallback."

Every entry below is transcribed from a detector's ``_build_alert`` method and
verified against real emitted alerts, not guessed from the naming. That
distinction is load-bearing: ``max_query_length`` in ``dns_tunnelling`` is the
longest query *observed*, not a threshold, and treating the ``max_`` prefix as a
rule rather than reading the source would have turned an observation into an
operating point and drawn a confident, wrong bar.

Nothing here mutates a stored value. ``AlertView.evidence_raw`` and
``AlertView.raw`` keep the detector's own words verbatim; this only feeds the
projection.
"""

from __future__ import annotations

from typing import Any

from ..schemas.enums import ThreatClass

__all__ = ["canonicalise_evidence"]


#: Observed values, renamed onto the contract's spelling.
_FEATURE_ALIASES: dict[ThreatClass, dict[str, str]] = {
    ThreatClass.C2_BEACONING: {
        "coefficient_of_variation": "interval_cv",
        "mean_interval_seconds": "mean_interval_sec",
        "interval_stddev_seconds": "interval_stddev_sec",
        "observation_count": "connection_count",
        "total_orig_bytes": "outbound_bytes",
    },
    ThreatClass.DDOS: {
        "unique_src_ips": "unique_sources",
        "flows_per_second": "flows_per_sec",
        "packets_per_second": "packets_per_sec",
        "packet_count": "packet_total",
        "byte_count": "byte_total",
    },
    ThreatClass.DATA_EXFILTRATION: {
        "total_orig_bytes": "outbound_bytes",
        "total_resp_bytes": "inbound_bytes",
        "orig_bytes_per_second": "outbound_bytes_per_sec",
        "observed_span_seconds": "transfer_duration_sec",
    },
    ThreatClass.DNS_TUNNELLING: {
        "observation_count": "query_count",
        "mean_query_length": "query_length",
        "mean_query_entropy": "query_entropy",
        "mean_subdomain_entropy": "subdomain_entropy",
        "mean_label_count": "label_count",
    },
    ThreatClass.ENCRYPTED_MALWARE: {
        "mean_sni_entropy": "sni_entropy",
        "max_sni_entropy": "sni_entropy_max",
        "tls_version": "ssl_version",
        "server_name": "sni",
        "obsolete_tls_version_ratio": "obsolete_version_ratio",
    },
    ThreatClass.DGA_DOMAIN: {
        "domain": "query",
        "dga_model_score": "model_score",
        "distinct_dga_domain_count": "distinct_domains",
    },
    ThreatClass.PORT_SCAN: {
        # port_scan already speaks the contract's vocabulary for its observed
        # values; only its operating points needed mapping.
    },
}


#: Detector-shipped operating points, mapped onto the feature each one bounds.
#: The value is the CONTRACT feature name - that is, the name after the alias
#: table above has been applied - because that is the key ``evidence.py`` will
#: be looking beside.
_OPERATING_POINTS: dict[ThreatClass, dict[str, str]] = {
    ThreatClass.PORT_SCAN: {
        "min_unique_ports": "unique_dst_ports",
        "min_unique_hosts": "unique_dst_ips",
    },
    ThreatClass.DDOS: {
        "min_unique_sources": "unique_sources",
        "min_flows": "flow_count",
        "min_packets": "packet_total",
    },
    ThreatClass.C2_BEACONING: {
        # The coefficient of variation is the detection: near-zero means
        # near-perfect regularity, so the threshold is an upper bound.
        "max_interval_cv": "interval_cv",
        "min_observations": "connection_count",
    },
    ThreatClass.DNS_TUNNELLING: {
        "min_suspicious_ratio": "suspicious_ratio",
        "min_dns_observations": "query_count",
    },
    ThreatClass.DATA_EXFILTRATION: {
        "min_total_orig_bytes": "outbound_bytes",
        "min_destination_concentration": "destination_concentration",
        "min_flows": "flow_count",
    },
    ThreatClass.ENCRYPTED_MALWARE: {
        "min_suspicious_ratio": "suspicious_ratio",
        "min_tls_observations": "tls_observation_count",
    },
    ThreatClass.DGA_DOMAIN: {
        # The DGA detector names its operating point ``score_threshold``, which
        # already ends in the suffix ``evidence.py`` strips - so it was being
        # discarded as the threshold for a feature called ``score``, which does
        # not exist. Pointing it at the model score makes it render.
        "score_threshold": "model_score",
    },
}

#: ``evidence.py`` reads a detector's operating point from ``<feature>_threshold``.
_THRESHOLD_SUFFIX = "_threshold"


def canonicalise_evidence(
    threat_class: ThreatClass, evidence: dict[str, Any]
) -> dict[str, Any]:
    """Evidence with detector spellings mapped onto the contract vocabulary.

    Returns a new dict; the input is never modified. Three rules, in order:

    1. An alias is applied only when the contract name is not already present.
       A detector that starts emitting the contract name directly immediately
       wins over its own alias, so this table decays gracefully rather than
       having to be maintained forever.
    2. An operating point becomes ``<feature>_threshold`` and its original key
       is dropped, because leaving both would render the threshold twice - once
       as the line on the bar and once as a meaningless row of its own.
    3. Anything unrecognised passes through untouched. A new detector key must
       still reach the dashboard the day it appears.
    """
    feature_map = _FEATURE_ALIASES.get(threat_class, {})
    operating = _OPERATING_POINTS.get(threat_class, {})

    result: dict[str, Any] = {}
    deferred: dict[str, Any] = {}

    for key, value in evidence.items():
        if key in operating:
            # Held back until the pass below, so it lands beside its feature
            # under the name evidence.py expects.
            deferred[operating[key]] = value
            continue

        target = feature_map.get(key, key)
        if target != key and target in evidence:
            # Rule 1: the detector already speaks the contract name. Keep both,
            # under their own names, and let the registry find the real one.
            result[key] = value
            continue
        result[target] = value

    for feature, threshold in deferred.items():
        result[f"{feature}{_THRESHOLD_SUFFIX}"] = threshold

    # The encrypted-session fingerprint is the one conditional mapping: the
    # detector reports the hash in ``fingerprint`` and says which kind it is in
    # ``fingerprint_type``, while the visual builder looks for ``ja3``/``ja4``
    # by name. Renaming unconditionally would file a JA4 hash under ``ja3``.
    kind = evidence.get("fingerprint_type")
    fingerprint = evidence.get("fingerprint")
    if isinstance(kind, str) and isinstance(fingerprint, str):
        target = kind.strip().lower()
        if target in {"ja3", "ja3s", "ja4"} and target not in result:
            result[target] = fingerprint

    return result
