"""Class-specific evidence visuals (Frontend spec 5.2).

Each threat class gets a ``visual`` object keyed by ``kind``; the frontend
switches on that key.  An unknown or absent ``kind`` falls back to evidence bars
alone, so a new detector never breaks the interface.

Provenance is the important idea in this module.  Some visuals need a *series* -
the beacon comb needs connection timestamps, the fan-out matrix needs contacted
ports - and the frozen v1.1 evidence bag may or may not contain one.  When it
does, we plot observations.  When it does not, we can sometimes reconstruct a
plausible series from the summary statistics the detector did report, and every
such payload is stamped::

    "source": "reconstructed_from_summary_statistics"

The frontend must render that differently from observed data.  This matters: a
comb drawn from ``mean_interval_sec`` and ``connection_count`` will look like a
perfect beacon by construction, because we built it that way.  Presenting it as
observed evidence would be fabricating the most convincing image in the product.
The honest fix is for detectors to ship ``timestamps`` in evidence; until they
do, the flag keeps the claim accurate.
"""

from __future__ import annotations

import math
from typing import Any

from ..schemas.alert_v11 import ThreatAlertV11
from ..schemas.enums import ThreatClass

OBSERVED = "observed"
RECONSTRUCTED = "reconstructed_from_summary_statistics"

#: Ceiling on fan-out matrix cells. A scan across 1024 ports is summarised by
#: sampling rather than by shipping every contact: the grid is a picture of the
#: sweep's shape, and the exact count travels as a scalar beside it.
_MAX_FANOUT_CELLS = 120


def _num(evidence: dict[str, Any], *keys: str) -> float | None:
    """First numeric value among ``keys``, or None.

    Detectors vary in what they call things (``connection_count`` vs
    ``observed_periods``), and the alert spec's evidence key lists are
    "recommended, not globally mandatory".  Accepting synonyms costs one tuple
    and avoids a visual silently disappearing because of a naming difference.
    """
    for k in keys:
        v = evidence.get(k)
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            return float(v)
    return None


def _series(evidence: dict[str, Any], *keys: str) -> list[float] | None:
    """First numeric list among ``keys``, or None."""
    for k in keys:
        v = evidence.get(k)
        if isinstance(v, list) and v:
            nums = [
                float(x)
                for x in v
                if isinstance(x, (int, float)) and not isinstance(x, bool)
            ]
            if len(nums) == len(v):
                return nums
    return None


def _str_series(evidence: dict[str, Any], *keys: str) -> list[str] | None:
    for k in keys:
        v = evidence.get(k)
        if isinstance(v, list) and v:
            return [str(x) for x in v]
    return None


# ---------------------------------------------------------------------------
# BC - beacon comb (Frontend spec 5.2)
# ---------------------------------------------------------------------------


def _beacon_comb(alert: ThreatAlertV11) -> dict[str, Any] | None:
    ev = alert.evidence
    start = alert.event_start.timestamp()
    end = alert.event_end.timestamp()

    observed = _series(ev, "timestamps", "connection_timestamps")
    mean_interval = _num(ev, "mean_interval_sec", "mean_interval_s")
    stddev = _num(ev, "interval_stddev_sec", "interval_stddev_s")
    count = _num(ev, "connection_count", "observed_periods")

    jitter = _num(ev, "jitter_pct")
    if jitter is None and mean_interval and stddev is not None and mean_interval > 0:
        jitter = (stddev / mean_interval) * 100.0

    if observed:
        timestamps = observed
        source = OBSERVED
    elif mean_interval and mean_interval > 0 and count and count >= 2:
        # Reconstruct evenly spaced ticks from the reported mean interval.  This
        # shows the *claim* the detector is making, not the observations behind
        # it - hence the source flag.  We do not add synthetic jitter: inventing
        # scatter would be inventing data twice over.
        n = int(min(count, 500))
        timestamps = [start + i * mean_interval for i in range(n)]
        timestamps = [t for t in timestamps if t <= end + mean_interval]
        source = RECONSTRUCTED
    else:
        return None

    intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]

    # Interval histogram: a beacon's intervals pile into one narrow bin, and the
    # tightness of that pile is the detection (frontend spec 5.2).
    histogram: list[dict[str, float]] = []
    if intervals:
        lo, hi = min(intervals), max(intervals)
        if hi - lo < 1e-9:
            histogram = [{"bin_start": lo, "bin_end": lo, "count": len(intervals)}]
        else:
            bins = 20
            width = (hi - lo) / bins
            counts = [0] * bins
            for iv in intervals:
                idx = min(int((iv - lo) / width), bins - 1)
                counts[idx] += 1
            histogram = [
                {
                    "bin_start": lo + i * width,
                    "bin_end": lo + (i + 1) * width,
                    "count": c,
                }
                for i, c in enumerate(counts)
            ]

    # Derive the axis from the series itself when the series extends past the
    # declared event window. A detector reporting a 1-second window alongside an
    # hour of connection timestamps is describing a summary, not a contradiction
    # - but plotting those ticks against the 1-second window puts every one of
    # them off-scale and renders an empty comb.
    axis_start = min(start, timestamps[0]) if timestamps else start
    axis_end = max(end, timestamps[-1]) if timestamps else end
    if axis_end <= axis_start:
        axis_end = axis_start + 1.0

    return {
        "kind": "beacon_comb",
        "source": source,
        "window_start": axis_start,
        "window_end": axis_end,
        "timestamps": timestamps,
        "intervals": intervals,
        "interval_histogram": histogram,
        "mean_interval_sec": mean_interval,
        "jitter_pct": round(jitter, 2) if jitter is not None else None,
        "interval_cv": _num(ev, "interval_cv"),
        "periodicity_score": _num(ev, "periodicity_score"),
    }


# ---------------------------------------------------------------------------
# PS - fan-out matrix (Frontend spec 5.2)
# ---------------------------------------------------------------------------


def _fanout_matrix(alert: ThreatAlertV11) -> dict[str, Any] | None:
    ev = alert.evidence
    ports = _series(ev, "port_series", "contacted_ports")
    unique_ports = _num(ev, "unique_dst_ports")
    unique_ips = _num(ev, "unique_dst_ips")
    if ports is None and unique_ports is None:
        return None

    rejected_ratio = _num(ev, "syn_no_ack_ratio") or 0.0

    # Columnar, and capped. Three parallel arrays cost a fraction of what a
    # dict-per-cell costs to build, sanitise and serialise - and at flood rates
    # that difference is most of the backend's per-alert budget. The cap is a
    # display decision too: a grid with more cells than horizontal pixels
    # renders as a solid block either way, so nothing is lost by sampling. The
    # true totals travel separately in unique_dst_ports.
    cell_ports: list[int] = []
    cell_offsets: list[float] = []
    cell_rejected: list[bool] = []
    source = OBSERVED

    if ports:
        span = max(alert.duration_sec, 1e-6)
        n = len(ports)
        stride = max(1, n // _MAX_FANOUT_CELLS)
        sampled = ports[::stride][:_MAX_FANOUT_CELLS]
        m = len(sampled)
        for i, p in enumerate(sampled):
            cell_ports.append(int(p))
            # Contact times were not reported per port, so position the cell by
            # its index across the observed window. The shape of the sweep is
            # preserved; the exact instant is not claimed.
            cell_offsets.append(round((i / max(m - 1, 1)) * span, 4))
            cell_rejected.append((i / max(m, 1)) < rejected_ratio)
    else:
        source = RECONSTRUCTED

    return {
        "kind": "fanout_matrix",
        "source": source,
        "cell_ports": cell_ports,
        "cell_offsets": cell_offsets,
        "cell_rejected": cell_rejected,
        "cells_sampled": len(cell_ports),
        "cells_total": len(ports) if ports else 0,
        "unique_dst_ports": int(unique_ports) if unique_ports else None,
        "unique_dst_ips": int(unique_ips) if unique_ips else None,
        "connection_attempts": _num(ev, "connection_attempts"),
        "rejected_connections": _num(ev, "rejected_connections"),
        "syn_no_ack_ratio": rejected_ratio,
        "duration_sec": alert.duration_sec,
        # Vertical = many ports on few hosts; horizontal = few ports across many
        # hosts.  Naming the pattern is what makes the picture read instantly.
        "pattern": _scan_pattern(unique_ports, unique_ips),
    }


def _scan_pattern(ports: float | None, ips: float | None) -> str:
    if not ports or not ips:
        return "unknown"
    if ports >= 50 and ips <= 3:
        return "vertical"
    if ips >= 20 and ports <= 5:
        return "horizontal"
    if ports >= 20 and ips >= 20:
        return "block"
    return "mixed"


# ---------------------------------------------------------------------------
# DF / AM - entropy against rate (Frontend spec 5.2)
# ---------------------------------------------------------------------------


def _rate_entropy(alert: ThreatAlertV11) -> dict[str, Any] | None:
    ev = alert.evidence
    rate_series = _series(ev, "rate_series")
    entropy_series = _series(ev, "entropy_series")
    flows_per_sec = _num(ev, "flows_per_sec")
    entropy = _num(ev, "source_ip_entropy")
    if flows_per_sec is None and rate_series is None:
        return None

    amplification = _num(ev, "amplification_factor")
    syn_ratio = _num(ev, "syn_no_ack_ratio")

    # The two flood shapes the detector distinguishes.  High source entropy with
    # no completed handshakes means the sources are forged; low entropy with
    # high volume means a real, concentrated set of attackers.
    if entropy is not None and syn_ratio is not None:
        if entropy >= 6.0 and syn_ratio >= 0.7:
            signature = "spoofed_flood"
        elif entropy < 3.0:
            signature = "direct_flood"
        else:
            signature = "mixed"
    else:
        signature = "unknown"
    if amplification and amplification >= 5:
        signature = "amplification"

    step = _num(ev, "series_step_sec") or 1.0
    t0 = _num(ev, "series_start") or alert.event_start.timestamp()

    return {
        "kind": "rate_entropy",
        "source": OBSERVED if rate_series else RECONSTRUCTED,
        "signature": signature,
        "series_start": t0,
        "series_step_sec": step,
        "rate_series": rate_series,
        "entropy_series": entropy_series,
        "flows_per_sec": flows_per_sec,
        "bytes_per_sec": _num(ev, "bytes_per_sec"),
        "packets_per_sec": _num(ev, "packets_per_sec"),
        "source_ip_entropy": entropy,
        "unique_sources": _num(ev, "unique_sources"),
        "syn_no_ack_ratio": syn_ratio,
        "amplification_factor": amplification,
        "reflector_port": ev.get("reflector_port"),
        # Drawn in --baseline as the learned-normal band.  Only present when the
        # detector reported one; we do not guess at what normal looks like.
        "baseline_band": _series(ev, "baseline_band"),
        "window_seconds": _num(ev, "window_seconds"),
    }


# ---------------------------------------------------------------------------
# DG - string inspector (Frontend spec 5.2)
# ---------------------------------------------------------------------------


def _string_inspector(alert: ThreatAlertV11) -> dict[str, Any] | None:
    ev = alert.evidence
    query = ev.get("query") or ev.get("domain")
    if not isinstance(query, str) or not query:
        return None

    heat = _series(ev, "ngram_heat")
    source = OBSERVED if heat else RECONSTRUCTED
    if not heat:
        # Without per-character n-gram scores from the model we fall back to a
        # local character-class heuristic: digits and long consonant runs are
        # improbable in legitimate hostnames.  This is a display aid derived
        # from the string itself, not a second opinion on the model's score,
        # and the source flag says so.
        heat = _character_heat(query)

    return {
        "kind": "string_inspector",
        "source": source,
        "query": query,
        "characters": list(query),
        "ngram_heat": heat[: len(query)],
        "model_score": alert.score,
        "ngram_score": _num(ev, "ngram_score"),
        "query_entropy": _num(ev, "query_entropy"),
        "query_length": _num(ev, "query_length") or len(query),
        "digit_ratio": _num(ev, "digit_ratio"),
        # The behavioural half of the detection, on the same screen as the
        # string half (frontend spec 5.2, DG).
        "nxdomain_series": _series(ev, "nxdomain_series"),
        "nxdomain_count": _num(ev, "nxdomain_count"),
        "nxdomain_rate": _num(ev, "nxdomain_rate"),
    }


_VOWELS = frozenset("aeiou")


def _character_heat(query: str) -> list[float]:
    """Per-character improbability in [0, 1], from character class alone."""
    heat: list[float] = []
    run = 0
    for ch in query.lower():
        if ch in ".-":
            run = 0
            heat.append(0.0)
        elif ch.isdigit():
            run = 0
            heat.append(0.85)
        elif ch in _VOWELS:
            run = 0
            heat.append(0.15)
        else:
            run += 1
            heat.append(min(0.35 + 0.2 * run, 1.0))
    return heat


# ---------------------------------------------------------------------------
# DT - subdomain fan-out (Frontend spec 5.2)
# ---------------------------------------------------------------------------


def _subdomain_fanout(alert: ThreatAlertV11) -> dict[str, Any] | None:
    ev = alert.evidence
    subdomains = _str_series(ev, "subdomains", "subdomain_samples")
    cardinality = _num(ev, "unique_subdomains", "subdomain_cardinality")
    parent = ev.get("parent_domain")
    if subdomains is None and cardinality is None:
        return None

    lengths = [len(s) for s in subdomains] if subdomains else []
    return {
        "kind": "subdomain_fanout",
        "source": OBSERVED if subdomains else RECONSTRUCTED,
        "parent_domain": parent,
        "subdomains": (subdomains or [])[:200],
        "cardinality": int(cardinality) if cardinality else len(subdomains or []),
        "queries_per_sec": _num(ev, "queries_per_sec"),
        "query_length": _num(ev, "query_length"),
        "query_length_distribution": _length_histogram(lengths),
        "query_entropy": _num(ev, "query_entropy"),
        "record_type": ev.get("record_type"),
        "txt_ratio": _num(ev, "txt_ratio"),
    }


def _length_histogram(lengths: list[int]) -> list[dict[str, int]]:
    """Query-length strip. Tunnels sit far right of normal DNS."""
    if not lengths:
        return []
    buckets: dict[int, int] = {}
    for n in lengths:
        buckets[(n // 10) * 10] = buckets.get((n // 10) * 10, 0) + 1
    return [
        {"bin_start": k, "bin_end": k + 10, "count": v}
        for k, v in sorted(buckets.items())
    ]


# ---------------------------------------------------------------------------
# EC - fingerprint rarity (Frontend spec 5.2)
# ---------------------------------------------------------------------------


def _fingerprint_rarity(alert: ThreatAlertV11) -> dict[str, Any] | None:
    ev = alert.evidence
    ja3 = ev.get("ja3") or ev.get("ja4")
    if not isinstance(ja3, str) or not ja3:
        return None

    histogram = _series(ev, "ja3_histogram")
    frequency = _num(ev, "ja3_frequency")
    rarity = _num(ev, "ja3_rarity")

    return {
        "kind": "fingerprint_rarity",
        "source": OBSERVED if histogram else RECONSTRUCTED,
        "fingerprint": ja3,
        "ja3s": ev.get("ja3s"),
        "matched_family": ev.get("matched_family"),
        # Log-scaled frequency distribution of every fingerprint seen during
        # the baseline period, with this connection marked far out in the tail.
        "baseline_histogram": histogram,
        "frequency": frequency,
        "rarity": rarity,
        "novel_for_host": ev.get("ja3_novel_for_host"),
        "host_history": _str_series(ev, "ja3_host_history"),
        "sni": ev.get("sni"),
        "ssl_version": ev.get("ssl_version"),
        "self_signed": ev.get("self_signed"),
        "cert_validity_days": _num(ev, "cert_validity_days"),
    }


# ---------------------------------------------------------------------------
# EX - baseline departure (Frontend spec 5.2)
# ---------------------------------------------------------------------------


def _baseline_departure(alert: ThreatAlertV11) -> dict[str, Any] | None:
    ev = alert.evidence
    outbound = _num(ev, "outbound_bytes")
    if outbound is None:
        return None
    inbound = _num(ev, "inbound_bytes")
    series = _series(ev, "outbound_series")
    band = _series(ev, "baseline_band")

    ratio = _num(ev, "out_in_byte_ratio")
    if ratio is None and inbound:
        ratio = outbound / inbound if inbound else None

    novel = ev.get("destination_novel")
    if novel is None:
        rarity = _num(ev, "destination_rarity")
        novel = rarity >= 0.8 if rarity is not None else None

    return {
        "kind": "baseline_departure",
        "source": OBSERVED if series else RECONSTRUCTED,
        "outbound_bytes": outbound,
        "inbound_bytes": inbound,
        "out_in_byte_ratio": ratio,
        "outbound_series": series,
        "baseline_band": band,
        "baseline_outbound_bytes": _num(ev, "baseline_outbound_bytes"),
        "baseline_ratio": _num(ev, "baseline_ratio"),
        "robust_z_score": _num(ev, "robust_z_score"),
        "anomaly_score": _num(ev, "anomaly_score") or alert.score,
        # Volume alone false-positives on backups; volume to somewhere never
        # contacted before is the real signal.  Give it its own readout.
        "destination_novel": novel,
        "destination_rarity": _num(ev, "destination_rarity"),
        "destination": alert.dst_ip,
        "transfer_duration_sec": _num(ev, "transfer_duration_sec")
        or alert.duration_sec,
    }


_BUILDERS = {
    ThreatClass.C2_BEACONING: _beacon_comb,
    ThreatClass.PORT_SCAN: _fanout_matrix,
    ThreatClass.DDOS: _rate_entropy,
    ThreatClass.DGA_DOMAIN: _string_inspector,
    ThreatClass.DNS_TUNNELLING: _subdomain_fanout,
    ThreatClass.ENCRYPTED_MALWARE: _fingerprint_rarity,
    ThreatClass.DATA_EXFILTRATION: _baseline_departure,
}


def build_visual(alert: ThreatAlertV11) -> dict[str, Any] | None:
    """Build the class-specific visual payload, or None.

    None is a supported outcome: the frontend falls back to evidence bars, which
    still answer the supporting-evidence requirement on their own.  A builder
    that cannot find the data it needs returns None rather than emitting an
    empty shell, so the UI never renders a chart with nothing in it.
    """
    builder = _BUILDERS.get(alert.threat_class)
    if builder is None:
        return None
    try:
        visual = builder(alert)
    except (TypeError, ValueError, ZeroDivisionError, OverflowError):
        # A malformed evidence bag must never take down the alert. The alert
        # itself is the graded output; the visual is amplification.
        return None
    if visual is None:
        return None
    return _sanitise(visual)


def _has_nonfinite(obj: Any) -> bool:
    """Cheap scan for anything ``json.dumps`` would refuse to emit."""
    if type(obj) is float:
        return not math.isfinite(obj)
    if type(obj) is list:
        return any(_has_nonfinite(v) for v in obj)
    if type(obj) is dict:
        return any(_has_nonfinite(v) for v in obj.values())
    return False


def _sanitise(obj: Any) -> Any:
    """Replace NaN/Infinity, which are not valid JSON and break strict parsers.

    Ratios computed from evidence can divide by a zero byte count, and Python
    will happily produce ``inf``.  ``json.dumps`` emits a bare ``Infinity``
    token that ``JSON.parse`` rejects, so the dashboard would lose the whole
    frame over one bad ratio.

    Scan first, rebuild only if needed.  Non-finite values are rare, while the
    payloads are large - a beacon comb carries hundreds of timestamps - so
    unconditionally rebuilding every container was costing more per alert than
    the rest of the projection put together.
    """
    if not _has_nonfinite(obj):
        return obj
    return _rebuild(obj)


def _rebuild(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _rebuild(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_rebuild(v) for v in obj]
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    return obj
