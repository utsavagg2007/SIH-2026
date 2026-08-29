"""Turn a flat v1.1 evidence bag into ordered evidence bars.

Input (alert spec section 6)::

    {"unique_dst_ports": 1024, "syn_no_ack_ratio": 0.99, "window_seconds": 12.4}

Output (frontend spec section 5.1)::

    [{"feature": "unique_dst_ports", "label": "Distinct destination ports",
      "value": 1024, "threshold": 100, "direction": "above",
      "scale": [0, 1500], "exceeded": true, "rank": 10}, ...]

The frontend switches on the presence of ``threshold`` to decide between a bar
and a plain value, so getting the null cases right matters more than getting
the thresholds exactly right.
"""

from __future__ import annotations

from typing import Any

from ..schemas.enums import ThreatClass
from ..schemas.view import EvidenceItem
from .thresholds import ContextSpec, ThresholdSpec, humanise, lookup

#: Evidence keys the detector may use to override a registry threshold.  A
#: detector that ships ``interval_cv`` and ``interval_cv_threshold`` is telling
#: us its actual operating point, and that beats our table every time.
_THRESHOLD_SUFFIX = "_threshold"

#: Keys consumed by the visual builders rather than shown as evidence rows.
#: A 400-element timestamp array is a picture, not a readout - it would push
#: every real evidence row off the panel.
_VISUAL_ONLY = frozenset(
    {
        "timestamps",
        "connection_timestamps",
        "intervals",
        "interval_series",
        "rate_series",
        "entropy_series",
        "port_series",
        "contacted_ports",
        "subdomains",
        "subdomain_samples",
        "ja3_histogram",
        "ja3_host_history",
        "outbound_series",
        "baseline_band",
        "ngram_heat",
        "nxdomain_series",
        "series_start",
        "series_step_sec",
    }
)


def _is_number(v: Any) -> bool:
    # bool is an int subclass in Python; a boolean evidence value is a flag, not
    # a magnitude, so it must not be treated as plottable on its own.
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _coerce_numeric(value: Any) -> float | None:
    """Best-effort numeric view of an evidence value, for threshold comparison.

    Booleans map to 1.0/0.0 so that flag-style features registered with a 0.5
    threshold - ``self_signed``, ``destination_novel`` - render as a crossed
    line rather than being silently skipped.
    """
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if _is_number(value):
        return float(value)
    return None


def build_evidence(
    threat_class: ThreatClass, evidence: dict[str, Any]
) -> list[EvidenceItem]:
    """Project one evidence bag into ordered display rows."""
    items: list[EvidenceItem] = []

    for key, value in evidence.items():
        if key in _VISUAL_ONLY or key.endswith(_THRESHOLD_SUFFIX):
            continue
        # Long series that were not declared in _VISUAL_ONLY still should not
        # become a single unreadable row.  Summarise rather than dump.
        if isinstance(value, list):
            items.append(
                EvidenceItem(
                    feature=key,
                    label=humanise(key),
                    value=f"{len(value)} values",
                    rank=85,
                )
            )
            continue

        spec = lookup(threat_class, key)
        numeric = _coerce_numeric(value)

        # A detector-supplied threshold always wins over the registry.
        override = evidence.get(f"{key}{_THRESHOLD_SUFFIX}")
        override_num = _coerce_numeric(override) if override is not None else None

        if isinstance(spec, ThresholdSpec) and numeric is not None:
            threshold = override_num if override_num is not None else spec.threshold
            exceeded = (
                numeric > threshold
                if spec.direction == "above"
                else numeric < threshold
            )
            lo, hi = spec.scale
            # Widen the track if the observed value or the threshold falls
            # outside it. A bar pinned at the end of its scale reads as "just
            # over the line" when it may be an order of magnitude past it.
            hi = max(hi, numeric * 1.15, threshold * 1.15)
            lo = min(lo, numeric)
            items.append(
                EvidenceItem(
                    feature=key,
                    label=spec.label,
                    value=value,
                    unit=spec.unit,
                    threshold=threshold,
                    direction=spec.direction,
                    scale=[lo, hi],
                    exceeded=exceeded,
                    rank=spec.rank,
                )
            )
            continue

        if isinstance(spec, ContextSpec):
            items.append(
                EvidenceItem(
                    feature=key,
                    label=spec.label,
                    value=value,
                    unit=spec.unit,
                    rank=spec.rank,
                )
            )
            continue

        # Unregistered, or registered with a threshold but carrying a
        # non-numeric value.  Either way: plain label/value pair, no invented
        # scale.
        if numeric is not None and override_num is not None:
            # The detector gave us a threshold for a key we do not know. Trust
            # it, and pick a scale from the two numbers we have.
            span = max(abs(numeric), abs(override_num)) * 1.3 or 1.0
            items.append(
                EvidenceItem(
                    feature=key,
                    label=humanise(key),
                    value=value,
                    threshold=override_num,
                    direction="above" if numeric >= override_num else "below",
                    scale=[min(0.0, numeric), span],
                    exceeded=True,
                    rank=45,
                )
            )
        else:
            items.append(
                EvidenceItem(
                    feature=key, label=humanise(key), value=value, rank=80
                )
            )

    # Most decisive first (spec 5.1), then crossed thresholds ahead of
    # uncrossed ones at the same rank, then alphabetical so the order is stable
    # between renders of the same alert.
    items.sort(key=lambda i: (i.rank, not bool(i.exceeded), i.feature))
    return items
