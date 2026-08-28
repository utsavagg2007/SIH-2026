"""Time helpers for the FlowEvent -> ThreatAlert boundary.

``FlowEvent`` carries epoch seconds because that is what the network layer
speaks. ``ThreatAlert`` v1.1 exposes timezone-aware datetimes serialized as
ISO-8601 UTC (``2026-08-29T00:20:10Z``). This module is the single place
that conversion happens.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

__all__ = ["epoch_to_utc", "ensure_utc", "to_iso8601_z", "now_utc"]


def epoch_to_utc(ts: float) -> datetime:
    """Convert epoch seconds to a timezone-aware UTC datetime.

    Raises on non-finite or non-numeric input rather than inventing a time.
    """
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        raise TypeError(f"epoch timestamp must be numeric, got {type(ts).__name__}")
    value = float(ts)
    if not math.isfinite(value):
        raise ValueError("epoch timestamp must be finite")
    return datetime.fromtimestamp(value, tz=timezone.utc)


def ensure_utc(dt: datetime) -> datetime:
    """Normalize an aware datetime to UTC. Naive datetimes are rejected.

    We refuse to assume a naive datetime is UTC: guessing a timezone is
    inventing data, and a silently wrong alert timestamp is worse than a
    loud validation error.
    """
    if not isinstance(dt, datetime):
        raise TypeError(f"expected datetime, got {type(dt).__name__}")
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(
            "naive datetime rejected: ThreatAlert timestamps must be timezone-aware"
        )
    return dt.astimezone(timezone.utc)


def to_iso8601_z(dt: datetime) -> str:
    """Serialize to ISO-8601 UTC with a literal ``Z`` suffix.

    Pinned here rather than relying on Pydantic's default datetime encoder so
    the full-stack contract cannot drift with a library upgrade. Sub-second
    precision is preserved when present (still valid ISO-8601).
    """
    text = ensure_utc(dt).isoformat()
    if text.endswith("+00:00"):
        text = text[:-6] + "Z"
    return text


def now_utc() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(tz=timezone.utc)
