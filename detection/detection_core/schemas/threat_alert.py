"""ThreatAlert v1.1 - the frozen output contract shared with full-stack.

Rules enforced here:

* ``score`` is ALWAYS a finite float in the inclusive range 0.0-1.0, for
  every ``score_type``. The meaning differs per score type; the wire value
  is always a normalized threat score.
* ``event_start`` / ``event_end`` / ``detected_at`` are timezone-aware
  datetimes, serialized to ISO-8601 UTC (``2026-08-29T00:20:10Z``). No
  epoch floats cross this boundary.
* The model is frozen and rejects unknown fields: it is a wire contract,
  not a scratch dict.
"""

from __future__ import annotations

import math
import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from .enums import EventScope, ScoreType, Severity, ThreatClass
from .timeutil import ensure_utc, now_utc, to_iso8601_z

__all__ = ["ThreatAlert", "ALERT_SCHEMA_VERSION"]

ALERT_SCHEMA_VERSION = "1.1"

_MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class ThreatAlert(BaseModel):
    """A single standardized detection result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: Literal["1.1"] = ALERT_SCHEMA_VERSION
    event_start: datetime
    event_end: datetime
    detected_at: datetime = Field(default_factory=now_utc)
    event_scope: EventScope
    flow_id: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    threat_class: ThreatClass
    severity: Severity
    score: float
    score_type: ScoreType
    evidence: dict[str, Any] = Field(default_factory=dict)
    detector: str
    detector_version: str
    mitre_techniques: list[str] = Field(default_factory=list)
    incident_id: str | None = None

    # --- validation -----------------------------------------------------

    @field_validator("alert_id")
    @classmethod
    def _uuid4_string(cls, value: str) -> str:
        """A supplied alert_id must be a real UUID v4, not just any string.

        Stays a string on the wire; we only canonicalize the form so the same
        id cannot appear in two spellings (case, braces, urn: prefix).
        """
        if not isinstance(value, str):
            raise ValueError("alert_id must be a string")
        try:
            parsed = uuid.UUID(value)
        except ValueError as exc:
            raise ValueError(f"alert_id must be a UUID string, got {value!r}") from exc
        if parsed.version != 4:
            raise ValueError(
                f"alert_id must be a UUID v4, got version {parsed.version}"
            )
        return str(parsed)

    @field_validator("event_start", "event_end", "detected_at")
    @classmethod
    def _aware_utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator("score")
    @classmethod
    def _normalized_score(cls, value: float) -> float:
        """Always 0.0-1.0 and finite, for every score_type."""
        if not math.isfinite(value):
            raise ValueError("score must be a finite number (no NaN, no infinity)")
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"score must be within [0.0, 1.0], got {value}")
        return value

    @field_validator("detector", "detector_version")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("must be a non-empty string")
        return stripped

    @field_validator("mitre_techniques")
    @classmethod
    def _valid_mitre(cls, values: list[str]) -> list[str]:
        for technique in values:
            if not _MITRE_RE.match(technique):
                raise ValueError(
                    f"invalid MITRE technique id {technique!r}; "
                    "expected Tnnnn or Tnnnn.nnn"
                )
        return values

    @model_validator(mode="after")
    def _ordered_window(self) -> ThreatAlert:
        if self.event_end < self.event_start:
            raise ValueError("event_end must not precede event_start")
        return self

    # --- serialization --------------------------------------------------

    @field_serializer("event_start", "event_end", "detected_at", when_used="json")
    def _serialize_dt(self, value: datetime) -> str:
        return to_iso8601_z(value)

    def to_wire(self) -> dict[str, Any]:
        """JSON-ready dict exactly as the full-stack team receives it."""
        return self.model_dump(mode="json")
