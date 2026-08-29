"""The frozen ingest contract: ThreatAlert v1.1.

This module is a direct transcription of SIH26_Alert_Output_Spec_v1.1_FINAL.md.
It is the *only* shape the detection/ML layer is allowed to POST, and the only
shape this backend accepts on the ingest path.

Deliberate properties:

* ``extra="forbid"`` on the top level.  A detector that adds a top-level field
  is making a breaking change (spec section 18) and must bump
  ``schema_version``; silently accepting it would let the two teams drift.
  ``evidence`` is the designated extension point and stays open.
* Nullable fields are *required but nullable* (spec section 3: every field is
  "yes" under Required).  A missing ``dst_ip`` key is a contract violation; an
  explicit ``null`` is correct usage.
* No severity is computed here.  Severity arrives from the detector.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import EventScope, ScoreType, Severity, ThreatClass

SCHEMA_VERSION = "1.1"

# Evidence values are restricted to JSON scalars by the TypeScript interface in
# spec section 12 (Record<string, string | number | boolean | null>).  We also
# allow lists of scalars, because several visual builders need a series (beacon
# timestamps, port lists) and the spec's own guarantee is only that evidence is
# "valid JSON".  Nested objects are rejected so the frontend's generic
# key/value renderer (spec section 6) can never be handed something it cannot
# display.
EvidenceScalar = str | int | float | bool | None
EvidenceValue = EvidenceScalar | list[EvidenceScalar]


class ThreatAlertV11(BaseModel):
    """One detection event, exactly as emitted by the detection/ML layer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alert_id: Annotated[str, Field(min_length=1, max_length=64)]
    schema_version: str

    event_start: datetime
    event_end: datetime
    detected_at: datetime

    event_scope: EventScope

    flow_id: str | None = Field(max_length=256)

    src_ip: str | None = Field(max_length=45)
    dst_ip: str | None = Field(max_length=45)
    dst_port: int | None = Field(ge=0, le=65535)
    protocol: str | None = Field(max_length=16)

    threat_class: ThreatClass
    severity: Severity

    score: float = Field(ge=0.0, le=1.0)
    score_type: ScoreType

    evidence: dict[str, EvidenceValue]

    detector: Annotated[str, Field(min_length=1, max_length=128)]
    detector_version: Annotated[str, Field(min_length=1, max_length=32)]

    mitre_techniques: list[Annotated[str, Field(max_length=32)]]

    incident_id: str | None = Field(max_length=64)

    # ------------------------------------------------------------------
    # validators
    # ------------------------------------------------------------------

    @field_validator("schema_version")
    @classmethod
    def _pin_schema_version(cls, v: str) -> str:
        """Spec section 3: must be exactly "1.1" for this contract."""
        if v != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported schema_version {v!r}; this backend implements "
                f"{SCHEMA_VERSION!r}. A different version is a breaking change "
                "and needs its own ingest route."
            )
        return v

    @field_validator("event_start", "event_end", "detected_at")
    @classmethod
    def _require_utc(cls, v: datetime) -> datetime:
        """Spec section 15: "timestamps are UTC ISO-8601".

        A naive datetime is ambiguous, and the build plan is explicit that no
        local time appears anywhere.  We reject naive input rather than guessing
        a zone, then normalise to UTC so downstream arithmetic always compares
        like with like.
        """
        if v.tzinfo is None:
            raise ValueError(
                "timestamp is missing a timezone; emit UTC ISO-8601 "
                "(e.g. 2026-08-28T23:44:03Z)"
            )
        return v.astimezone(timezone.utc)

    @field_validator("protocol")
    @classmethod
    def _normalise_protocol(cls, v: str | None) -> str | None:
        """Spec section 15: enum values are lowercase exact strings."""
        return v.lower() if v else v

    @field_validator("evidence")
    @classmethod
    def _reject_empty_evidence(cls, v: dict) -> dict:
        """Build Plan layer 0: "A detector that cannot say *why* it fired does
        not ship."  An empty evidence object is that detector."""
        if not v:
            raise ValueError(
                "evidence must contain at least one supporting feature; an "
                "alert with no evidence cannot satisfy the supporting-evidence "
                "requirement"
            )
        return v

    @model_validator(mode="after")
    def _check_time_ordering(self) -> ThreatAlertV11:
        """The event window must be coherent and must precede its own detection.

        These are cheap invariants that catch a whole class of upstream bug: a
        detector that swaps start/end, or one whose clock disagrees with the
        capture, would otherwise produce negative latencies in the metrics panel
        and nonsensical ranges on the dashboard.
        """
        if self.event_end < self.event_start:
            raise ValueError(
                f"event_end ({self.event_end.isoformat()}) precedes event_start "
                f"({self.event_start.isoformat()})"
            )
        if self.detected_at < self.event_start:
            raise ValueError(
                f"detected_at ({self.detected_at.isoformat()}) precedes "
                f"event_start ({self.event_start.isoformat()}); a detection "
                "cannot happen before the traffic it describes"
            )
        return self

    @model_validator(mode="after")
    def _check_scope_identifiers(self) -> ThreatAlertV11:
        """Spec section 5: use null when a concept does not apply - but the
        entity the alert *claims* to describe has to be identified.

        A source_host alert with no src_ip names no host, so nothing downstream
        can pivot on it: it cannot be correlated into an incident, cannot appear
        on a host timeline, and gives an analyst nothing to work with.  That is
        a detector bug, not a legitimate null.
        """
        required: dict[EventScope, tuple[str, ...]] = {
            EventScope.FLOW: ("flow_id",),
            EventScope.SOURCE_HOST: ("src_ip",),
            EventScope.DESTINATION_HOST: ("dst_ip",),
            EventScope.HOST_PAIR: ("src_ip", "dst_ip"),
            EventScope.NETWORK: (),
        }
        missing = [n for n in required[self.event_scope] if getattr(self, n) is None]
        if missing:
            raise ValueError(
                f"event_scope={self.event_scope.value!r} requires "
                f"{', '.join(missing)} to be non-null"
            )
        return self

    # ------------------------------------------------------------------
    # derived values
    # ------------------------------------------------------------------

    @property
    def detector_latency_ms(self) -> float:
        """Milliseconds from the end of the observed window to detector emission.

        This is the detection-layer half of the packet-to-alert delay that Build
        Plan layer 6 requires us to report.  The backend measures its own half
        separately; see ``app.core.metrics``.
        """
        return (self.detected_at - self.event_end).total_seconds() * 1000.0

    @property
    def duration_sec(self) -> float:
        return (self.event_end - self.event_start).total_seconds()


class AlertAccepted(BaseModel):
    """Spec section 9 - the 201 Created response body."""

    status: str = "accepted"
    alert_id: str
    # Not in the spec's example, but the ingest path is where deduplication
    # happens, so the detector deserves to know whether its alert opened a new
    # entry or folded into an existing one.  Additive; safe for a client to
    # ignore entirely.
    deduplicated: bool = False
    occurrences: int = 1
    incident_id: str | None = None


class BulkAlertsAccepted(BaseModel):
    """Response for the batched ingest route.

    The detection layer runs at line rate; one HTTP round-trip per alert would
    make the transport the bottleneck during exactly the floods we are meant to
    be detecting.
    """

    status: str = "accepted"
    accepted: int
    rejected: int
    created: int
    deduplicated: int
    errors: list[dict[str, Any]] = Field(default_factory=list)
