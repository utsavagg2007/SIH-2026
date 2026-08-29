"""View models: what the dashboard consumes.

The frozen v1.1 contract in ``alert_v11`` is what the *detector* emits.  It is
deliberately minimal - evidence is a flat key/value bag and nothing in it knows
about thresholds, occurrence counts, or how a beacon should be drawn.

The Frontend Design Specification section 7 asks for something richer: evidence
as an ordered array carrying the threshold each value crossed, a ``visual``
object keyed by ``kind``, and ``occurrences`` / ``first_seen`` from
deduplication.  Those are all backend-side derivations, which is precisely the
fusion layer the Downstream Architecture document describes in section 7.

So the split is:

    detector  --v1.1-->  backend  --view model-->  dashboard

Neither side has to change.  The backend owns the translation, and this module
is the target shape.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .enums import EventScope, KillChainStage, ScoreType, Severity, ThreatClass


class EvidenceItem(BaseModel):
    """One row in the evidence readout (Frontend spec 5.1).

    Two rendering modes, distinguished by whether ``threshold`` is set:

    * threshold present -> a bar with a marked threshold rule, and ``exceeded``
      says which side of it the observed value landed on.  The frontend colours
      the observed marker with the severity colour only when ``exceeded`` is
      true.
    * threshold absent -> a plain label/value pair.  The spec is explicit here:
      "Do not invent a scale to make them look uniform."  So ``scale`` stays
      null too, and the frontend must not draw a bar.
    """

    feature: str
    #: Human-readable label.  The frontend can format keys itself (spec 6), but
    #: shipping the label means units and capitalisation stay consistent between
    #: the dashboard, the analyst layer, and any export.
    label: str
    value: Any
    unit: str | None = None

    threshold: float | None = None
    direction: Literal["above", "below"] | None = None
    scale: list[float] | None = Field(default=None, min_length=2, max_length=2)
    exceeded: bool | None = None

    #: Ordering hint.  Spec 5.1: "Order by contribution, most decisive first."
    #: Lower sorts first.
    rank: int = 100


class AlertView(BaseModel):
    """A v1.1 alert projected into what the dashboard needs.

    Every field the detector supplied is preserved verbatim; everything else is
    additive.  ``raw`` carries the untouched v1.1 object so the "RAW FLOW
    RECORD" expander in the Live view (Frontend spec 4.1) can show exactly what
    arrived, with no backend reinterpretation.
    """

    model_config = ConfigDict(populate_by_name=True)

    alert_id: str
    schema_version: str

    # Epoch seconds. The frontend spec's WebSocket contract uses Unix floats and
    # the build plan freezes "time is always a Unix float in UTC", so the view
    # model uses those.  ISO-8601 strings are kept alongside because they are
    # what the REST consumer and the analyst layer read more comfortably.
    ts: float
    event_start: float
    event_end: float
    detected_at: float
    ingested_at: float

    event_start_iso: str
    event_end_iso: str
    detected_at_iso: str

    event_scope: EventScope
    flow_id: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None

    threat_class: ThreatClass
    #: Two-letter code for dense listings and Wire marks (Frontend spec 2.2).
    threat_code: str
    threat_label: str

    severity: Severity
    #: The frontend spec names this "confidence"; the alert spec names it
    #: "score" and warns against calling a rule score a confidence.  We ship
    #: both names for the same number so neither document is contradicted, and
    #: ``score_type`` tells the UI which label is honest ("Threat Score" plus a
    #: RULE/MODEL/ANOMALY/SIGNATURE badge, per alert spec section 4).
    score: float
    confidence: float
    score_type: ScoreType

    evidence: list[EvidenceItem]
    #: The original flat evidence bag, untouched.  Section 6 of the alert spec
    #: requires the frontend be able to render evidence generically; if our
    #: threshold registry has no opinion about a novel key, it still arrives.
    evidence_raw: dict[str, Any]

    visual: dict[str, Any] | None = None

    detector: str
    detector_version: str
    mitre_techniques: list[str]

    incident_id: str | None = None
    kill_chain_stage: KillChainStage

    # --- deduplication state (Build Plan layer 5) ---
    occurrences: int = 1
    first_seen: float
    last_seen: float
    dedup_key: str

    # --- latency accounting (Build Plan layer 6) ---
    #: event_end -> detected_at. Time spent inside the detection layer.
    detector_latency_ms: float
    #: detected_at -> backend receipt. Transport and queueing.
    transport_latency_ms: float
    #: event_end -> backend receipt. The packet-to-alert delay we report.
    pipeline_latency_ms: float

    raw: dict[str, Any]


class IncidentMember(BaseModel):
    """One node on the kill-chain ribbon (Frontend spec 6.1)."""

    alert_id: str
    ts: float
    threat_class: ThreatClass
    threat_code: str
    severity: Severity
    confidence: float
    stage: KillChainStage
    occurrences: int


class IncidentView(BaseModel):
    """Correlated alerts on one host, ordered into a narrative.

    Build Plan layer 5 calls this "the highest-value component in the entire
    build relative to its cost", and the frontend spends a full minute of the
    demo on it.
    """

    incident_id: str
    #: The host the correlation pivoted on.  Every member alert touches it.
    pivot_host: str
    opened_at: float
    updated_at: float
    opened_at_iso: str

    severity: Severity
    #: Highest member confidence.  Deliberately not an average: an incident is
    #: at least as strong as its strongest finding.
    confidence: float
    #: True when the incident spans more than one kill-chain stage.  The
    #: sequence is itself evidence (Frontend spec 6.1), so this is what the UI
    #: uses to justify escalating past the max member severity.
    escalated: bool

    #: Exact, even when ``members`` below is trimmed.
    alert_count: int
    stages: list[KillChainStage]
    threat_classes: list[ThreatClass]
    members: list[IncidentMember]
    #: True when ``members`` is a recent slice rather than the full set. The
    #: ribbon is a narrative, not a log; the complete list is available from
    #: ``GET /api/v1/alerts?incident_id=...``.
    members_truncated: bool = False
    elapsed_sec: float
    narrative: str


class HostView(BaseModel):
    """Everything the Host investigation view needs for one machine.

    Frontend spec 6.3: reached by clicking any IP anywhere in the product.
    """

    ip: str
    first_seen: float
    last_seen: float
    alert_count: int
    severity_counts: dict[str, int]
    threat_class_counts: dict[str, int]
    #: Peer addresses this host appeared with, most recent first.  This is the
    #: "destination set" panel; novelty is a detector-side judgement, so we
    #: report what was observed rather than guessing which peers are new.
    peers: list[str]
    ja3_history: list[str]
    incidents: list[str]
    alerts: list[AlertView]


class MetricsFrame(BaseModel):
    """The once-per-second metrics frame (Frontend spec 7).

    Two groups of numbers with different provenance, and the distinction
    matters when a judge asks:

    * ``flows_per_sec`` / ``packets_per_sec`` / ``mbps`` describe the *traffic*,
      which only the ingestion and detection layers can see.  The backend
      reports whatever they last told it via ``POST /api/v1/telemetry`` and
      reports zero if nothing has.  It does not estimate them.
    * ``alerts_per_sec`` and the latency percentiles are measured by this
      process from its own ingest path, and are honest without qualification.
    """

    type: Literal["metrics"] = "metrics"
    ts: float

    flows_per_sec: float = 0.0
    packets_per_sec: float = 0.0
    mbps: float = 0.0
    #: Whether the traffic figures above came from a live telemetry report or
    #: are stale/absent.  The UI should show them as unavailable when false
    #: rather than displaying a confident zero.
    traffic_telemetry_live: bool = False

    alerts_per_sec: float = 0.0
    alerts_total: int = 0

    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_max_ms: float = 0.0

    detectors_online: int = 0
    detectors_total: int = 0

    egress_blocked: bool = True
    uptime_s: float = 0.0

    ws_clients: int = 0
    #: Frames dropped by backpressure since the last frame.  Non-zero means the
    #: dashboard is behind; the spec would rather the UI say so than silently
    #: lie about completeness.
    ws_dropped: int = 0


class SystemStatusFrame(BaseModel):
    """Pushed when something about the system's state changes."""

    type: Literal["system.status"] = "system.status"
    ts: float
    replay_active: bool
    storage_backend: str
    storage_healthy: bool
    storage_queue_depth: int
    detail: str | None = None


class DetectorStatus(BaseModel):
    """One row of the Detector status panel (Frontend spec 6.2).

    Populated from what has actually been observed on the ingest path.  A
    detector that has never posted is reported as ``unseen``, not as offline -
    the backend genuinely cannot tell the difference between a detector that is
    down and one that has had nothing to report.
    """

    detector: str
    detector_version: str
    state: Literal["online", "degraded", "unseen"]
    alerts_produced: int
    last_seen: float | None
    mean_detector_latency_ms: float
    threat_classes: list[str]


class ConstraintProof(BaseModel):
    """The read-only constraint panel (Frontend spec 6.2).

    Three lines that say the system sent nothing, received one way only, and
    decrypted nothing.  Each is backed by something checkable rather than a
    hardcoded boolean; see ``app.core.constraints``.
    """

    ingest_direction: Literal["inbound_only"] = "inbound_only"
    egress_blocked: bool
    payload_decryption: Literal["never"] = "never"
    outbound_attempts: int
    write_routes_toward_network: int = 0
    checked_at: float
    notes: list[str]
