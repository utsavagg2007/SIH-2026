"""v1.1 alert -> dashboard view model.

The single place where the frozen ingest contract meets the frontend contract.
Everything the detector said is preserved; everything else is derived here or in
the fusion layer and is clearly additive.
"""

from __future__ import annotations

import time
from datetime import datetime

from ..fusion.dedup import DedupState
from ..schemas.alert_v11 import ThreatAlertV11
from ..schemas.enums import THREAT_CODE, THREAT_LABEL, THREAT_STAGE
from ..schemas.view import AlertView
from .evidence import build_evidence
from .visuals import build_visual


def _iso(dt: datetime) -> str:
    """ISO-8601 with a Z suffix rather than +00:00.

    The alert spec's examples all use Z, and round-tripping our own output back
    through the ingest validator should produce byte-identical strings.
    """
    return dt.isoformat().replace("+00:00", "Z")


def project_alert(
    alert: ThreatAlertV11,
    *,
    dedup: DedupState,
    incident_id: str | None,
    ingested_at: float | None = None,
) -> AlertView:
    """Build the view model for one alert.

    ``dedup`` supplies occurrence state; ``incident_id`` comes from correlation.
    Both are backend derivations, and both are what the frontend spec's
    WebSocket contract asks for but the frozen alert schema does not carry.
    """
    ingested_at = time.time() if ingested_at is None else ingested_at

    event_end = alert.event_end.timestamp()
    detected_at = alert.detected_at.timestamp()

    detector_latency = (detected_at - event_end) * 1000.0
    transport_latency = (ingested_at - detected_at) * 1000.0
    pipeline_latency = (ingested_at - event_end) * 1000.0

    return AlertView(
        alert_id=alert.alert_id,
        schema_version=alert.schema_version,
        ts=detected_at,
        event_start=alert.event_start.timestamp(),
        event_end=event_end,
        detected_at=detected_at,
        ingested_at=ingested_at,
        event_start_iso=_iso(alert.event_start),
        event_end_iso=_iso(alert.event_end),
        detected_at_iso=_iso(alert.detected_at),
        event_scope=alert.event_scope,
        flow_id=alert.flow_id,
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        dst_port=alert.dst_port,
        protocol=alert.protocol,
        threat_class=alert.threat_class,
        threat_code=THREAT_CODE[alert.threat_class],
        threat_label=THREAT_LABEL[alert.threat_class],
        severity=alert.severity,
        # Severity is passed through untouched. Alert spec section 4:
        # "The backend/frontend must not calculate severity independently."
        score=alert.score,
        confidence=alert.score,
        score_type=alert.score_type,
        evidence=build_evidence(alert.threat_class, alert.evidence),
        evidence_raw=dict(alert.evidence),
        visual=build_visual(alert),
        detector=alert.detector,
        detector_version=alert.detector_version,
        mitre_techniques=list(alert.mitre_techniques),
        # A detector may already know its incident (spec section 17 reserves the
        # field for a correlation layer). If it filled it in, that wins.
        incident_id=alert.incident_id or incident_id,
        kill_chain_stage=THREAT_STAGE[alert.threat_class],
        occurrences=dedup.occurrences,
        first_seen=dedup.first_seen,
        last_seen=dedup.last_seen,
        dedup_key=dedup.key,
        detector_latency_ms=round(detector_latency, 3),
        transport_latency_ms=round(transport_latency, 3),
        pipeline_latency_ms=round(pipeline_latency, 3),
        raw=alert.model_dump(mode="json"),
    )
