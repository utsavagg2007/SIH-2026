"""v1.1 alert -> dashboard view model.

The single place where the frozen ingest contract meets the frontend contract.
Everything the detector said is preserved; everything else is derived here or in
the fusion layer and is clearly additive.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from ..fusion.dedup import DedupState
from ..schemas.alert_v11 import ThreatAlertV11
from ..schemas.enums import THREAT_CODE, THREAT_LABEL, THREAT_STAGE
from ..schemas.view import AlertView
from .aliases import canonicalise_evidence
from .evidence import build_evidence
from .visuals import build_visual


def _iso(dt: datetime) -> str:
    """ISO-8601 with a Z suffix rather than +00:00.

    The alert spec's examples all use Z, and round-tripping our own output back
    through the ingest validator should produce byte-identical strings.
    """
    return dt.isoformat().replace("+00:00", "Z")


def _iso_epoch(epoch: float) -> str:
    """Same, for the deduplicated window bounds, which are epoch floats.

    The window belongs to the deduplicated finding rather than to any single
    arrival, so it is carried as a number through the fusion layer and only
    becomes a string here.
    """
    return _iso(datetime.fromtimestamp(epoch, tz=timezone.utc))


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

    # The deduplicated window, not just this occurrence's. A beacon that has
    # been running for an hour should say so; ``dedup`` has been widening these
    # on every repeat and until now nothing read them back out.
    event_start = dedup.event_start
    event_end = dedup.event_end
    detected_at = alert.detected_at.timestamp()

    detector_latency = (detected_at - alert.event_end.timestamp()) * 1000.0
    transport_latency = (ingested_at - detected_at) * 1000.0
    pipeline_latency = (ingested_at - alert.event_end.timestamp()) * 1000.0

    # Evidence is projected through the alias table so the detector's own
    # vocabulary reaches the registry and the visual builders. The originals are
    # preserved verbatim below in ``evidence_raw`` and ``raw``.
    canonical = canonicalise_evidence(alert.threat_class, alert.evidence)

    return AlertView(
        # The SURVIVING identity, not this arrival's. Deduplication folds
        # repeats into the first alert, and every consumer downstream keys on
        # alert_id: storage upserts on it, and the dashboard's reducer maps on
        # it. Emitting a fresh id per repeat meant a sixty-minute beacon
        # produced sixty rows in both - the exact outcome the dedup layer
        # exists to prevent, and the one Build Plan layer 5 tests for. The id
        # this occurrence arrived with is not lost: it is in ``raw``.
        alert_id=dedup.alert_id,
        schema_version=alert.schema_version,
        ts=detected_at,
        event_start=event_start,
        event_end=event_end,
        detected_at=detected_at,
        ingested_at=ingested_at,
        event_start_iso=_iso_epoch(event_start),
        event_end_iso=_iso_epoch(event_end),
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
        #
        # The score is the strongest seen across the folded occurrences, which
        # is what dedup.py's docstring promises the surviving alert gains. An
        # hour of beacon check-ins that peaked at 0.91 should not read 0.61
        # because the most recent one happened to be weaker.
        score=dedup.max_score,
        confidence=dedup.max_score,
        score_type=alert.score_type,
        evidence=build_evidence(alert.threat_class, canonical),
        evidence_raw=dict(alert.evidence),
        visual=build_visual(alert.model_copy(update={"evidence": canonical})),
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
