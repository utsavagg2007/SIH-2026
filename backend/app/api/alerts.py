"""Alert ingest and history.

Ingest (alert spec section 9)::

    POST /api/v1/alerts        one v1.1 alert   -> 201 / 422
    POST /api/v1/alerts/bulk   a batch of them  -> 207-style summary

History (alert spec section 11)::

    GET  /api/v1/alerts        filtered, paginated
    GET  /api/v1/alerts/{id}   one alert, full evidence

The ingest route does no I/O: it validates, hands the alert to the bus, and
returns.  That is what keeps the detector's POST latency independent of how many
dashboards are connected or how far behind the database is.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, ValidationError

from ..schemas.alert_v11 import AlertAccepted, BulkAlertsAccepted, ThreatAlertV11
from ..schemas.view import AlertView
from ..storage.base import AlertQuery
from .deps import BusDep, MetricsDep, RepoDep, SettingsDep

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["alerts"])


class AlertPageResponse(BaseModel):
    items: list[AlertView]
    total: int
    limit: int
    offset: int


@router.post(
    "/alerts",
    status_code=status.HTTP_201_CREATED,
    response_model=AlertAccepted,
    summary="Ingest one ThreatAlert v1.1",
    responses={422: {"description": "Alert does not conform to schema v1.1"}},
)
async def ingest_alert(alert: ThreatAlertV11, bus: BusDep) -> AlertAccepted:
    """Accept one alert from the detection layer.

    FastAPI's own validation produces the 422 the spec asks for, with the field
    path and reason in the body, so a detector team can see exactly which field
    broke the contract.
    """
    result = bus.publish(alert)
    return AlertAccepted(
        alert_id=alert.alert_id,
        deduplicated=result.deduplicated,
        occurrences=result.view.occurrences,
        incident_id=result.view.incident_id,
    )


class BulkAlerts(BaseModel):
    alerts: list[dict[str, Any]] = Field(min_length=1, max_length=5000)


@router.post(
    "/alerts/bulk",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=BulkAlertsAccepted,
    summary="Ingest a batch of ThreatAlert v1.1 objects",
)
async def ingest_alerts_bulk(
    payload: BulkAlerts, bus: BusDep, metrics: MetricsDep
) -> BulkAlertsAccepted:
    """Accept many alerts in one round-trip.

    Validation is per-alert and partial by design: one malformed alert in a
    batch of five hundred must not discard the other four hundred and
    ninety-nine.  Rejects come back with their index and reason so the sender
    can fix and resend just those.
    """
    created = deduped = rejected = 0
    errors: list[dict[str, Any]] = []

    for i, raw in enumerate(payload.alerts):
        try:
            alert = ThreatAlertV11.model_validate(raw)
        except ValidationError as exc:
            rejected += 1
            metrics.record_rejection()
            # Cap the error list: a batch where every alert is malformed should
            # produce a diagnosis, not a megabyte of response body.
            if len(errors) < 25:
                errors.append(
                    {
                        "index": i,
                        "alert_id": raw.get("alert_id") if isinstance(raw, dict) else None,
                        "errors": [
                            {"field": ".".join(str(p) for p in e["loc"]), "msg": e["msg"]}
                            for e in exc.errors()[:5]
                        ],
                    }
                )
            continue

        result = bus.publish(alert)
        if result.deduplicated:
            deduped += 1
        else:
            created += 1

    return BulkAlertsAccepted(
        accepted=created + deduped,
        rejected=rejected,
        created=created,
        deduplicated=deduped,
        errors=errors,
    )


@router.get(
    "/alerts",
    response_model=AlertPageResponse,
    summary="Query historical alerts",
)
async def list_alerts(
    repo: RepoDep,
    from_: Annotated[float | None, Query(alias="from", description="epoch seconds")] = None,
    to: Annotated[float | None, Query(description="epoch seconds")] = None,
    threat_class: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    src_ip: Annotated[str | None, Query()] = None,
    dst_ip: Annotated[str | None, Query()] = None,
    host: Annotated[str | None, Query(description="matches src or dst")] = None,
    detector: Annotated[str | None, Query()] = None,
    incident_id: Annotated[str | None, Query()] = None,
    min_score: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AlertPageResponse:
    page = await repo.query_alerts(
        AlertQuery(
            from_ts=from_,
            to_ts=to,
            threat_class=threat_class,
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            host=host,
            detector=detector,
            incident_id=incident_id,
            min_score=min_score,
            limit=limit,
            offset=offset,
        )
    )
    return AlertPageResponse(
        items=page.items, total=page.total, limit=page.limit, offset=page.offset
    )


@router.get(
    "/alerts/{alert_id}",
    response_model=AlertView,
    summary="One alert with full evidence",
)
async def get_alert(alert_id: str, repo: RepoDep, response: Response) -> AlertView:
    alert = await repo.get_alert(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No alert {alert_id!r}. Note that alerts reach durable storage "
                "asynchronously; an alert emitted moments ago may not be "
                "queryable yet. The live WebSocket carries it immediately."
            ),
        )
    # An alert is immutable apart from its occurrence count, so it caches well -
    # but not for long, because a deduplicated repeat updates it in place.
    response.headers["Cache-Control"] = "private, max-age=5"
    return alert


class TelemetryReport(BaseModel):
    """Traffic-rate report from the ingestion/detection layer.

    The backend only ever sees alerts, so it cannot measure flows/sec, packet
    rate, or Mb/s - those exist upstream.  Rather than fabricating them for the
    throughput panel, we accept them from whoever can actually count them, and
    mark the figures stale when nobody reports.
    """

    flows_per_sec: float = Field(ge=0)
    packets_per_sec: float = Field(default=0.0, ge=0)
    mbps: float = Field(default=0.0, ge=0)
    detectors_online: int = Field(default=0, ge=0)
    detectors_total: int = Field(default=0, ge=0)
    source: Literal["live_capture", "replay", "flow_collector", "benchmark"] = (
        "live_capture"
    )


@router.post(
    "/telemetry",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Report upstream traffic rates for the throughput panel",
)
async def report_telemetry(
    report: TelemetryReport, metrics: MetricsDep, settings: SettingsDep
) -> Response:
    metrics.record_telemetry(
        flows_per_sec=report.flows_per_sec,
        packets_per_sec=report.packets_per_sec,
        mbps=report.mbps,
        detectors_online=report.detectors_online,
        detectors_total=report.detectors_total,
        source=report.source,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
