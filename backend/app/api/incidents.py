"""Incident routes.

Incidents live in the fusion layer's in-memory engine, which is the authority on
what is currently correlated.  The database copy exists for history; the live
view reads from the engine so an incident that is still open reflects the alert
that arrived a second ago.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from ..schemas.view import AlertView, IncidentView
from ..storage.base import AlertQuery
from .deps import BusDep, RepoDep

router = APIRouter(prefix="/api/v1", tags=["incidents"])


class IncidentListResponse(BaseModel):
    items: list[IncidentView]
    total: int


class IncidentDetail(BaseModel):
    incident: IncidentView
    alerts: list[AlertView]


@router.get(
    "/incidents",
    response_model=IncidentListResponse,
    summary="Correlated incidents, most recently updated first",
)
async def list_incidents(
    bus: BusDep,
    from_: Annotated[float | None, Query(alias="from")] = None,
    to: Annotated[float | None, Query()] = None,
    host: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> IncidentListResponse:
    incidents = bus.incidents.list(limit=limit * 4)
    views = [bus.incidents.to_view(i) for i in incidents]

    if from_ is not None:
        views = [v for v in views if v.updated_at >= from_]
    if to is not None:
        views = [v for v in views if v.opened_at <= to]
    if host:
        views = [v for v in views if v.pivot_host == host]
    if severity:
        views = [v for v in views if v.severity.value == severity]

    return IncidentListResponse(items=views[:limit], total=len(views))


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentDetail,
    summary="One incident with its member alerts",
)
async def get_incident(
    incident_id: str, bus: BusDep, repo: RepoDep
) -> IncidentDetail:
    incident = bus.incidents.get(incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"No incident {incident_id!r}. Incidents are held for the "
                "correlation window and then evicted; older ones are "
                "reconstructable from /api/v1/alerts?incident_id=..."
            ),
        )

    view = bus.incidents.to_view(incident)
    # Fetch the member alerts individually rather than filtering the store by
    # incident_id: the durable copy may lag, and the incident already knows
    # exactly which alert ids belong to it.
    alerts: list[AlertView] = []
    for member in view.members:
        alert = await repo.get_alert(member.alert_id)
        if alert is not None:
            alerts.append(alert)

    if not alerts:
        page = await repo.query_alerts(
            AlertQuery(incident_id=incident_id, limit=200)
        )
        alerts = page.items

    return IncidentDetail(incident=view, alerts=alerts)
