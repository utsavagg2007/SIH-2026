"""Host investigation routes.

Frontend spec 6.3: every IP address in the interface is a link to its host view.
That single interaction rule is what makes the product navigable, so this route
has to work for any address that appears anywhere - including one that has only
ever been a destination.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from ..schemas.view import HostView
from .deps import BusDep, RepoDep

router = APIRouter(prefix="/api/v1", tags=["hosts"])


class HostListResponse(BaseModel):
    items: list[str]
    total: int


@router.get("/hosts", response_model=HostListResponse, summary="Hosts seen in alerts")
async def list_hosts(
    repo: RepoDep, limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> HostListResponse:
    hosts = await repo.distinct_hosts(limit)
    return HostListResponse(items=hosts, total=len(hosts))


@router.get(
    "/hosts/{ip}",
    response_model=HostView,
    summary="Baseline, history and alerts for one host",
)
async def get_host(
    ip: str,
    repo: RepoDep,
    bus: BusDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> HostView:
    alerts = await repo.host_alerts(ip, limit)
    if not alerts:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No alerts involving {ip!r}.",
        )

    severity_counts: dict[str, int] = {}
    class_counts: dict[str, int] = {}
    peers: dict[str, float] = {}
    ja3_history: dict[str, float] = {}

    for a in alerts:
        severity_counts[a.severity.value] = severity_counts.get(a.severity.value, 0) + 1
        class_counts[a.threat_class.value] = class_counts.get(a.threat_class.value, 0) + 1

        peer = a.dst_ip if a.src_ip == ip else a.src_ip
        if peer and peer != ip:
            peers[peer] = max(peers.get(peer, 0.0), a.ts)

        # JA3 history is a genuine per-host signal (Downstream Architecture,
        # model 2): a machine that presented a browser fingerprint all week and
        # suddenly presents a scripting-library one is the actual finding. We
        # can only report the fingerprints that appeared in alert evidence -
        # the full baseline lives in the detection layer's feature store.
        for key in ("ja3", "ja4"):
            v = a.evidence_raw.get(key)
            if isinstance(v, str) and v:
                ja3_history[v] = max(ja3_history.get(v, 0.0), a.ts)

    incidents = [i.incident_id for i in bus.incidents.for_host(ip)]
    # Also include incidents this host appears in without being the pivot.
    for a in alerts:
        if a.incident_id and a.incident_id not in incidents:
            incidents.append(a.incident_id)

    def _by_recency(d: dict[str, float]) -> list[str]:
        return [k for k, _ in sorted(d.items(), key=lambda kv: kv[1], reverse=True)]

    return HostView(
        ip=ip,
        first_seen=min(a.ts for a in alerts),
        last_seen=max(a.ts for a in alerts),
        alert_count=len(alerts),
        severity_counts=severity_counts,
        threat_class_counts=class_counts,
        peers=_by_recency(peers)[:100],
        ja3_history=_by_recency(ja3_history)[:50],
        incidents=incidents,
        alerts=alerts,
    )
