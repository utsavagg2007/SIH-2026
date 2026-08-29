"""Shared request dependencies.

Long-lived objects (the bus, the repository, the metrics registry) are created
once in the lifespan handler and stashed on ``app.state``.  These accessors pull
them back out with a useful error if the app was not wired up - which otherwise
surfaces as a confusing ``AttributeError`` deep in a route.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from ..config import Settings, get_settings
from ..core.bus import AlertBus
from ..core.constraints import ConstraintAuditor
from ..core.hub import ConnectionHub
from ..core.metrics import MetricsRegistry
from ..storage.base import AlertRepository


def _from_state(request: Request, name: str):
    obj = getattr(request.app.state, name, None)
    if obj is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{name} is not initialised; the service is still starting",
        )
    return obj


def get_bus(request: Request) -> AlertBus:
    return _from_state(request, "bus")


def get_repository(request: Request) -> AlertRepository:
    return _from_state(request, "repository")


def get_metrics(request: Request) -> MetricsRegistry:
    return _from_state(request, "metrics")


def get_hub(request: Request) -> ConnectionHub:
    return _from_state(request, "hub")


def get_auditor(request: Request) -> ConstraintAuditor:
    return _from_state(request, "auditor")


def get_replay(request: Request):
    return _from_state(request, "replay")


BusDep = Annotated[AlertBus, Depends(get_bus)]
RepoDep = Annotated[AlertRepository, Depends(get_repository)]
MetricsDep = Annotated[MetricsRegistry, Depends(get_metrics)]
HubDep = Annotated[ConnectionHub, Depends(get_hub)]
AuditorDep = Annotated[ConstraintAuditor, Depends(get_auditor)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
