"""Replay control (Frontend spec 6.4).

Deliberately plain: select a capture, set a speed multiplier, start and stop, and
read the position back.

Note on the read-only constraint: these routes write nothing toward the
monitored network.  Replay reads a local fixture file and pushes its contents
through the same in-process bus a live detector would post to.  Nothing leaves
this service.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..replay.engine import ReplayStatus
from .deps import BusDep

router = APIRouter(prefix="/api/v1/replay", tags=["replay"])


class ReplayStartRequest(BaseModel):
    capture: str
    speed: float = Field(default=1.0, gt=0, le=1000)
    loop: bool = False
    #: Hard cap on alerts per second, independent of speed. Used for the flood
    #: test the frontend spec asks for in week one: several hundred alerts per
    #: second, to confirm the interface holds sixty frames.
    max_rate: float | None = Field(default=None, gt=0, le=100_000)


class ReplayStatusResponse(BaseModel):
    running: bool
    capture: str | None
    speed: float
    position: int
    total: int
    emitted: int
    rejected: int
    elapsed_s: float
    loop: bool
    scenario: dict[str, Any]


def _to_response(s: ReplayStatus) -> ReplayStatusResponse:
    return ReplayStatusResponse(
        running=s.running,
        capture=s.capture,
        speed=s.speed,
        position=s.position,
        total=s.total,
        emitted=s.emitted,
        rejected=s.rejected,
        elapsed_s=s.elapsed_s,
        loop=s.loop,
        scenario=s.scenario,
    )


@router.get("/captures", summary="Replayable captures and their scenarios")
async def list_captures(request: Request) -> dict[str, Any]:
    engine = request.app.state.replay
    return {"items": engine.available_captures()}


@router.post("/start", response_model=ReplayStatusResponse, summary="Start replay")
async def start_replay(
    body: ReplayStartRequest, request: Request, bus: BusDep
) -> ReplayStatusResponse:
    engine = request.app.state.replay
    try:
        status_ = await engine.start(
            capture=body.capture,
            speed=body.speed,
            loop=body.loop,
            max_rate=body.max_rate,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return _to_response(status_)


@router.post("/stop", response_model=ReplayStatusResponse, summary="Stop replay")
async def stop_replay(request: Request) -> ReplayStatusResponse:
    engine = request.app.state.replay
    return _to_response(await engine.stop())


@router.get("/status", response_model=ReplayStatusResponse, summary="Replay position")
async def replay_status(request: Request) -> ReplayStatusResponse:
    engine = request.app.state.replay
    return _to_response(engine.status)
