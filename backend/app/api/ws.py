"""The live feed.

Endpoint: ``/ws/alerts`` (alert spec section 10).

Frame types::

    snapshot          sent once on connect - recent alerts, so a reconnecting
                      dashboard is not blank until the next detection
    alert.created     a new deduplicated finding
    alert.updated     a repeat folding into an existing one (occurrences++)
    incident.created  correlation opened an incident
    incident.updated  an alert joined an existing incident
    metrics           once per second (frontend spec section 7)
    system.status     storage/replay state changed

The connection is write-mostly.  We read from the socket only to notice that the
client has gone away and to answer a ping; the dashboard has nothing to command,
because this system has nothing to command (frontend spec 1: "This is an
instrument, not a console").
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..core.hub import ConnectionHub
from ..schemas.view import SystemStatusFrame

log = logging.getLogger(__name__)
router = APIRouter(tags=["live"])


@router.websocket("/ws/alerts")
async def alerts_socket(ws: WebSocket) -> None:
    app = ws.app
    hub: ConnectionHub = app.state.hub
    bus = app.state.bus
    repo = app.state.repository
    settings = app.state.settings

    conn = await hub.connect(ws)
    try:
        # Snapshot first. Without it, a dashboard that reconnects mid-demo shows
        # an empty stream until the next alert happens to arrive, which reads as
        # a broken feed.
        recent = await repo.recent_alerts(settings.ws_snapshot_size)
        hub.send_to(
            conn,
            "snapshot",
            {
                "alerts": [a.model_dump(mode="json") for a in reversed(recent)],
                "incidents": [
                    bus.incidents.to_view(i).model_dump(mode="json")
                    for i in bus.incidents.list(limit=25)
                ],
                "metrics": bus.metrics_frame().model_dump(),
                "schema_version": "1.1",
            },
        )
        hub.send_to(
            conn,
            "system.status",
            SystemStatusFrame(
                ts=bus.metrics_frame().ts,
                replay_active=app.state.replay.is_running,
                storage_backend=repo.backend_name,
                storage_healthy=await repo.healthy(),
                storage_queue_depth=bus.write_queue_depth,
            ).model_dump(),
        )

        while True:
            # Anything the client sends is a liveness signal. We answer "ping"
            # so a browser can measure round-trip time, and ignore the rest
            # rather than exposing a command surface.
            message = await ws.receive_text()
            if message.strip().lower() in {"ping", '{"type":"ping"}'}:
                hub.send_to(conn, "pong", {"ts": bus.metrics_frame().ts})

    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        log.debug("websocket closed: %s", exc)
    finally:
        await hub.disconnect(conn)
