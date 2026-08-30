"""WebSocket fan-out with backpressure.

Frontend spec 8.2 states the problem exactly: "Under flood conditions the
backend can emit alerts faster than React can render them.  This is not
hypothetical; it will happen during your DDoS demo."

The rule this module enforces: **one slow client must never slow the detection
path.**  Every connection owns a bounded queue and its own writer task.  When a
queue fills, the oldest frames are dropped and the client is told how many.  A
dashboard showing 400 of the last 500 alerts and saying so is useful; a
dashboard that stalls the pipeline to stay complete is not.

Broadcast is therefore non-blocking by construction: it only ever appends to
in-process deques.  No client, network, or database can apply backpressure to
the caller.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
from typing import Any

from fastapi import WebSocket

log = logging.getLogger(__name__)


def _json_default(obj: Any) -> Any:
    from datetime import date, datetime
    from enum import Enum
    from uuid import UUID

    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(f"not JSON-serialisable: {type(obj).__name__}")


def dumps(payload: Any) -> str:
    """Serialise a frame, refusing to emit non-finite numbers.

    ``json.dumps`` writes bare ``NaN``/``Infinity`` tokens, which are not valid
    JSON and which ``JSON.parse`` rejects outright - one bad ratio deep inside
    an evidence bag would cost the dashboard the entire frame.
    """
    return json.dumps(
        payload, default=_json_default, allow_nan=False, separators=(",", ":")
    )


def _strip_nonfinite(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _strip_nonfinite(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_strip_nonfinite(v) for v in obj]
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    return obj


class _Connection:
    """One dashboard connection and its outbound queue."""

    __slots__ = ("ws", "queue", "dropped", "task", "closed")

    def __init__(self, ws: WebSocket, maxlen: int) -> None:
        self.ws = ws
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=maxlen)
        self.dropped = 0
        self.task: asyncio.Task | None = None
        self.closed = False

    def offer(self, frame: str) -> None:
        """Enqueue without ever blocking the caller."""
        try:
            self.queue.put_nowait(frame)
        except asyncio.QueueFull:
            # Drop the oldest frame to make room. Under flood, the newest alerts
            # are the ones worth showing.
            try:
                self.queue.get_nowait()
                self.dropped += 1
            except asyncio.QueueEmpty:  # pragma: no cover - racy but harmless
                pass
            try:
                self.queue.put_nowait(frame)
            except asyncio.QueueFull:  # pragma: no cover
                self.dropped += 1

    def take_dropped(self) -> int:
        n, self.dropped = self.dropped, 0
        return n


class ConnectionHub:
    """Tracks connected dashboards and fans frames out to them."""

    def __init__(self, queue_max: int = 1000) -> None:
        self._queue_max = queue_max
        self._connections: set[_Connection] = set()
        self._lock = asyncio.Lock()

    @property
    def client_count(self) -> int:
        return len(self._connections)

    async def connect(self, ws: WebSocket) -> _Connection:
        await ws.accept()
        conn = _Connection(ws, self._queue_max)
        conn.task = asyncio.create_task(self._writer(conn))
        async with self._lock:
            self._connections.add(conn)
        return conn

    async def disconnect(self, conn: _Connection) -> None:
        conn.closed = True
        async with self._lock:
            self._connections.discard(conn)
        if conn.task is not None:
            conn.task.cancel()
            try:
                await conn.task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    async def _writer(self, conn: _Connection) -> None:
        """Drain one connection's queue.

        Runs as its own task so a client that stops reading blocks only itself.
        """
        try:
            while not conn.closed:
                frame = await conn.queue.get()
                await conn.ws.send_text(frame)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - any transport error ends the connection
            log.debug("websocket writer stopped: %s", exc)
            conn.closed = True

    def broadcast(self, frame_type: str, data: Any) -> None:
        """Queue a frame for every connected dashboard. Never blocks, never raises.

        Called from the alert ingest path, so it has to be safe under every
        failure mode: a serialisation error here must not turn into a 500 on a
        detector's POST.
        """
        if not self._connections:
            return
        payload = {"type": frame_type, "data": data}
        try:
            frame = dumps(payload)
        except (TypeError, ValueError):
            try:
                frame = dumps(_strip_nonfinite(payload))
            except (TypeError, ValueError):
                log.exception("dropping unserialisable %s frame", frame_type)
                return
        for conn in tuple(self._connections):
            if not conn.closed:
                conn.offer(frame)

    def send_to(self, conn: _Connection, frame_type: str, data: Any) -> None:
        """Queue a frame for one connection (used for the initial snapshot)."""
        try:
            conn.offer(dumps({"type": frame_type, "data": data}))
        except (TypeError, ValueError):
            log.exception("dropping unserialisable %s frame", frame_type)

    def collect_dropped(self) -> int:
        """Total frames dropped across all clients since the last call."""
        return sum(c.take_dropped() for c in tuple(self._connections))

    async def close_all(self) -> None:
        for conn in tuple(self._connections):
            await self.disconnect(conn)
            try:
                await conn.ws.close()
            except Exception:  # noqa: BLE001
                pass
