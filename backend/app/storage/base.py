"""Storage interface.

Two implementations back this: an in-memory ring buffer that needs no setup, and
Postgres (which is what a Supabase project gives you).  The interface is
deliberately narrow - the alert bus only ever needs to append in batches and
query historical windows.

Everything here is read-only over historical data on the API side.  Build Plan
layer 6: "Nothing in this system ever writes back toward the network."
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..schemas.view import AlertView


@dataclass(slots=True)
class AlertQuery:
    """Filters for the history API (alert spec section 11)."""

    from_ts: float | None = None
    to_ts: float | None = None
    threat_class: str | None = None
    severity: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    #: Matches either direction. The Host view needs "every alert involving
    #: this machine", which is not the same as filtering on src or dst alone.
    host: str | None = None
    detector: str | None = None
    incident_id: str | None = None
    min_score: float | None = None
    limit: int = 50
    offset: int = 0


@dataclass(slots=True)
class AlertPage:
    items: list[AlertView]
    total: int
    limit: int
    offset: int


@runtime_checkable
class AlertRepository(Protocol):
    async def connect(self) -> None: ...

    async def close(self) -> None: ...

    async def healthy(self) -> bool: ...

    async def save_alerts(self, alerts: list[AlertView]) -> None:
        """Persist a batch. Called only from the write-behind task."""
        ...

    async def query_alerts(self, q: AlertQuery) -> AlertPage: ...

    async def get_alert(self, alert_id: str) -> AlertView | None: ...

    async def recent_alerts(self, limit: int) -> list[AlertView]:
        """Newest first. Used for the snapshot a reconnecting dashboard gets."""
        ...

    async def host_alerts(self, ip: str, limit: int) -> list[AlertView]: ...

    async def distinct_hosts(self, limit: int) -> list[str]: ...

    @property
    def backend_name(self) -> str: ...
