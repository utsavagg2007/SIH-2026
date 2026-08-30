"""Read-only retrieval against the backend's alert API.

Hard boundaries, from the Layered Build Plan (layer 8) and the Downstream
Architecture (8.5):

* reads only from the alert store - never raw traffic, never payload;
* cannot influence detection, scoring or severity;
* is never on the critical path for emitting an alert.

Those are enforced structurally here rather than promised in a docstring: this
module issues **GET requests only**, against a fixed allowlist of backend
routes, and exposes no function that writes anything. The backend's own ingest
route (``POST /api/v1/alerts``) is unreachable from this client because no
method here can issue a POST.

Alerts arrive as plain dictionaries on purpose. The alert contract freezes the
top level but leaves ``evidence`` deliberately open-ended, and the integration
guide is explicit that a consumer must not break on an unfamiliar evidence key.
Parsing into a closed model here would reintroduce exactly that fragility.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

Alert = dict[str, Any]
Incident = dict[str, Any]

#: Every path this service is permitted to read. Anything not on this list is a
#: programming error, and ``_get`` raises rather than issuing the request - so
#: the blast radius of this component stays reviewable at a glance.
_ALLOWED_PREFIXES = (
    "/api/v1/alerts",
    "/api/v1/incidents",
    "/api/v1/hosts",
    "/api/v1/system/health",
    "/api/v1/system/constraints",
    "/api/v1/system/detectors",
)


class RetrievalError(RuntimeError):
    """The alert store could not be reached or answered with an error."""


class AlertStore:
    """A read-only view of the persisted alert corpus."""

    def __init__(self, base_url: str, *, timeout_s: float = 10.0) -> None:
        self._base = base_url.rstrip("/") + "/"
        self._timeout = timeout_s
        self._client: httpx.AsyncClient | None = None

    async def open(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- transport --------------------------------------------------------

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        if not any(path.startswith(prefix) for prefix in _ALLOWED_PREFIXES):
            raise RetrievalError(f"path {path!r} is not on the analyst read allowlist")
        if self._client is None:
            raise RetrievalError("AlertStore used before open()")

        clean = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            response = await self._client.get(urljoin(self._base, path.lstrip("/")), params=clean)
        except httpx.HTTPError as exc:
            raise RetrievalError(f"alert store unreachable: {exc}") from exc
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise RetrievalError(
                f"alert store returned {response.status_code} for {path}: {response.text[:200]}"
            )
        return response.json()

    async def healthy(self) -> bool:
        try:
            await self._get("/api/v1/system/health")
        except RetrievalError:
            return False
        return True

    # -- reads ------------------------------------------------------------

    async def get_alert(self, alert_id: str) -> Alert | None:
        return await self._get(f"/api/v1/alerts/{alert_id}")

    async def get_incident(self, incident_id: str) -> Incident | None:
        return await self._get(f"/api/v1/incidents/{incident_id}")

    async def get_host(self, ip: str) -> dict[str, Any] | None:
        return await self._get(f"/api/v1/hosts/{ip}")

    async def query_alerts(
        self,
        *,
        from_ts: float | None = None,
        to_ts: float | None = None,
        threat_class: str | None = None,
        severity: str | None = None,
        host: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        detector: str | None = None,
        incident_id: str | None = None,
        min_score: float | None = None,
        limit: int = 40,
    ) -> list[Alert]:
        page = await self._get(
            "/api/v1/alerts",
            {
                "from": from_ts,
                "to": to_ts,
                "threat_class": threat_class,
                "severity": severity,
                "host": host,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "detector": detector,
                "incident_id": incident_id,
                "min_score": min_score,
                "limit": limit,
            },
        )
        return list((page or {}).get("items", []))

    async def recent_incidents(self, limit: int = 10) -> list[Incident]:
        page = await self._get("/api/v1/incidents", {"limit": limit})
        if isinstance(page, dict):
            return list(page.get("items", []))
        return list(page or [])

    async def detectors(self) -> list[dict[str, Any]]:
        payload = await self._get("/api/v1/system/detectors")
        if isinstance(payload, dict):
            return list(payload.get("detectors", payload.get("items", [])))
        return list(payload or [])
