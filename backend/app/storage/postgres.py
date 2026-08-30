"""Postgres alert store, via asyncpg.

Works against any Postgres.  For Supabase, use the connection string from
Project Settings > Database - a Supabase project *is* a Postgres instance, and
connecting to it directly gets us three things the PostgREST/HTTP client cannot:

* real batched writes (``executemany`` over one connection), which Build Plan
  layer 6 requires because one insert per alert becomes the bottleneck during a
  flood;
* native JSONB for ``evidence``, indexed with GIN;
* a persistent pool, so the write-behind task is not paying TLS handshake cost
  per batch.

The schema lives in ``db/schema.sql`` and can be pasted straight into the
Supabase SQL editor.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import urlparse

from ..core.constraints import EgressLedger
from ..schemas.view import AlertView
from .base import AlertPage, AlertQuery

log = logging.getLogger(__name__)

_COLUMNS = """
    alert_id, schema_version, ts, event_start, event_end, detected_at,
    ingested_at, event_scope, flow_id, src_ip, dst_ip, dst_port, protocol,
    threat_class, severity, score, score_type, detector, detector_version,
    incident_id, kill_chain_stage, occurrences, first_seen, last_seen,
    dedup_key, detector_latency_ms, transport_latency_ms, pipeline_latency_ms,
    evidence, evidence_bars, visual, mitre_techniques, raw
"""

_INSERT = f"""
INSERT INTO alerts ({_COLUMNS})
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
        $20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)
ON CONFLICT (alert_id) DO UPDATE SET
    occurrences = EXCLUDED.occurrences,
    last_seen = EXCLUDED.last_seen,
    event_end = EXCLUDED.event_end,
    score = GREATEST(alerts.score, EXCLUDED.score),
    severity = EXCLUDED.severity,
    incident_id = COALESCE(EXCLUDED.incident_id, alerts.incident_id),
    evidence = EXCLUDED.evidence,
    evidence_bars = EXCLUDED.evidence_bars,
    visual = EXCLUDED.visual
"""


class PostgresRepository:
    """Batched, write-behind persistence. Never on the live path."""

    def __init__(
        self,
        dsn: str,
        *,
        pool_min: int = 1,
        pool_max: int = 8,
        ledger: EgressLedger | None = None,
    ) -> None:
        self._dsn = dsn
        self._pool_min = pool_min
        self._pool_max = pool_max
        self._pool: Any = None
        self._ledger = ledger
        self._healthy = False

    @property
    def backend_name(self) -> str:
        return "postgres"

    async def connect(self) -> None:
        import asyncpg  # imported here so the memory backend needs no driver

        host = urlparse(self._dsn).hostname or "unknown"
        if self._ledger is not None:
            # Connecting to the alert database is egress, and the constraint
            # panel discloses it rather than pretending the process is
            # hermetic. It is enclave-internal, not a path toward the
            # monitored network.
            self._ledger.record_storage_egress(host)

        self._pool = await asyncpg.create_pool(
            self._dsn,
            min_size=self._pool_min,
            max_size=self._pool_max,
            command_timeout=30,
            # Supabase's transaction pooler does not support prepared
            # statements; disabling the cache keeps this working against both
            # the pooler and a direct connection.
            statement_cache_size=0,
        )
        async with self._pool.acquire() as conn:
            await conn.execute("SELECT 1")
        self._healthy = True
        log.info("connected to postgres at %s", host)

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
        self._healthy = False

    async def healthy(self) -> bool:
        if self._pool is None:
            return False
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("SELECT 1")
            self._healthy = True
        except Exception:  # noqa: BLE001
            self._healthy = False
        return self._healthy

    # ------------------------------------------------------------------

    @staticmethod
    def _row_params(a: AlertView) -> tuple:
        return (
            a.alert_id,
            a.schema_version,
            a.ts,
            a.event_start,
            a.event_end,
            a.detected_at,
            a.ingested_at,
            a.event_scope.value,
            a.flow_id,
            a.src_ip,
            a.dst_ip,
            a.dst_port,
            a.protocol,
            a.threat_class.value,
            a.severity.value,
            a.score,
            a.score_type.value,
            a.detector,
            a.detector_version,
            a.incident_id,
            a.kill_chain_stage.value,
            a.occurrences,
            a.first_seen,
            a.last_seen,
            a.dedup_key,
            a.detector_latency_ms,
            a.transport_latency_ms,
            a.pipeline_latency_ms,
            json.dumps(a.evidence_raw, default=str),
            json.dumps([e.model_dump() for e in a.evidence], default=str),
            json.dumps(a.visual, default=str) if a.visual else None,
            list(a.mitre_techniques),
            json.dumps(a.raw, default=str),
        )

    async def save_alerts(self, alerts: list[AlertView]) -> None:
        if not alerts or self._pool is None:
            return
        params = [self._row_params(a) for a in alerts]
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.executemany(_INSERT, params)

    # ------------------------------------------------------------------

    @staticmethod
    def _to_view(row: Any) -> AlertView:
        """Rebuild the view model from a stored row.

        ``raw`` holds the untouched v1.1 object, so a stored alert can always be
        re-projected if the projection logic changes - the persisted copy never
        becomes the only source of truth for what the detector actually said.
        """
        data = dict(row)
        for key in ("evidence", "evidence_bars", "visual", "raw"):
            v = data.get(key)
            if isinstance(v, str):
                data[key] = json.loads(v)
        return AlertView(
            alert_id=data["alert_id"],
            schema_version=data["schema_version"],
            ts=data["ts"],
            event_start=data["event_start"],
            event_end=data["event_end"],
            detected_at=data["detected_at"],
            ingested_at=data["ingested_at"],
            event_start_iso=data["raw"]["event_start"],
            event_end_iso=data["raw"]["event_end"],
            detected_at_iso=data["raw"]["detected_at"],
            event_scope=data["event_scope"],
            flow_id=data["flow_id"],
            src_ip=data["src_ip"],
            dst_ip=data["dst_ip"],
            dst_port=data["dst_port"],
            protocol=data["protocol"],
            threat_class=data["threat_class"],
            threat_code=data["raw"].get("threat_code") or "",
            threat_label="",
            severity=data["severity"],
            score=data["score"],
            confidence=data["score"],
            score_type=data["score_type"],
            evidence=data["evidence_bars"] or [],
            evidence_raw=data["evidence"] or {},
            visual=data["visual"],
            detector=data["detector"],
            detector_version=data["detector_version"],
            mitre_techniques=list(data["mitre_techniques"] or []),
            incident_id=data["incident_id"],
            kill_chain_stage=data["kill_chain_stage"],
            occurrences=data["occurrences"],
            first_seen=data["first_seen"],
            last_seen=data["last_seen"],
            dedup_key=data["dedup_key"],
            detector_latency_ms=data["detector_latency_ms"],
            transport_latency_ms=data["transport_latency_ms"],
            pipeline_latency_ms=data["pipeline_latency_ms"],
            raw=data["raw"],
        )

    @staticmethod
    def _hydrate(view: AlertView) -> AlertView:
        """Restore the display fields that are derived, not stored."""
        from ..schemas.enums import THREAT_CODE, THREAT_LABEL

        return view.model_copy(
            update={
                "threat_code": THREAT_CODE[view.threat_class],
                "threat_label": THREAT_LABEL[view.threat_class],
            }
        )

    def _build_where(self, q: AlertQuery) -> tuple[str, list]:
        clauses: list[str] = []
        params: list = []

        def add(sql: str, value: Any) -> None:
            params.append(value)
            clauses.append(sql.format(n=len(params)))

        if q.from_ts is not None:
            add("ts >= ${n}", q.from_ts)
        if q.to_ts is not None:
            add("ts <= ${n}", q.to_ts)
        if q.threat_class:
            add("threat_class = ${n}", q.threat_class)
        if q.severity:
            add("severity = ${n}", q.severity)
        if q.src_ip:
            add("src_ip = ${n}", q.src_ip)
        if q.dst_ip:
            add("dst_ip = ${n}", q.dst_ip)
        if q.host:
            params.append(q.host)
            clauses.append(f"(src_ip = ${len(params)} OR dst_ip = ${len(params)})")
        if q.detector:
            add("detector = ${n}", q.detector)
        if q.incident_id:
            add("incident_id = ${n}", q.incident_id)
        if q.min_score is not None:
            add("score >= ${n}", q.min_score)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    async def query_alerts(self, q: AlertQuery) -> AlertPage:
        if self._pool is None:
            return AlertPage(items=[], total=0, limit=q.limit, offset=q.offset)
        where, params = self._build_where(q)
        async with self._pool.acquire() as conn:
            total = await conn.fetchval(
                f"SELECT COUNT(*) FROM alerts {where}", *params
            )
            rows = await conn.fetch(
                f"SELECT * FROM alerts {where} ORDER BY ts DESC "
                f"LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}",
                *params,
                q.limit,
                q.offset,
            )
        return AlertPage(
            items=[self._hydrate(self._to_view(r)) for r in rows],
            total=int(total or 0),
            limit=q.limit,
            offset=q.offset,
        )

    async def get_alert(self, alert_id: str) -> AlertView | None:
        if self._pool is None:
            return None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM alerts WHERE alert_id = $1", alert_id
            )
        return self._hydrate(self._to_view(row)) if row else None

    async def recent_alerts(self, limit: int) -> list[AlertView]:
        if self._pool is None:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM alerts ORDER BY ts DESC LIMIT $1", limit
            )
        return [self._hydrate(self._to_view(r)) for r in rows]

    async def host_alerts(self, ip: str, limit: int) -> list[AlertView]:
        if self._pool is None:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM alerts WHERE src_ip = $1 OR dst_ip = $1 "
                "ORDER BY ts DESC LIMIT $2",
                ip,
                limit,
            )
        return [self._hydrate(self._to_view(r)) for r in rows]

    async def distinct_hosts(self, limit: int) -> list[str]:
        if self._pool is None:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT ip FROM (
                    SELECT src_ip AS ip, MAX(ts) AS last_ts FROM alerts
                    WHERE src_ip IS NOT NULL GROUP BY src_ip
                    UNION ALL
                    SELECT dst_ip AS ip, MAX(ts) AS last_ts FROM alerts
                    WHERE dst_ip IS NOT NULL GROUP BY dst_ip
                ) t GROUP BY ip ORDER BY MAX(last_ts) DESC LIMIT $1
                """,
                limit,
            )
        return [r["ip"] for r in rows]
