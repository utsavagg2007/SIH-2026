"""In-memory alert store.

The zero-configuration path: ``uvicorn app.main:app`` works with no database,
no Supabase project, and no network.  That is not just developer convenience -
Frontend spec 8.1 calls a working fallback the demo-day insurance policy, and
the same logic applies to the backend.  If the database is unreachable on stage,
switching ``STORAGE_BACKEND=memory`` keeps every screen working.

Bounded by construction: a deque with a hard capacity, oldest evicted first.
"""

from __future__ import annotations

import bisect
from collections import deque

from ..schemas.view import AlertView
from .base import AlertPage, AlertQuery


class MemoryRepository:
    def __init__(self, capacity: int = 20_000) -> None:
        self._capacity = capacity
        self._alerts: deque[AlertView] = deque(maxlen=capacity)
        self._by_id: dict[str, AlertView] = {}
        # Index of ingest timestamps parallel to _alerts, kept sorted because
        # alerts are appended in arrival order. Lets time-range queries binary
        # search instead of scanning, which matters once the buffer is full.
        self._times: deque[float] = deque(maxlen=capacity)

    @property
    def backend_name(self) -> str:
        return "memory"

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def healthy(self) -> bool:
        return True

    async def save_alerts(self, alerts: list[AlertView]) -> None:
        for a in alerts:
            existing = self._by_id.get(a.alert_id)
            if existing is not None:
                # A deduplicated repeat: replace in place so occurrences and the
                # extended window are reflected, without adding a second row.
                idx = self._index_of(existing)
                if idx is not None:
                    self._alerts[idx] = a
                self._by_id[a.alert_id] = a
                continue
            if len(self._alerts) == self._capacity and self._alerts:
                self._by_id.pop(self._alerts[0].alert_id, None)
            self._alerts.append(a)
            self._times.append(a.ingested_at)
            self._by_id[a.alert_id] = a

    def _index_of(self, target: AlertView) -> int | None:
        for i, a in enumerate(self._alerts):
            if a.alert_id == target.alert_id:
                return i
        return None

    def _matches(self, a: AlertView, q: AlertQuery) -> bool:
        if q.from_ts is not None and a.ts < q.from_ts:
            return False
        if q.to_ts is not None and a.ts > q.to_ts:
            return False
        if q.threat_class and a.threat_class.value != q.threat_class:
            return False
        if q.severity and a.severity.value != q.severity:
            return False
        if q.src_ip and a.src_ip != q.src_ip:
            return False
        if q.dst_ip and a.dst_ip != q.dst_ip:
            return False
        if q.host and q.host not in (a.src_ip, a.dst_ip):
            return False
        if q.detector and a.detector != q.detector:
            return False
        if q.incident_id and a.incident_id != q.incident_id:
            return False
        if q.min_score is not None and a.score < q.min_score:
            return False
        return True

    async def query_alerts(self, q: AlertQuery) -> AlertPage:
        # Narrow by time first when possible: the deque is in arrival order, so
        # a bounded window can skip most of the buffer.
        candidates = list(self._alerts)
        if q.from_ts is not None and self._times:
            times = list(self._times)
            start = bisect.bisect_left(times, q.from_ts)
            candidates = candidates[max(start - 1, 0) :]

        matched = [a for a in candidates if self._matches(a, q)]
        matched.sort(key=lambda a: a.ts, reverse=True)
        window = matched[q.offset : q.offset + q.limit]
        return AlertPage(
            items=window, total=len(matched), limit=q.limit, offset=q.offset
        )

    async def get_alert(self, alert_id: str) -> AlertView | None:
        return self._by_id.get(alert_id)

    async def recent_alerts(self, limit: int) -> list[AlertView]:
        items = list(self._alerts)[-limit:]
        items.reverse()
        return items

    async def host_alerts(self, ip: str, limit: int) -> list[AlertView]:
        out = [a for a in self._alerts if ip in (a.src_ip, a.dst_ip)]
        out.sort(key=lambda a: a.ts, reverse=True)
        return out[:limit]

    async def distinct_hosts(self, limit: int) -> list[str]:
        seen: dict[str, float] = {}
        for a in self._alerts:
            for ip in (a.src_ip, a.dst_ip):
                if ip:
                    seen[ip] = max(seen.get(ip, 0.0), a.ts)
        return [
            ip for ip, _ in sorted(seen.items(), key=lambda kv: kv[1], reverse=True)
        ][:limit]
