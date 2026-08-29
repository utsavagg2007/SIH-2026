"""The alert bus: ingest -> fusion -> fan-out.

This is the spine of the backend.  One rule governs its design, from Downstream
Architecture 8.2 and Build Plan layer 6:

    "Each alert goes to two independent consumers in parallel - a WebSocket
    channel for the live dashboard, and a batched writer for PostgreSQL.  The
    live path never waits on the durable path.  Routing alerts through the
    database before display converts your streaming system into a micro-batch
    system and forfeits requirement (c)."

So ``publish`` is synchronous and does no I/O.  It validates, dedups,
correlates, projects, broadcasts to in-process queues, and appends to a
write-behind queue.  Nothing in that sequence can block on a socket or a
database.  A detector's POST returns as soon as the alert is on the wire to
every connected dashboard.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from ..config import Settings
from ..fusion.correlate import IncidentEngine
from ..fusion.dedup import Deduplicator
from ..projection.project import project_alert
from ..schemas.alert_v11 import ThreatAlertV11
from ..schemas.view import AlertView, IncidentView
from ..storage.base import AlertRepository
from .hub import ConnectionHub
from .metrics import MetricsRegistry

log = logging.getLogger(__name__)


@dataclass(slots=True)
class PublishResult:
    view: AlertView
    deduplicated: bool
    incident: IncidentView | None


class AlertBus:
    """Fans one v1.1 alert out to the live path and the durable path."""

    def __init__(
        self,
        *,
        settings: Settings,
        hub: ConnectionHub,
        metrics: MetricsRegistry,
        repository: AlertRepository,
    ) -> None:
        self._settings = settings
        self._hub = hub
        self._metrics = metrics
        self._repo = repository

        self._dedup = Deduplicator(
            window_s=settings.dedup_window_s, max_keys=settings.dedup_max_keys
        )
        self._incidents = IncidentEngine(
            window_s=settings.correlation_window_s,
            max_incidents=settings.correlation_max_incidents,
            escalate_stages=settings.correlation_escalate_stages,
        )

        # Write-behind queue. Bounded: if the durable path cannot keep up we
        # shed writes and say so, rather than letting the queue consume memory
        # until the process dies mid-demo.
        self._write_queue: asyncio.Queue[AlertView] = asyncio.Queue(
            maxsize=settings.db_queue_max
        )
        self._writer_task: asyncio.Task | None = None
        self._metrics_task: asyncio.Task | None = None
        self._running = False

        self.writes_shed = 0
        self.write_errors = 0

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        self._writer_task = asyncio.create_task(self._write_behind())
        self._metrics_task = asyncio.create_task(self._metrics_loop())

    async def stop(self) -> None:
        self._running = False
        for task in (self._writer_task, self._metrics_task):
            if task is not None:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
        # Best-effort drain so a clean shutdown does not lose the tail of the
        # run. Bounded by what is already queued; no new work is accepted.
        await self._drain_writes()

    # ------------------------------------------------------------------
    # the hot path
    # ------------------------------------------------------------------

    def publish(self, alert: ThreatAlertV11) -> PublishResult:
        """Process one alert. Synchronous, non-blocking, no I/O.

        Returns the projected view so the ingest route can answer the detector
        with occurrence and incident state.
        """
        now = time.time()

        dedup_result = self._dedup.observe(alert, now=now)
        state = dedup_result.state

        # Snapshot the revision before correlating so we can tell a material
        # change from a repeat that only moved an occurrence count.
        prior = self._incidents.peek_revision(alert)
        incident = self._incidents.correlate(
            alert, occurrences=state.occurrences, now=now
        )
        incident_view: IncidentView | None = None
        is_new_incident = False
        incident_changed = False
        if incident is not None:
            is_new_incident = incident.revision == 1 and prior is None
            incident_changed = incident.revision != prior
            # Building the view sorts every member and rebuilds the narrative.
            # Only pay for it when there is something new to say.
            if incident_changed:
                incident_view = self._incidents.to_view(incident)

        view = project_alert(
            alert,
            dedup=state,
            incident_id=incident.incident_id if incident else None,
            ingested_at=now,
        )

        self._metrics.record_alert(
            detector=alert.detector,
            detector_version=alert.detector_version,
            threat_class=alert.threat_class.value,
            detector_latency_ms=view.detector_latency_ms,
            pipeline_latency_ms=view.pipeline_latency_ms,
            deduplicated=dedup_result.is_duplicate,
            now=now,
        )

        # Live path first, always. Alert spec section 10 names the event types;
        # a repeat folds into an update so the dashboard row changes in place
        # instead of the stream filling with duplicates.
        frame = "alert.updated" if dedup_result.is_duplicate else "alert.created"
        self._hub.broadcast(frame, view.model_dump(mode="json"))

        if incident_view is not None:
            if is_new_incident:
                self._metrics.record_incident()
            self._hub.broadcast(
                "incident.created" if is_new_incident else "incident.updated",
                incident_view.model_dump(mode="json"),
            )

        # Durable path second, and only ever as an enqueue.
        self._enqueue_write(view)

        return PublishResult(
            view=view,
            deduplicated=dedup_result.is_duplicate,
            incident=incident_view,
        )

    def _enqueue_write(self, view: AlertView) -> None:
        try:
            self._write_queue.put_nowait(view)
        except asyncio.QueueFull:
            # Shedding is the correct failure here: the alert already reached
            # every dashboard, and the alternative is unbounded memory growth
            # during a flood. The count is surfaced on /system/health so the
            # loss is visible rather than silent.
            self.writes_shed += 1
            if self.writes_shed % 1000 == 1:
                log.warning(
                    "durable write queue full; shed %d alert(s) so far",
                    self.writes_shed,
                )

    # ------------------------------------------------------------------
    # background tasks
    # ------------------------------------------------------------------

    async def _write_behind(self) -> None:
        """Batch alerts into the repository.

        One insert per alert becomes the bottleneck during a flood, which is
        precisely when we least want one (Build Plan layer 6).
        """
        batch: list[AlertView] = []
        interval = self._settings.db_batch_interval_s
        size = self._settings.db_batch_size

        while self._running:
            try:
                deadline = asyncio.get_running_loop().time() + interval
                while len(batch) < size:
                    timeout = deadline - asyncio.get_running_loop().time()
                    if timeout <= 0:
                        break
                    try:
                        batch.append(
                            await asyncio.wait_for(
                                self._write_queue.get(), timeout=timeout
                            )
                        )
                    except asyncio.TimeoutError:
                        break
                if batch:
                    await self._flush(batch)
                    batch = []
            except asyncio.CancelledError:
                if batch:
                    await self._flush(batch)
                raise
            except Exception:  # noqa: BLE001
                log.exception("write-behind loop error")
                batch = []
                await asyncio.sleep(0.5)

    async def _flush(self, batch: list[AlertView]) -> None:
        try:
            await self._repo.save_alerts(batch)
        except Exception:  # noqa: BLE001
            # Storage failure must degrade to live-only, never halt detection
            # (Downstream Architecture 8.1: "log the degradation, keep
            # detecting").
            self.write_errors += 1
            log.exception("failed to persist %d alert(s); continuing", len(batch))

    async def _drain_writes(self) -> None:
        batch: list[AlertView] = []
        while not self._write_queue.empty():
            batch.append(self._write_queue.get_nowait())
            if len(batch) >= self._settings.db_batch_size:
                await self._flush(batch)
                batch = []
        if batch:
            await self._flush(batch)

    async def _metrics_loop(self) -> None:
        """Emit the once-per-second metrics frame (Frontend spec 7)."""
        interval = self._settings.metrics_interval_s
        while self._running:
            try:
                await asyncio.sleep(interval)
                self._hub.broadcast("metrics", self.metrics_frame().model_dump())
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("metrics loop error")

    # ------------------------------------------------------------------
    # readouts
    # ------------------------------------------------------------------

    def metrics_frame(self):
        from ..schemas.view import MetricsFrame

        now = time.time()
        p50, p95, pmax = self._metrics.latency_percentiles(now)
        traffic = self._metrics.traffic
        live = self._metrics.traffic_is_live(
            self._settings.telemetry_stale_after_s, now
        )
        return MetricsFrame(
            ts=now,
            flows_per_sec=traffic.flows_per_sec if live else 0.0,
            packets_per_sec=traffic.packets_per_sec if live else 0.0,
            mbps=traffic.mbps if live else 0.0,
            traffic_telemetry_live=live,
            alerts_per_sec=round(self._metrics.alerts_per_sec(now), 2),
            alerts_total=self._metrics.alerts_total,
            latency_p50_ms=p50,
            latency_p95_ms=p95,
            latency_max_ms=pmax,
            detectors_online=len(self._online_detectors(now)),
            detectors_total=max(
                len(self._metrics.detectors), traffic.detectors_total
            ),
            egress_blocked=True,
            uptime_s=round(self._metrics.uptime_s, 1),
            ws_clients=self._hub.client_count,
            ws_dropped=self._hub.collect_dropped(),
        )

    def _online_detectors(self, now: float) -> list[str]:
        stale = self._settings.detector_stale_after_s
        return [
            name
            for name, rec in self._metrics.detectors.items()
            if now - rec.last_seen <= stale
        ]

    @property
    def incidents(self) -> IncidentEngine:
        return self._incidents

    @property
    def dedup(self) -> Deduplicator:
        return self._dedup

    @property
    def write_queue_depth(self) -> int:
        return self._write_queue.qsize()
