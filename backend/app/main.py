"""FastAPI application.

    detector --POST /api/v1/alerts--> AlertBus
                                        |-- WebSocket  (live, never blocked)
                                        '-- write-behind batch --> Postgres

Run it::

    uvicorn app.main:app --reload            # in-memory store, zero config
    STORAGE_BACKEND=postgres uvicorn app.main:app
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import alerts, hosts, incidents, replay as replay_api, system, ws
from .config import get_settings
from .core.bus import AlertBus
from .core.constraints import ConstraintAuditor
from .core.hub import ConnectionHub
from .core.metrics import MetricsRegistry
from .replay.engine import ReplayEngine
from .storage.base import AlertRepository
from .storage.memory import MemoryRepository

log = logging.getLogger(__name__)


def _build_repository(settings, auditor: ConstraintAuditor) -> AlertRepository:
    """Pick a storage backend, falling back to memory rather than refusing to start.

    A misconfigured database on demo day should cost durability, not the demo.
    The System view reports which backend is actually in use, so the fallback is
    visible rather than silent.
    """
    if settings.storage_backend == "postgres":
        dsn = settings.resolved_database_url
        if not dsn:
            log.error(
                "STORAGE_BACKEND=postgres but no DATABASE_URL (or "
                "SUPABASE_PROJECT_REF + SUPABASE_DB_PASSWORD) is set; "
                "falling back to the in-memory store"
            )
        else:
            from .storage.postgres import PostgresRepository

            return PostgresRepository(
                dsn,
                pool_min=settings.db_pool_min,
                pool_max=settings.db_pool_max,
                ledger=auditor.ledger,
            )
    return MemoryRepository(capacity=settings.memory_alert_capacity)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    auditor = ConstraintAuditor()
    metrics = MetricsRegistry(
        window_s=settings.metrics_window_s,
        max_plausible_latency_ms=settings.max_plausible_latency_ms,
    )
    hub = ConnectionHub(queue_max=settings.ws_queue_max)
    repository = _build_repository(settings, auditor)

    try:
        await repository.connect()
    except Exception:  # noqa: BLE001
        log.exception(
            "storage backend %s failed to connect; falling back to memory",
            repository.backend_name,
        )
        repository = MemoryRepository(capacity=settings.memory_alert_capacity)
        await repository.connect()

    bus = AlertBus(
        settings=settings, hub=hub, metrics=metrics, repository=repository
    )
    await bus.start()

    fixtures = Path(settings.fixtures_dir)
    if not fixtures.is_absolute():
        fixtures = Path(__file__).resolve().parent.parent / settings.fixtures_dir

    app.state.settings = settings
    app.state.auditor = auditor
    app.state.metrics = metrics
    app.state.hub = hub
    app.state.repository = repository
    app.state.bus = bus
    app.state.replay = ReplayEngine(bus, fixtures)

    auditor.audit_routes(list(app.routes))
    log.info(
        "%s v%s ready | storage=%s | fixtures=%s",
        settings.app_name,
        settings.app_version,
        repository.backend_name,
        fixtures,
    )

    try:
        yield
    finally:
        await app.state.replay.stop()
        await bus.stop()
        await hub.close_all()
        await repository.close()
        log.info("shutdown complete")


app = FastAPI(
    title="SIH26-26145 Passive Threat Detection Backend",
    description=(
        "Ingests ThreatAlert v1.1 from the detection/ML layer, deduplicates and "
        "correlates it, and serves it to the dashboard over WebSocket and REST.\n\n"
        "**Read-only by construction.** No route in this service emits anything "
        "toward the monitored network, and no payload is ever decrypted. See "
        "`GET /api/v1/system/constraints`."
    ),
    version=get_settings().app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(hosts.router)
app.include_router(system.router)
app.include_router(replay_api.router)
app.include_router(ws.router)


@app.exception_handler(RequestValidationError)
async def validation_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """422 with a schema-conformance message on the ingest path.

    Alert spec section 9 specifies 422 for an invalid schema.  For ingest we say
    so explicitly and name the version, because the most likely cause is a
    detector that has drifted from the frozen contract, and a generic
    "validation error" sends people looking in the wrong place.
    """
    if request.url.path.startswith("/api/v1/alerts"):
        try:
            request.app.state.metrics.record_rejection()
        except AttributeError:
            pass
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "status": "rejected",
                "detail": "alert does not conform to ThreatAlert schema v1.1",
                "schema_version": "1.1",
                "errors": [
                    {
                        "field": ".".join(str(p) for p in e["loc"]),
                        "msg": e["msg"],
                        "type": e["type"],
                    }
                    for e in exc.errors()
                ],
            },
        )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors()},
    )


@app.get("/health", tags=["system"], summary="Liveness probe")
async def health() -> dict[str, str]:
    """Unconditional liveness. For readiness use /api/v1/system/health."""
    return {"status": "ok"}


def _mount_dashboard(application: FastAPI) -> None:
    """Serve the built dashboard from this process, when it has been built.

    The frontend talks to ``/api/v1`` and ``/ws/alerts`` as same-origin relative
    URLs, which the Vite dev proxy makes true during development and nothing
    made true afterwards: the production bundle loaded from any other origin
    failed every request. Mounting it here makes the relative URLs correct for
    free, and removes the need for CORS on the only path anyone actually runs.

    Mounted last and guarded on the directory existing, so a checkout that has
    never run ``npm run build`` starts exactly as before. The mount is
    read-only static file serving; it adds no route toward the monitored
    network, which is what ``ConstraintAuditor`` is counting.
    """
    dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
    if not dist.is_dir():
        log.info("no built dashboard at %s; API-only (run 'npm run build')", dist)
        return
    application.mount("/", StaticFiles(directory=dist, html=True), name="dashboard")
    log.info("serving the dashboard from %s", dist)


@app.get("/", tags=["system"], summary="Service descriptor")
async def root() -> dict:
    settings = get_settings()
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "alert_schema_version": "1.1",
        "docs": "/docs",
        "ingest": "POST /api/v1/alerts",
        "live_feed": "/ws/alerts",
        "constraint_proof": "/api/v1/system/constraints",
    }


_mount_dashboard(app)
