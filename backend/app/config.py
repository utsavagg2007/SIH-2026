"""Runtime configuration.

Every tunable that a demo operator might need to change lives here and is
settable from the environment or a ``.env`` file.  Defaults are chosen so that
``uvicorn app.main:app`` works with no configuration at all - the in-memory
store, no Supabase project, no external anything.  That matters more than it
sounds: the fallback path is the demo-day insurance policy.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- service ---------------------------------------------------------
    app_name: str = "SIH26 Passive Threat Detection Backend"
    app_version: str = "1.0.0"
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"

    #: Origins allowed to call the API.  The dashboard is served from a
    #: different port during development, so the Vite dev server is allowed by
    #: default.  This is a monitoring enclave, not a public service.
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:4173",
            "http://127.0.0.1:4173",
        ]
    )

    # --- storage ---------------------------------------------------------
    #: "memory" needs nothing and loses history on restart.  "postgres" talks
    #: to any Postgres, including the one behind a Supabase project - use the
    #: connection string from Supabase > Project Settings > Database.
    storage_backend: Literal["memory", "postgres"] = "memory"
    database_url: str | None = None
    #: Supabase convenience: if these two are set and database_url is not, the
    #: Postgres URL is derived from them.
    supabase_db_password: str | None = None
    supabase_project_ref: str | None = None

    db_pool_min: int = 1
    db_pool_max: int = 8
    #: Alerts are written in batches. One insert per alert becomes the
    #: bottleneck during a flood, which is exactly when we least want one
    #: (Build Plan layer 6).
    db_batch_size: int = 200
    db_batch_interval_s: float = 0.5
    #: Hard ceiling on the durable-write queue.  If Postgres cannot keep up we
    #: shed writes rather than growing memory without bound - the live path is
    #: what is graded, and it must not be dragged down by the durable one.
    db_queue_max: int = 50_000

    #: How many alerts the in-memory store keeps.  Also the cap on the
    #: snapshot a reconnecting dashboard receives.
    memory_alert_capacity: int = 20_000

    # --- fusion ----------------------------------------------------------
    #: Repeat findings for the same entity + class + detector inside this
    #: window fold into one alert with an occurrence count (Build Plan layer 5).
    dedup_window_s: float = 300.0
    dedup_max_keys: int = 100_000
    #: Alerts touching the same host within this window join one incident.
    correlation_window_s: float = 1800.0
    correlation_max_incidents: int = 10_000
    #: An incident needs at least this many distinct kill-chain stages before
    #: the sequence itself is treated as evidence and the severity escalates.
    correlation_escalate_stages: int = 2

    # --- live path -------------------------------------------------------
    #: Per-connection outbound queue.  When a client falls behind we drop the
    #: oldest frames and tell it how many, rather than letting one slow browser
    #: apply backpressure to the whole detection pipeline.
    ws_queue_max: int = 1000
    ws_snapshot_size: int = 100
    metrics_interval_s: float = 1.0
    #: Rolling window over which alerts/sec and latency percentiles are
    #: computed.
    metrics_window_s: float = 60.0

    # --- telemetry -------------------------------------------------------
    #: Traffic-rate telemetry older than this is treated as stale, and the
    #: metrics frame reports the figures as not-live instead of showing an
    #: outdated number as if it were current.
    telemetry_stale_after_s: float = 5.0
    #: A detector that has not posted for this long is reported as degraded.
    detector_stale_after_s: float = 120.0

    # --- replay ----------------------------------------------------------
    fixtures_dir: str = "fixtures"
    replay_default_speed: float = 1.0

    @property
    def resolved_database_url(self) -> str | None:
        """Postgres URL, derived from the Supabase settings when necessary."""
        if self.database_url:
            return self.database_url
        if self.supabase_project_ref and self.supabase_db_password:
            # Supabase's pooled connection endpoint.  Port 6543 is the
            # transaction pooler, which is the right choice for short-lived
            # batched writes.
            return (
                f"postgresql://postgres.{self.supabase_project_ref}:"
                f"{self.supabase_db_password}"
                f"@aws-0-ap-south-1.pooler.supabase.com:6543/postgres"
            )
        return None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
