"""Runtime configuration for the analyst service.

Defaults are chosen so ``uvicorn analyst.main:app --port 8100`` starts and
serves useful answers with **no API key and no network access at all** - it
falls back to the deterministic template provider. Supplying
``ANALYST_GEMINI_API_KEY`` is what turns generation on, and that is also the
only thing that opens an outbound connection.
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
        env_prefix="ANALYST_",
        extra="ignore",
    )

    app_name: str = "SIH26 AI Security Analyst"
    app_version: str = "0.1.0"
    host: str = "127.0.0.1"
    port: int = 8100
    log_level: str = "INFO"

    # --- where the alerts come from --------------------------------------
    #: The backend's read-only REST API. The analyst never touches raw
    #: traffic, never reads a PCAP, and never opens the detection database
    #: directly - it consumes exactly what the dashboard consumes, which
    #: keeps "reads only from the alert store" checkable rather than asserted.
    backend_url: str = "http://127.0.0.1:8000"
    backend_timeout_s: float = 10.0

    # --- generation -------------------------------------------------------
    #: "gemini" needs an API key and makes outbound HTTPS calls.
    #: "template" is fully local, deterministic, and needs nothing.
    #: "auto" picks gemini when a key is present and template otherwise.
    provider: Literal["auto", "gemini", "template"] = "auto"

    gemini_api_key: str | None = None
    #: Model id. Set this to whichever Gemini model your key can reach - the
    #: service does not hardcode a family, and reports the configured id in
    #: /health so a wrong value is visible immediately rather than at demo time.
    gemini_model: str = "gemini-2.5-flash-lite"
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta"
    gemini_timeout_s: float = 20.0
    gemini_max_output_tokens: int = 700
    #: Low, not zero. The analyst paraphrases a fact sheet; it must not invent,
    #: and it must not produce a different answer each time a judge clicks.
    gemini_temperature: float = 0.15

    # --- safety rails -----------------------------------------------------
    #: Hard ceiling on how many alerts one question may retrieve. The analyst
    #: is a narrator, not an exporter.
    max_retrieved_alerts: int = Field(default=40, ge=1, le=200)
    #: Refuse to generate when the fact sheet is empty. An analyst layer that
    #: speculates beyond its evidence is worse than no analyst layer
    #: (Layered Build Plan, layer 8).
    require_evidence: bool = True

    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:4173",
            "http://127.0.0.1:4173",
        ]
    )

    @property
    def resolved_provider(self) -> Literal["gemini", "template"]:
        if self.provider == "gemini":
            return "gemini"
        if self.provider == "template":
            return "template"
        return "gemini" if self.gemini_api_key else "template"

    @property
    def egress_enabled(self) -> bool:
        """Whether this process will open any outbound connection at all.

        Reported verbatim on ``/api/v1/analyst/constraints`` and mirrored into
        the dashboard's constraint panel, because "does your LLM have network
        access" is a question this project should answer with a readout rather
        than a sentence.
        """
        return self.resolved_provider == "gemini"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
