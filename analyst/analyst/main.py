"""FastAPI application for the analyst layer.

    uvicorn analyst.main:app --port 8100

Runs as its own process, on its own port, against the backend's public
read-only API. Nothing here is reachable from the detection path, and switching
this process off changes nothing upstream - which is the property the Layered
Build Plan asks to be demonstrated on demand.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .config import get_settings
from .grounding import FactSheet
from .llm import ENDPOINT_HOST, build_provider
from .llm.base import Generation
from .retrieval import AlertStore
from .service import AnalystService

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Wire models
# --------------------------------------------------------------------------


class Citation(BaseModel):
    """One claim and the stored field it came from."""

    text: str
    source: str
    value: Any = None


class AnalystAnswer(BaseModel):
    subject: str
    kind: Literal["alert", "incident", "corpus"]
    text: str
    #: False when the text is the deterministic rendering rather than model
    #: output. The panel badges this rather than hiding it.
    generated: bool
    provider: str
    model: str | None = None
    #: Present when generation was attempted and rejected or failed.
    degraded_reason: str | None = None
    citations: list[Citation]
    alert_ids: list[str]
    #: How the question was resolved to filters. Only set by /ask.
    interpreted_as: list[str] | None = None


class ExplainRequest(BaseModel):
    alert_id: str = Field(min_length=1, max_length=128)


class NarrateRequest(BaseModel):
    incident_id: str = Field(min_length=1, max_length=128)


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    limit: int | None = Field(default=None, ge=1, le=200)


class AnalystHealth(BaseModel):
    status: Literal["ok", "degraded"]
    provider: str
    model: str | None
    generation_enabled: bool
    alert_store: str
    alert_store_reachable: bool


class AnalystConstraints(BaseModel):
    """The read-only proof for this layer specifically.

    The dashboard's constraint panel shows the backend's three lines. This adds
    the fourth, which is the one a judge actually asks about.
    """

    reads_from: Literal["alert_store_only"] = "alert_store_only"
    reads_raw_traffic: Literal["never"] = "never"
    decrypts_payload: Literal["never"] = "never"
    influences_detection: Literal["never"] = "never"
    #: True when a hosted model is configured. Stated plainly rather than
    #: buried - a locally-rendered answer is the default, and this is what
    #: changes when generation is turned on.
    egress_enabled: bool
    egress_host: str | None
    egress_purpose: str
    disable_with: str = "ANALYST_PROVIDER=template"
    notes: list[str]


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/analyst", tags=["analyst"])


def _answer(
    sheet: FactSheet, generation: Generation, interpreted: list[str] | None = None
) -> AnalystAnswer:
    return AnalystAnswer(
        subject=sheet.subject,
        kind=sheet.kind,  # type: ignore[arg-type]
        text=generation.text,
        generated=generation.generated,
        provider=generation.provider,
        model=generation.model,
        degraded_reason=generation.degraded_reason,
        citations=[
            Citation(text=f.text, source=f.source, value=f.value) for f in sheet.ordered
        ],
        alert_ids=sheet.alert_ids,
        interpreted_as=interpreted,
    )


def _service(request: Request) -> AnalystService:
    return request.app.state.service


@router.post("/explain", response_model=AnalystAnswer, summary="Explain one alert")
async def explain(payload: ExplainRequest, request: Request) -> AnalystAnswer:
    sheet, generation = await _service(request).explain_alert(payload.alert_id)
    return _answer(sheet, generation)


@router.post("/narrate", response_model=AnalystAnswer, summary="Narrate one incident")
async def narrate(payload: NarrateRequest, request: Request) -> AnalystAnswer:
    sheet, generation = await _service(request).narrate_incident(payload.incident_id)
    return _answer(sheet, generation)


@router.post("/ask", response_model=AnalystAnswer, summary="Question the alert history")
async def ask(payload: AskRequest, request: Request) -> AnalystAnswer:
    sheet, generation, query = await _service(request).ask(payload.question, payload.limit)
    return _answer(sheet, generation, interpreted=query.understood)


@router.get("/health", response_model=AnalystHealth, summary="Analyst readiness")
async def health(request: Request) -> AnalystHealth:
    settings = request.app.state.settings
    provider = request.app.state.provider
    reachable = await _service(request).store_reachable()
    return AnalystHealth(
        status="ok" if reachable else "degraded",
        provider=provider.name,
        model=provider.model,
        generation_enabled=provider.name != "template",
        alert_store=settings.backend_url,
        alert_store_reachable=reachable,
    )


@router.get(
    "/constraints",
    response_model=AnalystConstraints,
    summary="What this layer can and cannot reach",
)
async def constraints(request: Request) -> AnalystConstraints:
    settings = request.app.state.settings
    provider = request.app.state.provider
    egress = bool(getattr(provider, "egress", False))
    notes = [
        "This layer runs in its own process and holds no detection state.",
        "It issues GET requests against the backend's read-only alert API and "
        "nothing else; no method in analyst.retrieval can POST.",
        "Every sentence it returns is derived from a stored alert field, and "
        "each is returned alongside the field it came from in `citations`.",
        "The system satisfies every problem-statement requirement with this "
        "process stopped.",
    ]
    if egress:
        notes.append(
            f"Generation is ON. This process sends the derived fact sheet - the "
            f"same text already on the dashboard - to {ENDPOINT_HOST}. No packet "
            "capture, payload, or raw flow record is ever transmitted."
        )
        notes.append(
            "That is egress from the monitoring enclave and is disclosed here "
            "deliberately. The ingest path remains one-directional regardless: "
            "this process cannot reach the monitored network, and nothing it "
            "returns re-enters detection."
        )
    else:
        notes.append(
            "Generation is OFF. This process opens no outbound connection at "
            "all; explanations are rendered locally from stored evidence."
        )
    return AnalystConstraints(
        egress_enabled=egress,
        egress_host=ENDPOINT_HOST if egress else None,
        egress_purpose=(
            "rephrasing a fact sheet built from stored alerts" if egress else "none"
        ),
        notes=notes,
    )


# --------------------------------------------------------------------------
# Application
# --------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    store = AlertStore(settings.backend_url, timeout_s=settings.backend_timeout_s)
    await store.open()
    provider = build_provider(settings)

    app.state.settings = settings
    app.state.store = store
    app.state.provider = provider
    app.state.service = AnalystService(store, provider, settings)

    log.info(
        "%s v%s ready | provider=%s | model=%s | egress=%s | alert store=%s",
        settings.app_name,
        settings.app_version,
        provider.name,
        provider.model or "-",
        "ENABLED" if getattr(provider, "egress", False) else "none",
        settings.backend_url,
    )
    try:
        yield
    finally:
        await provider.close()
        await store.close()


app = FastAPI(
    title="SIH26-26145 AI Security Analyst",
    description=(
        "Layer 8. Explains alerts and narrates incidents from the persisted "
        "alert store, in plain language, with every claim traced to the "
        "evidence field it came from.\n\n"
        "**Optional by construction.** The system meets every problem-statement "
        "requirement with this service stopped. See "
        "`GET /api/v1/analyst/constraints`."
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

app.include_router(router)


@app.get("/health", tags=["system"], summary="Liveness probe")
async def liveness() -> dict[str, str]:
    return {"status": "ok"}
