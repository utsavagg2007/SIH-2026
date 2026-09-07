"""The analyst service: retrieve, ground, generate, verify.

The order matters and is the whole design:

    retrieve   read-only, from the alert store the dashboard already reads
        |
    ground     reduce to a list of facts, each carrying its source field
        |
    generate   hand ONLY the facts to a model and ask for prose
        |
    verify     reject any generated figure the facts do not contain

Any step after the first can fail without costing an answer, because the
deterministic rendering of the fact sheet is always available. That is what
"never on the critical path" buys: the panel degrades from fluent to plain, and
never from working to broken.
"""

from __future__ import annotations

import logging

from .config import Settings
from .grounding import (
    FactSheet,
    describe_alert,
    describe_corpus,
    describe_incident,
    render_plain,
    unsupported_numbers,
)
from .llm import GenerationError, LLMProvider
from .llm.base import Generation
from .prompts import SYSTEM, build_user_prompt
from .queryplan import QueryPlan, plan
from .retrieval import AlertStore, RetrievalError

logger = logging.getLogger(__name__)


class AnalystService:
    def __init__(self, store: AlertStore, provider: LLMProvider, settings: Settings) -> None:
        self._store = store
        self._provider = provider
        self._settings = settings

    # -- public operations -------------------------------------------------

    async def explain_alert(self, alert_id: str) -> tuple[FactSheet, Generation]:
        alert = await self._store.get_alert(alert_id)
        if alert is None:
            sheet = FactSheet(subject=f"alert {alert_id}", kind="alert")
            sheet.empty_reason = (
                f"no alert {alert_id} is in the store. Alerts reach durable storage "
                "asynchronously, so one emitted moments ago may not be queryable yet."
            )
            return sheet, self._plain(sheet)
        sheet = describe_alert(alert)
        return sheet, await self._render(sheet)

    async def narrate_incident(self, incident_id: str) -> tuple[FactSheet, Generation]:
        incident = await self._store.get_incident(incident_id)
        if incident is None:
            sheet = FactSheet(subject=f"incident {incident_id}", kind="incident")
            sheet.empty_reason = f"no incident {incident_id} is in the store"
            return sheet, self._plain(sheet)

        members = await self._store.query_alerts(
            incident_id=incident_id, limit=self._settings.max_retrieved_alerts
        )
        sheet = describe_incident(incident, members)
        return sheet, await self._render(sheet)

    async def ask(self, question: str, limit: int | None = None) -> tuple[FactSheet, Generation, QueryPlan]:
        query = plan(
            question,
            limit=min(limit or self._settings.max_retrieved_alerts, self._settings.max_retrieved_alerts),
        )
        if query.rejected:
            # Out of scope, or shaped like an attempt to retarget the model.
            # Nothing is retrieved and nothing is generated: the question text
            # never reaches a prompt at all, which is the only injection
            # defence that does not depend on the model cooperating. The
            # subject deliberately does not echo the question back into the
            # panel.
            sheet = FactSheet(subject="an out-of-scope question", kind="corpus")
            sheet.empty_reason = query.rejected
            return sheet, self._plain(sheet), query
        alerts = [] if not query.wants_evidence else await self._store.query_alerts(
            from_ts=query.from_ts,
            to_ts=query.to_ts,
            threat_class=query.threat_class,
            severity=query.severity,
            host=query.host,
            limit=query.limit,
        )
        sheet = describe_corpus(
            question,
            alerts,
            window=query.window_label,
            threat_class=query.threat_class,
            background=query.wants_background,
            evidence=query.wants_evidence,
        )
        # How the question was read belongs in the answer, not in a log. An
        # analyst who asked about one host and got the whole network should be
        # able to see that immediately.
        sheet.add(
            "The question was interpreted as - " + "; ".join(query.understood) + ".",
            source="query plan",
            rank=95,
        )
        return sheet, await self._render(sheet, question=question), query

    # -- rendering ---------------------------------------------------------

    def _plain(self, sheet: FactSheet, reason: str | None = None) -> Generation:
        return Generation(
            text=render_plain(sheet) if not sheet.empty_reason else _refusal(sheet),
            generated=False,
            provider="template",
            model=None,
            degraded_reason=reason,
        )

    async def _render(self, sheet: FactSheet, question: str | None = None) -> Generation:
        """Generate if we can, verify what comes back, fall back if not.

        *question* is the operator's own wording, forwarded to the prompt for
        corpus sheets. ``build_user_prompt`` has always accepted it and nothing
        ever passed it, so the model saw the question only as the sheet's
        subject line and was told to "answer the analyst's question" without
        being shown one - which produced summaries of the retrieved set where a
        direct answer was asked for.
        """
        if sheet.empty_reason or (self._settings.require_evidence and sheet.is_empty):
            # Refusing to generate on an empty sheet is the single most
            # important rule in this layer. A model handed no facts will
            # produce a fluent, plausible, entirely invented paragraph.
            return self._plain(sheet, reason="no stored evidence to ground an answer")

        if not getattr(self._provider, "egress", False) and self._provider.name == "template":
            return self._plain(sheet)

        try:
            text = await self._provider.generate(
                SYSTEM, build_user_prompt(sheet, question)
            )
        except GenerationError as exc:
            logger.warning("generation failed, falling back to templates: %s", exc)
            return self._plain(sheet, reason=str(exc))

        invented = unsupported_numbers(text, sheet)
        if invented:
            # The model quoted a figure nothing measured. Do not show it, do
            # not silently patch it - fall back and say why.
            logger.warning(
                "generated text contained ungrounded figure(s) %s; using the "
                "deterministic rendering instead",
                invented,
            )
            return self._plain(
                sheet,
                reason=(
                    "the generated text quoted "
                    + ", ".join(invented[:5])
                    + ", which no stored evidence field supports"
                ),
            )

        return Generation(
            text=text,
            generated=True,
            provider=self._provider.name,
            model=self._provider.model,
        )

    # -- health ------------------------------------------------------------

    async def store_reachable(self) -> bool:
        try:
            return await self._store.healthy()
        except RetrievalError:
            return False


def _refusal(sheet: FactSheet) -> str:
    """What the panel says when there is nothing to say.

    Frontend spec section 9: state what happened, do not apologise.
    """
    return f"No answer available: {sheet.empty_reason}."
