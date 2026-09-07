"""Service behaviour, with a fake store and fake providers.

The property under test throughout is the one the layer is graded on: an answer
is either grounded in stored evidence or it is refused. Never invented.
"""

from __future__ import annotations

from typing import Any

import pytest

from analyst.config import Settings
from analyst.llm.base import GenerationError
from analyst.service import AnalystService
from tests.test_grounding import ALERT


class FakeStore:
    def __init__(self, alerts: list[dict[str, Any]] | None = None, incident: dict | None = None):
        self._alerts = {a["alert_id"]: a for a in (alerts or [])}
        self._incident = incident
        self.queries: list[dict[str, Any]] = []

    async def get_alert(self, alert_id: str):
        return self._alerts.get(alert_id)

    async def get_incident(self, incident_id: str):
        if self._incident and self._incident.get("incident_id") == incident_id:
            return self._incident
        return None

    async def query_alerts(self, **kwargs):
        self.queries.append(kwargs)
        return list(self._alerts.values())

    async def healthy(self):
        return True


class EchoProvider:
    """Returns a fixed, fully grounded sentence."""

    name = "gemini"
    model = "test-model"
    egress = True

    def __init__(self, text: str):
        self._text = text
        self.calls: list[tuple[str, str]] = []

    async def generate(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        return self._text

    async def close(self):
        return None


class BrokenProvider:
    name = "gemini"
    model = "test-model"
    egress = True

    async def generate(self, system: str, user: str) -> str:
        raise GenerationError("upstream is on fire")

    async def close(self):
        return None


class TemplateOnly:
    name = "template"
    model = None
    egress = False

    async def generate(self, system: str, user: str) -> str:  # pragma: no cover
        raise GenerationError("template provider does not generate text")

    async def close(self):
        return None


def _settings(**kw) -> Settings:
    return Settings(gemini_api_key=None, **kw)


@pytest.mark.asyncio
async def test_missing_alert_is_refused_not_invented():
    service = AnalystService(FakeStore(), EchoProvider("anything"), _settings())
    sheet, generation = await service.explain_alert("does-not-exist")
    assert generation.generated is False
    assert "No answer available" in generation.text
    assert sheet.empty_reason is not None


@pytest.mark.asyncio
async def test_generation_is_never_attempted_without_evidence():
    provider = EchoProvider("a fluent invention")
    service = AnalystService(FakeStore(), provider, _settings())
    await service.explain_alert("missing")
    assert provider.calls == [], "the model must not be called with an empty fact sheet"


@pytest.mark.asyncio
async def test_grounded_generation_is_returned_and_marked_generated():
    grounded = "The host beaconed 42 times with a mean interval of 60.2 seconds."
    service = AnalystService(FakeStore([ALERT]), EchoProvider(grounded), _settings())
    _, generation = await service.explain_alert(ALERT["alert_id"])
    assert generation.generated is True
    assert generation.text == grounded
    assert generation.provider == "gemini"
    assert generation.degraded_reason is None


@pytest.mark.asyncio
async def test_ungrounded_figure_is_rejected_and_falls_back():
    invented = "The host exfiltrated 4.7 gigabytes to an unknown server."
    service = AnalystService(FakeStore([ALERT]), EchoProvider(invented), _settings())
    _, generation = await service.explain_alert(ALERT["alert_id"])
    assert generation.generated is False
    assert "4.7" in (generation.degraded_reason or "")
    assert "4.7" not in generation.text


@pytest.mark.asyncio
async def test_provider_failure_degrades_to_the_template_answer():
    service = AnalystService(FakeStore([ALERT]), BrokenProvider(), _settings())
    _, generation = await service.explain_alert(ALERT["alert_id"])
    assert generation.generated is False
    assert "upstream is on fire" in (generation.degraded_reason or "")
    # The answer still contains the real evidence.
    assert "0.041" in generation.text


@pytest.mark.asyncio
async def test_template_provider_answers_without_any_model():
    service = AnalystService(FakeStore([ALERT]), TemplateOnly(), _settings())
    _, generation = await service.explain_alert(ALERT["alert_id"])
    assert generation.generated is False
    assert generation.provider == "template"
    assert "C2 Beaconing" in generation.text


@pytest.mark.asyncio
async def test_ask_pushes_parsed_filters_into_the_store_query():
    store = FakeStore([ALERT])
    service = AnalystService(store, TemplateOnly(), _settings())
    _, _, query = await service.ask("show me beaconing on 10.4.2.19 in the last 2 hours")
    assert store.queries, "the store should have been queried"
    issued = store.queries[0]
    assert issued["threat_class"] == "c2_beaconing"
    assert issued["host"] == "10.4.2.19"
    assert issued["from_ts"] is not None
    assert query.window_label == "in the last 2 hours"


@pytest.mark.asyncio
async def test_ask_reports_how_it_read_the_question():
    service = AnalystService(FakeStore([ALERT]), TemplateOnly(), _settings())
    sheet, generation, _ = await service.ask("anything at all about port scanning")
    assert any(f.source == "query plan" for f in sheet.facts)
    assert "interpreted as" in generation.text


# --------------------------------------------------------------------------
# Reference knowledge
#
# The chatbot's core case: an operator asks what a threat is. Retrieval alone
# cannot answer that - it is not a fact about any row - and before the knowledge
# base existed the empty result was refused outright, so the most natural
# question anyone types got "no stored alert matched that query".
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threat_question_is_answered_with_no_stored_alerts():
    provider = EchoProvider("DNS tunnelling carries data inside DNS queries.")
    service = AnalystService(FakeStore(), provider, _settings())

    sheet, generation, query = await service.ask("what is dns tunnelling?")

    assert query.threat_class == "dns_tunnelling"
    assert sheet.empty_reason is None, "a definition question must not be refused"
    assert provider.calls, "the model should have been given the knowledge facts"
    assert generation.generated is True


@pytest.mark.asyncio
async def test_knowledge_is_sourced_separately_from_measurement():
    """Both halves of a mixed answer, each traceable to where it came from."""
    service = AnalystService(FakeStore([ALERT]), TemplateOnly(), _settings())

    sheet, _, _ = await service.ask("what is beaconing and have we seen any")

    sources = {f.source for f in sheet.facts}
    assert "knowledge base: c2_beaconing" in sources
    assert "GET /api/v1/alerts" in sources


@pytest.mark.asyncio
async def test_unknown_subject_is_still_refused():
    """The knowledge base must not become a way to answer anything at all."""
    provider = EchoProvider("something confident")
    service = AnalystService(FakeStore(), provider, _settings())

    sheet, generation, _ = await service.ask("what is the wifi password")

    assert sheet.empty_reason is not None
    assert generation.generated is False
    assert provider.calls == []


@pytest.mark.asyncio
async def test_the_question_reaches_the_prompt():
    """`build_user_prompt` has always taken a question and nothing passed one,
    so the model was told to answer a question it was never shown."""
    provider = EchoProvider("an answer")
    service = AnalystService(FakeStore([ALERT]), provider, _settings())

    await service.ask("which hosts are beaconing")

    _, user_prompt = provider.calls[0]
    assert "which hosts are beaconing" in user_prompt
