"""The provider that needs nothing.

It opens no socket, holds no key, and returns the deterministic rendering of the
fact sheet. It exists so the sentence "the system passes every requirement in
the problem statement with the analyst layer switched off" is demonstrable in
thirty seconds rather than argued.

It is also the fallback path: whenever generation is unconfigured, unreachable,
rate-limited, or produces text the verifier rejects, the caller lands here and
the panel still answers the question.
"""

from __future__ import annotations

from .base import GenerationError


class TemplateProvider:
    name = "template"
    model = None
    egress = False

    async def generate(self, system: str, user: str) -> str:
        """Never generates.

        The caller is expected to notice ``egress is False`` and use
        :func:`analyst.grounding.render_plain` directly. Raising here rather
        than echoing the prompt back keeps a wiring mistake loud instead of
        letting a prompt leak into the dashboard as if it were an answer.
        """
        raise GenerationError("template provider does not generate text")

    async def close(self) -> None:  # pragma: no cover - nothing to release
        return None
