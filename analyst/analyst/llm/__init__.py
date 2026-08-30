"""Provider selection."""

from __future__ import annotations

import logging

from ..config import Settings
from .base import Generation, GenerationError, LLMProvider
from .gemini import ENDPOINT_HOST, GeminiProvider
from .template import TemplateProvider

__all__ = [
    "Generation",
    "GenerationError",
    "LLMProvider",
    "GeminiProvider",
    "TemplateProvider",
    "ENDPOINT_HOST",
    "build_provider",
]

logger = logging.getLogger(__name__)


def build_provider(settings: Settings) -> LLMProvider:
    """Pick a provider from configuration.

    A misconfigured key degrades to templates rather than refusing to start.
    The service is optional to the system by design; failing hard here would
    make an optional layer able to stop a demo, which is the opposite of what
    "never on the critical path" means.
    """
    if settings.resolved_provider == "gemini":
        if not settings.gemini_api_key:
            logger.warning(
                "ANALYST_PROVIDER=gemini but no ANALYST_GEMINI_API_KEY is set; "
                "falling back to the template provider"
            )
            return TemplateProvider()
        logger.info(
            "generation enabled via %s, model=%s - this process WILL make "
            "outbound requests to %s",
            "gemini",
            settings.gemini_model,
            ENDPOINT_HOST,
        )
        return GeminiProvider(
            settings.gemini_api_key,
            model=settings.gemini_model,
            base_url=settings.gemini_base_url,
            timeout_s=settings.gemini_timeout_s,
            max_output_tokens=settings.gemini_max_output_tokens,
            temperature=settings.gemini_temperature,
        )

    logger.info("generation disabled; using the local template provider (no egress)")
    return TemplateProvider()
