"""Shared rule-score and severity helpers.

Every detector normalizes its rule score the same way and maps it to the
same documented severity bands, so an analyst can compare a 0.8 from one
detector against a 0.8 from another. This module is that single definition;
detectors keep their own threshold logic local.

A rule score is NOT a probability. It says how far past its configured
thresholds an observation sits, normalized to [0.0, 1.0] so the UI can
render every detector's output on one scale.
"""

from __future__ import annotations

from ..schemas import Severity

__all__ = [
    "SCORE_PRECISION",
    "SEVERITY_CUTOFFS",
    "normalize_score",
    "severity_for",
    "severity_rank",
]

# Decimal places a rule score is rounded to before anything compares it.
# Without this, a score that is mathematically exactly 0.9 arrives as
# 0.8999999999999999 (e.g. 17 ports against a threshold of 5) and silently
# lands one severity band too low. Six places is far finer than a rule score
# can meaningfully resolve, so this only removes binary-float noise.
SCORE_PRECISION = 6

# Score -> Severity. Deterministic and documented; the Severity enum itself
# is a frozen part of the v1.1 contract and is not modified here.
SEVERITY_CUTOFFS: tuple[tuple[float, Severity], ...] = (
    (0.90, Severity.CRITICAL),
    (0.75, Severity.HIGH),
    (0.60, Severity.MEDIUM),
)

# Ordering for escalation checks.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


def normalize_score(value: float) -> float:
    """Clamp to [0.0, 1.0] and round, so boundary comparisons are exact."""
    return round(min(max(value, 0.0), 1.0), SCORE_PRECISION)


def severity_for(score: float) -> Severity:
    """Map a rule score to a band: >=0.90 critical, >=0.75 high, >=0.60 medium.

    Normalizes first so a score sitting exactly on a documented boundary
    classifies the same way however the arithmetic that produced it rounded.
    """
    score = normalize_score(score)
    for cutoff, severity in SEVERITY_CUTOFFS:
        if score >= cutoff:
            return severity
    return Severity.LOW


def severity_rank(severity: Severity) -> int:
    """Ordinal position of a severity, for escalation comparisons."""
    return _SEVERITY_RANK[severity]
