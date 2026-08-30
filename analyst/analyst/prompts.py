"""Prompts.

The model is a rewriter, not an investigator. It receives a numbered fact sheet
and is asked to turn it into prose. It is not given the alert, not given the
evidence bag, and not given any tool with which to look something up - so the
set of things it is able to say is bounded by the sheet before the request is
even sent.

The register is set deliberately by the Frontend Design Specification (section
9): "Words in this interface are readouts, not commentary. Keep them in the
register of an instrument: factual, present tense, no hedging, no personality."
An analyst panel that opens with "Great question!" undoes the whole aesthetic.
"""

from __future__ import annotations

from .grounding import FactSheet

SYSTEM = """\
You are the analyst panel of a passive network threat-detection console in a \
monitoring enclave. You explain findings that have already been made. You do \
not make findings.

Absolute rules:
1. Use ONLY the numbered facts supplied. Never add a number, hostname, IP \
address, port, domain, hash, technique id, time or threshold that is not in \
them.
2. If the facts do not answer the question, say exactly what is missing. Never \
fill a gap by inference.
3. Never suggest blocking, quarantining, resetting, rate-limiting or otherwise \
acting on traffic. This system is physically incapable of sending anything \
back toward the monitored network, so an instruction to act is a false \
statement about the product.
4. Call the score a threat score, never a probability or a confidence, unless \
a fact explicitly says it is a calibrated model score.
5. Do not restate a severity as your own judgement. Severity is assigned by \
the detection layer; report it.

Style: factual, present tense, no hedging, no personality, no preamble, no \
closing summary, no bullet lists unless the facts are a sequence of steps. \
Two to five sentences for one alert; up to eight for an incident. Plain text \
only - no markdown headings, no bold.
"""

_TASK = {
    "alert": (
        "Explain in plain language what this alert means and why the detector "
        "fired. Lead with the behaviour, then the evidence that crossed a "
        "threshold."
    ),
    "incident": (
        "Narrate this incident as a short sequence of what appears to have "
        "happened on this host, in kill-chain order. Make clear that the "
        "ordering is the argument."
    ),
    "corpus": (
        "Answer the analyst's question using only these facts. Begin with the "
        "direct answer, then the supporting counts."
    ),
}


def build_user_prompt(sheet: FactSheet, question: str | None = None) -> str:
    """Render the fact sheet into the user turn."""
    lines = [_TASK.get(sheet.kind, _TASK["alert"]), ""]
    if question and sheet.kind == "corpus":
        lines.append(f"Analyst question: {question.strip()}")
        lines.append("")
    lines.append(f"Subject: {sheet.subject}")
    lines.append("")
    lines.append("Facts (the complete set you may use):")
    for index, fact in enumerate(sheet.ordered, start=1):
        lines.append(f"{index}. {fact.text}   [source: {fact.source}]")
    lines.append("")
    lines.append(
        "Write the explanation now. Every claim must correspond to one of the "
        "facts above."
    )
    return "\n".join(lines)
