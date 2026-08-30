"""Turning stored alerts into a cited fact sheet.

This module is the reason the analyst layer is defensible, and it contains no
model call of any kind. It reduces an alert or an incident to a list of
:class:`Fact` objects, each carrying the exact stored field it came from. The
language model - when one is used at all - is handed *only* this list and asked
to rephrase it. It is never handed the raw alert, never asked to infer, and
never in a position to introduce a claim that has no field behind it.

That inverts the usual failure mode. A generated paragraph that mentions a
number the fact sheet does not contain is not a hallucination we have to detect
after the fact; it is a sentence :func:`unsupported_numbers` rejects, because
every figure the analyst is allowed to say is enumerable in advance.

The Layered Build Plan (layer 8) puts it plainly: "Every generated statement
traces back to specific evidence fields. An analyst layer that speculates
beyond its evidence is worse than no analyst layer."
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "Fact",
    "FactSheet",
    "describe_alert",
    "describe_incident",
    "describe_corpus",
    "render_plain",
    "unsupported_numbers",
]


# --------------------------------------------------------------------------
# Fact model
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Fact:
    """One atomic, attributable statement.

    ``source`` names the stored field this came from, in a form the dashboard
    can render as an inline reference beside the sentence (Frontend spec 6.5:
    "Every claim in the generated text renders with the evidence field it came
    from as a small inline reference").
    """

    text: str
    source: str
    value: Any = None
    #: Ordering hint, lower first. Mirrors ``EvidenceItem.rank`` so the most
    #: decisive evidence leads the explanation exactly as it leads the bars.
    rank: int = 100


@dataclass(slots=True)
class FactSheet:
    subject: str
    kind: str  # "alert" | "incident" | "corpus"
    facts: list[Fact] = field(default_factory=list)
    #: Alert ids this sheet was built from, for the citation footer.
    alert_ids: list[str] = field(default_factory=list)
    #: Set when retrieval found nothing. Generation is refused in that case.
    empty_reason: str | None = None

    def add(self, text: str, source: str, value: Any = None, rank: int = 100) -> None:
        self.facts.append(Fact(text=text, source=source, value=value, rank=rank))

    @property
    def ordered(self) -> list[Fact]:
        return sorted(self.facts, key=lambda f: (f.rank, f.source))

    @property
    def is_empty(self) -> bool:
        return not self.facts

    def numbers(self) -> set[str]:
        """Every numeric token that appears anywhere in the sheet."""
        found: set[str] = set()
        for fact in self.facts:
            found.update(_NUMBER_RE.findall(fact.text))
            if isinstance(fact.value, bool):
                continue
            if isinstance(fact.value, (int, float)):
                found.update(_NUMBER_RE.findall(_fmt(fact.value)))
        return found


# --------------------------------------------------------------------------
# Formatting helpers
# --------------------------------------------------------------------------

_NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")


def _fmt(value: Any) -> str:
    """Render a value the way the dashboard renders it.

    Floats are trimmed rather than printed at full precision: an explanation
    that says "0.9100000000000001" reads as a bug even when the number is right.
    """
    if value is None:
        return "not reported"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        if not math.isfinite(value):
            return "not reported"
        if value == int(value) and abs(value) < 1e15:
            return str(int(value))
        return f"{value:.4g}"
    if isinstance(value, (list, tuple)):
        items = [_fmt(v) for v in list(value)[:5]]
        suffix = f" (+{len(value) - 5} more)" if len(value) > 5 else ""
        return ", ".join(items) + suffix
    return str(value)


def _iso(epoch: Any) -> str:
    if isinstance(epoch, bool) or not isinstance(epoch, (int, float)):
        return "an unreported time"
    if not math.isfinite(float(epoch)):
        return "an unreported time"
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _endpoint(alert: dict[str, Any]) -> str:
    """A human label for the alert's endpoints.

    Null is a truthful value in this contract - an aggregate alert genuinely has
    no single destination. The integration guide is explicit that the stored
    null must never be mutated into a placeholder, and that a friendly label is
    a presentation-time decision. This is presentation time.
    """
    src = alert.get("src_ip") or "an unreported source"
    dst = alert.get("dst_ip")
    port = alert.get("dst_port")
    proto = alert.get("protocol")

    if dst is None:
        tail = "multiple destinations"
    elif port is not None:
        tail = f"{dst}:{port}"
    else:
        tail = str(dst)
    if proto:
        tail = f"{tail} over {proto}"
    return f"{src} to {tail}"


_SCORE_WORDING = {
    "calibrated_model": "a calibrated model score",
    "rule_score": "a rule score, which is deterministic rule strength and not a probability",
    "anomaly_score": "an anomaly score, which is normalised deviation and not a probability",
    "signature_match": "a signature match against a locally configured fingerprint list",
}

_SCOPE_WORDING = {
    "flow": "a single flow",
    "source_host": "one source host across many flows",
    "destination_host": "one destination host across many flows",
    "host_pair": "one source-destination relationship across many flows",
    "network": "network-wide behaviour",
}


# --------------------------------------------------------------------------
# Alert
# --------------------------------------------------------------------------


def describe_alert(alert: dict[str, Any]) -> FactSheet:
    """Reduce one projected alert to attributable facts."""
    alert_id = str(alert.get("alert_id", "unknown"))
    sheet = FactSheet(subject=f"alert {alert_id}", kind="alert", alert_ids=[alert_id])

    label = alert.get("threat_label") or str(alert.get("threat_class", "unknown")).replace("_", " ")
    severity = alert.get("severity", "unknown")
    sheet.add(
        f"The detection layer classified this as {label}, at {severity} severity.",
        source="threat_class, severity",
        value=alert.get("threat_class"),
        rank=0,
    )

    score = alert.get("score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        wording = _SCORE_WORDING.get(str(alert.get("score_type", "")), "a detector score")
        sheet.add(
            f"Its threat score is {_fmt(score)} on a 0-1 scale, which is {wording}.",
            source="score, score_type",
            value=score,
            rank=1,
        )

    scope = _SCOPE_WORDING.get(str(alert.get("event_scope")))
    if scope:
        sheet.add(
            f"The alert describes {scope}, not necessarily one connection.",
            source="event_scope",
            value=alert.get("event_scope"),
            rank=2,
        )

    sheet.add(
        f"The activity ran from {_iso(alert.get('event_start'))} to "
        f"{_iso(alert.get('event_end'))} and was detected at "
        f"{_iso(alert.get('detected_at'))}.",
        source="event_start, event_end, detected_at",
        rank=3,
    )
    sheet.add(
        f"The endpoints involved are {_endpoint(alert)}.",
        source="src_ip, dst_ip, dst_port, protocol",
        rank=4,
    )

    occurrences = alert.get("occurrences")
    if isinstance(occurrences, int) and not isinstance(occurrences, bool) and occurrences > 1:
        sheet.add(
            f"This finding repeated {occurrences} times and has been folded into one alert; "
            f"it was first seen at {_iso(alert.get('first_seen'))}.",
            source="occurrences, first_seen",
            value=occurrences,
            rank=5,
        )

    # --- the evidence bars, which are the actual argument -----------------
    for index, item in enumerate(alert.get("evidence") or []):
        if not isinstance(item, dict):
            continue
        name = item.get("label") or item.get("feature") or "an unnamed feature"
        unit = item.get("unit")
        rendered = f"{_fmt(item.get('value'))} {unit}" if unit else _fmt(item.get("value"))
        threshold = item.get("threshold")
        if isinstance(threshold, (int, float)) and not isinstance(threshold, bool):
            direction = "above" if item.get("direction") == "above" else "below"
            crossed = "which crossed" if item.get("exceeded") else "which did not cross"
            sentence = (
                f"{name} was {rendered}, {crossed} the detector threshold of "
                f"{_fmt(threshold)} ({direction})."
            )
        else:
            sentence = f"{name} was {rendered}."
        raw_rank = item.get("rank", 100)
        rank_hint = raw_rank if isinstance(raw_rank, int) and not isinstance(raw_rank, bool) else 100
        sheet.add(
            sentence,
            source=f"evidence.{item.get('feature', f'item_{index}')}",
            value=item.get("value"),
            rank=10 + rank_hint // 10,
        )

    techniques = alert.get("mitre_techniques") or []
    if techniques:
        sheet.add(
            "The detector mapped this to MITRE ATT&CK technique(s) "
            + ", ".join(str(t) for t in techniques)
            + ".",
            source="mitre_techniques",
            value=list(techniques),
            rank=60,
        )

    detector = alert.get("detector")
    if detector:
        sheet.add(
            f"The finding came from the {detector} detector, version "
            f"{alert.get('detector_version', 'unreported')}.",
            source="detector, detector_version",
            rank=70,
        )

    if alert.get("incident_id"):
        sheet.add(
            f"It belongs to incident {alert['incident_id']}, at the "
            f"{alert.get('kill_chain_stage', 'unclassified')} stage of the kill chain.",
            source="incident_id, kill_chain_stage",
            rank=80,
        )

    if sheet.is_empty:
        sheet.empty_reason = "the alert carried no readable fields"
    return sheet


# --------------------------------------------------------------------------
# Incident
# --------------------------------------------------------------------------

_STAGE_ORDER = (
    "reconnaissance",
    "delivery",
    "command_and_control",
    "collection",
    "exfiltration",
)


def describe_incident(
    incident: dict[str, Any], alerts: list[dict[str, Any]] | None = None
) -> FactSheet:
    """Reduce a correlated incident to an ordered, attributable narrative."""
    incident_id = str(incident.get("incident_id", "unknown"))
    members = [m for m in (incident.get("members") or []) if isinstance(m, dict)]
    ids = [str(m["alert_id"]) for m in members if m.get("alert_id")]
    sheet = FactSheet(subject=f"incident {incident_id}", kind="incident", alert_ids=ids)

    host = incident.get("pivot_host", "an unreported host")
    count = incident.get("alert_count", len(members))
    sheet.add(
        f"Incident {incident_id} groups {count} alert(s) that all touch host {host}.",
        source="incident_id, pivot_host, alert_count",
        value=count,
        rank=0,
    )
    sheet.add(
        f"It opened at {_iso(incident.get('opened_at'))} and spans "
        f"{_fmt(incident.get('elapsed_sec'))} seconds.",
        source="opened_at, elapsed_sec",
        rank=1,
    )
    sheet.add(
        f"Its severity is {incident.get('severity', 'unknown')} with a highest member "
        f"threat score of {_fmt(incident.get('confidence'))}.",
        source="severity, confidence",
        rank=2,
    )

    stages = list(incident.get("stages") or [])
    if stages:
        ordered = sorted(
            stages, key=lambda s: _STAGE_ORDER.index(s) if s in _STAGE_ORDER else 99
        )
        sheet.add(
            "The alerts span these kill-chain stages, in order: " + ", ".join(ordered) + ".",
            source="stages",
            value=ordered,
            rank=3,
        )
    if incident.get("escalated"):
        sheet.add(
            "The incident severity was escalated above any single member alert because the "
            "sequence spans more than one kill-chain stage, and the sequence is itself evidence.",
            source="escalated",
            value=True,
            rank=4,
        )

    for position, member in enumerate(members):
        repeats = member.get("occurrences")
        repeat_clause = (
            f", repeated {repeats} times"
            if isinstance(repeats, int) and not isinstance(repeats, bool) and repeats > 1
            else ""
        )
        sheet.add(
            f"Step {position + 1}: at {_iso(member.get('ts'))} the "
            f"{str(member.get('threat_class', 'unknown')).replace('_', ' ')} detector reported a "
            f"{member.get('severity', 'unknown')}-severity finding with threat score "
            f"{_fmt(member.get('confidence'))}{repeat_clause}.",
            source=f"members[{position}].alert_id={member.get('alert_id')}",
            rank=20 + position,
        )

    stored = incident.get("narrative")
    if stored:
        sheet.add(
            f"The correlation layer's own summary reads: {stored}",
            source="narrative",
            rank=90,
        )

    # Member evidence, capped - the incident view is a narrative, not a log.
    for alert in (alerts or [])[:5]:
        if not isinstance(alert, dict):
            continue
        top = [
            e
            for e in (alert.get("evidence") or [])
            if isinstance(e, dict) and e.get("exceeded")
        ][:2]
        for item in top:
            sheet.add(
                f"In the {str(alert.get('threat_class', 'unknown')).replace('_', ' ')} finding, "
                f"{item.get('label') or item.get('feature')} was {_fmt(item.get('value'))} "
                f"against a threshold of {_fmt(item.get('threshold'))}.",
                source=f"alert {alert.get('alert_id')} evidence.{item.get('feature')}",
                value=item.get("value"),
                rank=50,
            )

    if not members:
        sheet.empty_reason = "the incident has no member alerts"
    return sheet


# --------------------------------------------------------------------------
# Corpus (a natural-language question over history)
# --------------------------------------------------------------------------


def describe_corpus(
    question: str, alerts: list[dict[str, Any]], window: str | None = None
) -> FactSheet:
    """Reduce a set of retrieved alerts to facts that answer a question."""
    ids = [str(a.get("alert_id")) for a in alerts if a.get("alert_id")]
    sheet = FactSheet(
        subject=question.strip() or "the alert history", kind="corpus", alert_ids=ids
    )

    if not alerts:
        sheet.empty_reason = "no stored alert matched that query" + (
            f" within {window}" if window else ""
        )
        return sheet

    sheet.add(
        f"{len(alerts)} stored alert(s) match this query"
        + (f", {window}" if window else "")
        + ".",
        source="GET /api/v1/alerts",
        value=len(alerts),
        rank=0,
    )

    by_class: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    hosts: dict[str, int] = {}
    for alert in alerts:
        key = str(alert.get("threat_class"))
        by_class[key] = by_class.get(key, 0) + 1
        sev = str(alert.get("severity"))
        by_severity[sev] = by_severity.get(sev, 0) + 1
        for field_name in ("src_ip", "dst_ip"):
            ip = alert.get(field_name)
            if ip:
                hosts[str(ip)] = hosts.get(str(ip), 0) + 1

    sheet.add(
        "By threat class: "
        + ", ".join(
            f"{name.replace('_', ' ')} {n}"
            for name, n in sorted(by_class.items(), key=lambda kv: -kv[1])
        )
        + ".",
        source="threat_class",
        rank=1,
    )
    sheet.add(
        "By severity: "
        + ", ".join(
            f"{name} {n}" for name, n in sorted(by_severity.items(), key=lambda kv: -kv[1])
        )
        + ".",
        source="severity",
        rank=2,
    )
    if hosts:
        top = sorted(hosts.items(), key=lambda kv: -kv[1])[:5]
        sheet.add(
            "Most frequently involved hosts: "
            + ", ".join(f"{ip} ({n} alert(s))" for ip, n in top)
            + ".",
            source="src_ip, dst_ip",
            rank=3,
        )

    times = [
        a["ts"]
        for a in alerts
        if isinstance(a.get("ts"), (int, float)) and not isinstance(a.get("ts"), bool)
    ]
    if times:
        sheet.add(
            f"The matching alerts run from {_iso(min(times))} to {_iso(max(times))}.",
            source="ts",
            rank=4,
        )

    strongest = sorted(
        (
            a
            for a in alerts
            if isinstance(a.get("score"), (int, float)) and not isinstance(a.get("score"), bool)
        ),
        key=lambda a: -float(a["score"]),
    )[:3]
    for position, alert in enumerate(strongest):
        sheet.add(
            "The strongest match is "
            f"{str(alert.get('threat_class', 'unknown')).replace('_', ' ')} on "
            f"{_endpoint(alert)} at threat score {_fmt(alert.get('score'))} "
            f"({alert.get('severity')} severity).",
            source=f"alert {alert.get('alert_id')}",
            value=alert.get("score"),
            rank=10 + position,
        )
    return sheet


# --------------------------------------------------------------------------
# Deterministic rendering and verification
# --------------------------------------------------------------------------


def render_plain(sheet: FactSheet) -> str:
    """The explanation with no model involved.

    This is what the analyst returns when generation is disabled, unconfigured,
    or failing. It is less fluent and exactly as true, which is the correct
    trade for this layer.
    """
    if sheet.is_empty:
        return f"No stored evidence available for {sheet.subject}."
    return " ".join(fact.text for fact in sheet.ordered)


def unsupported_numbers(text: str, sheet: FactSheet) -> list[str]:
    """Numeric tokens in *text* that appear nowhere in the fact sheet.

    A cheap, deterministic check for the one failure mode that matters here: a
    generated sentence quoting a figure nothing measured. It is deliberately
    conservative - it flags rather than edits, and the caller decides whether to
    fall back to :func:`render_plain`. Values at or below ten are ignored,
    because ordinals and small counts ("the first finding", "3 stages") are
    legitimate prose that the sheet does not literally contain.
    """
    allowed = sheet.numbers()
    suspicious: list[str] = []
    for token in _NUMBER_RE.findall(text):
        if token in allowed:
            continue
        value = float(token)
        if value <= 10 and value == int(value):
            continue  # ordinal or small count in prose
        suspicious.append(token)
    return suspicious
