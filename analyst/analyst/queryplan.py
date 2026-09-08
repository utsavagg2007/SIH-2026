"""Turning an analyst's question into alert-store filters.

Retrieval here is structured, not embedded, and that is a deliberate choice
rather than a shortcut. The corpus is a few hundred thousand rows of *typed*
records with indexed columns for exactly the three things every question is
actually about - when, which host, which threat class. A vector index would add
an embedding model, a backfill job and an approximate answer to a problem that
Postgres answers exactly, and it would make "show me every host that beaconed
in the last hour" - the example question in the build plan - slower and less
correct rather than faster.

So this module parses the question into the filters the backend already
indexes, and the model never sees the corpus at all: it sees the fact sheet
built from whatever these filters returned. The one thing this cannot do is
answer a question phrased entirely in words that are not in the schema, and
:func:`plan` reports that honestly by returning an unfiltered recent-window
query rather than pretending to understand.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

__all__ = ["QueryPlan", "plan"]

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

#: Question vocabulary mapped onto the frozen threat_class enum. Several
#: phrasings per class because an analyst says "beaconing" and "callback" and
#: "c2" for the same thing, and none of them is the enum member.
_CLASS_WORDS: dict[str, tuple[str, ...]] = {
    "c2_beaconing": ("beacon", "beaconing", "c2", "command and control", "callback", "periodic"),
    "port_scan": ("port scan", "portscan", "scanning", "scanned", "recon", "reconnaissance", "sweep", "fan-out", "fanout"),
    "ddos": ("ddos", "flood", "syn flood", "volumetric", "amplification", "reflection", "denial of service"),
    "dga_domain": ("dga", "generated domain", "domain generation", "random domain"),
    "dns_tunnelling": ("dns tunnel", "tunnelling", "tunneling", "exfil over dns", "dns exfil"),
    "encrypted_malware": ("ja3", "ja4", "tls", "encrypted", "fingerprint", "sni"),
    "data_exfiltration": ("exfil", "exfiltration", "data loss", "upload", "outbound volume"),
}

_SEVERITIES = ("critical", "high", "medium", "low")

_UNIT_SECONDS = {
    "second": 1.0,
    "sec": 1.0,
    "minute": 60.0,
    "min": 60.0,
    "hour": 3600.0,
    "hr": 3600.0,
    "day": 86400.0,
    "week": 604800.0,
}

_RELATIVE = re.compile(
    r"\b(?:last|past|previous|within(?:\s+the)?)\s+(\d+)?\s*"
    r"(second|sec|minute|min|hour|hr|day|week)s?\b",
    re.IGNORECASE,
)

#: Phrasings that are not a question about this console but an attempt to
#: retarget the model: the classic instruction-override shapes, plus asking for
#: the prompt itself. Matched before anything else, because an injected string
#: can and will also contain "alert" to get past the vocabulary gate below.
_INJECTION = re.compile(
    r"\b(?:"
    r"ignore\s+(?:all\s+|any\s+|the\s+)*(?:previous|prior|above|earlier|preceding|these|your)"
    r"|disregard\s+(?:all\s+|any\s+|the\s+)*(?:previous|prior|above|earlier|these|your)"
    r"|forget\s+(?:everything|all|your|these|the\s+above)"
    r"|(?:reveal|repeat|print|show|output|display|list|tell\s+me|what\s+are)\s+"
    r"(?:me\s+)?(?:your|the)\s+(?:full\s+|exact\s+|initial\s+|original\s+|system\s+)*"
    r"(?:prompt|instructions|rules|guidelines|system\s+message)"
    r"|system\s+prompt|developer\s+mode|jailbreak"
    r"|new\s+instructions|override\s+(?:your|the|all)"
    r"|you\s+are\s+now|act\s+as\s+(?:a|an|if|though)|pretend\s+(?:to|that|you)"
    r"|role[\s-]?play|do\s+not\s+follow|instead\s+of\s+(?:answering|explaining)"
    r"|answer\s+(?:in|as)\s+(?:the\s+)?(?:character|persona)"
    r")\b",
    re.IGNORECASE,
)

#: Words that make a question about this console at all. Derived from the
#: filter vocabulary above plus the nouns the alert schema uses, so the two
#: cannot drift - a synonym added to _CLASS_WORDS is in scope for free.
_DOMAIN_WORDS: frozenset[str] = (
    frozenset(word for words in _CLASS_WORDS.values() for word in words)
    | frozenset(_SEVERITIES)
    | frozenset(_UNIT_SECONDS)
    | frozenset(
        """
        alert alerts incident incidents host hosts ip ips address addresses
        traffic network networks threat threats severity score scores detect
        detects detected detection detector detectors packet packets flow flows
        port ports protocol protocols dns tls ssl http https domain domains sni
        certificate anomaly anomalies attack attacks attacker malicious
        suspicious compromise compromised infected source destination src dst
        subnet vlan mitre attck technique techniques evidence session sessions
        connection connections bytes throughput fired firing triggered trigger
        console dashboard analyst detected asset endpoint endpoints server
        client mac interval jitter entropy signature behaviour behavior
        """.split()
    )
)

_WORD = re.compile(r"[a-z0-9]+")

#: A question that asks what something *is*, as opposed to what happened. Only
#: these get the knowledge-base entry attached to the fact sheet: "which hosts
#: are beaconing" wants a list of hosts, and handing the model seven paragraphs
#: on what beaconing is invites all seven back as prose.
#: Words that point the question at the alert history rather than at a
#: definition. "What is beaconing" wants the knowledge base and nothing else;
#: "what is beaconing and have we seen any" wants both, and says so with
#: "seen" and "any". Without this split a definition question retrieved the
#: recent alerts too, and the answer arrived with the current threats stapled
#: to it.
_EVIDENCE_WORDS = re.compile(
    r"\b(?:seen|see|any|anything|how\s+many|count|counts|which|who|whose|when|"
    r"where|show|list|happening|happened|going\s+on|current|currently|recent|"
    r"recently|now|today|latest|alert|alerts|incident|incidents|host|hosts|"
    r"we|our|us|fired|firing|triggered|active|open)\b",
    re.IGNORECASE,
)

_BACKGROUND = re.compile(
    r"\b(?:what(?:'s| is| are)|why|how\s+(?:does|do|is)|explain|describe|"
    r"define|definition|meaning|means)\b",
    re.IGNORECASE,
)

_REJECT_INJECTION = (
    "that question asks this panel to change or disclose its own instructions, "
    "which it does not do. Ask about an alert, a host, an incident or a threat "
    "class instead"
)
_REJECT_SCOPE = (
    "that question is outside what this console covers. It answers only about "
    "stored alerts, incidents, hosts and threat classes"
)


@dataclass(slots=True)
class QueryPlan:
    """The filters a question resolved to, and how it was read."""

    from_ts: float | None = None
    to_ts: float | None = None
    threat_class: str | None = None
    severity: str | None = None
    host: str | None = None
    limit: int = 40
    #: Human-readable description of the time window, for the fact sheet.
    window_label: str | None = None
    #: What the parser recognised, so the answer can say how it read the
    #: question rather than silently guessing.
    understood: list[str] = field(default_factory=list)
    #: Whether the question asks what a threat class *is*. Drives whether
    #: reference material is added to the fact sheet at all.
    wants_background: bool = False
    #: Whether the question asks about the alert history at all. False for a
    #: pure definition, which is answered from the knowledge base without
    #: touching the store.
    wants_evidence: bool = True
    #: Set when the question is not one this console answers. Retrieval and
    #: generation are both skipped in that case - the refusal is deterministic
    #: and no untrusted string ever reaches the model.
    rejected: str | None = None

    @property
    def is_unfiltered(self) -> bool:
        return not any((self.threat_class, self.severity, self.host, self.from_ts))


def plan(question: str, *, now: float | None = None, limit: int = 40) -> QueryPlan:
    """Parse *question* into alert-store filters.

    Matching is lowercase substring matching on a fixed vocabulary. That is
    unglamorous and it is the right amount of machinery: the filters are a
    closed set of five, the enum is frozen, and a parser that cannot be
    surprised is one that cannot silently retrieve the wrong window.
    """
    now = time.time() if now is None else now
    text = question.lower()
    result = QueryPlan(limit=limit)

    # --- scope gate -------------------------------------------------------
    # Cheapest possible place to stop a question this layer should not answer,
    # and the only one that stops it *before* the string reaches a prompt.
    if _INJECTION.search(question):
        result.rejected = _REJECT_INJECTION
        result.understood.append("the question was rejected as out of scope")
        return result

    result.wants_background = bool(_BACKGROUND.search(text))
    result.wants_evidence = not result.wants_background or bool(
        _EVIDENCE_WORDS.search(text)
    )

    # --- time window ------------------------------------------------------
    match = _RELATIVE.search(text)
    if match:
        count = int(match.group(1)) if match.group(1) else 1
        seconds = _UNIT_SECONDS[match.group(2).lower()] * count
        result.from_ts = now - seconds
        result.to_ts = now
        unit = match.group(2).lower()
        result.window_label = f"in the last {count} {unit}{'s' if count != 1 else ''}"
        result.understood.append(f"time window: {result.window_label}")
    elif "today" in text:
        result.from_ts = now - 86400.0
        result.to_ts = now
        result.window_label = "in the last 24 hours"
        result.understood.append("time window: the last 24 hours")
    elif "now" in text or "current" in text or "right now" in text:
        result.from_ts = now - 300.0
        result.to_ts = now
        result.window_label = "in the last 5 minutes"
        result.understood.append("time window: the last 5 minutes")

    # --- threat class -----------------------------------------------------
    # Longest phrase wins, so "dns tunnel" is not shadowed by "tunnel".
    best: tuple[int, str] | None = None
    for enum_value, words in _CLASS_WORDS.items():
        for word in words:
            if word in text and (best is None or len(word) > best[0]):
                best = (len(word), enum_value)
    if best is not None:
        result.threat_class = best[1]
        result.understood.append(f"threat class: {best[1]}")

    # --- severity ---------------------------------------------------------
    for severity in _SEVERITIES:
        if re.search(rf"\b{severity}\b", text):
            result.severity = severity
            result.understood.append(f"severity: {severity}")
            break

    # --- host -------------------------------------------------------------
    addresses = _IPV4.findall(question)
    if addresses:
        result.host = addresses[0]
        result.understood.append(f"host: {addresses[0]}")

    if result.host or result.severity or result.from_ts:
        result.wants_evidence = True

    if not result.understood:
        # No filter matched, so the only remaining evidence that this is a
        # question about the network at all is its vocabulary. Nothing from the
        # schema in it means nothing here can answer it.
        if not _DOMAIN_WORDS.intersection(_WORD.findall(text)):
            result.rejected = _REJECT_SCOPE
            result.understood.append("the question was rejected as out of scope")
            return result
        result.understood.append(
            "no filter recognised; searching the most recent alerts"
        )
    return result
