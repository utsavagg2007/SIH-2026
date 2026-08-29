"""Correlation: alerts into incidents.

Build Plan layer 5: "Group related alerts on the same host within a time window
into a single incident, and order them into a kill-chain narrative:
reconnaissance, then command and control, then exfiltration.  This is the
highest-value component in the entire build relative to its cost."

A host that gets scanned, then beacons, then uploads a large volume is one
story.  Emitting it as three unrelated alerts throws away the strongest signal
in the system - the *sequence* is itself evidence, which is why an incident
spanning multiple kill-chain stages escalates above the severity of any single
member.

The pivot is a host, not a flow.  Which host depends on scope: for a scan or an
exfiltration the interesting party is the source; for a flood it is the target.
"""

from __future__ import annotations

import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field

from ..schemas.alert_v11 import ThreatAlertV11
from ..schemas.enums import (
    SEVERITY_RANK,
    STAGE_ORDER,
    THREAT_CODE,
    THREAT_LABEL,
    THREAT_STAGE,
    EventScope,
    KillChainStage,
    Severity,
    ThreatClass,
)
from ..schemas.view import IncidentMember, IncidentView

#: Most member nodes an incident view will carry. The stages, severity and
#: alert_count stay exact regardless; only the per-node list is trimmed.
MAX_RIBBON_MEMBERS = 40


def pivot_host(alert: ThreatAlertV11) -> str | None:
    """The host this alert is *about*.

    For reconnaissance and exfiltration the actor is the source.  For a flood
    the source addresses are usually forged and worthless as a key - the victim
    is the stable identity, and correlating on a spoofed source would create one
    junk incident per forged packet.
    """
    if alert.threat_class is ThreatClass.DDOS:
        return alert.dst_ip or alert.src_ip
    if alert.event_scope is EventScope.DESTINATION_HOST:
        return alert.dst_ip
    return alert.src_ip or alert.dst_ip


@dataclass(slots=True)
class _Member:
    alert_id: str
    ts: float
    threat_class: ThreatClass
    severity: Severity
    score: float
    stage: KillChainStage
    occurrences: int = 1


@dataclass(slots=True)
class Incident:
    incident_id: str
    pivot_host: str
    opened_at: float
    updated_at: float
    members: dict[str, _Member] = field(default_factory=dict)
    #: Bumped only when the incident *materially* changes - a new member, a
    #: higher severity, or a new kill-chain stage. A deduplicated repeat that
    #: merely raises an occurrence count does not bump it.
    #:
    #: The bus uses this to decide whether to rebuild and broadcast the view.
    #: Without it, a flood against thirty hosts re-sorts and re-serialises
    #: thirty incidents of several hundred members each, once per alert - which
    #: is both the dominant cost on the hot path and a stream of near-identical
    #: frames the dashboard has no use for.
    revision: int = 0

    @property
    def severity(self) -> Severity:
        """Highest member severity, escalated one step when stages compound.

        Escalation is applied by ``IncidentEngine`` rather than here so the
        threshold stays configurable; this property is the un-escalated base.
        """
        if not self.members:
            return Severity.LOW
        return max(
            (m.severity for m in self.members.values()),
            key=lambda s: SEVERITY_RANK[s],
        )

    @property
    def stages(self) -> list[KillChainStage]:
        seen = {m.stage for m in self.members.values()}
        return sorted(seen, key=lambda s: STAGE_ORDER[s])

    @property
    def confidence(self) -> float:
        return max((m.score for m in self.members.values()), default=0.0)


_ESCALATION: dict[Severity, Severity] = {
    Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH,
    Severity.HIGH: Severity.CRITICAL,
    Severity.CRITICAL: Severity.CRITICAL,
}


class IncidentEngine:
    """Maintains open incidents keyed by pivot host.

    Bounded the same way the deduplicator is: time-based expiry first, hard
    ceiling as a backstop.
    """

    def __init__(
        self,
        window_s: float = 1800.0,
        max_incidents: int = 10_000,
        escalate_stages: int = 2,
    ) -> None:
        self._window = window_s
        self._max = max_incidents
        self._escalate_stages = escalate_stages
        #: pivot host -> currently open incident
        self._open: OrderedDict[str, Incident] = OrderedDict()
        #: incident_id -> incident, including recently closed ones so the REST
        #: detail route can still serve them.
        self._by_id: OrderedDict[str, Incident] = OrderedDict()

    def __len__(self) -> int:
        return len(self._by_id)

    def correlate(
        self,
        alert: ThreatAlertV11,
        occurrences: int = 1,
        now: float | None = None,
    ) -> Incident | None:
        """Attach an alert to an incident, opening one if needed.

        Returns None when the alert has no pivot host - a ``network``-scope
        alert with no addresses belongs to no single machine, and inventing a
        pivot for it would produce a meaningless incident.
        """
        now = time.time() if now is None else now
        host = pivot_host(alert)
        if not host:
            return None

        ts = alert.detected_at.timestamp()
        stage = THREAT_STAGE[alert.threat_class]

        incident = self._open.get(host)
        if incident is not None and (ts - incident.updated_at) > self._window:
            # The previous incident on this host has gone quiet.  Close it and
            # start a new one rather than stitching unrelated activity hours
            # apart into a single narrative.
            del self._open[host]
            incident = None

        if incident is None:
            incident = Incident(
                incident_id=f"INC-{uuid.uuid4().hex[:12]}",
                pivot_host=host,
                opened_at=ts,
                updated_at=ts,
            )
            self._open[host] = incident
            self._by_id[incident.incident_id] = incident

        member = incident.members.get(alert.alert_id)
        if member is None:
            incident.members[alert.alert_id] = _Member(
                alert_id=alert.alert_id,
                ts=ts,
                threat_class=alert.threat_class,
                severity=alert.severity,
                score=alert.score,
                stage=stage,
                occurrences=occurrences,
            )
            incident.revision += 1
        else:
            # A deduplicated repeat: update the member in place so the incident
            # reflects the latest state without gaining a node.
            member.occurrences = occurrences
            member.score = max(member.score, alert.score)
            if SEVERITY_RANK[alert.severity] > SEVERITY_RANK[member.severity]:
                member.severity = alert.severity
                incident.revision += 1

        incident.updated_at = max(incident.updated_at, ts)
        self._open.move_to_end(host)
        self._by_id.move_to_end(incident.incident_id)
        self._evict(now)
        return incident

    def peek_revision(self, alert: ThreatAlertV11) -> int | None:
        """Current revision of the incident this alert would join, if any.

        None means no incident is open for that host yet, so correlating will
        open one.
        """
        host = pivot_host(alert)
        if not host:
            return None
        incident = self._open.get(host)
        return incident.revision if incident is not None else None

    def get(self, incident_id: str) -> Incident | None:
        return self._by_id.get(incident_id)

    def list(self, limit: int = 100) -> list[Incident]:
        """Most recently updated first."""
        return sorted(
            self._by_id.values(), key=lambda i: i.updated_at, reverse=True
        )[:limit]

    def for_host(self, ip: str) -> list[Incident]:
        return [i for i in self._by_id.values() if i.pivot_host == ip]

    def effective_severity(self, incident: Incident) -> tuple[Severity, bool]:
        """Severity after kill-chain escalation, and whether it was escalated."""
        base = incident.severity
        if len(incident.stages) >= self._escalate_stages:
            return _ESCALATION[base], True
        return base, False

    def _evict(self, now: float) -> None:
        cutoff = now - self._window
        while self._open:
            host = next(iter(self._open))
            if self._open[host].updated_at >= cutoff:
                break
            del self._open[host]
        while len(self._by_id) > self._max:
            self._by_id.popitem(last=False)

    # ------------------------------------------------------------------
    # view projection
    # ------------------------------------------------------------------

    def to_view(self, incident: Incident) -> IncidentView:
        from datetime import datetime, timezone

        severity, escalated = self.effective_severity(incident)
        total = len(incident.members)
        source = incident.members.values()
        truncated = total > MAX_RIBBON_MEMBERS
        if truncated:
            # A kill-chain ribbon with six hundred nodes is not a narrative, it
            # is a wall - and building it on every update is the dominant cost
            # during a flood, where one victim accumulates member after member.
            # Keep the most recent slice; alert_count still reports the truth.
            source = sorted(incident.members.values(), key=lambda m: m.ts)[
                -MAX_RIBBON_MEMBERS:
            ]
        members = sorted(
            source,
            # Kill-chain order first, then time.  The ribbon is a narrative, and
            # a beacon observed before the scan that found it still belongs
            # after the scan in the telling.
            key=lambda m: (STAGE_ORDER[m.stage], m.ts),
        )
        return IncidentView(
            incident_id=incident.incident_id,
            pivot_host=incident.pivot_host,
            opened_at=incident.opened_at,
            updated_at=incident.updated_at,
            opened_at_iso=datetime.fromtimestamp(
                incident.opened_at, tz=timezone.utc
            ).isoformat().replace("+00:00", "Z"),
            severity=severity,
            confidence=incident.confidence,
            escalated=escalated,
            alert_count=total,
            members_truncated=truncated,
            stages=incident.stages,
            threat_classes=sorted(
                {m.threat_class for m in members}, key=lambda t: t.value
            ),
            members=[
                IncidentMember(
                    alert_id=m.alert_id,
                    ts=m.ts,
                    threat_class=m.threat_class,
                    threat_code=THREAT_CODE[m.threat_class],
                    severity=m.severity,
                    confidence=m.score,
                    stage=m.stage,
                    occurrences=m.occurrences,
                )
                for m in members
            ],
            elapsed_sec=incident.updated_at - incident.opened_at,
            narrative=build_narrative(incident, members, escalated, total),
        )


def build_narrative(
    incident: Incident,
    members: list[_Member],
    escalated: bool,
    total: int | None = None,
) -> str:
    """A one-line factual account of the incident.

    Deliberately templated, not generated.  This string is on the critical path
    for emitting an incident, and the AI analyst layer is explicitly barred from
    that path (Build Plan layer 8).  Every clause here restates a value already
    stored on the incident, so nothing in it can drift from the evidence.
    """
    if not members:
        return f"No activity recorded for {incident.pivot_host}."

    minutes = (incident.updated_at - incident.opened_at) / 60.0

    # Collapse runs of the same threat class into one clause with a count.
    # Spelling out four hundred DDoS findings in sequence produces a sentence
    # nobody reads; "DDoS flood x412" says the same thing.
    steps: list[tuple[str, int]] = []
    for m in members:
        label = THREAT_LABEL[m.threat_class].lower()
        findings = m.occurrences
        if steps and steps[-1][0] == label:
            steps[-1] = (label, steps[-1][1] + findings)
        else:
            steps.append((label, findings))
    rendered = " then ".join(
        label + (f" (x{n})" if n > 1 else "") for label, n in steps
    )

    span = f"over {minutes:.0f} min" if minutes >= 1 else "within one minute"
    text = f"{incident.pivot_host}: {rendered}, {span}."
    if total is not None and total > len(members):
        text += f" Showing the {len(members)} most recent of {total} alerts."
    if escalated:
        stages = ", ".join(s.value for s in incident.stages)
        text += (
            f" Activity spans {len(incident.stages)} kill-chain stages "
            f"({stages}); severity raised on the sequence."
        )
    return text
