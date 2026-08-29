"""DGA detector - Phase 2: the Phase-1 model, wired to live flows.

Phase 1 (``detection_core.ml.dga``) is the offline half: lexical features, a
dataset loader, a RandomForest and a training entry point. This module is the
online half and deliberately nothing more - it takes a queried domain off a
:class:`~detection_core.schemas.FlowEvent`, hands it to a fitted
:class:`~detection_core.ml.dga.DGAModel`, and turns a strong verdict into a
``ThreatAlert``.

Findings are correlated by source
--------------------------------
A single infected host walks through a generated list until something
resolves, so a per-domain alert means one alert per name tried - twenty
alerts describing one event. Classification stays per domain, but reporting
is per source: an eligible positive domain is folded into that source's
recent picture and the source emits at most one ``source_host`` alert per
``cooldown_seconds``. The domain-level cooldown is untouched and still runs
underneath, so a name queried in a loop contributes once.

Nothing about *what counts as DGA* changed. The model, its features and the
0.75 decision threshold are exactly as they were; only the scope and count
of the alerts describing those decisions are.

**No DGA feature logic lives here.** Normalization and feature extraction are
imported from Phase 1 and called, never reimplemented - a second copy of that
arithmetic would drift from whatever the model was trained on and quietly
invalidate every score.

Requires a raw query name
-------------------------
This detector reads ``flow.dns.query``. Current ingestion does **not** emit
it (see SCHEMA.md "Integration TODOs"), so against today's feed this detector
is correctly silent: no query, nothing to classify. The adapter already
preserves ``query`` / ``qtype`` / ``rcode`` when they appear, so the day
ingestion starts emitting them this works with no further change here.

The derived ``dns.query_entropy`` / ``query_length`` features that *are*
available today are deliberately not used as a substitute: the model was
trained on 20-odd lexical features extracted from the full name, and feeding
it two of them would not be the same model.

Importing this module is cheap; **constructing** a detector is not
-------------------------------------------------------------------
``detection_core.ml`` pulls in scikit-learn, joblib and numpy, which the
project keeps as the optional ``ml`` extra so that ``import detection_core``
works with pydantic alone. So the Phase-1 import happens inside
:meth:`DGADetector.__init__`, not at module scope. Registering every other
detector stays dependency-free; building *this* one needs the extra.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ..engine import Detector
from ..schemas import (
    MITRE_BY_CLASS,
    EventScope,
    FlowEvent,
    ScoreType,
    Severity,
    ThreatAlert,
    ThreatClass,
    epoch_to_utc,
)
from .scoring import normalize_score, severity_for

__all__ = ["DGAConfig", "DGADetector", "DomainClassifier"]

#: How many domain names one alert carries. Evidence is read by a human and
#: shipped over the wire, so it is a bounded sample - never the full set.
#: ``distinct_dga_domain_count`` reports the real total.
MAX_SAMPLE_DOMAINS = 10


@runtime_checkable
class DomainClassifier(Protocol):
    """What this detector needs from a model.

    :class:`~detection_core.ml.dga.DGAModel` satisfies this. Typing it as a
    protocol rather than the concrete class keeps the detector testable
    without a fitted RandomForest, and leaves room for a future calibrated
    model to be dropped in unchanged.
    """

    def predict_domain(self, domain: str) -> Any:  # -> DGAPrediction
        ...


@dataclass(frozen=True)
class DGAConfig:
    """Settings for :class:`DGADetector`. Deliberately small.

    Classification is per queried domain, so there is no window to size and
    no ratio to tune - the only real decisions are where to cut the model
    score and how often to repeat yourself.
    """

    #: Model score at or above which a domain is reported.
    #:
    #: **Untuned.** 0.75 is a conservative starting point for an uncalibrated
    #: RandomForest vote fraction, chosen so a domain has to look clearly
    #: generated rather than merely unusual. It must be re-derived from a
    #: precision/recall sweep over a real benign+DGA dataset - the Phase-1
    #: training entry point already reports the numbers needed to do that.
    score_threshold: float = 0.75

    #: After reporting a ``(src_ip, domain)`` pair, stay quiet about it this
    #: long. Malware re-queries the same name constantly; the finding is the
    #: domain, not each individual lookup.
    #:
    #: The same figure governs source-level correlation, deliberately: it is
    #: how long a positive domain stays part of a source's recent picture,
    #: and how long the source stays quiet after reporting. Reusing it avoids
    #: inventing a second timing constant nobody has validated - "how often
    #: to repeat yourself" is one question, asked at two scopes.
    cooldown_seconds: float = 300.0

    def __post_init__(self) -> None:
        # 0.0 would alert on every domain the model scores at all, which is
        # every domain. 1.0 is allowed but only fires on total certainty.
        if not 0.0 < self.score_threshold <= 1.0:
            raise ValueError("score_threshold must be within (0.0, 1.0]")
        if self.cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")


@dataclass(frozen=True)
class _DomainFinding:
    """One eligible positive domain, as this detector saw it."""

    timestamp: float
    domain: str
    normalized: str
    model_score: float
    score: float
    dst_ip: str
    dst_port: int | None
    proto: str | None


@dataclass
class _SourceCorrelation:
    """One source's recent DGA-positive domains, and when it last reported.

    Keyed by normalized domain, so a name queried a hundred times is one
    entry - the distinct count is the finding, not the query volume. Entries
    are dropped on event time, so this holds a rolling picture rather than a
    growing history.
    """

    findings: dict[str, _DomainFinding] = field(default_factory=dict)
    last_emitted_at: float | None = None

    def record(self, finding: _DomainFinding) -> None:
        self.findings[finding.normalized] = finding

    def expire(self, cutoff: float) -> None:
        """Drop findings at or before ``cutoff`` - the window's own rule."""
        for normalized, finding in list(self.findings.items()):
            if finding.timestamp <= cutoff:
                del self.findings[normalized]

    def is_idle(self, cutoff: float) -> bool:
        """Nothing recent to correlate and no emission left to suppress."""
        return not self.findings and (
            self.last_emitted_at is None or self.last_emitted_at <= cutoff
        )


class DGADetector(Detector):
    """Reports domains a fitted Phase-1 model scores as generated.

    Construct with a model instance, or with a path to a saved bundle::

        DGADetector(model=fitted_model)
        DGADetector(model_path="artifacts/dga.joblib")

    One of the two is required. There is deliberately no fallback to an
    untrained or stub model: a detector that silently scores everything 0.0
    looks healthy in a dashboard while detecting nothing.
    """

    name = "dga_domain"
    version = "0.1.0"

    def __init__(
        self,
        model: DomainClassifier | None = None,
        *,
        model_path: str | Path | None = None,
        config: DGAConfig | None = None,
    ) -> None:
        if (model is None) == (model_path is None):
            raise ValueError(
                "provide exactly one of model= or model_path= "
                "(a DGADetector cannot run without a fitted model)"
            )

        # Phase-1 import deferred to here: see the module docstring.
        from ..ml.dga import normalize_domain

        self._normalize_domain = normalize_domain
        self.config = config or DGAConfig()
        self.model = model if model is not None else self._load_model(model_path)
        self._verify_usable()

        self._last_alert_at: dict[tuple[str, str], float] = {}
        self._sources: dict[str, _SourceCorrelation] = {}
        self._since_sweep = 0

    # --- construction helpers -------------------------------------------

    @staticmethod
    def _load_model(model_path: str | Path) -> DomainClassifier:
        """Load a saved bundle, failing loudly and specifically.

        ``DGAModel.load`` already rejects a non-bundle, a stale
        ``format_version`` and a feature-schema mismatch with messages that
        name the problem. The only gap it leaves is a path that is not there
        at all, where joblib's own error is less direct - so that one is
        checked first.
        """
        from ..ml.dga import DGAModel

        path = Path(model_path)
        if not path.is_file():
            raise FileNotFoundError(
                f"DGA model not found at {path}. Train one with "
                "detection_core.ml.dga.train_dga and save it, or pass an "
                "already-loaded model="
            )
        return DGAModel.load(path)

    def _verify_usable(self) -> None:
        """Refuse a model that cannot actually classify anything."""
        if not hasattr(self.model, "predict_domain"):
            raise TypeError(
                f"model must expose predict_domain(); got "
                f"{type(self.model).__name__}"
            )
        # DGAModel exposes this; a duck-typed stand-in need not.
        if getattr(self.model, "is_fitted", True) is False:
            raise RuntimeError(
                "model is not fitted; fit() or load() it before detecting"
            )

    # --- detection ------------------------------------------------------

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        """Classify this flow's queried domain, if it has one."""
        domain = self._queried_domain(flow)
        if domain is None:
            return []

        normalized = self._normalize(domain)
        if normalized is None:
            return []

        self._sweep(flow.timestamp)

        prediction = self.model.predict_domain(normalized)
        model_score = float(getattr(prediction, "dga_score", 0.0))
        if model_score < self.config.score_threshold:
            return []

        key = (flow.src_ip, normalized)
        if not self._should_emit(key, flow.timestamp):
            return []
        # The domain has contributed. Stamped whether or not the source goes
        # on to report, so a name queried in a loop is counted once either
        # way - this is the existing per-domain cooldown, unchanged.
        self._last_alert_at[key] = flow.timestamp

        score = self._threat_score(model_score)
        correlation = self._correlate(
            flow=flow,
            domain=domain,
            normalized=normalized,
            model_score=model_score,
            score=score,
        )
        if not self._source_may_emit(correlation, flow.timestamp):
            # Folded into the source's picture; the alert that already went
            # out for this source still describes it. The next one, once the
            # source cooldown lapses, carries the accumulated count.
            return []

        alert = self._build_alert(
            flow=flow,
            correlation=correlation,
            domain=domain,
            normalized=normalized,
            prediction=prediction,
            model_score=model_score,
            score=score,
            severity=severity_for(score),
        )
        correlation.last_emitted_at = flow.timestamp
        return [alert]

    def flush(self) -> list[ThreatAlert]:
        """Nothing is held back - ``process()`` decides per domain."""
        return []

    def reset(self) -> None:
        """Drop all cooldown and correlation state."""
        self._last_alert_at.clear()
        self._sources.clear()
        self._since_sweep = 0

    # --- input handling -------------------------------------------------

    @staticmethod
    def _queried_domain(flow: FlowEvent) -> str | None:
        """The raw query name, or ``None`` when there is nothing to classify.

        Covers the three ways a flow can carry no domain: not DNS at all, a
        DNS block with no raw ``query`` (which is every record current
        ingestion produces), and a query that is present but blank.
        """
        dns = flow.dns
        if dns is None:
            return None
        query = dns.query
        if not isinstance(query, str) or not query.strip():
            return None
        return query

    def _normalize(self, domain: str) -> str | None:
        """Phase-1 normalization, or ``None`` if the name is unusable.

        ``normalize_domain`` is the contract: it rejects empty names,
        embedded whitespace, URLs and empty labels rather than guessing at a
        repair. A record that violates it is skipped - one malformed query
        must not take down a detector mid-stream - and it is idempotent, so
        handing the result to the model re-normalizes to the same string.
        """
        try:
            return self._normalize_domain(domain)
        except (ValueError, TypeError):
            return None

    # --- scoring --------------------------------------------------------

    def _threat_score(self, model_score: float) -> float:
        """Map an uncalibrated model score onto the project's 0-1 scale.

        The RandomForest's class-1 vote fraction is **not a calibrated
        probability** - Phase 1 says so explicitly - so it is not published
        as one. What *is* deterministic is how far past the configured
        threshold it sits, which is exactly the shape every other detector's
        ``rule_score`` already has: at the threshold this is 0.5, at a
        model score of 1.0 it is 1.0, linear between.

        The raw model score travels in the evidence as ``dga_model_score``,
        so nothing is lost by not publishing it as the headline number.
        """
        span = 1.0 - self.config.score_threshold
        if span <= 0:
            # threshold == 1.0: qualifying already means total confidence.
            return 1.0
        return normalize_score(
            0.5 + 0.5 * (model_score - self.config.score_threshold) / span
        )

    @staticmethod
    def _severity(score: float) -> Severity:
        """Project-standard severity bands - see ``scoring.severity_for``."""
        return severity_for(score)

    # --- source correlation ---------------------------------------------

    def _correlate(
        self,
        *,
        flow: FlowEvent,
        domain: str,
        normalized: str,
        model_score: float,
        score: float,
    ) -> _SourceCorrelation:
        """Fold one eligible positive domain into its source's picture."""
        correlation = self._sources.get(flow.src_ip)
        if correlation is None:
            correlation = self._sources[flow.src_ip] = _SourceCorrelation()
        correlation.expire(flow.timestamp - self.config.cooldown_seconds)
        correlation.record(
            _DomainFinding(
                timestamp=flow.timestamp,
                domain=domain,
                normalized=normalized,
                model_score=model_score,
                score=score,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                proto=flow.proto,
            )
        )
        return correlation

    def _source_may_emit(
        self, correlation: _SourceCorrelation, now: float
    ) -> bool:
        """Whether this source may report again.

        One report per ``cooldown_seconds`` per source. There is no
        severity-escalation escape hatch, matching the per-domain rule
        directly above it and for the same reason: the model is
        deterministic, so more domains is more of the same finding.
        """
        last = correlation.last_emitted_at
        return last is None or (now - last) >= self.config.cooldown_seconds

    @staticmethod
    def _only(values: set) -> object | None:
        """The single member of a set, or None when it is not unambiguous.

        The project-wide convention for aggregate alerts: a finding spanning
        several destinations reports ``dst_ip: None`` rather than picking one
        or inventing a placeholder.
        """
        return next(iter(values)) if len(values) == 1 else None

    # --- cooldown -------------------------------------------------------

    def _should_emit(self, key: tuple[str, str], now: float) -> bool:
        """One finding per ``(src_ip, domain)`` per cooldown.

        There is no severity-escalation escape hatch here, unlike the
        windowed detectors, and that is deliberate: the model is
        deterministic, so the same domain always scores the same. A repeat
        lookup is the same finding, never a worse one.
        """
        last = self._last_alert_at.get(key)
        return last is None or (now - last) >= self.config.cooldown_seconds

    def _sweep(self, now: float, every: int = 500) -> None:
        """Drop cooldown entries that can no longer suppress anything.

        Runs on every classified flow, so a host that queries thousands of
        distinct domains cannot grow this dict without bound - what is
        retained is only what was alerted on inside one cooldown.
        """
        self._since_sweep += 1
        if self._since_sweep < every:
            return
        self._since_sweep = 0
        cutoff = now - self.config.cooldown_seconds
        for key, last in list(self._last_alert_at.items()):
            if last <= cutoff:
                del self._last_alert_at[key]
        # A source with nothing recent and no live emission suppression is
        # just a name taking up room.
        for src_ip, correlation in list(self._sources.items()):
            correlation.expire(cutoff)
            if correlation.is_idle(cutoff):
                del self._sources[src_ip]

    # --- alert ----------------------------------------------------------

    def _build_alert(
        self,
        *,
        flow: FlowEvent,
        correlation: _SourceCorrelation,
        domain: str,
        normalized: str,
        prediction: Any,
        model_score: float,
        score: float,
        severity: Severity,
    ) -> ThreatAlert:
        config = self.config
        findings = list(correlation.findings.values())
        timestamps = [finding.timestamp for finding in findings]
        # A bounded, deterministically ordered sample - not a ranking, and
        # not the whole set. The count below is the real total.
        sample = sorted(correlation.findings)[:MAX_SAMPLE_DOMAINS]

        evidence: dict[str, Any] = {
            # --- the domain that triggered this report --------------------
            "domain": domain,
            "normalized_domain": normalized,
            # The model's own output, unmodified.
            "dga_model_score": model_score,
            "score_threshold": config.score_threshold,
            # Said plainly so nobody downstream reads the model score as a
            # probability. Phase 1 documents predict_scores() the same way.
            "model_score_is_calibrated": False,
            "score_note": (
                "dga_model_score is an uncalibrated RandomForest class-1 vote "
                "fraction, not a probability; the alert score is a rule_score "
                "derived from how far it exceeds score_threshold"
            ),
            # --- what this source has been doing --------------------------
            # Distinct normalized names this source queried inside the
            # aggregation window and which passed the model threshold. A
            # name re-queried in a loop counts once.
            "distinct_dga_domain_count": len(findings),
            "sample_domains": sample,
            "sample_domain_limit": MAX_SAMPLE_DOMAINS,
            "aggregation_window_seconds": config.cooldown_seconds,
        }

        label = getattr(prediction, "label", None)
        if label is not None:
            evidence["model_label"] = int(label)

        # Provenance, when the model carries it. Absent for a stand-in.
        metadata = getattr(self.model, "metadata", None)
        if metadata is not None:
            for field_name, key in (
                ("format_version", "model_format_version"),
                ("model_type", "model_type"),
                ("sklearn_version", "model_sklearn_version"),
                ("trained_at", "model_trained_at"),
            ):
                value = getattr(metadata, field_name, None)
                if value is not None:
                    evidence[key] = value

        # Only when ingestion actually supplied them.
        dns = flow.dns
        if dns is not None:
            if dns.qtype is not None:
                evidence["qtype"] = dns.qtype
            if dns.rcode is not None:
                evidence["rcode"] = dns.rcode

        return ThreatAlert(
            # The span the correlated findings actually cover.
            event_start=epoch_to_utc(min(timestamps)),
            event_end=epoch_to_utc(max(timestamps)),
            # The finding is this host's behaviour across several names, not
            # any single lookup.
            event_scope=EventScope.SOURCE_HOST,
            # No one flow represents a correlated source event, so none is
            # named - the aggregate contract every other detector follows.
            flow_id=None,
            src_ip=flow.src_ip,
            # Only when every correlated finding agrees; otherwise None,
            # never a placeholder.
            dst_ip=self._only({finding.dst_ip for finding in findings}),
            dst_port=self._only(
                {f.dst_port for f in findings if f.dst_port is not None}
            ),
            protocol=self._only({f.proto for f in findings if f.proto is not None}),
            threat_class=ThreatClass.DGA_DOMAIN,
            severity=severity,
            score=score,
            score_type=ScoreType.RULE_SCORE,
            evidence=evidence,
            detector=self.name,
            detector_version=self.version,
            mitre_techniques=list(MITRE_BY_CLASS[ThreatClass.DGA_DOMAIN]),
        )
