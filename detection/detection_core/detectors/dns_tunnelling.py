"""DNS tunnelling detector - repeated abnormal DNS queries to one resolver.

Tunnelling encodes payload into the query name itself, so the queries come
out long, high-entropy, deeply labelled, and often TXT. No single query
proves anything - a long random-looking name is also what a CDN, a cloud
storage bucket or an antivirus reputation lookup emits all day. What is
unusual is a host doing it *over and over* to *one resolver*.

So this detector is aggregate-first: it summarizes a rolling window of DNS
observations per ``(src_ip, dst_ip)`` and asks what fraction of them look
abnormal, never whether any one of them does.

State is keyed by :class:`DnsTunnelKey` - ``(src_ip, dst_ip)`` - so two
clients never pool their behaviour and one client's traffic to two different
resolvers stays separate. ``dst_ip`` is normally the DNS resolver.

Near-real-time: the decision happens inside
:meth:`DnsTunnellingDetector.process` and fires the moment the window
qualifies. ``flush()`` is not part of normal detection.

The detector-v2 ingestion profile now carries every DNS transaction and its
raw query/type/result metadata. Detection still uses the established derived
signals—``query_length``, ``query_entropy``, ``subdomain_entropy``,
``label_count`` and ``is_txt``—and reports raw-query availability as evidence.
Nothing here reconstructs a query string, and any field ingestion leaves
``None`` simply contributes no signal rather than being invented.

**This is a heuristic signal, not proof of exfiltration.** An alert means
"this host's DNS to this resolver looks encoded", which is a lead to
investigate. Confirming that data actually left requires packet/content-level
evidence beyond this metadata pipeline.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace

from ..aggregators.extremes import WindowExtreme
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
from .scoring import normalize_score, severity_for, severity_rank

__all__ = [
    "DnsAggregate",
    "DnsObservation",
    "DnsTunnelKey",
    "DnsTunnellingConfig",
    "DnsTunnellingDetector",
]

# The per-observation signals this detector can currently test. Fixed by
# what ingestion actually emits: long query, high query entropy, high
# subdomain entropy, many labels, TXT query. Raising this means adding a
# signal to ``_signal_count``.
MAX_SIGNALS = 5


def _has_raw_query(dns) -> bool:
    """Whether ingestion supplied a real query name on this record.

    A blank or whitespace-only string is not a query name, and neither is a
    non-string. Deliberately the same test :class:`DGADetector` uses to
    decide it has something to classify, so the two DNS detectors can never
    disagree about whether a feed is emitting raw names.
    """
    query = dns.query
    return isinstance(query, str) and bool(query.strip())


@dataclass(frozen=True)
class DnsTunnelKey:
    """One client/resolver pair.

    Frozen, so it hashes. Two pairs differing in either field are different
    keys and never share state: a different client is a different host, and
    a different resolver is a different conversation.
    """

    src_ip: str
    dst_ip: str

    @classmethod
    def from_flow(cls, flow: FlowEvent) -> DnsTunnelKey:
        return cls(src_ip=flow.src_ip, dst_ip=flow.dst_ip)


@dataclass(frozen=True)
class DnsObservation:
    """The slice of a DNS flow this detector needs, and nothing more.

    Deliberately not a ``FlowEvent``: the window may hold thousands of these,
    and retaining whole flows (with their nested TLS/HTTP blocks and ``extra``
    dicts) to read five numbers off them would be pure waste.

    Every DNS field is ``| None`` because ingestion supplies them per record
    and may omit any of them. ``None`` means "not measured" throughout - it
    is never defaulted to 0, which would silently read as "short query" or
    "no entropy".
    """

    timestamp: float
    query_length: int | None = None
    query_entropy: float | None = None
    subdomain_entropy: float | None = None
    label_count: int | None = None
    is_txt: bool | None = None
    #: Context only - reported as evidence, gates nothing.
    orig_bytes: int = 0
    #: The transport this query was seen on. Retained because the alert is
    #: an aggregate over the whole window: it can only report a port or a
    #: protocol honestly if it knows what every contributing observation
    #: used. ``None`` stays "not supplied", never 0 or a placeholder string.
    dst_port: int | None = None
    proto: str | None = None
    #: Whether this record carried a genuine ``dns.query``. The name itself
    #: is deliberately NOT retained: the window may hold thousands of these,
    #: nothing here classifies on the string, and holding payload-bearing
    #: query names in memory would be a liability rather than an asset.
    has_raw_query: bool = False

    @classmethod
    def from_flow(cls, flow: FlowEvent) -> DnsObservation:
        """Build from a flow carrying a ``dns`` block.

        Raises rather than asserting on a non-DNS flow: ``assert`` vanishes
        under ``python -O``, and silently observing a flow with no DNS data
        would pad the window with unmeasurable entries and depress the
        suspicious ratio.
        """
        dns = flow.dns
        if dns is None:
            raise ValueError("flow carries no dns block")
        return cls(
            timestamp=flow.timestamp,
            query_length=dns.query_length,
            query_entropy=dns.query_entropy,
            subdomain_entropy=dns.subdomain_entropy,
            label_count=dns.label_count,
            is_txt=dns.is_txt,
            orig_bytes=flow.orig_bytes,
            dst_port=flow.dst_port,
            proto=flow.proto,
            has_raw_query=_has_raw_query(dns),
        )


@dataclass(frozen=True)
class DnsAggregate:
    """What one pair's window looks like, in numbers.

    Every mean is ``None`` when no observation in the window carried that
    field, so the alert can say "not measured" instead of publishing a zero
    that was never observed.
    """

    observation_count: int
    suspicious_count: int
    suspicious_ratio: float
    #: Mean signals fired per *suspicious* observation - how strongly the
    #: separate indicators agree. ``None`` when nothing is suspicious.
    mean_signals: float | None
    txt_count: int
    #: ``None`` when no observation reported ``is_txt`` either way.
    txt_ratio: float | None
    mean_query_length: float | None
    max_query_length: int | None
    mean_query_entropy: float | None
    max_query_entropy: float | None
    mean_subdomain_entropy: float | None
    mean_label_count: float | None
    max_label_count: int | None
    total_orig_bytes: int
    time_span: tuple[float, float]
    #: The one destination port every observation that carried one agreed
    #: on, or ``None`` when the window is mixed or none reported a port.
    dst_port: int | None = None
    #: The same, for transport protocol.
    protocol: str | None = None
    #: Observations in this window that carried a real ``dns.query``.
    raw_query_count: int = 0


@dataclass(frozen=True)
class DnsTunnellingConfig:
    """Thresholds for :class:`DnsTunnellingDetector`. Every value is tunable.

    These defaults are **initial heuristics, not operationally tuned
    values.** They were chosen so that obviously encoded DNS (long
    base32-looking names, deep label stacks, TXT-heavy) fires while ordinary
    browsing - which does include long CDN and cloud-storage names - does
    not. They MUST be re-derived against captures of this network's normal
    DNS *and* real tunnelling traffic (iodine, dnscat2, dns2tcp) before
    anyone trusts them operationally.

    Entropy thresholds are in **bits per character** (base-2 Shannon over the
    query string), matching what ingestion computes. For scale: ordinary
    short domains land around 2.5-3.5, while base32/base64-encoded payload
    labels sit near 4.5-5.0.
    """

    #: Rolling window per pair, in seconds of event time (not wall clock).
    window_seconds: float = 300.0

    #: DNS queries needed on a pair before its behaviour is judged at all.
    #: This is what stops one odd-looking lookup from ever alerting.
    min_dns_observations: int = 20

    #: Query name length at or beyond which the query counts as long.
    #: Ordinary names are well under this; encoded payload pushes past it.
    suspicious_query_length: int = 50

    #: Full-query entropy (bits/char) counting as high.
    suspicious_entropy: float = 4.0

    #: Subdomain-only entropy (bits/char) counting as high. Ingestion
    #: reports 0.0 for names with two labels or fewer, so ordinary
    #: ``example.com`` lookups score nothing here.
    suspicious_subdomain_entropy: float = 3.5

    #: Label count at or beyond which the name counts as deeply nested.
    suspicious_label_count: int = 5

    #: Distinct signals ONE observation must fire before it is called
    #: suspicious. At least 2 by construction: a single metric is never
    #: enough, because each one alone has a benign explanation.
    min_signals_per_observation: int = 2

    #: Fraction of the window's observations that must be suspicious.
    #: Well under 1.0 on purpose - a real tunnel still interleaves ordinary
    #: lookups, so demanding every query look encoded would miss it.
    min_suspicious_ratio: float = 0.5

    #: TXT fraction at or beyond which the pair earns ``txt_bonus``. TXT
    #: carries far more payload than A, so a TXT-heavy pair is a stronger
    #: lead - but TXT alone never qualifies a pair (SPF/DKIM/reputation
    #: lookups are legitimately TXT-heavy), it only sharpens the score.
    suspicious_txt_ratio: float = 0.30

    #: Added to the score when the TXT fraction reaches the line above.
    txt_bonus: float = 0.10

    #: After alerting on a pair, stay quiet this long for it - unless the
    #: severity band rises, which always gets through.
    cooldown_seconds: float = 300.0

    #: Multiple of ``min_dns_observations`` at which volume saturates.
    saturation_multiple: float = 3.0

    #: How the three score components are blended. Must sum to 1.0.
    #: Ratio carries the most: *how much* of the traffic looks encoded is
    #: the actual finding.
    ratio_weight: float = 0.50
    volume_weight: float = 0.25
    agreement_weight: float = 0.25

    #: Hard ceiling on observations retained per pair, so a DNS flood cannot
    #: grow the window without bound between time-based expiries. Oldest are
    #: dropped first; statistics are then over the most recent N, which the
    #: evidence reports honestly as ``observation_count``.
    max_observations_per_key: int = 5000

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        # Two observations cannot establish "repeated aggregate behaviour",
        # which is the entire premise of this detector.
        if self.min_dns_observations < 3:
            raise ValueError("min_dns_observations must be at least 3")
        if self.suspicious_query_length < 1:
            raise ValueError("suspicious_query_length must be at least 1")
        if self.suspicious_entropy < 0:
            raise ValueError("suspicious_entropy must not be negative")
        if self.suspicious_subdomain_entropy < 0:
            raise ValueError("suspicious_subdomain_entropy must not be negative")
        if self.suspicious_label_count < 1:
            raise ValueError("suspicious_label_count must be at least 1")
        if not 2 <= self.min_signals_per_observation <= MAX_SIGNALS:
            raise ValueError(
                f"min_signals_per_observation must be within 2..{MAX_SIGNALS} - "
                "a single metric is never sufficient evidence"
            )
        if not 0.0 < self.min_suspicious_ratio <= 1.0:
            raise ValueError("min_suspicious_ratio must be within (0.0, 1.0]")
        if not 0.0 < self.suspicious_txt_ratio <= 1.0:
            raise ValueError("suspicious_txt_ratio must be within (0.0, 1.0]")
        if not 0.0 <= self.txt_bonus <= 1.0:
            raise ValueError("txt_bonus must be within [0.0, 1.0]")
        if self.cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must not be negative")
        if self.saturation_multiple <= 1:
            raise ValueError("saturation_multiple must be greater than 1")
        for name in ("ratio_weight", "volume_weight", "agreement_weight"):
            if not 0.0 <= getattr(self, name) <= 1.0:
                raise ValueError(f"{name} must be within [0.0, 1.0]")
        total = self.ratio_weight + self.volume_weight + self.agreement_weight
        if abs(total - 1.0) > 1e-9:
            raise ValueError(
                "ratio_weight + volume_weight + agreement_weight must sum to 1.0, "
                f"got {total}"
            )
        if self.max_observations_per_key < self.min_dns_observations:
            raise ValueError(
                "max_observations_per_key must be at least min_dns_observations, "
                "otherwise the window can never reach the threshold"
            )


@dataclass
class _PairState:
    """Per-pair bookkeeping the window itself does not hold."""

    last_alert_at: float | None = None
    last_severity: Severity | None = None


class _DnsWindow:
    """Rolling DNS observations for ONE pair.

    Local to this module on purpose. ``aggregators.ActivityWindow`` holds
    ``FlowObservation`` and exposes port/host/volume views; the DNS slice
    shares none of those fields or questions, and widening the shared
    observation to carry five DNS features would put unused state in every
    other detector's window. The expiry contract is deliberately identical:
    half-open, so an observation exactly ``window_seconds`` old has expired.

    Every statistic the ratio test reads is maintained **incrementally** -
    folded in on arrival, reversed on expiry - so judging a pair costs the
    same whether it holds twenty lookups or four thousand. Rebuilding them
    per flow made a busy resolver pair quadratic, the same defect
    ``ActivityWindow`` was fixed for.

    How many signals an observation fires depends only on that observation
    and the config, both immutable, so it is counted once on arrival and
    carried alongside. Nothing is approximated, capped for speed, or
    dropped: the deque still holds every observation until it expires.
    """

    def __init__(self, window_seconds: float, max_observations: int) -> None:
        self.window_seconds = window_seconds
        self.max_observations = max_observations
        # (observation, signal count) pairs, so the count can never drift
        # out of step with the observation it describes.
        self._events: deque[tuple[DnsObservation, int]] = deque()
        # The suspicious-signal bar, fixed by config for this window's life.
        self._threshold = 0
        self._reset_aggregates()

    def _reset_aggregates(self) -> None:
        self._suspicious_count = 0
        self._suspicious_signal_sum = 0
        self._txt_true = 0
        self._txt_known = 0
        self._length_sum = 0
        self._length_count = 0
        self._entropy_sum = 0.0
        self._entropy_count = 0
        self._sub_entropy_sum = 0.0
        self._sub_entropy_count = 0
        self._label_sum = 0
        self._label_count = 0
        self._orig_bytes_total = 0
        self._raw_query_count = 0
        # Reference counts: the live values, for unanimity and for extremes
        # that subtraction cannot undo.
        self._dst_port_counts: dict[int, int] = {}
        self._proto_counts: dict[str, int] = {}
        # Extremes go through WindowExtreme rather than a cache that is
        # rebuilt when the extreme leaves: at the occupancy cap the oldest
        # observation leaves on every flow, which turns "rebuild rarely"
        # into a full rescan per flow.
        self._max_length = WindowExtreme(largest=True)
        self._max_entropy = WindowExtreme(largest=True)
        self._max_label = WindowExtreme(largest=True)
        self._min_timestamp = WindowExtreme(largest=False)
        self._max_timestamp = WindowExtreme(largest=True)
        # Observations leave in arrival order, so a counter per side names
        # them without the caller carrying an id around.
        self._added = 0
        self._removed = 0

    @staticmethod
    def _increment(counts: dict, key) -> None:
        counts[key] = counts.get(key, 0) + 1

    @staticmethod
    def _decrement(counts: dict, key) -> None:
        remaining = counts[key] - 1
        if remaining:
            counts[key] = remaining
        else:
            del counts[key]

    def _add(self, observation: DnsObservation, signals: int, threshold: int) -> None:
        sequence = self._added
        self._added += 1
        if signals >= threshold:
            self._suspicious_count += 1
            self._suspicious_signal_sum += signals
        if observation.is_txt is not None:
            self._txt_known += 1
            if observation.is_txt:
                self._txt_true += 1
        if observation.query_length is not None:
            self._length_sum += observation.query_length
            self._length_count += 1
            self._max_length.push(sequence, observation.query_length)
        if observation.query_entropy is not None:
            self._entropy_sum += observation.query_entropy
            self._entropy_count += 1
            self._max_entropy.push(sequence, observation.query_entropy)
        if observation.subdomain_entropy is not None:
            self._sub_entropy_sum += observation.subdomain_entropy
            self._sub_entropy_count += 1
        if observation.label_count is not None:
            self._label_sum += observation.label_count
            self._label_count += 1
            self._max_label.push(sequence, observation.label_count)
        self._orig_bytes_total += observation.orig_bytes
        if observation.has_raw_query:
            self._raw_query_count += 1
        if observation.dst_port is not None:
            self._increment(self._dst_port_counts, observation.dst_port)
        if observation.proto is not None:
            self._increment(self._proto_counts, observation.proto)

        # ``None`` here means "cache invalid, recompute on read" - it does
        self._min_timestamp.push(sequence, observation.timestamp)
        self._max_timestamp.push(sequence, observation.timestamp)

    def _remove(self, observation: DnsObservation, signals: int, threshold: int) -> None:
        if signals >= threshold:
            self._suspicious_count -= 1
            self._suspicious_signal_sum -= signals
        if observation.is_txt is not None:
            self._txt_known -= 1
            if observation.is_txt:
                self._txt_true -= 1
        if observation.query_length is not None:
            self._length_sum -= observation.query_length
            self._length_count -= 1
        if observation.query_entropy is not None:
            self._entropy_sum -= observation.query_entropy
            self._entropy_count -= 1
        if observation.subdomain_entropy is not None:
            self._sub_entropy_sum -= observation.subdomain_entropy
            self._sub_entropy_count -= 1
        if observation.label_count is not None:
            self._label_sum -= observation.label_count
            self._label_count -= 1
        self._orig_bytes_total -= observation.orig_bytes
        if observation.has_raw_query:
            self._raw_query_count -= 1
        if observation.dst_port is not None:
            self._decrement(self._dst_port_counts, observation.dst_port)
        if observation.proto is not None:
            self._decrement(self._proto_counts, observation.proto)

        # Departures are FIFO, so this counter names the one leaving.
        sequence = self._removed
        self._removed += 1
        self._max_length.pop(sequence)
        self._max_entropy.pop(sequence)
        self._max_label.pop(sequence)
        self._min_timestamp.pop(sequence)
        self._max_timestamp.pop(sequence)

    def observe(self, observation: DnsObservation, signals: int, threshold: int) -> None:
        # The cap is enforced here rather than by ``deque(maxlen=...)``: a
        # maxlen deque evicts silently, which would leave the aggregates
        # describing an observation the window no longer holds.
        self._threshold = threshold
        if len(self._events) >= self.max_observations:
            self._drop_oldest()
        self._events.append((observation, signals))
        self._add(observation, signals, threshold)
        self.expire(observation.timestamp)

    def _drop_oldest(self) -> None:
        observation, signals = self._events.popleft()
        self._remove(observation, signals, self._threshold)

    def expire(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0].timestamp <= cutoff:
            self._drop_oldest()

    # --- derived views, all O(1) ------------------------------------------

    @property
    def suspicious_count(self) -> int:
        return self._suspicious_count

    def mean_signals(self) -> float | None:
        if not self._suspicious_count:
            return None
        return self._suspicious_signal_sum / self._suspicious_count

    @property
    def txt_count(self) -> int:
        return self._txt_true

    def txt_ratio(self) -> float | None:
        return (self._txt_true / self._txt_known) if self._txt_known else None

    def mean_query_length(self) -> float | None:
        return (self._length_sum / self._length_count) if self._length_count else None

    def max_query_length(self) -> int | None:
        longest = self._max_length.value
        return None if longest is None else int(longest)

    def mean_query_entropy(self) -> float | None:
        return (self._entropy_sum / self._entropy_count) if self._entropy_count else None

    def max_query_entropy(self) -> float | None:
        return self._max_entropy.value

    def mean_subdomain_entropy(self) -> float | None:
        if not self._sub_entropy_count:
            return None
        return self._sub_entropy_sum / self._sub_entropy_count

    # --- exact float means, for evidence --------------------------------
    #
    # A running float sum and a fresh sum of the same values disagree in the
    # last bit: adding then subtracting a float does not restore the total
    # exactly. That is harmless for the running counts - every value the
    # ratio test and the score read is integer arithmetic, so those are bit
    # exact - but these two means are *published as evidence*, and evidence
    # that shifts in its sixteenth digit depending on what expired an hour
    # ago is evidence nobody can reproduce.
    #
    # So they are summed from the resident observations, in order, exactly
    # as the pre-incremental code did. That is O(n), which is why the
    # detector only calls them when it is actually building an alert.

    def exact_mean_query_entropy(self) -> float | None:
        values = [
            observation.query_entropy
            for observation, _signals in self._events
            if observation.query_entropy is not None
        ]
        return (sum(values) / len(values)) if values else None

    def exact_mean_subdomain_entropy(self) -> float | None:
        values = [
            observation.subdomain_entropy
            for observation, _signals in self._events
            if observation.subdomain_entropy is not None
        ]
        return (sum(values) / len(values)) if values else None

    def mean_label_count(self) -> float | None:
        return (self._label_sum / self._label_count) if self._label_count else None

    def max_label_count(self) -> int | None:
        most = self._max_label.value
        return None if most is None else int(most)

    @property
    def total_orig_bytes(self) -> int:
        return self._orig_bytes_total

    @property
    def raw_query_count(self) -> int:
        return self._raw_query_count

    def unanimous_dst_port(self) -> int | None:
        return next(iter(self._dst_port_counts)) if len(self._dst_port_counts) == 1 else None

    def unanimous_proto(self) -> str | None:
        return next(iter(self._proto_counts)) if len(self._proto_counts) == 1 else None

    def time_span(self) -> tuple[float, float] | None:
        earliest = self._min_timestamp.value
        latest = self._max_timestamp.value
        if earliest is None or latest is None:
            return None
        return earliest, latest

    def is_empty(self) -> bool:
        return not self._events

    def clear(self) -> None:
        self._events.clear()
        self._reset_aggregates()

    def __len__(self) -> int:
        return len(self._events)

    def __iter__(self):
        return (observation for observation, _signals in self._events)


class DnsTunnellingDetector(Detector):
    """Flags a host whose DNS to one resolver repeatedly looks encoded.

    A pair qualifies only when **both** hold inside the window:

    * **volume** - ``observation_count >= min_dns_observations``. One
      abnormal query, or a handful, can never alert.
    * **prevalence** - ``suspicious_ratio >= min_suspicious_ratio``, where an
      observation is suspicious only once at least
      ``min_signals_per_observation`` independent indicators fire on it.

    The two-level structure is the point. Requiring several signals per
    query stops any one metric carrying an alert on its own - a long name, a
    high-entropy name and a deep label stack each have dull explanations
    alone. Requiring a high *fraction* of such queries stops a few unusual
    lookups inside normal traffic from mattering.

    Non-DNS flows are ignored before any state is touched, so registering
    this detector cannot change what the port-scan, DDoS or beaconing
    detectors see or cost.
    """

    name = "dns_tunnelling"
    version = "0.1.0"

    def __init__(self, config: DnsTunnellingConfig | None = None) -> None:
        self.config = config or DnsTunnellingConfig()
        self._windows: dict[DnsTunnelKey, _DnsWindow] = {}
        self._state: dict[DnsTunnelKey, _PairState] = {}
        self._since_sweep = 0

    # --- detection ------------------------------------------------------

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        """Observe every represented DNS transaction exactly once."""
        if not flow.dns_transactions:
            return self._process_one(flow)

        alerts: list[ThreatAlert] = []
        for index, dns in enumerate(flow.dns_transactions):
            transaction_flow = flow.model_copy(
                update={
                    "timestamp": dns.event_time
                    if dns.event_time is not None
                    else flow.timestamp,
                    "dns": dns,
                    "dns_transactions": [],
                    "src_ip": dns.src_ip if dns.src_ip is not None else flow.src_ip,
                    "src_port": dns.src_port if dns.src_port is not None else flow.src_port,
                    "dst_ip": dns.dst_ip if dns.dst_ip is not None else flow.dst_ip,
                    "dst_port": dns.dst_port if dns.dst_port is not None else flow.dst_port,
                    "proto": dns.proto if dns.proto is not None else flow.proto,
                    # Flow bytes cannot be apportioned to individual DNS rows.
                    # Count them once instead of multiplying them by the
                    # number of transactions on the connection.
                    "orig_bytes": flow.orig_bytes if index == 0 else 0,
                }
            )
            alerts.extend(self._process_one(transaction_flow))
        return alerts

    def _process_one(self, flow: FlowEvent) -> list[ThreatAlert]:
        """Apply the original one-query window update to one transaction."""
        if flow.dns is None:
            # Not DNS as far as this layer can tell - the block is the only
            # honest marker we have. Ingestion emits no `service`, and a
            # port number is not proof of a protocol, so nothing is guessed
            # from dst_port here. Cheapest possible exit: no state touched.
            return []

        key = DnsTunnelKey.from_flow(flow)
        window = self._window_for(key)
        observation = DnsObservation.from_flow(flow)
        window.observe(
            observation,
            self._signal_count(observation),
            self.config.min_signals_per_observation,
        )
        self._maybe_sweep(flow.timestamp)

        stats = self._aggregate(window)
        if stats is None or not self._qualifies(stats):
            return []

        score = self._rule_score(stats)
        severity = severity_for(score)
        if not self._should_emit(key, flow.timestamp, severity):
            return []

        # Evidence-only float means, recomputed exactly for the alert.
        stats = replace(
            stats,
            mean_query_entropy=window.exact_mean_query_entropy(),
            mean_subdomain_entropy=window.exact_mean_subdomain_entropy(),
        )
        alert = self._build_alert(key, stats, score, severity)

        # Only once the alert exists. If building or validating it raises,
        # nothing was emitted, so nothing may enter the cooldown - otherwise
        # the failure would also silence the next several real tunnels.
        state = self._state.setdefault(key, _PairState())
        state.last_alert_at = flow.timestamp
        state.last_severity = severity
        return [alert]

    def flush(self) -> list[ThreatAlert]:
        """Nothing is ever held back - ``process()`` already alerted."""
        return []

    def reset(self) -> None:
        """Drop every pair's window, cooldown and escalation state."""
        self._windows.clear()
        self._state.clear()
        self._since_sweep = 0

    # --- window management ----------------------------------------------

    def _window_for(self, key: DnsTunnelKey) -> _DnsWindow:
        window = self._windows.get(key)
        if window is None:
            window = _DnsWindow(
                self.config.window_seconds, self.config.max_observations_per_key
            )
            self._windows[key] = window
        return window

    def _maybe_sweep(self, now: float, every: int = 500) -> None:
        """Evict pairs that have gone quiet, so memory stays bounded.

        Each window self-trims on write, but a pair that stops querying
        keeps an (eventually empty) window forever. A long capture with many
        one-off pairs would otherwise leak one dict entry each.

        A pair's cooldown outlives its window. Dropping both together would
        mean that with ``cooldown_seconds`` longer than ``window_seconds`` a
        pair could go quiet, come back and immediately re-alert inside the
        cooldown it was supposed to be serving. So the cooldown entry is
        released only once it can no longer suppress anything - which still
        bounds it, and it is the smaller dict regardless (only pairs that
        actually alerted ever get one).
        """
        self._since_sweep += 1
        if self._since_sweep < every:
            return
        self._since_sweep = 0
        for key in list(self._windows):
            window = self._windows[key]
            window.expire(now)
            if window.is_empty():
                del self._windows[key]
        for key, state in list(self._state.items()):
            if (
                state.last_alert_at is not None
                and (now - state.last_alert_at) >= self.config.cooldown_seconds
            ):
                del self._state[key]

    # --- aggregation ----------------------------------------------------

    def _signal_count(self, observation: DnsObservation) -> int:
        """How many independent tunnelling indicators this query fires.

        A field ingestion did not supply is skipped, never defaulted: a
        missing ``query_length`` must not read as a short query, and a
        missing ``is_txt`` must not read as "not TXT" for scoring purposes.
        The observation simply has fewer chances to look suspicious, which
        is the honest outcome when the data is not there.
        """
        config = self.config
        count = 0
        if (
            observation.query_length is not None
            and observation.query_length >= config.suspicious_query_length
        ):
            count += 1
        if (
            observation.query_entropy is not None
            and observation.query_entropy >= config.suspicious_entropy
        ):
            count += 1
        if (
            observation.subdomain_entropy is not None
            and observation.subdomain_entropy >= config.suspicious_subdomain_entropy
        ):
            count += 1
        if (
            observation.label_count is not None
            and observation.label_count >= config.suspicious_label_count
        ):
            count += 1
        if observation.is_txt:
            count += 1
        return count

    def _aggregate(self, window: _DnsWindow) -> DnsAggregate | None:
        """Summarize a pair's window. ``None`` when it holds nothing.

        Every value is read from the window's incremental state rather
        than recomputed over its contents, so this is O(1) - extremes
        included, see :class:`WindowExtreme`. Means are still taken only
        over the observations
        that actually carried the field, so a partially-populated window
        reports a real mean of what was measured rather than one diluted by
        absent values.
        """
        total = len(window)
        if not total:
            return None

        return DnsAggregate(
            observation_count=total,
            suspicious_count=window.suspicious_count,
            # `total` is >= 1 here, so this division is always safe.
            suspicious_ratio=window.suspicious_count / total,
            mean_signals=window.mean_signals(),
            txt_count=window.txt_count,
            # Over the observations that reported is_txt at all, not the
            # whole window - otherwise absent flags would read as "not TXT".
            txt_ratio=window.txt_ratio(),
            mean_query_length=window.mean_query_length(),
            max_query_length=window.max_query_length(),
            mean_query_entropy=window.mean_query_entropy(),
            max_query_entropy=window.max_query_entropy(),
            mean_subdomain_entropy=window.mean_subdomain_entropy(),
            mean_label_count=window.mean_label_count(),
            max_label_count=window.max_label_count(),
            total_orig_bytes=window.total_orig_bytes,
            time_span=window.time_span(),
            # Over this window only - an expired observation cannot make a
            # port ambiguous or claim a raw query the alert no longer covers.
            dst_port=window.unanimous_dst_port(),
            protocol=window.unanimous_proto(),
            raw_query_count=window.raw_query_count,
        )

    @staticmethod
    def _unanimous(values: list):
        """The single value every observation that knew it agreed on.

        ``None`` when the window is split, and ``None`` when nothing in it
        reported the field at all - an aggregate alert covering a whole
        window must not publish one port because the flow that happened to
        cross the threshold used it.

        Observations that did not carry the field are skipped rather than
        counted as disagreement: a missing port is not a port, which is
        exactly how ``ActivityWindow.dst_ports`` treats it for the other
        detectors. So twenty ``:53`` lookups plus one record whose port
        ingestion omitted still report 53, while a window genuinely split
        across ``:53`` and ``:5353`` reports ``None`` rather than picking one.
        """
        known = {value for value in values if value is not None}
        return next(iter(known)) if len(known) == 1 else None

    @staticmethod
    def _mean(values: list) -> float | None:
        """Arithmetic mean, or ``None`` for an empty list.

        Every caller passes a list that may legitimately be empty (a window
        where no observation carried that field), so the guard is the point.
        """
        return (sum(values) / len(values)) if values else None

    def _qualifies(self, stats: DnsAggregate) -> bool:
        """Enough DNS to judge, and enough of it abnormal."""
        return (
            stats.observation_count >= self.config.min_dns_observations
            and stats.suspicious_ratio >= self.config.min_suspicious_ratio
        )

    # --- scoring --------------------------------------------------------

    def _rule_score(self, stats: DnsAggregate) -> float:
        """Deterministic 0.0-1.0 rule score. Not a calibrated probability.

        Explicit threshold logic, hence ``rule_score`` - nothing here models
        a distribution of normal behaviour, so calling it an anomaly score
        would misrepresent it.

        Three components, each 0 at the qualification boundary and 1 at its
        strongest:

        * **prevalence** - 0 at ``min_suspicious_ratio``, 1 when every query
          in the window is suspicious.
        * **volume** - 0 at ``min_dns_observations``, 1 once the window
          holds ``saturation_multiple`` times that.
        * **agreement** - 0 when suspicious queries fire the bare
          ``min_signals_per_observation`` indicators, 1 when they fire all
          ``MAX_SIGNALS``.

        Their weighted blend maps onto the project's usual curve, so a pair
        that has only just qualified scores 0.5 and the most blatant tunnel
        scores 1.0. A TXT-heavy pair adds ``txt_bonus`` on top. The result is
        clamped to [0.0, 1.0].
        """
        config = self.config

        ratio_span = 1.0 - config.min_suspicious_ratio
        if ratio_span <= 0:
            # min_suspicious_ratio == 1.0: qualifying already means "all of
            # them", so prevalence is maxed by definition.
            prevalence = 1.0
        else:
            prevalence = (stats.suspicious_ratio - config.min_suspicious_ratio) / ratio_span
        prevalence = _clamp01(prevalence)

        growth = stats.observation_count / config.min_dns_observations - 1.0
        volume = _clamp01(growth / (config.saturation_multiple - 1.0))

        signal_span = MAX_SIGNALS - config.min_signals_per_observation
        if stats.mean_signals is None or signal_span <= 0:
            # No suspicious observations cannot reach this code (the pair
            # would not have qualified); signal_span is 0 only when the
            # config demands all signals already, so agreement is maxed.
            agreement = 1.0
        else:
            agreement = _clamp01(
                (stats.mean_signals - config.min_signals_per_observation) / signal_span
            )

        strength = (
            config.ratio_weight * prevalence
            + config.volume_weight * volume
            + config.agreement_weight * agreement
        )
        score = 0.5 + 0.5 * strength
        if stats.txt_ratio is not None and stats.txt_ratio >= config.suspicious_txt_ratio:
            score += config.txt_bonus
        return normalize_score(score)

    @staticmethod
    def _severity(score: float) -> Severity:
        """Project-standard severity bands - see ``scoring.severity_for``."""
        return severity_for(score)

    # --- cooldown -------------------------------------------------------

    def _should_emit(self, key: DnsTunnelKey, now: float, severity: Severity) -> bool:
        """Cooldown, with an escape hatch for genuine escalation.

        A pair that has just alerted stays quiet for ``cooldown_seconds`` -
        unless the behaviour has grown into a strictly higher severity band,
        which is news worth interrupting for. A rising score inside the same
        band is not: that would be the alert spam the cooldown exists to
        stop.
        """
        state = self._state.get(key)
        if state is None or state.last_alert_at is None:
            return True
        if (now - state.last_alert_at) >= self.config.cooldown_seconds:
            return True
        if state.last_severity is None:
            return True
        return severity_rank(severity) > severity_rank(state.last_severity)

    # --- alert ----------------------------------------------------------

    def _build_alert(
        self,
        key: DnsTunnelKey,
        stats: DnsAggregate,
        score: float,
        severity: Severity,
    ) -> ThreatAlert:
        config = self.config

        return ThreatAlert(
            event_start=epoch_to_utc(stats.time_span[0]),
            event_end=epoch_to_utc(stats.time_span[1]),
            event_scope=EventScope.HOST_PAIR,
            flow_id=None,
            # Straight off the key - the alert describes exactly the pair
            # whose DNS was measured.
            src_ip=key.src_ip,
            dst_ip=key.dst_ip,
            # The window's port/proto, not the triggering flow's: this is a
            # HOST_PAIR alert over every query in the window, so it may only
            # name a port that all of them used. Mixed - or never supplied -
            # reports None. Ingestion emits no `service`, so nothing is
            # assumed to be port 53 and no protocol is invented.
            dst_port=stats.dst_port,
            protocol=stats.protocol,
            threat_class=ThreatClass.DNS_TUNNELLING,
            severity=severity,
            score=score,
            score_type=ScoreType.RULE_SCORE,
            evidence={
                # --- what was actually measured ---------------------------
                "observation_count": stats.observation_count,
                "suspicious_observation_count": stats.suspicious_count,
                "suspicious_ratio": stats.suspicious_ratio,
                "mean_signals_per_suspicious_observation": stats.mean_signals,
                # None below means "ingestion supplied no such value in this
                # window", never "measured as zero".
                "mean_query_length": stats.mean_query_length,
                "max_query_length": stats.max_query_length,
                "mean_query_entropy": stats.mean_query_entropy,
                "max_query_entropy": stats.max_query_entropy,
                "mean_subdomain_entropy": stats.mean_subdomain_entropy,
                "mean_label_count": stats.mean_label_count,
                "max_label_count": stats.max_label_count,
                "txt_query_count": stats.txt_count,
                "txt_ratio": stats.txt_ratio,
                # Context only - gates nothing.
                "total_orig_bytes": stats.total_orig_bytes,
                # --- thresholds this verdict was measured against ---------
                "window_seconds": config.window_seconds,
                "min_dns_observations": config.min_dns_observations,
                "min_suspicious_ratio": config.min_suspicious_ratio,
                "min_signals_per_observation": config.min_signals_per_observation,
                "suspicious_query_length": config.suspicious_query_length,
                "suspicious_entropy": config.suspicious_entropy,
                "suspicious_subdomain_entropy": config.suspicious_subdomain_entropy,
                "suspicious_label_count": config.suspicious_label_count,
                "suspicious_txt_ratio": config.suspicious_txt_ratio,
                # Whether any query in THIS window carried a raw name.
                # Current ingestion emits none, so this is normally false and
                # the verdict rests on derived features alone - but a feed
                # that does emit dns.query is reported as it is rather than
                # denied. Detection itself is unchanged either way: the raw
                # name is evidence for the analyst, not an input to the rule.
                "raw_query_available": stats.raw_query_count > 0,
                "raw_query_observation_count": stats.raw_query_count,
            },
            detector=self.name,
            detector_version=self.version,
            mitre_techniques=list(MITRE_BY_CLASS[ThreatClass.DNS_TUNNELLING]),
        )


def _clamp01(value: float) -> float:
    """Clamp to [0.0, 1.0]. Score components are blended before rounding."""
    return min(max(value, 0.0), 1.0)
