"""Adapter for ingestion's ``features.jsonl``.

THIS FILE (plus ``encodings.py``) IS THE ONLY PLACE IN detection_core THAT
UNDERSTANDS THE INGESTION FORMAT. When the ingestion team changes their
output, this is the only file that should need editing.

Behaviour on bad input, per the agreed contract:

* a record that cannot form a valid FlowEvent is logged, counted and
  skipped - processing continues;
* required core fields are never silently coerced to ``None``;
* optional fields that ingestion does not supply are ``None``, never
  invented.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..schemas import DnsInfo, FlowEvent, HttpInfo, TlsInfo
from .encodings import (
    EXPECTED_CORE_FIELDS,
    IGNORED_WINDOW_FIELDS,
    KNOWN_TOP_LEVEL_FIELDS,
    decode_conn_state,
    decode_http_method,
    decode_ssl_version,
)

__all__ = ["AdapterStats", "IngestionJsonlAdapter", "record_to_flow_event", "SOURCE_NAME"]

logger = logging.getLogger(__name__)

# Stable serialized provenance tag retained for backward compatibility.  The
# historical misspelling is not a filesystem path; the repository directory is
# now ``ingestion/`` and the Python extension remains ``ingestion_core``.
SOURCE_NAME = "injestion_core.features_jsonl"


@dataclass
class AdapterStats:
    """Counters for one adapter run."""

    total_lines: int = 0
    blank_lines: int = 0
    parsed: int = 0
    json_errors: int = 0
    validation_errors: int = 0
    drift_warnings: list[str] = field(default_factory=list)

    @property
    def skipped(self) -> int:
        """Records seen but not converted (blank lines are not records)."""
        return self.json_errors + self.validation_errors

    @property
    def errors(self) -> int:
        return self.json_errors + self.validation_errors

    def reset(self) -> None:
        self.total_lines = 0
        self.blank_lines = 0
        self.parsed = 0
        self.json_errors = 0
        self.validation_errors = 0
        self.drift_warnings.clear()


def _timestamp_from_flow_id(flow_id: Any) -> float | None:
    """Epoch seconds from ``src:dst:port:proto:ts``.

    Splits on the LAST colon only - ``flow_id`` embeds IP addresses, and an
    IPv6 address contains colons of its own.
    """
    if not isinstance(flow_id, str):
        return None
    _, separator, tail = flow_id.rpartition(":")
    if not separator:
        return None
    try:
        return float(tail)
    except ValueError:
        return None


def _resolve_timestamp(record: Mapping[str, Any]) -> float:
    """Prefer an explicit top-level timestamp, else derive from flow_id.

    The ``flow_id`` fallback exists for records that carry **no** event time
    of their own. It is not a repair for one that is present and wrong: a
    record saying ``"timestamp": "2000.5"`` has an event time, and quietly
    substituting a different number recovered from the id would place the
    flow somewhere on the timeline the producer never claimed - and every
    window, interval and cooldown downstream would believe it.

    So a present-but-unusable value is an error, and only an absent one
    falls back. An explicit ``null`` counts as absent: that is a producer
    saying it has no timestamp, not one supplying a bad one.

    Non-finite floats are left to ``FlowEvent``'s own finite validator,
    which already rejects them.
    """
    for key in ("timestamp", "ts"):
        if key not in record:
            continue
        value = record[key]
        if value is None:  # explicitly "not supplied"
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(
                f"{key}={value!r} is not a number; a malformed event time is "
                "not repaired from flow_id, because that would silently move "
                "the flow to a different point in time"
            )
        return float(value)
    derived = _timestamp_from_flow_id(record.get("flow_id"))
    if derived is None:
        raise ValueError(
            "cannot determine timestamp: no numeric 'timestamp'/'ts' field and "
            f"flow_id={record.get('flow_id')!r} has no parseable trailing epoch"
        )
    return derived


def _require_block(record: Mapping[str, Any], key: str) -> Mapping[str, Any] | None:
    """Return a nested block, or None if absent. A non-object block is an error."""
    raw = record.get(key)
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise ValueError(f"{key!r} block must be a JSON object, got {type(raw).__name__}")
    return raw


def _build_dns_block(raw: Mapping[str, Any]) -> DnsInfo:
    return DnsInfo(
        uid=raw.get("uid"),
        event_time=raw.get("event_time"),
        source_ordinal=raw.get("source_ordinal"),
        src_ip=raw.get("src_ip"),
        src_port=raw.get("src_port"),
        dst_ip=raw.get("dst_ip"),
        dst_port=raw.get("dst_port"),
        proto=raw.get("proto"),
        # Exact raw detector-v2 telemetry; old records may omit it.
        query=raw.get("query"),
        qtype=raw.get("qtype"),
        rcode=raw.get("rcode"),
        qtype_num=raw.get("qtype_num"),
        rcode_num=raw.get("rcode_num"),
        transaction_count=raw.get("transaction_count"),
        authoritative_answer=raw.get("authoritative_answer"),
        truncated=raw.get("truncated"),
        recursion_desired=raw.get("recursion_desired"),
        recursion_available=raw.get("recursion_available"),
        z=raw.get("z"),
        answer_count=raw.get("answer_count"),
        rejected=raw.get("rejected"),
        query_length=raw.get("query_length"),
        query_entropy=raw.get("query_entropy"),
        subdomain_entropy=raw.get("subdomain_entropy"),
        is_txt=raw.get("is_txt"),
        label_count=raw.get("label_count"),
    )


def _build_dns(record: Mapping[str, Any]) -> DnsInfo | None:
    raw = _require_block(record, "dns")
    if raw is None:
        return None
    return _build_dns_block(raw)


def _build_tls_block(raw: Mapping[str, Any]) -> TlsInfo:
    return TlsInfo(
        uid=raw.get("uid"),
        event_time=raw.get("event_time"),
        source_ordinal=raw.get("source_ordinal"),
        src_ip=raw.get("src_ip"),
        src_port=raw.get("src_port"),
        dst_ip=raw.get("dst_ip"),
        dst_port=raw.get("dst_port"),
        proto=raw.get("proto"),
        # Exact raw telemetry from detector-v2 when the source observed it.
        ja3=raw.get("ja3"),
        ja3s=raw.get("ja3s"),
        ja4=raw.get("ja4"),
        server_name=raw.get("server_name"),
        cipher=raw.get("cipher"),
        transaction_count=raw.get("transaction_count"),
        version=raw.get("version") or decode_ssl_version(raw.get("ssl_version_encoded")),
        has_ja3=raw.get("has_ja3"),
        has_ja3s=raw.get("has_ja3s"),
        # Derived only when ingestion observed a real server name.
        sni_length=raw.get("sni_length"),
        sni_entropy=raw.get("sni_entropy"),
    )
    # NOTE: ingestion's `cipher_encoded` is deliberately NOT mapped. It is
    # computed upstream as (cipher_name_length % 16) + 1 - a function of how
    # long the cipher's *name* happens to be, not of which cipher was
    # negotiated. Their own README marks it a placeholder. Carrying it would
    # invite a detector to treat a meaningless number as a security signal.


def _build_tls(record: Mapping[str, Any]) -> TlsInfo | None:
    raw = _require_block(record, "tls")
    if raw is None:
        return None
    return _build_tls_block(raw)


def _build_http_block(raw: Mapping[str, Any]) -> HttpInfo:
    return HttpInfo(
        uid=raw.get("uid"),
        event_time=raw.get("event_time"),
        source_ordinal=raw.get("source_ordinal"),
        src_ip=raw.get("src_ip"),
        src_port=raw.get("src_port"),
        dst_ip=raw.get("dst_ip"),
        dst_port=raw.get("dst_port"),
        proto=raw.get("proto"),
        # Exact raw detector-v2 request telemetry; old records may omit it.
        host=raw.get("host"),
        uri=raw.get("uri"),
        user_agent=raw.get("user_agent"),
        method=raw.get("method") or decode_http_method(raw.get("method_encoded")),
        host_length=raw.get("host_length"),
        uri_length=raw.get("uri_length"),
        uri_entropy=raw.get("uri_entropy"),
        has_user_agent=raw.get("has_user_agent"),
        user_agent_length=raw.get("user_agent_length"),
        request_body_len=raw.get("request_body_len"),
        response_body_len=raw.get("response_body_len"),
        status_code=raw.get("status_code"),
        transaction_count=raw.get("transaction_count"),
    )


def _build_http(record: Mapping[str, Any]) -> HttpInfo | None:
    raw = _require_block(record, "http")
    if raw is None:
        return None
    return _build_http_block(raw)


def _build_transactions(record: Mapping[str, Any], key: str, builder) -> list[Any]:
    """Validate and map an explicitly present transaction array in source order."""

    if key not in record:
        return []
    raw_items = record[key]
    if not isinstance(raw_items, list):
        raise ValueError(f"{key!r} must be a JSON array, got {type(raw_items).__name__}")
    result = []
    for index, raw in enumerate(raw_items):
        if not isinstance(raw, Mapping):
            raise ValueError(
                f"{key}[{index}] must be a JSON object, got {type(raw).__name__}"
            )
        result.append(builder(raw))
    return result


def _validate_transaction_count(
    name: str, scalar: Any, transactions: list[Any], array_present: bool
) -> None:
    if not array_present:
        return
    if scalar is None:
        if transactions:
            raise ValueError(f"{name}_transactions requires the {name!r} compatibility block")
        return
    if not transactions:
        raise ValueError(f"{name}_transactions must not be empty when {name!r} is present")
    if scalar.transaction_count is None:
        raise ValueError(
            f"{name}.transaction_count is required when {name}_transactions is present"
        )
    if scalar.transaction_count != len(transactions):
        raise ValueError(
            f"{name}.transaction_count={scalar.transaction_count} does not match "
            f"len({name}_transactions)={len(transactions)}"
        )


def _validate_transaction_identity_and_order(
    name: str,
    record: Mapping[str, Any],
    scalar: Any,
    transactions: list[Any],
) -> None:
    """Reject cross-flow rows and contradictory physical-order evidence."""

    if not transactions:
        return
    candidate_uids: list[tuple[str, str]] = []
    top_level_uid = record.get("uid")
    if isinstance(top_level_uid, str) and top_level_uid:
        candidate_uids.append(("top-level uid", top_level_uid))
    if scalar is not None and scalar.uid:
        candidate_uids.append((f"{name}.uid", scalar.uid))
    for index, transaction in enumerate(transactions):
        if transaction.uid:
            candidate_uids.append((f"{name}_transactions[{index}].uid", transaction.uid))
    if candidate_uids:
        expected_source, expected_uid = candidate_uids[0]
        for source, uid in candidate_uids[1:]:
            if uid == expected_uid:
                continue
            raise ValueError(
                f"{source}={uid!r} does not match {expected_source}={expected_uid!r}"
            )
    ordinals = [item.source_ordinal for item in transactions if item.source_ordinal is not None]
    if any(right <= left for left, right in zip(ordinals, ordinals[1:])):
        raise ValueError(f"{name}_transactions source_ordinal values must be strictly increasing")


def _resolve_uid(record: Mapping[str, Any], blocks: list[Any]) -> str | None:
    """Top-level uid if ingestion ever adds one, else the first block uid."""
    top_level = record.get("uid")
    if isinstance(top_level, str) and top_level:
        return top_level
    for block in blocks:
        if block is not None and block.uid:
            return block.uid
    return None


def _collect_extra(record: Mapping[str, Any]) -> dict[str, Any]:
    """Unrecognized top-level keys, for forward compatibility.

    Window fields are excluded on purpose: they are not canonical, so
    nothing downstream may reach them even via ``extra``.
    """
    return {
        key: value
        for key, value in record.items()
        if key not in KNOWN_TOP_LEVEL_FIELDS and key not in IGNORED_WINDOW_FIELDS
    }


def record_to_flow_event(record: Mapping[str, Any]) -> FlowEvent:
    """Map one ingestion record to a FlowEvent. Raises if it cannot.

    Pure function - no logging, no state - so it is trivially unit-testable.
    """
    if not isinstance(record, Mapping):
        raise TypeError(f"record must be a JSON object, got {type(record).__name__}")

    dns = _build_dns(record)
    tls = _build_tls(record)
    http = _build_http(record)
    dns_transactions = _build_transactions(record, "dns_transactions", _build_dns_block)
    tls_transactions = _build_transactions(record, "tls_transactions", _build_tls_block)
    http_transactions = _build_transactions(record, "http_transactions", _build_http_block)
    _validate_transaction_count("dns", dns, dns_transactions, "dns_transactions" in record)
    _validate_transaction_count("tls", tls, tls_transactions, "tls_transactions" in record)
    _validate_transaction_count("http", http, http_transactions, "http_transactions" in record)
    _validate_transaction_identity_and_order("dns", record, dns, dns_transactions)
    _validate_transaction_identity_and_order("tls", record, tls, tls_transactions)
    _validate_transaction_identity_and_order("http", record, http, http_transactions)

    return FlowEvent(
        flow_id=record.get("flow_id"),
        uid=_resolve_uid(
            record,
            [dns, tls, http, *dns_transactions, *tls_transactions, *http_transactions],
        ),
        timestamp=_resolve_timestamp(record),
        src_ip=record.get("src_ip"),
        src_port=record.get("src_port"),
        dst_ip=record.get("dst_ip"),
        dst_port=record.get("dst_port"),
        proto=record.get("proto"),
        service=record.get("service"),
        duration=record.get("duration"),
        orig_bytes=record.get("orig_bytes"),
        resp_bytes=record.get("resp_bytes"),
        orig_pkts=record.get("orig_pkts"),
        resp_pkts=record.get("resp_pkts"),
        orig_ip_bytes=record.get("orig_ip_bytes"),
        resp_ip_bytes=record.get("resp_ip_bytes"),
        conn_state=record.get("conn_state")
        or decode_conn_state(record.get("conn_state_encoded")),
        dns=dns,
        tls=tls,
        http=http,
        dns_transactions=dns_transactions,
        tls_transactions=tls_transactions,
        http_transactions=http_transactions,
        source=SOURCE_NAME,
        extra=_collect_extra(record),
    )


#: How many field errors one skipped record may report before the rest are
#: summarized. A malformed record can fail every field at once, and a log
#: line long enough to wrap is a log line nobody reads.
_MAX_REPORTED_ERRORS = 5


def describe_record_error(exc: Exception) -> str:
    """A one-line, field-first explanation of why a record was rejected.

    ``str(ValidationError)`` is written for a traceback, not a log stream:
    it spans several lines per record and spends one of them per error on a
    ``https://errors.pydantic.dev/...`` link, which pushes the part an
    analyst actually needs - the field and the reason - into the middle of a
    block. Every other line the adapter emits is one record, one line, so a
    skipped record should read the same way::

        src_ip: Value error, must be a non-empty string; dst_port: Input
        should be less than or equal to 65535

    Anything that is not a Pydantic ``ValidationError`` is returned as-is:
    the adapter's own ``ValueError``/``TypeError`` messages are already
    single-line and specific, and rewording them here would only obscure
    them. Nothing about which records are rejected changes - this formats an
    exception that has already been raised.
    """
    reporter = getattr(exc, "errors", None)
    if reporter is None:
        return str(exc)
    try:
        details = list(reporter())
    except Exception:  # pragma: no cover - not a pydantic-shaped errors()
        return str(exc)
    if not details:  # pragma: no cover - a ValidationError always has one
        return str(exc)

    parts = []
    for error in details[:_MAX_REPORTED_ERRORS]:
        location = ".".join(str(item) for item in error.get("loc", ())) or "<record>"
        parts.append(f"{location}: {error.get('msg', 'invalid value')}")
    summary = "; ".join(parts)
    remaining = len(details) - len(parts)
    if remaining > 0:
        summary += f"; (+{remaining} more field error(s))"
    return summary


class IngestionJsonlAdapter:
    """Streams ingestion's ``features.jsonl`` as ``FlowEvent`` objects.

    Satisfies :class:`~detection_core.adapters.base.FlowSource` when
    constructed with a ``path``::

        engine.run(IngestionJsonlAdapter(path="features.jsonl"))
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        strict: bool = False,
        warn_on_drift: bool = True,
        log: logging.Logger | None = None,
    ) -> None:
        self.path = Path(path) if path is not None else None
        self.strict = strict
        self.warn_on_drift = warn_on_drift
        self.log = log or logger
        self.stats = AdapterStats()
        self._drift_seen: set[str] = set()

    def __iter__(self) -> Iterator[FlowEvent]:
        if self.path is None:
            raise ValueError(
                "IngestionJsonlAdapter has no path; construct with a path or call "
                "from_path()/from_lines() explicitly"
            )
        return self.from_path(self.path)

    def from_path(self, path: str | Path | None = None) -> Iterator[FlowEvent]:
        """Stream a JSONL file line-by-line (never loads it all into memory)."""
        target = Path(path) if path is not None else self.path
        if target is None:
            raise ValueError("no path given to from_path()")
        with open(target, "r", encoding="utf-8") as handle:
            yield from self.from_lines(handle)

    def from_lines(self, lines: Iterable[str]) -> Iterator[FlowEvent]:
        """Convert an iterable of JSON text lines into FlowEvents."""
        self.stats.reset()
        self._drift_seen.clear()

        for line_no, line in enumerate(lines, start=1):
            self.stats.total_lines += 1
            text = line.strip()
            if not text:
                self.stats.blank_lines += 1
                continue

            try:
                record = json.loads(text)
            except json.JSONDecodeError as exc:
                self.stats.json_errors += 1
                self.log.warning("line %d: invalid JSON, skipping (%s)", line_no, exc)
                if self.strict:
                    raise
                continue

            if not isinstance(record, Mapping):
                self.stats.validation_errors += 1
                self.log.warning(
                    "line %d: expected a JSON object, got %s, skipping",
                    line_no,
                    type(record).__name__,
                )
                if self.strict:
                    raise ValueError(f"line {line_no}: expected a JSON object")
                continue

            if self.warn_on_drift:
                self._check_drift(record, line_no)

            try:
                event = record_to_flow_event(record)
            except Exception as exc:  # ValidationError, ValueError, TypeError
                self.stats.validation_errors += 1
                self.log.warning(
                    "line %d: could not build FlowEvent, skipping (%s)",
                    line_no,
                    describe_record_error(exc),
                )
                if self.strict:
                    # Re-raised unchanged: a caller catching this still gets
                    # the original exception, not the formatted summary.
                    raise
                continue

            # Counted before the yield so stats stay correct if a consumer
            # stops iterating early.
            self.stats.parsed += 1
            yield event

    def _check_drift(self, record: Mapping[str, Any], line_no: int) -> None:
        """Warn once per novel key when the upstream schema moves."""
        unknown = set(record) - KNOWN_TOP_LEVEL_FIELDS - IGNORED_WINDOW_FIELDS
        for key in sorted(unknown):
            marker = f"unknown:{key}"
            if marker not in self._drift_seen:
                self._drift_seen.add(marker)
                message = (
                    f"schema drift: unknown ingestion field {key!r} "
                    f"(first seen line {line_no}); kept in FlowEvent.extra"
                )
                self.stats.drift_warnings.append(message)
                self.log.warning(message)

        missing = EXPECTED_CORE_FIELDS - set(record)
        for key in sorted(missing):
            marker = f"missing:{key}"
            if marker not in self._drift_seen:
                self._drift_seen.add(marker)
                message = (
                    f"schema drift: expected ingestion field {key!r} is absent "
                    f"(first seen line {line_no})"
                )
                self.stats.drift_warnings.append(message)
                self.log.warning(message)
