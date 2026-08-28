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

# Named for the actual repository directory, which is spelled "injestion_core"
# (the Python module it builds is spelled "ingestion_core").
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
    """Prefer an explicit top-level timestamp, else derive from flow_id."""
    for key in ("timestamp", "ts"):
        value = record.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
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


def _build_dns(record: Mapping[str, Any]) -> DnsInfo | None:
    raw = _require_block(record, "dns")
    if raw is None:
        return None
    return DnsInfo(
        uid=raw.get("uid"),
        # query / qtype / rcode: integration TODO, absent upstream today.
        query=raw.get("query"),
        qtype=raw.get("qtype"),
        rcode=raw.get("rcode"),
        query_length=raw.get("query_length"),
        query_entropy=raw.get("query_entropy"),
        subdomain_entropy=raw.get("subdomain_entropy"),
        is_txt=raw.get("is_txt"),
        label_count=raw.get("label_count"),
    )


def _build_tls(record: Mapping[str, Any]) -> TlsInfo | None:
    raw = _require_block(record, "tls")
    if raw is None:
        return None
    return TlsInfo(
        uid=raw.get("uid"),
        # ja3 / ja3s / ja4 / server_name: integration TODO, absent upstream today.
        ja3=raw.get("ja3"),
        ja3s=raw.get("ja3s"),
        ja4=raw.get("ja4"),
        server_name=raw.get("server_name"),
        version=raw.get("version") or decode_ssl_version(raw.get("ssl_version_encoded")),
        has_ja3=raw.get("has_ja3"),
        has_ja3s=raw.get("has_ja3s"),
    )


def _build_http(record: Mapping[str, Any]) -> HttpInfo | None:
    raw = _require_block(record, "http")
    if raw is None:
        return None
    return HttpInfo(
        uid=raw.get("uid"),
        # host / uri / user_agent: integration TODO, absent upstream today.
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
    )


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

    return FlowEvent(
        flow_id=record.get("flow_id"),
        uid=_resolve_uid(record, [dns, tls, http]),
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
        conn_state=record.get("conn_state")
        or decode_conn_state(record.get("conn_state_encoded")),
        dns=dns,
        tls=tls,
        http=http,
        source=SOURCE_NAME,
        extra=_collect_extra(record),
    )


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
                    "line %d: could not build FlowEvent, skipping (%s)", line_no, exc
                )
                if self.strict:
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
