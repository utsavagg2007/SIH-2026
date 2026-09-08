"""Explicit detector-facing projection of parsed Zeek records.

This module preserves the useful feature-interface repairs that existed on the
compiled branch without changing the frozen M1D legacy projection or the
CanonicalObservation v1 producer.  It is selected only by
``--feature-profile detector-v2``.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from math import log2
from typing import Any, Iterator, TextIO

from ingestion_core import (
    extract_dns_features,
    extract_flow_features,
    extract_http_features,
    extract_tls_features,
    extract_window_features,
)

PROFILE_NAME = "detector-v2"

_QTYPE_NAMES = {
    "1": "A",
    "2": "NS",
    "5": "CNAME",
    "6": "SOA",
    "12": "PTR",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "33": "SRV",
    "35": "NAPTR",
    "43": "DS",
    "46": "RRSIG",
    "47": "NSEC",
    "48": "DNSKEY",
    "50": "NSEC3",
    "52": "TLSA",
    "65": "HTTPS",
    "99": "SPF",
    "251": "IXFR",
    "252": "AXFR",
    "255": "ANY",
}

_RCODE_NAMES = {
    "0": "NOERROR",
    "1": "FORMERR",
    "2": "SERVFAIL",
    "3": "NXDOMAIN",
    "4": "NOTIMP",
    "5": "REFUSED",
    "6": "YXDOMAIN",
    "7": "YXRRSET",
    "8": "NXRRSET",
    "9": "NOTAUTH",
    "10": "NOTZONE",
}

_UNSET = {"", "-", "(empty)"}


@dataclass
class PipelineStats:
    """Counts and availability diagnostics for one detector-v2 projection."""

    conn_records: int = 0
    dns_records: int = 0
    ssl_records: int = 0
    http_records: int = 0
    emitted: int = 0
    with_dns: int = 0
    with_tls: int = 0
    with_http: int = 0
    with_raw_query: int = 0
    with_ja3: int = 0
    with_ja3s: int = 0
    with_ja4: int = 0
    with_sni: int = 0
    multi_row_uids: dict[str, int] = field(default_factory=dict)

    def render(self) -> str:
        lines = [
            f"parsed   conn={self.conn_records} dns={self.dns_records} "
            f"ssl={self.ssl_records} http={self.http_records}",
            f"emitted  {self.emitted} flow record(s)",
            f"enriched dns={self.with_dns} tls={self.with_tls} http={self.with_http}",
            f"raw      dns.query={self.with_raw_query} tls.ja3={self.with_ja3} "
            f"tls.ja3s={self.with_ja3s} tls.ja4={self.with_ja4} "
            f"tls.server_name={self.with_sni}",
        ]
        for kind, count in sorted(self.multi_row_uids.items()):
            lines.append(
                f"note     {count} uid(s) carried multiple {kind} rows; all rows "
                f"are preserved in {kind}_transactions and the earliest "
                f"event-time row remains in {kind} for compatibility"
            )
        if not self.with_raw_query and self.dns_records:
            lines.append(
                "warning  DNS rows were parsed but no raw query survived - "
                "the DGA detector will stay silent"
            )
        if not self.with_ja3 and self.ssl_records:
            lines.append(
                "warning  TLS rows were parsed but no JA3 hash was present"
            )
        return "\n".join(lines)


def _clean(value: Any) -> Any:
    if isinstance(value, str) and value.strip() in _UNSET:
        return None
    return value


def _qtype_name(raw: Any) -> str | None:
    value = _clean(raw)
    if value is None:
        return None
    text = str(value).strip()
    return _QTYPE_NAMES.get(text, text) if text.isdigit() else text.upper()


def _rcode_name(raw: Any) -> str | None:
    value = _clean(raw)
    if value is None:
        return None
    text = str(value).strip()
    return _RCODE_NAMES.get(text, text) if text.isdigit() else text.upper()


def _protocol_index(
    records: list[dict],
    features: list[dict],
    kind: str,
    stats: PipelineStats,
) -> dict[str, tuple[dict, dict, int]]:
    """Choose the earliest protocol row per UID and expose multiplicity."""

    index: dict[str, tuple[dict, dict, int]] = {}
    for record, derived in zip(records, features, strict=True):
        uid = record.get("uid")
        if not uid:
            continue
        existing = index.get(uid)
        if existing is None:
            index[uid] = (record, derived, 1)
            continue
        previous_record, previous_derived, count = existing
        if count == 1:
            stats.multi_row_uids[kind] = stats.multi_row_uids.get(kind, 0) + 1
        if record.get("timestamp", 0.0) < previous_record.get("timestamp", 0.0):
            index[uid] = (record, derived, count + 1)
        else:
            index[uid] = (previous_record, previous_derived, count + 1)
    return index


def _protocol_groups(
    records: list[dict], features: list[dict]
) -> dict[str, list[tuple[dict, dict]]]:
    """Group rows by UID without changing physical source-row order."""

    groups: dict[str, list[tuple[dict, dict]]] = {}
    for record, derived in zip(records, features, strict=True):
        uid = record.get("uid")
        if uid:
            groups.setdefault(uid, []).append((record, derived))
    return groups


def _dns_block(raw: dict, derived: dict, transactions: int | None) -> dict:
    qtype = _qtype_name(raw.get("qtype_name") or raw.get("qtype"))
    block = {
        "uid": raw.get("uid"),
        "query": _clean(raw.get("query")),
        "qtype": qtype,
        "qtype_num": _clean(raw.get("qtype")),
        "rcode": _rcode_name(raw.get("rcode_name") or raw.get("rcode")),
        "rcode_num": _clean(raw.get("rcode")),
        "query_length": derived.get("query_length"),
        "query_entropy": derived.get("query_entropy"),
        "subdomain_entropy": derived.get("subdomain_entropy"),
        "is_txt": qtype == "TXT",
        "label_count": derived.get("label_count"),
    }
    if transactions is not None:
        block["transaction_count"] = transactions
    return block


def _shannon(text: str) -> float:
    if not text:
        return 0.0
    total = len(text)
    return -sum((count / total) * log2(count / total) for count in Counter(text).values())


def _tls_block(raw: dict, derived: dict, transactions: int | None) -> dict:
    server_name = _clean(raw.get("server_name"))
    block = {
        "uid": raw.get("uid"),
        "ja3": _clean(raw.get("ja3")),
        "ja3s": _clean(raw.get("ja3s")),
        "ja4": _clean(raw.get("ja4")),
        "server_name": server_name,
        "version": _clean(raw.get("version")),
        "cipher": _clean(raw.get("cipher")),
        "has_ja3": derived.get("has_ja3"),
        "has_ja3s": derived.get("has_ja3s"),
        "ssl_version_encoded": derived.get("ssl_version_encoded"),
    }
    if server_name:
        block["sni_length"] = len(server_name)
        block["sni_entropy"] = _shannon(server_name)
    if transactions is not None:
        block["transaction_count"] = transactions
    return block


def _http_block(raw: dict, derived: dict, transactions: int | None) -> dict:
    block = {
        "uid": raw.get("uid"),
        "host": _clean(raw.get("host")),
        "uri": _clean(raw.get("uri")),
        "user_agent": _clean(raw.get("user_agent")),
        "method": _clean(raw.get("method")),
        "status_code": raw.get("status_code"),
        "host_length": derived.get("host_length"),
        "uri_length": derived.get("uri_length"),
        "uri_entropy": derived.get("uri_entropy"),
        "has_user_agent": derived.get("has_user_agent"),
        "user_agent_length": derived.get("user_agent_length"),
        "request_body_len": derived.get("request_body_len"),
        "response_body_len": derived.get("response_body_len"),
    }
    if transactions is not None:
        block["transaction_count"] = transactions
    return block


def _transaction_source(raw: dict) -> dict:
    """Approved source identity/tuple facts shared by transaction blocks."""

    return {
        "event_time": raw.get("event_time"),
        "source_ordinal": raw.get("source_ordinal"),
        "src_ip": _clean(raw.get("src_ip")),
        "src_port": raw.get("src_port"),
        "dst_ip": _clean(raw.get("dst_ip")),
        "dst_port": raw.get("dst_port"),
        "proto": _clean(raw.get("proto")),
    }


def _dns_transaction(raw: dict, derived: dict) -> dict:
    block = _dns_block(raw, derived, None)
    block.update(_transaction_source(raw))
    block.update(
        {
            "authoritative_answer": raw.get("authoritative_answer"),
            "truncated": raw.get("truncated"),
            "recursion_desired": raw.get("recursion_desired"),
            "recursion_available": raw.get("recursion_available"),
            "z": raw.get("z"),
            "answer_count": raw.get("answer_count"),
            "rejected": raw.get("rejected"),
        }
    )
    return block


def _tls_transaction(raw: dict, derived: dict) -> dict:
    block = _tls_block(raw, derived, None)
    block.update(_transaction_source(raw))
    return block


def _http_transaction(raw: dict, derived: dict) -> dict:
    block = _http_block(raw, derived, None)
    block.update(_transaction_source(raw))
    return block


def join_by_uid(parsed: dict[str, list[dict]]) -> list[dict]:
    """Return the first connection row for each non-empty UID."""

    by_uid: dict[str, dict] = {}
    for conn in parsed.get("conn", []):
        uid = conn.get("uid")
        if uid:
            by_uid.setdefault(uid, dict(conn))
    return list(by_uid.values())


def build_records(
    joined: list[dict],
    parsed: dict[str, list[dict]],
    *,
    window_secs: float = 60.0,
    emit_window: bool = False,
    stats: PipelineStats | None = None,
) -> Iterator[dict]:
    """Yield detector-facing flow records in stable event-time order."""

    stats = stats or PipelineStats()
    stats.conn_records = len(parsed.get("conn", []))
    stats.dns_records = len(parsed.get("dns", []))
    stats.ssl_records = len(parsed.get("ssl", []))
    stats.http_records = len(parsed.get("http", []))

    ordered = sorted(joined, key=lambda record: record.get("timestamp", 0.0))
    conn_json = json.dumps(ordered)
    flow_features = json.loads(extract_flow_features(conn_json))
    window_features = (
        json.loads(extract_window_features(conn_json, window_secs))
        if emit_window
        else None
    )

    dns_records = parsed.get("dns", [])
    ssl_records = parsed.get("ssl", [])
    http_records = parsed.get("http", [])
    dns_features = (
        json.loads(extract_dns_features(json.dumps(dns_records))) if dns_records else []
    )
    tls_features = (
        json.loads(extract_tls_features(json.dumps(ssl_records))) if ssl_records else []
    )
    http_features = (
        json.loads(extract_http_features(json.dumps(http_records))) if http_records else []
    )
    dns_index = _protocol_index(dns_records, dns_features, "dns", stats)
    tls_index = _protocol_index(ssl_records, tls_features, "tls", stats)
    http_index = _protocol_index(http_records, http_features, "http", stats)
    dns_groups = _protocol_groups(dns_records, dns_features)
    tls_groups = _protocol_groups(ssl_records, tls_features)
    http_groups = _protocol_groups(http_records, http_features)

    for index, conn in enumerate(ordered):
        uid = conn.get("uid")
        vector: dict[str, Any] = dict(flow_features[index])
        vector["uid"] = uid
        vector["timestamp"] = conn.get("timestamp")
        vector["src_port"] = conn.get("src_port")
        vector["service"] = _clean(conn.get("service"))
        vector["conn_state"] = _clean(conn.get("conn_state"))
        vector["orig_ip_bytes"] = conn.get("orig_ip_bytes")
        vector["resp_ip_bytes"] = conn.get("resp_ip_bytes")

        if window_features is not None:
            vector.update(window_features[index])

        if uid in dns_index:
            raw, derived, count = dns_index[uid]
            vector["dns"] = _dns_block(raw, derived, count)
            vector["dns_transactions"] = [
                _dns_transaction(transaction, transaction_features)
                for transaction, transaction_features in dns_groups[uid]
            ]
            stats.with_dns += 1
            if any(item["query"] for item in vector["dns_transactions"]):
                stats.with_raw_query += 1
        if uid in tls_index:
            raw, derived, count = tls_index[uid]
            vector["tls"] = _tls_block(raw, derived, count)
            vector["tls_transactions"] = [
                _tls_transaction(transaction, transaction_features)
                for transaction, transaction_features in tls_groups[uid]
            ]
            stats.with_tls += 1
            if any(item["ja3"] for item in vector["tls_transactions"]):
                stats.with_ja3 += 1
            if any(item["ja3s"] for item in vector["tls_transactions"]):
                stats.with_ja3s += 1
            if any(item["ja4"] for item in vector["tls_transactions"]):
                stats.with_ja4 += 1
            if any(item["server_name"] for item in vector["tls_transactions"]):
                stats.with_sni += 1
        if uid in http_index:
            raw, derived, count = http_index[uid]
            vector["http"] = _http_block(raw, derived, count)
            vector["http_transactions"] = [
                _http_transaction(transaction, transaction_features)
                for transaction, transaction_features in http_groups[uid]
            ]
            stats.with_http += 1

        stats.emitted += 1
        yield vector


@contextmanager
def open_output(path: str) -> Iterator[TextIO]:
    """Open a detector-v2 sink; ``-`` is a record-flushed stdout stream."""

    if path == "-":
        yield sys.stdout
        return
    handle = open(path, "w", encoding="utf-8")
    try:
        yield handle
    finally:
        handle.close()


def write_output(
    parsed: dict[str, list[dict]],
    output_path: str,
    window_secs: float,
    emit_window: bool,
) -> PipelineStats:
    """Project parsed logs and write one flushed JSON object per line."""

    stats = PipelineStats()
    joined = join_by_uid(parsed)
    with open_output(output_path) as handle:
        for record in build_records(
            joined,
            parsed,
            window_secs=window_secs,
            emit_window=emit_window,
            stats=stats,
        ):
            handle.write(json.dumps(record) + "\n")
            handle.flush()
    return stats
