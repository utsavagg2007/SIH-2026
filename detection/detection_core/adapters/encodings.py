"""Inverse lookup tables for ingestion's integer encodings.

This module is ingestion-format knowledge and MUST NOT be imported outside
``detection_core.adapters``. Detectors depend on FlowEvent, not on how
ingestion happens to encode a conn_state today.

Tables transcribed (read-only) from injestion_core/README.md.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "CONN_STATE_BY_CODE",
    "SSL_VERSION_BY_CODE",
    "HTTP_METHOD_BY_CODE",
    "KNOWN_TOP_LEVEL_FIELDS",
    "IGNORED_WINDOW_FIELDS",
    "decode_conn_state",
    "decode_ssl_version",
    "decode_http_method",
]

# NOTE: ingestion's integer mapping still has no entry for Zeek's "S0"
# (connection attempt, no reply) - `encode_conn_state` in
# `ingestion/src/features/flow.rs` has no S0 arm, so under the frozen
# `legacy-m1d` feature profile S0 encodes to 0 and decodes back to None here,
# indistinguishable from "unknown".
#
# The `detector-v2` profile does not go through this table at all: it emits the
# raw `conn_state` string alongside `conn_state_encoded`, and
# `record_to_flow_event` prefers the raw value, so S0 survives intact. This
# table is therefore the *fallback* path, not the only one.
#
# S0 is a primary port-scan signal, so a scan detector must still treat an
# absent or unclassified conn_state as "no evidence" and fall back to the
# responder-byte proxy rather than concluding the responder answered. See
# `aggregators.sliding_window.CLASSIFIED_CONN_STATES`.
CONN_STATE_BY_CODE: dict[int, str] = {
    1: "S1",
    2: "S2",
    3: "S3",
    4: "SF",
    5: "REJ",
    6: "RSTO",
    7: "RSTOS0",
    8: "RSTR",
    9: "RSTRH",
    10: "SH",
    11: "SHR",
    12: "OTH",
}

SSL_VERSION_BY_CODE: dict[int, str] = {
    1: "TLSv10",
    2: "TLSv11",
    3: "TLSv12",
    4: "TLSv13",
    5: "SSLv3",
}

HTTP_METHOD_BY_CODE: dict[int, str] = {
    1: "GET",
    2: "POST",
    3: "HEAD",
    4: "PUT",
    5: "DELETE",
    6: "OPTIONS",
    7: "CONNECT",
    8: "TRACE",
    9: "PATCH",
}

# Top-level keys the adapter recognizes. Includes forward-compatible names
# (uid, src_port, service, conn_state, ts/timestamp) that current ingestion
# does not emit yet: if they appear, the adapter uses them and no drift
# warning fires.
KNOWN_TOP_LEVEL_FIELDS: frozenset[str] = frozenset(
    {
        "flow_id",
        "src_ip",
        "dst_ip",
        "dst_port",
        "proto",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "byte_ratio",
        "orig_pkts",
        "resp_pkts",
        "pkt_ratio",
        "conn_state_encoded",
        "dns",
        "tls",
        "http",
        # Emitted by ingestion's `detector-v2` feature profile; absent under
        # the frozen `legacy-m1d` one, which is why they are listed rather
        # than required.
        "uid",
        "src_port",
        "service",
        "conn_state",
        "ts",
        "timestamp",
        # Layer-3 byte counters, carried by detector-v2 next to the payload
        # counters. Listed here so they do not raise a drift warning on every
        # single record - which is all this set does. Being recognized also
        # keeps them out of FlowEvent.extra, and that is the intent: every
        # volume threshold in this project is defined on payload bytes
        # (orig_bytes / resp_bytes), and a header-inclusive counter sitting
        # next to them in extra is an invitation to compare the wrong two
        # numbers. Read them from the ingestion record if they are ever
        # genuinely needed.
        "orig_ip_bytes",
        "resp_ip_bytes",
    }
)

# Ingestion's global sliding-window features. Deliberately NOT mapped onto
# FlowEvent and NOT copied into FlowEvent.extra: the upstream window logic is
# still being corrected, so nothing downstream may depend on these values.
# Listed here only so they do not trigger a schema-drift warning.
# Correct source/destination/pair-keyed state will live in aggregators/.
IGNORED_WINDOW_FIELDS: frozenset[str] = frozenset(
    {
        "flow_rate",
        "byte_rate",
        "inter_arrival_mean",
        "inter_arrival_stddev",
        "unique_dst_ports",
        "unique_dst_ips",
        "src_ip_entropy",
    }
)

# Keys expected on every well-formed line; absence signals upstream drift.
EXPECTED_CORE_FIELDS: frozenset[str] = frozenset(
    {
        "flow_id",
        "src_ip",
        "dst_ip",
        "proto",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
    }
)


def _decode(table: dict[int, str], code: Any) -> str | None:
    """Look ``code`` up in ``table``; unknown or non-integer codes give None.

    These all back optional FlowEvent fields, so None means "not available",
    which is allowed. Booleans are rejected explicitly because ``bool`` is a
    subclass of ``int`` in Python.
    """
    if code is None or isinstance(code, bool) or not isinstance(code, int):
        return None
    return table.get(code)


def decode_conn_state(code: Any) -> str | None:
    """Integer conn_state code -> Zeek conn_state string (0/unknown -> None)."""
    return _decode(CONN_STATE_BY_CODE, code)


def decode_ssl_version(code: Any) -> str | None:
    """Integer SSL version code -> version string (0/unknown -> None)."""
    return _decode(SSL_VERSION_BY_CODE, code)


def decode_http_method(code: Any) -> str | None:
    """Integer HTTP method code -> method string (0/unknown -> None)."""
    return _decode(HTTP_METHOD_BY_CODE, code)
