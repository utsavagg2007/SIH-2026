"""FlowEvent: one normalized network flow.

This is the ONLY input type detectors are allowed to depend on. Nothing
downstream of the adapter layer should know that ``features.jsonl`` exists.

Design rules baked into these models:

* Core fields are required and strictly validated. Malformed core data
  raises; it is never coerced to ``None``, and a stringly-typed number such
  as ``"123"`` is rejected rather than quietly converted.
* Optional fields are ``| None`` because source runtimes and compatibility
  profiles differ in availability. Absent means ``None``; nothing is invented.
* Models are frozen. The engine hands the same FlowEvent instance to every
  registered detector, so immutability stops one detector corrupting the
  input of the next.
"""

from __future__ import annotations

import math
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = ["DnsInfo", "TlsInfo", "HttpInfo", "FlowEvent"]

_BLOCK_CONFIG = ConfigDict(frozen=True, extra="ignore")

# Core numeric fields (and the ports) that must arrive as real JSON numbers.
_NUMERIC_CORE_FIELDS = (
    "timestamp",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "src_port",
    "dst_port",
)


def _require_json_number(value: Any) -> Any:
    """Reject stringly-typed and boolean numbers before Pydantic coerces them.

    Pydantic's lax mode would happily turn ``"123"`` into ``123`` and
    ``"1.5"`` into ``1.5``. For core flow fields that is exactly the silent
    conversion we refuse: a quoted number means the upstream producer is
    malformed, and we would rather skip the record loudly than detect on
    laundered data. ``bool`` is rejected explicitly because it is a subclass
    of ``int`` in Python.

    Genuine JSON numbers pass straight through, so an ``int`` still satisfies
    a float field (``"duration": 0``) and a lossless float still satisfies an
    int field.
    """
    if isinstance(value, bool):
        raise ValueError("must be a JSON number, not a boolean")
    if isinstance(value, str):
        raise ValueError(f"must be a JSON number, not a string ({value!r})")
    return value


class DnsInfo(BaseModel):
    """DNS data attached to a flow.

    The detector-v2 profile supplies raw query/type/result metadata and
    derived features; old scalar-only records may still omit any field.
    """

    model_config = _BLOCK_CONFIG

    uid: str | None = None
    event_time: float | None = None
    source_ordinal: int | None = Field(default=None, ge=0)
    src_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    proto: str | None = None

    # Raw values supplied by the explicit detector-v2 ingestion profile.
    query: str | None = None
    qtype: str | None = None
    rcode: str | None = None
    qtype_num: str | None = None
    rcode_num: str | None = None
    transaction_count: int | None = Field(default=None, ge=1)
    authoritative_answer: bool | None = None
    truncated: bool | None = None
    recursion_desired: bool | None = None
    recursion_available: bool | None = None
    z: int | None = Field(default=None, ge=0, le=255)
    answer_count: int | None = Field(default=None, ge=0)
    rejected: bool | None = None

    # Derived features - supplied by current ingestion.
    query_length: int | None = Field(default=None, ge=0)
    query_entropy: float | None = None
    subdomain_entropy: float | None = None
    is_txt: bool | None = None
    label_count: int | None = Field(default=None, ge=0)

    @field_validator("event_time", "query_entropy", "subdomain_entropy")
    @classmethod
    def _finite_optional_float(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("must be a finite number")
        return value


class TlsInfo(BaseModel):
    """TLS data attached to a flow.

    The explicit detector-v2 ingestion profile supplies raw JA3/JA3S/JA4/SNI
    when its source telemetry contains them. The standard runtime may omit
    fingerprints, while the qualified modes provide JA4 alone or JA3/JA3S/JA4.
    SNI length and entropy are supplied only when a real server name exists.

    Everything optional here defaults to ``None`` meaning *not available*.
    Nothing is ever invented, and no absent value is defaulted to 0.
    """

    model_config = _BLOCK_CONFIG

    uid: str | None = None
    event_time: float | None = None
    source_ordinal: int | None = Field(default=None, ge=0)
    src_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    proto: str | None = None

    # Raw values supplied by the explicit detector-v2 ingestion profile.
    ja3: str | None = None
    ja3s: str | None = None
    ja4: str | None = None
    server_name: str | None = None
    cipher: str | None = None
    transaction_count: int | None = Field(default=None, ge=1)

    # Decoded from ssl_version_encoded by the adapter.
    version: str | None = None

    # Derived features - supplied by current ingestion.
    has_ja3: bool | None = None
    has_ja3s: bool | None = None

    # Derived SNI features supplied only for an observed server name.
    # the adapter can carry them the day it is emitted; detection_core can
    # also compute the same two numbers itself from a raw ``server_name``.
    sni_length: int | None = Field(default=None, ge=0)
    sni_entropy: float | None = None

    @field_validator("event_time", "sni_entropy")
    @classmethod
    def _finite_optional_float(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("must be a finite number")
        return value


class HttpInfo(BaseModel):
    """HTTP data attached to a flow.

    The detector-v2 profile supplies raw request metadata and derived
    features; old scalar-only records may still omit any field.
    """

    model_config = _BLOCK_CONFIG

    uid: str | None = None
    event_time: float | None = None
    source_ordinal: int | None = Field(default=None, ge=0)
    src_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    proto: str | None = None

    # Raw values supplied by the explicit detector-v2 ingestion profile.
    host: str | None = None
    uri: str | None = None
    user_agent: str | None = None

    # Decoded from method_encoded by the adapter.
    method: str | None = None

    # Derived features - supplied by current ingestion.
    host_length: int | None = Field(default=None, ge=0)
    uri_length: int | None = Field(default=None, ge=0)
    uri_entropy: float | None = None
    has_user_agent: bool | None = None
    user_agent_length: int | None = Field(default=None, ge=0)
    request_body_len: int | None = Field(default=None, ge=0)
    response_body_len: int | None = Field(default=None, ge=0)
    status_code: int | None = Field(default=None, ge=0)
    transaction_count: int | None = Field(default=None, ge=1)

    @field_validator("event_time", "uri_entropy")
    @classmethod
    def _finite_optional_float(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("must be a finite number")
        return value


class FlowEvent(BaseModel):
    """One normalized network flow, independent of any ingestion format."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    # --- identity -------------------------------------------------------
    flow_id: str | None = None
    uid: str | None = None

    # --- core (required, strictly validated) ----------------------------
    timestamp: float
    src_ip: str
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_ip: str
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    proto: str
    service: str | None = None
    duration: float = Field(ge=0.0)
    orig_bytes: int = Field(ge=0)
    resp_bytes: int = Field(ge=0)
    orig_pkts: int = Field(ge=0)
    resp_pkts: int = Field(ge=0)
    orig_ip_bytes: int | None = Field(default=None, ge=0)
    resp_ip_bytes: int | None = Field(default=None, ge=0)
    conn_state: str | None = None

    # --- optional protocol blocks ---------------------------------------
    dns: DnsInfo | None = None
    tls: TlsInfo | None = None
    http: HttpInfo | None = None
    dns_transactions: list[DnsInfo] = Field(default_factory=list)
    tls_transactions: list[TlsInfo] = Field(default_factory=list)
    http_transactions: list[HttpInfo] = Field(default_factory=list)

    # --- provenance / forward compatibility -----------------------------
    source: str = "unknown"
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator(*_NUMERIC_CORE_FIELDS, mode="before")
    @classmethod
    def _strict_numbers(cls, value: Any) -> Any:
        """Core numbers must be real JSON numbers, never coerced strings."""
        if value is None:
            # Optional ports may legitimately be absent; required fields still
            # fail below on the missing/None type check.
            return value
        return _require_json_number(value)

    @field_validator("timestamp", "duration")
    @classmethod
    def _finite(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("must be a finite number")
        return value

    @field_validator("src_ip", "dst_ip", "proto")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("must be a non-empty string")
        return stripped

    @property
    def total_bytes(self) -> int:
        return self.orig_bytes + self.resp_bytes

    @property
    def total_pkts(self) -> int:
        return self.orig_pkts + self.resp_pkts

    @property
    def dns_observations(self) -> tuple[DnsInfo, ...]:
        """All DNS rows, falling back to the compatibility scalar for old input."""
        if self.dns_transactions:
            return tuple(self.dns_transactions)
        return (self.dns,) if self.dns is not None else ()

    @property
    def tls_observations(self) -> tuple[TlsInfo, ...]:
        """All TLS rows, falling back to the compatibility scalar for old input."""
        if self.tls_transactions:
            return tuple(self.tls_transactions)
        return (self.tls,) if self.tls is not None else ()

    @property
    def http_observations(self) -> tuple[HttpInfo, ...]:
        """All HTTP rows, falling back to the compatibility scalar for old input."""
        if self.http_transactions:
            return tuple(self.http_transactions)
        return (self.http,) if self.http is not None else ()
