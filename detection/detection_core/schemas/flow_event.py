"""FlowEvent: one normalized network flow.

This is the ONLY input type detectors are allowed to depend on. Nothing
downstream of the adapter layer should know that ``features.jsonl`` exists.

Design rules baked into these models:

* Core fields are required and strictly validated. Malformed core data
  raises; it is never coerced to ``None``, and a stringly-typed number such
  as ``"123"`` is rejected rather than quietly converted.
* Optional fields are ``| None`` because current ingestion does not supply
  them yet (see SCHEMA.md "Integration TODOs"). Absent means ``None``.
  Nothing is ever invented.
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

    ``query`` / ``qtype`` / ``rcode`` are integration TODOs: current
    ingestion emits only derived features, not the raw strings.
    """

    model_config = _BLOCK_CONFIG

    uid: str | None = None

    # Raw values supplied by the explicit detector-v2 ingestion profile.
    query: str | None = None
    qtype: str | None = None
    rcode: str | None = None
    qtype_num: str | None = None
    rcode_num: str | None = None
    transaction_count: int | None = Field(default=None, ge=1)

    # Derived features - supplied by current ingestion.
    query_length: int | None = Field(default=None, ge=0)
    query_entropy: float | None = None
    subdomain_entropy: float | None = None
    is_txt: bool | None = None
    label_count: int | None = Field(default=None, ge=0)


class TlsInfo(BaseModel):
    """TLS data attached to a flow.

    The explicit detector-v2 ingestion profile supplies raw JA3/JA3S/JA4/SNI
    when its source telemetry contains them. The standard runtime may omit
    fingerprints, while the separately qualified JA4 runtime can provide JA4.
    SNI length and entropy are supplied only when a real server name exists.

    Everything optional here defaults to ``None`` meaning *not available*.
    Nothing is ever invented, and no absent value is defaulted to 0.
    """

    model_config = _BLOCK_CONFIG

    uid: str | None = None

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


class HttpInfo(BaseModel):
    """HTTP data attached to a flow.

    ``host`` / ``uri`` / ``user_agent`` are integration TODOs: current
    ingestion emits only lengths and entropies.
    """

    model_config = _BLOCK_CONFIG

    uid: str | None = None

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
