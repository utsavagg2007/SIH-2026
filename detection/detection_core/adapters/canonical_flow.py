"""Bounded canonical JSONL -> detector events; the frozen schema owns field rules.

This repository-supported adapter handles flow envelopes from NetFlow v5/v9.
It does not implement IPFIX, protocol enrichment, counter scaling or inference.
Runtime validation covers the consumed flow subset; qualification additionally
uses the repository's full JSON-schema harness. No validation dependency added.
"""

from __future__ import annotations

import calendar
import copy
import ipaddress
import json
import math
import re
from datetime import datetime
from decimal import Decimal, localcontext
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

from ..schemas.canonical_flow import CanonicalFlowEvent

MAX_LINE_BYTES = 65_536
MAX_RECORDS = 100_000
MAX_TIME_LENGTH = 64
SUPPORTED_SOURCES = frozenset({"netflow_v5", "netflow_v9"})


@lru_cache(maxsize=1)
def _schema() -> dict:
    # Kept with the checkout, not a second independently versioned schema.
    path = Path(__file__).resolve().parents[3] / "contracts/canonical_observation_v1.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _fail(field: str, rule: str) -> None:
    # Never include untrusted source values / raw packet data in errors.
    raise ValueError(f"{field}: {rule}")


def _matches(value: Any, rule: dict) -> bool:
    try:
        _validate(value, rule, "field")
        return True
    except ValueError:
        return False


def _validate(value: Any, rule: dict, field: str) -> None:
    """Validate only the flow-subset keywords in the authoritative v1 schema."""
    if "$ref" in rule:
        _validate(value, _schema()["$defs"][rule["$ref"].split("/")[-1]], field)
        return
    if "const" in rule and (type(value) is not type(rule["const"]) or value != rule["const"]):
        _fail(field, "unexpected constant")
    if "enum" in rule and not any(type(value) is type(x) and value == x for x in rule["enum"]):
        _fail(field, "unsupported enum")
    kind = rule.get("type")
    types = kind if isinstance(kind, list) else [kind] if kind else []
    checks = {
        "object": type(value) is dict, "array": type(value) is list,
        "string": type(value) is str, "integer": type(value) is int,
        "number": type(value) in (int, float), "boolean": type(value) is bool,
        "null": value is None,
    }
    if types and not any(checks.get(t, False) for t in types):
        _fail(field, "incorrect JSON type")
    if type(value) in (int, float):
        if type(value) is float and not math.isfinite(value):
            _fail(field, "non-finite number")
        for key, valid in (("minimum", lambda x: value >= x),
                           ("maximum", lambda x: value <= x),
                           ("exclusiveMinimum", lambda x: value > x)):
            if key in rule and not valid(rule[key]):
                _fail(field, "number outside contract range")
    if type(value) is str:
        if len(value) < rule.get("minLength", 0):
            _fail(field, "empty string")
        if "pattern" in rule and re.search(rule["pattern"], value) is None:
            _fail(field, "invalid format")
        if rule.get("format") == "date-time":
            _epoch(value, field)
        if rule.get("format") in ("ipv4", "ipv6"):
            try:
                address = ipaddress.ip_address(value)
                if address.version != (4 if rule["format"] == "ipv4" else 6):
                    _fail(field, "wrong address family")
            except ValueError:
                _fail(field, "invalid address")
    if type(value) is dict:
        if any(k not in value for k in rule.get("required", ())):
            _fail(field, "missing required field")
        if len(value) < rule.get("minProperties", 0):
            _fail(field, "empty counter object")
        props = rule.get("properties", {})
        if rule.get("additionalProperties") is False and value.keys() - props.keys():
            _fail(field, "unknown field")
        for key in value.keys() & props.keys():
            _validate(value[key], props[key], f"{field}.{key}")
    if type(value) is list:
        if rule.get("uniqueItems") and len({json.dumps(x, sort_keys=True) for x in value}) != len(value):
            _fail(field, "duplicate array item")
        for item in value:
            _validate(item, rule.get("items", {}), field)
    if "oneOf" in rule and sum(_matches(value, x) for x in rule["oneOf"]) != 1:
        _fail(field, "no unique matching contract alternative")
    if "anyOf" in rule and not any(_matches(value, x) for x in rule["anyOf"]):
        _fail(field, "no matching contract alternative")
    if "not" in rule and _matches(value, rule["not"]):
        _fail(field, "forbidden field combination")
    for clause in rule.get("allOf", ()):
        _validate(value, clause, field)
    if "if" in rule:
        _validate(value, rule.get("then" if _matches(value, rule["if"]) else "else", {}), field)


def _epoch(value: str, field: str) -> Decimal:
    if len(value) > MAX_TIME_LENGTH:
        _fail(field, "timestamp resource limit")
    try:
        whole = datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
        seconds = Decimal(calendar.timegm(whole.timetuple()))
        fraction = value[19:-1]
        with localcontext() as ctx:
            ctx.prec = 80
            return seconds + (Decimal("0" + fraction) if fraction else Decimal(0))
    except (ValueError, OverflowError):
        _fail(field, "invalid UTC calendar timestamp")


def canonical_flow_to_flow_event(record: dict) -> CanonicalFlowEvent:
    if type(record) is not dict:
        _fail("observation", "must be an object")
    if record.get("observation_type") != "flow":
        _fail("observation_type", "only canonical flows are supported")
    if type(record.get("telemetry_source")) is not str or record["telemetry_source"] not in SUPPORTED_SOURCES:
        _fail("telemetry_source", "unsupported_telemetry_source")
    _validate(record, _schema(), "observation")
    data = record["data"]
    start = _epoch(data["start_time"], "data.start_time")
    end = _epoch(data["end_time"], "data.end_time") if "end_time" in data else None
    with localcontext() as ctx:
        ctx.prec = 80
        duration = end - start if end is not None else None
    if duration is not None and duration < 0:
        _fail("data.end_time", "precedes start_time")
    forward = data["counters"]["src_to_dst"]
    reverse = data["counters"].get("dst_to_src", {})
    proto = data["ip_protocol"]
    metadata = copy.deepcopy({k: v for k, v in record.items() if k != "data"})
    metadata.update({k: copy.deepcopy(v) for k, v in data.items()
                     if k in ("start_time", "end_time", "direction_mode", "ip_protocol", "counters")})
    return CanonicalFlowEvent(
        flow_id=record["record_id"], timestamp=float(start),
        src_ip=data["src_ip"], dst_ip=data["dst_ip"],
        src_port=data.get("src_port"), dst_port=data.get("dst_port"),
        proto={1: "icmp", 6: "tcp", 17: "udp", 58: "icmp6"}.get(proto, f"ip_protocol_{proto}"),
        duration=float(duration) if duration is not None else None,
        orig_pkts=forward.get("packets"), resp_pkts=reverse.get("packets"),
        orig_bytes=forward.get("payload_bytes"), resp_bytes=reverse.get("payload_bytes"),
        orig_ip_bytes=forward.get("ip_bytes"), resp_ip_bytes=reverse.get("ip_bytes"),
        service=data.get("service"), conn_state=data.get("connection_state"),
        source=record["telemetry_source"], canonical=metadata,
    )


def _object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("JSON", "duplicate object key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    _fail("JSON", "non-finite number")


class CanonicalFlowAdapter:
    """Fail-closed streaming reader. Invalid lines are NOT silently dropped."""

    def __init__(self, path: str | Path, *, max_records: int = MAX_RECORDS,
                 max_line_bytes: int = MAX_LINE_BYTES) -> None:
        if not 1 <= max_records <= MAX_RECORDS or not 1 <= max_line_bytes <= MAX_LINE_BYTES:
            raise ValueError("invalid canonical input limits")
        self.path = Path(path)
        self.max_records = max_records
        self.max_line_bytes = max_line_bytes

    def __iter__(self) -> Iterator[CanonicalFlowEvent]:
        with self.path.open("rb") as stream:
            for ordinal in range(self.max_records + 1):
                line = stream.readline(self.max_line_bytes + 1)
                if not line:
                    return
                if ordinal == self.max_records:
                    _fail("JSONL", "record limit exceeded")
                if len(line) > self.max_line_bytes:
                    _fail("JSONL", "line limit exceeded")
                try:
                    record = json.loads(line.decode("utf-8"), object_pairs_hook=_object,
                                        parse_constant=_constant)
                    yield canonical_flow_to_flow_event(record)
                except (ValueError, RecursionError) as exc:
                    # No raw source values, even for JSON decoder errors.
                    raise ValueError(f"canonical JSONL line {ordinal + 1}: invalid observation") from exc
