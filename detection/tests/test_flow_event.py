"""FlowEvent schema tests.

The core contract under test: required fields validate strictly and are
never silently degraded to None; optional fields default to None and are
never invented.
"""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from detection_core import DnsInfo, FlowEvent, HttpInfo, TlsInfo

from .conftest import make_flow


def test_minimal_valid_flow():
    flow = make_flow()
    assert flow.src_ip == "10.0.0.1"
    assert flow.dst_ip == "10.0.0.2"
    assert flow.proto == "tcp"
    assert flow.orig_bytes == 100
    assert flow.total_bytes == 300
    assert flow.total_pkts == 5


@pytest.mark.parametrize(
    "field",
    [
        "timestamp",
        "src_ip",
        "dst_ip",
        "proto",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
    ],
)
def test_required_core_field_missing_raises(field):
    payload = make_flow().model_dump()
    payload.pop(field)
    with pytest.raises(ValidationError):
        FlowEvent(**payload)


@pytest.mark.parametrize(
    "field",
    [
        "timestamp",
        "src_ip",
        "dst_ip",
        "proto",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
    ],
)
def test_required_core_field_none_raises(field):
    """None for a core field must raise, never be accepted."""
    with pytest.raises(ValidationError):
        make_flow(**{field: None})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("orig_bytes", "not-a-number"),
        ("resp_bytes", "abc"),
        ("orig_pkts", []),
        ("duration", "soon"),
        ("timestamp", {}),
        ("src_ip", 12345),
    ],
)
def test_malformed_core_field_raises(field, value):
    with pytest.raises(ValidationError):
        make_flow(**{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("orig_bytes", -1),
        ("resp_bytes", -1),
        ("orig_pkts", -1),
        ("resp_pkts", -1),
        ("duration", -0.5),
    ],
)
def test_negative_counters_rejected(field, value):
    with pytest.raises(ValidationError):
        make_flow(**{field: value})


# --------------------------------------------------------------------------
# Strict numerics: no silent string coercion on core fields or ports
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("orig_bytes", "123"),
        ("resp_bytes", "0"),
        ("orig_pkts", "1"),
        ("resp_pkts", "2"),
        ("duration", "1.5"),
        ("timestamp", "123"),
        ("timestamp", "1747147700.5"),
        ("dst_port", "443"),
        ("src_port", "1024"),
        ("orig_ip_bytes", "123"),
        ("resp_ip_bytes", "456"),
    ],
)
def test_numeric_strings_rejected_not_coerced(field, value):
    """A quoted number means a malformed producer - skip it, do not launder it."""
    with pytest.raises(ValidationError):
        make_flow(**{field: value})


@pytest.mark.parametrize(
    "field",
    ["orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "duration", "timestamp"],
)
def test_boolean_rejected_for_numeric_fields(field):
    """bool subclasses int in Python; True must not become 1."""
    with pytest.raises(ValidationError):
        make_flow(**{field: True})


def test_genuine_json_numbers_still_accepted():
    """Strictness must not reject legitimate int/float JSON values."""
    flow = make_flow(
        timestamp=1747147700,  # int for a float field
        duration=0,  # int for a float field
        orig_bytes=71,
        resp_bytes=377.0,  # lossless float for an int field
        dst_port=443,
        src_port=51514,
    )
    assert flow.timestamp == 1747147700.0
    assert flow.duration == 0.0
    assert flow.resp_bytes == 377
    assert flow.src_port == 51514


def test_optional_ports_still_accept_none():
    """Strict numerics must not make unavailable optional fields required."""
    flow = make_flow(src_port=None, dst_port=None)
    assert flow.src_port is None
    assert flow.dst_port is None


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_timestamp_rejected(value):
    with pytest.raises(ValidationError):
        make_flow(timestamp=value)


@pytest.mark.parametrize("value", [math.nan, math.inf])
def test_non_finite_duration_rejected(value):
    with pytest.raises(ValidationError):
        make_flow(duration=value)


@pytest.mark.parametrize("field", ["src_ip", "dst_ip", "proto"])
def test_blank_string_rejected(field):
    with pytest.raises(ValidationError):
        make_flow(**{field: "   "})


@pytest.mark.parametrize(("field", "value"), [("src_port", -1), ("dst_port", 70000)])
def test_port_range_enforced(field, value):
    with pytest.raises(ValidationError):
        make_flow(**{field: value})


def test_optional_fields_default_to_none():
    """Fields current ingestion cannot supply are None, not invented."""
    flow = make_flow()
    assert flow.uid is None
    assert flow.src_port is None
    assert flow.service is None
    assert flow.conn_state is None
    assert flow.orig_ip_bytes is None
    assert flow.resp_ip_bytes is None
    assert flow.dns is None
    assert flow.tls is None
    assert flow.http is None
    assert flow.extra == {}
    assert flow.source == "unknown"


def test_nested_blocks_attach():
    flow = make_flow(
        dns=DnsInfo(uid="C1", query_length=20, is_txt=True),
        tls=TlsInfo(uid="C1", version="TLSv13", has_ja3=True),
        http=HttpInfo(uid="C1", method="POST", status_code=200),
    )
    assert flow.dns.is_txt is True
    assert flow.tls.version == "TLSv13"
    assert flow.http.method == "POST"
    # Raw-string integration TODOs stay None until ingestion supplies them.
    assert flow.dns.query is None
    assert flow.tls.ja3 is None
    assert flow.http.uri is None


def test_flow_event_is_frozen(flow):
    """The engine hands one instance to every detector; it must be immutable."""
    with pytest.raises(ValidationError):
        flow.src_ip = "192.168.0.1"


def test_nested_blocks_are_frozen():
    dns = DnsInfo(uid="C1")
    with pytest.raises(ValidationError):
        dns.uid = "C2"


def test_no_window_block_on_flow_event():
    """Regression guard: ingestion's global window features are not canonical."""
    assert "window" not in FlowEvent.model_fields
    flow = make_flow()
    assert not hasattr(flow, "window")


def test_unknown_constructor_fields_ignored():
    flow = FlowEvent(
        timestamp=1.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        proto="tcp",
        duration=0.0,
        orig_bytes=0,
        resp_bytes=0,
        orig_pkts=0,
        resp_pkts=0,
        something_new="ignored",
    )
    assert not hasattr(flow, "something_new")
