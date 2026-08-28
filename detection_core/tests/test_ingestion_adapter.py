"""IngestionJsonlAdapter tests.

Covers the real ingestion sample, decoding, graceful degradation, schema
drift warnings and the strict/lenient malformed-record contract.
"""

from __future__ import annotations

import json
import logging

import pytest
from pydantic import ValidationError

from detection_core import FlowEvent
from detection_core.adapters import (
    SOURCE_NAME,
    FlowSource,
    IngestionJsonlAdapter,
    record_to_flow_event,
)
from detection_core.adapters.encodings import (
    IGNORED_WINDOW_FIELDS,
    decode_conn_state,
    decode_http_method,
    decode_ssl_version,
)


# --------------------------------------------------------------------------
# Encoding tables
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "expected"),
    [(4, "SF"), (5, "REJ"), (12, "OTH"), (0, None), (99, None), (None, None)],
)
def test_decode_conn_state(code, expected):
    assert decode_conn_state(code) == expected


@pytest.mark.parametrize(
    ("code", "expected"), [(3, "TLSv12"), (4, "TLSv13"), (5, "SSLv3"), (0, None)]
)
def test_decode_ssl_version(code, expected):
    assert decode_ssl_version(code) == expected


@pytest.mark.parametrize(
    ("code", "expected"), [(1, "GET"), (2, "POST"), (9, "PATCH"), (0, None)]
)
def test_decode_http_method(code, expected):
    assert decode_http_method(code) == expected


def test_decode_rejects_bools():
    """bool is a subclass of int; True must not decode as code 1."""
    assert decode_conn_state(True) is None
    assert decode_http_method(True) is None


# --------------------------------------------------------------------------
# The real ingestion sample
# --------------------------------------------------------------------------


def test_provenance_names_the_actual_repo_directory():
    """The directory on disk is spelled 'injestion_core'."""
    assert SOURCE_NAME == "injestion_core.features_jsonl"


def test_parses_real_sample(sample_path):
    adapter = IngestionJsonlAdapter()
    flows = list(adapter.from_path(sample_path))

    assert len(flows) == 2
    assert adapter.stats.parsed == 2
    assert adapter.stats.errors == 0
    assert all(isinstance(flow, FlowEvent) for flow in flows)


def test_sample_field_mapping(sample_path):
    flow = next(iter(IngestionJsonlAdapter().from_path(sample_path)))

    assert flow.flow_id == "192.168.1.8:192.0.78.212:80:tcp:1747147647.669"
    assert flow.timestamp == pytest.approx(1747147647.669)
    assert flow.src_ip == "192.168.1.8"
    assert flow.dst_ip == "192.0.78.212"
    assert flow.dst_port == 80
    assert flow.proto == "tcp"
    assert flow.duration == pytest.approx(0.098478)
    assert flow.orig_bytes == 71
    assert flow.resp_bytes == 377
    assert flow.orig_pkts == 6
    assert flow.resp_pkts == 4
    assert flow.conn_state == "SF"
    assert flow.source == SOURCE_NAME

    # Not supplied by current ingestion - must stay None, never invented.
    assert flow.src_port is None
    assert flow.service is None

    # uid is back-filled from the nested block, since there is no top-level one.
    assert flow.uid == "C7ZPaz39Ox50iiiCP4"

    assert flow.http is not None
    assert flow.http.method == "GET"
    assert flow.http.status_code == 301
    assert flow.http.request_body_len == 0
    assert flow.http.response_body_len == 162
    assert flow.http.host is None  # integration TODO
    assert flow.dns is None
    assert flow.tls is None


def test_unknown_method_code_maps_to_none(sample_path):
    """Line 2 has method_encoded 0; unknown must be None, not a guess."""
    flows = list(IngestionJsonlAdapter().from_path(sample_path))
    assert flows[1].http.method is None


def test_window_features_are_not_consumed(sample_path):
    """Ingestion's global window logic is not canonical: ignore, don't expose."""
    flow = next(iter(IngestionJsonlAdapter().from_path(sample_path)))
    assert not hasattr(flow, "window")
    for field in IGNORED_WINDOW_FIELDS:
        assert field not in flow.extra


# --------------------------------------------------------------------------
# Edge cases
# --------------------------------------------------------------------------


def test_all_edge_cases_parse(edge_cases_path):
    adapter = IngestionJsonlAdapter()
    flows = list(adapter.from_path(edge_cases_path))
    assert len(flows) == 9
    assert adapter.stats.errors == 0


def test_dns_only_flow(edge_cases_path):
    flow = list(IngestionJsonlAdapter().from_path(edge_cases_path))[0]
    assert flow.dns is not None
    assert flow.dns.is_txt is True
    assert flow.dns.label_count == 5
    assert flow.dns.query_entropy == pytest.approx(3.91)
    assert flow.dns.query is None  # integration TODO
    assert flow.tls is None and flow.http is None
    assert flow.uid == "CdnsOnly01"


def test_tls_only_flow(edge_cases_path):
    flow = list(IngestionJsonlAdapter().from_path(edge_cases_path))[1]
    assert flow.tls is not None
    assert flow.tls.version == "TLSv12"
    assert flow.tls.has_ja3 is True
    assert flow.tls.ja3 is None  # integration TODO
    assert flow.tls.ja4 is None  # integration TODO


def test_all_three_blocks(edge_cases_path):
    flow = list(IngestionJsonlAdapter().from_path(edge_cases_path))[2]
    assert flow.dns is not None and flow.tls is not None and flow.http is not None
    assert flow.uid == "CallThree03"
    assert flow.http.method == "POST"
    assert flow.tls.version == "TLSv13"


def test_flow_with_no_blocks(edge_cases_path):
    flow = list(IngestionJsonlAdapter().from_path(edge_cases_path))[3]
    assert (flow.dns, flow.tls, flow.http) == (None, None, None)
    assert flow.conn_state == "REJ"
    assert flow.uid is None


def test_unknown_conn_state_is_none(edge_cases_path):
    """conn_state_encoded 0 means unknown - do not invent a state."""
    flow = list(IngestionJsonlAdapter().from_path(edge_cases_path))[4]
    assert flow.conn_state is None


def test_ipv6_timestamp_uses_last_colon(edge_cases_path):
    """flow_id embeds IPv6 addresses; only the LAST colon delimits the epoch."""
    flow = list(IngestionJsonlAdapter().from_path(edge_cases_path))[5]
    assert flow.src_ip == "2001:db8::1"
    assert flow.dst_ip == "2001:db8::2"
    assert flow.timestamp == pytest.approx(1747147705.600)


def test_unknown_field_kept_in_extra(edge_cases_path):
    flow = list(IngestionJsonlAdapter().from_path(edge_cases_path))[6]
    assert flow.extra == {"future_ingestion_field": "surprise"}


def test_window_fields_excluded_from_extra(edge_cases_path):
    flow = list(IngestionJsonlAdapter().from_path(edge_cases_path))[7]
    assert flow.extra == {}


def test_forward_compatible_top_level_fields(edge_cases_path):
    """If ingestion later emits raw fields, the adapter prefers them."""
    flow = list(IngestionJsonlAdapter().from_path(edge_cases_path))[8]
    assert flow.uid == "CforwardCompat09"
    assert flow.src_port == 51514
    assert flow.service == "ssl"
    # Explicit conn_state wins over the encoded fallback (which said SF).
    assert flow.conn_state == "S1"


def test_explicit_timestamp_preferred_over_flow_id():
    record = {
        "flow_id": "10.0.0.1:10.0.0.2:80:tcp:1000.0",
        "timestamp": 2000.5,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "proto": "tcp",
        "duration": 0.1,
        "orig_bytes": 1,
        "resp_bytes": 1,
        "orig_pkts": 1,
        "resp_pkts": 1,
    }
    assert record_to_flow_event(record).timestamp == pytest.approx(2000.5)


# --------------------------------------------------------------------------
# Malformed records
# --------------------------------------------------------------------------


def test_malformed_records_are_skipped_not_fatal(malformed_path, caplog):
    adapter = IngestionJsonlAdapter()
    with caplog.at_level(logging.WARNING):
        flows = list(adapter.from_path(malformed_path))

    assert flows == []
    assert adapter.stats.total_lines == 9
    assert adapter.stats.blank_lines == 1
    assert adapter.stats.parsed == 0
    assert adapter.stats.json_errors == 1
    assert adapter.stats.validation_errors == 7
    assert adapter.stats.skipped == 8
    assert caplog.records


def test_good_records_survive_bad_neighbours(malformed_path, sample_path):
    """One bad line must not stop the run."""
    lines = malformed_path.read_text(encoding="utf-8").splitlines()
    lines += sample_path.read_text(encoding="utf-8").splitlines()

    adapter = IngestionJsonlAdapter()
    flows = list(adapter.from_lines(lines))

    assert len(flows) == 2
    assert adapter.stats.parsed == 2
    assert adapter.stats.errors == 8


def test_strict_mode_raises_on_bad_json(malformed_path):
    adapter = IngestionJsonlAdapter(strict=True)
    with pytest.raises(json.JSONDecodeError):
        list(adapter.from_path(malformed_path))


def test_strict_mode_raises_on_invalid_flow():
    bad = json.dumps(
        {
            "flow_id": "10.0.0.1:10.0.0.2:80:tcp:1000.0",
            "dst_ip": "10.0.0.2",
            "proto": "tcp",
            "duration": 0.1,
            "orig_bytes": 1,
            "resp_bytes": 1,
            "orig_pkts": 1,
            "resp_pkts": 1,
        }
    )
    adapter = IngestionJsonlAdapter(strict=True)
    with pytest.raises(ValidationError):
        list(adapter.from_lines([bad]))


@pytest.mark.parametrize(
    ("field", "value"),
    [("orig_bytes", "123"), ("duration", "1.5"), ("dst_port", "443")],
)
def test_stringly_typed_numbers_are_skipped_by_adapter(field, value, caplog):
    """Strict core validation reaches all the way through the adapter."""
    record = {
        "flow_id": "10.0.0.1:10.0.0.2:80:tcp:1000.0",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "proto": "tcp",
        "duration": 0.1,
        "orig_bytes": 1,
        "resp_bytes": 1,
        "orig_pkts": 1,
        "resp_pkts": 1,
    }
    record[field] = value

    adapter = IngestionJsonlAdapter()
    with caplog.at_level(logging.WARNING):
        flows = list(adapter.from_lines([json.dumps(record)]))

    assert flows == []
    assert adapter.stats.validation_errors == 1


def test_missing_timestamp_raises():
    with pytest.raises(ValueError, match="timestamp"):
        record_to_flow_event(
            {
                "flow_id": "no-colons-here",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "proto": "tcp",
                "duration": 0.1,
                "orig_bytes": 1,
                "resp_bytes": 1,
                "orig_pkts": 1,
                "resp_pkts": 1,
            }
        )


def test_non_object_nested_block_raises():
    with pytest.raises(ValueError, match="must be a JSON object"):
        record_to_flow_event(
            {
                "flow_id": "10.0.0.1:10.0.0.2:80:tcp:1000.0",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "proto": "tcp",
                "duration": 0.1,
                "orig_bytes": 1,
                "resp_bytes": 1,
                "orig_pkts": 1,
                "resp_pkts": 1,
                "dns": "not-an-object",
            }
        )


# --------------------------------------------------------------------------
# Schema drift
# --------------------------------------------------------------------------


def test_drift_warning_on_unknown_field(edge_cases_path, caplog):
    adapter = IngestionJsonlAdapter()
    with caplog.at_level(logging.WARNING):
        list(adapter.from_path(edge_cases_path))

    assert any("future_ingestion_field" in msg for msg in adapter.stats.drift_warnings)


def test_drift_warning_on_missing_field():
    record = {
        "timestamp": 100.0,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "proto": "tcp",
        "duration": 0.1,
        "orig_bytes": 1,
        "resp_bytes": 1,
        "orig_pkts": 1,
        "resp_pkts": 1,
    }
    adapter = IngestionJsonlAdapter()
    list(adapter.from_lines([json.dumps(record)]))
    assert any("flow_id" in msg for msg in adapter.stats.drift_warnings)


def test_drift_warning_emitted_once_per_key():
    record = {
        "flow_id": "10.0.0.1:10.0.0.2:80:tcp:1000.0",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "proto": "tcp",
        "duration": 0.1,
        "orig_bytes": 1,
        "resp_bytes": 1,
        "orig_pkts": 1,
        "resp_pkts": 1,
        "brand_new": 1,
    }
    line = json.dumps(record)
    adapter = IngestionJsonlAdapter()
    list(adapter.from_lines([line, line, line]))
    assert len(adapter.stats.drift_warnings) == 1


def test_drift_warnings_can_be_disabled(edge_cases_path):
    adapter = IngestionJsonlAdapter(warn_on_drift=False)
    list(adapter.from_path(edge_cases_path))
    assert adapter.stats.drift_warnings == []


# --------------------------------------------------------------------------
# FlowSource protocol
# --------------------------------------------------------------------------


def test_adapter_with_path_is_a_flow_source(sample_path):
    adapter = IngestionJsonlAdapter(path=sample_path)
    assert isinstance(adapter, FlowSource)
    assert len(list(adapter)) == 2


def test_adapter_without_path_cannot_iterate():
    with pytest.raises(ValueError, match="no path"):
        list(IngestionJsonlAdapter())


def test_plain_list_is_a_flow_source():
    assert isinstance([], FlowSource)


def test_stats_reset_between_runs(sample_path):
    adapter = IngestionJsonlAdapter()
    list(adapter.from_path(sample_path))
    list(adapter.from_path(sample_path))
    assert adapter.stats.parsed == 2
