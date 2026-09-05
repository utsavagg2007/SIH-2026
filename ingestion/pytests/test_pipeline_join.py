"""Regression tests for the four silent defects in the ingestion join.

Each test names the defect it locks down. Every one of these would have passed
trivially before the fix by asserting nothing about the field in question -
which is exactly how they survived - so they assert on the emitted record, the
thing detection_core actually reads.
"""

from __future__ import annotations

import json

# Zeek writes a connection record when the connection CLOSES, but `ts` is when
# it OPENED. So a long-lived connection appears later in the file than short
# ones that started after it. This fixture is deliberately out of timestamp
# order for that reason - the old code was only ever tested on sorted input.
CONN = [
    {
        "uid": "Clate", "timestamp": 100.0, "src_ip": "10.0.0.5", "src_port": 51111,
        "dst_ip": "10.0.0.53", "dst_port": 53, "proto": "udp", "service": "dns",
        "duration": 120.0, "orig_bytes": 74, "resp_bytes": 190, "conn_state": "SF",
        "orig_pkts": 1, "resp_pkts": 1, "orig_ip_bytes": 102, "resp_ip_bytes": 218,
    },
    {
        "uid": "Cearly", "timestamp": 10.0, "src_ip": "10.0.0.5", "src_port": 51112,
        "dst_ip": "10.0.0.80", "dst_port": 22, "proto": "tcp", "service": "-",
        "duration": 0.1, "orig_bytes": 0, "resp_bytes": 0, "conn_state": "S0",
        "orig_pkts": 1, "resp_pkts": 0, "orig_ip_bytes": 40, "resp_ip_bytes": 0,
    },
    {
        "uid": "Ctls", "timestamp": 50.0, "src_ip": "10.0.0.5", "src_port": 51113,
        "dst_ip": "185.62.11.4", "dst_port": 443, "proto": "tcp", "service": "ssl",
        "duration": 2.0, "orig_bytes": 900, "resp_bytes": 5000, "conn_state": "SF",
        "orig_pkts": 8, "resp_pkts": 9, "orig_ip_bytes": 1200, "resp_ip_bytes": 5400,
    },
]

DNS = [
    {"uid": "Clate", "timestamp": 100.1, "query": "kq3v9x2mzt7wp00.com",
     "qtype": "16", "rcode": "3"},
    {"uid": "Clate", "timestamp": 100.5, "query": "kq3v9x2mzt7wp01.com",
     "qtype": "1", "rcode": "3"},
]

SSL = [
    {"uid": "Ctls", "timestamp": 50.0, "version": "TLSv13",
     "cipher": "TLS_AES_128_GCM_SHA256", "ja3": "a0e9f5d64349fb13191bc781f81f42e1",
     "ja3s": "f4febc55ea12b31ae17cfb7e614afda8", "server_name": "cdn.example.test"},
]

HTTP = [
    {"uid": "Cearly", "timestamp": 10.0, "method": "GET", "host": "example.test",
     "uri": "/index.html", "user_agent": "curl/8.4.0",
     "request_body_len": 0, "response_body_len": 512, "status_code": 200},
]

PARSED = {"conn": CONN, "dns": DNS, "ssl": SSL, "http": HTTP}


def _emit(pipeline, **kwargs):
    joined = pipeline.join_by_uid(PARSED)
    stats = pipeline.PipelineStats()
    records = list(pipeline.build_records(joined, PARSED, stats=stats, **kwargs))
    return records, stats


# -- defect 1: window features joined to the wrong flow ---------------------


def test_records_come_out_in_event_time_order(pipeline):
    records, _ = _emit(pipeline)
    stamps = [r["timestamp"] for r in records]
    assert stamps == sorted(stamps)
    assert [r["uid"] for r in records] == ["Cearly", "Ctls", "Clate"]


def test_window_features_land_on_their_own_flow(pipeline):
    """The misalignment regression.

    The fake window extractor stamps each row with the uid of the record it was
    computed from. Before the fix, flow features came back in input order and
    window features in timestamp order, so these disagreed on every record whose
    position moved.
    """
    records, _ = _emit(pipeline, emit_window=True)
    for record in records:
        assert record["_window_owner_uid"] == record["uid"]


def test_window_block_is_absent_unless_asked_for(pipeline):
    records, _ = _emit(pipeline)
    assert all("flow_rate" not in r for r in records)
    # And when asked for, the 1e6 single-flow artefact is still there - it is a
    # property of the Rust window, not something this layer invented or hides.
    windowed, _ = _emit(pipeline, emit_window=True)
    assert windowed[0]["flow_rate"] == 1_000_000.0


# -- defect 2: the raw observables never reached the output -----------------


def test_raw_dns_query_survives(pipeline):
    records, stats = _emit(pipeline)
    dns_record = next(r for r in records if r["uid"] == "Clate")
    assert dns_record["dns"]["query"] == "kq3v9x2mzt7wp00.com"
    assert stats.with_raw_query == 1


def test_raw_tls_fingerprints_and_sni_survive(pipeline):
    records, stats = _emit(pipeline)
    tls = next(r for r in records if r["uid"] == "Ctls")["tls"]
    assert tls["ja3"] == "a0e9f5d64349fb13191bc781f81f42e1"
    assert tls["ja3s"] == "f4febc55ea12b31ae17cfb7e614afda8"
    assert tls["server_name"] == "cdn.example.test"
    assert tls["cipher"] == "TLS_AES_128_GCM_SHA256"
    assert stats.with_ja3 == 1 and stats.with_sni == 1


def test_sni_length_and_entropy_are_derived_from_the_real_name(pipeline):
    records, _ = _emit(pipeline)
    tls = next(r for r in records if r["uid"] == "Ctls")["tls"]
    assert tls["sni_length"] == len("cdn.example.test")
    assert tls["sni_entropy"] > 0


def test_ja4_is_absent_rather_than_faked(pipeline):
    records, _ = _emit(pipeline)
    tls = next(r for r in records if r["uid"] == "Ctls")["tls"]
    assert tls["ja4"] is None


def test_meaningless_cipher_encoding_is_not_carried(pipeline):
    records, _ = _emit(pipeline)
    tls = next(r for r in records if r["uid"] == "Ctls")["tls"]
    assert "cipher_encoded" not in tls


def test_raw_http_strings_survive(pipeline):
    records, _ = _emit(pipeline)
    http = next(r for r in records if r["uid"] == "Cearly")["http"]
    assert http["host"] == "example.test"
    assert http["uri"] == "/index.html"
    assert http["user_agent"] == "curl/8.4.0"


def test_protocol_multiplicity_is_explicit_for_every_block(pipeline):
    parsed = dict(PARSED)
    parsed["ssl"] = SSL + [dict(SSL[0], timestamp=51.0, cipher="second")]
    parsed["http"] = HTTP + [dict(HTTP[0], timestamp=11.0, uri="/second")]
    joined = pipeline.join_by_uid(parsed)
    records = list(pipeline.build_records(joined, parsed))
    tls = next(r for r in records if r["uid"] == "Ctls")["tls"]
    http = next(r for r in records if r["uid"] == "Cearly")["http"]
    assert tls["transaction_count"] == 2
    assert http["transaction_count"] == 2


# -- defect 3: qtype and rcode were numbers wearing a string's name ---------


def test_numeric_qtype_is_decoded_and_is_txt_is_recomputed(pipeline):
    records, _ = _emit(pipeline)
    dns = next(r for r in records if r["uid"] == "Clate")["dns"]
    assert dns["qtype"] == "TXT"
    assert dns["qtype_num"] == "16"
    assert dns["is_txt"] is True, "the crate compares a number against 'TXT'"


def test_nxdomain_is_visible_by_name(pipeline):
    records, _ = _emit(pipeline)
    dns = next(r for r in records if r["uid"] == "Clate")["dns"]
    assert dns["rcode"] == "NXDOMAIN"
    assert dns["rcode_num"] == "3"


# -- defect 4 and identity fields ------------------------------------------


def test_identity_and_event_time_fields_are_emitted(pipeline):
    records, _ = _emit(pipeline)
    first = records[0]
    for key in ("uid", "timestamp", "src_port", "service", "conn_state"):
        assert key in first, f"{key} must reach detection_core"
    assert first["uid"] == "Cearly"
    assert first["timestamp"] == 10.0
    assert first["src_port"] == 51112


def test_raw_s0_survives_even_though_the_encoder_has_no_arm_for_it(pipeline):
    """S0 is the primary port-scan and SYN-flood signal.

    The crate's encode_conn_state has no S0 case, so conn_state_encoded is 0 -
    indistinguishable from an unrecognised state. The raw string carries it.
    """
    records, _ = _emit(pipeline)
    scan = next(r for r in records if r["uid"] == "Cearly")
    assert scan["conn_state"] == "S0"
    assert scan["conn_state_encoded"] == 0


def test_zeek_unset_sentinel_becomes_none_not_empty_string(pipeline):
    records, _ = _emit(pipeline)
    scan = next(r for r in records if r["uid"] == "Cearly")
    assert scan["service"] is None, "'-' is Zeek saying it saw nothing"


def test_multiple_protocol_rows_for_one_uid_are_counted_not_silently_dropped(pipeline):
    records, stats = _emit(pipeline)
    dns = next(r for r in records if r["uid"] == "Clate")["dns"]
    # Earliest row wins, deterministically, regardless of file order.
    assert dns["query"] == "kq3v9x2mzt7wp00.com"
    assert dns["transaction_count"] == 2
    assert stats.multi_row_uids.get("dns") == 1


def test_every_record_is_json_serialisable(pipeline):
    records, _ = _emit(pipeline, emit_window=True)
    for record in records:
        json.loads(json.dumps(record))
