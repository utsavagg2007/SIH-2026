use ingestion_core::features::http_features::HttpFeatures;
use ingestion_core::zeek_parser::http_log::{parse_http_log, parse_http_log_lossless};
use ingestion_core::zeek_parser::source_types::{DiagnosticKind, SourceValue, ZeekLogType};

#[test]
fn lossless_http_is_header_driven_and_preserves_states_and_ordinals() {
    let content = "#empty_field\tEMPTY\n\
#unset_field\tUNSET\n\
#fields\tstatus_code\tid.resp_h\tunknown_field\turi\tuid\tid.orig_h\tproto\tts\tid.orig_p\tid.resp_p\tip_proto\tmethod\thost\tuser_agent\trequest_body_len\tresponse_body_len\ttrans_depth\n\
201\t198.51.100.2\tignored\t/Case?X=1\tH1\t192.0.2.1\ttcp\t0.123456789\t50000\t8080\t6\tPATCH\tMiXeD.Example\tAgent/1\t0\t99\t7\n\
UNSET\t198.51.100.3\tignored\tEMPTY\tH2\t192.0.2.2\tUNSET\t1\t0\t0\tUNSET\tEMPTY\tUNSET\tEMPTY\tUNSET\tEMPTY\tUNSET\n\
2\tSHORT\n";
    let parsed = parse_http_log_lossless(content).unwrap();
    assert_eq!(parsed.records.len(), 3);
    assert_eq!(
        parsed
            .records
            .iter()
            .map(|record| record.row_ordinal)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    let full = &parsed.records[0];
    assert_eq!(full.src_port, SourceValue::Value(50000));
    assert_eq!(full.dst_port, SourceValue::Value(8080));
    assert_eq!(full.ip_proto, SourceValue::Value(6));
    assert_eq!(full.trans_depth, SourceValue::Value(7));
    assert_eq!(full.method.as_value().map(String::as_str), Some("PATCH"));
    assert_eq!(
        full.host.as_value().map(String::as_str),
        Some("MiXeD.Example")
    );
    assert_eq!(full.uri.as_value().map(String::as_str), Some("/Case?X=1"));
    assert_eq!(
        full.user_agent.as_value().map(String::as_str),
        Some("Agent/1")
    );
    assert_eq!(full.status_code, SourceValue::Value(201));
    assert_eq!(full.request_body_len, SourceValue::Value(0));
    assert_eq!(full.response_body_len, SourceValue::Value(99));

    let states = &parsed.records[1];
    assert_eq!(states.method, SourceValue::Empty);
    assert_eq!(states.host, SourceValue::Unset);
    assert_eq!(states.uri, SourceValue::Empty);
    assert_eq!(states.user_agent, SourceValue::Empty);
    assert_eq!(states.status_code, SourceValue::Unset);
    assert_eq!(states.request_body_len, SourceValue::Unset);
    assert_eq!(states.response_body_len, SourceValue::Empty);
    assert!(parsed.records[2].row_too_short_for_legacy);
    assert!(parsed.diagnostics.iter().all(|diagnostic| {
        diagnostic.log_type == ZeekLogType::Http && diagnostic.row_ordinal.is_some()
    }));
}

#[test]
fn malformed_http_values_remain_invalid_with_context() {
    let content = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tip_proto\ttrans_depth\tstatus_code\trequest_body_len\tresponse_body_len\n\
1e3\tH-BAD\tnot-ip\t70000\t198.51.100.2\tbad\t999\tnope\tbad\t-1\t18446744073709551616\n";
    let parsed = parse_http_log_lossless(content).unwrap();
    let record = &parsed.records[0];
    assert!(matches!(record.timestamp_raw, SourceValue::Invalid(_)));
    assert!(matches!(record.src_ip, SourceValue::Invalid(_)));
    assert!(matches!(record.src_port, SourceValue::Invalid(_)));
    assert!(matches!(record.dst_port, SourceValue::Invalid(_)));
    assert!(matches!(record.ip_proto, SourceValue::Invalid(_)));
    assert!(matches!(record.trans_depth, SourceValue::Invalid(_)));
    assert!(matches!(record.status_code, SourceValue::Invalid(_)));
    assert!(matches!(record.request_body_len, SourceValue::Invalid(_)));
    assert!(matches!(record.response_body_len, SourceValue::Invalid(_)));
    for expected in [
        DiagnosticKind::MalformedDecimalTimestamp,
        DiagnosticKind::InvalidIp,
        DiagnosticKind::MalformedInteger,
        DiagnosticKind::OutOfRangeValue,
    ] {
        assert!(parsed
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == expected));
    }
    assert!(parsed.diagnostics.iter().all(|diagnostic| {
        diagnostic.log_type == ZeekLogType::Http
            && diagnostic.source_record_id.as_deref() == Some("H-BAD")
            && diagnostic.row_ordinal == Some(0)
    }));
}

#[test]
fn legacy_http_projection_and_features_are_exactly_compatible() {
    let content = "#fields\tts\tuid\tmethod\thost\turi\tuser_agent\trequest_body_len\tresponse_body_len\tstatus_code\n\
1e3\tH-LEGACY\tPOST\tx\ta\t-\tbad\t2\tbad\n\
2\tSHORT\n";
    let records = parse_http_log(content).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].timestamp, 1000.0);
    assert_eq!(records[0].method, "POST");
    assert_eq!(records[0].host, "x");
    assert_eq!(records[0].uri, "a");
    assert_eq!(records[0].user_agent, "");
    assert_eq!(records[0].request_body_len, 0);
    assert_eq!(records[0].response_body_len, 2);
    assert_eq!(records[0].status_code, 0);

    let feature = HttpFeatures::from_http_record(&records[0]);
    assert_eq!(
        serde_json::to_string(&feature).unwrap(),
        r#"{"uid":"H-LEGACY","method_encoded":2,"host_length":1,"uri_length":1,"uri_entropy":-0.0,"has_user_agent":false,"user_agent_length":0,"request_body_len":0,"response_body_len":2,"status_code":0}"#
    );
}
