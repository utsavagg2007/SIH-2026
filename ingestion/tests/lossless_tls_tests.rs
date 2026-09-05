use ingestion_core::features::tls_features::TlsFeatures;
use ingestion_core::zeek_parser::source_types::{DiagnosticKind, SourceValue, ZeekLogType};
use ingestion_core::zeek_parser::ssl_log::{
    parse_ssl_log, parse_ssl_log_detector, parse_ssl_log_lossless,
};

#[test]
fn lossless_tls_is_header_driven_and_preserves_states_and_ordinals() {
    let content = "#set_separator\t;\n\
#empty_field\tEMPTY\n\
#unset_field\tUNSET\n\
#fields\tja3s\tid.resp_h\tunknown_field\tserver_name\tuid\tid.orig_h\tproto\tts\tid.orig_p\tid.resp_p\tip_proto\tversion\tcipher\tja3\tja4\n\
server-fp\t198.51.100.2\tignored\tMiXeD.Example\tT1\t192.0.2.1\ttcp\t0.123456789\t50000\t443\t6\tTLSv13\tTLS_AES_128_GCM_SHA256\tclient-fp\tja4-token\n\
UNSET\t198.51.100.3\tignored\tEMPTY\tT2\t192.0.2.2\tUNSET\t1\t0\t0\tUNSET\tEMPTY\tUNSET\tEMPTY\tUNSET\n\
2\tSHORT\n";

    let parsed = parse_ssl_log_lossless(content).unwrap();
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
    assert_eq!(full.uid.as_value().map(String::as_str), Some("T1"));
    assert_eq!(full.src_port, SourceValue::Value(50000));
    assert_eq!(full.dst_port, SourceValue::Value(443));
    assert_eq!(full.ip_proto, SourceValue::Value(6));
    assert_eq!(full.version.as_value().map(String::as_str), Some("TLSv13"));
    assert_eq!(
        full.cipher.as_value().map(String::as_str),
        Some("TLS_AES_128_GCM_SHA256")
    );
    assert_eq!(
        full.server_name.as_value().map(String::as_str),
        Some("MiXeD.Example")
    );
    assert_eq!(full.ja3.as_value().map(String::as_str), Some("client-fp"));
    assert_eq!(full.ja3s.as_value().map(String::as_str), Some("server-fp"));
    assert_eq!(full.ja4.as_value().map(String::as_str), Some("ja4-token"));

    let states = &parsed.records[1];
    assert_eq!(states.src_port, SourceValue::Value(0));
    assert_eq!(states.dst_port, SourceValue::Value(0));
    assert_eq!(states.proto, SourceValue::Unset);
    assert_eq!(states.ip_proto, SourceValue::Unset);
    assert_eq!(states.version, SourceValue::Empty);
    assert_eq!(states.cipher, SourceValue::Unset);
    assert_eq!(states.server_name, SourceValue::Empty);
    assert_eq!(states.ja3, SourceValue::Empty);
    assert_eq!(states.ja3s, SourceValue::Unset);
    assert_eq!(states.ja4, SourceValue::Unset);

    assert!(parsed.records[2].row_too_short_for_legacy);
    assert!(parsed.diagnostics.iter().all(|diagnostic| {
        diagnostic.log_type == ZeekLogType::Ssl && diagnostic.row_ordinal.is_some()
    }));
}

#[test]
fn malformed_tls_values_remain_invalid_with_context() {
    let content = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tip_proto\n\
1e3\tT-BAD\tnot-ip\t70000\t198.51.100.2\tbad\tbogus\t999\n";
    let parsed = parse_ssl_log_lossless(content).unwrap();
    let record = &parsed.records[0];
    assert!(matches!(record.timestamp_raw, SourceValue::Invalid(_)));
    assert!(matches!(record.src_ip, SourceValue::Invalid(_)));
    assert!(matches!(record.src_port, SourceValue::Invalid(_)));
    assert!(matches!(record.dst_port, SourceValue::Invalid(_)));
    assert!(matches!(record.ip_proto, SourceValue::Invalid(_)));
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
        diagnostic.log_type == ZeekLogType::Ssl
            && diagnostic.source_record_id.as_deref() == Some("T-BAD")
            && diagnostic.row_ordinal == Some(0)
    }));
}

#[test]
fn legacy_tls_projection_and_features_are_exactly_compatible() {
    let content = "#fields\tts\tuid\tversion\tcipher\tja3\tja3s\tserver_name\n\
1e3\tS-LEGACY\tTLSv13\tTLS_AES_128_GCM_SHA256\tabc\t-\texample.test\n\
2\tSHORT\n";
    let records = parse_ssl_log(content).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].timestamp, 1000.0);
    assert_eq!(records[0].uid, "S-LEGACY");
    assert_eq!(records[0].version, "TLSv13");
    assert_eq!(records[0].cipher, "TLS_AES_128_GCM_SHA256");
    assert_eq!(records[0].ja3.as_deref(), Some("abc"));
    assert_eq!(records[0].ja3s, None);
    assert_eq!(records[0].server_name, "example.test");

    let feature = TlsFeatures::from_ssl_record(&records[0]);
    assert_eq!(
        serde_json::to_string(&feature).unwrap(),
        r#"{"uid":"S-LEGACY","has_ja3":true,"has_ja3s":false,"ssl_version_encoded":4,"cipher_encoded":7}"#
    );
}

#[test]
fn detector_tls_projection_preserves_exact_ja4_source_states_without_derivation() {
    let with_ja4 = "#empty_field\tEMPTY\n\
#unset_field\tUNSET\n\
#fields\tunknown\tja4\tserver_name\tuid\tts\tversion\tcipher\tja3\tja3s\n\
ignored\tt13d020200_abc123_def456\ta.example\tT1\t1\tTLSv13\tTLS_AES_128_GCM_SHA256\tja3-a\tja3s-a\n\
ignored\tsecond-arbitrary-nonempty-value\tb.example\tT1\t2\tTLSv12\tTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\tja3-b\tja3s-b\n\
ignored\tUNSET\tc.example\tT2\t3\tTLSv13\tcipher\tja3-c\tja3s-c\n\
ignored\tEMPTY\td.example\tT3\t4\tTLSv13\tcipher\tja3-d\tja3s-d\n";
    let projected = parse_ssl_log_detector(with_ja4).unwrap();
    assert_eq!(projected.len(), 4);
    assert_eq!(
        projected[0].ja4.as_deref(),
        Some("t13d020200_abc123_def456")
    );
    assert_eq!(
        projected[1].ja4.as_deref(),
        Some("second-arbitrary-nonempty-value")
    );
    assert_eq!(projected[2].ja4, None);
    assert_eq!(projected[3].ja4, None);

    let without_header = "#fields\tts\tuid\tversion\tcipher\tja3\tja3s\tserver_name\n\
5\tT4\tTLSv13\tcipher\tlooks-like-ja3\tserver-ja3\te.example\n";
    let missing = parse_ssl_log_detector(without_header).unwrap();
    assert_eq!(missing[0].ja4, None);

    let legacy = parse_ssl_log(with_ja4).unwrap();
    assert_eq!(
        serde_json::to_string(&legacy[0]).unwrap(),
        r#"{"uid":"T1","timestamp":1.0,"version":"TLSv13","cipher":"TLS_AES_128_GCM_SHA256","ja3":"ja3-a","ja3s":"ja3s-a","server_name":"a.example"}"#
    );
}
