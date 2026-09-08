use ingestion_core::features::dns_features::DnsFeatures;
use ingestion_core::zeek_parser::dns_log::{
    parse_dns_log, parse_dns_log_detector, parse_dns_log_lossless,
};
use ingestion_core::zeek_parser::source_types::{DiagnosticKind, SourceValue, ZeekLogType};

#[test]
fn lossless_dns_preserves_header_states_codes_flags_and_ordinals() {
    let content = "#set_separator\t;
#empty_field\tEMPTY
#unset_field\tUNSET
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tip_proto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected
0.123456789\tD1\t192.0.2.1\t0\t198.51.100.2\t53\tudp\t17\t0007\t0.1\tMiXeD.Example.\t0\tC0\t16\tTXT\t3\tNXDOMAIN\tT\tF\tT\tF\t0\t192.0.2.9;2001:db8::9\t60.0;30.0\tF
# comment does not consume a physical data ordinal
1\tD2\t2001:0DB8::1\tUNSET\t2001:DB8::2\tEMPTY\ttcp\tUNSET\tUNSET\tEMPTY\tEMPTY\tUNSET\tEMPTY\tUNSET\tEMPTY\tUNSET\tEMPTY\tUNSET\tEMPTY\tUNSET\tEMPTY\tUNSET\tEMPTY\tUNSET\tEMPTY
2\tSHORT
";

    let parsed = parse_dns_log_lossless(content).unwrap();
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
    assert_eq!(full.src_port, SourceValue::Value(0));
    assert_eq!(full.ip_proto, SourceValue::Value(17));
    assert_eq!(full.transaction_id.as_value().unwrap().raw, "0007");
    assert_eq!(full.transaction_id.as_value().unwrap().value, 7);
    assert_eq!(full.qclass.as_value().unwrap().value, 0);
    assert_eq!(full.qtype.as_value().unwrap().value, 16);
    assert_eq!(full.rcode.as_value().unwrap().value, 3);
    assert_eq!(full.authoritative_answer, SourceValue::Value(true));
    assert_eq!(full.truncated, SourceValue::Value(false));
    assert_eq!(full.answer_count, SourceValue::Value(2));

    let states = &parsed.records[1];
    assert_eq!(states.src_port, SourceValue::Unset);
    assert_eq!(states.dst_port, SourceValue::Empty);
    assert_eq!(states.query, SourceValue::Empty);
    assert_eq!(states.qtype, SourceValue::Unset);
    assert_eq!(states.qclass_name, SourceValue::Empty);
    assert_eq!(states.answers_raw, SourceValue::Empty);
    assert_eq!(states.answer_count, SourceValue::Value(0));
    assert!(parsed.records[2].row_too_short_for_legacy);
    assert_eq!(parsed.records[2].src_ip, SourceValue::Missing);

    assert!(parsed.diagnostics.iter().all(|diagnostic| {
        diagnostic.log_type == ZeekLogType::Dns
            && diagnostic.row_ordinal.is_some()
            && (diagnostic.row_ordinal != Some(0)
                || diagnostic.source_record_id.as_deref() == Some("D1"))
    }));
}

#[test]
fn malformed_optional_dns_values_remain_invalid_with_context() {
    let content = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tip_proto\tqclass\tqtype\trcode\tAA\tanswers
1\tD-BAD\t192.0.2.1\t70000\t198.51.100.1\tbad\tudp\twat\tnope\t65536\t4096\tmaybe\ta,,b
";
    let parsed = parse_dns_log_lossless(content).unwrap();
    let record = &parsed.records[0];
    assert!(matches!(record.src_port, SourceValue::Invalid(_)));
    assert!(matches!(record.dst_port, SourceValue::Invalid(_)));
    assert!(matches!(record.ip_proto, SourceValue::Invalid(_)));
    assert!(matches!(record.qclass, SourceValue::Invalid(_)));
    assert!(matches!(record.qtype, SourceValue::Invalid(_)));
    assert!(matches!(record.rcode, SourceValue::Invalid(_)));
    assert!(matches!(
        record.authoritative_answer,
        SourceValue::Invalid(_)
    ));
    assert!(matches!(record.answer_count, SourceValue::Invalid(_)));

    for expected in [
        DiagnosticKind::MalformedInteger,
        DiagnosticKind::InvalidProtocolField,
        DiagnosticKind::OutOfRangeValue,
        DiagnosticKind::MalformedBoolean,
        DiagnosticKind::InvalidAnswersEncoding,
    ] {
        assert!(
            parsed
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == expected),
            "missing diagnostic {expected:?}"
        );
    }
    assert!(parsed.diagnostics.iter().all(|diagnostic| {
        diagnostic.log_type == ZeekLogType::Dns
            && diagnostic.source_record_id.as_deref() == Some("D-BAD")
            && diagnostic.row_ordinal == Some(0)
    }));
    let answers_diagnostic = parsed
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.kind == DiagnosticKind::InvalidAnswersEncoding)
        .unwrap();
    assert_eq!(answers_diagnostic.raw_value, None);
}

#[test]
fn legacy_dns_projection_and_features_are_byte_compatible() {
    let content = "#fields\tts\tuid\tquery\tqtype\trcode
1e3\tD-LEGACY\ta\tTXT\tNOERROR
2\tD-SHORT
";
    let records = parse_dns_log(content).unwrap();
    assert_eq!(records.len(), 1, "legacy parser still skips short rows");
    assert_eq!(records[0].timestamp, 1000.0);
    assert_eq!(records[0].uid, "D-LEGACY");
    assert_eq!(records[0].query, "a");
    assert_eq!(records[0].qtype, "TXT");
    assert_eq!(records[0].rcode, "NOERROR");

    let feature = DnsFeatures::from_dns_record(&records[0]);
    assert_eq!(
        serde_json::to_string(&feature).unwrap(),
        r#"{"uid":"D-LEGACY","query_length":1,"query_entropy":-0.0,"subdomain_entropy":0.0,"is_txt":true,"label_count":1}"#
    );
}

#[test]
fn header_driven_parser_supports_reordered_minimal_legacy_fields() {
    let content = "#fields\trcode\tquery\tuid\tts\tqtype
NXDOMAIN\texample.test\tD-ORDER\t3.5\tA
";
    let records = parse_dns_log(content).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].uid, "D-ORDER");
    assert_eq!(records[0].timestamp, 3.5);
    assert_eq!(records[0].query, "example.test");
    assert_eq!(records[0].qtype, "A");
    assert_eq!(records[0].rcode, "NXDOMAIN");
}

#[test]
fn detector_dns_projection_retains_every_physical_row_and_approved_source_fact() {
    let content = "#set_separator\t,\n\
#fields\tquery\tuid\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\trejected\n\
one.example\tD1\t1.25\t192.0.2.1\t53000\t198.51.100.53\t53\tudp\t1\tA\t0\tNOERROR\tF\tF\tT\tT\t0\t203.0.113.1,203.0.113.2\tF\n\
two.example\tD1\t1.50\t192.0.2.1\t53000\t198.51.100.53\t53\tudp\t16\tTXT\t3\tNXDOMAIN\tT\tT\tF\tF\t1\t-\tT\n";
    let records = parse_dns_log_detector(content).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].source_ordinal, 0);
    assert_eq!(records[1].source_ordinal, 1);
    assert_eq!(records[0].event_time, Some(1.25));
    assert_eq!(records[0].src_ip.as_deref(), Some("192.0.2.1"));
    assert_eq!(records[0].src_port, Some(53000));
    assert_eq!(records[0].dst_ip.as_deref(), Some("198.51.100.53"));
    assert_eq!(records[0].dst_port, Some(53));
    assert_eq!(records[0].proto.as_deref(), Some("udp"));
    assert_eq!(records[0].qtype_name.as_deref(), Some("A"));
    assert_eq!(records[0].rcode_name.as_deref(), Some("NOERROR"));
    assert_eq!(records[0].answer_count, Some(2));
    assert_eq!(records[1].authoritative_answer, Some(true));
    assert_eq!(records[1].truncated, Some(true));
    assert_eq!(records[1].recursion_desired, Some(false));
    assert_eq!(records[1].recursion_available, Some(false));
    assert_eq!(records[1].z, Some(1));
    assert_eq!(records[1].rejected, Some(true));
}
