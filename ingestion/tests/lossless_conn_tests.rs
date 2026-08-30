use ingestion_core::features::{flow::FlowFeatures, temporal::sliding_window_features};
use ingestion_core::zeek_parser::conn_log::{parse_conn_log, parse_conn_log_lossless};
use ingestion_core::zeek_parser::source_types::{DiagnosticKind, SourceValue, ZeekLogType};

fn conn_log_with_edge_rows() -> &'static str {
    "#separator \\x09\n\
#set_separator\t,\n\
#empty_field\t(empty)\n\
#unset_field\t-\n\
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tip_proto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\torig_ip_bytes\tresp_ip_bytes\tmissed_bytes\n\
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\tcount\tcount\tcount\n\
0.123456\tC1\t192.0.2.1\t1234\t198.51.100.2\t80\ttcp\t6\thttp\t0\t0\t5\tSF\tShAD\t0\t1\t40\t60\t0\n\
# a comment between data rows must not consume an ordinal\n\
bad\tCbad\tnot-an-ip\tbad\t198.51.100.3\t443\tbogus\twat\t-\toops\toops\t-\t-\t-\toops\t-\toops\t-\tbad\n\
\n\
1.000000\tC2\t2001:db8::1\t0\t2001:db8::2\t443\ttcp\t6\t\t-\t10\t20\tSF\t(empty)\t-\t2\t50\t60\t-\n\
2\tCshort\n\
3\tCextra\t192.0.2.5\t50\t198.51.100.5\t53\tudp\t17\tdns\t0.1\t1\t2\tSF\tDd\t1\t1\t29\t30\t0\tEXTRA\n"
}

#[test]
fn lossless_parser_preserves_state_and_physical_ordinals() {
    let parsed = parse_conn_log_lossless(conn_log_with_edge_rows()).unwrap();
    assert_eq!(parsed.records.len(), 5);
    assert_eq!(
        parsed
            .records
            .iter()
            .map(|record| record.row_ordinal)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );

    assert_eq!(parsed.records[0].orig_packets, SourceValue::Value(0));
    assert_eq!(parsed.records[0].missed_bytes, SourceValue::Value(0));
    assert_eq!(
        parsed.records[1].timestamp_raw,
        SourceValue::Invalid("bad".into())
    );
    assert_eq!(
        parsed.records[1].orig_packets,
        SourceValue::Invalid("oops".into())
    );
    assert!(matches!(parsed.records[1].src_ip, SourceValue::Invalid(_)));
    assert_eq!(parsed.records[2].service, SourceValue::Value(String::new()));
    assert_eq!(parsed.records[2].duration_raw, SourceValue::Unset);
    assert_eq!(parsed.records[2].connection_history, SourceValue::Empty);
    assert_eq!(parsed.records[2].orig_packets, SourceValue::Unset);
    assert!(parsed.records[3].row_too_short_for_legacy);
    assert_eq!(parsed.records[3].src_ip, SourceValue::Missing);
    assert!(!parsed.records[4].row_too_short_for_legacy);

    let malformed_port = parsed
        .diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic.kind == DiagnosticKind::MalformedInteger
                && diagnostic.field.as_deref() == Some("id.orig_p")
        })
        .unwrap();
    assert_eq!(malformed_port.log_type, ZeekLogType::Conn);
    assert_eq!(malformed_port.source_record_id.as_deref(), Some("Cbad"));
    assert_eq!(malformed_port.row_ordinal, Some(1));

    for expected in [
        DiagnosticKind::MalformedDecimalTimestamp,
        DiagnosticKind::MalformedDuration,
        DiagnosticKind::MalformedInteger,
        DiagnosticKind::InvalidIp,
        DiagnosticKind::InvalidProtocolField,
        DiagnosticKind::MissingColumn,
        DiagnosticKind::ExtraColumn,
    ] {
        assert!(
            parsed
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.kind == expected),
            "missing diagnostic kind {expected:?}"
        );
    }
}

#[test]
fn legacy_projection_retains_previous_default_and_short_row_behavior() {
    let records = parse_conn_log(conn_log_with_edge_rows()).unwrap();
    assert_eq!(records.len(), 4, "legacy parser still skips short rows");
    assert_eq!(records[0].orig_pkts, 0, "reported zero stays zero");
    assert_eq!(records[1].timestamp, 0.0, "malformed legacy time defaults");
    assert_eq!(records[1].src_ip, "not-an-ip");
    assert_eq!(records[1].src_port, 0);
    assert_eq!(records[1].orig_bytes, 0);
    assert_eq!(records[2].service, "");
    assert_eq!(records[2].duration, 0.0);
    assert_eq!(records[3].uid, "Cextra");
}

#[test]
fn legacy_projection_preserves_original_ip_spelling() {
    let content =
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\torig_pkts\n\
1\tC-IP\t2001:0DB8:0000:0000:0000:0000:0000:0001\t1\t2001:DB8::2\t2\ttcp\t1\n";
    let records = parse_conn_log(content).unwrap();
    assert_eq!(records[0].src_ip, "2001:0DB8:0000:0000:0000:0000:0000:0001");
    assert_eq!(records[0].dst_ip, "2001:DB8::2");
}

#[test]
fn custom_markers_and_missing_uid_are_preserved_in_diagnostics() {
    let custom_markers = "#empty_field\tEMPTY-VALUE\n\
#unset_field\tUNSET-VALUE\n\
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\torig_ip_bytes\tresp_ip_bytes\tmissed_bytes\n\
1\tC-MARKERS\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\tUNSET-VALUE\t0\t0\t0\tSF\tEMPTY-VALUE\t0\t0\t40\t40\t0\n";
    let parsed = parse_conn_log_lossless(custom_markers).unwrap();
    assert_eq!(parsed.records[0].service, SourceValue::Unset);
    assert_eq!(parsed.records[0].connection_history, SourceValue::Empty);
    assert_eq!(parsed.records[0].orig_packets, SourceValue::Value(0));

    let missing_uid = "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\torig_pkts\n\
1\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\tbad\n";
    let parsed = parse_conn_log_lossless(missing_uid).unwrap();
    assert_eq!(parsed.records[0].uid, SourceValue::Missing);
    let diagnostic = parsed
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.field.as_deref() == Some("orig_pkts"))
        .unwrap();
    assert_eq!(diagnostic.log_type, ZeekLogType::Conn);
    assert_eq!(diagnostic.source_record_id, None);
    assert_eq!(diagnostic.row_ordinal, Some(0));
}

#[test]
fn legacy_scientific_notation_flows_through_features_unchanged() {
    let content = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\torig_ip_bytes\tresp_ip_bytes\n\
1e3\tC-EXP\t192.0.2.1\t1234\t198.51.100.2\t80\ttcp\thttp\t1e3\t10\t20\tSF\t1\t2\t50\t100\n";
    let records = parse_conn_log(content).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].timestamp, 1000.0);
    assert_eq!(records[0].duration, 1000.0);

    let features = FlowFeatures::from_flow_record(&records[0]);
    assert_eq!(features.flow_id, "192.0.2.1:198.51.100.2:80:tcp:1000.000");
    let serialized = serde_json::to_value(&features).unwrap();
    assert_eq!(serialized["duration"], 1000.0);
    assert_eq!(serialized["orig_bytes"], 10);
    assert_eq!(serialized["resp_bytes"], 20);
    assert_eq!(serialized["conn_state_encoded"], 4);
}

#[test]
fn legacy_sliding_window_behavior_remains_deterministic() {
    let content = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\torig_ip_bytes\tresp_ip_bytes\n\
101\tC-LATE\t192.0.2.1\t1\t198.51.100.2\t443\ttcp\tssl\t1\t5\t15\tSF\t1\t1\t45\t55\n\
100\tC-EARLY\t192.0.2.1\t1\t198.51.100.1\t80\ttcp\thttp\t1\t10\t20\tSF\t1\t1\t50\t60\n";
    let records = parse_conn_log(content).unwrap();
    assert_eq!(records[0].uid, "C-LATE", "parser retains source order");
    let windows = sliding_window_features(&records, 60.0);
    assert_eq!(windows.len(), 2);
    assert_eq!(windows[0].unique_dst_ips, 1);
    assert_eq!(windows[1].unique_dst_ips, 2);
    assert_eq!(windows[1].unique_dst_ports, 2);
    assert!((windows[1].flow_rate - (2.0 / 1.000001)).abs() < 1e-12);
    assert!((windows[1].byte_rate - (50.0 / 1.000001)).abs() < 1e-10);
    assert_eq!(windows[1].inter_arrival_mean, 1.0);
}
