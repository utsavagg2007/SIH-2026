use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use ingestion_core::canonical::correlation::{FlowCorrelationCandidate, FlowCorrelationIndex};
use ingestion_core::canonical::dns_producer::produce_dns_observations_from_parse;
use ingestion_core::canonical::id::{
    generate_zeek_record_id, IdentityObservationType, ZeekLogName,
};
use ingestion_core::canonical::producer::{
    produce_flow_observations_from_parse, FlowProducerConfig, ZEEK_PARSER_NAME, ZEEK_PARSER_VERSION,
};
use ingestion_core::canonical::{CanonicalData, Fidelity, InputMode};
use ingestion_core::features::dns_features::DnsFeatures;
use ingestion_core::zeek_parser::conn_log::parse_conn_log_lossless;
use ingestion_core::zeek_parser::dns_log::{parse_dns_log, parse_dns_log_lossless};
use ingestion_core::zeek_parser::source_types::{
    DiagnosticKind, LosslessParseResult, SourceValue, ZeekDnsRecord,
};

const INPUT_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OBSERVED_AT: &str = "2026-08-30T12:34:56.123456Z";
const FIELDS: [&str; 25] = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "ip_proto",
    "trans_id",
    "rtt",
    "query",
    "qclass",
    "qclass_name",
    "qtype",
    "qtype_name",
    "rcode",
    "rcode_name",
    "AA",
    "TC",
    "RD",
    "RA",
    "Z",
    "answers",
    "TTLs",
    "rejected",
];

fn row(overrides: &[(&str, &str)]) -> String {
    let mut values = vec![
        "1",
        "D1",
        "192.0.2.1",
        "53000",
        "198.51.100.2",
        "53",
        "udp",
        "17",
        "7",
        "0.01",
        "MiXeD.Example.",
        "1",
        "C_INTERNET",
        "16",
        "TXT",
        "0",
        "NOERROR",
        "F",
        "F",
        "T",
        "T",
        "0",
        "(empty)",
        "(empty)",
        "F",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    for (field, value) in overrides {
        let index = FIELDS
            .iter()
            .position(|candidate| candidate == field)
            .unwrap();
        values[index] = (*value).to_string();
    }
    values.join("\t")
}

fn parse_rows(rows: &[String]) -> LosslessParseResult<ZeekDnsRecord> {
    parse_rows_with_separator(rows, ",")
}

fn parse_rows_with_separator(
    rows: &[String],
    set_separator: &str,
) -> LosslessParseResult<ZeekDnsRecord> {
    let content = format!(
        "#set_separator\t{set_separator}\n#empty_field\t(empty)\n#unset_field\t-\n#fields\t{}\n{}\n",
        FIELDS.join("\t"),
        rows.join("\n")
    );
    parse_dns_log_lossless(&content).unwrap()
}

fn config(observed_at: &str) -> FlowProducerConfig {
    FlowProducerConfig::new("sensor-alpha", INPUT_HASH, observed_at).unwrap()
}

fn dns_data(
    observation: &ingestion_core::canonical::CanonicalObservation,
) -> &ingestion_core::canonical::DnsData {
    let CanonicalData::Dns(data) = &observation.data else {
        panic!("expected DNS data");
    };
    data
}

fn assert_contract_valid(observation: &ingestion_core::canonical::CanonicalObservation) {
    let schema = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("contracts/canonical_observation_v1.schema.json");
    let script = "$json=[Console]::In.ReadToEnd(); $errors=@(); \
        $ok=Test-Json -Json $json -SchemaFile $env:M1B_SCHEMA_PATH \
        -ErrorAction SilentlyContinue -ErrorVariable errors; \
        if(-not $ok){ $errors | ForEach-Object { [Console]::Error.WriteLine($_) }; exit 1 }";
    let mut child = Command::new("pwsh")
        .args(["-NoProfile", "-Command", script])
        .env("M1B_SCHEMA_PATH", schema)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("PowerShell 7 is required by the repository contract harness");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(serde_json::to_string(observation).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "generated DNS failed frozen schema validation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn full_dns_maps_exact_source_facts_quality_and_provenance() {
    let parsed = parse_rows(&[row(&[
        ("ts", "0.123456789"),
        ("query", "Case.Preserved."),
        ("qclass", "0"),
        ("qtype", "0"),
        ("rcode", "0"),
        ("AA", "T"),
        ("TC", "T"),
        ("RD", "F"),
        ("RA", "T"),
        ("rejected", "T"),
        ("answers", "192.0.2.9,2001:db8::9"),
    ])]);
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 1);
    let observation = &produced.observations[0];
    let data = dns_data(observation);
    assert_eq!(data.event_time, "1970-01-01T00:00:00.123456789Z");
    assert_eq!(data.src_ip, "192.0.2.1");
    assert_eq!(data.dst_ip, "198.51.100.2");
    assert_eq!(data.src_port, Some(53000));
    assert_eq!(data.dst_port, Some(53));
    assert_eq!(data.ip_protocol, 17);
    assert_eq!(data.query.as_deref(), Some("Case.Preserved."));
    assert_eq!(data.qclass, Some(0));
    assert_eq!(data.qtype, Some(0));
    assert_eq!(data.rcode, Some(0));
    assert_eq!(data.authoritative_answer, Some(true));
    assert_eq!(data.dns_truncated, Some(true));
    assert_eq!(data.recursion_desired, Some(false));
    assert_eq!(data.recursion_available, Some(true));
    assert_eq!(data.rejected, Some(true));
    assert_eq!(data.answer_count, Some(2));
    assert_eq!(observation.source_record_id.as_deref(), Some("D1"));
    assert_eq!(observation.quality.fidelity, Fidelity::Exact);
    assert_eq!(observation.quality.sampling_rate, None);
    assert_eq!(observation.quality.sampling_probability, None);
    assert!(
        !observation.quality.truncated,
        "DNS TC is not quality truncation"
    );
    assert!(!observation.quality.loss_detected);
    assert_eq!(observation.quality.missed_content_bytes, None);
    assert_eq!(observation.provenance.input_mode, InputMode::PcapFile);
    assert_eq!(observation.provenance.parser_name, ZEEK_PARSER_NAME);
    assert_eq!(observation.provenance.parser_version, ZEEK_PARSER_VERSION);
    assert_eq!(
        observation.provenance.input_sha256.as_deref(),
        Some(INPUT_HASH)
    );
    let serialized = serde_json::to_value(observation).unwrap();
    assert!(serialized["data"].get("trans_id").is_none());
    assert!(serialized["data"].get("transaction_id").is_none());
    assert!(serialized["data"].get("answers").is_none());
    assert!(serialized["data"].get("TTLs").is_none());
    assert_contract_valid(observation);
}

#[test]
fn partial_dns_omits_optional_facts_without_fabrication() {
    let rows = vec![
        row(&[
            ("uid", "-"),
            ("id.orig_p", "-"),
            ("id.resp_p", "-"),
            ("query", "-"),
            ("qclass", "-"),
            ("qtype", "-"),
            ("rcode", "-"),
            ("AA", "-"),
            ("TC", "-"),
            ("RD", "-"),
            ("RA", "-"),
            ("answers", "-"),
            ("rejected", "-"),
        ]),
        row(&[("uid", "D-EMPTY"), ("query", "(empty)")]),
        row(&[("uid", "D-ACTUAL-EMPTY"), ("query", "")]),
    ];
    let parsed = parse_rows(&rows);
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 3);
    let partial = dns_data(&produced.observations[0]);
    assert_eq!(produced.observations[0].source_record_id, None);
    assert_eq!(partial.src_port, None);
    assert_eq!(partial.dst_port, None);
    assert_eq!(partial.query, None);
    assert_eq!(partial.qtype, None);
    assert_eq!(partial.qclass, None);
    assert_eq!(partial.rcode, None);
    assert_eq!(partial.authoritative_answer, None);
    assert_eq!(partial.flow_record_id, None);
    assert_eq!(
        dns_data(&produced.observations[1]).query.as_deref(),
        Some("")
    );
    assert_eq!(
        dns_data(&produced.observations[2]).query.as_deref(),
        Some("")
    );
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn malformed_optional_values_are_omitted_but_row_still_emits() {
    let parsed = parse_rows(&[row(&[
        ("id.orig_p", "70000"),
        ("id.resp_p", "bad"),
        ("ip_proto", "bad"),
        ("qclass", "nope"),
        ("qtype", "65536"),
        ("rcode", "4096"),
        ("AA", "maybe"),
        ("answers", "a,,b"),
    ])]);
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(
        produced.observations.len(),
        1,
        "known udp is the protocol fallback"
    );
    let data = dns_data(&produced.observations[0]);
    assert_eq!(data.src_port, None);
    assert_eq!(data.dst_port, None);
    assert_eq!(data.ip_protocol, 17);
    assert_eq!(data.qclass, None);
    assert_eq!(data.qtype, None);
    assert_eq!(data.rcode, None);
    assert_eq!(data.authoritative_answer, None);
    assert_eq!(data.answer_count, None);
    for expected in [
        DiagnosticKind::MalformedInteger,
        DiagnosticKind::InvalidProtocolField,
        DiagnosticKind::OutOfRangeValue,
        DiagnosticKind::MalformedBoolean,
        DiagnosticKind::InvalidAnswersEncoding,
    ] {
        assert!(produced
            .diagnostics
            .iter()
            .any(|item| item.kind == expected));
    }
    assert_contract_valid(&produced.observations[0]);
}

#[test]
fn maximum_valid_rcode_is_preserved_without_range_diagnostic() {
    let parsed = parse_rows(&[row(&[("rcode", "4095")])]);
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);

    assert_eq!(produced.observations.len(), 1);
    assert_eq!(dns_data(&produced.observations[0]).rcode, Some(4095));
    assert!(!produced.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == DiagnosticKind::OutOfRangeValue
            && diagnostic.field.as_deref() == Some("rcode")
    }));
    assert_contract_valid(&produced.observations[0]);
}

#[test]
fn rich_reordered_header_ignores_unknown_field_and_maps_by_name() {
    let content = "#set_separator\t,\n\
#empty_field\t(empty)\n\
#unset_field\t-\n\
#fields\trcode\tid.resp_h\tsome_unknown_field\tquery\tuid\tid.orig_h\tproto\tts\tid.orig_p\tid.resp_p\tqtype\tqclass\tAA\tTC\tRD\tRA\tanswers\trejected\n\
3\t198.51.100.44\tignored-value\tReordered.Example.\tD-REORDER\t192.0.2.44\tudp\t7.25\t44000\t5353\t28\t1\tT\tF\tT\tF\t2001:db8::44\tF\n";
    let parsed = parse_dns_log_lossless(content).unwrap();
    let source = &parsed.records[0];
    assert_eq!(source.uid.as_value().map(String::as_str), Some("D-REORDER"));
    assert_eq!(
        source.query.as_value().map(String::as_str),
        Some("Reordered.Example.")
    );
    assert_eq!(source.src_port, SourceValue::Value(44000));
    assert_eq!(source.dst_port, SourceValue::Value(5353));
    assert_eq!(source.qtype.as_value().unwrap().value, 28);
    assert_eq!(source.qclass.as_value().unwrap().value, 1);
    assert_eq!(source.rcode.as_value().unwrap().value, 3);
    assert_eq!(source.answer_count, SourceValue::Value(1));

    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 1);
    let data = dns_data(&produced.observations[0]);
    assert_eq!(data.event_time, "1970-01-01T00:00:07.250Z");
    assert_eq!(data.src_ip, "192.0.2.44");
    assert_eq!(data.dst_ip, "198.51.100.44");
    assert_eq!(data.src_port, Some(44000));
    assert_eq!(data.dst_port, Some(5353));
    assert_eq!(data.ip_protocol, 17);
    assert_eq!(data.query.as_deref(), Some("Reordered.Example."));
    assert_eq!(data.qtype, Some(28));
    assert_eq!(data.qclass, Some(1));
    assert_eq!(data.rcode, Some(3));
    assert_eq!(data.authoritative_answer, Some(true));
    assert_eq!(data.dns_truncated, Some(false));
    assert_eq!(data.recursion_desired, Some(true));
    assert_eq!(data.recursion_available, Some(false));
    assert_eq!(data.rejected, Some(false));
    assert_eq!(data.answer_count, Some(1));
    assert_contract_valid(&produced.observations[0]);

    let legacy = parse_dns_log(content).unwrap();
    assert_eq!(legacy.len(), 1);
    assert_eq!(legacy[0].uid, "D-REORDER");
    assert_eq!(legacy[0].query, "Reordered.Example.");
    assert_eq!(legacy[0].qtype, "28");
    assert_eq!(legacy[0].rcode, "3");
}

#[test]
fn complete_tcp_dns_preserves_source_ports_query_and_numeric_codes() {
    let parsed = parse_rows(&[row(&[
        ("ts", "9.125"),
        ("proto", "tcp"),
        ("ip_proto", "6"),
        ("id.orig_p", "60123"),
        ("id.resp_p", "853"),
        ("query", "Tcp.Case-Preserved.Example."),
        ("qtype", "16"),
        ("qclass", "255"),
        ("rcode", "5"),
    ])]);
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);

    assert_eq!(produced.observations.len(), 1);
    let data = dns_data(&produced.observations[0]);
    assert_eq!(data.event_time, "1970-01-01T00:00:09.125Z");
    assert_eq!(data.ip_protocol, 6);
    assert_eq!(data.src_port, Some(60123));
    assert_eq!(data.dst_port, Some(853));
    assert_eq!(data.query.as_deref(), Some("Tcp.Case-Preserved.Example."));
    assert_eq!(data.qtype, Some(16));
    assert_eq!(data.qclass, Some(255));
    assert_eq!(data.rcode, Some(5));
    assert_contract_valid(&produced.observations[0]);
}

#[test]
fn nonnumeric_qtype_is_omitted_canonically_but_preserved_for_legacy_features() {
    let source_row = row(&[
        ("uid", "D-TXT-RAW"),
        ("query", "txt.example"),
        ("qtype", "TXT"),
    ]);
    let content = format!(
        "#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#fields\t{}\n{source_row}\n",
        FIELDS.join("\t")
    );
    let parsed = parse_dns_log_lossless(&content).unwrap();
    assert_eq!(
        parsed.records[0].qtype,
        SourceValue::Invalid("TXT".to_string())
    );
    assert!(parsed.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == DiagnosticKind::MalformedInteger
            && diagnostic.field.as_deref() == Some("qtype")
            && diagnostic.raw_value.as_deref() == Some("TXT")
    }));

    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 1);
    assert_eq!(dns_data(&produced.observations[0]).qtype, None);
    assert_ne!(dns_data(&produced.observations[0]).qtype, Some(0));
    assert_contract_valid(&produced.observations[0]);

    let legacy = parse_dns_log(&content).unwrap();
    assert_eq!(legacy.len(), 1);
    assert_eq!(legacy[0].qtype, "TXT");
    let feature = DnsFeatures::from_dns_record(&legacy[0]);
    assert!(feature.is_txt);
}

#[test]
fn answer_count_respects_custom_separator_and_rejects_overflow() {
    let parsed = parse_rows_with_separator(
        &[
            row(&[("uid", "EMPTY"), ("answers", "(empty)")]),
            row(&[("uid", "MULTI"), ("answers", "a;b;c")]),
            row(&[("uid", "BAD"), ("answers", "a;;c")]),
        ],
        ";",
    );
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 3);
    assert_eq!(dns_data(&produced.observations[0]).answer_count, Some(0));
    assert_eq!(dns_data(&produced.observations[1]).answer_count, Some(3));
    assert_eq!(dns_data(&produced.observations[2]).answer_count, None);
    assert!(produced
        .diagnostics
        .iter()
        .any(|item| item.kind == DiagnosticKind::InvalidAnswersEncoding));

    for observation in &produced.observations {
        assert_contract_valid(observation);
    }

    let oversized = (0..=u16::MAX).map(|_| "a").collect::<Vec<_>>().join(",");
    let parsed = parse_rows(&[row(&[("uid", "TOO-MANY"), ("answers", &oversized)])]);
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(dns_data(&produced.observations[0]).answer_count, None);
    assert!(produced
        .diagnostics
        .iter()
        .any(|item| item.kind == DiagnosticKind::OutOfRangeValue));
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn answer_count_handles_valid_and_structurally_invalid_zeek_vectors() {
    let parsed = parse_rows(&[
        row(&[("uid", "ONE"), ("answers", "203.0.113.7")]),
        row(&[("uid", "LEADING"), ("answers", ",203.0.113.7")]),
        row(&[("uid", "TRAILING"), ("answers", "203.0.113.7,")]),
        row(&[("uid", "ESCAPED"), ("answers", r"left\x2cright")]),
        row(&[
            ("uid", "PUNCTUATION"),
            ("answers", r#"\"v=spf1 include:_spf.example -all;~?\""#),
        ]),
    ]);
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);

    assert_eq!(produced.observations.len(), 5);
    assert_eq!(dns_data(&produced.observations[0]).answer_count, Some(1));
    assert_eq!(dns_data(&produced.observations[1]).answer_count, None);
    assert_eq!(dns_data(&produced.observations[2]).answer_count, None);
    assert_eq!(dns_data(&produced.observations[3]).answer_count, Some(1));
    assert_eq!(dns_data(&produced.observations[4]).answer_count, Some(1));
    assert_eq!(
        produced
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.kind == DiagnosticKind::InvalidAnswersEncoding)
            .map(|diagnostic| diagnostic.source_record_id.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("LEADING"), Some("TRAILING")]
    );
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn repeated_uid_query_and_timestamp_preserve_one_to_many_order_and_identity() {
    let parsed = parse_rows(&[
        row(&[("uid", "C1"), ("ts", "5"), ("query", "same.test")]),
        row(&[("uid", "C1"), ("ts", "5"), ("query", "same.test")]),
        row(&[("uid", "C1"), ("ts", "5"), ("query", "same.test")]),
    ]);
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 3);
    assert_eq!(
        produced
            .observations
            .iter()
            .map(|item| item.source_record_id.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("C1"), Some("C1"), Some("C1")]
    );
    assert_eq!(
        produced
            .observations
            .iter()
            .map(|item| item.record_id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    for observation in &produced.observations {
        let data = dns_data(observation);
        assert_eq!(data.event_time, "1970-01-01T00:00:05Z");
        assert_eq!(data.query.as_deref(), Some("same.test"));
        assert_contract_valid(observation);
    }
}

#[test]
fn one_flow_and_three_dns_rows_preserve_all_rows_and_the_same_unique_link() {
    let conn = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tip_proto\tduration\torig_pkts
1\tC1\t192.0.2.1\t53000\t198.51.100.2\t53\tudp\t17\t0\t1
";
    let flow_parse = parse_conn_log_lossless(conn).unwrap();
    let flow_result = produce_flow_observations_from_parse(&flow_parse, &config(OBSERVED_AT));
    assert_eq!(flow_result.observations.len(), 1);
    let flow_id = flow_result.observations[0].record_id.clone();
    let index = FlowCorrelationIndex::from_flow_observations(&flow_result.observations);

    let parsed = parse_rows(&[
        row(&[("uid", "C1"), ("query", "first.test")]),
        row(&[("uid", "C1"), ("query", "second.test")]),
        row(&[("uid", "C1"), ("query", "third.test")]),
    ]);
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), Some(&index));
    assert_eq!(produced.observations.len(), 3);
    assert_eq!(
        produced
            .observations
            .iter()
            .map(|observation| dns_data(observation).query.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("first.test"), Some("second.test"), Some("third.test")]
    );
    assert!(produced.observations.iter().all(|observation| {
        dns_data(observation).flow_record_id.as_deref() == Some(flow_id.as_str())
    }));
    assert_eq!(
        produced
            .observations
            .iter()
            .map(|observation| observation.record_id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn dns_uuid_has_fixed_vector_empty_uid_and_clock_independence() {
    assert_eq!(
        generate_zeek_record_id(
            "sensor-alpha",
            INPUT_HASH,
            IdentityObservationType::Dns,
            ZeekLogName::Dns,
            "D1",
            0,
        )
        .unwrap(),
        "ebca8681-b655-5f83-961f-f937897aac6a"
    );
    let parsed = parse_rows(&[row(&[("uid", "-")])]);
    let first = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    let replay =
        produce_dns_observations_from_parse(&parsed, &config("2026-08-30T12:35:00Z"), None);
    assert_eq!(
        first.observations[0].record_id,
        replay.observations[0].record_id
    );
    assert_eq!(
        first.observations[0].record_id,
        generate_zeek_record_id(
            "sensor-alpha",
            INPUT_HASH,
            IdentityObservationType::Dns,
            ZeekLogName::Dns,
            "",
            0,
        )
        .unwrap()
    );
    assert_contract_valid(&first.observations[0]);
    assert_contract_valid(&replay.observations[0]);
}

fn candidate(
    record_id: &str,
    src_ip: &str,
    dst_ip: &str,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    ip_protocol: u8,
) -> FlowCorrelationCandidate {
    FlowCorrelationCandidate {
        record_id: record_id.to_string(),
        src_ip: src_ip.parse::<IpAddr>().unwrap(),
        dst_ip: dst_ip.parse::<IpAddr>().unwrap(),
        src_port,
        dst_port,
        ip_protocol,
    }
}

#[test]
fn correlation_links_only_a_unique_tuple_consistent_flow() {
    let parsed = parse_rows(&[
        row(&[("uid", "NONE")]),
        row(&[("uid", "UNIQUE")]),
        row(&[("uid", "ONE-MATCH")]),
        row(&[("uid", "AMBIGUOUS")]),
        row(&[("uid", "INCONSISTENT")]),
    ]);
    let mut index = FlowCorrelationIndex::default();
    index.insert(
        "UNIQUE",
        candidate(
            "flow-unique",
            "192.0.2.1",
            "198.51.100.2",
            Some(53000),
            Some(53),
            17,
        ),
    );
    index.insert(
        "ONE-MATCH",
        candidate(
            "flow-wrong",
            "192.0.2.9",
            "198.51.100.2",
            Some(53000),
            Some(53),
            17,
        ),
    );
    index.insert(
        "ONE-MATCH",
        candidate(
            "flow-match",
            "192.0.2.1",
            "198.51.100.2",
            Some(53000),
            Some(53),
            17,
        ),
    );
    for id in ["flow-a", "flow-b"] {
        index.insert(
            "AMBIGUOUS",
            candidate(id, "192.0.2.1", "198.51.100.2", Some(53000), Some(53), 17),
        );
    }
    index.insert(
        "INCONSISTENT",
        candidate(
            "flow-other",
            "192.0.2.1",
            "198.51.100.99",
            Some(53000),
            Some(53),
            17,
        ),
    );

    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), Some(&index));
    assert_eq!(produced.observations.len(), 5);
    assert_eq!(dns_data(&produced.observations[0]).flow_record_id, None);
    assert_eq!(
        dns_data(&produced.observations[1])
            .flow_record_id
            .as_deref(),
        Some("flow-unique")
    );
    assert_eq!(
        dns_data(&produced.observations[2])
            .flow_record_id
            .as_deref(),
        Some("flow-match")
    );
    assert_eq!(dns_data(&produced.observations[3]).flow_record_id, None);
    assert_eq!(dns_data(&produced.observations[4]).flow_record_id, None);
    assert_eq!(
        produced
            .diagnostics
            .iter()
            .filter(|item| item.kind == DiagnosticKind::AmbiguousFlowLink)
            .count(),
        1
    );
    assert_eq!(
        produced
            .diagnostics
            .iter()
            .filter(|item| item.kind == DiagnosticKind::InconsistentFlowLink)
            .count(),
        1
    );
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn correlation_allows_missing_optional_ports_and_normalized_ipv6() {
    let parsed = parse_rows(&[row(&[
        ("uid", "V6"),
        ("id.orig_h", "2001:0DB8:0000:0000:0000:0000:0000:0001"),
        ("id.resp_h", "2001:DB8::2"),
        ("id.orig_p", "-"),
        ("id.resp_p", "-"),
        ("proto", "tcp"),
        ("ip_proto", "6"),
    ])]);
    let mut index = FlowCorrelationIndex::default();
    index.insert(
        "V6",
        candidate(
            "flow-v6",
            "2001:db8::1",
            "2001:db8::2",
            Some(44444),
            Some(53),
            6,
        ),
    );
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), Some(&index));
    let data = dns_data(&produced.observations[0]);
    assert_eq!(data.src_ip, "2001:db8::1");
    assert_eq!(data.dst_ip, "2001:db8::2");
    assert_eq!(data.flow_record_id.as_deref(), Some("flow-v6"));
    assert_contract_valid(&produced.observations[0]);
}

#[test]
fn invalid_required_facts_skip_only_affected_dns_rows() {
    let parsed = parse_rows(&[
        row(&[("uid", "BAD-TIME"), ("ts", "1e3")]),
        row(&[("uid", "BAD-SRC"), ("id.orig_h", "not-ip")]),
        row(&[("uid", "BAD-DST"), ("id.resp_h", "not-ip")]),
        row(&[("uid", "NO-PROTO"), ("proto", "bogus"), ("ip_proto", "-")]),
        row(&[("uid", "GOOD")]),
    ]);
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 1);
    assert_eq!(
        produced.observations[0].source_record_id.as_deref(),
        Some("GOOD")
    );
    assert!(produced
        .diagnostics
        .iter()
        .any(|item| item.kind == DiagnosticKind::MalformedDecimalTimestamp));
    assert!(produced
        .diagnostics
        .iter()
        .any(|item| item.kind == DiagnosticKind::InvalidIp));
    assert!(produced
        .diagnostics
        .iter()
        .any(|item| item.kind == DiagnosticKind::InvalidProtocolField));
    assert_contract_valid(&produced.observations[0]);
}

#[test]
fn protocol_resolution_uses_numeric_priority_and_never_port_guessing() {
    let parsed = parse_rows(&[
        row(&[("uid", "CONFLICT"), ("proto", "udp"), ("ip_proto", "6")]),
        row(&[("uid", "FALLBACK"), ("proto", "tcp"), ("ip_proto", "bad")]),
        row(&[
            ("uid", "PORT53"),
            ("proto", "bogus"),
            ("ip_proto", "-"),
            ("id.resp_p", "53"),
        ]),
    ]);
    let produced = produce_dns_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 2);
    assert_eq!(dns_data(&produced.observations[0]).ip_protocol, 6);
    assert_eq!(dns_data(&produced.observations[1]).ip_protocol, 6);
    assert!(produced
        .diagnostics
        .iter()
        .any(|item| item.kind == DiagnosticKind::ConflictingProtocolFields));
    assert!(produced.diagnostics.iter().any(|item| {
        item.kind == DiagnosticKind::InvalidProtocolField
            && item.source_record_id.as_deref() == Some("PORT53")
    }));
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}
