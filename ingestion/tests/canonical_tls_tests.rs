use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use ingestion_core::canonical::correlation::{FlowCorrelationCandidate, FlowCorrelationIndex};
use ingestion_core::canonical::producer::{
    FlowProducerConfig, ZEEK_PARSER_NAME, ZEEK_PARSER_VERSION,
};
use ingestion_core::canonical::tls_producer::produce_tls_observations_from_parse;
use ingestion_core::canonical::{CanonicalData, Fidelity, InputMode};
use ingestion_core::zeek_parser::source_types::{
    DiagnosticKind, LosslessParseResult, ZeekTlsRecord,
};
use ingestion_core::zeek_parser::ssl_log::parse_ssl_log_lossless;

const INPUT_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OBSERVED_AT: &str = "2026-08-30T12:34:56.123456Z";
const FIELDS: [&str; 14] = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "ip_proto",
    "version",
    "cipher",
    "server_name",
    "ja3",
    "ja3s",
    "ja4",
];

fn row(overrides: &[(&str, &str)]) -> String {
    let mut values = vec![
        "1",
        "T1",
        "192.0.2.1",
        "50000",
        "198.51.100.2",
        "443",
        "tcp",
        "6",
        "TLSv13",
        "TLS_AES_128_GCM_SHA256",
        "MiXeD.Example",
        "client-fingerprint",
        "server-fingerprint",
        "ja4-token",
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

fn parse_rows(rows: &[String]) -> LosslessParseResult<ZeekTlsRecord> {
    let content = format!(
        "#empty_field\t(empty)\n#unset_field\t-\n#fields\t{}\n{}\n",
        FIELDS.join("\t"),
        rows.join("\n")
    );
    parse_ssl_log_lossless(&content).unwrap()
}

fn config(observed_at: &str) -> FlowProducerConfig {
    FlowProducerConfig::new("sensor-alpha", INPUT_HASH, observed_at).unwrap()
}

fn tls_data(
    observation: &ingestion_core::canonical::CanonicalObservation,
) -> &ingestion_core::canonical::TlsData {
    let CanonicalData::Tls(data) = &observation.data else {
        panic!("expected TLS data");
    };
    data
}

fn candidate(
    record_id: &str,
    src_ip: &str,
    dst_ip: &str,
    src_port: u16,
    dst_port: u16,
    ip_protocol: u8,
) -> FlowCorrelationCandidate {
    candidate_with_ports(
        record_id,
        src_ip,
        dst_ip,
        Some(src_port),
        Some(dst_port),
        ip_protocol,
    )
}

fn candidate_with_ports(
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

fn assert_contract_valid(observation: &ingestion_core::canonical::CanonicalObservation) {
    let schema = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("contracts/canonical_observation_v1.schema.json");
    let script = "$json=[Console]::In.ReadToEnd(); $errors=@(); \
        $ok=Test-Json -Json $json -SchemaFile $env:M1C_SCHEMA_PATH \
        -ErrorAction SilentlyContinue -ErrorVariable errors; \
        if(-not $ok){ $errors | ForEach-Object { [Console]::Error.WriteLine($_) }; exit 1 }";
    let mut child = Command::new("pwsh")
        .args(["-NoProfile", "-Command", script])
        .env("M1C_SCHEMA_PATH", schema)
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
        "generated TLS failed frozen schema validation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn full_tls_preserves_raw_source_facts_quality_and_provenance() {
    let parsed = parse_rows(&[row(&[("ts", "0.123456789")])]);
    let produced = produce_tls_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 1);
    let observation = &produced.observations[0];
    let data = tls_data(observation);
    assert_eq!(data.event_time, "1970-01-01T00:00:00.123456789Z");
    assert_eq!(data.src_ip, "192.0.2.1");
    assert_eq!(data.dst_ip, "198.51.100.2");
    assert_eq!(data.src_port, 50000);
    assert_eq!(data.dst_port, 443);
    assert_eq!(data.ip_protocol, 6);
    assert_eq!(data.version.as_deref(), Some("TLSv13"));
    assert_eq!(data.cipher.as_deref(), Some("TLS_AES_128_GCM_SHA256"));
    assert_eq!(data.server_name.as_deref(), Some("MiXeD.Example"));
    assert_eq!(data.ja3.as_deref(), Some("client-fingerprint"));
    assert_eq!(data.ja3s.as_deref(), Some("server-fingerprint"));
    assert_eq!(data.ja4.as_deref(), Some("ja4-token"));
    assert_eq!(data.flow_record_id, None);
    assert_eq!(observation.quality.fidelity, Fidelity::Exact);
    assert_eq!(observation.quality.sampling_rate, None);
    assert_eq!(observation.quality.sampling_probability, None);
    assert!(!observation.quality.truncated);
    assert!(!observation.quality.loss_detected);
    assert_eq!(observation.quality.missed_content_bytes, None);
    assert_eq!(observation.provenance.input_mode, InputMode::PcapFile);
    assert_eq!(observation.provenance.parser_name, ZEEK_PARSER_NAME);
    assert_eq!(observation.provenance.parser_version, ZEEK_PARSER_VERSION);
    assert_contract_valid(observation);
}

#[test]
fn partial_tls_omits_all_optional_metadata_without_fabrication() {
    let parsed = parse_rows(&[row(&[
        ("version", "-"),
        ("cipher", "(empty)"),
        ("server_name", "-"),
        ("ja3", "-"),
        ("ja3s", "(empty)"),
        ("ja4", "-"),
    ])]);
    let produced = produce_tls_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    let data = tls_data(&produced.observations[0]);
    assert_eq!(data.version, None);
    assert_eq!(data.cipher, None);
    assert_eq!(data.server_name, None);
    assert_eq!(data.ja3, None);
    assert_eq!(data.ja3s, None);
    assert_eq!(data.ja4, None);
    assert_contract_valid(&produced.observations[0]);
}

#[test]
fn invalid_required_tls_facts_skip_only_affected_rows() {
    let parsed = parse_rows(&[
        row(&[("uid", "BAD-TIME"), ("ts", "1e3")]),
        row(&[("uid", "BAD-IP"), ("id.orig_h", "not-ip")]),
        row(&[("uid", "NO-PORT"), ("id.orig_p", "-")]),
        row(&[("uid", "BAD-PORT"), ("id.resp_p", "70000")]),
        row(&[("uid", "GOOD")]),
    ]);
    let produced = produce_tls_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 1);
    assert_eq!(
        produced.observations[0].source_record_id.as_deref(),
        Some("GOOD")
    );
    for expected in [
        DiagnosticKind::MalformedDecimalTimestamp,
        DiagnosticKind::InvalidIp,
        DiagnosticKind::MissingRequiredField,
        DiagnosticKind::OutOfRangeValue,
    ] {
        assert!(produced
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == expected));
    }
}

#[test]
fn direct_protocol_priority_and_optional_linking_never_guess() {
    let parsed = parse_rows(&[
        row(&[("uid", "CONFLICT"), ("proto", "tcp"), ("ip_proto", "17")]),
        row(&[("uid", "NAMED"), ("proto", "tcp"), ("ip_proto", "-")]),
        row(&[("uid", "LINK-UNIQUE")]),
        row(&[("uid", "LINK-AMB")]),
        row(&[("uid", "LINK-INC")]),
    ]);
    let mut index = FlowCorrelationIndex::default();
    index.insert(
        "LINK-UNIQUE",
        candidate(
            "flow-unique-link",
            "192.0.2.1",
            "198.51.100.2",
            50000,
            443,
            6,
        ),
    );
    for id in ["flow-a", "flow-b"] {
        index.insert(
            "LINK-AMB",
            candidate(id, "192.0.2.1", "198.51.100.2", 50000, 443, 6),
        );
    }
    index.insert(
        "LINK-INC",
        candidate("flow-other", "192.0.2.1", "198.51.100.99", 50000, 443, 6),
    );
    let produced = produce_tls_observations_from_parse(&parsed, &config(OBSERVED_AT), Some(&index));
    assert_eq!(produced.observations.len(), 5);
    assert_eq!(tls_data(&produced.observations[0]).ip_protocol, 17);
    assert_eq!(tls_data(&produced.observations[1]).ip_protocol, 6);
    assert_eq!(
        tls_data(&produced.observations[2])
            .flow_record_id
            .as_deref(),
        Some("flow-unique-link")
    );
    assert_eq!(tls_data(&produced.observations[3]).flow_record_id, None);
    assert_eq!(tls_data(&produced.observations[4]).flow_record_id, None);
    for expected in [
        DiagnosticKind::ConflictingProtocolFields,
        DiagnosticKind::AmbiguousFlowLink,
        DiagnosticKind::InconsistentFlowLink,
    ] {
        assert!(produced
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == expected));
    }
}

#[test]
fn required_protocol_enrichment_requires_exactly_one_endpoint_match() {
    let parsed = parse_rows(&[
        row(&[("uid", "UNIQUE"), ("proto", "-"), ("ip_proto", "-")]),
        row(&[("uid", "NONE"), ("proto", "-"), ("ip_proto", "-")]),
        row(&[("uid", "AMB"), ("proto", "-"), ("ip_proto", "-")]),
        row(&[("uid", "INC"), ("proto", "-"), ("ip_proto", "-")]),
    ]);
    let mut index = FlowCorrelationIndex::default();
    index.insert(
        "UNIQUE",
        candidate("flow-unique", "192.0.2.1", "198.51.100.2", 50000, 443, 6),
    );
    for id in ["flow-a", "flow-b"] {
        index.insert(
            "AMB",
            candidate(id, "192.0.2.1", "198.51.100.2", 50000, 443, 6),
        );
    }
    index.insert(
        "INC",
        candidate("flow-other", "192.0.2.1", "198.51.100.99", 50000, 443, 17),
    );
    let produced = produce_tls_observations_from_parse(&parsed, &config(OBSERVED_AT), Some(&index));
    assert_eq!(produced.observations.len(), 1);
    let data = tls_data(&produced.observations[0]);
    assert_eq!(data.ip_protocol, 6);
    assert_eq!(data.flow_record_id.as_deref(), Some("flow-unique"));
    for expected in [
        DiagnosticKind::MissingRequiredProtocol,
        DiagnosticKind::AmbiguousFlowLink,
        DiagnosticKind::InconsistentFlowLink,
    ] {
        assert!(produced
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.kind == expected));
    }
    assert_contract_valid(&produced.observations[0]);
}

#[test]
fn tls_repeated_rows_have_fixed_distinct_clock_independent_ids() {
    let parsed = parse_rows(&[
        row(&[("ts", "5")]),
        row(&[("ts", "5")]),
        row(&[("ts", "5")]),
    ]);
    let first = produce_tls_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    let replay =
        produce_tls_observations_from_parse(&parsed, &config("2026-08-30T12:35:00Z"), None);
    assert_eq!(first.observations.len(), 3);
    assert_eq!(
        first.observations[0].record_id,
        "58ce231f-c0a5-5f89-8f45-53e118bb7d56"
    );
    assert_eq!(
        first
            .observations
            .iter()
            .map(|observation| observation.record_id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    for (left, right) in first.observations.iter().zip(&replay.observations) {
        assert_eq!(left.record_id, right.record_id);
        assert_eq!(tls_data(left).event_time, "1970-01-01T00:00:05Z");
        assert_contract_valid(left);
    }
}

#[test]
fn tls_ja4_is_per_row_and_never_changes_canonical_identity() {
    let with_values = parse_rows(&[
        row(&[("ts", "7"), ("ja4", "first-source-ja4")]),
        row(&[("ts", "7"), ("ja4", "second-source-ja4")]),
    ]);
    let without_values = parse_rows(&[
        row(&[("ts", "7"), ("ja4", "-")]),
        row(&[("ts", "7"), ("ja4", "-")]),
    ]);
    let enriched = produce_tls_observations_from_parse(&with_values, &config(OBSERVED_AT), None);
    let absent = produce_tls_observations_from_parse(&without_values, &config(OBSERVED_AT), None);

    assert_eq!(enriched.observations.len(), 2);
    assert_eq!(
        tls_data(&enriched.observations[0]).ja4.as_deref(),
        Some("first-source-ja4")
    );
    assert_eq!(
        tls_data(&enriched.observations[1]).ja4.as_deref(),
        Some("second-source-ja4")
    );
    assert_eq!(tls_data(&absent.observations[0]).ja4, None);
    assert_eq!(tls_data(&absent.observations[1]).ja4, None);
    assert_eq!(
        enriched
            .observations
            .iter()
            .map(|observation| observation.record_id.as_str())
            .collect::<Vec<_>>(),
        absent
            .observations
            .iter()
            .map(|observation| observation.record_id.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn tls_ipv6_protocol_enrichment_normalizes_endpoints() {
    let parsed = parse_rows(&[row(&[
        ("uid", "V6"),
        ("id.orig_h", "2001:0DB8:0000:0000:0000:0000:0000:0001"),
        ("id.resp_h", "2001:DB8::2"),
        ("proto", "-"),
        ("ip_proto", "-"),
    ])]);
    let mut index = FlowCorrelationIndex::default();
    index.insert(
        "V6",
        candidate("flow-v6", "2001:db8::1", "2001:db8::2", 50000, 443, 6),
    );
    let produced = produce_tls_observations_from_parse(&parsed, &config(OBSERVED_AT), Some(&index));
    let data = tls_data(&produced.observations[0]);
    assert_eq!(data.src_ip, "2001:db8::1");
    assert_eq!(data.dst_ip, "2001:db8::2");
    assert_eq!(data.flow_record_id.as_deref(), Some("flow-v6"));
    assert_contract_valid(&produced.observations[0]);
}

#[test]
fn tls_optional_link_requires_exact_present_ports_and_unique_candidate() {
    let parsed = parse_rows(&[
        row(&[("uid", "MISS-SRC")]),
        row(&[("uid", "MISS-DST")]),
        row(&[("uid", "ONE-EXACT")]),
        row(&[("uid", "DUPLICATE")]),
    ]);
    let mut index = FlowCorrelationIndex::default();
    index.insert(
        "MISS-SRC",
        candidate_with_ports(
            "flow-missing-src",
            "192.0.2.1",
            "198.51.100.2",
            None,
            Some(443),
            6,
        ),
    );
    index.insert(
        "MISS-DST",
        candidate_with_ports(
            "flow-missing-dst",
            "192.0.2.1",
            "198.51.100.2",
            Some(50000),
            None,
            6,
        ),
    );
    index.insert(
        "ONE-EXACT",
        candidate(
            "flow-wrong-port",
            "192.0.2.1",
            "198.51.100.2",
            49999,
            443,
            6,
        ),
    );
    index.insert(
        "ONE-EXACT",
        candidate("flow-exact", "192.0.2.1", "198.51.100.2", 50000, 443, 6),
    );
    for id in ["flow-duplicate-a", "flow-duplicate-b"] {
        index.insert(
            "DUPLICATE",
            candidate(id, "192.0.2.1", "198.51.100.2", 50000, 443, 6),
        );
    }

    let produced = produce_tls_observations_from_parse(&parsed, &config(OBSERVED_AT), Some(&index));
    assert_eq!(produced.observations.len(), 4);
    assert_eq!(tls_data(&produced.observations[0]).flow_record_id, None);
    assert_eq!(tls_data(&produced.observations[1]).flow_record_id, None);
    assert_eq!(
        tls_data(&produced.observations[2])
            .flow_record_id
            .as_deref(),
        Some("flow-exact")
    );
    assert_eq!(tls_data(&produced.observations[3]).flow_record_id, None);
    assert_eq!(
        produced
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.kind == DiagnosticKind::InconsistentFlowLink)
            .count(),
        2
    );
    assert!(produced.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == DiagnosticKind::AmbiguousFlowLink
            && diagnostic.source_record_id.as_deref() == Some("DUPLICATE")
            && diagnostic.field.as_deref() == Some("flow_record_id")
    }));
    for observation in &produced.observations {
        assert_eq!(tls_data(observation).ip_protocol, 6);
        assert_contract_valid(observation);
    }
}

#[test]
fn tls_port_zero_protocol_fallback_and_uidless_direct_row_are_preserved() {
    let parsed = parse_rows(&[
        row(&[("uid", "ZERO"), ("id.orig_p", "0")]),
        row(&[
            ("uid", "BAD-NUMERIC"),
            ("ip_proto", "bad"),
            ("proto", "tcp"),
        ]),
        row(&[("uid", "RANGE"), ("ip_proto", "999"), ("proto", "udp")]),
        row(&[("uid", "-")]),
    ]);
    let produced = produce_tls_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 4);
    assert_eq!(tls_data(&produced.observations[0]).src_port, 0);
    assert_eq!(tls_data(&produced.observations[1]).ip_protocol, 6);
    assert_eq!(tls_data(&produced.observations[2]).ip_protocol, 17);
    assert_eq!(produced.observations[3].source_record_id, None);
    assert_eq!(tls_data(&produced.observations[3]).flow_record_id, None);
    assert!(produced
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == DiagnosticKind::InvalidProtocolField));
    assert!(produced
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == DiagnosticKind::OutOfRangeValue));
    assert!(!produced.diagnostics.iter().any(|diagnostic| {
        diagnostic.row_ordinal == Some(3)
            && diagnostic.kind == DiagnosticKind::MissingRequiredProtocol
    }));
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn tls_absent_ja4_and_unknown_source_fields_never_serialize() {
    let content = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tip_proto\tversion\tcipher\tserver_name\tja3\tja3s\tsubject\tissuer\tcurve\tcert_chain_fuids\tarbitrary_unknown_field\n\
1\tRICH-TLS\t192.0.2.1\t50000\t198.51.100.2\t443\ttcp\t6\tTLSv13\tTLS_AES_128_GCM_SHA256\texample.test\tclient-fp\tserver-fp\tplaceholder-subject\tplaceholder-issuer\tplaceholder-curve\tplaceholder-chain\tplaceholder-unknown\n";
    let parsed = parse_ssl_log_lossless(content).unwrap();
    assert_eq!(
        parsed.records[0].ja4,
        ingestion_core::zeek_parser::source_types::SourceValue::Missing
    );
    let produced = produce_tls_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 1);
    assert_eq!(tls_data(&produced.observations[0]).ja4, None);
    let serialized = serde_json::to_value(&produced.observations[0]).unwrap();
    for field in [
        "subject",
        "issuer",
        "curve",
        "cert_chain_fuids",
        "arbitrary_unknown_field",
    ] {
        assert!(serialized["data"].get(field).is_none());
    }
    assert_contract_valid(&produced.observations[0]);
}
