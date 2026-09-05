use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use ingestion_core::canonical::correlation::{FlowCorrelationCandidate, FlowCorrelationIndex};
use ingestion_core::canonical::http_producer::produce_http_observations_from_parse;
use ingestion_core::canonical::producer::FlowProducerConfig;
use ingestion_core::canonical::{CanonicalData, Fidelity};
use ingestion_core::zeek_parser::http_log::parse_http_log_lossless;
use ingestion_core::zeek_parser::source_types::{
    DiagnosticKind, LosslessParseResult, ZeekHttpRecord,
};

const INPUT_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OBSERVED_AT: &str = "2026-08-30T12:34:56.123456Z";
const FIELDS: [&str; 17] = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "ip_proto",
    "trans_depth",
    "method",
    "host",
    "uri",
    "user_agent",
    "status_code",
    "request_body_len",
    "response_body_len",
    "unknown_source_field",
];

fn row(overrides: &[(&str, &str)]) -> String {
    let mut values = vec![
        "1",
        "H1",
        "192.0.2.10",
        "51000",
        "198.51.100.20",
        "8080",
        "tcp",
        "6",
        "1",
        "PATCH",
        "MiXeD.Example",
        "/Case/Path?X=1",
        "Agent/Case-Sensitive",
        "200",
        "0",
        "128",
        "ignored",
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

fn parse_rows(rows: &[String]) -> LosslessParseResult<ZeekHttpRecord> {
    let content = format!(
        "#empty_field\t(empty)\n#unset_field\t-\n#fields\t{}\n{}\n",
        FIELDS.join("\t"),
        rows.join("\n")
    );
    parse_http_log_lossless(&content).unwrap()
}

fn config(observed_at: &str) -> FlowProducerConfig {
    FlowProducerConfig::new("sensor-alpha", INPUT_HASH, observed_at).unwrap()
}

fn http_data(
    observation: &ingestion_core::canonical::CanonicalObservation,
) -> &ingestion_core::canonical::HttpData {
    let CanonicalData::Http(data) = &observation.data else {
        panic!("expected HTTP data");
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
        "generated HTTP failed frozen schema validation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn full_http_preserves_raw_source_facts_status_body_quality_and_schema() {
    let parsed = parse_rows(&[row(&[("ts", "0.123456789")])]);
    let produced = produce_http_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 1);
    let observation = &produced.observations[0];
    let data = http_data(observation);
    assert_eq!(data.event_time, "1970-01-01T00:00:00.123456789Z");
    assert_eq!(data.src_ip, "192.0.2.10");
    assert_eq!(data.dst_ip, "198.51.100.20");
    assert_eq!(data.src_port, 51000);
    assert_eq!(data.dst_port, 8080);
    assert_eq!(data.ip_protocol, 6);
    assert_eq!(data.method.as_deref(), Some("PATCH"));
    assert_eq!(data.host.as_deref(), Some("MiXeD.Example"));
    assert_eq!(data.uri.as_deref(), Some("/Case/Path?X=1"));
    assert_eq!(data.user_agent.as_deref(), Some("Agent/Case-Sensitive"));
    assert_eq!(data.status_code, Some(200));
    assert_eq!(data.request_body_bytes, Some(0));
    assert_eq!(data.response_body_bytes, Some(128));
    assert_eq!(observation.quality.fidelity, Fidelity::Exact);
    assert_eq!(observation.quality.missed_content_bytes, None);
    let serialized = serde_json::to_value(observation).unwrap();
    assert!(serialized["data"].get("trans_depth").is_none());
    assert!(serialized["data"].get("unknown_source_field").is_none());
    assert_contract_valid(observation);
}

#[test]
fn http_optional_strings_preserve_empty_only_where_schema_allows_it() {
    let parsed = parse_rows(&[
        row(&[
            ("uid", "EMPTY-MARKERS"),
            ("method", "(empty)"),
            ("host", "(empty)"),
            ("uri", "(empty)"),
            ("user_agent", "(empty)"),
            ("status_code", "-"),
        ]),
        row(&[
            ("uid", "MISSING"),
            ("method", "-"),
            ("host", "-"),
            ("uri", "-"),
            ("user_agent", "-"),
        ]),
    ]);
    let produced = produce_http_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    let empty = http_data(&produced.observations[0]);
    assert_eq!(empty.method, None);
    assert_eq!(empty.host, None);
    assert_eq!(empty.uri.as_deref(), Some(""));
    assert_eq!(empty.user_agent.as_deref(), Some(""));
    assert_eq!(empty.status_code, None);
    let missing = http_data(&produced.observations[1]);
    assert_eq!(missing.method, None);
    assert_eq!(missing.host, None);
    assert_eq!(missing.uri, None);
    assert_eq!(missing.user_agent, None);
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn http_status_and_body_failures_never_fabricate_zero() {
    let parsed = parse_rows(&[
        row(&[("uid", "MAX"), ("status_code", "599")]),
        row(&[("uid", "ZERO"), ("status_code", "0")]),
        row(&[("uid", "HIGH"), ("status_code", "600")]),
        row(&[("uid", "BAD"), ("status_code", "bad")]),
        row(&[
            ("uid", "BODIES"),
            ("request_body_len", "-1"),
            ("response_body_len", "18446744073709551616"),
        ]),
    ]);
    let produced = produce_http_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 5);
    assert_eq!(http_data(&produced.observations[0]).status_code, Some(599));
    assert_eq!(http_data(&produced.observations[1]).status_code, None);
    assert_eq!(http_data(&produced.observations[2]).status_code, None);
    assert_eq!(http_data(&produced.observations[3]).status_code, None);
    let bodies = http_data(&produced.observations[4]);
    assert_eq!(bodies.request_body_bytes, None);
    assert_eq!(bodies.response_body_bytes, None);
    assert!(
        produced
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.kind == DiagnosticKind::OutOfRangeValue)
            .count()
            >= 2
    );
    assert!(produced
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == DiagnosticKind::MalformedInteger));
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn invalid_required_http_facts_skip_only_affected_rows() {
    let parsed = parse_rows(&[
        row(&[("uid", "BAD-TIME"), ("ts", "1e3")]),
        row(&[("uid", "BAD-IP"), ("id.resp_h", "not-ip")]),
        row(&[("uid", "NO-PORT"), ("id.orig_p", "-")]),
        row(&[("uid", "BAD-PORT"), ("id.resp_p", "70000")]),
        row(&[("uid", "GOOD")]),
    ]);
    let produced = produce_http_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 1);
    assert_eq!(
        produced.observations[0].source_record_id.as_deref(),
        Some("GOOD")
    );
}

#[test]
fn http_protocol_resolution_and_enrichment_obey_exact_candidate_policy() {
    let parsed = parse_rows(&[
        row(&[("uid", "CONFLICT"), ("proto", "tcp"), ("ip_proto", "17")]),
        row(&[("uid", "NAMED"), ("proto", "tcp"), ("ip_proto", "-")]),
        row(&[("uid", "UNIQUE"), ("proto", "-"), ("ip_proto", "-")]),
        row(&[("uid", "NONE"), ("proto", "-"), ("ip_proto", "-")]),
        row(&[("uid", "AMB"), ("proto", "-"), ("ip_proto", "-")]),
        row(&[("uid", "INC"), ("proto", "-"), ("ip_proto", "-")]),
    ]);
    let mut index = FlowCorrelationIndex::default();
    index.insert(
        "UNIQUE",
        candidate("flow-unique", "192.0.2.10", "198.51.100.20", 51000, 8080, 6),
    );
    for id in ["flow-a", "flow-b"] {
        index.insert(
            "AMB",
            candidate(id, "192.0.2.10", "198.51.100.20", 51000, 8080, 6),
        );
    }
    index.insert(
        "INC",
        candidate("flow-other", "192.0.2.10", "198.51.100.99", 51000, 8080, 17),
    );
    let produced =
        produce_http_observations_from_parse(&parsed, &config(OBSERVED_AT), Some(&index));
    assert_eq!(produced.observations.len(), 3);
    assert_eq!(http_data(&produced.observations[0]).ip_protocol, 17);
    assert_eq!(http_data(&produced.observations[1]).ip_protocol, 6);
    let enriched = http_data(&produced.observations[2]);
    assert_eq!(enriched.ip_protocol, 6);
    assert_eq!(enriched.flow_record_id.as_deref(), Some("flow-unique"));
    for expected in [
        DiagnosticKind::ConflictingProtocolFields,
        DiagnosticKind::MissingRequiredProtocol,
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
fn three_identical_http_rows_survive_with_fixed_clock_independent_ids() {
    let parsed = parse_rows(&[
        row(&[("ts", "5")]),
        row(&[("ts", "5")]),
        row(&[("ts", "5")]),
    ]);
    let first = produce_http_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    let replay =
        produce_http_observations_from_parse(&parsed, &config("2026-08-30T12:35:00Z"), None);
    assert_eq!(first.observations.len(), 3);
    assert_eq!(
        first.observations[0].record_id,
        "32eebf67-4ea9-5512-9f36-e92cd741fd20"
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
        assert_eq!(http_data(left).event_time, "1970-01-01T00:00:05Z");
        assert_contract_valid(left);
    }
}

#[test]
fn http_ipv6_direct_protocol_and_optional_flow_link_are_normalized() {
    let parsed = parse_rows(&[row(&[
        ("uid", "V6"),
        ("id.orig_h", "2001:0DB8:0000:0000:0000:0000:0000:0001"),
        ("id.resp_h", "2001:DB8::2"),
    ])]);
    let mut index = FlowCorrelationIndex::default();
    index.insert(
        "V6",
        candidate("flow-v6", "2001:db8::1", "2001:db8::2", 51000, 8080, 6),
    );
    let produced =
        produce_http_observations_from_parse(&parsed, &config(OBSERVED_AT), Some(&index));
    let data = http_data(&produced.observations[0]);
    assert_eq!(data.src_ip, "2001:db8::1");
    assert_eq!(data.dst_ip, "2001:db8::2");
    assert_eq!(data.flow_record_id.as_deref(), Some("flow-v6"));
    assert_contract_valid(&produced.observations[0]);
}

#[test]
fn http_optional_link_requires_exact_present_ports_and_unique_candidate() {
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
            "192.0.2.10",
            "198.51.100.20",
            None,
            Some(8080),
            6,
        ),
    );
    index.insert(
        "MISS-DST",
        candidate_with_ports(
            "flow-missing-dst",
            "192.0.2.10",
            "198.51.100.20",
            Some(51000),
            None,
            6,
        ),
    );
    index.insert(
        "ONE-EXACT",
        candidate(
            "flow-wrong-port",
            "192.0.2.10",
            "198.51.100.20",
            50999,
            8080,
            6,
        ),
    );
    index.insert(
        "ONE-EXACT",
        candidate("flow-exact", "192.0.2.10", "198.51.100.20", 51000, 8080, 6),
    );
    for id in ["flow-duplicate-a", "flow-duplicate-b"] {
        index.insert(
            "DUPLICATE",
            candidate(id, "192.0.2.10", "198.51.100.20", 51000, 8080, 6),
        );
    }

    let produced =
        produce_http_observations_from_parse(&parsed, &config(OBSERVED_AT), Some(&index));
    assert_eq!(produced.observations.len(), 4);
    assert_eq!(http_data(&produced.observations[0]).flow_record_id, None);
    assert_eq!(http_data(&produced.observations[1]).flow_record_id, None);
    assert_eq!(
        http_data(&produced.observations[2])
            .flow_record_id
            .as_deref(),
        Some("flow-exact")
    );
    assert_eq!(http_data(&produced.observations[3]).flow_record_id, None);
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
        assert_eq!(http_data(observation).ip_protocol, 6);
        assert_contract_valid(observation);
    }
}

#[test]
fn http_port_zero_protocol_fallback_and_uidless_direct_row_are_preserved() {
    let parsed = parse_rows(&[
        row(&[("uid", "ZERO"), ("id.resp_p", "0")]),
        row(&[
            ("uid", "BAD-NUMERIC"),
            ("ip_proto", "bad"),
            ("proto", "tcp"),
        ]),
        row(&[("uid", "RANGE"), ("ip_proto", "999"), ("proto", "udp")]),
        row(&[("uid", "-")]),
    ]);
    let produced = produce_http_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 4);
    assert_eq!(http_data(&produced.observations[0]).dst_port, 0);
    assert_eq!(http_data(&produced.observations[1]).ip_protocol, 6);
    assert_eq!(http_data(&produced.observations[2]).ip_protocol, 17);
    assert_eq!(produced.observations[3].source_record_id, None);
    assert_eq!(http_data(&produced.observations[3]).flow_record_id, None);
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
fn http_status_lower_bound_and_response_body_zero_are_preserved() {
    let parsed = parse_rows(&[
        row(&[("uid", "LOWER"), ("status_code", "100")]),
        row(&[("uid", "BELOW"), ("status_code", "99")]),
        row(&[("uid", "ZERO-BODY"), ("response_body_len", "0")]),
    ]);
    let produced = produce_http_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 3);
    assert_eq!(http_data(&produced.observations[0]).status_code, Some(100));
    assert_eq!(http_data(&produced.observations[1]).status_code, None);
    assert_eq!(
        http_data(&produced.observations[2]).response_body_bytes,
        Some(0)
    );
    assert!(produced.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == DiagnosticKind::OutOfRangeValue
            && diagnostic.source_record_id.as_deref() == Some("BELOW")
            && diagnostic.raw_value.as_deref() == Some("99")
    }));
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn http_unknown_sensitive_source_fields_never_serialize() {
    let content = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tip_proto\tmethod\thost\turi\tuser_agent\tstatus_code\trequest_body_len\tresponse_body_len\tusername\tpassword\treferrer\tarbitrary_unknown_field\n\
1\tRICH-HTTP\t192.0.2.10\t51000\t198.51.100.20\t8080\ttcp\t6\tGET\texample.test\t/safe\tAgent/1\t200\t0\t0\tplaceholder-user\tplaceholder-password\tplaceholder-referrer\tplaceholder-unknown\n";
    let parsed = parse_http_log_lossless(content).unwrap();
    let produced = produce_http_observations_from_parse(&parsed, &config(OBSERVED_AT), None);
    assert_eq!(produced.observations.len(), 1);
    let serialized = serde_json::to_value(&produced.observations[0]).unwrap();
    for field in [
        "username",
        "password",
        "referrer",
        "arbitrary_unknown_field",
    ] {
        assert!(serialized["data"].get(field).is_none());
    }
    assert_contract_valid(&produced.observations[0]);
}
