use std::io::Write;
use std::process::{Command, Stdio};

use ingestion_core::canonical::id::{
    generate_zeek_record_id, normalize_sha256, sha256_file, IdentityObservationType,
    InputIdentityError, ZeekLogName,
};
use ingestion_core::canonical::producer::{
    produce_flow_observations_from_parse, FlowProducerConfig, ZEEK_PARSER_NAME, ZEEK_PARSER_VERSION,
};
use ingestion_core::canonical::time::{
    validate_canonical_utc, zeek_end_time_to_rfc3339, zeek_timestamp_to_rfc3339, ExactTimeError,
};
use ingestion_core::canonical::{CanonicalData, DirectionMode, Fidelity, InputMode};
use ingestion_core::zeek_parser::conn_log::parse_conn_log_lossless;
use ingestion_core::zeek_parser::source_types::{DiagnosticKind, ZeekLogType};

const INPUT_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OBSERVED_AT: &str = "2026-08-30T12:34:56.123456Z";

fn conn_header() -> &'static str {
    "#separator \\x09\n\
#set_separator\t,\n\
#empty_field\t(empty)\n\
#unset_field\t-\n\
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tip_proto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts\torig_ip_bytes\tresp_ip_bytes\tmissed_bytes\n\
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\tcount\tcount\tcount\n"
}

fn parse_rows(
    rows: &[&str],
) -> ingestion_core::zeek_parser::source_types::LosslessParseResult<
    ingestion_core::zeek_parser::source_types::ZeekConnRecord,
> {
    let content = format!("{}{}\n", conn_header(), rows.join("\n"));
    parse_conn_log_lossless(&content).unwrap()
}

fn config(observed_at: &str) -> FlowProducerConfig {
    FlowProducerConfig::new("sensor-alpha", INPUT_HASH, observed_at).unwrap()
}

fn assert_contract_valid(observation: &ingestion_core::canonical::CanonicalObservation) {
    let schema = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("contracts/canonical_observation_v1.schema.json");
    let script = "$json=[Console]::In.ReadToEnd(); $errors=@(); \
        $ok=Test-Json -Json $json -SchemaFile $env:M1A_SCHEMA_PATH \
        -ErrorAction SilentlyContinue -ErrorVariable errors; \
        if(-not $ok){ $errors | ForEach-Object { [Console]::Error.WriteLine($_) }; exit 1 }";
    let mut child = Command::new("pwsh")
        .args(["-NoProfile", "-Command", script])
        .env("M1A_SCHEMA_PATH", schema)
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
        "generated flow failed frozen schema validation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn exact_time_conversion_covers_required_cases() {
    assert_eq!(
        zeek_timestamp_to_rfc3339("0").unwrap(),
        "1970-01-01T00:00:00Z"
    );
    assert_eq!(
        zeek_timestamp_to_rfc3339("0.123456789").unwrap(),
        "1970-01-01T00:00:00.123456789Z"
    );
    assert_eq!(
        zeek_end_time_to_rfc3339("0.999999999", "0.000000001").unwrap(),
        "1970-01-01T00:00:01Z"
    );
    assert_eq!(
        zeek_end_time_to_rfc3339("86399.75", "0.25").unwrap(),
        "1970-01-02T00:00:00Z"
    );
    assert_eq!(
        zeek_timestamp_to_rfc3339("1.0000000000").unwrap(),
        "1970-01-01T00:00:01Z"
    );
    assert_eq!(
        zeek_timestamp_to_rfc3339("1.0000000001"),
        Err(ExactTimeError::UnsupportedPrecision)
    );
    assert_eq!(
        zeek_timestamp_to_rfc3339("-0.1").unwrap(),
        "1969-12-31T23:59:59.900Z"
    );
    assert_eq!(
        zeek_timestamp_to_rfc3339("253402300800"),
        Err(ExactTimeError::OutOfRange)
    );
    assert_eq!(
        zeek_end_time_to_rfc3339("10", "-0.1"),
        Err(ExactTimeError::NegativeDuration)
    );
    assert_eq!(
        zeek_end_time_to_rfc3339("10", "bad"),
        Err(ExactTimeError::InvalidDecimal)
    );
    assert!(validate_canonical_utc(OBSERVED_AT).is_ok());
    assert!(validate_canonical_utc("2026-08-30T12:34:60Z").is_err());
    assert!(validate_canonical_utc("2026-08-30T12:34:56+00:00").is_err());
}

#[test]
fn uuidv5_has_a_fixed_vector_and_all_approved_coordinates() {
    let base = generate_zeek_record_id(
        "sensor-alpha",
        INPUT_HASH,
        IdentityObservationType::Flow,
        ZeekLogName::Conn,
        "C1",
        0,
    )
    .unwrap();
    assert_eq!(base, "e4583e96-47e8-54d0-98d9-50546d84facb");
    assert_eq!(
        base,
        generate_zeek_record_id(
            "sensor-alpha",
            &INPUT_HASH.to_uppercase(),
            IdentityObservationType::Flow,
            ZeekLogName::Conn,
            "C1",
            0,
        )
        .unwrap(),
        "the approved identity coordinate uses lowercase PCAP SHA-256"
    );
    assert!(generate_zeek_record_id(
        "",
        INPUT_HASH,
        IdentityObservationType::Flow,
        ZeekLogName::Conn,
        "C1",
        0,
    )
    .is_err());
    assert_eq!(
        base,
        generate_zeek_record_id(
            "sensor-alpha",
            INPUT_HASH,
            IdentityObservationType::Flow,
            ZeekLogName::Conn,
            "C1",
            0,
        )
        .unwrap()
    );

    let variants = [
        generate_zeek_record_id(
            "sensor-beta",
            INPUT_HASH,
            IdentityObservationType::Flow,
            ZeekLogName::Conn,
            "C1",
            0,
        )
        .unwrap(),
        generate_zeek_record_id(
            "sensor-alpha",
            &"f".repeat(64),
            IdentityObservationType::Flow,
            ZeekLogName::Conn,
            "C1",
            0,
        )
        .unwrap(),
        generate_zeek_record_id(
            "sensor-alpha",
            INPUT_HASH,
            IdentityObservationType::Dns,
            ZeekLogName::Conn,
            "C1",
            0,
        )
        .unwrap(),
        generate_zeek_record_id(
            "sensor-alpha",
            INPUT_HASH,
            IdentityObservationType::Flow,
            ZeekLogName::Dns,
            "C1",
            0,
        )
        .unwrap(),
        generate_zeek_record_id(
            "sensor-alpha",
            INPUT_HASH,
            IdentityObservationType::Flow,
            ZeekLogName::Conn,
            "C1",
            1,
        )
        .unwrap(),
    ];
    assert!(variants.iter().all(|value| value != &base));

    let empty_uid = generate_zeek_record_id(
        "sensor-alpha",
        INPUT_HASH,
        IdentityObservationType::Flow,
        ZeekLogName::Conn,
        "",
        0,
    )
    .unwrap();
    assert_ne!(empty_uid, base);
    assert_eq!(
        generate_zeek_record_id(
            "sénsor-α",
            INPUT_HASH,
            IdentityObservationType::Flow,
            ZeekLogName::Conn,
            "UID-λ",
            0,
        )
        .unwrap(),
        generate_zeek_record_id(
            "sénsor-α",
            INPUT_HASH,
            IdentityObservationType::Flow,
            ZeekLogName::Conn,
            "UID-λ",
            0,
        )
        .unwrap()
    );
}

#[test]
fn sha256_support_normalizes_and_hashes_original_artifact_bytes() {
    assert_eq!(
        normalize_sha256(&INPUT_HASH.to_uppercase()).unwrap(),
        INPUT_HASH
    );
    assert!(normalize_sha256("not-a-hash").is_err());

    let path = std::env::temp_dir().join(format!("m1a-sha256-{}.bin", std::process::id()));
    std::fs::write(&path, b"abc").unwrap();
    let digest = sha256_file(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(
        digest,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    let missing = std::env::temp_dir().join(format!(
        "m1a-sha256-missing-{}-never-created.bin",
        std::process::id()
    ));
    assert!(matches!(
        sha256_file(missing),
        Err(InputIdentityError::Io(_))
    ));
}

#[test]
fn flow_maps_raw_facts_counters_quality_and_provenance() {
    let parsed = parse_rows(&[
        "0.123456789\tC1\t192.0.2.1\t1234\t198.51.100.2\t80\ttcp\t6\thttp\t0.876543211\t0\t5\tSF\tShADadFf\t0\t1\t40\t60\t0",
    ]);
    let produced = produce_flow_observations_from_parse(&parsed, &config(OBSERVED_AT));
    assert!(produced.diagnostics.is_empty());
    assert_eq!(produced.observations.len(), 1);
    let observation = &produced.observations[0];
    assert_eq!(observation.schema_version, "1.0");
    assert_eq!(observation.source_record_id.as_deref(), Some("C1"));
    assert_eq!(observation.sensor_id, "sensor-alpha");
    assert_eq!(observation.observed_at, OBSERVED_AT);
    assert_eq!(observation.quality.fidelity, Fidelity::Exact);
    assert_eq!(observation.quality.sampling_rate, None);
    assert_eq!(observation.quality.sampling_probability, None);
    assert!(!observation.quality.truncated);
    assert!(!observation.quality.loss_detected);
    assert_eq!(observation.quality.missed_content_bytes, Some(0));
    assert_eq!(observation.provenance.input_mode, InputMode::PcapFile);
    assert_eq!(
        observation.provenance.input_sha256.as_deref(),
        Some(INPUT_HASH)
    );
    assert_eq!(observation.provenance.parser_name, ZEEK_PARSER_NAME);
    assert_eq!(observation.provenance.parser_version, ZEEK_PARSER_VERSION);

    let CanonicalData::Flow(flow) = &observation.data;
    assert_eq!(flow.start_time, "1970-01-01T00:00:00.123456789Z");
    assert_eq!(flow.end_time.as_deref(), Some("1970-01-01T00:00:01Z"));
    assert_eq!(flow.src_ip, "192.0.2.1");
    assert_eq!(flow.dst_ip, "198.51.100.2");
    assert_eq!(flow.src_port, Some(1234));
    assert_eq!(flow.dst_port, Some(80));
    assert_eq!(flow.ip_protocol, 6);
    assert_eq!(flow.direction_mode, DirectionMode::OriginatorResponder);
    assert_eq!(flow.service.as_deref(), Some("http"));
    assert_eq!(flow.connection_state.as_deref(), Some("SF"));
    assert_eq!(flow.connection_history.as_deref(), Some("ShADadFf"));
    assert_eq!(flow.counters.src_to_dst.packets, Some(0));
    assert_eq!(flow.counters.src_to_dst.payload_bytes, Some(0));
    assert_eq!(flow.counters.src_to_dst.ip_bytes, Some(40));
    assert_eq!(flow.counters.src_to_dst.l2_bytes, None);
    let reverse = flow.counters.dst_to_src.as_ref().unwrap();
    assert_eq!(reverse.packets, Some(1));
    assert_eq!(reverse.payload_bytes, Some(5));
    assert_eq!(reverse.ip_bytes, Some(60));
    assert_eq!(reverse.l2_bytes, None);
    let serialized = serde_json::to_value(observation).unwrap();
    assert!(serialized.get("source_record_index").is_none());
    assert!(serialized["quality"].get("sampling_rate").is_none());
    assert!(serialized["quality"].get("sampling_probability").is_none());
    assert!(serialized["data"]["counters"]["src_to_dst"]
        .get("l2_bytes")
        .is_none());
    assert_contract_valid(observation);
}

#[test]
fn ipv6_udp_icmp_missing_values_and_loss_are_mapped_without_fabrication() {
    let parsed = parse_rows(&[
        "1\tV6\t2001:db8::1\t123\t2001:db8::2\t443\ttcp\t6\t-\t-\t-\t-\tSF\t-\t1\t-\t60\t-\t-",
        "2\tUDP\t192.0.2.3\t0\t198.51.100.4\t53\tudp\t-\tdns\t0\t0\t0\tSF\tDd\t0\t0\t28\t28\t12",
        "3\tICMP\t192.0.2.4\t8\t198.51.100.5\t0\ticmp\t1\t-\t0\t-\t-\tOTH\t-\t1\t-\t84\t-\t0",
        "4\tPARTIAL\t192.0.2.6\tbad\t198.51.100.6\t443\ttcp\t6\t-\t-\t-\t2\tSF\t-\tbad\t1\t40\t60\t-",
    ]);
    let produced = produce_flow_observations_from_parse(&parsed, &config(OBSERVED_AT));
    assert_eq!(produced.observations.len(), 4);

    let CanonicalData::Flow(ipv6) = &produced.observations[0].data;
    assert_eq!(ipv6.src_ip, "2001:db8::1");
    assert_eq!(ipv6.end_time, None);
    assert_eq!(ipv6.service, None);
    assert_eq!(ipv6.counters.dst_to_src, None);

    let udp_observation = &produced.observations[1];
    assert!(udp_observation.quality.loss_detected);
    assert_eq!(udp_observation.quality.missed_content_bytes, Some(12));
    let CanonicalData::Flow(udp) = &udp_observation.data;
    assert_eq!(udp.ip_protocol, 17);
    assert_eq!(udp.src_port, Some(0));
    assert_eq!(udp.counters.src_to_dst.packets, Some(0));

    let CanonicalData::Flow(icmp) = &produced.observations[2].data;
    assert_eq!(icmp.ip_protocol, 1);
    assert_eq!(icmp.src_port, None);
    assert_eq!(icmp.dst_port, None);
    assert_eq!(icmp.icmp_type, None);
    assert_eq!(icmp.icmp_code, None);

    let CanonicalData::Flow(partial) = &produced.observations[3].data;
    assert_eq!(partial.src_port, None);
    assert_eq!(partial.counters.src_to_dst.packets, None);
    assert_eq!(partial.counters.src_to_dst.payload_bytes, None);
    assert_eq!(partial.counters.src_to_dst.ip_bytes, Some(40));

    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn invalid_required_facts_skip_only_the_affected_flow() {
    let parsed = parse_rows(&[
        "bad\tBADTIME\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\t6\t-\t0\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
        "1\tBADIP\tnot-ip\t1\t198.51.100.1\t2\ttcp\t6\t-\t0\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
        "2\tBADPROTO\t192.0.2.1\t1\t198.51.100.1\t2\tbogus\t-\t-\t0\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
        "3\tNOORIG\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\t6\t-\t0\t-\t1\tSF\t-\t-\t1\t-\t40\t0",
        "4\tGOOD\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\t6\t-\t0\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
    ]);
    let produced = produce_flow_observations_from_parse(&parsed, &config(OBSERVED_AT));
    assert_eq!(produced.observations.len(), 1);
    assert_eq!(
        produced.observations[0].source_record_id.as_deref(),
        Some("GOOD")
    );
    assert!(produced
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == DiagnosticKind::MissingRequiredCounters));
    assert!(produced
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == DiagnosticKind::InvalidProtocolField));
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn end_time_diagnostics_and_duplicate_uid_identity_are_correct() {
    let parsed = parse_rows(&[
        "10\tDUP\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\t6\t-\t-0.5\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
        "10\tDUP\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\t6\t-\tbad\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
        "10\tDUP\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\t6\t-\t0\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
    ]);
    let produced = produce_flow_observations_from_parse(&parsed, &config(OBSERVED_AT));
    assert_eq!(produced.observations.len(), 3);
    let ids: std::collections::HashSet<_> = produced
        .observations
        .iter()
        .map(|observation| observation.record_id.as_str())
        .collect();
    assert_eq!(ids.len(), 3);

    let CanonicalData::Flow(negative) = &produced.observations[0].data;
    let CanonicalData::Flow(malformed) = &produced.observations[1].data;
    let CanonicalData::Flow(zero) = &produced.observations[2].data;
    assert_eq!(negative.end_time, None);
    assert_eq!(malformed.end_time, None);
    assert_eq!(zero.end_time.as_deref(), Some("1970-01-01T00:00:10Z"));
    assert!(produced
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == DiagnosticKind::NegativeDuration));
    assert!(produced
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.kind == DiagnosticKind::MalformedDuration));
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }

    let other_clock = config("2026-08-30T12:35:00Z");
    let replay = produce_flow_observations_from_parse(&parsed, &other_clock);
    assert_eq!(
        produced.observations[0].record_id, replay.observations[0].record_id,
        "observed_at must not affect identity"
    );
    for observation in &replay.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn producer_configuration_requires_explicit_valid_inputs() {
    assert!(FlowProducerConfig::new("", INPUT_HASH, OBSERVED_AT).is_err());
    assert!(FlowProducerConfig::new("sensor", "bad", OBSERVED_AT).is_err());
    assert!(FlowProducerConfig::new("sensor", INPUT_HASH, "not-time").is_err());
}

#[test]
fn canonical_rejects_legacy_scientific_notation_timestamp() {
    let parsed = parse_rows(&[
        "1e3\tC-EXP\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\t6\t-\t0\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
        "1\tC-EXP-DURATION\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\t6\t-\t1e3\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
    ]);
    let produced = produce_flow_observations_from_parse(&parsed, &config(OBSERVED_AT));
    assert_eq!(produced.observations.len(), 1);
    assert_eq!(
        produced.observations[0].source_record_id.as_deref(),
        Some("C-EXP-DURATION")
    );
    let CanonicalData::Flow(duration) = &produced.observations[0].data;
    assert_eq!(duration.end_time, None);
    let diagnostic = produced
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.kind == DiagnosticKind::MalformedDecimalTimestamp)
        .unwrap();
    assert_eq!(diagnostic.log_type, ZeekLogType::Conn);
    assert_eq!(diagnostic.source_record_id.as_deref(), Some("C-EXP"));
    assert_eq!(diagnostic.row_ordinal, Some(0));
    assert!(produced.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == DiagnosticKind::MalformedDuration
            && diagnostic.source_record_id.as_deref() == Some("C-EXP-DURATION")
    }));
    assert_contract_valid(&produced.observations[0]);
}

#[test]
fn protocol_conflicts_and_invalid_numeric_values_use_approved_resolution() {
    let parsed = parse_rows(&[
        "1\tCONFLICT\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\t17\t-\t0\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
        "2\tOUTOFRANGE\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\t999\t-\t0\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
        "3\tMALFORMED\t192.0.2.1\t1\t198.51.100.1\t2\tudp\twat\t-\t0\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
    ]);
    let produced = produce_flow_observations_from_parse(&parsed, &config(OBSERVED_AT));
    assert_eq!(produced.observations.len(), 3);

    let CanonicalData::Flow(conflict) = &produced.observations[0].data;
    let CanonicalData::Flow(out_of_range) = &produced.observations[1].data;
    let CanonicalData::Flow(malformed) = &produced.observations[2].data;
    assert_eq!(conflict.ip_protocol, 17, "valid numeric source wins");
    assert_eq!(out_of_range.ip_protocol, 6, "known tcp fallback is used");
    assert_eq!(malformed.ip_protocol, 17, "known udp fallback is used");
    let legacy_conflict = ingestion_core::zeek_parser::types::FlowRecord::from(&parsed.records[0]);
    assert_eq!(legacy_conflict.proto, "tcp");
    let conflict_diagnostic = produced
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.kind == DiagnosticKind::ConflictingProtocolFields)
        .unwrap();
    assert_eq!(
        conflict_diagnostic.source_record_id.as_deref(),
        Some("CONFLICT")
    );
    assert_eq!(conflict_diagnostic.log_type, ZeekLogType::Conn);
    assert_eq!(
        produced
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.kind == DiagnosticKind::InvalidProtocolField)
            .count(),
        2
    );
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}

#[test]
fn one_originator_counter_and_malformed_optional_values_do_not_fabricate_zero() {
    let parsed = parse_rows(&[
        "1\tONECOUNTER\t192.0.2.1\t1\t198.51.100.1\t2\ttcp\t6\t-\t-\t-\t-\tSF\t-\t7\t-\t-\t-\tbad",
        "2\tBADPORT\t192.0.2.1\t1\t198.51.100.1\tbad\ttcp\t6\t-\t0\t1\t1\tSF\t-\t1\t1\t40\t40\t0",
    ]);
    let produced = produce_flow_observations_from_parse(&parsed, &config(OBSERVED_AT));
    assert_eq!(produced.observations.len(), 2);

    let one_counter_observation = &produced.observations[0];
    assert!(!one_counter_observation.quality.loss_detected);
    assert_eq!(one_counter_observation.quality.missed_content_bytes, None);
    let CanonicalData::Flow(one_counter) = &one_counter_observation.data;
    assert_eq!(one_counter.counters.src_to_dst.packets, Some(7));
    assert_eq!(one_counter.counters.src_to_dst.payload_bytes, None);
    assert_eq!(one_counter.counters.src_to_dst.ip_bytes, None);
    assert_eq!(one_counter.counters.dst_to_src, None);
    let serialized = serde_json::to_value(one_counter_observation).unwrap();
    assert!(serialized["data"]["counters"]["src_to_dst"]
        .get("payload_bytes")
        .is_none());
    assert!(serialized["data"]["counters"]["src_to_dst"]
        .get("ip_bytes")
        .is_none());

    let CanonicalData::Flow(bad_port) = &produced.observations[1].data;
    assert_eq!(bad_port.dst_port, None);
    assert!(produced.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == DiagnosticKind::MalformedInteger
            && diagnostic.source_record_id.as_deref() == Some("ONECOUNTER")
            && diagnostic.field.as_deref() == Some("missed_bytes")
    }));
    assert!(produced.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == DiagnosticKind::MalformedInteger
            && diagnostic.source_record_id.as_deref() == Some("BADPORT")
            && diagnostic.field.as_deref() == Some("id.resp_p")
    }));
    for observation in &produced.observations {
        assert_contract_valid(observation);
    }
}
