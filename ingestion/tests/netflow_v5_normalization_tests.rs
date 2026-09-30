use ingestion_core::canonical::output::write_canonical_observations_jsonl;
use ingestion_core::canonical::{
    CanonicalData, CanonicalObservation, DirectionMode, Fidelity, InputMode, TcpFlag,
    TelemetrySource,
};
use ingestion_core::netflow::normalize::{
    ExportDatagramContext, ExporterClockStatus, NetFlowV5NormalizationConfig,
    NetFlowV5NormalizationDiagnosticKind, NetFlowV5Normalizer, SequenceStatus,
    DEFAULT_MAX_FLOW_AGE_MS,
};
use ingestion_core::netflow::v5::{parse_netflow_v5_datagram, NetFlowV5Datagram, NetFlowV5Header};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const INPUT_SHA: &str = "c5654e512d1a0b18900df0242ccafc483450b4acac2a388cfa8f71aab3e65327";
const OTHER_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OBSERVED_AT: &str = "2026-09-18T00:00:00Z";

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("export")
        .join("netflow_v5")
}

fn fixture(name: &str) -> Vec<u8> {
    fs::read(fixture_dir().join(format!("{name}.bin"))).expect("fixture must be readable")
}

fn parsed_fixture(name: &str) -> NetFlowV5Datagram {
    parse_netflow_v5_datagram(&fixture(name)).expect("fixture must parse")
}

fn valid_wire_datagram() -> Vec<u8> {
    let mut bytes = fixture("minimal_valid_one_record");
    bytes[4..8].copy_from_slice(&10_000_u32.to_be_bytes());
    bytes[48..52].copy_from_slice(&8_000_u32.to_be_bytes());
    bytes[52..56].copy_from_slice(&9_000_u32.to_be_bytes());
    bytes
}

fn context_with(
    exporter_id: &str,
    input_sha256: &str,
    datagram_ordinal: u64,
) -> ExportDatagramContext {
    ExportDatagramContext::new(
        "sensor-netflow-test",
        InputMode::ExportFile,
        input_sha256,
        exporter_id,
        Some("192.0.2.200:2055".to_string()),
        OBSERVED_AT,
        datagram_ordinal,
    )
    .expect("test context must be valid")
}

fn context(datagram_ordinal: u64) -> ExportDatagramContext {
    context_with("exporter-a", INPUT_SHA, datagram_ordinal)
}

fn datagram(
    sequence: u32,
    count: u16,
    sys_uptime_ms: u32,
    unix_secs: u32,
    unix_nsecs: u32,
) -> NetFlowV5Datagram {
    let source = parsed_fixture("minimal_valid_one_record");
    let mut records = Vec::with_capacity(usize::from(count));
    for ordinal in 0..count {
        let mut record = source.records[0].clone();
        record.record_ordinal = ordinal as u8;
        record.first_sys_uptime_ms = sys_uptime_ms;
        record.last_sys_uptime_ms = sys_uptime_ms;
        records.push(record);
    }
    NetFlowV5Datagram {
        header: NetFlowV5Header {
            version: 5,
            count,
            sys_uptime_ms,
            unix_secs,
            unix_nsecs,
            flow_sequence: sequence,
            engine_type: 7,
            engine_id: 9,
            raw_sampling: 0,
            sampling_mode: 0,
            sampling_interval: 0,
        },
        records,
        diagnostics: Vec::new(),
    }
}

fn normalize_one(datagram: &NetFlowV5Datagram) -> CanonicalObservation {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    let result = normalizer.process_datagram(datagram, &context(0));
    assert_eq!(
        result.observations.len(),
        1,
        "diagnostics: {:?}",
        result.diagnostics
    );
    result
        .observations
        .into_iter()
        .next()
        .expect("one observation")
}

fn flow(observation: &CanonicalObservation) -> &ingestion_core::canonical::FlowData {
    match &observation.data {
        CanonicalData::Flow(flow) => flow,
        _ => panic!("expected canonical flow"),
    }
}

fn jsonl_bytes(observations: &[CanonicalObservation], name: &str) -> Vec<u8> {
    let target = std::env::temp_dir().join(format!(
        "sih-netflow-v5-{name}-{}-{}.jsonl",
        std::process::id(),
        observations.len()
    ));
    let _ = fs::remove_file(&target);
    write_canonical_observations_jsonl(&target, observations).expect("JSONL write must succeed");
    let bytes = fs::read(&target).expect("JSONL must be readable");
    fs::remove_file(target).expect("temporary JSONL must be removable");
    bytes
}

#[test]
fn source_context_is_explicit_validated_and_offline_only() {
    let valid = context(42);
    assert_eq!(valid.sensor_id(), "sensor-netflow-test");
    assert_eq!(valid.input_sha256(), INPUT_SHA);
    assert_eq!(valid.exporter_id(), "exporter-a");
    assert_eq!(valid.transport_source(), Some("192.0.2.200:2055"));
    assert_eq!(valid.observed_at(), OBSERVED_AT);
    assert_eq!(valid.datagram_ordinal(), 42);

    assert!(ExportDatagramContext::new(
        "sensor",
        InputMode::ExportStream,
        INPUT_SHA,
        "exporter-a",
        None,
        OBSERVED_AT,
        0,
    )
    .is_err());
    assert!(ExportDatagramContext::new(
        "sensor",
        InputMode::ExportFile,
        INPUT_SHA,
        "bad/exporter",
        None,
        OBSERVED_AT,
        0,
    )
    .is_err());
    assert!(ExportDatagramContext::new(
        "sensor",
        InputMode::ExportFile,
        "not-a-hash",
        "exporter-a",
        None,
        OBSERVED_AT,
        0,
    )
    .is_err());
}

#[test]
fn normal_time_reconstruction_uses_exact_integer_nanoseconds() {
    let mut source = datagram(100, 1, 10_000, 1_700_000_000, 123_456_789);
    source.records[0].first_sys_uptime_ms = 8_000;
    source.records[0].last_sys_uptime_ms = 9_000;
    let observation = normalize_one(&source);
    assert_eq!(
        flow(&observation).start_time,
        "2023-11-14T22:13:18.123456789Z"
    );
    assert_eq!(
        flow(&observation).end_time.as_deref(),
        Some("2023-11-14T22:13:19.123456789Z")
    );
}

#[test]
fn exact_export_anchor_is_preserved_when_first_last_equal_sys_uptime() {
    let source = datagram(100, 1, 10_000, 1_700_000_000, 123_456_789);
    let observation = normalize_one(&source);
    assert_eq!(
        flow(&observation).start_time,
        "2023-11-14T22:13:20.123456789Z"
    );
    assert_eq!(
        flow(&observation).end_time.as_deref(),
        Some("2023-11-14T22:13:20.123456789Z")
    );
}

#[test]
fn flow_crossing_one_uptime_wrap_is_reconstructed() {
    let mut source = datagram(100, 1, 500, 1_700_000_000, 123_456_789);
    source.records[0].first_sys_uptime_ms = u32::MAX - 499;
    source.records[0].last_sys_uptime_ms = 250;
    let observation = normalize_one(&source);
    assert_eq!(
        flow(&observation).start_time,
        "2023-11-14T22:13:19.123456789Z"
    );
    assert_eq!(
        flow(&observation).end_time.as_deref(),
        Some("2023-11-14T22:13:19.873456789Z")
    );
}

#[test]
fn flow_ending_before_uptime_wrap_is_reconstructed() {
    let mut source = datagram(100, 1, 500, 1_700_000_000, 123_456_789);
    source.records[0].first_sys_uptime_ms = u32::MAX - 999;
    source.records[0].last_sys_uptime_ms = u32::MAX - 499;
    let observation = normalize_one(&source);
    assert_eq!(
        flow(&observation).start_time,
        "2023-11-14T22:13:18.623456789Z"
    );
    assert_eq!(
        flow(&observation).end_time.as_deref(),
        Some("2023-11-14T22:13:19.123456789Z")
    );
}

#[test]
fn one_ms_future_last_is_diagnosed_and_only_affected_record_is_skipped() {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    normalizer.process_datagram(&datagram(100, 1, 10_000, 1_700_000_000, 0), &context(0));
    let mut source = datagram(101, 2, 11_000, 1_700_000_001, 0);
    source.records[0].first_sys_uptime_ms = 10_000;
    source.records[0].last_sys_uptime_ms = 11_001;
    let result = normalizer.process_datagram(&source, &context(1));
    assert_eq!(result.observations.len(), 1);
    assert!(result.observations[0]
        .source_record_id
        .as_deref()
        .unwrap()
        .ends_with("/1/1"));
    let diagnostic = result
        .diagnostics
        .iter()
        .find(|item| item.kind == NetFlowV5NormalizationDiagnosticKind::FlowTimeOrderingInvalid)
        .expect("dedicated future/order diagnostic");
    assert_eq!(diagnostic.datagram_ordinal, 1);
    assert_eq!(diagnostic.record_ordinal, Some(0));
    assert_eq!(diagnostic.field, "end_age_ms");
    assert_eq!(diagnostic.value_ms, Some(u64::from(u32::MAX)));
    assert_eq!(diagnostic.limit_ms, Some(DEFAULT_MAX_FLOW_AGE_MS));
    let evidence = diagnostic.flow_time.expect("bounded wire-time context");
    assert_eq!(evidence.first_sys_uptime_ms, 10_000);
    assert_eq!(evidence.last_sys_uptime_ms, 11_001);
    assert_eq!(evidence.sys_uptime_ms, 11_000);
    assert_eq!(evidence.end_age_ms, u64::from(u32::MAX));
    assert_eq!(evidence.duration_ms, 1_001);
    assert!(!result
        .diagnostics
        .iter()
        .any(|item| item.kind == NetFlowV5NormalizationDiagnosticKind::FlowAgeExceeded));
    // Sequence advancement follows the structurally valid header's count,
    // including rejected records; invalid row times never replace header time.
    let next =
        normalizer.process_datagram(&datagram(103, 1, 12_000, 1_700_000_002, 0), &context(2));
    assert_eq!(next.sequence_status, SequenceStatus::InOrder);
    assert_eq!(next.clock_status, ExporterClockStatus::InOrder);
    assert!(!next.observations[0].quality.loss_detected);
    assert!(next.diagnostics.is_empty());
}

#[test]
fn all_ordering_rejections_keep_trusted_header_sequence_state() {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    let mut source = datagram(100, 1, 10_000, 1_700_000_000, 0);
    source.records[0].last_sys_uptime_ms = 10_001;
    assert!(normalizer
        .process_datagram(&source, &context(0))
        .observations
        .is_empty());
    let next =
        normalizer.process_datagram(&datagram(101, 1, 11_000, 1_700_000_001, 0), &context(1));
    assert_eq!(next.sequence_status, SequenceStatus::InOrder);
    assert_eq!(next.clock_status, ExporterClockStatus::InOrder);
    assert_eq!(next.observations.len(), 1);
    assert!(next.diagnostics.is_empty());
}

#[test]
fn gross_first_last_inversions_are_order_failures_even_when_end_age_also_exceeds_limit() {
    for (first, last, limit) in [(10_001, 9_000, 2_000), (20_000, 5_000, 500)] {
        let mut source = datagram(100, 1, 10_000, 1_700_000_000, 0);
        source.records[0].first_sys_uptime_ms = first;
        source.records[0].last_sys_uptime_ms = last;
        let result = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig {
            max_flow_age_ms: limit,
        })
        .process_datagram(&source, &context(0));
        assert!(result.observations.is_empty());
        let diagnostic = result
            .diagnostics
            .iter()
            .find(|item| item.kind == NetFlowV5NormalizationDiagnosticKind::FlowTimeOrderingInvalid)
            .expect("ordering diagnostic takes precedence");
        assert_eq!(diagnostic.field, "duration_ms");
        assert_eq!(
            diagnostic.value_ms,
            Some(u64::from(last.wrapping_sub(first)))
        );
        assert_eq!(diagnostic.flow_time.unwrap().first_sys_uptime_ms, first);
        assert!(!result
            .diagnostics
            .iter()
            .any(|item| item.kind == NetFlowV5NormalizationDiagnosticKind::FlowAgeExceeded));
    }
}

#[test]
fn oversized_age_policy_does_not_allow_future_or_half_cycle_ambiguous_times() {
    for (first, last, expected_field) in [
        (9_000, 10_001, "end_age_ms"),
        (10_001, 9_000, "duration_ms"),
        (1_u32 << 31, 0, "duration_ms"),
        (10_000, 10_000_u32.wrapping_add(1 << 31), "end_age_ms"),
        (1_000, 4_000_000_000, "start_age_ms"),
    ] {
        let mut source = datagram(100, 1, 1_000, 1_700_000_000, 0);
        if expected_field != "start_age_ms" {
            source.header.sys_uptime_ms = 10_000;
        }
        source.records[0].first_sys_uptime_ms = first;
        source.records[0].last_sys_uptime_ms = last;
        let result = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig {
            max_flow_age_ms: u64::MAX,
        })
        .process_datagram(&source, &context(0));
        assert!(result.observations.is_empty());
        assert!(
            result.diagnostics.iter().any(|item| {
                item.kind == NetFlowV5NormalizationDiagnosticKind::FlowTimeOrderingInvalid
                    && item.field == expected_field
            }),
            "{:?}",
            result.diagnostics
        );
    }
}

#[test]
fn modular_wrap_policy_boundary_is_inclusive() {
    for (age, accepted) in [(1_000_u32, true), (1_001, false)] {
        let mut source = datagram(100, 1, 500, 1_700_000_000, 0);
        source.records[0].last_sys_uptime_ms = 500_u32.wrapping_sub(age);
        source.records[0].first_sys_uptime_ms = source.records[0].last_sys_uptime_ms;
        let result = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig {
            max_flow_age_ms: 1_000,
        })
        .process_datagram(&source, &context(0));
        assert_eq!(result.observations.len(), usize::from(accepted));
        assert_eq!(
            result
                .diagnostics
                .iter()
                .any(|item| item.kind
                    == NetFlowV5NormalizationDiagnosticKind::FlowTimeOrderingInvalid),
            !accepted
        );
    }
}

#[test]
fn maximum_flow_age_is_inclusive_and_configurable() {
    let mut accepted = datagram(100, 1, DEFAULT_MAX_FLOW_AGE_MS as u32, 1_700_000_000, 0);
    accepted.records[0].first_sys_uptime_ms = 0;
    accepted.records[0].last_sys_uptime_ms = 0;
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    let accepted_result = normalizer.process_datagram(&accepted, &context(0));
    assert_eq!(accepted_result.observations.len(), 1);

    let custom = NetFlowV5NormalizationConfig {
        max_flow_age_ms: 1_000,
    };
    let mut short_normalizer = NetFlowV5Normalizer::new(custom);
    let mut short = datagram(200, 1, 1_000, 1_700_000_000, 0);
    short.records[0].first_sys_uptime_ms = 0;
    short.records[0].last_sys_uptime_ms = 0;
    assert_eq!(
        short_normalizer
            .process_datagram(&short, &context(0))
            .observations
            .len(),
        1
    );
}

#[test]
fn age_above_limit_skips_only_the_affected_record() {
    let mut source = datagram(100, 2, 10_000, 1_700_000_000, 0);
    source.records[0].first_sys_uptime_ms = 9_000;
    source.records[0].last_sys_uptime_ms = 9_000;
    source.records[1].first_sys_uptime_ms = 0;
    source.records[1].last_sys_uptime_ms = 0;
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig {
        max_flow_age_ms: 2_000,
    });
    let result = normalizer.process_datagram(&source, &context(0));
    assert_eq!(result.observations.len(), 1);
    let diagnostic = result
        .diagnostics
        .iter()
        .find(|item| item.kind == NetFlowV5NormalizationDiagnosticKind::FlowAgeExceeded)
        .expect("age diagnostic");
    assert_eq!(diagnostic.record_ordinal, Some(1));
    assert_eq!(diagnostic.field, "end_age_ms");
    assert_eq!(diagnostic.value_ms, Some(10_000));
    assert_eq!(diagnostic.limit_ms, Some(2_000));
}

#[test]
fn duration_above_limit_is_rejected_independently_of_end_age() {
    let mut source = datagram(100, 1, 10_000, 1_700_000_000, 0);
    source.records[0].first_sys_uptime_ms = 0;
    source.records[0].last_sys_uptime_ms = 10_000;
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig {
        max_flow_age_ms: 2_000,
    });
    let result = normalizer.process_datagram(&source, &context(0));
    assert!(result.observations.is_empty());
    assert!(result.diagnostics.iter().any(|item| {
        item.kind == NetFlowV5NormalizationDiagnosticKind::FlowAgeExceeded
            && item.field == "duration_ms"
            && item.value_ms == Some(10_000)
    }));
}

#[test]
fn checked_timestamp_underflow_skips_record() {
    let mut source = datagram(100, 1, 1_000, 0, 0);
    source.records[0].first_sys_uptime_ms = 0;
    source.records[0].last_sys_uptime_ms = 0;
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig {
        max_flow_age_ms: 2_000,
    });
    let result = normalizer.process_datagram(&source, &context(0));
    assert!(result.observations.is_empty());
    assert!(result.diagnostics.iter().any(|item| {
        item.kind == NetFlowV5NormalizationDiagnosticKind::TimestampUnderflow
            && item.field == "end_time"
    }));
}

#[test]
fn exporter_uptime_wrap_is_distinguished_from_restart() {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    let first = datagram(100, 1, u32::MAX - 500, 1_700_000_000, 0);
    let second = datagram(101, 1, 500, 1_700_000_001, 1_000_000);
    normalizer.process_datagram(&first, &context(0));
    let result = normalizer.process_datagram(&second, &context(1));
    assert_eq!(result.clock_status, ExporterClockStatus::UptimeWrapped);
    assert_eq!(result.sequence_status, SequenceStatus::InOrder);
    assert!(!result
        .diagnostics
        .iter()
        .any(|item| { item.kind == NetFlowV5NormalizationDiagnosticKind::ExporterRestart }));
}

#[test]
fn clock_shift_and_regression_are_reported_conservatively() {
    let mut shifted = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    shifted.process_datagram(&datagram(100, 1, 10_000, 1_700_000_000, 0), &context(0));
    let shift_result =
        shifted.process_datagram(&datagram(101, 1, 11_000, 1_700_000_010, 0), &context(1));
    assert_eq!(shift_result.clock_status, ExporterClockStatus::Shifted);
    assert!(shift_result
        .diagnostics
        .iter()
        .any(|item| { item.kind == NetFlowV5NormalizationDiagnosticKind::ExporterClockShift }));

    let mut regressed = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    regressed.process_datagram(&datagram(100, 1, 10_000, 1_700_000_010, 0), &context(0));
    let regression_result =
        regressed.process_datagram(&datagram(101, 1, 11_000, 1_700_000_000, 0), &context(1));
    assert_eq!(
        regression_result.clock_status,
        ExporterClockStatus::Regressed
    );
    assert!(regression_result.diagnostics.iter().any(|item| {
        item.kind == NetFlowV5NormalizationDiagnosticKind::ExporterClockRegression
    }));
}

#[test]
fn sequence_progression_uses_previous_record_count() {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    normalizer.process_datagram(&datagram(100, 3, 10_000, 1_700_000_000, 0), &context(0));
    let result =
        normalizer.process_datagram(&datagram(103, 1, 11_000, 1_700_000_001, 0), &context(1));
    assert_eq!(result.sequence_status, SequenceStatus::InOrder);
}

#[test]
fn sequence_wrap_is_normal_progression() {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    normalizer.process_datagram(
        &datagram(u32::MAX - 1, 2, 10_000, 1_700_000_000, 0),
        &context(0),
    );
    let result =
        normalizer.process_datagram(&datagram(0, 1, 11_000, 1_700_000_001, 0), &context(1));
    assert_eq!(result.sequence_status, SequenceStatus::Wrapped);
}

#[test]
fn duplicate_does_not_claim_loss() {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    normalizer.process_datagram(&datagram(100, 2, 10_000, 1_700_000_000, 0), &context(0));
    let result =
        normalizer.process_datagram(&datagram(100, 2, 10_000, 1_700_000_000, 0), &context(1));
    assert_eq!(result.sequence_status, SequenceStatus::Duplicate);
    assert!(result
        .diagnostics
        .iter()
        .any(|item| { item.kind == NetFlowV5NormalizationDiagnosticKind::Duplicate }));
    assert!(result.observations.iter().all(|item| {
        !item.quality.loss_detected && item.quality.missed_content_bytes.is_none()
    }));
}

#[test]
fn forward_gap_reports_missing_records_without_missing_bytes() {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    normalizer.process_datagram(&datagram(100, 2, 10_000, 1_700_000_000, 0), &context(0));
    let result =
        normalizer.process_datagram(&datagram(105, 1, 11_000, 1_700_000_001, 0), &context(1));
    assert_eq!(
        result.sequence_status,
        SequenceStatus::Gap { missing_records: 3 }
    );
    let diagnostic = result
        .diagnostics
        .iter()
        .find(|item| item.kind == NetFlowV5NormalizationDiagnosticKind::SequenceGap)
        .expect("gap diagnostic");
    assert_eq!(diagnostic.expected_sequence, Some(102));
    assert_eq!(diagnostic.actual_sequence, Some(105));
    assert_eq!(diagnostic.missing_records, Some(3));
    assert!(result
        .observations
        .iter()
        .all(|item| { item.quality.loss_detected && item.quality.missed_content_bytes.is_none() }));
}

#[test]
fn sequence_regression_without_restart_evidence_is_not_called_restart() {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    normalizer.process_datagram(&datagram(1_000, 2, 10_000, 1_700_000_000, 0), &context(0));
    let result =
        normalizer.process_datagram(&datagram(500, 1, 11_000, 1_700_000_001, 0), &context(1));
    assert_eq!(result.sequence_status, SequenceStatus::Regression);
    assert!(result
        .diagnostics
        .iter()
        .any(|item| { item.kind == NetFlowV5NormalizationDiagnosticKind::SequenceRegression }));
    assert!(!result
        .diagnostics
        .iter()
        .any(|item| { item.kind == NetFlowV5NormalizationDiagnosticKind::ExporterRestart }));
}

#[test]
fn rejected_state_transition_does_not_replace_last_valid_sequence_state() {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    normalizer.process_datagram(&datagram(100, 2, 10_000, 1_700_000_000, 0), &context(0));
    let regression =
        normalizer.process_datagram(&datagram(50, 1, 11_000, 1_700_000_001, 0), &context(1));
    assert_eq!(regression.sequence_status, SequenceStatus::Regression);

    let recovered =
        normalizer.process_datagram(&datagram(102, 1, 12_000, 1_700_000_002, 0), &context(2));
    assert_eq!(recovered.sequence_status, SequenceStatus::InOrder);
}

#[test]
fn restart_requires_combined_uptime_sequence_and_boot_evidence() {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    normalizer.process_datagram(&datagram(1_000, 2, 100_000, 1_700_000_000, 0), &context(0));
    let result = normalizer.process_datagram(&datagram(0, 1, 1_000, 1_700_000_010, 0), &context(1));
    assert_eq!(result.sequence_status, SequenceStatus::Restart);
    assert_eq!(result.clock_status, ExporterClockStatus::Restart);
    assert!(result
        .diagnostics
        .iter()
        .any(|item| { item.kind == NetFlowV5NormalizationDiagnosticKind::ExporterRestart }));
    assert!(result
        .observations
        .iter()
        .all(|item| !item.quality.loss_detected));
}

#[test]
fn sampling_quality_is_conservative_and_counters_are_unscaled() {
    let config = NetFlowV5NormalizationConfig {
        max_flow_age_ms: 30 * 24 * 60 * 60 * 1_000,
    };
    let cases = [
        ("sampling_disabled", Fidelity::Exact, None, false),
        (
            "sampling_deterministic",
            Fidelity::Sampled,
            Some(100),
            false,
        ),
        ("sampling_random", Fidelity::Sampled, Some(16_383), false),
        ("sampling_reserved", Fidelity::Unknown, None, true),
    ];
    for (name, fidelity, rate, invalid) in cases {
        let source = parsed_fixture(name);
        let expected_packets = source.records[0].packet_count;
        let expected_octets = source.records[0].octet_count;
        let mut normalizer = NetFlowV5Normalizer::new(config);
        let result = normalizer.process_datagram(&source, &context(0));
        assert_eq!(
            result.observations.len(),
            1,
            "{name}: {:?}",
            result.diagnostics
        );
        let observation = &result.observations[0];
        assert_eq!(observation.quality.fidelity, fidelity);
        assert_eq!(observation.quality.sampling_rate, rate);
        assert_eq!(
            flow(observation).counters.src_to_dst.packets,
            Some(u64::from(expected_packets))
        );
        assert_eq!(
            flow(observation).counters.src_to_dst.ip_bytes,
            Some(u64::from(expected_octets))
        );
        assert_eq!(
            result
                .diagnostics
                .iter()
                .any(|item| item.kind == NetFlowV5NormalizationDiagnosticKind::SamplingInvalid),
            invalid
        );
    }

    let mut explicit_one = datagram(200, 1, 10_000, 1_700_000_000, 0);
    explicit_one.header.raw_sampling = (1 << 14) | 1;
    explicit_one.header.sampling_mode = 1;
    explicit_one.header.sampling_interval = 1;
    let observation = normalize_one(&explicit_one);
    assert_eq!(observation.quality.fidelity, Fidelity::Sampled);
    assert_eq!(observation.quality.sampling_rate, Some(1));

    let mut invalid_zero = datagram(300, 1, 10_000, 1_700_000_000, 0);
    invalid_zero.header.raw_sampling = 1 << 14;
    invalid_zero.header.sampling_mode = 1;
    invalid_zero.header.sampling_interval = 0;
    let mut invalid_normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    let invalid = invalid_normalizer.process_datagram(&invalid_zero, &context(0));
    assert_eq!(invalid.observations[0].quality.fidelity, Fidelity::Unknown);
    assert_eq!(invalid.observations[0].quality.sampling_rate, None);
    assert!(invalid
        .diagnostics
        .iter()
        .any(|item| { item.kind == NetFlowV5NormalizationDiagnosticKind::SamplingInvalid }));
}

#[test]
fn sequence_loss_flag_does_not_override_sampled_fidelity() {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    let mut first = datagram(100, 2, 10_000, 1_700_000_000, 0);
    first.header.raw_sampling = (1 << 14) | 100;
    first.header.sampling_mode = 1;
    first.header.sampling_interval = 100;
    normalizer.process_datagram(&first, &context(0));
    let mut gap = datagram(105, 1, 11_000, 1_700_000_001, 0);
    gap.header.raw_sampling = (1 << 14) | 100;
    gap.header.sampling_mode = 1;
    gap.header.sampling_interval = 100;
    let result = normalizer.process_datagram(&gap, &context(1));
    assert_eq!(result.observations[0].quality.fidelity, Fidelity::Sampled);
    assert_eq!(result.observations[0].quality.sampling_rate, Some(100));
    assert!(result.observations[0].quality.loss_detected);
}

#[test]
fn canonical_tcp_udp_icmp_mapping_obeys_semantics() {
    let mut tcp_source = datagram(100, 1, 10_000, 1_700_000_000, 0);
    tcp_source.records[0].protocol = 6;
    tcp_source.records[0].tcp_flags = 0x1b;
    let tcp = normalize_one(&tcp_source);
    let tcp_flow = flow(&tcp);
    assert_eq!(tcp_flow.src_port, Some(12_345));
    assert_eq!(tcp_flow.dst_port, Some(443));
    assert_eq!(tcp_flow.icmp_type, None);
    assert_eq!(tcp_flow.icmp_code, None);
    assert_eq!(
        tcp_flow.tcp_flags.as_deref(),
        Some(&[TcpFlag::Fin, TcpFlag::Syn, TcpFlag::Psh, TcpFlag::Ack][..])
    );

    let mut udp_source = tcp_source.clone();
    udp_source.records[0].protocol = 17;
    udp_source.records[0].tcp_flags = u8::MAX;
    let udp = normalize_one(&udp_source);
    assert_eq!(flow(&udp).src_port, Some(12_345));
    assert_eq!(flow(&udp).dst_port, Some(443));
    assert_eq!(flow(&udp).icmp_type, None);
    assert_eq!(flow(&udp).icmp_code, None);
    assert_eq!(flow(&udp).tcp_flags, None);

    let mut sctp_source = udp_source;
    sctp_source.records[0].protocol = 132;
    let sctp = normalize_one(&sctp_source);
    assert_eq!(flow(&sctp).src_port, Some(12_345));
    assert_eq!(flow(&sctp).dst_port, Some(443));

    let mut icmp_source = tcp_source;
    icmp_source.records[0].protocol = 1;
    icmp_source.records[0].dst_port = 0x0800;
    let icmp = normalize_one(&icmp_source);
    assert_eq!(flow(&icmp).src_port, None);
    assert_eq!(flow(&icmp).dst_port, None);
    assert_eq!(flow(&icmp).icmp_type, Some(8));
    assert_eq!(flow(&icmp).icmp_code, Some(0));
    assert_eq!(flow(&icmp).tcp_flags, None);
}

fn assert_icmp_wire_identity(icmp_type: u8, icmp_code: u8) {
    let mut bytes = valid_wire_datagram();
    bytes[62] = 1;
    bytes[56..58].copy_from_slice(&0xdead_u16.to_be_bytes());
    bytes[58..60].copy_from_slice(&[icmp_type, icmp_code]);
    let parsed = parse_netflow_v5_datagram(&bytes).expect("F2 ICMP wire decode");
    assert_eq!(parsed.records[0].src_port, 0xdead);
    assert_eq!(
        parsed.records[0].dst_port,
        u16::from_be_bytes([icmp_type, icmp_code])
    );
    let result = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default())
        .process_bytes(&bytes, &context(0))
        .unwrap();
    assert_eq!(result.observations.len(), 1);
    let data = flow(&result.observations[0]);
    assert_eq!(data.icmp_type, Some(icmp_type));
    assert_eq!(data.icmp_code, Some(icmp_code));
    assert_eq!(data.src_port, None);
    assert_eq!(data.dst_port, None);
    assert_eq!(data.tcp_flags, None);
    let serialized = serde_json::to_value(&result.observations[0]).unwrap();
    assert!(serialized["data"].get("src_port").is_none());
    assert!(serialized["data"].get("dst_port").is_none());
    assert_eq!(serialized["data"]["icmp_type"], icmp_type);
    assert_eq!(serialized["data"]["icmp_code"], icmp_code);
}

#[test]
fn icmp_echo_request_preserves_type_eight_code_zero_from_wire() {
    assert_icmp_wire_identity(8, 0);
}

#[test]
fn icmp_destination_unreachable_preserves_nonzero_code_from_wire() {
    assert_icmp_wire_identity(3, 13);
}

#[test]
fn icmp_zero_and_maximum_words_are_preserved_without_source_port_fallback() {
    assert_icmp_wire_identity(0, 0);
    assert_icmp_wire_identity(255, 255);
}

#[test]
fn non_port_bearing_non_icmp_protocols_do_not_fabricate_ports_or_icmp() {
    for protocol in [47, 50, 89] {
        let mut source = datagram(100, 1, 10_000, 1_700_000_000, 0);
        source.records[0].protocol = protocol;
        source.records[0].dst_port = 0x0800;
        let observation = normalize_one(&source);
        let data = flow(&observation);
        assert_eq!(
            (data.src_port, data.dst_port, data.icmp_type, data.icmp_code),
            (None, None, None, None)
        );
    }
}

#[test]
fn interface_index_zero_and_nonzero_are_independent_and_raw_u16_values_stay_lossless() {
    for input in [0_u16, 1, u16::MAX] {
        for output in [0_u16, 1, u16::MAX] {
            let mut bytes = valid_wire_datagram();
            bytes[36..38].copy_from_slice(&input.to_be_bytes());
            bytes[38..40].copy_from_slice(&output.to_be_bytes());
            let parsed = parse_netflow_v5_datagram(&bytes).unwrap();
            assert_eq!(parsed.records[0].input_ifindex, input);
            assert_eq!(parsed.records[0].output_ifindex, output);
            let observation = normalize_one(&parsed);
            assert_eq!(
                flow(&observation).ingress_interface,
                (input != 0).then(|| format!("ifindex:{input}"))
            );
            assert_eq!(
                flow(&observation).egress_interface,
                (output != 0).then(|| format!("ifindex:{output}"))
            );
            let serialized = serde_json::to_value(&observation).unwrap();
            assert_eq!(
                serialized["data"].get("ingress_interface").is_some(),
                input != 0
            );
            assert_eq!(
                serialized["data"].get("egress_interface").is_some(),
                output != 0
            );
        }
    }
}

#[test]
fn all_v5_tcp_flag_bits_map_in_frozen_canonical_order() {
    let source = parsed_fixture("tcp_flags");
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig {
        max_flow_age_ms: 30 * 24 * 60 * 60 * 1_000,
    });
    let result = normalizer.process_datagram(&source, &context(0));
    assert_eq!(
        flow(&result.observations[0]).tcp_flags.as_deref(),
        Some(
            &[
                TcpFlag::Fin,
                TcpFlag::Syn,
                TcpFlag::Rst,
                TcpFlag::Psh,
                TcpFlag::Ack,
                TcpFlag::Urg,
                TcpFlag::Ece,
                TcpFlag::Cwr,
            ][..]
        )
    );
}

#[test]
fn canonical_flow_is_unidirectional_ip_byte_based_and_minimized() {
    let source = datagram(100, 1, 10_000, 1_700_000_000, 0);
    let observation = normalize_one(&source);
    let data = flow(&observation);
    assert_eq!(observation.telemetry_source, TelemetrySource::NetFlowV5);
    assert_eq!(data.direction_mode, DirectionMode::Unidirectional);
    assert_eq!(data.counters.src_to_dst.packets, Some(0x0102_0304));
    assert_eq!(data.counters.src_to_dst.ip_bytes, Some(0x1122_3344));
    assert_eq!(data.counters.src_to_dst.payload_bytes, None);
    assert_eq!(data.counters.src_to_dst.l2_bytes, None);
    assert_eq!(data.counters.dst_to_src, None);
    assert_eq!(data.ingress_interface.as_deref(), Some("ifindex:4660"));
    assert_eq!(data.egress_interface.as_deref(), Some("ifindex:22136"));
    assert_eq!(data.service, None);
    assert_eq!(data.connection_state, None);
    assert_eq!(data.connection_history, None);
    assert_eq!(data.end_reason, None);

    let serialized = serde_json::to_value(&observation).expect("canonical serialization");
    assert!(serialized["data"]["counters"].get("dst_to_src").is_none());
    assert!(serialized["data"]["counters"]["src_to_dst"]
        .get("payload_bytes")
        .is_none());
    for field in [
        "service",
        "connection_state",
        "connection_history",
        "end_reason",
    ] {
        assert!(serialized["data"].get(field).is_none());
    }
}

#[test]
fn zero_and_maximum_counters_remain_exact_source_values() {
    let config = NetFlowV5NormalizationConfig {
        max_flow_age_ms: 30 * 24 * 60 * 60 * 1_000,
    };
    for (name, expected) in [
        ("zero_counters", 0_u64),
        ("max_u32_counters", u64::from(u32::MAX)),
    ] {
        let mut normalizer = NetFlowV5Normalizer::new(config);
        let result = normalizer.process_datagram(&parsed_fixture(name), &context(0));
        assert_eq!(
            result.observations.len(),
            1,
            "{name}: {:?}",
            result.diagnostics
        );
        assert_eq!(
            flow(&result.observations[0]).counters.src_to_dst.packets,
            Some(expected)
        );
        assert_eq!(
            flow(&result.observations[0]).counters.src_to_dst.ip_bytes,
            Some(expected)
        );
    }
}

#[test]
fn provenance_observed_at_and_source_coordinate_are_exact() {
    let source = datagram(12345, 1, 10_000, 1_700_000_000, 0);
    let observation = normalize_one(&source);
    assert_eq!(observation.observed_at, OBSERVED_AT);
    assert_eq!(
        observation.source_record_id.as_deref(),
        Some("netflow_v5/exporter-a/7/9/12345/0/0")
    );
    assert_eq!(observation.provenance.input_mode, InputMode::ExportFile);
    assert_eq!(
        observation.provenance.input_sha256.as_deref(),
        Some(INPUT_SHA)
    );
    assert_eq!(
        observation.provenance.exporter_id.as_deref(),
        Some("exporter-a")
    );
    assert_eq!(observation.provenance.message_sequence, Some(12345));
    assert_eq!(observation.provenance.observation_domain_id, None);
    assert_eq!(observation.provenance.template_id, None);
}

#[test]
fn record_identity_has_all_required_coordinates_and_is_deterministic() {
    let base = datagram(100, 1, 10_000, 1_700_000_000, 0);
    let first = normalize_one(&base);
    let second = normalize_one(&base);
    assert_eq!(first.record_id, second.record_id);
    assert_eq!(first.record_id, "4084204f-91b4-5e4c-9720-aa3dcea371e1");

    let different_artifact = {
        let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
        normalizer
            .process_datagram(&base, &context_with("exporter-a", OTHER_SHA, 0))
            .observations
            .remove(0)
    };
    let different_exporter = {
        let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
        normalizer
            .process_datagram(&base, &context_with("exporter-b", INPUT_SHA, 0))
            .observations
            .remove(0)
    };
    let different_datagram = {
        let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
        normalizer
            .process_datagram(&base, &context(1))
            .observations
            .remove(0)
    };
    let mut changed_engine = base.clone();
    changed_engine.header.engine_id = 10;
    let different_engine = normalize_one(&changed_engine);
    let mut changed_engine_type = base.clone();
    changed_engine_type.header.engine_type = 8;
    let different_engine_type = normalize_one(&changed_engine_type);

    assert_ne!(first.record_id, different_artifact.record_id);
    assert_ne!(first.record_id, different_exporter.record_id);
    assert_ne!(first.record_id, different_datagram.record_id);
    assert_ne!(first.record_id, different_engine.record_id);
    assert_ne!(first.record_id, different_engine_type.record_id);
}

#[test]
fn repeated_identical_five_tuples_receive_distinct_ordered_ids() {
    let source = parsed_fixture("repeated_5tuple_distinct_rows");
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    let result = normalizer.process_datagram(&source, &context(0));
    assert_eq!(result.observations.len(), 3);
    let ids: Vec<_> = result
        .observations
        .iter()
        .map(|item| item.record_id.as_str())
        .collect();
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[1], ids[2]);
    assert_ne!(ids[0], ids[2]);
    assert_eq!(
        result
            .observations
            .iter()
            .map(|item| item.source_record_id.as_deref().expect("source id"))
            .collect::<Vec<_>>(),
        [
            "netflow_v5/exporter-a/7/9/287454020/0/0",
            "netflow_v5/exporter-a/7/9/287454020/0/1",
            "netflow_v5/exporter-a/7/9/287454020/0/2",
        ]
    );
}

#[test]
fn deterministic_jsonl_preserves_physical_order_and_path_independence() {
    let bytes = fixture("multiple_records");
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let first_path =
        std::env::temp_dir().join(format!("netflow-original-{}.bin", std::process::id()));
    let renamed_path =
        std::env::temp_dir().join(format!("netflow-renamed-{}.dat", std::process::id()));
    fs::write(&first_path, &bytes).expect("write original fixture copy");
    fs::write(&renamed_path, &bytes).expect("write renamed fixture copy");
    assert_eq!(artifact_sha256(&first_path), digest);
    assert_eq!(artifact_sha256(&renamed_path), digest);

    let source_a = parse_netflow_v5_datagram(&fs::read(&first_path).expect("read first"))
        .expect("first copy parses");
    let source_b = parse_netflow_v5_datagram(&fs::read(&renamed_path).expect("read renamed"))
        .expect("renamed copy parses");
    let context = context_with("exporter-a", &digest, 0);
    let mut first_normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    let mut second_normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig::default());
    let first = first_normalizer.process_datagram(&source_a, &context);
    let second = second_normalizer.process_datagram(&source_b, &context);
    let first_jsonl = jsonl_bytes(&first.observations, "first");
    let second_jsonl = jsonl_bytes(&second.observations, "second");
    assert_eq!(first_jsonl, second_jsonl);
    assert_eq!(
        first
            .observations
            .iter()
            .map(|item| flow(item).src_ip.as_str())
            .collect::<Vec<_>>(),
        ["192.0.2.200", "192.0.2.1", "192.0.2.150"]
    );
    fs::remove_file(first_path).expect("remove original copy");
    fs::remove_file(renamed_path).expect("remove renamed copy");
}

#[test]
fn canonical_outputs_match_independently_frozen_jsonl_and_sha_vectors() {
    let config = NetFlowV5NormalizationConfig {
        max_flow_age_ms: 30 * 24 * 60 * 60 * 1_000,
    };
    for name in [
        "minimal_valid_one_record",
        "multiple_records",
        "zero_counters",
        "sampling_deterministic",
        "repeated_5tuple_distinct_rows",
    ] {
        let bytes = fixture(name);
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let golden_context = ExportDatagramContext::new(
            "sensor-netflow-golden",
            InputMode::ExportFile,
            digest,
            "exporter-golden",
            None,
            OBSERVED_AT,
            0,
        )
        .expect("golden context");
        let mut normalizer = NetFlowV5Normalizer::new(config);
        let result = normalizer
            .process_bytes(&bytes, &golden_context)
            .expect("golden bytes");
        let actual = jsonl_bytes(&result.observations, name);
        let canonical_dir = fixture_dir().join("canonical");
        let expected = fs::read(canonical_dir.join(format!("{name}.canonical.jsonl")))
            .expect("golden canonical JSONL");
        assert_eq!(actual, expected, "canonical golden drift: {name}");

        let sidecar = fs::read_to_string(canonical_dir.join(format!("{name}.canonical.sha256")))
            .expect("golden canonical SHA sidecar");
        let expected_hash = sidecar
            .split_whitespace()
            .next()
            .expect("golden SHA digest");
        assert_eq!(
            format!("{:x}", Sha256::digest(&expected)),
            expected_hash,
            "canonical golden SHA drift: {name}"
        );
    }
}

#[test]
fn bytes_api_uses_f2_parser_and_rejects_malformed_input_transactionally() {
    let mut normalizer = NetFlowV5Normalizer::new(NetFlowV5NormalizationConfig {
        max_flow_age_ms: 30 * 24 * 60 * 60 * 1_000,
    });
    let valid = fixture("minimal_valid_one_record");
    assert!(normalizer.process_bytes(&valid[..23], &context(0)).is_err());
    let result = normalizer
        .process_bytes(&valid, &context(0))
        .expect("valid bytes should still be initial state");
    assert_eq!(result.sequence_status, SequenceStatus::Initial);
    assert_eq!(result.observations.len(), 1);
}

fn artifact_sha256(path: &Path) -> String {
    format!(
        "{:x}",
        Sha256::digest(fs::read(path).expect("artifact must be readable"))
    )
}
