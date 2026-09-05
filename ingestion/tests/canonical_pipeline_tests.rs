use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use ingestion_core::canonical::orchestrator::{
    produce_canonical_observations_from_log_dir, CanonicalOrchestrationError,
};
use ingestion_core::canonical::output::{write_canonical_observations_jsonl, CanonicalOutputError};
use ingestion_core::canonical::producer::FlowProducerConfig;
use ingestion_core::canonical::{CanonicalData, ObservationType};

const INPUT_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OBSERVED_AT: &str = "2026-08-31T12:34:56.123456Z";

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zeek/legacy_regression")
}

fn config() -> FlowProducerConfig {
    FlowProducerConfig::new("m1d-test-sensor", INPUT_HASH, OBSERVED_AT).unwrap()
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sih-m1d-pipeline-{name}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn copy_fixture_logs(destination: &Path) {
    for name in ["conn.log", "dns.log", "ssl.log", "http.log"] {
        fs::copy(fixture_dir().join(name), destination.join(name)).unwrap();
    }
}

fn append_data_row(path: &Path, row: &str) {
    let content = fs::read_to_string(path).unwrap();
    let close = content.find("#close").unwrap();
    let mut updated = String::with_capacity(content.len() + row.len() + 1);
    updated.push_str(&content[..close]);
    updated.push_str(row);
    updated.push('\n');
    updated.push_str(&content[close..]);
    fs::write(path, updated).unwrap();
}

fn validate_jsonl_against_frozen_schema(jsonl: &[u8]) {
    let schema = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("contracts/canonical_observation_v1.schema.json");
    let script = "$raw=[Console]::In.ReadToEnd(); $lines=$raw -split \"`n\" | Where-Object { $_ -ne '' }; \
        foreach($line in $lines){ $errors=@(); $ok=Test-Json -Json $line -SchemaFile $env:M1D_SCHEMA_PATH \
        -ErrorAction SilentlyContinue -ErrorVariable errors; if(-not $ok){ $errors | ForEach-Object { \
        [Console]::Error.WriteLine($_) }; exit 1 } }";
    let mut child = Command::new("pwsh")
        .args(["-NoProfile", "-Command", script])
        .env("M1D_SCHEMA_PATH", schema)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("PowerShell 7 is required by the frozen contract harness");
    child.stdin.as_mut().unwrap().write_all(jsonl).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "integrated canonical JSONL failed frozen schema validation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn orchestrator_preserves_type_order_rows_links_and_http_one_to_many() {
    let result =
        produce_canonical_observations_from_log_dir(fixture_dir(), &config(), false).unwrap();
    assert_eq!(result.summary.flow_emitted, 2);
    assert_eq!(result.summary.dns_emitted, 2);
    assert_eq!(result.summary.tls_emitted, 1);
    assert_eq!(result.summary.http_emitted, 2);
    assert_eq!(result.summary.rows_skipped, 0);
    assert!(result.summary.missing_optional_logs.is_empty());
    assert_eq!(result.observations.len(), 7);
    assert_eq!(
        result
            .observations
            .iter()
            .map(|observation| observation.observation_type)
            .collect::<Vec<_>>(),
        vec![
            ObservationType::Flow,
            ObservationType::Flow,
            ObservationType::Dns,
            ObservationType::Dns,
            ObservationType::Tls,
            ObservationType::Http,
            ObservationType::Http,
        ]
    );
    assert!(result
        .observations
        .iter()
        .all(|observation| observation.observed_at == OBSERVED_AT));

    let dns_queries = result
        .observations
        .iter()
        .filter_map(|observation| match &observation.data {
            CanonicalData::Dns(data) => data.query.as_deref(),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(dns_queries, vec!["abc.def", "ghi.jkl"]);

    let http_rows = result
        .observations
        .iter()
        .filter_map(|observation| match &observation.data {
            CanonicalData::Http(data) => Some((
                data.uri.as_deref(),
                data.flow_record_id.as_deref(),
                observation.source_record_id.as_deref(),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(http_rows.len(), 2);
    assert_eq!(http_rows[0].0, Some("/first"));
    assert_eq!(http_rows[1].0, Some("/second"));
    assert_eq!(http_rows[0].1, http_rows[1].1);
    assert!(http_rows[0].1.is_some());
    assert_eq!(http_rows[0].2, Some("C1"));
    assert_eq!(http_rows[1].2, Some("C1"));
    assert_ne!(
        result.observations[5].record_id,
        result.observations[6].record_id
    );
}

#[test]
fn integrated_jsonl_is_compact_lf_terminated_schema_valid_and_minimized() {
    let result =
        produce_canonical_observations_from_log_dir(fixture_dir(), &config(), false).unwrap();
    let dir = temp_dir("jsonl");
    let output = dir.join("canonical.jsonl");
    write_canonical_observations_jsonl(&output, &result.observations).unwrap();
    let bytes = fs::read(&output).unwrap();
    assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 7);
    assert!(bytes.ends_with(b"\n"));
    assert!(!bytes.starts_with(&[0xef, 0xbb, 0xbf]));
    assert!(!bytes.contains(&b'\r'));
    let text = String::from_utf8(bytes.clone()).unwrap();
    for forbidden in [
        "username",
        "password",
        "Authorization",
        "Cookie",
        "Set-Cookie",
        "answers",
        "TTLs",
        "trans_depth",
    ] {
        assert!(
            !text.contains(forbidden),
            "leaked forbidden field {forbidden}"
        );
    }
    validate_jsonl_against_frozen_schema(&bytes);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_optional_logs_are_zero_and_missing_conn_policy_is_contextual() {
    let dir = temp_dir("missing");
    fs::copy(fixture_dir().join("conn.log"), dir.join("conn.log")).unwrap();
    let result = produce_canonical_observations_from_log_dir(&dir, &config(), false).unwrap();
    assert_eq!(result.summary.flow_emitted, 2);
    assert_eq!(result.summary.dns_emitted, 0);
    assert_eq!(result.summary.tls_emitted, 0);
    assert_eq!(result.summary.http_emitted, 0);
    assert_eq!(
        result.summary.missing_optional_logs,
        vec!["dns.log", "ssl.log", "http.log"]
    );

    fs::remove_file(dir.join("conn.log")).unwrap();
    let error = produce_canonical_observations_from_log_dir(&dir, &config(), false).unwrap_err();
    assert!(matches!(
        error,
        CanonicalOrchestrationError::MissingConnLog(_)
    ));
    let empty = produce_canonical_observations_from_log_dir(&dir, &config(), true).unwrap();
    assert!(empty.observations.is_empty());

    fs::copy(fixture_dir().join("dns.log"), dir.join("dns.log")).unwrap();
    let error = produce_canonical_observations_from_log_dir(&dir, &config(), true).unwrap_err();
    assert!(matches!(
        error,
        CanonicalOrchestrationError::IncompleteLogSet(_)
    ));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn output_rejects_existing_target_without_changing_evidence() {
    let result =
        produce_canonical_observations_from_log_dir(fixture_dir(), &config(), false).unwrap();
    let dir = temp_dir("existing");
    let output = dir.join("canonical.jsonl");
    fs::write(&output, b"prior evidence").unwrap();
    let error = write_canonical_observations_jsonl(&output, &result.observations).unwrap_err();
    assert!(matches!(error, CanonicalOutputError::TargetExists(_)));
    assert_eq!(fs::read(&output).unwrap(), b"prior evidence");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn diagnostics_are_propagated_in_bounded_redacted_form() {
    let dir = temp_dir("diagnostics");
    for name in ["conn.log", "dns.log", "ssl.log", "http.log"] {
        fs::copy(fixture_dir().join(name), dir.join(name)).unwrap();
    }
    let http_path = dir.join("http.log");
    let content = fs::read_to_string(&http_path).unwrap();
    fs::write(
        &http_path,
        content.replace("\t201\t12\t20", "\tsecret-invalid-status\t12\t20"),
    )
    .unwrap();

    let result = produce_canonical_observations_from_log_dir(&dir, &config(), false).unwrap();
    assert_eq!(result.observations.len(), 7);
    assert!(result.summary.diagnostics_count > 0);
    assert!(!result.summary.diagnostics.is_empty());
    let serialized = serde_json::to_string(&result.summary).unwrap();
    assert!(!serialized.contains("raw_value"));
    assert!(!serialized.contains("secret-invalid-status"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn integrated_tls_one_to_many_preserves_rows_ordinals_ids_and_link() {
    let dir = temp_dir("tls-one-to-many");
    copy_fixture_logs(&dir);
    let conn = fs::read_to_string(dir.join("conn.log")).unwrap();
    let one_flow = conn
        .lines()
        .filter(|line| line.starts_with('#') || line.contains("\tC1\t"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(dir.join("conn.log"), one_flow).unwrap();
    fs::remove_file(dir.join("dns.log")).unwrap();
    fs::remove_file(dir.join("http.log")).unwrap();
    append_data_row(
        &dir.join("ssl.log"),
        "1000.200000\tC1\t192.0.2.10\t50000\t198.51.100.20\t80\ttcp\t6\tTLSv13\tTLS_AES_128_GCM_SHA256\texample.test\tclient-ja3-2\tserver-ja3-2\t-",
    );

    let result = produce_canonical_observations_from_log_dir(&dir, &config(), false).unwrap();
    assert_eq!(result.summary.flow_emitted, 1);
    assert_eq!(result.summary.tls_emitted, 2);
    let tls = result
        .observations
        .iter()
        .filter(|observation| observation.observation_type == ObservationType::Tls)
        .collect::<Vec<_>>();
    assert_eq!(tls.len(), 2);
    assert_eq!(tls[0].source_record_id.as_deref(), Some("C1"));
    assert_eq!(tls[1].source_record_id.as_deref(), Some("C1"));
    assert_ne!(tls[0].record_id, tls[1].record_id);
    let tls_facts = tls
        .iter()
        .map(|observation| match &observation.data {
            CanonicalData::Tls(data) => (
                data.event_time.as_str(),
                data.ja3.as_deref(),
                data.flow_record_id.as_deref(),
            ),
            _ => unreachable!(),
        })
        .collect::<Vec<_>>();
    assert_eq!(tls_facts[0].0, "1970-01-01T00:16:40.100Z");
    assert_eq!(tls_facts[1].0, "1970-01-01T00:16:40.200Z");
    assert_eq!(tls_facts[0].1, Some("client-ja3"));
    assert_eq!(tls_facts[1].1, Some("client-ja3-2"));
    assert_eq!(tls_facts[0].2, tls_facts[1].2);
    assert!(tls_facts[0].2.is_some());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn diagnostics_over_one_hundred_keep_full_count_and_bounded_safe_details() {
    let dir = temp_dir("diagnostic-bound");
    copy_fixture_logs(&dir);
    for index in 0..137 {
        append_data_row(
            &dir.join("http.log"),
            &format!(
                "1000.{index:06}\tC1\t192.0.2.10\t50000\t198.51.100.20\t80\ttcp\t6\t{}\tGET\texample.test\t/marker-sensitive-uri\tmarker-sensitive-agent\tmarker-invalid-status\t0\t10",
                index + 3
            ),
        );
    }

    let result = produce_canonical_observations_from_log_dir(&dir, &config(), false).unwrap();
    assert_eq!(result.summary.diagnostics_count, 137);
    assert_eq!(result.summary.diagnostics.len(), 100);
    assert!(result.summary.diagnostics_truncated);
    assert_eq!(result.summary.rows_skipped, 0);
    assert_eq!(result.summary.http_emitted, 139);
    let serialized = serde_json::to_string(&result.summary).unwrap();
    for marker in [
        "marker-sensitive-uri",
        "marker-sensitive-agent",
        "marker-invalid-status",
    ] {
        assert!(!serialized.contains(marker));
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn mixed_required_and_optional_failures_have_exact_skip_accounting() {
    let dir = temp_dir("rows-skipped");
    copy_fixture_logs(&dir);
    append_data_row(
        &dir.join("conn.log"),
        "invalid-ts\tBAD-CONN\t192.0.2.1\t1234\t198.51.100.1\t80\ttcp\t6\thttp\t1.0\t1\t1\tSF\tSh\t1\t1\t40\t40\t0",
    );
    append_data_row(
        &dir.join("dns.log"),
        "invalid-ts\tBAD-DNS\t192.0.2.1\t1234\t198.51.100.53\t53\tudp\t17\texample.test\t1\t0\tF\tF\tT\tT\tmarker-dns-answer\tF",
    );
    append_data_row(
        &dir.join("ssl.log"),
        "invalid-ts\tBAD-TLS\t192.0.2.1\t1234\t198.51.100.1\t443\ttcp\t6\tTLSv13\tTLS_AES_128_GCM_SHA256\texample.test\tja3\tja3s\t-",
    );
    append_data_row(
        &dir.join("http.log"),
        "invalid-ts\tBAD-HTTP\t192.0.2.1\t1234\t198.51.100.1\t80\ttcp\t6\t3\tGET\texample.test\t/required-invalid\tagent\t200\t0\t1",
    );
    let http = fs::read_to_string(dir.join("http.log")).unwrap();
    fs::write(
        dir.join("http.log"),
        http.replace("\t201\t12\t20", "\toptional-invalid-status\t12\t20"),
    )
    .unwrap();

    let result = produce_canonical_observations_from_log_dir(&dir, &config(), false).unwrap();
    assert_eq!(result.summary.flow_emitted, 2);
    assert_eq!(result.summary.dns_emitted, 2);
    assert_eq!(result.summary.tls_emitted, 1);
    assert_eq!(result.summary.http_emitted, 2);
    assert_eq!(result.summary.rows_skipped, 4);
    assert_eq!(result.observations.len(), 7);
    assert_eq!(result.summary.diagnostics_count, 9);
    assert!(!result.summary.diagnostics_truncated);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn default_diagnostics_never_include_sensitive_source_markers() {
    let dir = temp_dir("diagnostic-privacy");
    copy_fixture_logs(&dir);
    let http_path = dir.join("http.log");
    let http = fs::read_to_string(&http_path)
        .unwrap()
        .replace(
            "response_body_len",
            "response_body_len\tpassword_like_unknown",
        )
        .replace(
            "\t200\t0\t10",
            "\tprivacy-invalid-status\t0\t10\tmarker-password",
        )
        .replace("\t201\t12\t20", "\t201\t12\t20\tmarker-password")
        .replace("/first", "/marker-uri")
        .replace("FixtureAgent/1", "marker-user-agent");
    fs::write(&http_path, http).unwrap();
    let dns_path = dir.join("dns.log");
    let dns = fs::read_to_string(&dns_path)
        .unwrap()
        .replace("203.0.113.1", "marker-full-dns-answer");
    fs::write(&dns_path, dns).unwrap();
    let ssl_path = dir.join("ssl.log");
    let ssl = fs::read_to_string(&ssl_path)
        .unwrap()
        .replace("\tja4", "\tja4\tcertificate_subject_unknown")
        .replace("\t-\n#close", "\t-\tmarker-certificate-subject\n#close");
    fs::write(&ssl_path, ssl).unwrap();

    let result = produce_canonical_observations_from_log_dir(&dir, &config(), false).unwrap();
    assert!(result.summary.diagnostics_count > 0);
    let serialized = serde_json::to_string(&result.summary).unwrap();
    for marker in [
        "marker-uri",
        "marker-user-agent",
        "privacy-invalid-status",
        "marker-password",
        "marker-full-dns-answer",
        "marker-certificate-subject",
    ] {
        assert!(!serialized.contains(marker), "diagnostic leaked {marker}");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn larger_conn_log_preserves_order_and_releases_phase_inputs() {
    let dir = temp_dir("larger-log");
    copy_fixture_logs(&dir);
    for index in 0..1_000 {
        append_data_row(
            &dir.join("conn.log"),
            &format!(
                "2000.{index:06}\tL{index}\t192.0.2.10\t{}\t198.51.100.20\t80\ttcp\t6\thttp\t1.000000\t100\t200\tSF\tShADadFf\t5\t4\t300\t400\t0",
                10_000 + index
            ),
        );
    }
    let result = produce_canonical_observations_from_log_dir(&dir, &config(), false).unwrap();
    assert_eq!(result.summary.flow_emitted, 1_002);
    assert_eq!(result.observations.len(), 1_007);
    assert!(result.observations[..1_002]
        .iter()
        .all(|observation| observation.observation_type == ObservationType::Flow));
    fs::remove_dir_all(dir).unwrap();
}
