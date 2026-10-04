//! Real executable output/status regression; no alternative serializer.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("sih-netflow-export-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        // Only the exact directory exclusively created by this test owns data.
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/export")
        .join(name)
}
fn run(input: &Path, directory: &Path, v5: bool, extra: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_netflow_export"));
    command.args(["--source", if v5 { "netflow-v5" } else { "netflow-v9" }]);
    command
        .arg("--input")
        .arg(input)
        .arg("--output-dir")
        .arg(directory);
    command.args([
        "--sensor-id",
        if v5 {
            "sensor-netflow-golden"
        } else {
            "sensor-v9-a"
        },
        "--exporter-id",
        if v5 { "exporter-golden" } else { "exporter-a" },
        "--observed-at",
        if v5 {
            "2026-09-18T00:00:00Z"
        } else {
            "2026-10-03T00:00:00Z"
        },
    ]);
    if !v5 {
        command.args(["--session-id", "collector-a.udp.epoch-1"]);
    }
    if input.extension().and_then(|s| s.to_str()) == Some("hex") {
        command.args(["--wire-format", "hex"]);
    }
    command.args(extra).output().unwrap()
}
fn status(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path.join("ingestion_status.json")).unwrap()).unwrap()
}

#[test]
fn v5_real_f4_output_matches_existing_golden_and_order() {
    let temp = TestDir::new();
    let output = temp.0.join("result");
    assert!(run(
        &fixture("netflow_v5/repeated_5tuple_distinct_rows.bin"),
        &output,
        true,
        &[]
    )
    .status
    .success());
    assert_eq!(
        fs::read(output.join("canonical_observations.jsonl")).unwrap(),
        fs::read(fixture(
            "netflow_v5/canonical/repeated_5tuple_distinct_rows.canonical.jsonl"
        ))
        .unwrap()
    );
    assert_eq!(status(&output)["records_emitted"], 3);
}

#[test]
fn v9_output_uses_existing_golden_utf8_lf_serializer() {
    let temp = TestDir::new();
    let output = temp.0.join("result");
    assert!(run(
        &fixture("netflow_v9_canonical/wire/tcp_min.hex"),
        &output,
        false,
        &[]
    )
    .status
    .success());
    let actual = fs::read(output.join("canonical_observations.jsonl")).unwrap();
    assert_eq!(
        actual,
        fs::read(fixture("netflow_v9_canonical/golden/tcp_min.jsonl")).unwrap()
    );
    assert!(std::str::from_utf8(&actual).is_ok());
    assert!(!actual.starts_with(&[0xef, 0xbb, 0xbf]));
    assert_eq!(actual.iter().filter(|b| **b == b'\n').count(), 1);
    assert!(!actual.contains(&b'\r'));
    assert!(output.join("ingestion_complete.json").is_file());
}

#[test]
fn zero_emission_rejection_has_diagnostics_and_complete_empty_jsonl() {
    let temp = TestDir::new();
    let output = temp.0.join("result");
    assert!(run(
        &fixture("netflow_v9_canonical/wire/missing_src.hex"),
        &output,
        false,
        &[]
    )
    .status
    .success());
    assert!(fs::read(output.join("canonical_observations.jsonl"))
        .unwrap()
        .is_empty());
    assert_eq!(status(&output)["records_rejected"], 1);
    assert_eq!(status(&output)["normalizer_diagnostics_total"], 1);
}

#[test]
fn inconclusive_reset_obligation_is_actionable_and_not_repaired() {
    let temp = TestDir::new();
    let output = temp.0.join("result");
    assert!(run(
        &fixture("netflow_v9/malformed/untrusted_template_extent.bin"),
        &output,
        false,
        &[]
    )
    .status
    .success());
    let status = status(&output);
    assert_eq!(status["count_validation"]["state"], "Inconclusive");
    assert_eq!(status["parse_completion"], "StoppedForReset");
    assert_eq!(status["session_disposition"], "ResetRequired");
    assert_eq!(status["reset_required"], true);
    assert_eq!(status["registry_reused"], false);
    assert_eq!(
        status["reset_action"],
        "DiscardRegistryAndUseNewSessionEpoch"
    );
}

#[test]
fn count_mismatch_remains_structured_even_with_canonical_output() {
    let temp = TestDir::new();
    let mut bytes = fs::read(fixture("netflow_v9_canonical/wire/tcp_min.hex")).unwrap();
    // Count 0002 -> 0003 in the independent ASCII hex wire fixture.
    bytes[7] = b'3';
    let input = temp.0.join("mismatch.hex");
    fs::write(&input, bytes).unwrap();
    let output = temp.0.join("result");
    assert!(run(&input, &output, false, &[]).status.success());
    assert_eq!(status(&output)["records_emitted"], 1);
    assert_eq!(
        status(&output)["count_validation"],
        serde_json::json!({"state":"Mismatch","declared":3,"parsed":2})
    );
}

#[test]
fn parser_stopped_at_limit_retains_inconclusive_status() {
    let temp = TestDir::new();
    let output = temp.0.join("result");
    assert!(run(
        &fixture("netflow_v9_canonical/wire/repeated.hex"),
        &output,
        false,
        &["--v9-max-data-records", "1"]
    )
    .status
    .success());
    let status = status(&output);
    assert_eq!(status["parse_completion"], "StoppedAtLimit");
    assert_eq!(status["count_validation"]["state"], "Inconclusive");
}

#[test]
fn normalizer_stopped_at_limit_does_not_change_parser_status() {
    let temp = TestDir::new();
    let output = temp.0.join("result");
    assert!(run(
        &fixture("netflow_v9_canonical/wire/repeated.hex"),
        &output,
        false,
        &["--v9-max-observations", "1"]
    )
    .status
    .success());
    let status = status(&output);
    assert_eq!(status["normalization_status"], "StoppedAtLimit");
    assert_eq!(status["parse_completion"], "Complete");
    assert_eq!(status["records_emitted"], 1);
}

#[test]
fn malformed_wire_and_oversize_publish_no_final_output() {
    let temp = TestDir::new();
    for (name, bytes) in [
        ("malformed.bin", vec![0; 3]),
        ("oversize.bin", vec![0; 65_536]),
    ] {
        let input = temp.0.join(name);
        fs::write(&input, bytes).unwrap();
        let output = temp.0.join(format!("output-{name}"));
        assert!(!run(&input, &output, false, &[]).status.success());
        assert!(!output.exists());
    }
}

#[test]
fn existing_output_is_never_replaced() {
    let temp = TestDir::new();
    let output = temp.0.join("result");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("sentinel"), b"preserve").unwrap();
    assert!(!run(
        &fixture("netflow_v9_canonical/wire/tcp_min.hex"),
        &output,
        false,
        &[]
    )
    .status
    .success());
    assert_eq!(fs::read(output.join("sentinel")).unwrap(), b"preserve");
    assert!(!output.join("canonical_observations.jsonl").exists());
}

#[test]
fn replay_jsonl_and_status_are_byte_identical() {
    let temp = TestDir::new();
    let first = temp.0.join("first");
    let second = temp.0.join("second");
    let input = fixture("netflow_v9_canonical/wire/repeated.hex");
    assert!(run(&input, &first, false, &[]).status.success());
    assert!(run(&input, &second, false, &[]).status.success());
    for name in [
        "canonical_observations.jsonl",
        "ingestion_status.json",
        "ingestion_complete.json",
    ] {
        assert_eq!(
            fs::read(first.join(name)).unwrap(),
            fs::read(second.join(name)).unwrap()
        );
    }
}
