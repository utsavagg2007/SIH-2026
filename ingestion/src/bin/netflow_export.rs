//! One-shot offline integration. F2--F7 remain unchanged and own wire semantics.
//! Outputs are complete only when ingestion_complete.json exists. No collector
//! epoch is reused: each invocation owns and drops a fresh bounded F5 registry.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use ingestion_core::canonical::output::write_canonical_observations_jsonl;
use ingestion_core::canonical::{CanonicalObservation, InputMode};
use ingestion_core::netflow::input::{process_raw_datagram_file, RawDatagramInputConfig};
use ingestion_core::netflow::template::{TemplateRegistry, TransportSessionKey};
use ingestion_core::netflow::v5::parse_netflow_v5_datagram;
use ingestion_core::netflow::v9::{
    parse_netflow_v9, CountValidation, NetFlowV9ParseContext, NetFlowV9ParserConfig,
};
use ingestion_core::netflow::v9_normalize::{
    normalize_netflow_v9, NetFlowV9ByteBasisProfile, NetFlowV9NormalizationConfig,
    NetFlowV9SourceContext,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_WIRE_BYTES: usize = 65_535;
const MAX_HEX_BYTES: usize = MAX_WIRE_BYTES * 4;

fn bounded_read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(u64::try_from(limit)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input artifact limit exceeded".into());
    }
    Ok(bytes)
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn wire_bytes(artifact: &[u8], format: &str) -> Result<Vec<u8>> {
    if format == "raw" {
        return Ok(artifact.to_vec());
    }
    let digits: Vec<_> = artifact
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if !digits.len().is_multiple_of(2) || digits.len() / 2 > MAX_WIRE_BYTES {
        return Err("invalid bounded hex datagram".into());
    }
    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16).ok_or("invalid hex")?;
            let low = char::from(pair[1]).to_digit(16).ok_or("invalid hex")?;
            Ok(u8::try_from(high * 16 + low)?)
        })
        .collect()
}

fn args() -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(key) = args.next() {
        if !matches!(
            key.as_str(),
            "--source"
                | "--input"
                | "--output-dir"
                | "--sensor-id"
                | "--exporter-id"
                | "--session-id"
                | "--observed-at"
                | "--wire-format"
                | "--byte-basis"
                | "--v9-max-data-records"
                | "--v9-max-observations"
        ) {
            return Err("unknown argument (see docs/NETFLOW_E2E.md)".into());
        }
        let value = args.next().ok_or("argument requires value")?;
        if values.insert(key, value).is_some() {
            return Err("duplicate argument".into());
        }
    }
    Ok(values)
}

fn required<'a>(args: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str> {
    args.get(key)
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing required argument: {key}").into())
}

fn limit(args: &BTreeMap<String, String>, key: &str) -> Result<usize> {
    let value = args.get(key).map_or(Ok(16_384), |s| s.parse())?;
    if !(1..=16_384).contains(&value) {
        return Err("v9 record limit must be within 1..16384".into());
    }
    Ok(value)
}

fn ingest(args: &BTreeMap<String, String>) -> Result<(Vec<CanonicalObservation>, Value)> {
    let source = required(args, "--source")?;
    let input = Path::new(required(args, "--input")?);
    let sensor = required(args, "--sensor-id")?;
    let exporter = required(args, "--exporter-id")?;
    let observed = required(args, "--observed-at")?;
    let format = args.get("--wire-format").map_or("raw", String::as_str);
    let basis = args.get("--byte-basis").map_or("unknown", String::as_str);
    if !matches!(source, "netflow-v5" | "netflow-v9")
        || !matches!(format, "raw" | "hex")
        || !matches!(basis, "unknown" | "ip")
    {
        return Err("unsupported source, wire format, or byte basis".into());
    }
    if source == "netflow-v5" && (format != "raw" || basis != "unknown") {
        return Err("v5 uses the frozen F4 raw input and F3 byte semantics".into());
    }
    let read_limit = if source == "netflow-v5" {
        24 + 30 * 48
    } else if format == "hex" {
        MAX_HEX_BYTES
    } else {
        MAX_WIRE_BYTES
    };
    let artifact = bounded_read(input, read_limit)?;
    let artifact_hash = hash(&artifact);
    let bytes = wire_bytes(&artifact, format)?;
    let wire_hash = hash(&bytes);
    if source == "netflow-v5" {
        let parsed = parse_netflow_v5_datagram(&bytes)?;
        let mut config = RawDatagramInputConfig::new(sensor, exporter, observed);
        // The F4 reader validates the same artifact; a concurrent input rewrite
        // cannot make the independently inspected record count contradict it.
        config.expected_sha256 = Some(artifact_hash.clone());
        let out = process_raw_datagram_file(input, &config)?;
        let emitted = out.observations.len();
        let mut warnings = Vec::new();
        if !parsed.diagnostics.is_empty() {
            warnings.push("ParserDiagnostics");
        }
        if out.diagnostics_total > 0 {
            warnings.push("NormalizationDiagnostics");
        }
        let status = json!({
            "status_version": "1.0", "source": "netflow_v5",
            "artifact_sha256": artifact_hash, "wire_sha256": wire_hash,
            "wire_format": format, "records_decoded": parsed.records.len(),
            "records_emitted": emitted, "records_rejected": parsed.records.len() - emitted,
            "options_records_ignored": 0, "datagrams_accepted": out.datagrams_accepted,
            "parser_diagnostics_total": parsed.diagnostics.len(), "parser_diagnostics_dropped": 0,
            "parser_diagnostics": parsed.diagnostics.iter().map(|d| format!("{d:?}")).collect::<Vec<_>>(),
            "normalizer_diagnostics_total": out.diagnostics_total,
            "normalizer_diagnostics_dropped": out.diagnostics_dropped,
            "normalizer_diagnostics": out.diagnostics.iter().map(|d| format!("{d:?}")).collect::<Vec<_>>(),
            "warnings": warnings,
            "reset_required": false,
        });
        return Ok((out.observations, status));
    }
    let session = TransportSessionKey::new(exporter, required(args, "--session-id")?, 256)?;
    let max_records = limit(args, "--v9-max-data-records")?;
    let config =
        NetFlowV9ParserConfig::new(MAX_WIRE_BYTES, 1024, 512, 2048, 4096, max_records, 128)?;
    let mut registry = TemplateRegistry::new(Default::default());
    let parsed = parse_netflow_v9(
        &bytes,
        NetFlowV9ParseContext {
            session,
            datagram_ordinal: 0,
        },
        &mut registry,
        config,
    )?;
    let basis = if basis == "ip" {
        NetFlowV9ByteBasisProfile::VerifiedIpLayer
    } else {
        NetFlowV9ByteBasisProfile::Unknown
    };
    let context =
        NetFlowV9SourceContext::new(sensor, InputMode::ExportFile, &wire_hash, observed, basis)?;
    let normalization = NetFlowV9NormalizationConfig::new(
        86_400_000,
        16_384,
        limit(args, "--v9-max-observations")?,
        128,
        16_384,
    )?;
    let out = normalize_netflow_v9(&parsed, &context, normalization)
        .map_err(|e| format!("{e}; parser_status={:?}", e.parser_status))?;
    let count = match out.parser_status.count_validation {
        CountValidation::Match => json!({"state": "Match"}),
        CountValidation::Mismatch { declared, parsed } => {
            json!({"state": "Mismatch", "declared": declared, "parsed": parsed})
        }
        CountValidation::Inconclusive => json!({"state": "Inconclusive"}),
    };
    let mut warnings = Vec::new();
    if out.parser_status.count_validation != CountValidation::Match {
        warnings.push("CountValidation");
    }
    if out.parser_status.diagnostics_total > 0 {
        warnings.push("ParserDiagnostics");
    }
    if out.diagnostics_total > 0 {
        warnings.push("NormalizationDiagnostics");
    }
    if out.parser_status.reset_required() {
        warnings.push("ResetRequired");
    }
    let status = json!({
        "status_version": "1.0", "source": "netflow_v9",
        "artifact_sha256": artifact_hash, "wire_sha256": wire_hash,
        "wire_format": format, "byte_basis_profile": format!("{basis:?}"),
        "records_decoded": out.parser_status.decoded_record_count,
        "records_inspected": out.records_inspected, "records_emitted": out.records_emitted,
        "records_rejected": out.records_rejected, "options_records_ignored": out.options_records_ignored,
        "count_validation": count, "parse_completion": format!("{:?}", out.parser_status.completion),
        "session_disposition": format!("{:?}", out.parser_status.session_disposition),
        "reset_required": out.parser_status.reset_required(),
        "reset_action": if out.parser_status.reset_required() { "DiscardRegistryAndUseNewSessionEpoch" } else { "None" },
        "registry_reused": false,
        "parser_diagnostics_total": out.parser_status.diagnostics_total,
        "parser_diagnostics_dropped": out.parser_status.diagnostics_dropped,
        "parser_diagnostics": out.parser_status.diagnostics.iter().map(|d| format!("{d:?}")).collect::<Vec<_>>(),
        "normalizer_diagnostics_total": out.diagnostics_total,
        "normalizer_diagnostics_dropped": out.diagnostics_dropped,
        "normalizer_diagnostics": out.diagnostics.iter().map(|d| format!("{d:?}")).collect::<Vec<_>>(),
        "normalization_status": format!("{:?}", out.normalization_status),
        "audit": out.audit.iter().map(|entry| json!({
            "datagram_ordinal": entry.datagram_ordinal, "flowset_ordinal": entry.flowset_ordinal,
            "record_ordinal": entry.record_ordinal, "byte_offset": entry.byte_offset,
            "template_id": entry.template_id, "generation": entry.generation,
            "action": format!("{:?}", entry.action),
        })).collect::<Vec<_>>(),
        "warnings": warnings,
    });
    // Registry ownership ends here, even if ResetRequired has a valid prefix.
    Ok((out.observations, status))
}

fn write_new_json(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    let temporary = path.with_extension("json.partial");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::hard_link(&temporary, path)?; // atomic and never overwrites
    fs::remove_file(&temporary)?;
    Ok(())
}

fn run() -> Result<()> {
    let args = args()?;
    let output = PathBuf::from(required(&args, "--output-dir")?);
    // Finish all input validation before claiming any output path.
    let (observations, status) = ingest(&args)?;
    fs::create_dir(&output)?; // exclusive; never replaces an existing run
    write_new_json(&output.join("ingestion_status.json"), &status)?;
    write_canonical_observations_jsonl(output.join("canonical_observations.jsonl"), &observations)?;
    write_new_json(
        &output.join("ingestion_complete.json"),
        &json!({"complete": true}),
    )?;
    println!("{}", serde_json::to_string(&status)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("NetFlow export failed: {error}");
        std::process::exit(1);
    }
}
