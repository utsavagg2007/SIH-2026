use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::canonical::correlation::FlowCorrelationIndex;
use crate::canonical::dns_producer::produce_dns_observations_from_parse;
use crate::canonical::http_producer::produce_http_observations_from_parse;
use crate::canonical::producer::{produce_flow_observations_from_parse, FlowProducerConfig};
use crate::canonical::tls_producer::produce_tls_observations_from_parse;
use crate::canonical::CanonicalObservation;
use crate::zeek_parser::conn_log::parse_conn_log_lossless;
use crate::zeek_parser::dns_log::parse_dns_log_lossless;
use crate::zeek_parser::http_log::parse_http_log_lossless;
use crate::zeek_parser::source_types::{SourceDiagnostic, ZeekLogType};
use crate::zeek_parser::ssl_log::parse_ssl_log_lossless;

const MAX_RETURNED_DIAGNOSTICS: usize = 100;

#[derive(Debug)]
pub enum CanonicalOrchestrationError {
    LogDirectoryUnavailable(PathBuf),
    MissingConnLog(PathBuf),
    IncompleteLogSet(PathBuf),
    ReadLog {
        path: PathBuf,
        source: std::io::Error,
    },
    ParseLog {
        path: PathBuf,
        message: String,
    },
}

impl fmt::Display for CanonicalOrchestrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LogDirectoryUnavailable(path) => {
                write!(f, "Zeek log directory is unavailable: {}", path.display())
            }
            Self::MissingConnLog(path) => {
                write!(f, "required conn.log is missing: {}", path.display())
            }
            Self::IncompleteLogSet(path) => write!(
                f,
                "canonical Zeek log set is incomplete: protocol logs exist but {} is missing",
                path.display()
            ),
            Self::ReadLog { path, source } => {
                write!(f, "failed to read Zeek log {}: {source}", path.display())
            }
            Self::ParseLog { path, message } => {
                write!(f, "failed to parse Zeek log {}: {message}", path.display())
            }
        }
    }
}

impl std::error::Error for CanonicalOrchestrationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadLog { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalDiagnostic {
    pub log_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_record_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_ordinal: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub kind: String,
    pub message: String,
}

impl CanonicalDiagnostic {
    fn from_source(value: &SourceDiagnostic) -> Self {
        let log_type = match value.log_type {
            ZeekLogType::Conn => "conn",
            ZeekLogType::Dns => "dns",
            ZeekLogType::Ssl => "ssl",
            ZeekLogType::Http => "http",
        };
        Self {
            log_type: log_type.to_string(),
            source_record_id: value.source_record_id.clone(),
            row_ordinal: value.row_ordinal,
            field: value.field.clone(),
            kind: format!("{:?}", value.kind),
            message: value.message.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalRunSummary {
    pub flow_emitted: usize,
    pub dns_emitted: usize,
    pub tls_emitted: usize,
    pub http_emitted: usize,
    pub rows_skipped: usize,
    pub diagnostics_count: usize,
    pub diagnostics_truncated: bool,
    pub missing_optional_logs: Vec<String>,
    pub diagnostics: Vec<CanonicalDiagnostic>,
}

impl CanonicalRunSummary {
    fn empty(missing_optional_logs: Vec<String>) -> Self {
        Self {
            flow_emitted: 0,
            dns_emitted: 0,
            tls_emitted: 0,
            http_emitted: 0,
            rows_skipped: 0,
            diagnostics_count: 0,
            diagnostics_truncated: false,
            missing_optional_logs,
            diagnostics: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CanonicalRunResult {
    pub observations: Vec<CanonicalObservation>,
    pub summary: CanonicalRunSummary,
}

fn read_log(path: &Path) -> Result<String, CanonicalOrchestrationError> {
    fs::read_to_string(path).map_err(|source| CanonicalOrchestrationError::ReadLog {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_error(path: &Path, message: String) -> CanonicalOrchestrationError {
    CanonicalOrchestrationError::ParseLog {
        path: path.to_path_buf(),
        message,
    }
}

fn finish_summary(
    flow_emitted: usize,
    dns_emitted: usize,
    tls_emitted: usize,
    http_emitted: usize,
    rows_skipped: usize,
    missing_optional_logs: Vec<String>,
    diagnostics: &[SourceDiagnostic],
) -> CanonicalRunSummary {
    let public_diagnostics = diagnostics
        .iter()
        .take(MAX_RETURNED_DIAGNOSTICS)
        .map(CanonicalDiagnostic::from_source)
        .collect::<Vec<_>>();
    CanonicalRunSummary {
        flow_emitted,
        dns_emitted,
        tls_emitted,
        http_emitted,
        rows_skipped,
        diagnostics_count: diagnostics.len(),
        diagnostics_truncated: diagnostics.len() > public_diagnostics.len(),
        missing_optional_logs,
        diagnostics: public_diagnostics,
    }
}

/// Produce one ordered canonical batch from an existing Zeek log directory.
///
/// `allow_empty_log_set` is reserved for a successful, fresh Zeek execution
/// that emitted no supported logs. Arbitrary external/skip-Zeek log sets must
/// pass `false`, making a missing `conn.log` an input-level failure.
pub fn produce_canonical_observations_from_log_dir(
    log_dir: impl AsRef<Path>,
    config: &FlowProducerConfig,
    allow_empty_log_set: bool,
) -> Result<CanonicalRunResult, CanonicalOrchestrationError> {
    let log_dir = log_dir.as_ref();
    if !log_dir.is_dir() {
        return Err(CanonicalOrchestrationError::LogDirectoryUnavailable(
            log_dir.to_path_buf(),
        ));
    }

    let conn_path = log_dir.join("conn.log");
    let dns_path = log_dir.join("dns.log");
    let ssl_path = log_dir.join("ssl.log");
    let http_path = log_dir.join("http.log");
    let optional = [
        ("dns.log", dns_path.as_path()),
        ("ssl.log", ssl_path.as_path()),
        ("http.log", http_path.as_path()),
    ];

    if !conn_path.is_file() {
        if optional.iter().any(|(_, path)| path.is_file()) {
            return Err(CanonicalOrchestrationError::IncompleteLogSet(conn_path));
        }
        if allow_empty_log_set {
            return Ok(CanonicalRunResult {
                observations: Vec::new(),
                summary: CanonicalRunSummary::empty(
                    optional
                        .iter()
                        .map(|(name, _)| (*name).to_string())
                        .collect(),
                ),
            });
        }
        return Err(CanonicalOrchestrationError::MissingConnLog(conn_path));
    }

    // Keep the potentially large source text and lossless parse tree scoped to
    // the producer phase. Only the produced observations/diagnostics survive.
    let (flow_rows, flow_result) = {
        let content = read_log(&conn_path)?;
        let parsed = parse_conn_log_lossless(&content)
            .map_err(|message| parse_error(&conn_path, message))?;
        let source_rows = parsed.records.len();
        let produced = produce_flow_observations_from_parse(&parsed, config);
        (source_rows, produced)
    };
    let flow_emitted = flow_result.observations.len();
    let correlation = FlowCorrelationIndex::from_flow_observations(&flow_result.observations);
    let mut observations = flow_result.observations;
    let mut diagnostics = flow_result.diagnostics;
    let mut rows_skipped = flow_rows.saturating_sub(flow_emitted);
    let mut missing_optional_logs = Vec::new();

    let mut dns_emitted = 0;
    if dns_path.is_file() {
        let content = read_log(&dns_path)?;
        let parsed =
            parse_dns_log_lossless(&content).map_err(|message| parse_error(&dns_path, message))?;
        let source_rows = parsed.records.len();
        let mut produced = produce_dns_observations_from_parse(&parsed, config, Some(&correlation));
        dns_emitted = produced.observations.len();
        rows_skipped += source_rows.saturating_sub(dns_emitted);
        observations.append(&mut produced.observations);
        diagnostics.append(&mut produced.diagnostics);
    } else {
        missing_optional_logs.push("dns.log".to_string());
    }

    let mut tls_emitted = 0;
    if ssl_path.is_file() {
        let content = read_log(&ssl_path)?;
        let parsed =
            parse_ssl_log_lossless(&content).map_err(|message| parse_error(&ssl_path, message))?;
        let source_rows = parsed.records.len();
        let mut produced = produce_tls_observations_from_parse(&parsed, config, Some(&correlation));
        tls_emitted = produced.observations.len();
        rows_skipped += source_rows.saturating_sub(tls_emitted);
        observations.append(&mut produced.observations);
        diagnostics.append(&mut produced.diagnostics);
    } else {
        missing_optional_logs.push("ssl.log".to_string());
    }

    let mut http_emitted = 0;
    if http_path.is_file() {
        let content = read_log(&http_path)?;
        let parsed = parse_http_log_lossless(&content)
            .map_err(|message| parse_error(&http_path, message))?;
        let source_rows = parsed.records.len();
        let mut produced =
            produce_http_observations_from_parse(&parsed, config, Some(&correlation));
        http_emitted = produced.observations.len();
        rows_skipped += source_rows.saturating_sub(http_emitted);
        observations.append(&mut produced.observations);
        diagnostics.append(&mut produced.diagnostics);
    } else {
        missing_optional_logs.push("http.log".to_string());
    }

    let summary = finish_summary(
        flow_emitted,
        dns_emitted,
        tls_emitted,
        http_emitted,
        rows_skipped,
        missing_optional_logs,
        &diagnostics,
    );
    Ok(CanonicalRunResult {
        observations,
        summary,
    })
}
