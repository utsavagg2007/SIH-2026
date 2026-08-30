use std::fmt;

use crate::canonical::id::{
    generate_zeek_record_id, normalize_sha256, IdentityObservationType, InputIdentityError,
    ZeekLogName,
};
use crate::canonical::time::{
    validate_canonical_utc, zeek_end_time_to_rfc3339, zeek_timestamp_to_rfc3339, ExactTimeError,
};
use crate::canonical::{
    CanonicalData, CanonicalObservation, DirectionCounters, DirectionMode, Fidelity, FlowCounters,
    FlowData, InputMode, ObservationType, Provenance, Quality, TelemetrySource,
};
use crate::zeek_parser::source_types::{
    DiagnosticKind, LosslessParseResult, SourceDiagnostic, SourceIp, SourceValue, ZeekConnRecord,
    ZeekLogType,
};

pub const ZEEK_PARSER_NAME: &str = "sih-ingestion-core-zeek";
pub const ZEEK_PARSER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowProducerConfig {
    sensor_id: String,
    input_sha256: String,
    observed_at: String,
}

#[derive(Debug)]
pub enum FlowProducerConfigError {
    EmptySensorId,
    InvalidInputIdentity(InputIdentityError),
    InvalidObservedAt(ExactTimeError),
}

impl fmt::Display for FlowProducerConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySensorId => {
                f.write_str("sensor_id must be supplied explicitly and be nonempty")
            }
            Self::InvalidInputIdentity(error) => {
                write!(f, "invalid original-PCAP identity: {error}")
            }
            Self::InvalidObservedAt(error) => write!(f, "invalid observed_at: {error}"),
        }
    }
}

impl std::error::Error for FlowProducerConfigError {}

impl FlowProducerConfig {
    pub fn new(
        sensor_id: impl Into<String>,
        input_sha256: impl AsRef<str>,
        observed_at: impl Into<String>,
    ) -> Result<Self, FlowProducerConfigError> {
        let sensor_id = sensor_id.into();
        if sensor_id.is_empty() {
            return Err(FlowProducerConfigError::EmptySensorId);
        }
        let input_sha256 = normalize_sha256(input_sha256.as_ref())
            .map_err(FlowProducerConfigError::InvalidInputIdentity)?;
        let observed_at = observed_at.into();
        validate_canonical_utc(&observed_at).map_err(FlowProducerConfigError::InvalidObservedAt)?;
        Ok(Self {
            sensor_id,
            input_sha256,
            observed_at,
        })
    }

    pub fn sensor_id(&self) -> &str {
        &self.sensor_id
    }

    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }

    pub fn observed_at(&self) -> &str {
        &self.observed_at
    }
}

#[derive(Debug, Clone)]
pub struct FlowProductionResult {
    pub observations: Vec<CanonicalObservation>,
    pub diagnostics: Vec<SourceDiagnostic>,
}

fn diagnostic(
    record: &ZeekConnRecord,
    field: &str,
    kind: DiagnosticKind,
    raw_value: Option<String>,
    message: impl Into<String>,
) -> SourceDiagnostic {
    let mut diagnostic = SourceDiagnostic::for_row(
        ZeekLogType::Conn,
        record.row_ordinal,
        field,
        kind,
        raw_value,
        message,
    );
    diagnostic.source_record_id = valid_nonempty(&record.uid);
    diagnostic
}

fn valid_nonempty(value: &SourceValue<String>) -> Option<String> {
    match value {
        SourceValue::Value(value) if !value.is_empty() => Some(value.clone()),
        _ => None,
    }
}

fn resolve_protocol(
    record: &ZeekConnRecord,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<u8> {
    let numeric = record.ip_proto.copied();
    let named = match record.proto.as_value().map(String::as_str) {
        Some("tcp") => Some(6),
        Some("udp") => Some(17),
        Some("icmp") => Some(1),
        Some("icmp6") => Some(58),
        _ => None,
    };

    if let (Some(numeric), Some(named)) = (numeric, named) {
        if numeric != named {
            diagnostics.push(diagnostic(
                record,
                "ip_proto",
                DiagnosticKind::ConflictingProtocolFields,
                Some(numeric.to_string()),
                format!("numeric ip_proto {numeric} conflicts with named proto {named}"),
            ));
        }
        return Some(numeric);
    }
    if let Some(numeric) = numeric {
        return Some(numeric);
    }
    if let Some(named) = named {
        return Some(named);
    }

    diagnostics.push(diagnostic(
        record,
        "proto",
        DiagnosticKind::InvalidProtocolField,
        match &record.proto {
            SourceValue::Value(raw) | SourceValue::Invalid(raw) => Some(raw.clone()),
            _ => None,
        },
        "neither numeric ip_proto nor a known proto name is available",
    ));
    None
}

fn required_start_time(
    record: &ZeekConnRecord,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<String> {
    let Some(raw) = record.timestamp_raw.as_value() else {
        diagnostics.push(diagnostic(
            record,
            "ts",
            DiagnosticKind::MissingRequiredField,
            match &record.timestamp_raw {
                SourceValue::Invalid(raw) => Some(raw.clone()),
                _ => None,
            },
            "a valid source timestamp is required for canonical flow emission",
        ));
        return None;
    };

    match zeek_timestamp_to_rfc3339(raw) {
        Ok(timestamp) => Some(timestamp),
        Err(error) => {
            diagnostics.push(diagnostic(
                record,
                "ts",
                DiagnosticKind::MalformedDecimalTimestamp,
                Some(raw.clone()),
                error.to_string(),
            ));
            None
        }
    }
}

fn optional_end_time(
    record: &ZeekConnRecord,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<String> {
    let timestamp = record.timestamp_raw.as_value()?;
    let duration = record.duration_raw.as_value()?;
    match zeek_end_time_to_rfc3339(timestamp, duration) {
        Ok(value) => Some(value),
        Err(error) => {
            let kind = if error == ExactTimeError::NegativeDuration {
                DiagnosticKind::NegativeDuration
            } else {
                DiagnosticKind::MalformedDuration
            };
            diagnostics.push(diagnostic(
                record,
                "duration",
                kind,
                Some(duration.clone()),
                error.to_string(),
            ));
            None
        }
    }
}

fn required_ip(
    record: &ZeekConnRecord,
    field: &str,
    value: &SourceValue<SourceIp>,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<String> {
    match value {
        SourceValue::Value(value) => Some(value.parsed.to_string()),
        SourceValue::Invalid(raw) => {
            diagnostics.push(diagnostic(
                record,
                field,
                DiagnosticKind::InvalidIp,
                Some(raw.clone()),
                "a valid source IP address is required for canonical flow emission",
            ));
            None
        }
        _ => {
            diagnostics.push(diagnostic(
                record,
                field,
                DiagnosticKind::MissingRequiredField,
                None,
                "a source IP address is required for canonical flow emission",
            ));
            None
        }
    }
}

fn produce_flow(
    record: &ZeekConnRecord,
    config: &FlowProducerConfig,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<CanonicalObservation> {
    let start_time = required_start_time(record, diagnostics)?;
    let src_ip = required_ip(record, "id.orig_h", &record.src_ip, diagnostics)?;
    let dst_ip = required_ip(record, "id.resp_h", &record.dst_ip, diagnostics)?;
    let ip_protocol = resolve_protocol(record, diagnostics)?;

    let src_to_dst = DirectionCounters {
        packets: record.orig_packets.copied(),
        payload_bytes: record.orig_payload_bytes.copied(),
        ip_bytes: record.orig_ip_bytes.copied(),
        l2_bytes: None,
    };
    if src_to_dst.is_empty() {
        diagnostics.push(diagnostic(
            record,
            "counters.src_to_dst",
            DiagnosticKind::MissingRequiredCounters,
            None,
            "no defensible originator counter is available",
        ));
        return None;
    }

    let reverse = DirectionCounters {
        packets: record.resp_packets.copied(),
        payload_bytes: record.resp_payload_bytes.copied(),
        ip_bytes: record.resp_ip_bytes.copied(),
        l2_bytes: None,
    };
    let dst_to_src = (!reverse.is_empty()).then_some(reverse);
    let is_icmp = matches!(ip_protocol, 1 | 58);
    let source_record_id = valid_nonempty(&record.uid);
    let uid_coordinate = source_record_id.as_deref().unwrap_or("");
    let record_id = generate_zeek_record_id(
        config.sensor_id(),
        config.input_sha256(),
        IdentityObservationType::Flow,
        ZeekLogName::Conn,
        uid_coordinate,
        record.row_ordinal,
    )
    .expect("FlowProducerConfig already validated identity coordinates");

    let missed_content_bytes = record.missed_bytes.copied();
    // "Exact" describes faithful normalization of the available source facts, not
    // complete packet visibility. Likewise, false truncation/loss flags mean this
    // producer found no defensible evidence of either condition; they do not prove
    // that no upstream truncation or capture loss occurred.
    let quality = Quality {
        fidelity: Fidelity::Exact,
        sampling_rate: None,
        sampling_probability: None,
        truncated: false,
        loss_detected: missed_content_bytes.is_some_and(|value| value > 0),
        missed_content_bytes,
    };
    let provenance = Provenance {
        input_mode: InputMode::PcapFile,
        parser_name: ZEEK_PARSER_NAME.to_string(),
        parser_version: ZEEK_PARSER_VERSION.to_string(),
        input_sha256: Some(config.input_sha256().to_string()),
        capture_interface: None,
        exporter_id: None,
        observation_domain_id: None,
        template_id: None,
        message_sequence: None,
    };
    let flow = FlowData {
        start_time,
        end_time: optional_end_time(record, diagnostics),
        src_ip,
        dst_ip,
        src_port: (!is_icmp).then(|| record.src_port.copied()).flatten(),
        dst_port: (!is_icmp).then(|| record.dst_port.copied()).flatten(),
        icmp_type: None,
        icmp_code: None,
        ip_protocol,
        direction_mode: DirectionMode::OriginatorResponder,
        service: valid_nonempty(&record.service),
        connection_state: valid_nonempty(&record.connection_state),
        connection_history: valid_nonempty(&record.connection_history),
        tcp_flags: None,
        end_reason: None,
        ingress_interface: None,
        egress_interface: None,
        counters: FlowCounters {
            src_to_dst,
            dst_to_src,
        },
    };

    Some(CanonicalObservation {
        schema_version: "1.0".to_string(),
        record_id,
        source_record_id,
        observation_type: ObservationType::Flow,
        telemetry_source: TelemetrySource::Zeek,
        sensor_id: config.sensor_id().to_string(),
        observed_at: config.observed_at().to_string(),
        quality,
        provenance,
        data: CanonicalData::Flow(flow),
    })
}

pub fn produce_flow_observations(
    records: &[ZeekConnRecord],
    config: &FlowProducerConfig,
) -> FlowProductionResult {
    let mut diagnostics = Vec::new();
    let observations = records
        .iter()
        .filter_map(|record| produce_flow(record, config, &mut diagnostics))
        .collect();
    FlowProductionResult {
        observations,
        diagnostics,
    }
}

/// Produce flows while carrying parser diagnostics into the complete result.
pub fn produce_flow_observations_from_parse(
    parsed: &LosslessParseResult<ZeekConnRecord>,
    config: &FlowProducerConfig,
) -> FlowProductionResult {
    let mut result = produce_flow_observations(&parsed.records, config);
    let mut diagnostics = parsed.diagnostics.clone();
    diagnostics.append(&mut result.diagnostics);
    result.diagnostics = diagnostics;
    result
}
