use crate::canonical::correlation::{
    CandidateCorrelationOutcome, CorrelationOutcome, EndpointCorrelationTuple, FlowCorrelationIndex,
};
use crate::canonical::id::{generate_zeek_record_id, IdentityObservationType, ZeekLogName};
use crate::canonical::producer::{FlowProducerConfig, ZEEK_PARSER_NAME, ZEEK_PARSER_VERSION};
use crate::canonical::time::zeek_timestamp_to_rfc3339;
use crate::canonical::{
    CanonicalData, CanonicalObservation, Fidelity, InputMode, ObservationType, Provenance, Quality,
    TelemetrySource, TlsData,
};
use crate::zeek_parser::source_types::{
    DiagnosticKind, LosslessParseResult, SourceDiagnostic, SourceIp, SourceValue, ZeekLogType,
    ZeekTlsRecord,
};

#[derive(Debug, Clone)]
pub struct TlsProductionResult {
    pub observations: Vec<CanonicalObservation>,
    pub diagnostics: Vec<SourceDiagnostic>,
}

fn valid_nonempty(value: &SourceValue<String>) -> Option<String> {
    match value {
        SourceValue::Value(value) if !value.is_empty() => Some(value.clone()),
        _ => None,
    }
}

fn diagnostic(
    record: &ZeekTlsRecord,
    field: &str,
    kind: DiagnosticKind,
    raw_value: Option<String>,
    message: impl Into<String>,
) -> SourceDiagnostic {
    let mut diagnostic = SourceDiagnostic::for_row(
        ZeekLogType::Ssl,
        record.row_ordinal,
        field,
        kind,
        raw_value,
        message,
    );
    diagnostic.source_record_id = valid_nonempty(&record.uid);
    diagnostic
}

fn required_event_time(
    record: &ZeekTlsRecord,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<String> {
    match &record.timestamp_raw {
        SourceValue::Value(raw) => match zeek_timestamp_to_rfc3339(raw) {
            Ok(value) => Some(value),
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
        },
        SourceValue::Invalid(raw) => {
            diagnostics.push(diagnostic(
                record,
                "ts",
                DiagnosticKind::MalformedDecimalTimestamp,
                Some(raw.clone()),
                "a valid plain-decimal source timestamp is required for canonical TLS emission",
            ));
            None
        }
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => {
            diagnostics.push(diagnostic(
                record,
                "ts",
                DiagnosticKind::MissingRequiredField,
                None,
                "a valid source timestamp is required for canonical TLS emission",
            ));
            None
        }
    }
}

fn required_ip<'a>(
    record: &ZeekTlsRecord,
    field: &str,
    value: &'a SourceValue<SourceIp>,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<&'a SourceIp> {
    match value {
        SourceValue::Value(value) => Some(value),
        SourceValue::Invalid(raw) => {
            diagnostics.push(diagnostic(
                record,
                field,
                DiagnosticKind::InvalidIp,
                Some(raw.clone()),
                "a valid source IP address is required for canonical TLS emission",
            ));
            None
        }
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => {
            diagnostics.push(diagnostic(
                record,
                field,
                DiagnosticKind::MissingRequiredField,
                None,
                "a source IP address is required for canonical TLS emission",
            ));
            None
        }
    }
}

fn required_port(
    record: &ZeekTlsRecord,
    field: &str,
    value: &SourceValue<u16>,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<u16> {
    match value {
        SourceValue::Value(value) => Some(*value),
        // The lossless parser already emitted the precise malformed/range diagnostic.
        SourceValue::Invalid(_) => None,
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => {
            diagnostics.push(diagnostic(
                record,
                field,
                DiagnosticKind::MissingRequiredField,
                None,
                "a source-reported port is required for canonical TLS emission",
            ));
            None
        }
    }
}

fn direct_protocol(record: &ZeekTlsRecord, diagnostics: &mut Vec<SourceDiagnostic>) -> Option<u8> {
    let numeric = record.ip_proto.copied();
    let named = match record.proto.as_value().map(String::as_str) {
        Some("tcp") => Some(6),
        Some("udp") => Some(17),
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
    if let SourceValue::Value(raw) = &record.proto {
        if !raw.is_empty() {
            diagnostics.push(diagnostic(
                record,
                "proto",
                DiagnosticKind::InvalidProtocolField,
                Some(raw.clone()),
                "named proto is not one of the approved exact mappings",
            ));
        }
    }
    None
}

fn optional_flow_link(
    record: &ZeekTlsRecord,
    index: Option<&FlowCorrelationIndex>,
    tuple: EndpointCorrelationTuple,
    ip_protocol: u8,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<String> {
    let index = index?;
    let uid = valid_nonempty(&record.uid)?;
    match index.correlate_exact_protocol_tuple(&uid, tuple, ip_protocol) {
        CorrelationOutcome::NoCandidates => None,
        CorrelationOutcome::Unique(record_id) => Some(record_id),
        CorrelationOutcome::Ambiguous => {
            diagnostics.push(diagnostic(
                record,
                "flow_record_id",
                DiagnosticKind::AmbiguousFlowLink,
                None,
                "more than one tuple-consistent canonical flow shares this UID",
            ));
            None
        }
        CorrelationOutcome::Inconsistent => {
            diagnostics.push(diagnostic(
                record,
                "flow_record_id",
                DiagnosticKind::InconsistentFlowLink,
                None,
                "canonical flows share this UID but none has a consistent tuple",
            ));
            None
        }
    }
}

fn protocol_and_link(
    record: &ZeekTlsRecord,
    index: Option<&FlowCorrelationIndex>,
    src_ip: &SourceIp,
    dst_ip: &SourceIp,
    src_port: u16,
    dst_port: u16,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<(u8, Option<String>)> {
    let tuple = EndpointCorrelationTuple {
        src_ip: src_ip.parsed,
        dst_ip: dst_ip.parsed,
        src_port,
        dst_port,
    };
    if let Some(ip_protocol) = direct_protocol(record, diagnostics) {
        let link = optional_flow_link(record, index, tuple, ip_protocol, diagnostics);
        return Some((ip_protocol, link));
    }

    let Some(uid) = valid_nonempty(&record.uid) else {
        diagnostics.push(diagnostic(
            record,
            "ip_protocol",
            DiagnosticKind::MissingRequiredProtocol,
            None,
            "TLS ip_protocol is unavailable and flow enrichment requires a nonempty UID",
        ));
        return None;
    };
    let Some(index) = index else {
        diagnostics.push(diagnostic(
            record,
            "ip_protocol",
            DiagnosticKind::MissingRequiredProtocol,
            None,
            "TLS ip_protocol is unavailable and no canonical flow index was supplied",
        ));
        return None;
    };

    match index.correlate_endpoints(&uid, tuple) {
        CandidateCorrelationOutcome::Unique(candidate) => {
            Some((candidate.ip_protocol, Some(candidate.record_id)))
        }
        CandidateCorrelationOutcome::NoCandidates => {
            diagnostics.push(diagnostic(
                record,
                "ip_protocol",
                DiagnosticKind::MissingRequiredProtocol,
                None,
                "TLS ip_protocol is unavailable and no flow candidate shares this UID",
            ));
            None
        }
        CandidateCorrelationOutcome::Ambiguous => {
            diagnostics.push(diagnostic(
                record,
                "ip_protocol",
                DiagnosticKind::AmbiguousFlowLink,
                None,
                "TLS ip_protocol enrichment found more than one endpoint-consistent flow",
            ));
            None
        }
        CandidateCorrelationOutcome::Inconsistent => {
            diagnostics.push(diagnostic(
                record,
                "ip_protocol",
                DiagnosticKind::InconsistentFlowLink,
                None,
                "TLS flow candidates share the UID but none matches the source endpoints",
            ));
            None
        }
    }
}

fn produce_tls(
    record: &ZeekTlsRecord,
    config: &FlowProducerConfig,
    correlation: Option<&FlowCorrelationIndex>,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<CanonicalObservation> {
    let event_time = required_event_time(record, diagnostics)?;
    let src_ip = required_ip(record, "id.orig_h", &record.src_ip, diagnostics)?;
    let dst_ip = required_ip(record, "id.resp_h", &record.dst_ip, diagnostics)?;
    let src_port = required_port(record, "id.orig_p", &record.src_port, diagnostics)?;
    let dst_port = required_port(record, "id.resp_p", &record.dst_port, diagnostics)?;
    let (ip_protocol, flow_record_id) = protocol_and_link(
        record,
        correlation,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        diagnostics,
    )?;
    let source_record_id = valid_nonempty(&record.uid);
    let record_id = generate_zeek_record_id(
        config.sensor_id(),
        config.input_sha256(),
        IdentityObservationType::Tls,
        ZeekLogName::Ssl,
        source_record_id.as_deref().unwrap_or(""),
        record.row_ordinal,
    )
    .expect("FlowProducerConfig already validated identity coordinates");

    Some(CanonicalObservation {
        schema_version: "1.0".to_string(),
        record_id,
        source_record_id,
        observation_type: ObservationType::Tls,
        telemetry_source: TelemetrySource::Zeek,
        sensor_id: config.sensor_id().to_string(),
        observed_at: config.observed_at().to_string(),
        quality: Quality {
            fidelity: Fidelity::Exact,
            sampling_rate: None,
            sampling_probability: None,
            truncated: false,
            loss_detected: false,
            missed_content_bytes: None,
        },
        provenance: Provenance {
            input_mode: InputMode::PcapFile,
            parser_name: ZEEK_PARSER_NAME.to_string(),
            parser_version: ZEEK_PARSER_VERSION.to_string(),
            input_sha256: Some(config.input_sha256().to_string()),
            capture_interface: None,
            exporter_id: None,
            observation_domain_id: None,
            template_id: None,
            message_sequence: None,
        },
        data: CanonicalData::Tls(TlsData {
            event_time,
            flow_record_id,
            src_ip: src_ip.parsed.to_string(),
            dst_ip: dst_ip.parsed.to_string(),
            src_port,
            dst_port,
            ip_protocol,
            version: valid_nonempty(&record.version),
            cipher: valid_nonempty(&record.cipher),
            server_name: valid_nonempty(&record.server_name),
            ja3: valid_nonempty(&record.ja3),
            ja3s: valid_nonempty(&record.ja3s),
            ja4: valid_nonempty(&record.ja4),
        }),
    })
}

pub fn produce_tls_observations_from_parse(
    parsed: &LosslessParseResult<ZeekTlsRecord>,
    config: &FlowProducerConfig,
    correlation: Option<&FlowCorrelationIndex>,
) -> TlsProductionResult {
    let mut diagnostics = parsed.diagnostics.clone();
    let observations = parsed
        .records
        .iter()
        .filter_map(|record| produce_tls(record, config, correlation, &mut diagnostics))
        .collect();
    TlsProductionResult {
        observations,
        diagnostics,
    }
}
