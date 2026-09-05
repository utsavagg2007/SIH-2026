use crate::canonical::correlation::{
    CorrelationOutcome, DnsCorrelationTuple, FlowCorrelationIndex,
};
use crate::canonical::id::{generate_zeek_record_id, IdentityObservationType, ZeekLogName};
use crate::canonical::producer::{FlowProducerConfig, ZEEK_PARSER_NAME, ZEEK_PARSER_VERSION};
use crate::canonical::time::zeek_timestamp_to_rfc3339;
use crate::canonical::{
    CanonicalData, CanonicalObservation, DnsData, Fidelity, InputMode, ObservationType, Provenance,
    Quality, TelemetrySource,
};
use crate::zeek_parser::source_types::{
    DiagnosticKind, LosslessParseResult, SourceDiagnostic, SourceIp, SourceValue, ZeekDnsRecord,
    ZeekLogType,
};

#[derive(Debug, Clone)]
pub struct DnsProductionResult {
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
    record: &ZeekDnsRecord,
    field: &str,
    kind: DiagnosticKind,
    raw_value: Option<String>,
    message: impl Into<String>,
) -> SourceDiagnostic {
    let mut diagnostic = SourceDiagnostic::for_row(
        ZeekLogType::Dns,
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
    record: &ZeekDnsRecord,
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
                "a valid plain-decimal source timestamp is required for canonical DNS emission",
            ));
            None
        }
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => {
            diagnostics.push(diagnostic(
                record,
                "ts",
                DiagnosticKind::MissingRequiredField,
                None,
                "a valid source timestamp is required for canonical DNS emission",
            ));
            None
        }
    }
}

fn required_ip<'a>(
    record: &ZeekDnsRecord,
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
                "a valid source IP address is required for canonical DNS emission",
            ));
            None
        }
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => {
            diagnostics.push(diagnostic(
                record,
                field,
                DiagnosticKind::MissingRequiredField,
                None,
                "a source IP address is required for canonical DNS emission",
            ));
            None
        }
    }
}

fn resolve_protocol(record: &ZeekDnsRecord, diagnostics: &mut Vec<SourceDiagnostic>) -> Option<u8> {
    let numeric = record.ip_proto.copied();
    let named = match record.proto.as_value().map(String::as_str) {
        Some("udp") => Some(17),
        Some("tcp") => Some(6),
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
        "neither numeric ip_proto nor a known DNS transport name is available",
    ));
    None
}

fn canonical_query(value: &SourceValue<String>) -> Option<String> {
    match value {
        SourceValue::Value(raw) => Some(raw.clone()),
        SourceValue::Empty => Some(String::new()),
        SourceValue::Missing | SourceValue::Unset | SourceValue::Invalid(_) => None,
    }
}

fn correlate_flow(
    record: &ZeekDnsRecord,
    index: Option<&FlowCorrelationIndex>,
    tuple: DnsCorrelationTuple,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<String> {
    let index = index?;
    let uid = valid_nonempty(&record.uid)?;
    match index.correlate(&uid, tuple) {
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

fn produce_dns(
    record: &ZeekDnsRecord,
    config: &FlowProducerConfig,
    correlation: Option<&FlowCorrelationIndex>,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> Option<CanonicalObservation> {
    let event_time = required_event_time(record, diagnostics)?;
    let src_ip = required_ip(record, "id.orig_h", &record.src_ip, diagnostics)?;
    let dst_ip = required_ip(record, "id.resp_h", &record.dst_ip, diagnostics)?;
    let ip_protocol = resolve_protocol(record, diagnostics)?;
    let src_port = record.src_port.copied();
    let dst_port = record.dst_port.copied();
    let source_record_id = valid_nonempty(&record.uid);
    let flow_record_id = correlate_flow(
        record,
        correlation,
        DnsCorrelationTuple {
            src_ip: src_ip.parsed,
            dst_ip: dst_ip.parsed,
            src_port,
            dst_port,
            ip_protocol,
        },
        diagnostics,
    );

    let record_id = generate_zeek_record_id(
        config.sensor_id(),
        config.input_sha256(),
        IdentityObservationType::Dns,
        ZeekLogName::Dns,
        source_record_id.as_deref().unwrap_or(""),
        record.row_ordinal,
    )
    .expect("FlowProducerConfig already validated identity coordinates");

    let data = DnsData {
        event_time,
        flow_record_id,
        src_ip: src_ip.parsed.to_string(),
        dst_ip: dst_ip.parsed.to_string(),
        src_port,
        dst_port,
        ip_protocol,
        query: canonical_query(&record.query),
        qtype: record.qtype.as_value().map(|code| code.value),
        qclass: record.qclass.as_value().map(|code| code.value),
        rcode: record.rcode.as_value().map(|code| code.value),
        authoritative_answer: record.authoritative_answer.copied(),
        dns_truncated: record.truncated.copied(),
        recursion_desired: record.recursion_desired.copied(),
        recursion_available: record.recursion_available.copied(),
        rejected: record.rejected.copied(),
        answer_count: record.answer_count.copied(),
    };

    Some(CanonicalObservation {
        schema_version: "1.0".to_string(),
        record_id,
        source_record_id,
        observation_type: ObservationType::Dns,
        telemetry_source: TelemetrySource::Zeek,
        sensor_id: config.sensor_id().to_string(),
        observed_at: config.observed_at().to_string(),
        quality: Quality {
            fidelity: Fidelity::Exact,
            sampling_rate: None,
            sampling_probability: None,
            // DNS TC describes the DNS message, not capture or producer truncation.
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
        data: CanonicalData::Dns(data),
    })
}

pub fn produce_dns_observations(
    records: &[ZeekDnsRecord],
    config: &FlowProducerConfig,
    correlation: Option<&FlowCorrelationIndex>,
) -> DnsProductionResult {
    let mut diagnostics = Vec::new();
    let observations = records
        .iter()
        .filter_map(|record| produce_dns(record, config, correlation, &mut diagnostics))
        .collect();
    DnsProductionResult {
        observations,
        diagnostics,
    }
}

/// Produce DNS observations while carrying parser diagnostics into the result.
pub fn produce_dns_observations_from_parse(
    parsed: &LosslessParseResult<ZeekDnsRecord>,
    config: &FlowProducerConfig,
    correlation: Option<&FlowCorrelationIndex>,
) -> DnsProductionResult {
    let mut result = produce_dns_observations(&parsed.records, config, correlation);
    let mut diagnostics = parsed.diagnostics.clone();
    diagnostics.append(&mut result.diagnostics);
    result.diagnostics = diagnostics;
    result
}
