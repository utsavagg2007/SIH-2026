use crate::zeek_parser::header::{field_cell, parse_header, split_log_rows, ZeekCell, ZeekHeader};
use crate::zeek_parser::source_types::{
    is_plain_decimal, DiagnosticKind, LosslessParseResult, SourceDiagnostic, SourceIp, SourceValue,
    ZeekConnRecord, ZeekLogType,
};
use crate::zeek_parser::types::FlowRecord;

fn source_string(
    cols: &[&str],
    header: &ZeekHeader,
    field: &str,
    row_ordinal: u64,
    required: bool,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> SourceValue<String> {
    match field_cell(cols, header, field) {
        ZeekCell::Missing => {
            if required || header.field_index.contains_key(field) {
                diagnostics.push(SourceDiagnostic::for_row(
                    ZeekLogType::Conn,
                    row_ordinal,
                    field,
                    DiagnosticKind::MissingColumn,
                    None,
                    format!("field {field} is missing from this source row"),
                ));
            }
            SourceValue::Missing
        }
        ZeekCell::Unset => SourceValue::Unset,
        ZeekCell::Empty => SourceValue::Empty,
        ZeekCell::Value(value) => SourceValue::Value(value.to_string()),
    }
}

fn source_decimal(
    cols: &[&str],
    header: &ZeekHeader,
    field: &str,
    row_ordinal: u64,
    required: bool,
    kind: DiagnosticKind,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> SourceValue<String> {
    match source_string(cols, header, field, row_ordinal, required, diagnostics) {
        SourceValue::Value(raw) if is_plain_decimal(&raw) => SourceValue::Value(raw),
        SourceValue::Value(raw) => {
            diagnostics.push(SourceDiagnostic::for_row(
                ZeekLogType::Conn,
                row_ordinal,
                field,
                kind,
                Some(raw.clone()),
                format!("field {field} is not a plain decimal"),
            ));
            SourceValue::Invalid(raw)
        }
        SourceValue::Invalid(raw) => SourceValue::Invalid(raw),
        SourceValue::Missing => SourceValue::Missing,
        SourceValue::Unset => SourceValue::Unset,
        SourceValue::Empty => SourceValue::Empty,
    }
}

fn source_integer<T>(
    cols: &[&str],
    header: &ZeekHeader,
    field: &str,
    row_ordinal: u64,
    required: bool,
    kind: DiagnosticKind,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> SourceValue<T>
where
    T: std::str::FromStr,
{
    match source_string(cols, header, field, row_ordinal, required, diagnostics) {
        SourceValue::Value(raw) => match raw.parse::<T>() {
            Ok(value) => SourceValue::Value(value),
            Err(_) => {
                diagnostics.push(SourceDiagnostic::for_row(
                    ZeekLogType::Conn,
                    row_ordinal,
                    field,
                    kind,
                    Some(raw.clone()),
                    format!("field {field} is not a valid nonnegative integer"),
                ));
                SourceValue::Invalid(raw)
            }
        },
        SourceValue::Invalid(raw) => SourceValue::Invalid(raw),
        SourceValue::Missing => SourceValue::Missing,
        SourceValue::Unset => SourceValue::Unset,
        SourceValue::Empty => SourceValue::Empty,
    }
}

fn source_ip(
    cols: &[&str],
    header: &ZeekHeader,
    field: &str,
    row_ordinal: u64,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> SourceValue<SourceIp> {
    match source_string(cols, header, field, row_ordinal, true, diagnostics) {
        SourceValue::Value(raw) => match raw.parse() {
            Ok(value) => SourceValue::Value(SourceIp { raw, parsed: value }),
            Err(_) => {
                diagnostics.push(SourceDiagnostic::for_row(
                    ZeekLogType::Conn,
                    row_ordinal,
                    field,
                    DiagnosticKind::InvalidIp,
                    Some(raw.clone()),
                    format!("field {field} is not a valid IPv4 or IPv6 address"),
                ));
                SourceValue::Invalid(raw)
            }
        },
        SourceValue::Invalid(raw) => SourceValue::Invalid(raw),
        SourceValue::Missing => SourceValue::Missing,
        SourceValue::Unset => SourceValue::Unset,
        SourceValue::Empty => SourceValue::Empty,
    }
}

/// Parse conn.log without collapsing absence, invalid values, or row identity.
pub fn parse_conn_log_lossless(
    content: &str,
) -> Result<LosslessParseResult<ZeekConnRecord>, String> {
    let (header_lines, data_rows) = split_log_rows(content);
    let header = parse_header(&header_lines)?;
    let expected_columns = header.field_index.len();
    let mut diagnostics = Vec::new();
    let mut records = Vec::with_capacity(data_rows.len());

    for row in data_rows {
        let diagnostic_start = diagnostics.len();
        let cols: Vec<&str> = row.line.split('\t').collect();
        let row_too_short_for_legacy = cols.len() < expected_columns;
        if cols.len() > expected_columns {
            diagnostics.push(SourceDiagnostic::for_row(
                ZeekLogType::Conn,
                row.ordinal,
                "<row>",
                DiagnosticKind::ExtraColumn,
                None,
                format!(
                    "row has {} columns but the header declares {expected_columns}",
                    cols.len()
                ),
            ));
        }

        let record = ZeekConnRecord {
            row_ordinal: row.ordinal,
            row_too_short_for_legacy,
            uid: source_string(&cols, &header, "uid", row.ordinal, true, &mut diagnostics),
            timestamp_raw: source_decimal(
                &cols,
                &header,
                "ts",
                row.ordinal,
                true,
                DiagnosticKind::MalformedDecimalTimestamp,
                &mut diagnostics,
            ),
            duration_raw: source_decimal(
                &cols,
                &header,
                "duration",
                row.ordinal,
                false,
                DiagnosticKind::MalformedDuration,
                &mut diagnostics,
            ),
            src_ip: source_ip(&cols, &header, "id.orig_h", row.ordinal, &mut diagnostics),
            src_port: source_integer(
                &cols,
                &header,
                "id.orig_p",
                row.ordinal,
                false,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            dst_ip: source_ip(&cols, &header, "id.resp_h", row.ordinal, &mut diagnostics),
            dst_port: source_integer(
                &cols,
                &header,
                "id.resp_p",
                row.ordinal,
                false,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            proto: source_string(&cols, &header, "proto", row.ordinal, true, &mut diagnostics),
            ip_proto: source_integer(
                &cols,
                &header,
                "ip_proto",
                row.ordinal,
                false,
                DiagnosticKind::InvalidProtocolField,
                &mut diagnostics,
            ),
            service: source_string(
                &cols,
                &header,
                "service",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            connection_state: source_string(
                &cols,
                &header,
                "conn_state",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            connection_history: source_string(
                &cols,
                &header,
                "history",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            orig_packets: source_integer(
                &cols,
                &header,
                "orig_pkts",
                row.ordinal,
                false,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            resp_packets: source_integer(
                &cols,
                &header,
                "resp_pkts",
                row.ordinal,
                false,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            orig_payload_bytes: source_integer(
                &cols,
                &header,
                "orig_bytes",
                row.ordinal,
                false,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            resp_payload_bytes: source_integer(
                &cols,
                &header,
                "resp_bytes",
                row.ordinal,
                false,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            orig_ip_bytes: source_integer(
                &cols,
                &header,
                "orig_ip_bytes",
                row.ordinal,
                false,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            resp_ip_bytes: source_integer(
                &cols,
                &header,
                "resp_ip_bytes",
                row.ordinal,
                false,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            missed_bytes: source_integer(
                &cols,
                &header,
                "missed_bytes",
                row.ordinal,
                false,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
        };
        let source_record_id = match &record.uid {
            SourceValue::Value(uid) if !uid.is_empty() => Some(uid.clone()),
            _ => None,
        };
        for diagnostic in &mut diagnostics[diagnostic_start..] {
            diagnostic.source_record_id.clone_from(&source_record_id);
        }
        records.push(record);
    }

    Ok(LosslessParseResult {
        records,
        diagnostics,
    })
}

fn legacy_string(value: &SourceValue<String>) -> String {
    match value {
        SourceValue::Value(value) | SourceValue::Invalid(value) => value.clone(),
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => String::new(),
    }
}

fn legacy_ip(value: &SourceValue<SourceIp>) -> String {
    match value {
        SourceValue::Value(value) => value.raw.clone(),
        SourceValue::Invalid(raw) => raw.clone(),
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => String::new(),
    }
}

fn legacy_f64(value: &SourceValue<String>) -> f64 {
    match value {
        SourceValue::Value(raw) | SourceValue::Invalid(raw) => raw.parse::<f64>().unwrap_or(0.0),
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => 0.0,
    }
}

impl From<&ZeekConnRecord> for FlowRecord {
    fn from(record: &ZeekConnRecord) -> Self {
        Self {
            uid: legacy_string(&record.uid),
            timestamp: legacy_f64(&record.timestamp_raw),
            src_ip: legacy_ip(&record.src_ip),
            src_port: record.src_port.copied().unwrap_or(0),
            dst_ip: legacy_ip(&record.dst_ip),
            dst_port: record.dst_port.copied().unwrap_or(0),
            proto: legacy_string(&record.proto),
            service: legacy_string(&record.service),
            duration: legacy_f64(&record.duration_raw),
            orig_bytes: record.orig_payload_bytes.copied().unwrap_or(0),
            resp_bytes: record.resp_payload_bytes.copied().unwrap_or(0),
            conn_state: legacy_string(&record.connection_state),
            orig_pkts: record.orig_packets.copied().unwrap_or(0),
            resp_pkts: record.resp_packets.copied().unwrap_or(0),
            orig_ip_bytes: record.orig_ip_bytes.copied().unwrap_or(0),
            resp_ip_bytes: record.resp_ip_bytes.copied().unwrap_or(0),
        }
    }
}

/// Legacy parser API retained for Python and existing feature extraction.
pub fn parse_conn_log(content: &str) -> Result<Vec<FlowRecord>, String> {
    let parsed = parse_conn_log_lossless(content)?;
    Ok(parsed
        .records
        .iter()
        .filter(|record| !record.row_too_short_for_legacy)
        .map(FlowRecord::from)
        .collect())
}
