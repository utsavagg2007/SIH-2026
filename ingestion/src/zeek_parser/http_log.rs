use crate::zeek_parser::header::{field_cell, parse_header, split_log_rows, ZeekCell, ZeekHeader};
use crate::zeek_parser::source_types::{
    is_plain_decimal, DiagnosticKind, LosslessParseResult, SourceDiagnostic, SourceIp, SourceValue,
    ZeekHttpRecord, ZeekLogType,
};
use crate::zeek_parser::types::HttpRecord;

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
                    ZeekLogType::Http,
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
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> SourceValue<String> {
    match source_string(cols, header, field, row_ordinal, true, diagnostics) {
        SourceValue::Value(raw) if is_plain_decimal(&raw) => SourceValue::Value(raw),
        SourceValue::Value(raw) => {
            diagnostics.push(SourceDiagnostic::for_row(
                ZeekLogType::Http,
                row_ordinal,
                field,
                DiagnosticKind::MalformedDecimalTimestamp,
                Some(raw.clone()),
                format!("field {field} is not a plain decimal"),
            ));
            SourceValue::Invalid(raw)
        }
        other => other,
    }
}

fn source_unsigned<T>(
    cols: &[&str],
    header: &ZeekHeader,
    field: &str,
    row_ordinal: u64,
    max: u64,
    malformed_kind: DiagnosticKind,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> SourceValue<T>
where
    T: TryFrom<u64>,
{
    match source_string(cols, header, field, row_ordinal, false, diagnostics) {
        SourceValue::Value(raw) => match raw.parse::<u64>() {
            Ok(value) if value <= max => match T::try_from(value) {
                Ok(value) => SourceValue::Value(value),
                Err(_) => unreachable!("validated unsigned value must fit target type"),
            },
            Ok(_) => {
                diagnostics.push(SourceDiagnostic::for_row(
                    ZeekLogType::Http,
                    row_ordinal,
                    field,
                    DiagnosticKind::OutOfRangeValue,
                    Some(raw.clone()),
                    format!("field {field} is outside the approved range 0..={max}"),
                ));
                SourceValue::Invalid(raw)
            }
            Err(_) => {
                let overflow = !raw.is_empty() && raw.bytes().all(|byte| byte.is_ascii_digit());
                let kind = if overflow {
                    DiagnosticKind::OutOfRangeValue
                } else {
                    malformed_kind
                };
                diagnostics.push(SourceDiagnostic::for_row(
                    ZeekLogType::Http,
                    row_ordinal,
                    field,
                    kind,
                    Some(raw.clone()),
                    if overflow {
                        format!("field {field} exceeds the supported unsigned integer range")
                    } else {
                        format!("field {field} is not a valid nonnegative integer")
                    },
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
            Ok(parsed) => SourceValue::Value(SourceIp { raw, parsed }),
            Err(_) => {
                diagnostics.push(SourceDiagnostic::for_row(
                    ZeekLogType::Http,
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

/// Parse http.log without collapsing source absence, invalid values, or row identity.
pub fn parse_http_log_lossless(
    content: &str,
) -> Result<LosslessParseResult<ZeekHttpRecord>, String> {
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
                ZeekLogType::Http,
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

        let record = ZeekHttpRecord {
            row_ordinal: row.ordinal,
            row_too_short_for_legacy,
            uid: source_string(&cols, &header, "uid", row.ordinal, false, &mut diagnostics),
            timestamp_raw: source_decimal(&cols, &header, "ts", row.ordinal, &mut diagnostics),
            src_ip: source_ip(&cols, &header, "id.orig_h", row.ordinal, &mut diagnostics),
            src_port: source_unsigned(
                &cols,
                &header,
                "id.orig_p",
                row.ordinal,
                u16::MAX as u64,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            dst_ip: source_ip(&cols, &header, "id.resp_h", row.ordinal, &mut diagnostics),
            dst_port: source_unsigned(
                &cols,
                &header,
                "id.resp_p",
                row.ordinal,
                u16::MAX as u64,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            proto: source_string(
                &cols,
                &header,
                "proto",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            ip_proto: source_unsigned(
                &cols,
                &header,
                "ip_proto",
                row.ordinal,
                u8::MAX as u64,
                DiagnosticKind::InvalidProtocolField,
                &mut diagnostics,
            ),
            trans_depth: source_unsigned(
                &cols,
                &header,
                "trans_depth",
                row.ordinal,
                u64::MAX,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            method: source_string(
                &cols,
                &header,
                "method",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            host: source_string(&cols, &header, "host", row.ordinal, false, &mut diagnostics),
            uri: source_string(&cols, &header, "uri", row.ordinal, false, &mut diagnostics),
            user_agent: source_string(
                &cols,
                &header,
                "user_agent",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            status_code: source_unsigned(
                &cols,
                &header,
                "status_code",
                row.ordinal,
                u16::MAX as u64,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            request_body_len: source_unsigned(
                &cols,
                &header,
                "request_body_len",
                row.ordinal,
                u64::MAX,
                DiagnosticKind::MalformedInteger,
                &mut diagnostics,
            ),
            response_body_len: source_unsigned(
                &cols,
                &header,
                "response_body_len",
                row.ordinal,
                u64::MAX,
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

fn legacy_f64(value: &SourceValue<String>) -> f64 {
    match value {
        SourceValue::Value(raw) | SourceValue::Invalid(raw) => raw.parse::<f64>().unwrap_or(0.0),
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => 0.0,
    }
}

fn legacy_u64(value: &SourceValue<u64>) -> u64 {
    match value {
        SourceValue::Value(value) => *value,
        SourceValue::Invalid(raw) => raw.parse::<u64>().unwrap_or(0),
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => 0,
    }
}

fn legacy_u16(value: &SourceValue<u16>) -> u16 {
    match value {
        SourceValue::Value(value) => *value,
        SourceValue::Invalid(raw) => raw.parse::<u16>().unwrap_or(0),
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => 0,
    }
}

impl From<&ZeekHttpRecord> for HttpRecord {
    fn from(record: &ZeekHttpRecord) -> Self {
        Self {
            uid: legacy_string(&record.uid),
            timestamp: legacy_f64(&record.timestamp_raw),
            method: legacy_string(&record.method),
            host: legacy_string(&record.host),
            uri: legacy_string(&record.uri),
            user_agent: legacy_string(&record.user_agent),
            request_body_len: legacy_u64(&record.request_body_len),
            response_body_len: legacy_u64(&record.response_body_len),
            status_code: legacy_u16(&record.status_code),
        }
    }
}

/// Legacy parser API retained for Python and existing feature extraction.
pub fn parse_http_log(content: &str) -> Result<Vec<HttpRecord>, String> {
    let parsed = parse_http_log_lossless(content)?;
    Ok(parsed
        .records
        .iter()
        .filter(|record| !record.row_too_short_for_legacy)
        .map(HttpRecord::from)
        .collect())
}
