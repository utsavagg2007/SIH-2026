use crate::zeek_parser::header::{field_cell, parse_header, split_log_rows, ZeekCell, ZeekHeader};
use crate::zeek_parser::source_types::{
    is_plain_decimal, DiagnosticKind, LosslessParseResult, SourceDiagnostic, SourceIp, SourceValue,
    ZeekLogType, ZeekTlsRecord,
};
use crate::zeek_parser::types::{DetectorSslRecord, SslRecord};

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
                    ZeekLogType::Ssl,
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
                ZeekLogType::Ssl,
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
                    ZeekLogType::Ssl,
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
                    ZeekLogType::Ssl,
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
                    ZeekLogType::Ssl,
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

/// Parse ssl.log without collapsing source absence, invalid values, or row identity.
pub fn parse_ssl_log_lossless(content: &str) -> Result<LosslessParseResult<ZeekTlsRecord>, String> {
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
                ZeekLogType::Ssl,
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

        let record = ZeekTlsRecord {
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
            version: source_string(
                &cols,
                &header,
                "version",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            cipher: source_string(
                &cols,
                &header,
                "cipher",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            server_name: source_string(
                &cols,
                &header,
                "server_name",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            ja3: source_string(&cols, &header, "ja3", row.ordinal, false, &mut diagnostics),
            ja3s: source_string(&cols, &header, "ja3s", row.ordinal, false, &mut diagnostics),
            ja4: source_string(&cols, &header, "ja4", row.ordinal, false, &mut diagnostics),
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

fn legacy_optional_string(value: &SourceValue<String>) -> Option<String> {
    match value {
        SourceValue::Value(value) | SourceValue::Invalid(value) => Some(value.clone()),
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => None,
    }
}

fn legacy_f64(value: &SourceValue<String>) -> f64 {
    match value {
        SourceValue::Value(raw) | SourceValue::Invalid(raw) => raw.parse::<f64>().unwrap_or(0.0),
        SourceValue::Missing | SourceValue::Unset | SourceValue::Empty => 0.0,
    }
}

impl From<&ZeekTlsRecord> for SslRecord {
    fn from(record: &ZeekTlsRecord) -> Self {
        Self {
            uid: legacy_string(&record.uid),
            timestamp: legacy_f64(&record.timestamp_raw),
            version: legacy_string(&record.version),
            cipher: legacy_string(&record.cipher),
            ja3: legacy_optional_string(&record.ja3),
            ja3s: legacy_optional_string(&record.ja3s),
            server_name: legacy_string(&record.server_name),
        }
    }
}

/// Legacy parser API retained for Python and existing feature extraction.
pub fn parse_ssl_log(content: &str) -> Result<Vec<SslRecord>, String> {
    let parsed = parse_ssl_log_lossless(content)?;
    Ok(parsed
        .records
        .iter()
        .filter(|record| !record.row_too_short_for_legacy)
        .map(SslRecord::from)
        .collect())
}

/// Detector-v2 parser API retaining source JA4 without changing SslRecord.
pub fn parse_ssl_log_detector(content: &str) -> Result<Vec<DetectorSslRecord>, String> {
    let parsed = parse_ssl_log_lossless(content)?;
    Ok(parsed
        .records
        .iter()
        .filter(|record| !record.row_too_short_for_legacy)
        .map(|record| DetectorSslRecord {
            legacy: SslRecord::from(record),
            ja4: legacy_optional_string(&record.ja4),
        })
        .collect())
}
