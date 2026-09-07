use crate::zeek_parser::header::{field_cell, parse_header, split_log_rows, ZeekCell, ZeekHeader};
use crate::zeek_parser::source_types::{
    is_plain_decimal, DiagnosticKind, LosslessParseResult, SourceCode, SourceDiagnostic, SourceIp,
    SourceValue, ZeekDnsRecord, ZeekLogType,
};
use crate::zeek_parser::types::{DetectorDnsRecord, DnsRecord};

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
                    ZeekLogType::Dns,
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
                ZeekLogType::Dns,
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
                    ZeekLogType::Dns,
                    row_ordinal,
                    field,
                    DiagnosticKind::OutOfRangeValue,
                    Some(raw.clone()),
                    format!("field {field} is outside the approved range 0..={max}"),
                ));
                SourceValue::Invalid(raw)
            }
            Err(_) => {
                diagnostics.push(SourceDiagnostic::for_row(
                    ZeekLogType::Dns,
                    row_ordinal,
                    field,
                    malformed_kind,
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

fn source_code_u16(
    cols: &[&str],
    header: &ZeekHeader,
    field: &str,
    row_ordinal: u64,
    max: u64,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> SourceValue<SourceCode<u16>> {
    match source_string(cols, header, field, row_ordinal, false, diagnostics) {
        SourceValue::Value(raw) => match raw.parse::<u64>() {
            Ok(value) if value <= max => SourceValue::Value(SourceCode {
                raw,
                value: value as u16,
            }),
            Ok(_) => {
                diagnostics.push(SourceDiagnostic::for_row(
                    ZeekLogType::Dns,
                    row_ordinal,
                    field,
                    DiagnosticKind::OutOfRangeValue,
                    Some(raw.clone()),
                    format!("field {field} is outside the approved range 0..={max}"),
                ));
                SourceValue::Invalid(raw)
            }
            Err(_) => {
                diagnostics.push(SourceDiagnostic::for_row(
                    ZeekLogType::Dns,
                    row_ordinal,
                    field,
                    DiagnosticKind::MalformedInteger,
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

fn source_code_u8(
    cols: &[&str],
    header: &ZeekHeader,
    field: &str,
    row_ordinal: u64,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> SourceValue<SourceCode<u8>> {
    match source_string(cols, header, field, row_ordinal, false, diagnostics) {
        SourceValue::Value(raw) => match raw.parse::<u64>() {
            Ok(value) if value <= u8::MAX as u64 => SourceValue::Value(SourceCode {
                raw,
                value: value as u8,
            }),
            Ok(_) => {
                diagnostics.push(SourceDiagnostic::for_row(
                    ZeekLogType::Dns,
                    row_ordinal,
                    field,
                    DiagnosticKind::OutOfRangeValue,
                    Some(raw.clone()),
                    "field Z is outside the approved range 0..=255",
                ));
                SourceValue::Invalid(raw)
            }
            Err(_) => {
                diagnostics.push(SourceDiagnostic::for_row(
                    ZeekLogType::Dns,
                    row_ordinal,
                    field,
                    DiagnosticKind::MalformedInteger,
                    Some(raw.clone()),
                    "field Z is not a valid nonnegative integer",
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
                    ZeekLogType::Dns,
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

fn source_boolean(
    cols: &[&str],
    header: &ZeekHeader,
    field: &str,
    row_ordinal: u64,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> SourceValue<bool> {
    match source_string(cols, header, field, row_ordinal, false, diagnostics) {
        SourceValue::Value(raw) if raw == "T" => SourceValue::Value(true),
        SourceValue::Value(raw) if raw == "F" => SourceValue::Value(false),
        SourceValue::Value(raw) => {
            diagnostics.push(SourceDiagnostic::for_row(
                ZeekLogType::Dns,
                row_ordinal,
                field,
                DiagnosticKind::MalformedBoolean,
                Some(raw.clone()),
                format!("field {field} must be the Zeek boolean T or F"),
            ));
            SourceValue::Invalid(raw)
        }
        SourceValue::Invalid(raw) => SourceValue::Invalid(raw),
        SourceValue::Missing => SourceValue::Missing,
        SourceValue::Unset => SourceValue::Unset,
        SourceValue::Empty => SourceValue::Empty,
    }
}

fn answer_count(
    answers: &SourceValue<String>,
    set_separator: &str,
    row_ordinal: u64,
    diagnostics: &mut Vec<SourceDiagnostic>,
) -> SourceValue<u16> {
    match answers {
        SourceValue::Missing => SourceValue::Missing,
        SourceValue::Unset => SourceValue::Unset,
        SourceValue::Empty => SourceValue::Value(0),
        SourceValue::Invalid(raw) => SourceValue::Invalid(raw.clone()),
        SourceValue::Value(raw) if raw.is_empty() => SourceValue::Value(0),
        SourceValue::Value(raw) => {
            if set_separator.is_empty() || raw.split(set_separator).any(str::is_empty) {
                diagnostics.push(SourceDiagnostic::for_row(
                    ZeekLogType::Dns,
                    row_ordinal,
                    "answers",
                    DiagnosticKind::InvalidAnswersEncoding,
                    None,
                    "answers is not a defensibly encoded Zeek vector",
                ));
                return SourceValue::Invalid(raw.clone());
            }
            let count = raw.split(set_separator).count();
            match u16::try_from(count) {
                Ok(count) => SourceValue::Value(count),
                Err(_) => {
                    diagnostics.push(SourceDiagnostic::for_row(
                        ZeekLogType::Dns,
                        row_ordinal,
                        "answers",
                        DiagnosticKind::OutOfRangeValue,
                        None,
                        "answers contains more than 65535 elements",
                    ));
                    SourceValue::Invalid(raw.clone())
                }
            }
        }
    }
}

/// Parse dns.log without collapsing absence, invalid values, or row identity.
pub fn parse_dns_log_lossless(content: &str) -> Result<LosslessParseResult<ZeekDnsRecord>, String> {
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
                ZeekLogType::Dns,
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

        let uid = source_string(&cols, &header, "uid", row.ordinal, false, &mut diagnostics);
        let timestamp_raw = source_decimal(
            &cols,
            &header,
            "ts",
            row.ordinal,
            true,
            DiagnosticKind::MalformedDecimalTimestamp,
            &mut diagnostics,
        );
        let answers_raw = source_string(
            &cols,
            &header,
            "answers",
            row.ordinal,
            false,
            &mut diagnostics,
        );
        let parsed_answer_count = answer_count(
            &answers_raw,
            &header.set_separator,
            row.ordinal,
            &mut diagnostics,
        );

        let record = ZeekDnsRecord {
            row_ordinal: row.ordinal,
            row_too_short_for_legacy,
            uid,
            timestamp_raw,
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
            transaction_id: source_code_u16(
                &cols,
                &header,
                "trans_id",
                row.ordinal,
                u16::MAX as u64,
                &mut diagnostics,
            ),
            rtt_raw: source_decimal(
                &cols,
                &header,
                "rtt",
                row.ordinal,
                false,
                DiagnosticKind::MalformedDuration,
                &mut diagnostics,
            ),
            query: source_string(
                &cols,
                &header,
                "query",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            qclass: source_code_u16(
                &cols,
                &header,
                "qclass",
                row.ordinal,
                u16::MAX as u64,
                &mut diagnostics,
            ),
            qclass_name: source_string(
                &cols,
                &header,
                "qclass_name",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            qtype: source_code_u16(
                &cols,
                &header,
                "qtype",
                row.ordinal,
                u16::MAX as u64,
                &mut diagnostics,
            ),
            qtype_name: source_string(
                &cols,
                &header,
                "qtype_name",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            rcode: source_code_u16(&cols, &header, "rcode", row.ordinal, 4095, &mut diagnostics),
            rcode_name: source_string(
                &cols,
                &header,
                "rcode_name",
                row.ordinal,
                false,
                &mut diagnostics,
            ),
            authoritative_answer: source_boolean(
                &cols,
                &header,
                "AA",
                row.ordinal,
                &mut diagnostics,
            ),
            truncated: source_boolean(&cols, &header, "TC", row.ordinal, &mut diagnostics),
            recursion_desired: source_boolean(&cols, &header, "RD", row.ordinal, &mut diagnostics),
            recursion_available: source_boolean(
                &cols,
                &header,
                "RA",
                row.ordinal,
                &mut diagnostics,
            ),
            z: source_code_u8(&cols, &header, "Z", row.ordinal, &mut diagnostics),
            answers_raw,
            answer_count: parsed_answer_count,
            ttls_raw: source_string(&cols, &header, "TTLs", row.ordinal, false, &mut diagnostics),
            rejected: source_boolean(&cols, &header, "rejected", row.ordinal, &mut diagnostics),
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

fn legacy_code<T>(value: &SourceValue<SourceCode<T>>) -> String {
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

fn detector_string(value: &SourceValue<String>) -> Option<String> {
    value.as_value().cloned()
}

fn detector_f64(value: &SourceValue<String>) -> Option<f64> {
    value.as_value().and_then(|raw| raw.parse::<f64>().ok())
}

fn detector_ip(value: &SourceValue<SourceIp>) -> Option<String> {
    value.as_value().map(|address| address.raw.clone())
}

impl From<&ZeekDnsRecord> for DnsRecord {
    fn from(record: &ZeekDnsRecord) -> Self {
        Self {
            uid: legacy_string(&record.uid),
            timestamp: legacy_f64(&record.timestamp_raw),
            query: legacy_string(&record.query),
            qtype: legacy_code(&record.qtype),
            rcode: legacy_code(&record.rcode),
        }
    }
}

/// Legacy parser API retained for Python and existing feature extraction.
pub fn parse_dns_log(content: &str) -> Result<Vec<DnsRecord>, String> {
    let parsed = parse_dns_log_lossless(content)?;
    Ok(parsed
        .records
        .iter()
        .filter(|record| !record.row_too_short_for_legacy)
        .map(DnsRecord::from)
        .collect())
}

/// Detector-v2 parser API retaining every physical row and approved source fact.
pub fn parse_dns_log_detector(content: &str) -> Result<Vec<DetectorDnsRecord>, String> {
    let parsed = parse_dns_log_lossless(content)?;
    Ok(parsed
        .records
        .iter()
        .map(|record| DetectorDnsRecord {
            legacy: DnsRecord::from(record),
            source_ordinal: record.row_ordinal,
            event_time: detector_f64(&record.timestamp_raw),
            src_ip: detector_ip(&record.src_ip),
            src_port: record.src_port.copied(),
            dst_ip: detector_ip(&record.dst_ip),
            dst_port: record.dst_port.copied(),
            proto: detector_string(&record.proto),
            qtype_name: detector_string(&record.qtype_name),
            rcode_name: detector_string(&record.rcode_name),
            authoritative_answer: record.authoritative_answer.copied(),
            truncated: record.truncated.copied(),
            recursion_desired: record.recursion_desired.copied(),
            recursion_available: record.recursion_available.copied(),
            z: match &record.z {
                SourceValue::Value(value) => Some(value.value),
                _ => None,
            },
            answer_count: record.answer_count.copied(),
            rejected: record.rejected.copied(),
        })
        .collect())
}
