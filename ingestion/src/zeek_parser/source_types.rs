use std::net::IpAddr;

/// A typed Zeek field that keeps source absence and parse failure distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceValue<T> {
    /// The field was not present in the header or the physical row was short.
    Missing,
    /// The field contained the log's configured `#unset_field` marker.
    Unset,
    /// The field contained the log's configured `#empty_field` marker.
    Empty,
    /// The source text was present but was not valid for the requested type.
    Invalid(String),
    /// A valid source-reported value. For strings, this may be an actual empty string.
    Value(T),
}

impl<T> SourceValue<T> {
    pub fn as_value(&self) -> Option<&T> {
        match self {
            Self::Value(value) => Some(value),
            _ => None,
        }
    }
}

impl<T: Copy> SourceValue<T> {
    pub fn copied(&self) -> Option<T> {
        self.as_value().copied()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticKind {
    MissingColumn,
    ExtraColumn,
    MalformedInteger,
    MalformedDecimalTimestamp,
    MalformedDuration,
    InvalidIp,
    InvalidProtocolField,
    ConflictingProtocolFields,
    MissingRequiredField,
    MissingRequiredCounters,
    NegativeDuration,
    MalformedBoolean,
    InvalidAnswersEncoding,
    OutOfRangeValue,
    AmbiguousFlowLink,
    InconsistentFlowLink,
    MissingRequiredProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeekLogType {
    Conn,
    Dns,
    Ssl,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDiagnostic {
    pub log_type: ZeekLogType,
    pub source_record_id: Option<String>,
    pub row_ordinal: Option<u64>,
    pub field: Option<String>,
    pub kind: DiagnosticKind,
    pub raw_value: Option<String>,
    pub message: String,
}

impl SourceDiagnostic {
    pub fn for_row(
        log_type: ZeekLogType,
        row_ordinal: u64,
        field: impl Into<String>,
        kind: DiagnosticKind,
        raw_value: Option<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            log_type,
            source_record_id: None,
            row_ordinal: Some(row_ordinal),
            field: Some(field.into()),
            kind,
            raw_value,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LosslessParseResult<T> {
    pub records: Vec<T>,
    pub diagnostics: Vec<SourceDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceIp {
    pub raw: String,
    pub parsed: IpAddr,
}

/// A parsed source code together with its original lexical representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCode<T> {
    pub raw: String,
    pub value: T,
}

/// Lossless source representation of one physical conn.log data row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeekConnRecord {
    pub row_ordinal: u64,
    pub row_too_short_for_legacy: bool,
    pub uid: SourceValue<String>,
    pub timestamp_raw: SourceValue<String>,
    pub duration_raw: SourceValue<String>,
    pub src_ip: SourceValue<SourceIp>,
    pub src_port: SourceValue<u16>,
    pub dst_ip: SourceValue<SourceIp>,
    pub dst_port: SourceValue<u16>,
    pub proto: SourceValue<String>,
    pub ip_proto: SourceValue<u8>,
    pub service: SourceValue<String>,
    pub connection_state: SourceValue<String>,
    pub connection_history: SourceValue<String>,
    pub orig_packets: SourceValue<u64>,
    pub resp_packets: SourceValue<u64>,
    pub orig_payload_bytes: SourceValue<u64>,
    pub resp_payload_bytes: SourceValue<u64>,
    pub orig_ip_bytes: SourceValue<u64>,
    pub resp_ip_bytes: SourceValue<u64>,
    pub missed_bytes: SourceValue<u64>,
}

/// Lossless source representation of one physical dns.log data row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeekDnsRecord {
    pub row_ordinal: u64,
    pub row_too_short_for_legacy: bool,
    pub uid: SourceValue<String>,
    pub timestamp_raw: SourceValue<String>,
    pub src_ip: SourceValue<SourceIp>,
    pub src_port: SourceValue<u16>,
    pub dst_ip: SourceValue<SourceIp>,
    pub dst_port: SourceValue<u16>,
    pub proto: SourceValue<String>,
    pub ip_proto: SourceValue<u8>,
    pub transaction_id: SourceValue<SourceCode<u16>>,
    pub rtt_raw: SourceValue<String>,
    pub query: SourceValue<String>,
    pub qclass: SourceValue<SourceCode<u16>>,
    pub qclass_name: SourceValue<String>,
    pub qtype: SourceValue<SourceCode<u16>>,
    pub qtype_name: SourceValue<String>,
    pub rcode: SourceValue<SourceCode<u16>>,
    pub rcode_name: SourceValue<String>,
    pub authoritative_answer: SourceValue<bool>,
    pub truncated: SourceValue<bool>,
    pub recursion_desired: SourceValue<bool>,
    pub recursion_available: SourceValue<bool>,
    pub z: SourceValue<SourceCode<u8>>,
    pub answers_raw: SourceValue<String>,
    pub answer_count: SourceValue<u16>,
    pub ttls_raw: SourceValue<String>,
    pub rejected: SourceValue<bool>,
}

/// Lossless source representation of one physical ssl.log data row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeekTlsRecord {
    pub row_ordinal: u64,
    pub row_too_short_for_legacy: bool,
    pub uid: SourceValue<String>,
    pub timestamp_raw: SourceValue<String>,
    pub src_ip: SourceValue<SourceIp>,
    pub src_port: SourceValue<u16>,
    pub dst_ip: SourceValue<SourceIp>,
    pub dst_port: SourceValue<u16>,
    pub proto: SourceValue<String>,
    pub ip_proto: SourceValue<u8>,
    pub version: SourceValue<String>,
    pub cipher: SourceValue<String>,
    pub server_name: SourceValue<String>,
    pub ja3: SourceValue<String>,
    pub ja3s: SourceValue<String>,
    pub ja4: SourceValue<String>,
}

/// Lossless source representation of one physical http.log data row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeekHttpRecord {
    pub row_ordinal: u64,
    pub row_too_short_for_legacy: bool,
    pub uid: SourceValue<String>,
    pub timestamp_raw: SourceValue<String>,
    pub src_ip: SourceValue<SourceIp>,
    pub src_port: SourceValue<u16>,
    pub dst_ip: SourceValue<SourceIp>,
    pub dst_port: SourceValue<u16>,
    pub proto: SourceValue<String>,
    pub ip_proto: SourceValue<u8>,
    pub trans_depth: SourceValue<u64>,
    pub method: SourceValue<String>,
    pub host: SourceValue<String>,
    pub uri: SourceValue<String>,
    pub user_agent: SourceValue<String>,
    pub status_code: SourceValue<u16>,
    pub request_body_len: SourceValue<u64>,
    pub response_body_len: SourceValue<u64>,
}

/// Validate the lexical form of a non-exponent decimal while retaining its text.
pub fn is_plain_decimal(raw: &str) -> bool {
    let unsigned = raw
        .strip_prefix('-')
        .or_else(|| raw.strip_prefix('+'))
        .unwrap_or(raw);
    if unsigned.is_empty() {
        return false;
    }

    let mut parts = unsigned.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some() || whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }

    match fraction {
        Some(value) => !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
        None => true,
    }
}
