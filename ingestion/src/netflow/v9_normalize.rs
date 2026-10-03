//! F7's bounded, stateless semantic boundary over immutable F6 output.
//!
//! No framing, registry lookup, sampler association, counter scaling, sequence
//! continuity, or collector/session management lives here. The caller must bind
//! artifact identity and act on the returned F6 reset obligation.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::template::{TemplateKind, TemplateProtocol};
use super::v9::{
    CountValidation, DataFlowSetState, FieldRole, FieldValueView, FlowSetContent,
    NetFlowV9Diagnostic, NetFlowV9Header, NetFlowV9ParseContext, NetFlowV9ParseOutcome,
    ParseCompletion, RecordView, SessionDisposition, TemplateSnapshot,
};
use crate::canonical::id::{
    generate_netflow_v9_record_id, generate_netflow_v9_session_fingerprint, normalize_sha256,
    NetFlowV9IdentityCoordinates,
};
use crate::canonical::time::{unix_nanoseconds_to_rfc3339, validate_canonical_utc};
use crate::canonical::{
    CanonicalData, CanonicalObservation, DirectionCounters, DirectionMode, Fidelity, FlowCounters,
    FlowData, InputMode, ObservationType, Provenance, Quality, TcpFlag, TelemetrySource,
};

pub const DEFAULT_MAX_FLOW_AGE_MS: u64 = 86_400_000;
pub const MAX_FLOW_AGE_MS: u64 = (1_u64 << 31) - 1;
pub const MAX_IDENTITY_BYTES: usize = 256;
pub const MAX_SOURCE_RECORD_ID_BYTES: usize = 512;
pub const PARSER_NAME: &str = "sih-ingestion-core-netflow-v9";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetFlowV9ByteBasisProfile {
    Unknown,
    VerifiedIpLayer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetFlowV9SourceContext {
    sensor_id: String,
    input_mode: InputMode,
    input_sha256: String,
    observed_at: String,
    byte_basis_profile: NetFlowV9ByteBasisProfile,
    capture_interface: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetFlowV9ContextError {
    pub field: &'static str,
}
impl fmt::Display for NetFlowV9ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid bounded v9 normalization context: {}",
            self.field
        )
    }
}
impl std::error::Error for NetFlowV9ContextError {}

impl NetFlowV9SourceContext {
    pub fn new(
        sensor_id: &str,
        input_mode: InputMode,
        input_sha256: &str,
        observed_at: &str,
        byte_basis_profile: NetFlowV9ByteBasisProfile,
    ) -> Result<Self, NetFlowV9ContextError> {
        if sensor_id.is_empty() || sensor_id.len() > MAX_IDENTITY_BYTES {
            return Err(NetFlowV9ContextError { field: "sensor_id" });
        }
        if !matches!(input_mode, InputMode::ExportFile | InputMode::PcapFile) {
            return Err(NetFlowV9ContextError {
                field: "input_mode",
            });
        }
        let input_sha256 = normalize_sha256(input_sha256).map_err(|_| NetFlowV9ContextError {
            field: "input_sha256",
        })?;
        if observed_at.len() > 64 || validate_canonical_utc(observed_at).is_err() {
            return Err(NetFlowV9ContextError {
                field: "observed_at",
            });
        }
        Ok(Self {
            sensor_id: sensor_id.into(),
            input_mode,
            input_sha256,
            observed_at: observed_at.into(),
            byte_basis_profile,
            capture_interface: None,
        })
    }

    pub fn with_capture_interface(mut self, value: &str) -> Result<Self, NetFlowV9ContextError> {
        if value.is_empty() || value.len() > 256 {
            return Err(NetFlowV9ContextError {
                field: "capture_interface",
            });
        }
        self.capture_interface = Some(value.into());
        Ok(self)
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
    pub fn byte_basis_profile(&self) -> NetFlowV9ByteBasisProfile {
        self.byte_basis_profile
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetFlowV9NormalizationConfig {
    max_flow_age_ms: u64,
    max_records_inspected_per_batch: usize,
    max_observations_per_batch: usize,
    max_normalization_diagnostics_per_batch: usize,
    max_audit_entries_per_batch: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetFlowV9ConfigError {
    pub field: &'static str,
}
impl fmt::Display for NetFlowV9ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid v9 normalization limit: {}", self.field)
    }
}
impl std::error::Error for NetFlowV9ConfigError {}

impl Default for NetFlowV9NormalizationConfig {
    fn default() -> Self {
        Self {
            max_flow_age_ms: DEFAULT_MAX_FLOW_AGE_MS,
            max_records_inspected_per_batch: 16_384,
            max_observations_per_batch: 16_384,
            max_normalization_diagnostics_per_batch: 128,
            max_audit_entries_per_batch: 16_384,
        }
    }
}
impl NetFlowV9NormalizationConfig {
    pub fn new(
        age_ms: u64,
        records: usize,
        observations: usize,
        diagnostics: usize,
        audit: usize,
    ) -> Result<Self, NetFlowV9ConfigError> {
        if age_ms > MAX_FLOW_AGE_MS {
            return Err(NetFlowV9ConfigError {
                field: "max_flow_age_ms",
            });
        }
        for (field, limit) in [
            ("max_records_inspected_per_batch", records),
            ("max_observations_per_batch", observations),
            ("max_audit_entries_per_batch", audit),
        ] {
            if limit == 0 {
                return Err(NetFlowV9ConfigError { field });
            }
        }
        Ok(Self {
            max_flow_age_ms: age_ms,
            max_records_inspected_per_batch: records,
            max_observations_per_batch: observations,
            max_normalization_diagnostics_per_batch: diagnostics,
            max_audit_entries_per_batch: audit,
        })
    }
    pub fn max_flow_age_ms(&self) -> u64 {
        self.max_flow_age_ms
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetFlowV9NormalizationStatus {
    Complete,
    CompleteWithRejectionsOrWarnings,
    StoppedAtLimit,
}

/// Not serialized into CanonicalObservation. Retains warnings even when F6's
/// diagnostic retention cap was zero. No ownership of F5 is needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetFlowV9ParserStatus<'a> {
    pub count_validation: CountValidation,
    pub completion: ParseCompletion,
    pub session_disposition: SessionDisposition,
    pub decoded_record_count: usize,
    pub diagnostics_total: usize,
    pub diagnostics_dropped: usize,
    pub diagnostics: &'a [NetFlowV9Diagnostic],
}
impl<'a> NetFlowV9ParserStatus<'a> {
    fn from_outcome(out: &'a NetFlowV9ParseOutcome<'_>) -> Self {
        Self {
            count_validation: out.count_validation,
            completion: out.completion,
            session_disposition: out.session_disposition,
            decoded_record_count: out.decoded_record_count,
            diagnostics_total: out.diagnostics_total,
            diagnostics_dropped: out.diagnostics_dropped,
            diagnostics: &out.diagnostics,
        }
    }
    pub fn reset_required(&self) -> bool {
        self.session_disposition == SessionDisposition::ResetRequired
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetFlowV9NormalizationDiagnosticKind {
    MissingRequiredField,
    UnsupportedFieldWidth,
    AmbiguousField,
    AddressFamilyConflict,
    InvalidSemanticValue,
    FlowTimeOrderingInvalid,
    FlowAgeExceeded,
    TimestampArithmeticFailure,
    InputBindingMismatch,
    CanonicalConstructionFailure,
    DuplicateEquivalent,
    DeferredSemanticsObserved,
    NormalizationLimitExceeded,
}
use NetFlowV9NormalizationDiagnosticKind as Kind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetFlowV9NormalizationDiagnostic {
    pub kind: Kind,
    pub datagram_ordinal: u64,
    pub flowset_ordinal: Option<u32>,
    pub record_ordinal: Option<u32>,
    pub field_ordinal: Option<u32>,
    pub field_id: Option<u16>,
    pub field: &'static str,
    pub width: Option<usize>,
    pub value: Option<u64>,
    pub limit: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetFlowV9AuditAction {
    Emitted { observation_index: usize },
    Rejected { reason: Kind },
    OptionsIgnored,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetFlowV9AuditEntry {
    pub datagram_ordinal: u64,
    pub flowset_ordinal: u32,
    pub record_ordinal: u32,
    pub byte_offset: usize,
    pub template_id: u16,
    pub generation: u64,
    pub action: NetFlowV9AuditAction,
}

#[must_use = "inspect parser_status and quarantine/reset the session when required"]
#[derive(Clone, Debug, PartialEq)]
pub struct NetFlowV9NormalizationResult<'a> {
    pub observations: Vec<CanonicalObservation>,
    pub diagnostics: Vec<NetFlowV9NormalizationDiagnostic>,
    pub diagnostics_total: usize,
    pub diagnostics_dropped: usize,
    pub records_inspected: usize,
    pub records_emitted: usize,
    pub records_rejected: usize,
    pub options_records_ignored: usize,
    pub audit: Vec<NetFlowV9AuditEntry>,
    pub parser_status: NetFlowV9ParserStatus<'a>,
    pub normalization_status: NetFlowV9NormalizationStatus,
}

/// Even an accounting error cannot hide the caller's F6 reset obligation.
#[derive(Debug, PartialEq, Eq)]
pub struct NetFlowV9NormalizationError<'a> {
    pub parser_status: NetFlowV9ParserStatus<'a>,
}
impl fmt::Display for NetFlowV9NormalizationError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("v9 normalization accounting overflow; inspect preserved parser status")
    }
}
impl std::error::Error for NetFlowV9NormalizationError<'_> {}

#[derive(Clone, Copy)]
struct Failure {
    kind: Kind,
    field: &'static str,
    field_id: Option<u16>,
    field_ordinal: Option<u32>,
    width: Option<usize>,
    value: Option<u64>,
    limit: Option<u64>,
}
impl Failure {
    fn new(kind: Kind, field: &'static str, field_id: Option<u16>) -> Self {
        Self {
            kind,
            field,
            field_id,
            field_ordinal: None,
            width: None,
            value: None,
            limit: None,
        }
    }
    fn interval(kind: Kind, field: &'static str, value: u64, limit: u64) -> Self {
        Self {
            value: Some(value),
            limit: Some(limit),
            ..Self::new(kind, field, None)
        }
    }
}

fn increment<'a>(
    value: &mut usize,
    status: NetFlowV9ParserStatus<'a>,
) -> Result<(), NetFlowV9NormalizationError<'a>> {
    *value = value.checked_add(1).ok_or(NetFlowV9NormalizationError {
        parser_status: status,
    })?;
    Ok(())
}
impl<'a> NetFlowV9NormalizationResult<'a> {
    fn diagnostic(
        &mut self,
        failure: Failure,
        flowset: Option<u32>,
        record: Option<u32>,
        datagram: u64,
        cap: usize,
    ) -> Result<(), NetFlowV9NormalizationError<'a>> {
        increment(&mut self.diagnostics_total, self.parser_status)?;
        if self.normalization_status == NetFlowV9NormalizationStatus::Complete {
            self.normalization_status =
                NetFlowV9NormalizationStatus::CompleteWithRejectionsOrWarnings;
        }
        if self.diagnostics.len() >= cap {
            increment(&mut self.diagnostics_dropped, self.parser_status)?;
        } else {
            self.diagnostics.push(NetFlowV9NormalizationDiagnostic {
                kind: failure.kind,
                datagram_ordinal: datagram,
                flowset_ordinal: flowset,
                record_ordinal: record,
                field_ordinal: failure.field_ordinal,
                field_id: failure.field_id,
                field: failure.field,
                width: failure.width,
                value: failure.value,
                limit: failure.limit,
            });
        }
        Ok(())
    }
}

const SUPPORTED_IDS: [u16; 16] = [1, 2, 4, 6, 7, 8, 10, 11, 12, 14, 21, 22, 27, 28, 32, 60];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Unsigned(u64),
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}
struct Values {
    entries: [Option<Value>; 16],
    duplicate: Option<Failure>,
    deferred_bytes: bool,
}
impl Values {
    fn get(&self, id: u16) -> Option<Value> {
        SUPPORTED_IDS
            .iter()
            .position(|value| *value == id)
            .and_then(|index| self.entries.get(index))
            .copied()
            .flatten()
    }
    fn number(&self, id: u16) -> Option<u64> {
        match self.get(id) {
            Some(Value::Unsigned(value)) => Some(value),
            _ => None,
        }
    }
    fn required(&self, id: u16, field: &'static str) -> Result<u64, Failure> {
        self.number(id)
            .ok_or(Failure::new(Kind::MissingRequiredField, field, Some(id)))
    }
}

fn decode(field: FieldValueView<'_>) -> Result<Value, Failure> {
    let id = field.specifier.field_id;
    let width = field.bytes.len();
    let allowed = match id {
        1 | 2 => (1..=8).contains(&width),
        10 | 14 => (2..=8).contains(&width),
        4 | 6 | 60 => width == 1,
        7 | 11 | 32 => width == 2,
        8 | 12 | 21 | 22 => width == 4,
        27 | 28 => width == 16,
        _ => false,
    };
    let bad = Failure {
        field_ordinal: Some(field.field_ordinal),
        width: Some(width),
        ..Failure::new(Kind::UnsupportedFieldWidth, "ie_width", Some(id))
    };
    if !allowed || usize::from(field.specifier.encoded_length) != width {
        return Err(bad);
    }
    match id {
        8 | 12 => {
            let octets: [u8; 4] = field.bytes.try_into().map_err(|_| bad)?;
            Ok(Value::V4(Ipv4Addr::from(octets)))
        }
        27 | 28 => {
            let octets: [u8; 16] = field.bytes.try_into().map_err(|_| bad)?;
            Ok(Value::V6(Ipv6Addr::from(octets)))
        }
        _ => {
            let mut value = 0_u64;
            for byte in field.bytes {
                value = value
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(u64::from(*byte)))
                    .ok_or(bad)?;
            }
            Ok(Value::Unsigned(value))
        }
    }
}

fn collect(record: RecordView<'_>, basis: NetFlowV9ByteBasisProfile) -> Result<Values, Failure> {
    let mut values = Values {
        entries: [None; 16],
        duplicate: None,
        deferred_bytes: false,
    };
    for field in record.fields() {
        if field.role != FieldRole::Data || field.specifier.enterprise_number.is_some() {
            return Err(Failure::new(Kind::InputBindingMismatch, "field_role", None));
        }
        let id = field.specifier.field_id;
        if id == 1 && basis == NetFlowV9ByteBasisProfile::Unknown {
            values.deferred_bytes = true;
            continue;
        }
        let Some(index) = SUPPORTED_IDS.iter().position(|value| *value == id) else {
            continue;
        };
        let value = decode(field)?;
        let entry = values.entries.get_mut(index).ok_or(Failure::new(
            Kind::CanonicalConstructionFailure,
            "ie_slot",
            Some(id),
        ))?;
        if let Some(previous) = *entry {
            let duplicate = Failure {
                field_ordinal: Some(field.field_ordinal),
                ..Failure::new(Kind::DuplicateEquivalent, "duplicate", Some(id))
            };
            if previous != value {
                return Err(Failure {
                    kind: Kind::AmbiguousField,
                    ..duplicate
                });
            }
            values.duplicate.get_or_insert(duplicate);
        } else {
            *entry = Some(value);
        }
    }
    Ok(values)
}

fn endpoints(values: &Values) -> Result<(String, String), Failure> {
    let family = match values.number(60) {
        Some(4) => 4,
        Some(6) => 6,
        Some(_) => {
            return Err(Failure::new(
                Kind::InvalidSemanticValue,
                "ip_version",
                Some(60),
            ))
        }
        None if values.get(27).is_some() || values.get(28).is_some() => {
            return Err(Failure::new(
                Kind::AddressFamilyConflict,
                "ip_version",
                Some(60),
            ))
        }
        None => 4,
    };
    let (src_id, dst_id) = if family == 4 { (8, 12) } else { (27, 28) };
    let address = |id, label| match values.get(id) {
        Some(Value::V4(value)) if family == 4 => Ok(value.to_string()),
        Some(Value::V6(value)) if family == 6 => Ok(value.to_string()),
        _ => Err(Failure::new(Kind::MissingRequiredField, label, Some(id))),
    };
    Ok((address(src_id, "src_ip")?, address(dst_id, "dst_ip")?))
}

fn times(
    header: &NetFlowV9Header,
    first: u32,
    last: u32,
    age: u64,
) -> Result<(String, String), Failure> {
    let end_age = u64::from(header.sys_uptime_ms.wrapping_sub(last));
    let duration = u64::from(last.wrapping_sub(first));
    let total = end_age.checked_add(duration).ok_or(Failure::new(
        Kind::TimestampArithmeticFailure,
        "start_age",
        None,
    ))?;
    let wrap_limit = age.min(MAX_FLOW_AGE_MS);
    if last > header.sys_uptime_ms && end_age > wrap_limit {
        return Err(Failure::interval(
            Kind::FlowTimeOrderingInvalid,
            "end_age_ms",
            end_age,
            wrap_limit,
        ));
    }
    if first > last && duration > wrap_limit {
        return Err(Failure::interval(
            Kind::FlowTimeOrderingInvalid,
            "duration_ms",
            duration,
            wrap_limit,
        ));
    }
    if total >= (1_u64 << 32) {
        return Err(Failure::interval(
            Kind::FlowTimeOrderingInvalid,
            "start_age_ms",
            total,
            (1_u64 << 32) - 1,
        ));
    }
    for (field, value) in [("end_age_ms", end_age), ("duration_ms", duration)] {
        if value > age {
            return Err(Failure::interval(Kind::FlowAgeExceeded, field, value, age));
        }
    }
    let arithmetic = Failure::new(Kind::TimestampArithmeticFailure, "flow_time", None);
    let export = u64::from(header.unix_seconds)
        .checked_mul(1_000_000_000)
        .ok_or(arithmetic)?;
    let end = export
        .checked_sub(end_age.checked_mul(1_000_000).ok_or(arithmetic)?)
        .ok_or(arithmetic)?;
    let start = end
        .checked_sub(duration.checked_mul(1_000_000).ok_or(arithmetic)?)
        .ok_or(arithmetic)?;
    Ok((
        unix_nanoseconds_to_rfc3339(start).map_err(|_| arithmetic)?,
        unix_nanoseconds_to_rfc3339(end).map_err(|_| arithmetic)?,
    ))
}

fn flags(raw: u8) -> Vec<TcpFlag> {
    [
        (1, TcpFlag::Fin),
        (2, TcpFlag::Syn),
        (4, TcpFlag::Rst),
        (8, TcpFlag::Psh),
        (16, TcpFlag::Ack),
        (32, TcpFlag::Urg),
        (64, TcpFlag::Ece),
        (128, TcpFlag::Cwr),
    ]
    .into_iter()
    .filter_map(|(bit, flag)| (raw & bit != 0).then_some(flag))
    .collect()
}

struct RecordBinding<'a> {
    header: &'a NetFlowV9Header,
    context: &'a NetFlowV9ParseContext,
    snapshot: &'a TemplateSnapshot,
    flowset_ordinal: u32,
}
struct RecordSuccess {
    observation: CanonicalObservation,
    duplicate: Option<Failure>,
    deferred_bytes: bool,
}

fn normalize_record(
    record: RecordView<'_>,
    binding: &RecordBinding<'_>,
    source: &NetFlowV9SourceContext,
    age: u64,
) -> Result<RecordSuccess, Failure> {
    let values = collect(record, source.byte_basis_profile)?;
    let construction = Failure::new(Kind::CanonicalConstructionFailure, "canonical", None);
    let protocol = u8::try_from(values.required(4, "ip_protocol")?).map_err(|_| construction)?;
    let (src_ip, dst_ip) = endpoints(&values)?;
    let first = u32::try_from(values.required(22, "start_time")?).map_err(|_| construction)?;
    let last = u32::try_from(values.required(21, "end_time")?).map_err(|_| construction)?;
    let (start_time, end_time) = times(binding.header, first, last, age)?;
    let packets = values.number(2);
    let ip_bytes = values.number(1);
    if packets.is_none() && ip_bytes.is_none() {
        return Err(Failure::new(
            Kind::MissingRequiredField,
            "forward_counter",
            None,
        ));
    }
    let port = |id| -> Result<Option<u16>, Failure> {
        if !matches!(protocol, 6 | 17) {
            return Ok(None);
        }
        values
            .number(id)
            .map(|v| u16::try_from(v).map_err(|_| construction))
            .transpose()
    };
    let icmp = if protocol == 1 {
        values.number(32)
    } else {
        None
    };
    let icmp_type = icmp
        .map(|v| u8::try_from(v >> 8).map_err(|_| construction))
        .transpose()?;
    let icmp_code = icmp
        .map(|v| u8::try_from(v & 255).map_err(|_| construction))
        .transpose()?;
    let tcp_flags = if protocol == 6 {
        values
            .number(6)
            .map(|v| u8::try_from(v).map(flags).map_err(|_| construction))
            .transpose()?
    } else {
        None
    };
    let interface = |id| {
        values
            .number(id)
            .filter(|v| *v != 0)
            .map(|v| format!("ifindex:{v}"))
    };
    let coordinates = NetFlowV9IdentityCoordinates {
        sensor_id: &source.sensor_id,
        input_sha256: &source.input_sha256,
        exporter_id: binding.context.session.exporter_id(),
        session_id: binding.context.session.session_id(),
        source_id: binding.header.source_id,
        sequence_number: binding.header.sequence_number,
        datagram_ordinal: binding.context.datagram_ordinal,
        flowset_ordinal: binding.flowset_ordinal,
        record_ordinal: record.record_ordinal,
    };
    let record_id = generate_netflow_v9_record_id(&coordinates).map_err(|_| construction)?;
    let fingerprint =
        generate_netflow_v9_session_fingerprint(coordinates.exporter_id, coordinates.session_id)
            .map_err(|_| construction)?;
    let source_record_id = format!(
        "netflow_v9/{}/{}/{}/{}/{}/{}/{}",
        coordinates.exporter_id,
        fingerprint,
        coordinates.source_id,
        coordinates.sequence_number,
        coordinates.datagram_ordinal,
        coordinates.flowset_ordinal,
        coordinates.record_ordinal
    );
    if source_record_id.len() > MAX_SOURCE_RECORD_ID_BYTES {
        return Err(construction);
    }
    let counters = DirectionCounters {
        packets,
        payload_bytes: None,
        ip_bytes,
        l2_bytes: None,
    };
    if counters.is_empty() {
        return Err(construction);
    }
    let flow = FlowData {
        start_time,
        end_time: Some(end_time),
        src_ip,
        dst_ip,
        src_port: port(7)?,
        dst_port: port(11)?,
        icmp_type,
        icmp_code,
        ip_protocol: protocol,
        direction_mode: DirectionMode::Unidirectional,
        service: None,
        connection_state: None,
        connection_history: None,
        tcp_flags,
        end_reason: None,
        ingress_interface: interface(10),
        egress_interface: interface(14),
        counters: FlowCounters {
            src_to_dst: counters,
            dst_to_src: None,
        },
    };
    Ok(RecordSuccess {
        observation: CanonicalObservation {
            schema_version: "1.0".into(),
            record_id,
            source_record_id: Some(source_record_id),
            observation_type: ObservationType::Flow,
            telemetry_source: TelemetrySource::NetFlowV9,
            sensor_id: source.sensor_id.clone(),
            observed_at: source.observed_at.clone(),
            quality: Quality {
                fidelity: Fidelity::Unknown,
                sampling_rate: None,
                sampling_probability: None,
                truncated: false,
                loss_detected: false,
                missed_content_bytes: None,
            },
            provenance: Provenance {
                input_mode: source.input_mode,
                parser_name: PARSER_NAME.into(),
                parser_version: env!("CARGO_PKG_VERSION").into(),
                input_sha256: Some(source.input_sha256.clone()),
                capture_interface: source.capture_interface.clone(),
                exporter_id: Some(coordinates.exporter_id.into()),
                observation_domain_id: Some(coordinates.source_id),
                template_id: Some(binding.snapshot.key.template_id()),
                message_sequence: Some(u64::from(coordinates.sequence_number)),
            },
            data: CanonicalData::Flow(flow),
        },
        duplicate: values.duplicate,
        deferred_bytes: values.deferred_bytes,
    })
}

/// Normalize only processed Decoded F6 records. The result borrows parser
/// diagnostics, not F5. Caller-supplied hashes/session epochs remain a trust
/// boundary. Parser partial/reset status is never repaired or overwritten.
pub fn normalize_netflow_v9<'a>(
    out: &'a NetFlowV9ParseOutcome<'_>,
    source: &NetFlowV9SourceContext,
    config: NetFlowV9NormalizationConfig,
) -> Result<NetFlowV9NormalizationResult<'a>, NetFlowV9NormalizationError<'a>> {
    let parser_status = NetFlowV9ParserStatus::from_outcome(out);
    let clean = out.count_validation == CountValidation::Match
        && out.completion == ParseCompletion::Complete
        && out.session_disposition == SessionDisposition::Continue
        && out.diagnostics_total == 0;
    let mut result = NetFlowV9NormalizationResult {
        observations: Vec::new(),
        diagnostics: Vec::new(),
        diagnostics_total: 0,
        diagnostics_dropped: 0,
        records_inspected: 0,
        records_emitted: 0,
        records_rejected: 0,
        options_records_ignored: 0,
        audit: Vec::new(),
        parser_status,
        normalization_status: if clean {
            NetFlowV9NormalizationStatus::Complete
        } else {
            NetFlowV9NormalizationStatus::CompleteWithRejectionsOrWarnings
        },
    };
    let cap = config.max_normalization_diagnostics_per_batch;
    let datagram = out.context.datagram_ordinal;
    if out.header.version != 9
        || u64::from(out.header.unix_seconds).checked_mul(1_000_000_000) != Some(out.source_time_ns)
        || out.context.session.exporter_id().len() > MAX_IDENTITY_BYTES
        || out.context.session.session_id().len() > MAX_IDENTITY_BYTES
    {
        result.diagnostic(
            Failure::new(Kind::InputBindingMismatch, "parse_context", None),
            None,
            None,
            datagram,
            cap,
        )?;
        return Ok(result);
    }
    'flowsets: for (index, flowset) in out.flowsets.iter().enumerate() {
        if !flowset.processed {
            continue;
        }
        let FlowSetContent::Data(data) = &flowset.content else {
            continue;
        };
        if data.state != DataFlowSetState::Decoded {
            continue;
        }
        let Some(snapshot) = data.snapshot() else {
            result.diagnostic(
                Failure::new(Kind::InputBindingMismatch, "snapshot", None),
                Some(flowset.flowset_ordinal),
                None,
                datagram,
                cap,
            )?;
            continue;
        };
        if u32::try_from(index).ok() != Some(flowset.flowset_ordinal)
            || snapshot.key.protocol() != TemplateProtocol::NetFlowV9
            || snapshot.key.session() != &out.context.session
            || snapshot.key.observation_scope_id() != out.header.source_id
            || snapshot.key.template_id() != flowset.flowset_id
            // Cross-check F6 metadata only; no wire framing or field slicing.
            || data.record_count.checked_mul(snapshot.record_length())
                .and_then(|n| n.checked_add(data.padding.len())) != Some(flowset.raw_payload.len())
            || flowset.byte_offset.checked_add(4) != Some(data.records_byte_offset)
        {
            result.diagnostic(
                Failure::new(Kind::InputBindingMismatch, "snapshot_key", None),
                Some(flowset.flowset_ordinal),
                None,
                datagram,
                cap,
            )?;
            continue;
        }
        let options = snapshot.definition().kind() == TemplateKind::Options;
        let mut records_seen = 0_usize;
        for record in data.records() {
            let exhausted = if result.records_inspected >= config.max_records_inspected_per_batch {
                Some(("records_inspected", config.max_records_inspected_per_batch))
            } else if result.audit.len() >= config.max_audit_entries_per_batch {
                Some(("audit_entries", config.max_audit_entries_per_batch))
            } else if !options && result.observations.len() >= config.max_observations_per_batch {
                Some(("observations", config.max_observations_per_batch))
            } else {
                None
            };
            if let Some((field, limit)) = exhausted {
                result.normalization_status = NetFlowV9NormalizationStatus::StoppedAtLimit;
                let failure = Failure {
                    limit: u64::try_from(limit).ok(),
                    ..Failure::new(Kind::NormalizationLimitExceeded, field, None)
                };
                result.diagnostic(
                    failure,
                    Some(flowset.flowset_ordinal),
                    Some(record.record_ordinal),
                    datagram,
                    cap,
                )?;
                break 'flowsets;
            }
            increment(&mut result.records_inspected, parser_status)?;
            increment(&mut records_seen, parser_status)?;
            let action = if records_seen > data.record_count
                || record.bytes().len() != snapshot.record_length()
            {
                increment(&mut result.records_rejected, parser_status)?;
                result.diagnostic(
                    Failure::new(Kind::InputBindingMismatch, "record_count", None),
                    Some(flowset.flowset_ordinal),
                    Some(record.record_ordinal),
                    datagram,
                    cap,
                )?;
                NetFlowV9AuditAction::Rejected {
                    reason: Kind::InputBindingMismatch,
                }
            } else if options {
                increment(&mut result.options_records_ignored, parser_status)?;
                NetFlowV9AuditAction::OptionsIgnored
            } else {
                let binding = RecordBinding {
                    header: &out.header,
                    context: &out.context,
                    snapshot,
                    flowset_ordinal: flowset.flowset_ordinal,
                };
                match normalize_record(record, &binding, source, config.max_flow_age_ms) {
                    Ok(success) => {
                        if let Some(failure) = success.duplicate {
                            result.diagnostic(
                                failure,
                                Some(flowset.flowset_ordinal),
                                Some(record.record_ordinal),
                                datagram,
                                cap,
                            )?;
                        }
                        if success.deferred_bytes {
                            result.diagnostic(
                                Failure::new(
                                    Kind::DeferredSemanticsObserved,
                                    "byte_basis",
                                    Some(1),
                                ),
                                Some(flowset.flowset_ordinal),
                                Some(record.record_ordinal),
                                datagram,
                                cap,
                            )?;
                        }
                        let observation_index = result.observations.len();
                        result.observations.push(success.observation);
                        increment(&mut result.records_emitted, parser_status)?;
                        NetFlowV9AuditAction::Emitted { observation_index }
                    }
                    Err(failure) => {
                        increment(&mut result.records_rejected, parser_status)?;
                        result.diagnostic(
                            failure,
                            Some(flowset.flowset_ordinal),
                            Some(record.record_ordinal),
                            datagram,
                            cap,
                        )?;
                        NetFlowV9AuditAction::Rejected {
                            reason: failure.kind,
                        }
                    }
                }
            };
            result.audit.push(NetFlowV9AuditEntry {
                datagram_ordinal: datagram,
                flowset_ordinal: flowset.flowset_ordinal,
                record_ordinal: record.record_ordinal,
                byte_offset: record.byte_offset,
                template_id: snapshot.key.template_id(),
                generation: snapshot.generation,
                action,
            });
        }
        if records_seen != data.record_count {
            result.diagnostic(
                Failure::new(Kind::InputBindingMismatch, "record_count", None),
                Some(flowset.flowset_ordinal),
                None,
                datagram,
                cap,
            )?;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accounting_overflow_is_checked_and_preserves_reset() {
        let status = NetFlowV9ParserStatus {
            count_validation: CountValidation::Inconclusive,
            completion: ParseCompletion::StoppedForReset,
            session_disposition: SessionDisposition::ResetRequired,
            decoded_record_count: 0,
            diagnostics_total: 0,
            diagnostics_dropped: 0,
            diagnostics: &[],
        };
        let mut count = usize::MAX;
        let failure = increment(&mut count, status).expect_err("overflow must fail closed");
        assert_eq!(count, usize::MAX);
        assert!(failure.parser_status.reset_required());
    }
}
