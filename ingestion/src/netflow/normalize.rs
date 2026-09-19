//! Stateful NetFlow v5 normalization into the frozen canonical v1 model.

use std::collections::BTreeMap;
use std::fmt;

use crate::canonical::id::{
    generate_netflow_v5_record_id, normalize_sha256, InputIdentityError,
    NetFlowV5IdentityCoordinates,
};
use crate::canonical::time::{unix_nanoseconds_to_rfc3339, validate_canonical_utc};
use crate::canonical::{
    CanonicalData, CanonicalObservation, DirectionCounters, DirectionMode, Fidelity, FlowCounters,
    FlowData, InputMode, ObservationType, Provenance, Quality, TcpFlag, TelemetrySource,
};
use crate::netflow::v5::{
    parse_netflow_v5_datagram, NetFlowV5Datagram, NetFlowV5DiagnosticKind, NetFlowV5Header,
    NetFlowV5ParseError, NetFlowV5Record,
};

pub const NETFLOW_V5_NORMALIZER_NAME: &str = "sih-ingestion-core-netflow-v5";
pub const NETFLOW_V5_NORMALIZER_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_MAX_FLOW_AGE_MS: u64 = 24 * 60 * 60 * 1_000;

const SYS_UPTIME_MODULUS_MS: u64 = 1_u64 << 32;
const NANOS_PER_MILLISECOND: u64 = 1_000_000;
const NANOS_PER_SECOND: u64 = 1_000_000_000;
const BOOT_EPOCH_TOLERANCE_NS: u64 = NANOS_PER_SECOND;
const MAX_CONTEXT_ID_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportDatagramContext {
    sensor_id: String,
    input_mode: InputMode,
    input_sha256: String,
    exporter_id: String,
    transport_source: Option<String>,
    observed_at: String,
    datagram_ordinal: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportDatagramContextError {
    EmptySensorId,
    EmptyExporterId,
    ContextValueTooLong { field: &'static str },
    InvalidExporterId,
    InvalidInputMode,
    InvalidInputSha256,
    InvalidObservedAt,
    EmptyTransportSource,
}

impl fmt::Display for ExportDatagramContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptySensorId => "sensor_id must be nonempty",
            Self::EmptyExporterId => "exporter_id must be nonempty",
            Self::ContextValueTooLong { field } => {
                return write!(formatter, "{field} exceeds {MAX_CONTEXT_ID_BYTES} bytes")
            }
            Self::InvalidExporterId => {
                "exporter_id may contain only ASCII letters, digits, '.', '_', ':', and '-'"
            }
            Self::InvalidInputMode => "F3 offline NetFlow v5 requires input_mode=export_file",
            Self::InvalidInputSha256 => "input_sha256 must be 64 hexadecimal characters",
            Self::InvalidObservedAt => "observed_at must be canonical RFC3339 UTC",
            Self::EmptyTransportSource => "transport_source must be nonempty when supplied",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ExportDatagramContextError {}

impl ExportDatagramContext {
    pub fn new(
        sensor_id: impl Into<String>,
        input_mode: InputMode,
        input_sha256: impl AsRef<str>,
        exporter_id: impl Into<String>,
        transport_source: Option<String>,
        observed_at: impl Into<String>,
        datagram_ordinal: u64,
    ) -> Result<Self, ExportDatagramContextError> {
        let sensor_id = sensor_id.into();
        if sensor_id.is_empty() {
            return Err(ExportDatagramContextError::EmptySensorId);
        }
        if sensor_id.len() > MAX_CONTEXT_ID_BYTES {
            return Err(ExportDatagramContextError::ContextValueTooLong { field: "sensor_id" });
        }
        if input_mode != InputMode::ExportFile {
            return Err(ExportDatagramContextError::InvalidInputMode);
        }
        let exporter_id = exporter_id.into();
        if exporter_id.is_empty() {
            return Err(ExportDatagramContextError::EmptyExporterId);
        }
        if exporter_id.len() > MAX_CONTEXT_ID_BYTES {
            return Err(ExportDatagramContextError::ContextValueTooLong {
                field: "exporter_id",
            });
        }
        if !exporter_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        {
            return Err(ExportDatagramContextError::InvalidExporterId);
        }
        if transport_source.as_ref().is_some_and(String::is_empty) {
            return Err(ExportDatagramContextError::EmptyTransportSource);
        }
        if transport_source
            .as_ref()
            .is_some_and(|source| source.len() > MAX_CONTEXT_ID_BYTES)
        {
            return Err(ExportDatagramContextError::ContextValueTooLong {
                field: "transport_source",
            });
        }
        let input_sha256 = normalize_sha256(input_sha256.as_ref())
            .map_err(|_| ExportDatagramContextError::InvalidInputSha256)?;
        let observed_at = observed_at.into();
        validate_canonical_utc(&observed_at)
            .map_err(|_| ExportDatagramContextError::InvalidObservedAt)?;
        Ok(Self {
            sensor_id,
            input_mode,
            input_sha256,
            exporter_id,
            transport_source,
            observed_at,
            datagram_ordinal,
        })
    }

    /// Build the same frozen normalization context for an offline PCAP artifact.
    ///
    /// The original constructor intentionally remains export-file-only. F4 uses
    /// this narrow constructor so PCAP provenance is accurate without changing
    /// any F3 normalization semantics.
    pub(crate) fn new_pcap(
        sensor_id: impl Into<String>,
        input_sha256: impl AsRef<str>,
        exporter_id: impl Into<String>,
        transport_source: Option<String>,
        observed_at: impl Into<String>,
        datagram_ordinal: u64,
    ) -> Result<Self, ExportDatagramContextError> {
        let mut context = Self::new(
            sensor_id,
            InputMode::ExportFile,
            input_sha256,
            exporter_id,
            transport_source,
            observed_at,
            datagram_ordinal,
        )?;
        context.input_mode = InputMode::PcapFile;
        Ok(context)
    }

    pub fn sensor_id(&self) -> &str {
        &self.sensor_id
    }

    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }

    pub fn exporter_id(&self) -> &str {
        &self.exporter_id
    }

    pub fn transport_source(&self) -> Option<&str> {
        self.transport_source.as_deref()
    }

    pub fn observed_at(&self) -> &str {
        &self.observed_at
    }

    pub fn datagram_ordinal(&self) -> u64 {
        self.datagram_ordinal
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetFlowV5NormalizationConfig {
    pub max_flow_age_ms: u64,
}

impl Default for NetFlowV5NormalizationConfig {
    fn default() -> Self {
        Self {
            max_flow_age_ms: DEFAULT_MAX_FLOW_AGE_MS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetFlowV5NormalizationDiagnosticKind {
    NonzeroPadding,
    SamplingInvalid,
    FlowAgeExceeded,
    TimestampUnderflow,
    TimestampOutOfRange,
    IdentityFailure,
    SequenceGap,
    Duplicate,
    SequenceRegression,
    ExporterRestart,
    ExporterClockShift,
    ExporterClockRegression,
    UptimeAmbiguous,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetFlowV5NormalizationDiagnostic {
    pub kind: NetFlowV5NormalizationDiagnosticKind,
    pub datagram_ordinal: u64,
    pub record_ordinal: Option<u8>,
    pub byte_offset: Option<usize>,
    pub field: &'static str,
    pub expected_sequence: Option<u32>,
    pub actual_sequence: Option<u32>,
    pub missing_records: Option<u32>,
    pub value_ms: Option<u64>,
    pub limit_ms: Option<u64>,
}

impl NetFlowV5NormalizationDiagnostic {
    fn datagram(
        kind: NetFlowV5NormalizationDiagnosticKind,
        context: &ExportDatagramContext,
        field: &'static str,
    ) -> Self {
        Self {
            kind,
            datagram_ordinal: context.datagram_ordinal,
            record_ordinal: None,
            byte_offset: None,
            field,
            expected_sequence: None,
            actual_sequence: None,
            missing_records: None,
            value_ms: None,
            limit_ms: None,
        }
    }

    fn record(
        kind: NetFlowV5NormalizationDiagnosticKind,
        context: &ExportDatagramContext,
        record_ordinal: u8,
        field: &'static str,
    ) -> Self {
        let mut diagnostic = Self::datagram(kind, context, field);
        diagnostic.record_ordinal = Some(record_ordinal);
        diagnostic
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceStatus {
    Initial,
    InOrder,
    Wrapped,
    Gap { missing_records: u32 },
    Duplicate,
    Regression,
    Restart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExporterClockStatus {
    Initial,
    InOrder,
    UptimeWrapped,
    Restart,
    Shifted,
    Regressed,
    Ambiguous,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NetFlowV5NormalizationResult {
    pub observations: Vec<CanonicalObservation>,
    pub diagnostics: Vec<NetFlowV5NormalizationDiagnostic>,
    pub sequence_status: SequenceStatus,
    pub clock_status: ExporterClockStatus,
}

#[derive(Debug)]
pub enum NetFlowV5ProcessingError {
    Parse(NetFlowV5ParseError),
}

impl fmt::Display for NetFlowV5ProcessingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "NetFlow v5 parse failed: {error}"),
        }
    }
}

impl std::error::Error for NetFlowV5ProcessingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
        }
    }
}

impl From<NetFlowV5ParseError> for NetFlowV5ProcessingError {
    fn from(value: NetFlowV5ParseError) -> Self {
        Self::Parse(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct StreamKey {
    exporter_id: String,
    engine_type: u8,
    engine_id: u8,
}

#[derive(Clone, Debug)]
struct StreamState {
    flow_sequence: u32,
    record_count: u16,
    sys_uptime_ms: u32,
    export_ns: u64,
    uptime_wraps: u64,
    boot_epoch_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SequenceRelation {
    InOrder,
    Gap(u32),
    Duplicate,
    Regression,
}

#[derive(Clone, Debug)]
struct StateAssessment {
    sequence_status: SequenceStatus,
    clock_status: ExporterClockStatus,
    loss_detected: bool,
    diagnostics: Vec<NetFlowV5NormalizationDiagnostic>,
    next_state: Option<StreamState>,
}

#[derive(Clone, Debug)]
pub struct NetFlowV5Normalizer {
    config: NetFlowV5NormalizationConfig,
    streams: BTreeMap<StreamKey, StreamState>,
}

impl NetFlowV5Normalizer {
    pub fn new(config: NetFlowV5NormalizationConfig) -> Self {
        Self {
            config,
            streams: BTreeMap::new(),
        }
    }

    pub fn process_bytes(
        &mut self,
        bytes: &[u8],
        context: &ExportDatagramContext,
    ) -> Result<NetFlowV5NormalizationResult, NetFlowV5ProcessingError> {
        let parsed = parse_netflow_v5_datagram(bytes)?;
        Ok(self.process_datagram(&parsed, context))
    }

    pub fn process_datagram(
        &mut self,
        datagram: &NetFlowV5Datagram,
        context: &ExportDatagramContext,
    ) -> NetFlowV5NormalizationResult {
        let key = StreamKey {
            exporter_id: context.exporter_id.clone(),
            engine_type: datagram.header.engine_type,
            engine_id: datagram.header.engine_id,
        };
        let assessment = assess_state(self.streams.get(&key), &datagram.header, context);
        let mut diagnostics = assessment.diagnostics;
        translate_parser_diagnostics(datagram, context, &mut diagnostics);

        let (fidelity, sampling_rate, sampling_invalid) = sampling_quality(&datagram.header);
        if sampling_invalid
            && !diagnostics
                .iter()
                .any(|item| item.kind == NetFlowV5NormalizationDiagnosticKind::SamplingInvalid)
        {
            diagnostics.push(NetFlowV5NormalizationDiagnostic::datagram(
                NetFlowV5NormalizationDiagnosticKind::SamplingInvalid,
                context,
                "sampling",
            ));
        }

        let policy = CanonicalizationPolicy {
            max_flow_age_ms: self.config.max_flow_age_ms,
            fidelity,
            sampling_rate,
            loss_detected: assessment.loss_detected,
        };
        let mut observations = Vec::with_capacity(datagram.records.len());
        for record in &datagram.records {
            match canonicalize_record(&datagram.header, record, context, policy) {
                Ok(observation) => observations.push(observation),
                Err(mut diagnostic) => {
                    diagnostic.datagram_ordinal = context.datagram_ordinal;
                    diagnostics.push(diagnostic);
                }
            }
        }

        if let Some(next_state) = assessment.next_state {
            self.streams.insert(key, next_state);
        }

        NetFlowV5NormalizationResult {
            observations,
            diagnostics,
            sequence_status: assessment.sequence_status,
            clock_status: assessment.clock_status,
        }
    }
}

fn export_nanoseconds(header: &NetFlowV5Header) -> Option<u64> {
    u64::from(header.unix_secs)
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|value| value.checked_add(u64::from(header.unix_nsecs)))
}

fn state_from_header(header: &NetFlowV5Header, uptime_wraps: u64) -> Option<StreamState> {
    let export_ns = export_nanoseconds(header)?;
    let extended_uptime_ms = uptime_wraps
        .checked_mul(SYS_UPTIME_MODULUS_MS)?
        .checked_add(u64::from(header.sys_uptime_ms))?;
    let uptime_ns = extended_uptime_ms.checked_mul(NANOS_PER_MILLISECOND)?;
    let boot_epoch_ns = export_ns.checked_sub(uptime_ns)?;
    Some(StreamState {
        flow_sequence: header.flow_sequence,
        record_count: header.count,
        sys_uptime_ms: header.sys_uptime_ms,
        export_ns,
        uptime_wraps,
        boot_epoch_ns,
    })
}

fn sequence_relation(previous: &StreamState, header: &NetFlowV5Header) -> SequenceRelation {
    let expected = previous
        .flow_sequence
        .wrapping_add(u32::from(previous.record_count));
    if header.flow_sequence == expected {
        SequenceRelation::InOrder
    } else if header.flow_sequence == previous.flow_sequence {
        SequenceRelation::Duplicate
    } else {
        let delta = header.flow_sequence.wrapping_sub(expected);
        if delta < (1_u32 << 31) {
            SequenceRelation::Gap(delta)
        } else {
            SequenceRelation::Regression
        }
    }
}

fn sequence_diagnostic(
    relation: SequenceRelation,
    previous: &StreamState,
    header: &NetFlowV5Header,
    context: &ExportDatagramContext,
) -> Option<NetFlowV5NormalizationDiagnostic> {
    let expected = previous
        .flow_sequence
        .wrapping_add(u32::from(previous.record_count));
    let kind = match relation {
        SequenceRelation::InOrder => return None,
        SequenceRelation::Gap(_) => NetFlowV5NormalizationDiagnosticKind::SequenceGap,
        SequenceRelation::Duplicate => NetFlowV5NormalizationDiagnosticKind::Duplicate,
        SequenceRelation::Regression => NetFlowV5NormalizationDiagnosticKind::SequenceRegression,
    };
    let mut diagnostic = NetFlowV5NormalizationDiagnostic::datagram(kind, context, "flow_sequence");
    diagnostic.expected_sequence = Some(expected);
    diagnostic.actual_sequence = Some(header.flow_sequence);
    if let SequenceRelation::Gap(missing) = relation {
        diagnostic.missing_records = Some(missing);
    }
    Some(diagnostic)
}

fn assess_state(
    previous: Option<&StreamState>,
    header: &NetFlowV5Header,
    context: &ExportDatagramContext,
) -> StateAssessment {
    let Some(previous) = previous else {
        return match state_from_header(header, 0) {
            Some(next_state) => StateAssessment {
                sequence_status: SequenceStatus::Initial,
                clock_status: ExporterClockStatus::Initial,
                loss_detected: false,
                diagnostics: Vec::new(),
                next_state: Some(next_state),
            },
            None => StateAssessment {
                sequence_status: SequenceStatus::Initial,
                clock_status: ExporterClockStatus::Ambiguous,
                loss_detected: false,
                diagnostics: vec![NetFlowV5NormalizationDiagnostic::datagram(
                    NetFlowV5NormalizationDiagnosticKind::UptimeAmbiguous,
                    context,
                    "sys_uptime",
                )],
                next_state: None,
            },
        };
    };

    let relation = sequence_relation(previous, header);
    let mut diagnostics = Vec::new();
    let expected = previous
        .flow_sequence
        .wrapping_add(u32::from(previous.record_count));
    let sequence_wrapped =
        matches!(relation, SequenceRelation::InOrder) && expected < previous.flow_sequence;
    let mut sequence_status = match relation {
        SequenceRelation::InOrder if sequence_wrapped => SequenceStatus::Wrapped,
        SequenceRelation::InOrder => SequenceStatus::InOrder,
        SequenceRelation::Gap(missing_records) => SequenceStatus::Gap { missing_records },
        SequenceRelation::Duplicate => SequenceStatus::Duplicate,
        SequenceRelation::Regression => SequenceStatus::Regression,
    };
    let loss_detected = matches!(relation, SequenceRelation::Gap(_));
    let Some(current_export_ns) = export_nanoseconds(header) else {
        diagnostics.push(NetFlowV5NormalizationDiagnostic::datagram(
            NetFlowV5NormalizationDiagnosticKind::UptimeAmbiguous,
            context,
            "export_time",
        ));
        return StateAssessment {
            sequence_status,
            clock_status: ExporterClockStatus::Ambiguous,
            loss_detected,
            diagnostics,
            next_state: None,
        };
    };

    if current_export_ns < previous.export_ns {
        if let Some(diagnostic) = sequence_diagnostic(relation, previous, header, context) {
            diagnostics.push(diagnostic);
        }
        diagnostics.push(NetFlowV5NormalizationDiagnostic::datagram(
            NetFlowV5NormalizationDiagnosticKind::ExporterClockRegression,
            context,
            "export_time",
        ));
        return StateAssessment {
            sequence_status,
            clock_status: ExporterClockStatus::Regressed,
            loss_detected,
            diagnostics,
            next_state: None,
        };
    }

    let uptime_decreased = header.sys_uptime_ms < previous.sys_uptime_ms;
    if uptime_decreased {
        let export_elapsed_ms = (current_export_ns - previous.export_ns) / NANOS_PER_MILLISECOND;
        let uptime_elapsed_ms =
            u64::from(header.sys_uptime_ms.wrapping_sub(previous.sys_uptime_ms));
        let wrap_timing_consistent = export_elapsed_ms.abs_diff(uptime_elapsed_ms) <= 1_000;
        let restart_state = state_from_header(header, 0);
        let restart_boot_shift = restart_state.as_ref().is_some_and(|state| {
            state.boot_epoch_ns.abs_diff(previous.boot_epoch_ns) > BOOT_EPOCH_TOLERANCE_NS
        });

        if matches!(relation, SequenceRelation::Regression) && restart_boot_shift {
            sequence_status = SequenceStatus::Restart;
            let mut diagnostic = NetFlowV5NormalizationDiagnostic::datagram(
                NetFlowV5NormalizationDiagnosticKind::ExporterRestart,
                context,
                "exporter_state",
            );
            diagnostic.expected_sequence = Some(expected);
            diagnostic.actual_sequence = Some(header.flow_sequence);
            diagnostics.push(diagnostic);
            return StateAssessment {
                sequence_status,
                clock_status: ExporterClockStatus::Restart,
                loss_detected: false,
                diagnostics,
                next_state: restart_state,
            };
        }

        if wrap_timing_consistent
            && !matches!(
                relation,
                SequenceRelation::Duplicate | SequenceRelation::Regression
            )
        {
            let next_state = previous
                .uptime_wraps
                .checked_add(1)
                .and_then(|wraps| state_from_header(header, wraps));
            if let Some(diagnostic) = sequence_diagnostic(relation, previous, header, context) {
                diagnostics.push(diagnostic);
            }
            if next_state.is_none() {
                diagnostics.push(NetFlowV5NormalizationDiagnostic::datagram(
                    NetFlowV5NormalizationDiagnosticKind::UptimeAmbiguous,
                    context,
                    "sys_uptime",
                ));
                return StateAssessment {
                    sequence_status,
                    clock_status: ExporterClockStatus::Ambiguous,
                    loss_detected,
                    diagnostics,
                    next_state: None,
                };
            }
            return StateAssessment {
                sequence_status,
                clock_status: ExporterClockStatus::UptimeWrapped,
                loss_detected,
                diagnostics,
                next_state,
            };
        }

        if let Some(diagnostic) = sequence_diagnostic(relation, previous, header, context) {
            diagnostics.push(diagnostic);
        }
        diagnostics.push(NetFlowV5NormalizationDiagnostic::datagram(
            NetFlowV5NormalizationDiagnosticKind::UptimeAmbiguous,
            context,
            "sys_uptime",
        ));
        return StateAssessment {
            sequence_status,
            clock_status: ExporterClockStatus::Ambiguous,
            loss_detected,
            diagnostics,
            next_state: None,
        };
    }

    let next_state = state_from_header(header, previous.uptime_wraps);
    let mut clock_status = ExporterClockStatus::InOrder;
    if next_state.as_ref().is_some_and(|state| {
        state.boot_epoch_ns.abs_diff(previous.boot_epoch_ns) > BOOT_EPOCH_TOLERANCE_NS
    }) {
        clock_status = ExporterClockStatus::Shifted;
        diagnostics.push(NetFlowV5NormalizationDiagnostic::datagram(
            NetFlowV5NormalizationDiagnosticKind::ExporterClockShift,
            context,
            "exporter_boot_epoch",
        ));
    }
    if next_state.is_none() {
        clock_status = ExporterClockStatus::Ambiguous;
        diagnostics.push(NetFlowV5NormalizationDiagnostic::datagram(
            NetFlowV5NormalizationDiagnosticKind::UptimeAmbiguous,
            context,
            "sys_uptime",
        ));
    }
    if let Some(diagnostic) = sequence_diagnostic(relation, previous, header, context) {
        diagnostics.push(diagnostic);
    }
    let next_state = if matches!(
        relation,
        SequenceRelation::InOrder | SequenceRelation::Gap(_)
    ) {
        next_state
    } else {
        None
    };
    StateAssessment {
        sequence_status,
        clock_status,
        loss_detected,
        diagnostics,
        next_state,
    }
}

fn translate_parser_diagnostics(
    datagram: &NetFlowV5Datagram,
    context: &ExportDatagramContext,
    diagnostics: &mut Vec<NetFlowV5NormalizationDiagnostic>,
) {
    for source in &datagram.diagnostics {
        let kind = match source.kind {
            NetFlowV5DiagnosticKind::NonzeroPadding => {
                NetFlowV5NormalizationDiagnosticKind::NonzeroPadding
            }
            NetFlowV5DiagnosticKind::SamplingConfigurationInvalid => {
                NetFlowV5NormalizationDiagnosticKind::SamplingInvalid
            }
            _ => continue,
        };
        let mut diagnostic =
            NetFlowV5NormalizationDiagnostic::datagram(kind, context, source.field);
        diagnostic.record_ordinal = source.record_ordinal;
        diagnostic.byte_offset = Some(source.byte_offset);
        diagnostics.push(diagnostic);
    }
}

fn sampling_quality(header: &NetFlowV5Header) -> (Fidelity, Option<u64>, bool) {
    match (header.sampling_mode, header.sampling_interval) {
        (0, 0) => (Fidelity::Exact, None, false),
        (1 | 2, interval) if interval > 0 => (Fidelity::Sampled, Some(u64::from(interval)), false),
        _ => (Fidelity::Unknown, None, true),
    }
}

fn tcp_flags(raw: u8) -> Vec<TcpFlag> {
    [
        (0x01, TcpFlag::Fin),
        (0x02, TcpFlag::Syn),
        (0x04, TcpFlag::Rst),
        (0x08, TcpFlag::Psh),
        (0x10, TcpFlag::Ack),
        (0x20, TcpFlag::Urg),
        (0x40, TcpFlag::Ece),
        (0x80, TcpFlag::Cwr),
    ]
    .into_iter()
    .filter_map(|(mask, flag)| (raw & mask != 0).then_some(flag))
    .collect()
}

fn source_record_id(
    header: &NetFlowV5Header,
    record: &NetFlowV5Record,
    context: &ExportDatagramContext,
) -> String {
    format!(
        "netflow_v5/{}/{}/{}/{}/{}/{}",
        context.exporter_id,
        header.engine_type,
        header.engine_id,
        header.flow_sequence,
        context.datagram_ordinal,
        record.record_ordinal
    )
}

#[derive(Clone, Debug)]
struct RecordFailure {
    kind: NetFlowV5NormalizationDiagnosticKind,
    record_ordinal: u8,
    field: &'static str,
    value_ms: Option<u64>,
    limit_ms: Option<u64>,
}

impl RecordFailure {
    fn into_diagnostic(self) -> NetFlowV5NormalizationDiagnostic {
        NetFlowV5NormalizationDiagnostic {
            kind: self.kind,
            datagram_ordinal: 0,
            record_ordinal: Some(self.record_ordinal),
            byte_offset: None,
            field: self.field,
            expected_sequence: None,
            actual_sequence: None,
            missing_records: None,
            value_ms: self.value_ms,
            limit_ms: self.limit_ms,
        }
    }
}

fn normalized_times(
    header: &NetFlowV5Header,
    record: &NetFlowV5Record,
    max_flow_age_ms: u64,
) -> Result<(String, String), RecordFailure> {
    let end_age_ms = u64::from(header.sys_uptime_ms.wrapping_sub(record.last_sys_uptime_ms));
    if end_age_ms > max_flow_age_ms {
        return Err(RecordFailure {
            kind: NetFlowV5NormalizationDiagnosticKind::FlowAgeExceeded,
            record_ordinal: record.record_ordinal,
            field: "end_age_ms",
            value_ms: Some(end_age_ms),
            limit_ms: Some(max_flow_age_ms),
        });
    }
    let duration_ms = u64::from(
        record
            .last_sys_uptime_ms
            .wrapping_sub(record.first_sys_uptime_ms),
    );
    if duration_ms > max_flow_age_ms {
        return Err(RecordFailure {
            kind: NetFlowV5NormalizationDiagnosticKind::FlowAgeExceeded,
            record_ordinal: record.record_ordinal,
            field: "duration_ms",
            value_ms: Some(duration_ms),
            limit_ms: Some(max_flow_age_ms),
        });
    }
    let export_ns = export_nanoseconds(header).ok_or(RecordFailure {
        kind: NetFlowV5NormalizationDiagnosticKind::TimestampOutOfRange,
        record_ordinal: record.record_ordinal,
        field: "export_time",
        value_ms: None,
        limit_ms: None,
    })?;
    let end_ns = export_ns
        .checked_sub(
            end_age_ms
                .checked_mul(NANOS_PER_MILLISECOND)
                .ok_or(RecordFailure {
                    kind: NetFlowV5NormalizationDiagnosticKind::TimestampOutOfRange,
                    record_ordinal: record.record_ordinal,
                    field: "end_time",
                    value_ms: None,
                    limit_ms: None,
                })?,
        )
        .ok_or(RecordFailure {
            kind: NetFlowV5NormalizationDiagnosticKind::TimestampUnderflow,
            record_ordinal: record.record_ordinal,
            field: "end_time",
            value_ms: Some(end_age_ms),
            limit_ms: None,
        })?;
    let start_ns = end_ns
        .checked_sub(
            duration_ms
                .checked_mul(NANOS_PER_MILLISECOND)
                .ok_or(RecordFailure {
                    kind: NetFlowV5NormalizationDiagnosticKind::TimestampOutOfRange,
                    record_ordinal: record.record_ordinal,
                    field: "start_time",
                    value_ms: None,
                    limit_ms: None,
                })?,
        )
        .ok_or(RecordFailure {
            kind: NetFlowV5NormalizationDiagnosticKind::TimestampUnderflow,
            record_ordinal: record.record_ordinal,
            field: "start_time",
            value_ms: Some(duration_ms),
            limit_ms: None,
        })?;
    let start = unix_nanoseconds_to_rfc3339(start_ns).map_err(|_| RecordFailure {
        kind: NetFlowV5NormalizationDiagnosticKind::TimestampOutOfRange,
        record_ordinal: record.record_ordinal,
        field: "start_time",
        value_ms: None,
        limit_ms: None,
    })?;
    let end = unix_nanoseconds_to_rfc3339(end_ns).map_err(|_| RecordFailure {
        kind: NetFlowV5NormalizationDiagnosticKind::TimestampOutOfRange,
        record_ordinal: record.record_ordinal,
        field: "end_time",
        value_ms: None,
        limit_ms: None,
    })?;
    Ok((start, end))
}

#[derive(Clone, Copy)]
struct CanonicalizationPolicy {
    max_flow_age_ms: u64,
    fidelity: Fidelity,
    sampling_rate: Option<u64>,
    loss_detected: bool,
}

fn canonicalize_record(
    header: &NetFlowV5Header,
    record: &NetFlowV5Record,
    context: &ExportDatagramContext,
    policy: CanonicalizationPolicy,
) -> Result<CanonicalObservation, NetFlowV5NormalizationDiagnostic> {
    let (start_time, end_time) = normalized_times(header, record, policy.max_flow_age_ms)
        .map_err(RecordFailure::into_diagnostic)?;
    let record_id = generate_netflow_v5_record_id(&NetFlowV5IdentityCoordinates {
        sensor_id: &context.sensor_id,
        input_sha256: &context.input_sha256,
        exporter_id: &context.exporter_id,
        engine_type: header.engine_type,
        engine_id: header.engine_id,
        flow_sequence: header.flow_sequence,
        datagram_ordinal: context.datagram_ordinal,
        record_ordinal: record.record_ordinal,
    })
    .map_err(|_error: InputIdentityError| {
        NetFlowV5NormalizationDiagnostic::record(
            NetFlowV5NormalizationDiagnosticKind::IdentityFailure,
            context,
            record.record_ordinal,
            "record_id",
        )
    })?;

    let has_transport_ports = matches!(record.protocol, 6 | 17 | 132);
    let flags = (record.protocol == 6).then(|| tcp_flags(record.tcp_flags));
    let flow = FlowData {
        start_time,
        end_time: Some(end_time),
        src_ip: record.src_addr.to_string(),
        dst_ip: record.dst_addr.to_string(),
        src_port: has_transport_ports.then_some(record.src_port),
        dst_port: has_transport_ports.then_some(record.dst_port),
        icmp_type: None,
        icmp_code: None,
        ip_protocol: record.protocol,
        direction_mode: DirectionMode::Unidirectional,
        service: None,
        connection_state: None,
        connection_history: None,
        tcp_flags: flags,
        end_reason: None,
        ingress_interface: Some(format!("ifindex:{}", record.input_ifindex)),
        egress_interface: Some(format!("ifindex:{}", record.output_ifindex)),
        counters: FlowCounters {
            src_to_dst: DirectionCounters {
                packets: Some(u64::from(record.packet_count)),
                payload_bytes: None,
                ip_bytes: Some(u64::from(record.octet_count)),
                l2_bytes: None,
            },
            dst_to_src: None,
        },
    };
    Ok(CanonicalObservation {
        schema_version: "1.0".to_string(),
        record_id,
        source_record_id: Some(source_record_id(header, record, context)),
        observation_type: ObservationType::Flow,
        telemetry_source: TelemetrySource::NetFlowV5,
        sensor_id: context.sensor_id.clone(),
        observed_at: context.observed_at.clone(),
        quality: Quality {
            fidelity: policy.fidelity,
            sampling_rate: policy.sampling_rate,
            sampling_probability: None,
            truncated: false,
            loss_detected: policy.loss_detected,
            missed_content_bytes: None,
        },
        provenance: Provenance {
            input_mode: context.input_mode,
            parser_name: NETFLOW_V5_NORMALIZER_NAME.to_string(),
            parser_version: NETFLOW_V5_NORMALIZER_VERSION.to_string(),
            input_sha256: Some(context.input_sha256.clone()),
            capture_interface: None,
            exporter_id: Some(context.exporter_id.clone()),
            observation_domain_id: None,
            template_id: None,
            message_sequence: Some(u64::from(header.flow_sequence)),
        },
        data: CanonicalData::Flow(flow),
    })
}
