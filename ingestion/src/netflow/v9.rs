//! F6: bounded lossless NetFlow v9 structure, not canonical field semantics.
//!
//! `parse_netflow_v9_wire` is pure full-packet framing/resource preflight.
//! `resolve_netflow_v9` applies F5 operations strictly in physical order. Errors
//! returned as `Err` have no state effects; subsequent failures are explicit
//! partial outcomes. A ResetRequired outcome requires caller quarantine/new
//! session epoch before further resolution; this module owns no session manager.
//! Unknown data is borrowed only by the current result, never queued in F5.

use super::template::{
    TemplateDefinition, TemplateFieldSpecifier, TemplateKey, TemplateKind, TemplateLookup,
    TemplateProtocol, TemplateRegistry, TemplateRegistryError, TemplateTimelineKey,
    TemplateTransition, TemplateWithdrawal, TransportSessionKey,
};
use std::fmt;

pub const NETFLOW_V9_HEADER_LEN: usize = 20;
const MAX_RECORD_BYTES: usize = u16::MAX as usize - 4;

/// Configurable project limits, not RFC constants. No limit-driven preallocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetFlowV9ParserConfig {
    max_datagram_bytes: usize,
    max_flowsets_per_datagram: usize,
    max_template_records_per_flowset: usize,
    max_template_records_per_datagram: usize,
    max_data_records_per_flowset: usize,
    max_data_records_per_datagram: usize,
    max_diagnostics_per_datagram: usize,
}

impl Default for NetFlowV9ParserConfig {
    fn default() -> Self {
        Self {
            max_datagram_bytes: 65_535,
            max_flowsets_per_datagram: 1_024,
            max_template_records_per_flowset: 512,
            max_template_records_per_datagram: 2_048,
            max_data_records_per_flowset: 4_096,
            max_data_records_per_datagram: 16_384,
            max_diagnostics_per_datagram: 128,
        }
    }
}

impl NetFlowV9ParserConfig {
    pub fn new(
        max_datagram_bytes: usize,
        max_flowsets_per_datagram: usize,
        max_template_records_per_flowset: usize,
        max_template_records_per_datagram: usize,
        max_data_records_per_flowset: usize,
        max_data_records_per_datagram: usize,
        max_diagnostics_per_datagram: usize,
    ) -> Result<Self, NetFlowV9ParseError> {
        for (field, value, element_size) in [
            ("max_datagram_bytes", max_datagram_bytes, 1),
            (
                "max_flowsets_per_datagram",
                max_flowsets_per_datagram,
                std::mem::size_of::<FlowSetOutcome<'static>>(),
            ),
            (
                "max_template_records_per_flowset",
                max_template_records_per_flowset,
                std::mem::size_of::<TemplateRecordOutcome<'static>>(),
            ),
            (
                "max_template_records_per_datagram",
                max_template_records_per_datagram,
                std::mem::size_of::<TemplateRecordOutcome<'static>>(),
            ),
            (
                "max_data_records_per_flowset",
                max_data_records_per_flowset,
                std::mem::size_of::<RecordView<'static>>(),
            ),
            (
                "max_data_records_per_datagram",
                max_data_records_per_datagram,
                std::mem::size_of::<RecordView<'static>>(),
            ),
        ] {
            if value == 0
                || value > u32::MAX as usize
                || value
                    .checked_mul(element_size)
                    .filter(|n| *n <= isize::MAX as usize)
                    .is_none()
            {
                return Err(NetFlowV9ParseError::InvalidConfig { field });
            }
        }
        // Largest diagnostic count: two per template plus three per FlowSet and
        // one count summary. Snapshot descriptors are bounded independently by
        // F5 AND the physical datagram. Reject unrepresentable owned budgets.
        let diagnostic_budget = max_template_records_per_datagram
            .checked_mul(2)
            .and_then(|n| {
                max_flowsets_per_datagram
                    .checked_mul(3)
                    .and_then(|f| n.checked_add(f))
            })
            .and_then(|n| n.checked_add(1));
        let snapshot_budget = max_flowsets_per_datagram
            .checked_mul(MAX_RECORD_BYTES / 4)
            .and_then(|n| n.checked_mul(std::mem::size_of::<TemplateFieldSpecifier>()));
        if diagnostic_budget.is_none()
            || snapshot_budget
                .filter(|n| *n <= isize::MAX as usize)
                .is_none()
            || max_diagnostics_per_datagram
                .checked_mul(std::mem::size_of::<NetFlowV9Diagnostic>())
                .filter(|n| *n <= isize::MAX as usize)
                .is_none()
        {
            return Err(NetFlowV9ParseError::InvalidConfig {
                field: "owned_budget",
            });
        }
        Ok(Self {
            max_datagram_bytes,
            max_flowsets_per_datagram,
            max_template_records_per_flowset,
            max_template_records_per_datagram,
            max_data_records_per_flowset,
            max_data_records_per_datagram,
            max_diagnostics_per_datagram,
        })
    }

    pub fn max_datagram_bytes(&self) -> usize {
        self.max_datagram_bytes
    }
    pub fn max_flowsets_per_datagram(&self) -> usize {
        self.max_flowsets_per_datagram
    }
    pub fn max_template_records_per_flowset(&self) -> usize {
        self.max_template_records_per_flowset
    }
    pub fn max_template_records_per_datagram(&self) -> usize {
        self.max_template_records_per_datagram
    }
    pub fn max_data_records_per_flowset(&self) -> usize {
        self.max_data_records_per_flowset
    }
    pub fn max_data_records_per_datagram(&self) -> usize {
        self.max_data_records_per_datagram
    }
    pub fn max_diagnostics_per_datagram(&self) -> usize {
        self.max_diagnostics_per_datagram
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetFlowV9Header {
    pub version: u16,
    pub count: u16,
    pub sys_uptime_ms: u32,
    pub unix_seconds: u32,
    pub sequence_number: u32,
    pub source_id: u32,
}

/// Caller supplies complete collector/exporter/transport/epoch identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetFlowV9ParseContext {
    pub session: TransportSessionKey,
    pub datagram_ordinal: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetFlowV9ParseError {
    InvalidConfig {
        field: &'static str,
    },
    LimitExceeded {
        field: &'static str,
        count: usize,
        limit: usize,
    },
    TruncatedHeader {
        available: usize,
    },
    MissingFlowSets,
    UnsupportedVersion {
        version: u16,
    },
    TrailingPacketBytes {
        offset: usize,
        available: usize,
    },
    InvalidFlowSetLength {
        offset: usize,
        length: u16,
    },
    FlowSetBeyondPacket {
        offset: usize,
        length: u16,
    },
    Arithmetic {
        offset: usize,
    },
    RegistryPrecheck(TemplateRegistryError),
}

impl fmt::Display for NetFlowV9ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetFlow v9 preflight: {self:?}")
    }
}
impl std::error::Error for NetFlowV9ParseError {}

impl NetFlowV9ParseError {
    /// No Err mutates F5. Nevertheless, a rejected/unframed source packet can
    /// hide a newer layout; callers must quarantine the session, not silently
    /// reuse cached layouts on subsequent packets. No automatic epoch inference.
    pub fn session_disposition(&self) -> SessionDisposition {
        match self {
            Self::InvalidConfig { .. }
            | Self::RegistryPrecheck(TemplateRegistryError::InvalidIdentity { .. }) => {
                SessionDisposition::Continue
            }
            _ => SessionDisposition::ResetRequired,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetFlowV9DiagnosticKind {
    ReservedFlowSetId,
    InvalidTemplateId,
    InvalidTemplateFieldCount,
    MalformedTemplateRecord,
    MalformedOptionsTemplateLengths,
    UnsupportedTemplateLayout,
    InvalidDataRecordLength,
    UnknownTemplate,
    ExpiredTemplate,
    InvalidPadding,
    UnalignedFlowSet,
    TemplateRegistryFailure,
    CountMismatch,
    LimitExceeded,
}

/// Only bounded typed/numeric metadata: never packet/identity strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetFlowV9Diagnostic {
    pub kind: NetFlowV9DiagnosticKind,
    pub datagram_ordinal: u64,
    pub flowset_ordinal: Option<u32>,
    pub record_ordinal: Option<u32>,
    pub byte_offset: usize,
    pub template_id: Option<u16>,
    pub count: Option<usize>,
    pub limit: Option<usize>,
    pub generation: Option<u64>,
    pub expires_at_ns: Option<u64>,
    pub registry_error: Option<TemplateRegistryError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountValidation {
    Match,
    Mismatch { declared: u16, parsed: usize },
    Inconclusive,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseCompletion {
    Complete,
    CompleteWithDiagnostics,
    StoppedAtLimit,
    StoppedForReset,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionDisposition {
    Continue,
    ResetRequired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataFlowSetState {
    Decoded,
    SkippedUnknown,
    SkippedExpired,
    Rejected,
    Unprocessed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldRole {
    Data,
    Scope,
    Option,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldValueView<'a> {
    pub field_ordinal: u32,
    pub role: FieldRole,
    pub specifier: TemplateFieldSpecifier,
    pub bytes: &'a [u8],
}

/// Private binding prevents callers pairing record bytes with another template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordView<'a> {
    pub record_ordinal: u32,
    pub byte_offset: usize,
    bytes: &'a [u8],
    definition: &'a TemplateDefinition,
}

impl<'a> RecordView<'a> {
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn fields(&self) -> FieldValueIter<'a> {
        FieldValueIter {
            bytes: self.bytes,
            definition: self.definition,
            ordinal: 0,
            offset: 0,
        }
    }
}

pub struct FieldValueIter<'a> {
    bytes: &'a [u8],
    definition: &'a TemplateDefinition,
    ordinal: usize,
    offset: usize,
}
impl<'a> Iterator for FieldValueIter<'a> {
    type Item = FieldValueView<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let specifier = *self.definition.fields().get(self.ordinal)?;
        let end = self
            .offset
            .checked_add(usize::from(specifier.encoded_length))?;
        let bytes = self.bytes.get(self.offset..end)?;
        let field_ordinal = u32::try_from(self.ordinal).ok()?;
        let role = match self.definition.kind() {
            TemplateKind::Data => FieldRole::Data,
            TemplateKind::Options
                if self.ordinal < usize::from(self.definition.scope_field_count()) =>
            {
                FieldRole::Scope
            }
            TemplateKind::Options => FieldRole::Option,
        };
        self.ordinal = self.ordinal.checked_add(1)?;
        self.offset = end;
        Some(FieldValueView {
            field_ordinal,
            role,
            specifier,
            bytes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateSnapshot {
    pub key: TemplateKey,
    pub generation: u64,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub expires_at_ns: u64,
    definition: TemplateDefinition,
    record_length: usize,
}
impl TemplateSnapshot {
    pub fn definition(&self) -> &TemplateDefinition {
        &self.definition
    }
    pub fn record_length(&self) -> usize {
        self.record_length
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataFlowSetOutcome<'a> {
    pub state: DataFlowSetState,
    pub local_invalidation: Option<TemplateWithdrawal>,
    snapshot: Option<TemplateSnapshot>,
    record_bytes: &'a [u8],
    pub record_count: usize,
    pub records_byte_offset: usize,
    pub padding: &'a [u8],
}
impl<'a> DataFlowSetOutcome<'a> {
    pub fn snapshot(&self) -> Option<&TemplateSnapshot> {
        self.snapshot.as_ref()
    }
    /// Borrow one immutable snapshot per FlowSet; no owned per-record/field values.
    pub fn records(&self) -> impl Iterator<Item = RecordView<'_>> {
        self.snapshot.iter().flat_map(move |snapshot| {
            self.record_bytes
                .chunks_exact(snapshot.record_length)
                .enumerate()
                .filter_map(move |(ordinal, bytes)| {
                    let record_ordinal = u32::try_from(ordinal).ok()?;
                    let byte_offset = ordinal
                        .checked_mul(snapshot.record_length)?
                        .checked_add(self.records_byte_offset)?;
                    Some(RecordView {
                        record_ordinal,
                        byte_offset,
                        bytes,
                        definition: &snapshot.definition,
                    })
                })
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateRecordState {
    Applied(TemplateTransition),
    Rejected {
        reason: NetFlowV9DiagnosticKind,
        local_invalidation: Option<TemplateWithdrawal>,
    },
    Unprocessed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateRecordOutcome<'a> {
    pub record_ordinal: u32,
    pub byte_offset: usize,
    pub template_id: Option<u16>,
    pub scope_field_count: u16,
    pub field_count: usize,
    pub state: TemplateRecordState,
    pub raw_record: &'a [u8],
    descriptors: &'a [u8],
}
impl TemplateRecordOutcome<'_> {
    /// Includes unsupported descriptors (e.g. zero width); malformed byte-length
    /// records expose raw_record instead, never pretend to have field structure.
    pub fn descriptors(&self) -> impl Iterator<Item = TemplateFieldSpecifier> + '_ {
        self.descriptors.as_chunks::<4>().0.iter().filter_map(|b| {
            Some(TemplateFieldSpecifier {
                field_id: read_u16(b, 0).ok()?,
                encoded_length: read_u16(b, 2).ok()?,
                enterprise_number: None,
            })
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowSetContent<'a> {
    Templates {
        kind: TemplateKind,
        records: Vec<TemplateRecordOutcome<'a>>,
        padding: &'a [u8],
    },
    Data(DataFlowSetOutcome<'a>),
    Reserved,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowSetOutcome<'a> {
    pub flowset_ordinal: u32,
    pub byte_offset: usize,
    pub flowset_id: u16,
    pub length: u16,
    pub raw_payload: &'a [u8],
    pub processed: bool,
    pub content: FlowSetContent<'a>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetFlowV9ParseOutcome<'a> {
    pub header: NetFlowV9Header,
    pub context: NetFlowV9ParseContext,
    pub source_time_ns: u64,
    pub flowsets: Vec<FlowSetOutcome<'a>>,
    pub count_validation: CountValidation,
    pub completion: ParseCompletion,
    pub session_disposition: SessionDisposition,
    pub diagnostics: Vec<NetFlowV9Diagnostic>,
    pub diagnostics_total: usize,
    pub diagnostics_dropped: usize,
    pub decoded_record_count: usize,
}

// Controlled constructors: offsets/slices cannot be forged by public callers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetFlowV9WireDatagram<'a> {
    header: NetFlowV9Header,
    flowsets: Vec<WireFlowSet<'a>>,
    config: NetFlowV9ParserConfig,
}
impl NetFlowV9WireDatagram<'_> {
    pub fn header(&self) -> &NetFlowV9Header {
        &self.header
    }
    pub fn flowset_count(&self) -> usize {
        self.flowsets.len()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct WireFlowSet<'a> {
    ordinal: u32,
    offset: usize,
    payload_offset: usize,
    end_offset: usize,
    id: u16,
    length: u16,
    payload: &'a [u8],
    templates: Vec<WireTemplate<'a>>,
    padding: &'a [u8],
    suffix_error: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct WireTemplate<'a> {
    ordinal: u32,
    offset: usize,
    id: Option<u16>,
    scope: u16,
    count: usize,
    raw: &'a [u8],
    descriptors: &'a [u8],
    error: Option<NetFlowV9DiagnosticKind>,
    boundary_trusted: bool,
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], NetFlowV9ParseError> {
    let end = offset
        .checked_add(N)
        .ok_or(NetFlowV9ParseError::Arithmetic { offset })?;
    bytes
        .get(offset..end)
        .and_then(|b| b.try_into().ok())
        .ok_or(NetFlowV9ParseError::Arithmetic { offset })
}
fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, NetFlowV9ParseError> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, NetFlowV9ParseError> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}
fn limit(count: usize, cap: usize, field: &'static str) -> Result<(), NetFlowV9ParseError> {
    if count > cap {
        Err(NetFlowV9ParseError::LimitExceeded {
            field,
            count,
            limit: cap,
        })
    } else {
        Ok(())
    }
}
fn add(a: usize, b: usize) -> Result<usize, NetFlowV9ParseError> {
    a.checked_add(b)
        .ok_or(NetFlowV9ParseError::Arithmetic { offset: a })
}

/// Pure checked framing plus template-record resource preflight. Wire records
/// borrow descriptors; F5 field bounds are enforced before owned construction.
pub fn parse_netflow_v9_wire(
    bytes: &[u8],
    config: NetFlowV9ParserConfig,
) -> Result<NetFlowV9WireDatagram<'_>, NetFlowV9ParseError> {
    limit(bytes.len(), config.max_datagram_bytes, "datagram_bytes")?;
    if bytes.len() < NETFLOW_V9_HEADER_LEN {
        return Err(NetFlowV9ParseError::TruncatedHeader {
            available: bytes.len(),
        });
    }
    let header = NetFlowV9Header {
        version: read_u16(bytes, 0)?,
        count: read_u16(bytes, 2)?,
        sys_uptime_ms: read_u32(bytes, 4)?,
        unix_seconds: read_u32(bytes, 8)?,
        sequence_number: read_u32(bytes, 12)?,
        source_id: read_u32(bytes, 16)?,
    };
    if header.version != 9 {
        return Err(NetFlowV9ParseError::UnsupportedVersion {
            version: header.version,
        });
    }
    let mut flowsets = Vec::new();
    let mut offset = NETFLOW_V9_HEADER_LEN;
    while offset < bytes.len() {
        let available = bytes.len() - offset;
        if available < 4 {
            return Err(NetFlowV9ParseError::TrailingPacketBytes { offset, available });
        }
        let id = read_u16(bytes, offset)?;
        let length = read_u16(bytes, add(offset, 2)?)?;
        if length < 4 {
            return Err(NetFlowV9ParseError::InvalidFlowSetLength { offset, length });
        }
        let end = add(offset, usize::from(length))?;
        let payload = bytes
            .get(add(offset, 4)?..end)
            .ok_or(NetFlowV9ParseError::FlowSetBeyondPacket { offset, length })?;
        limit(
            add(flowsets.len(), 1)?,
            config.max_flowsets_per_datagram,
            "flowsets",
        )?;
        let ordinal = u32::try_from(flowsets.len())
            .map_err(|_| NetFlowV9ParseError::Arithmetic { offset })?;
        flowsets.push(WireFlowSet {
            ordinal,
            offset,
            payload_offset: add(offset, 4)?,
            end_offset: end,
            id,
            length,
            payload,
            templates: Vec::new(),
            padding: &[],
            suffix_error: false,
        });
        offset = end;
    }
    if flowsets.is_empty() {
        return Err(NetFlowV9ParseError::MissingFlowSets);
    }
    // Full outer framing above precedes even template record scanning.
    let mut total_templates = 0;
    for flowset in &mut flowsets {
        if flowset.id <= 1 {
            parse_wire_templates(flowset, config, &mut total_templates)?;
        }
    }
    Ok(NetFlowV9WireDatagram {
        header,
        flowsets,
        config,
    })
}

fn parse_wire_templates<'a>(
    flowset: &mut WireFlowSet<'a>,
    config: NetFlowV9ParserConfig,
    total: &mut usize,
) -> Result<(), NetFlowV9ParseError> {
    let bytes = flowset.payload;
    let header_length = if flowset.id == 0 { 4 } else { 6 };
    let mut offset = 0;
    while offset < bytes.len() {
        let rest = bytes
            .get(offset..)
            .ok_or(NetFlowV9ParseError::Arithmetic { offset })?;
        if rest.len() <= 3 {
            flowset.padding = rest;
            flowset.suffix_error = rest.iter().any(|b| *b != 0);
            break;
        }
        limit(
            add(flowset.templates.len(), 1)?,
            config.max_template_records_per_flowset,
            "templates_per_flowset",
        )?;
        *total = add(*total, 1)?;
        limit(
            *total,
            config.max_template_records_per_datagram,
            "templates_per_datagram",
        )?;
        let ordinal = u32::try_from(flowset.templates.len())
            .map_err(|_| NetFlowV9ParseError::Arithmetic { offset })?;
        let absolute = add(flowset.payload_offset, offset)?;
        let id = read_u16(rest, 0).ok();
        if rest.len() < header_length {
            flowset.templates.push(WireTemplate {
                ordinal,
                offset: absolute,
                id,
                scope: 0,
                count: 0,
                raw: rest,
                descriptors: &[],
                error: Some(NetFlowV9DiagnosticKind::MalformedTemplateRecord),
                boundary_trusted: false,
            });
            break;
        }
        let (scope, count, descriptor_length, mut error) = if flowset.id == 0 {
            let count = usize::from(read_u16(rest, 2)?);
            (
                0,
                count,
                count
                    .checked_mul(4)
                    .ok_or(NetFlowV9ParseError::Arithmetic { offset })?,
                None,
            )
        } else {
            let scope_bytes = usize::from(read_u16(rest, 2)?);
            let option_bytes = usize::from(read_u16(rest, 4)?);
            let malformed = scope_bytes % 4 != 0 || option_bytes % 4 != 0;
            let scope = u16::try_from(scope_bytes / 4)
                .map_err(|_| NetFlowV9ParseError::Arithmetic { offset })?;
            (
                scope,
                add(scope_bytes / 4, option_bytes / 4)?,
                add(scope_bytes, option_bytes)?,
                malformed.then_some(NetFlowV9DiagnosticKind::MalformedOptionsTemplateLengths),
            )
        };
        let extent = add(header_length, descriptor_length)?;
        if extent > rest.len() {
            flowset.templates.push(WireTemplate {
                ordinal,
                offset: absolute,
                id,
                scope,
                count,
                raw: rest,
                descriptors: &[],
                error: Some(NetFlowV9DiagnosticKind::MalformedTemplateRecord),
                boundary_trusted: false,
            });
            break;
        }
        if id.is_some_and(|n| n < 256) && error.is_none() {
            error = Some(NetFlowV9DiagnosticKind::InvalidTemplateId);
        }
        if count == 0 && error.is_none() {
            error = Some(NetFlowV9DiagnosticKind::InvalidTemplateFieldCount);
        }
        let descriptors = if error == Some(NetFlowV9DiagnosticKind::MalformedOptionsTemplateLengths)
        {
            &[][..]
        } else {
            rest.get(header_length..extent)
                .ok_or(NetFlowV9ParseError::Arithmetic { offset })?
        };
        flowset.templates.push(WireTemplate {
            ordinal,
            offset: absolute,
            id,
            scope,
            count,
            raw: rest
                .get(..extent)
                .ok_or(NetFlowV9ParseError::Arithmetic { offset })?,
            descriptors,
            error,
            boundary_trusted: true,
        });
        offset = add(offset, extent)?;
    }
    Ok(())
}

struct Resolver<'a> {
    outcome: NetFlowV9ParseOutcome<'a>,
    config: NetFlowV9ParserConfig,
    parsed_count: usize,
    reliable: bool,
}
impl Resolver<'_> {
    fn diagnostic(
        &mut self,
        kind: NetFlowV9DiagnosticKind,
        fs: Option<&WireFlowSet<'_>>,
        record: Option<&WireTemplate<'_>>,
    ) -> NetFlowV9Diagnostic {
        NetFlowV9Diagnostic {
            kind,
            datagram_ordinal: self.outcome.context.datagram_ordinal,
            flowset_ordinal: fs.map(|f| f.ordinal),
            record_ordinal: record.map(|r| r.ordinal),
            byte_offset: record.map_or_else(|| fs.map_or(2, |f| f.offset), |r| r.offset),
            template_id: record
                .and_then(|r| r.id)
                .or_else(|| fs.filter(|f| f.id >= 256).map(|f| f.id)),
            count: None,
            limit: None,
            generation: None,
            expires_at_ns: None,
            registry_error: None,
        }
    }
    fn emit(&mut self, diagnostic: NetFlowV9Diagnostic) {
        // Config validation proves total diagnostics <= 2*T + 3*S + 1.
        // Still use checked accounting; an impossible overflow fails closed.
        if let Some(total) = self.outcome.diagnostics_total.checked_add(1) {
            self.outcome.diagnostics_total = total;
        } else {
            self.reset();
            return;
        }
        if self.outcome.diagnostics.len() < self.config.max_diagnostics_per_datagram {
            self.outcome.diagnostics.push(diagnostic);
        } else if let Some(dropped) = self.outcome.diagnostics_dropped.checked_add(1) {
            self.outcome.diagnostics_dropped = dropped;
        } else {
            self.reset();
        }
    }
    fn reset(&mut self) {
        self.reliable = false;
        self.outcome.completion = ParseCompletion::StoppedForReset;
        self.outcome.session_disposition = SessionDisposition::ResetRequired;
    }
    fn registry_failure(
        &mut self,
        fs: &WireFlowSet<'_>,
        record: Option<&WireTemplate<'_>>,
        error: TemplateRegistryError,
    ) {
        let mut diagnostic = self.diagnostic(
            NetFlowV9DiagnosticKind::TemplateRegistryFailure,
            Some(fs),
            record,
        );
        diagnostic.registry_error = Some(error);
        self.emit(diagnostic);
    }
    fn increment_count(&mut self, count: usize) {
        if let Some(total) = self.parsed_count.checked_add(count) {
            self.parsed_count = total;
        } else {
            self.reset();
        }
    }
}

fn record_length(definition: &TemplateDefinition) -> Option<usize> {
    // Bound snapshots of caller-prepopulated F5 definitions as well as wire ones.
    if definition.fields().len() > MAX_RECORD_BYTES / 4 {
        return None;
    }
    definition
        .fields()
        .iter()
        .try_fold(0_usize, |total, field| {
            if field.encoded_length == 0 || field.enterprise_number.is_some() {
                return None;
            }
            total
                .checked_add(usize::from(field.encoded_length))
                .filter(|n| *n <= MAX_RECORD_BYTES)
        })
        .filter(|n| *n > 0)
}

fn empty_data<'a>(fs: &WireFlowSet<'a>) -> DataFlowSetOutcome<'a> {
    DataFlowSetOutcome {
        state: DataFlowSetState::Unprocessed,
        local_invalidation: None,
        snapshot: None,
        record_bytes: &[],
        record_count: 0,
        records_byte_offset: fs.payload_offset,
        padding: &[],
    }
}

/// All ordinary Err paths occur before any mutation. Use the partial outcome's
/// completion/disposition even when diagnostic retention is configured to zero.
pub fn resolve_netflow_v9<'a>(
    wire: NetFlowV9WireDatagram<'a>,
    context: NetFlowV9ParseContext,
    registry: &mut TemplateRegistry,
) -> Result<NetFlowV9ParseOutcome<'a>, NetFlowV9ParseError> {
    // Revalidate context against THIS registry's bound; callers can construct a
    // session under a larger limit. No inferred endpoint/session fallback.
    TransportSessionKey::new(
        context.session.exporter_id(),
        context.session.session_id(),
        registry.config().max_identity_bytes(),
    )
    .map_err(NetFlowV9ParseError::RegistryPrecheck)?;
    let source_time_ns = u64::from(wire.header.unix_seconds)
        .checked_mul(1_000_000_000)
        .ok_or(NetFlowV9ParseError::Arithmetic { offset: 8 })?;
    let timeline = TemplateTimelineKey::new(
        TemplateProtocol::NetFlowV9,
        context.session.clone(),
        wire.header.source_id,
    );
    if let Some(previous_ns) = registry.timeline_last_source_time_ns(&timeline) {
        if source_time_ns < previous_ns {
            return Err(NetFlowV9ParseError::RegistryPrecheck(
                TemplateRegistryError::SourceTimeRegression {
                    previous_ns,
                    provided_ns: source_time_ns,
                },
            ));
        }
    }
    let mut resolver = Resolver {
        outcome: NetFlowV9ParseOutcome {
            header: wire.header,
            context,
            source_time_ns,
            flowsets: Vec::new(),
            count_validation: CountValidation::Inconclusive,
            completion: ParseCompletion::Complete,
            session_disposition: SessionDisposition::Continue,
            diagnostics: Vec::new(),
            diagnostics_total: 0,
            diagnostics_dropped: 0,
            decoded_record_count: 0,
        },
        config: wire.config,
        parsed_count: 0,
        reliable: true,
    };
    for fs in &wire.flowsets {
        let mut result = FlowSetOutcome {
            flowset_ordinal: fs.ordinal,
            byte_offset: fs.offset,
            flowset_id: fs.id,
            length: fs.length,
            raw_payload: fs.payload,
            processed: false,
            content: FlowSetContent::Reserved,
        };
        let continuing = matches!(
            resolver.outcome.completion,
            ParseCompletion::Complete | ParseCompletion::CompleteWithDiagnostics
        );
        if fs.id <= 1 {
            let kind = if fs.id == 0 {
                TemplateKind::Data
            } else {
                TemplateKind::Options
            };
            let mut records = Vec::new();
            if continuing {
                result.processed = true;
                warn_unaligned(&mut resolver, fs);
                if fs.templates.is_empty() {
                    let diagnostic = resolver.diagnostic(
                        NetFlowV9DiagnosticKind::MalformedTemplateRecord,
                        Some(fs),
                        None,
                    );
                    resolver.emit(diagnostic);
                    resolver.reset();
                }
            }
            for record in &fs.templates {
                let mut record_result = TemplateRecordOutcome {
                    record_ordinal: record.ordinal,
                    byte_offset: record.offset,
                    template_id: record.id,
                    scope_field_count: record.scope,
                    field_count: record.count,
                    raw_record: record.raw,
                    descriptors: record.descriptors,
                    state: TemplateRecordState::Unprocessed,
                };
                if continuing
                    && resolver.outcome.session_disposition == SessionDisposition::Continue
                {
                    apply_template(
                        &mut resolver,
                        registry,
                        fs,
                        record,
                        kind,
                        &mut record_result,
                    );
                }
                records.push(record_result);
            }
            if continuing
                && resolver.outcome.session_disposition == SessionDisposition::Continue
                && fs.suffix_error
            {
                let mut diagnostic =
                    resolver.diagnostic(NetFlowV9DiagnosticKind::InvalidPadding, Some(fs), None);
                if let Some(offset) = fs.end_offset.checked_sub(fs.padding.len()) {
                    diagnostic.byte_offset = offset;
                }
                resolver.emit(diagnostic);
                resolver.reset();
            }
            result.content = FlowSetContent::Templates {
                kind,
                records,
                padding: fs.padding,
            };
        } else if fs.id >= 256 {
            let mut data = empty_data(fs);
            if continuing {
                result.processed = true;
                warn_unaligned(&mut resolver, fs);
                apply_data(&mut resolver, registry, fs, &mut data);
            }
            result.content = FlowSetContent::Data(data);
        } else if continuing {
            result.processed = true;
            warn_unaligned(&mut resolver, fs);
            let diagnostic =
                resolver.diagnostic(NetFlowV9DiagnosticKind::ReservedFlowSetId, Some(fs), None);
            resolver.emit(diagnostic);
            resolver.reliable = false;
        }
        resolver.outcome.flowsets.push(result);
    }
    if resolver.reliable {
        resolver.outcome.count_validation =
            if resolver.parsed_count == usize::from(wire.header.count) {
                CountValidation::Match
            } else {
                CountValidation::Mismatch {
                    declared: wire.header.count,
                    parsed: resolver.parsed_count,
                }
            };
        if matches!(
            resolver.outcome.count_validation,
            CountValidation::Mismatch { .. }
        ) {
            let mut diagnostic =
                resolver.diagnostic(NetFlowV9DiagnosticKind::CountMismatch, None, None);
            diagnostic.count = Some(resolver.parsed_count);
            diagnostic.limit = Some(usize::from(wire.header.count));
            resolver.emit(diagnostic);
        }
    }
    if resolver.outcome.completion == ParseCompletion::Complete
        && resolver.outcome.diagnostics_total > 0
    {
        resolver.outcome.completion = ParseCompletion::CompleteWithDiagnostics;
    }
    Ok(resolver.outcome)
}

pub fn parse_netflow_v9<'a>(
    bytes: &'a [u8],
    context: NetFlowV9ParseContext,
    registry: &mut TemplateRegistry,
    config: NetFlowV9ParserConfig,
) -> Result<NetFlowV9ParseOutcome<'a>, NetFlowV9ParseError> {
    resolve_netflow_v9(parse_netflow_v9_wire(bytes, config)?, context, registry)
}

fn warn_unaligned(resolver: &mut Resolver<'_>, fs: &WireFlowSet<'_>) {
    if !fs.length.is_multiple_of(4) {
        let diagnostic =
            resolver.diagnostic(NetFlowV9DiagnosticKind::UnalignedFlowSet, Some(fs), None);
        resolver.emit(diagnostic);
    }
}

fn apply_template(
    resolver: &mut Resolver<'_>,
    registry: &mut TemplateRegistry,
    fs: &WireFlowSet<'_>,
    record: &WireTemplate<'_>,
    kind: TemplateKind,
    result: &mut TemplateRecordOutcome<'_>,
) {
    let key = record.id.and_then(|id| {
        TemplateKey::new(
            TemplateProtocol::NetFlowV9,
            resolver.outcome.context.session.clone(),
            resolver.outcome.header.source_id,
            id,
        )
        .ok()
    });
    let mut reason = record.error;
    let mut registry_error = None;
    if reason.is_none() {
        if record.count > registry.config().max_fields_per_template() {
            reason = Some(NetFlowV9DiagnosticKind::InvalidTemplateFieldCount);
        } else {
            // Count/boundary validated BEFORE allocating owned descriptors.
            let fields: Vec<_> = result.descriptors().collect();
            match TemplateDefinition::new(
                kind,
                record.scope,
                &fields,
                registry.config().max_fields_per_template(),
            ) {
                Ok(definition) if record_length(&definition).is_some() => {
                    if let Some(key) = key.as_ref() {
                        match registry.insert(
                            key.clone(),
                            definition,
                            resolver.outcome.source_time_ns,
                        ) {
                            Ok(transition) => {
                                result.state = TemplateRecordState::Applied(transition);
                                resolver.increment_count(1);
                                return;
                            }
                            Err(error) => {
                                registry_error = Some(error);
                                reason = Some(NetFlowV9DiagnosticKind::TemplateRegistryFailure);
                            }
                        }
                    } else {
                        reason = Some(NetFlowV9DiagnosticKind::InvalidTemplateId);
                    }
                }
                Ok(_) => {
                    reason = Some(NetFlowV9DiagnosticKind::UnsupportedTemplateLayout);
                }
                Err(error) => {
                    registry_error = Some(error);
                    reason = Some(NetFlowV9DiagnosticKind::InvalidTemplateFieldCount);
                }
            }
        }
    }
    let reason = reason.unwrap_or(NetFlowV9DiagnosticKind::MalformedTemplateRecord);
    let mut diagnostic = resolver.diagnostic(reason, Some(fs), Some(record));
    diagnostic.registry_error = registry_error;
    if reason == NetFlowV9DiagnosticKind::InvalidTemplateFieldCount {
        diagnostic.count = Some(record.count);
        diagnostic.limit = Some(registry.config().max_fields_per_template());
    }
    resolver.emit(diagnostic);
    resolver.reliable = false;
    let invalidation = if record.boundary_trusted {
        if let Some(key) = key {
            match registry.withdraw(&key, resolver.outcome.source_time_ns) {
                Ok(invalidation) => Some(invalidation),
                Err(error) => {
                    resolver.registry_failure(fs, Some(record), error);
                    resolver.reset();
                    None
                }
            }
        } else {
            resolver.reset();
            None
        }
    } else {
        resolver.reset();
        None
    };
    result.state = TemplateRecordState::Rejected {
        reason,
        local_invalidation: invalidation,
    };
}

fn apply_data<'a>(
    resolver: &mut Resolver<'a>,
    registry: &mut TemplateRegistry,
    fs: &WireFlowSet<'a>,
    data: &mut DataFlowSetOutcome<'a>,
) {
    let key = match TemplateKey::new(
        TemplateProtocol::NetFlowV9,
        resolver.outcome.context.session.clone(),
        resolver.outcome.header.source_id,
        fs.id,
    ) {
        Ok(key) => key,
        Err(error) => {
            resolver.registry_failure(fs, None, error);
            resolver.reset();
            data.state = DataFlowSetState::Rejected;
            return;
        }
    };
    let entry = match registry.lookup(&key, resolver.outcome.source_time_ns) {
        Ok(TemplateLookup::Found(entry)) => entry,
        Ok(TemplateLookup::Unknown) => {
            let diagnostic =
                resolver.diagnostic(NetFlowV9DiagnosticKind::UnknownTemplate, Some(fs), None);
            resolver.emit(diagnostic);
            resolver.reliable = false;
            data.state = DataFlowSetState::SkippedUnknown;
            return;
        }
        Ok(TemplateLookup::Expired {
            generation,
            expires_at_ns,
        }) => {
            let mut diagnostic =
                resolver.diagnostic(NetFlowV9DiagnosticKind::ExpiredTemplate, Some(fs), None);
            diagnostic.generation = Some(generation);
            diagnostic.expires_at_ns = Some(expires_at_ns);
            resolver.emit(diagnostic);
            resolver.reliable = false;
            data.state = DataFlowSetState::SkippedExpired;
            return;
        }
        Err(error) => {
            resolver.registry_failure(fs, None, error);
            resolver.reset();
            data.state = DataFlowSetState::Rejected;
            return;
        }
    };
    let length = match record_length(entry.definition()) {
        Some(length) => length,
        None => {
            let diagnostic = resolver.diagnostic(
                NetFlowV9DiagnosticKind::UnsupportedTemplateLayout,
                Some(fs),
                None,
            );
            resolver.emit(diagnostic);
            resolver.reliable = false;
            data.state = DataFlowSetState::Rejected;
            match registry.withdraw(&key, resolver.outcome.source_time_ns) {
                Ok(invalidation) => {
                    data.local_invalidation = Some(invalidation);
                }
                Err(error) => {
                    resolver.registry_failure(fs, None, error);
                    resolver.reset();
                }
            }
            return;
        }
    };
    let snapshot = TemplateSnapshot {
        key,
        generation: entry.generation(),
        definition: entry.definition().clone(),
        record_length: length,
        first_seen_ns: entry.first_seen_ns(),
        last_seen_ns: entry.last_seen_ns(),
        expires_at_ns: entry.expires_at_ns(),
    };
    let count = fs.payload.len() / length;
    let remainder = fs.payload.len() % length;
    let record_bytes_length = match count.checked_mul(length) {
        Some(n) => n,
        None => {
            resolver.reset();
            data.state = DataFlowSetState::Rejected;
            return;
        }
    };
    let padding = match fs.payload.get(record_bytes_length..) {
        Some(p) => p,
        None => {
            resolver.reset();
            data.state = DataFlowSetState::Rejected;
            return;
        }
    };
    data.snapshot = Some(snapshot);
    data.padding = padding;
    if count == 0 {
        let mut diagnostic = resolver.diagnostic(
            NetFlowV9DiagnosticKind::InvalidDataRecordLength,
            Some(fs),
            None,
        );
        diagnostic.count = Some(0);
        diagnostic.limit = Some(1);
        resolver.emit(diagnostic);
        resolver.reliable = false;
        data.state = DataFlowSetState::Rejected;
        return;
    }
    if remainder > 3 || padding.iter().any(|b| *b != 0) {
        let mut diagnostic =
            resolver.diagnostic(NetFlowV9DiagnosticKind::InvalidPadding, Some(fs), None);
        if let Some(offset) = fs.payload_offset.checked_add(record_bytes_length) {
            diagnostic.byte_offset = offset;
        }
        diagnostic.count = Some(remainder);
        diagnostic.limit = Some(3);
        resolver.emit(diagnostic);
        resolver.reliable = false;
        data.state = DataFlowSetState::Rejected;
        return;
    }
    if count > resolver.config.max_data_records_per_flowset {
        let mut diagnostic =
            resolver.diagnostic(NetFlowV9DiagnosticKind::LimitExceeded, Some(fs), None);
        diagnostic.count = Some(count);
        diagnostic.limit = Some(resolver.config.max_data_records_per_flowset);
        resolver.emit(diagnostic);
        resolver.reliable = false;
        data.state = DataFlowSetState::Rejected;
        return;
    }
    let total = resolver.outcome.decoded_record_count.checked_add(count);
    if total.is_none_or(|n| n > resolver.config.max_data_records_per_datagram) {
        let mut diagnostic =
            resolver.diagnostic(NetFlowV9DiagnosticKind::LimitExceeded, Some(fs), None);
        diagnostic.count = total;
        diagnostic.limit = Some(resolver.config.max_data_records_per_datagram);
        resolver.emit(diagnostic);
        resolver.reliable = false;
        resolver.outcome.completion = ParseCompletion::StoppedAtLimit;
        // Current lookup effects (watermark/expiry) remain applied and visible;
        // no decoded prefix of this FlowSet is returned, no later work occurs.
        data.state = DataFlowSetState::Rejected;
        return;
    }
    if let (Some(total), Some(record_bytes)) = (total, fs.payload.get(..record_bytes_length)) {
        resolver.outcome.decoded_record_count = total;
        resolver.increment_count(count);
        data.record_bytes = record_bytes;
        data.record_count = count;
        data.state = DataFlowSetState::Decoded;
    } else {
        resolver.reset();
        data.state = DataFlowSetState::Rejected;
    }
}
