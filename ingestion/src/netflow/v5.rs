//! Strict, lossless decoding of one complete NetFlow v5 UDP payload.
//!
//! This module intentionally stops at the wire representation. It does not
//! normalize timestamps, extrapolate sampled counters, track sequences, create
//! identities, or emit canonical observations.

use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;

/// Size of the fixed NetFlow v5 header in bytes.
pub const NETFLOW_V5_HEADER_LEN: usize = 24;
/// Size of one fixed NetFlow v5 record in bytes.
pub const NETFLOW_V5_RECORD_LEN: usize = 48;
/// Smallest record count permitted by the NetFlow v5 wire format.
pub const NETFLOW_V5_MIN_RECORDS: u16 = 1;
/// Largest record count permitted by the NetFlow v5 wire format.
pub const NETFLOW_V5_MAX_RECORDS: u16 = 30;

/// Lossless representation of the fixed NetFlow v5 datagram header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetFlowV5Header {
    pub version: u16,
    pub count: u16,
    pub sys_uptime_ms: u32,
    pub unix_secs: u32,
    pub unix_nsecs: u32,
    pub flow_sequence: u32,
    pub engine_type: u8,
    pub engine_id: u8,
    pub raw_sampling: u16,
    pub sampling_mode: u8,
    pub sampling_interval: u16,
}

/// Lossless representation of one fixed NetFlow v5 record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetFlowV5Record {
    /// Zero-based physical position of this record in the UDP payload.
    pub record_ordinal: u8,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub next_hop: Ipv4Addr,
    pub input_ifindex: u16,
    pub output_ifindex: u16,
    pub packet_count: u32,
    pub octet_count: u32,
    pub first_sys_uptime_ms: u32,
    pub last_sys_uptime_ms: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub pad1: u8,
    pub tcp_flags: u8,
    pub protocol: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub pad2: u16,
}

/// A complete decoded NetFlow v5 UDP payload plus nonfatal source diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetFlowV5Datagram {
    pub header: NetFlowV5Header,
    pub records: Vec<NetFlowV5Record>,
    pub diagnostics: Vec<NetFlowV5Diagnostic>,
}

/// Bounded diagnostic categories emitted by the F2 source decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetFlowV5DiagnosticKind {
    UnsupportedVersion,
    TruncatedHeader,
    InvalidRecordCount,
    InvalidDatagramLength,
    InvalidUnixNanoseconds,
    NonzeroPadding,
    SamplingConfigurationInvalid,
}

/// A diagnostic with deterministic, bounded coordinates and no packet bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetFlowV5Diagnostic {
    pub kind: NetFlowV5DiagnosticKind,
    /// Byte offset in the supplied UDP payload, or its EOF for truncation.
    pub byte_offset: usize,
    /// Physical record ordinal when the diagnostic belongs to a record.
    pub record_ordinal: Option<u8>,
    /// Static wire-field name; never contains source-controlled content.
    pub field: &'static str,
}

impl NetFlowV5Diagnostic {
    fn fatal(
        kind: NetFlowV5DiagnosticKind,
        byte_offset: usize,
        field: &'static str,
    ) -> NetFlowV5ParseError {
        NetFlowV5ParseError {
            diagnostic: Self {
                kind,
                byte_offset,
                record_ordinal: None,
                field,
            },
        }
    }

    fn for_record(
        kind: NetFlowV5DiagnosticKind,
        byte_offset: usize,
        record_ordinal: u8,
        field: &'static str,
    ) -> Self {
        Self {
            kind,
            byte_offset,
            record_ordinal: Some(record_ordinal),
            field,
        }
    }
}

/// Fatal structural error. A fatal error never returns a partial datagram.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetFlowV5ParseError {
    pub diagnostic: NetFlowV5Diagnostic,
}

impl fmt::Display for NetFlowV5ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "NetFlow v5 {:?} at byte {} ({})",
            self.diagnostic.kind, self.diagnostic.byte_offset, self.diagnostic.field
        )
    }
}

impl Error for NetFlowV5ParseError {}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], NetFlowV5ParseError> {
        let start = self.offset;
        let end = start.checked_add(N).ok_or_else(|| {
            NetFlowV5Diagnostic::fatal(NetFlowV5DiagnosticKind::InvalidDatagramLength, start, field)
        })?;
        let source = self.bytes.get(start..end).ok_or_else(|| {
            NetFlowV5Diagnostic::fatal(
                NetFlowV5DiagnosticKind::InvalidDatagramLength,
                self.bytes.len(),
                field,
            )
        })?;
        let value = source.try_into().map_err(|_| {
            NetFlowV5Diagnostic::fatal(NetFlowV5DiagnosticKind::InvalidDatagramLength, start, field)
        })?;
        self.offset = end;
        Ok(value)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, NetFlowV5ParseError> {
        Ok(self.take::<1>(field)?[0])
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, NetFlowV5ParseError> {
        Ok(u16::from_be_bytes(self.take(field)?))
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, NetFlowV5ParseError> {
        Ok(u32::from_be_bytes(self.take(field)?))
    }

    fn read_ipv4(&mut self, field: &'static str) -> Result<Ipv4Addr, NetFlowV5ParseError> {
        Ok(Ipv4Addr::from(self.take::<4>(field)?))
    }
}

/// Decode one complete NetFlow v5 UDP payload.
///
/// The input must contain exactly one datagram. Structural failures return no
/// decoded value; nonfatal source anomalies are returned in `diagnostics`.
pub fn parse_netflow_v5_datagram(bytes: &[u8]) -> Result<NetFlowV5Datagram, NetFlowV5ParseError> {
    if bytes.len() < NETFLOW_V5_HEADER_LEN {
        return Err(NetFlowV5Diagnostic::fatal(
            NetFlowV5DiagnosticKind::TruncatedHeader,
            bytes.len(),
            "header",
        ));
    }

    let mut cursor = ByteCursor::new(bytes);
    let version = cursor.read_u16("version")?;
    let count = cursor.read_u16("count")?;
    let sys_uptime_ms = cursor.read_u32("sys_uptime")?;
    let unix_secs = cursor.read_u32("unix_secs")?;
    let unix_nsecs = cursor.read_u32("unix_nsecs")?;
    let flow_sequence = cursor.read_u32("flow_sequence")?;
    let engine_type = cursor.read_u8("engine_type")?;
    let engine_id = cursor.read_u8("engine_id")?;
    let raw_sampling = cursor.read_u16("sampling")?;

    if version != 5 {
        return Err(NetFlowV5Diagnostic::fatal(
            NetFlowV5DiagnosticKind::UnsupportedVersion,
            0,
            "version",
        ));
    }
    if !(NETFLOW_V5_MIN_RECORDS..=NETFLOW_V5_MAX_RECORDS).contains(&count) {
        return Err(NetFlowV5Diagnostic::fatal(
            NetFlowV5DiagnosticKind::InvalidRecordCount,
            2,
            "count",
        ));
    }
    if unix_nsecs >= 1_000_000_000 {
        return Err(NetFlowV5Diagnostic::fatal(
            NetFlowV5DiagnosticKind::InvalidUnixNanoseconds,
            12,
            "unix_nsecs",
        ));
    }

    let records_len = usize::from(count)
        .checked_mul(NETFLOW_V5_RECORD_LEN)
        .ok_or_else(|| {
            NetFlowV5Diagnostic::fatal(
                NetFlowV5DiagnosticKind::InvalidDatagramLength,
                NETFLOW_V5_HEADER_LEN,
                "count",
            )
        })?;
    let expected_len = NETFLOW_V5_HEADER_LEN
        .checked_add(records_len)
        .ok_or_else(|| {
            NetFlowV5Diagnostic::fatal(
                NetFlowV5DiagnosticKind::InvalidDatagramLength,
                NETFLOW_V5_HEADER_LEN,
                "datagram",
            )
        })?;
    if bytes.len() != expected_len {
        return Err(NetFlowV5Diagnostic::fatal(
            NetFlowV5DiagnosticKind::InvalidDatagramLength,
            bytes.len().min(expected_len),
            "datagram",
        ));
    }

    let sampling_mode = (raw_sampling >> 14) as u8;
    let sampling_interval = raw_sampling & 0x3fff;
    let header = NetFlowV5Header {
        version,
        count,
        sys_uptime_ms,
        unix_secs,
        unix_nsecs,
        flow_sequence,
        engine_type,
        engine_id,
        raw_sampling,
        sampling_mode,
        sampling_interval,
    };

    let mut diagnostics = Vec::with_capacity(3);
    if (sampling_mode == 0 && sampling_interval != 0)
        || ((sampling_mode == 1 || sampling_mode == 2) && sampling_interval == 0)
        || sampling_mode == 3
    {
        diagnostics.push(NetFlowV5Diagnostic {
            kind: NetFlowV5DiagnosticKind::SamplingConfigurationInvalid,
            byte_offset: 22,
            record_ordinal: None,
            field: "sampling",
        });
    }

    let mut records = Vec::with_capacity(usize::from(count));
    for record_ordinal in 0..count as u8 {
        let record_start =
            NETFLOW_V5_HEADER_LEN + usize::from(record_ordinal) * NETFLOW_V5_RECORD_LEN;
        let src_addr = cursor.read_ipv4("srcaddr")?;
        let dst_addr = cursor.read_ipv4("dstaddr")?;
        let next_hop = cursor.read_ipv4("nexthop")?;
        let input_ifindex = cursor.read_u16("input")?;
        let output_ifindex = cursor.read_u16("output")?;
        let packet_count = cursor.read_u32("dPkts")?;
        let octet_count = cursor.read_u32("dOctets")?;
        let first_sys_uptime_ms = cursor.read_u32("First")?;
        let last_sys_uptime_ms = cursor.read_u32("Last")?;
        let src_port = cursor.read_u16("srcport")?;
        let dst_port = cursor.read_u16("dstport")?;
        let pad1 = cursor.read_u8("pad1")?;
        let tcp_flags = cursor.read_u8("tcp_flags")?;
        let protocol = cursor.read_u8("prot")?;
        let tos = cursor.read_u8("tos")?;
        let src_as = cursor.read_u16("src_as")?;
        let dst_as = cursor.read_u16("dst_as")?;
        let src_mask = cursor.read_u8("src_mask")?;
        let dst_mask = cursor.read_u8("dst_mask")?;
        let pad2 = cursor.read_u16("pad2")?;

        if pad1 != 0 {
            diagnostics.push(NetFlowV5Diagnostic::for_record(
                NetFlowV5DiagnosticKind::NonzeroPadding,
                record_start + 36,
                record_ordinal,
                "pad1",
            ));
        }
        if pad2 != 0 {
            diagnostics.push(NetFlowV5Diagnostic::for_record(
                NetFlowV5DiagnosticKind::NonzeroPadding,
                record_start + 46,
                record_ordinal,
                "pad2",
            ));
        }

        records.push(NetFlowV5Record {
            record_ordinal,
            src_addr,
            dst_addr,
            next_hop,
            input_ifindex,
            output_ifindex,
            packet_count,
            octet_count,
            first_sys_uptime_ms,
            last_sys_uptime_ms,
            src_port,
            dst_port,
            pad1,
            tcp_flags,
            protocol,
            tos,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            pad2,
        });
    }

    Ok(NetFlowV5Datagram {
        header,
        records,
        diagnostics,
    })
}
