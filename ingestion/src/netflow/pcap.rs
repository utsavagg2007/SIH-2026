//! Narrow, dependency-free classic-PCAP extraction for offline NetFlow v5 qualification.

use std::fmt;
use std::io::{self, Read};
use std::net::Ipv4Addr;

use crate::canonical::time::unix_nanoseconds_to_rfc3339;

const CLASSIC_PCAP_GLOBAL_HEADER_LEN: usize = 24;
const CLASSIC_PCAP_PACKET_HEADER_LEN: usize = 16;
const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_HEADER_LEN: usize = 4;
const IPV4_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const LINKTYPE_ETHERNET: u32 = 1;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_PROVIDER_VLAN: u16 = 0x88a8;
const IP_PROTOCOL_UDP: u8 = 17;

pub const DEFAULT_MAX_CAPTURED_PACKET_BYTES: u32 = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcapTimestampPrecision {
    Microseconds,
    Nanoseconds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ByteOrder {
    Little,
    Big,
}

impl ByteOrder {
    fn u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }

    fn u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }
}

#[derive(Debug)]
pub enum ClassicPcapError {
    Io(io::Error),
    TruncatedGlobalHeader,
    UnsupportedMagic([u8; 4]),
    UnsupportedVersion {
        major: u16,
        minor: u16,
    },
    UnsupportedLinkType(u32),
    InvalidSnapLength(u32),
    TruncatedPacketHeader {
        packet_ordinal: u64,
    },
    CapturedLengthExceedsSnapLength {
        packet_ordinal: u64,
        captured_length: u32,
        snap_length: u32,
    },
    CapturedLengthExceedsLimit {
        packet_ordinal: u64,
        captured_length: u32,
        limit: u32,
    },
    CapturedLengthExceedsOriginal {
        packet_ordinal: u64,
        captured_length: u32,
        original_length: u32,
    },
    TruncatedPacketData {
        packet_ordinal: u64,
        expected: u32,
    },
    TimestampFractionOutOfRange {
        packet_ordinal: u64,
        value: u32,
        precision: PcapTimestampPrecision,
    },
    TimestampOutOfRange {
        packet_ordinal: u64,
    },
    PacketOrdinalOverflow,
}

impl fmt::Display for ClassicPcapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "PCAP I/O failed: {error}"),
            Self::TruncatedGlobalHeader => formatter.write_str("classic PCAP global header is truncated"),
            Self::UnsupportedMagic(magic) => write!(formatter, "unsupported PCAP magic number {magic:02x?}"),
            Self::UnsupportedVersion { major, minor } => {
                write!(formatter, "unsupported classic PCAP version {major}.{minor}")
            }
            Self::UnsupportedLinkType(value) => {
                write!(formatter, "unsupported PCAP link type {value}; Ethernet (1) is required")
            }
            Self::InvalidSnapLength(value) => write!(formatter, "invalid PCAP snap length {value}"),
            Self::TruncatedPacketHeader { packet_ordinal } => {
                write!(formatter, "packet {packet_ordinal} has a truncated PCAP record header")
            }
            Self::CapturedLengthExceedsSnapLength {
                packet_ordinal,
                captured_length,
                snap_length,
            } => write!(
                formatter,
                "packet {packet_ordinal} captured length {captured_length} exceeds snap length {snap_length}"
            ),
            Self::CapturedLengthExceedsLimit {
                packet_ordinal,
                captured_length,
                limit,
            } => write!(
                formatter,
                "packet {packet_ordinal} captured length {captured_length} exceeds configured limit {limit}"
            ),
            Self::CapturedLengthExceedsOriginal {
                packet_ordinal,
                captured_length,
                original_length,
            } => write!(
                formatter,
                "packet {packet_ordinal} captured length {captured_length} exceeds original length {original_length}"
            ),
            Self::TruncatedPacketData {
                packet_ordinal,
                expected,
            } => write!(
                formatter,
                "packet {packet_ordinal} data is truncated before {expected} captured bytes"
            ),
            Self::TimestampFractionOutOfRange {
                packet_ordinal,
                value,
                precision,
            } => write!(
                formatter,
                "packet {packet_ordinal} timestamp fraction {value} is invalid for {precision:?} precision"
            ),
            Self::TimestampOutOfRange { packet_ordinal } => {
                write!(formatter, "packet {packet_ordinal} timestamp is outside canonical range")
            }
            Self::PacketOrdinalOverflow => formatter.write_str("PCAP packet ordinal overflow"),
        }
    }
}

impl std::error::Error for ClassicPcapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ClassicPcapError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedPacket {
    pub packet_ordinal: u64,
    pub observed_at: String,
    pub captured_length: u32,
    pub original_length: u32,
    pub data: Vec<u8>,
}

pub struct ClassicPcapReader<R> {
    reader: R,
    byte_order: ByteOrder,
    precision: PcapTimestampPrecision,
    snap_length: u32,
    max_captured_packet_bytes: u32,
    next_packet_ordinal: u64,
}

impl<R: Read> ClassicPcapReader<R> {
    pub fn new(mut reader: R, max_captured_packet_bytes: u32) -> Result<Self, ClassicPcapError> {
        let mut header = [0_u8; CLASSIC_PCAP_GLOBAL_HEADER_LEN];
        if !read_exact_complete(&mut reader, &mut header)? {
            return Err(ClassicPcapError::TruncatedGlobalHeader);
        }
        let magic = [header[0], header[1], header[2], header[3]];
        let (byte_order, precision) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (ByteOrder::Little, PcapTimestampPrecision::Microseconds),
            [0xa1, 0xb2, 0xc3, 0xd4] => (ByteOrder::Big, PcapTimestampPrecision::Microseconds),
            [0x4d, 0x3c, 0xb2, 0xa1] => (ByteOrder::Little, PcapTimestampPrecision::Nanoseconds),
            [0xa1, 0xb2, 0x3c, 0x4d] => (ByteOrder::Big, PcapTimestampPrecision::Nanoseconds),
            value => return Err(ClassicPcapError::UnsupportedMagic(value)),
        };
        let major = byte_order.u16([header[4], header[5]]);
        let minor = byte_order.u16([header[6], header[7]]);
        if (major, minor) != (2, 4) {
            return Err(ClassicPcapError::UnsupportedVersion { major, minor });
        }
        let snap_length = byte_order.u32([header[16], header[17], header[18], header[19]]);
        if snap_length == 0 {
            return Err(ClassicPcapError::InvalidSnapLength(snap_length));
        }
        let link_type = byte_order.u32([header[20], header[21], header[22], header[23]]);
        if link_type != LINKTYPE_ETHERNET {
            return Err(ClassicPcapError::UnsupportedLinkType(link_type));
        }
        if max_captured_packet_bytes == 0 {
            return Err(ClassicPcapError::InvalidSnapLength(
                max_captured_packet_bytes,
            ));
        }
        Ok(Self {
            reader,
            byte_order,
            precision,
            snap_length,
            max_captured_packet_bytes,
            next_packet_ordinal: 0,
        })
    }

    pub fn precision(&self) -> PcapTimestampPrecision {
        self.precision
    }

    pub fn snap_length(&self) -> u32 {
        self.snap_length
    }

    pub fn next_packet(&mut self) -> Result<Option<CapturedPacket>, ClassicPcapError> {
        let packet_ordinal = self.next_packet_ordinal;
        let mut header = [0_u8; CLASSIC_PCAP_PACKET_HEADER_LEN];
        match read_record_header(&mut self.reader, &mut header)? {
            RecordHeaderRead::Eof => return Ok(None),
            RecordHeaderRead::Complete => {}
            RecordHeaderRead::Truncated => {
                return Err(ClassicPcapError::TruncatedPacketHeader { packet_ordinal })
            }
        }

        let timestamp_seconds = self
            .byte_order
            .u32([header[0], header[1], header[2], header[3]]);
        let timestamp_fraction = self
            .byte_order
            .u32([header[4], header[5], header[6], header[7]]);
        let captured_length = self
            .byte_order
            .u32([header[8], header[9], header[10], header[11]]);
        let original_length = self
            .byte_order
            .u32([header[12], header[13], header[14], header[15]]);

        if captured_length > self.snap_length {
            return Err(ClassicPcapError::CapturedLengthExceedsSnapLength {
                packet_ordinal,
                captured_length,
                snap_length: self.snap_length,
            });
        }
        if captured_length > self.max_captured_packet_bytes {
            return Err(ClassicPcapError::CapturedLengthExceedsLimit {
                packet_ordinal,
                captured_length,
                limit: self.max_captured_packet_bytes,
            });
        }
        if captured_length > original_length {
            return Err(ClassicPcapError::CapturedLengthExceedsOriginal {
                packet_ordinal,
                captured_length,
                original_length,
            });
        }

        let fractional_limit = match self.precision {
            PcapTimestampPrecision::Microseconds => 1_000_000,
            PcapTimestampPrecision::Nanoseconds => 1_000_000_000,
        };
        if timestamp_fraction >= fractional_limit {
            return Err(ClassicPcapError::TimestampFractionOutOfRange {
                packet_ordinal,
                value: timestamp_fraction,
                precision: self.precision,
            });
        }
        let fractional_nanoseconds = match self.precision {
            PcapTimestampPrecision::Microseconds => u64::from(timestamp_fraction)
                .checked_mul(1_000)
                .ok_or(ClassicPcapError::TimestampOutOfRange { packet_ordinal })?,
            PcapTimestampPrecision::Nanoseconds => u64::from(timestamp_fraction),
        };
        let timestamp_nanoseconds = u64::from(timestamp_seconds)
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(fractional_nanoseconds))
            .ok_or(ClassicPcapError::TimestampOutOfRange { packet_ordinal })?;
        let observed_at = unix_nanoseconds_to_rfc3339(timestamp_nanoseconds)
            .map_err(|_| ClassicPcapError::TimestampOutOfRange { packet_ordinal })?;

        let captured_length_usize = usize::try_from(captured_length).map_err(|_| {
            ClassicPcapError::CapturedLengthExceedsLimit {
                packet_ordinal,
                captured_length,
                limit: self.max_captured_packet_bytes,
            }
        })?;
        let mut data = vec![0_u8; captured_length_usize];
        if !read_exact_complete(&mut self.reader, &mut data)? {
            return Err(ClassicPcapError::TruncatedPacketData {
                packet_ordinal,
                expected: captured_length,
            });
        }
        self.next_packet_ordinal = self
            .next_packet_ordinal
            .checked_add(1)
            .ok_or(ClassicPcapError::PacketOrdinalOverflow)?;
        Ok(Some(CapturedPacket {
            packet_ordinal,
            observed_at,
            captured_length,
            original_length,
            data,
        }))
    }
}

enum RecordHeaderRead {
    Eof,
    Complete,
    Truncated,
}

fn read_record_header<R: Read>(reader: &mut R, target: &mut [u8]) -> io::Result<RecordHeaderRead> {
    let mut filled = 0;
    while filled < target.len() {
        match reader.read(&mut target[filled..])? {
            0 if filled == 0 => return Ok(RecordHeaderRead::Eof),
            0 => return Ok(RecordHeaderRead::Truncated),
            count => filled += count,
        }
    }
    Ok(RecordHeaderRead::Complete)
}

fn read_exact_complete<R: Read>(reader: &mut R, target: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < target.len() {
        match reader.read(&mut target[filled..])? {
            0 => return Ok(false),
            count => filled += count,
        }
    }
    Ok(true)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcapUdpFilters {
    pub exporter_source_ip: Option<Ipv4Addr>,
    pub collector_destination_ip: Option<Ipv4Addr>,
    source_ports: Vec<u16>,
    destination_ports: Vec<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcapFilterError {
    MissingPortFilter,
}

impl fmt::Display for PcapFilterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPortFilter => formatter
                .write_str("at least one UDP source-port or destination-port filter is required"),
        }
    }
}

impl std::error::Error for PcapFilterError {}

impl PcapUdpFilters {
    pub fn new(
        exporter_source_ip: Option<Ipv4Addr>,
        collector_destination_ip: Option<Ipv4Addr>,
        mut source_ports: Vec<u16>,
        mut destination_ports: Vec<u16>,
    ) -> Result<Self, PcapFilterError> {
        source_ports.sort_unstable();
        source_ports.dedup();
        destination_ports.sort_unstable();
        destination_ports.dedup();
        if source_ports.is_empty() && destination_ports.is_empty() {
            return Err(PcapFilterError::MissingPortFilter);
        }
        Ok(Self {
            exporter_source_ip,
            collector_destination_ip,
            source_ports,
            destination_ports,
        })
    }

    pub fn source_ports(&self) -> &[u16] {
        &self.source_ports
    }

    pub fn destination_ports(&self) -> &[u16] {
        &self.destination_ports
    }

    fn matches(
        &self,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> bool {
        self.exporter_source_ip
            .is_none_or(|expected| expected == source_ip)
            && self
                .collector_destination_ip
                .is_none_or(|expected| expected == destination_ip)
            && (self.source_ports.is_empty()
                || self.source_ports.binary_search(&source_port).is_ok())
            && (self.destination_ports.is_empty()
                || self
                    .destination_ports
                    .binary_search(&destination_port)
                    .is_ok())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcapPacketDiagnosticKind {
    EthernetTooShort,
    VlanHeaderTruncated,
    NestedVlanUnsupported,
    Ipv6Unsupported,
    Ipv4HeaderTruncated,
    Ipv4HeaderLengthInvalid,
    Ipv4TotalLengthInvalid,
    Ipv4PacketTruncated,
    FragmentedUdpUnsupported,
    UdpHeaderTruncated,
    UdpLengthInvalid,
    UdpPayloadTruncated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcapPacketDiagnostic {
    pub kind: PcapPacketDiagnosticKind,
    pub packet_ordinal: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpCandidate<'a> {
    pub packet_ordinal: u64,
    pub observed_at: &'a str,
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

pub fn extract_udp_candidate<'a>(
    packet: &'a CapturedPacket,
    filters: &PcapUdpFilters,
) -> Result<Option<UdpCandidate<'a>>, PcapPacketDiagnostic> {
    let fail = |kind| PcapPacketDiagnostic {
        kind,
        packet_ordinal: packet.packet_ordinal,
    };
    if packet.data.len() < ETHERNET_HEADER_LEN {
        return Err(fail(PcapPacketDiagnosticKind::EthernetTooShort));
    }
    let mut ether_type =
        be_u16(&packet.data, 12).ok_or_else(|| fail(PcapPacketDiagnosticKind::EthernetTooShort))?;
    let mut network_offset = ETHERNET_HEADER_LEN;
    if ether_type == ETHERTYPE_VLAN {
        let required = ETHERNET_HEADER_LEN
            .checked_add(VLAN_HEADER_LEN)
            .ok_or_else(|| fail(PcapPacketDiagnosticKind::VlanHeaderTruncated))?;
        if packet.data.len() < required {
            return Err(fail(PcapPacketDiagnosticKind::VlanHeaderTruncated));
        }
        ether_type = be_u16(&packet.data, 16)
            .ok_or_else(|| fail(PcapPacketDiagnosticKind::VlanHeaderTruncated))?;
        network_offset = required;
        if matches!(ether_type, ETHERTYPE_VLAN | ETHERTYPE_PROVIDER_VLAN) {
            return Err(fail(PcapPacketDiagnosticKind::NestedVlanUnsupported));
        }
    } else if ether_type == ETHERTYPE_PROVIDER_VLAN {
        return Err(fail(PcapPacketDiagnosticKind::NestedVlanUnsupported));
    }
    if ether_type == ETHERTYPE_IPV6 {
        return Err(fail(PcapPacketDiagnosticKind::Ipv6Unsupported));
    }
    if ether_type != ETHERTYPE_IPV4 {
        return Ok(None);
    }

    let minimum_end = network_offset
        .checked_add(IPV4_MIN_HEADER_LEN)
        .ok_or_else(|| fail(PcapPacketDiagnosticKind::Ipv4HeaderTruncated))?;
    if packet.data.len() < minimum_end {
        return Err(fail(PcapPacketDiagnosticKind::Ipv4HeaderTruncated));
    }
    let version_ihl = packet.data[network_offset];
    if version_ihl >> 4 != 4 {
        return Ok(None);
    }
    let ihl_words = usize::from(version_ihl & 0x0f);
    if ihl_words < 5 {
        return Err(fail(PcapPacketDiagnosticKind::Ipv4HeaderLengthInvalid));
    }
    let ipv4_header_length = ihl_words
        .checked_mul(4)
        .ok_or_else(|| fail(PcapPacketDiagnosticKind::Ipv4HeaderLengthInvalid))?;
    let ipv4_header_end = network_offset
        .checked_add(ipv4_header_length)
        .ok_or_else(|| fail(PcapPacketDiagnosticKind::Ipv4HeaderLengthInvalid))?;
    if ipv4_header_end > packet.data.len() {
        return Err(fail(PcapPacketDiagnosticKind::Ipv4HeaderTruncated));
    }
    let total_length = usize::from(
        be_u16(&packet.data, network_offset + 2)
            .ok_or_else(|| fail(PcapPacketDiagnosticKind::Ipv4TotalLengthInvalid))?,
    );
    if total_length < ipv4_header_length {
        return Err(fail(PcapPacketDiagnosticKind::Ipv4TotalLengthInvalid));
    }
    let ipv4_end = network_offset
        .checked_add(total_length)
        .ok_or_else(|| fail(PcapPacketDiagnosticKind::Ipv4TotalLengthInvalid))?;
    if ipv4_end > packet.data.len() {
        return Err(fail(PcapPacketDiagnosticKind::Ipv4PacketTruncated));
    }
    if packet.data[network_offset + 9] != IP_PROTOCOL_UDP {
        return Ok(None);
    }

    let source_ip = Ipv4Addr::new(
        packet.data[network_offset + 12],
        packet.data[network_offset + 13],
        packet.data[network_offset + 14],
        packet.data[network_offset + 15],
    );
    let destination_ip = Ipv4Addr::new(
        packet.data[network_offset + 16],
        packet.data[network_offset + 17],
        packet.data[network_offset + 18],
        packet.data[network_offset + 19],
    );
    if filters
        .exporter_source_ip
        .is_some_and(|expected| expected != source_ip)
        || filters
            .collector_destination_ip
            .is_some_and(|expected| expected != destination_ip)
    {
        return Ok(None);
    }

    let fragment = be_u16(&packet.data, network_offset + 6)
        .ok_or_else(|| fail(PcapPacketDiagnosticKind::Ipv4HeaderTruncated))?;
    if fragment & 0x3fff != 0 {
        return Err(fail(PcapPacketDiagnosticKind::FragmentedUdpUnsupported));
    }

    let udp_end_minimum = ipv4_header_end
        .checked_add(UDP_HEADER_LEN)
        .ok_or_else(|| fail(PcapPacketDiagnosticKind::UdpHeaderTruncated))?;
    if udp_end_minimum > ipv4_end {
        return Err(fail(PcapPacketDiagnosticKind::UdpHeaderTruncated));
    }
    let source_port = be_u16(&packet.data, ipv4_header_end)
        .ok_or_else(|| fail(PcapPacketDiagnosticKind::UdpHeaderTruncated))?;
    let destination_port = be_u16(&packet.data, ipv4_header_end + 2)
        .ok_or_else(|| fail(PcapPacketDiagnosticKind::UdpHeaderTruncated))?;
    if !filters.matches(source_ip, destination_ip, source_port, destination_port) {
        return Ok(None);
    }
    let udp_length = usize::from(
        be_u16(&packet.data, ipv4_header_end + 4)
            .ok_or_else(|| fail(PcapPacketDiagnosticKind::UdpHeaderTruncated))?,
    );
    if udp_length < UDP_HEADER_LEN {
        return Err(fail(PcapPacketDiagnosticKind::UdpLengthInvalid));
    }
    let udp_end = ipv4_header_end
        .checked_add(udp_length)
        .ok_or_else(|| fail(PcapPacketDiagnosticKind::UdpLengthInvalid))?;
    if udp_end > ipv4_end || udp_end > packet.data.len() {
        return Err(fail(PcapPacketDiagnosticKind::UdpPayloadTruncated));
    }
    let payload_start = ipv4_header_end + UDP_HEADER_LEN;
    Ok(Some(UdpCandidate {
        packet_ordinal: packet.packet_ordinal,
        observed_at: &packet.observed_at,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        payload: &packet.data[payload_start..udp_end],
    }))
}

fn be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([value[0], value[1]]))
}
