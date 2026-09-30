//! Offline artifact wrappers for the frozen NetFlow v5 F2/F3 pipeline.

use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::canonical::id::{normalize_sha256, sha256_file, InputIdentityError};
use crate::canonical::output::{write_canonical_observations_jsonl, CanonicalOutputError};
use crate::canonical::{CanonicalObservation, InputMode};
use crate::netflow::normalize::{
    ExportDatagramContext, ExportDatagramContextError, NetFlowV5FlowTimeContext,
    NetFlowV5NormalizationConfig, NetFlowV5NormalizationDiagnosticKind, NetFlowV5Normalizer,
    NetFlowV5ProcessingError,
};
use crate::netflow::pcap::{
    extract_udp_candidate, ClassicPcapError, ClassicPcapReader, PcapPacketDiagnosticKind,
    PcapUdpFilters, DEFAULT_MAX_CAPTURED_PACKET_BYTES,
};
use crate::netflow::v5::parse_netflow_v5_datagram;

pub const DEFAULT_MAX_RAW_DATAGRAM_BYTES: u64 = 24 + 30 * 48;
pub const DEFAULT_MAX_CANONICAL_OBSERVATIONS: usize = 100_000;
pub const DEFAULT_MAX_DIAGNOSTICS: usize = 1_000;

#[derive(Clone, Debug)]
pub struct RawDatagramInputConfig {
    pub sensor_id: String,
    pub exporter_id: String,
    pub transport_source: Option<String>,
    pub observed_at: String,
    pub expected_sha256: Option<String>,
    pub max_artifact_bytes: u64,
    pub normalization: NetFlowV5NormalizationConfig,
}

impl RawDatagramInputConfig {
    pub fn new(
        sensor_id: impl Into<String>,
        exporter_id: impl Into<String>,
        observed_at: impl Into<String>,
    ) -> Self {
        Self {
            sensor_id: sensor_id.into(),
            exporter_id: exporter_id.into(),
            transport_source: None,
            observed_at: observed_at.into(),
            expected_sha256: None,
            max_artifact_bytes: DEFAULT_MAX_RAW_DATAGRAM_BYTES,
            normalization: NetFlowV5NormalizationConfig::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PcapInputConfig {
    pub sensor_id: String,
    pub exporter_id: String,
    pub expected_sha256: Option<String>,
    pub filters: PcapUdpFilters,
    pub max_captured_packet_bytes: u32,
    pub max_canonical_observations: usize,
    pub max_diagnostics: usize,
    pub normalization: NetFlowV5NormalizationConfig,
}

impl PcapInputConfig {
    pub fn new(
        sensor_id: impl Into<String>,
        exporter_id: impl Into<String>,
        filters: PcapUdpFilters,
    ) -> Self {
        Self {
            sensor_id: sensor_id.into(),
            exporter_id: exporter_id.into(),
            expected_sha256: None,
            filters,
            max_captured_packet_bytes: DEFAULT_MAX_CAPTURED_PACKET_BYTES,
            max_canonical_observations: DEFAULT_MAX_CANONICAL_OBSERVATIONS,
            max_diagnostics: DEFAULT_MAX_DIAGNOSTICS,
            normalization: NetFlowV5NormalizationConfig::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfflineInputDiagnosticKind {
    Packet(PcapPacketDiagnosticKind),
    NetFlowV5Rejected,
    Normalization(NetFlowV5NormalizationDiagnosticKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfflineInputDiagnostic {
    pub kind: OfflineInputDiagnosticKind,
    pub packet_ordinal: Option<u64>,
    pub datagram_ordinal: Option<u64>,
    pub record_ordinal: Option<u8>,
    pub flow_time: Option<NetFlowV5FlowTimeContext>,
    pub limit_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OfflineQualificationResult {
    pub artifact_sha256: String,
    pub observations: Vec<CanonicalObservation>,
    pub diagnostics: Vec<OfflineInputDiagnostic>,
    pub diagnostics_total: u64,
    pub diagnostics_dropped: u64,
    pub packets_seen: u64,
    pub candidates_seen: u64,
    pub datagrams_accepted: u64,
}

#[derive(Debug)]
pub enum OfflineInputError {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Identity(InputIdentityError),
    Context(ExportDatagramContextError),
    RawDatagram(NetFlowV5ProcessingError),
    Pcap(ClassicPcapError),
    Output(CanonicalOutputError),
    InvalidExpectedSha256,
    ArtifactSha256Mismatch {
        expected: String,
        actual: String,
    },
    ArtifactChangedDuringRead {
        initial: String,
        parsed: String,
    },
    RawArtifactTooLarge {
        limit: u64,
    },
    ObservationLimitExceeded {
        limit: usize,
    },
    CounterOverflow(&'static str),
}

impl fmt::Display for OfflineInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "failed to {operation} {}: {source}", path.display()),
            Self::Identity(error) => write!(formatter, "artifact identity failed: {error}"),
            Self::Context(error) => write!(formatter, "source context is invalid: {error}"),
            Self::RawDatagram(error) => write!(formatter, "raw NetFlow v5 input failed: {error}"),
            Self::Pcap(error) => write!(formatter, "PCAP input failed: {error}"),
            Self::Output(error) => write!(formatter, "canonical output failed: {error}"),
            Self::InvalidExpectedSha256 => {
                formatter.write_str("expected artifact SHA-256 is not 64 hexadecimal characters")
            }
            Self::ArtifactSha256Mismatch { expected, actual } => write!(
                formatter,
                "expected artifact SHA-256 {expected} does not match actual bytes {actual}"
            ),
            Self::ArtifactChangedDuringRead { initial, parsed } => write!(
                formatter,
                "PCAP artifact changed during qualification: initial SHA-256 {initial}, parsed SHA-256 {parsed}"
            ),
            Self::RawArtifactTooLarge { limit } => {
                write!(formatter, "raw datagram artifact exceeds {limit} bytes")
            }
            Self::ObservationLimitExceeded { limit } => write!(
                formatter,
                "canonical observation count exceeds configured limit {limit}"
            ),
            Self::CounterOverflow(counter) => write!(formatter, "{counter} counter overflow"),
        }
    }
}

impl std::error::Error for OfflineInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Identity(error) => Some(error),
            Self::Context(error) => Some(error),
            Self::RawDatagram(error) => Some(error),
            Self::Pcap(error) => Some(error),
            Self::Output(error) => Some(error),
            _ => None,
        }
    }
}

impl From<InputIdentityError> for OfflineInputError {
    fn from(value: InputIdentityError) -> Self {
        Self::Identity(value)
    }
}

impl From<ExportDatagramContextError> for OfflineInputError {
    fn from(value: ExportDatagramContextError) -> Self {
        Self::Context(value)
    }
}

impl From<NetFlowV5ProcessingError> for OfflineInputError {
    fn from(value: NetFlowV5ProcessingError) -> Self {
        Self::RawDatagram(value)
    }
}

impl From<ClassicPcapError> for OfflineInputError {
    fn from(value: ClassicPcapError) -> Self {
        Self::Pcap(value)
    }
}

impl From<CanonicalOutputError> for OfflineInputError {
    fn from(value: CanonicalOutputError) -> Self {
        Self::Output(value)
    }
}

pub fn process_raw_datagram_file(
    input: impl AsRef<Path>,
    config: &RawDatagramInputConfig,
) -> Result<OfflineQualificationResult, OfflineInputError> {
    let input = input.as_ref();
    let mut file = File::open(input).map_err(|source| OfflineInputError::Io {
        operation: "open raw datagram artifact",
        path: input.to_path_buf(),
        source,
    })?;
    let read_limit =
        config
            .max_artifact_bytes
            .checked_add(1)
            .ok_or(OfflineInputError::RawArtifactTooLarge {
                limit: config.max_artifact_bytes,
            })?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| OfflineInputError::Io {
            operation: "read raw datagram artifact",
            path: input.to_path_buf(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > config.max_artifact_bytes {
        return Err(OfflineInputError::RawArtifactTooLarge {
            limit: config.max_artifact_bytes,
        });
    }
    let artifact_sha256 = format!("{:x}", Sha256::digest(&bytes));
    verify_expected_sha(config.expected_sha256.as_deref(), &artifact_sha256)?;
    let context = ExportDatagramContext::new(
        config.sensor_id.clone(),
        InputMode::ExportFile,
        &artifact_sha256,
        config.exporter_id.clone(),
        config.transport_source.clone(),
        config.observed_at.clone(),
        0,
    )?;
    let mut normalizer = NetFlowV5Normalizer::new(config.normalization);
    let normalized = normalizer.process_bytes(&bytes, &context)?;
    let diagnostics_total = u64::try_from(normalized.diagnostics.len()).unwrap_or(u64::MAX);
    let diagnostics = normalized
        .diagnostics
        .iter()
        .take(DEFAULT_MAX_DIAGNOSTICS)
        .map(|diagnostic| OfflineInputDiagnostic {
            kind: OfflineInputDiagnosticKind::Normalization(diagnostic.kind),
            packet_ordinal: None,
            datagram_ordinal: Some(0),
            record_ordinal: diagnostic.record_ordinal,
            flow_time: diagnostic.flow_time,
            limit_ms: diagnostic.limit_ms,
        })
        .collect::<Vec<_>>();
    let diagnostics_dropped = diagnostics_total.saturating_sub(diagnostics.len() as u64);
    Ok(OfflineQualificationResult {
        artifact_sha256,
        observations: normalized.observations,
        diagnostics,
        diagnostics_total,
        diagnostics_dropped,
        packets_seen: 0,
        candidates_seen: 1,
        datagrams_accepted: 1,
    })
}

pub fn process_pcap_file(
    input: impl AsRef<Path>,
    config: &PcapInputConfig,
) -> Result<OfflineQualificationResult, OfflineInputError> {
    let input = input.as_ref();
    let artifact_sha256 = sha256_file(input)?;
    verify_expected_sha(config.expected_sha256.as_deref(), &artifact_sha256)?;
    // Validate deployment-controlled context before processing any packet, even
    // when the capture contains no matching datagram.
    ExportDatagramContext::new_pcap(
        config.sensor_id.clone(),
        &artifact_sha256,
        config.exporter_id.clone(),
        None,
        "1970-01-01T00:00:00Z",
        0,
    )?;

    let file = File::open(input).map_err(|source| OfflineInputError::Io {
        operation: "open PCAP artifact",
        path: input.to_path_buf(),
        source,
    })?;
    let mut hashing_reader = HashingReader::new(BufReader::new(file));
    let mut normalizer = NetFlowV5Normalizer::new(config.normalization);
    let mut observations = Vec::new();
    let mut diagnostics = Vec::new();
    let mut diagnostics_total = 0_u64;
    let mut packets_seen = 0_u64;
    let mut candidates_seen = 0_u64;
    let mut datagrams_accepted = 0_u64;

    {
        let mut pcap =
            ClassicPcapReader::new(&mut hashing_reader, config.max_captured_packet_bytes)?;
        while let Some(packet) = pcap.next_packet()? {
            packets_seen = packets_seen
                .checked_add(1)
                .ok_or(OfflineInputError::CounterOverflow("packet"))?;
            let candidate = match extract_udp_candidate(&packet, &config.filters) {
                Ok(Some(candidate)) => candidate,
                Ok(None) => continue,
                Err(diagnostic) => {
                    push_diagnostic(
                        &mut diagnostics,
                        &mut diagnostics_total,
                        config.max_diagnostics,
                        OfflineInputDiagnostic {
                            kind: OfflineInputDiagnosticKind::Packet(diagnostic.kind),
                            packet_ordinal: Some(diagnostic.packet_ordinal),
                            datagram_ordinal: None,
                            record_ordinal: None,
                            flow_time: None,
                            limit_ms: None,
                        },
                    )?;
                    continue;
                }
            };
            candidates_seen = candidates_seen
                .checked_add(1)
                .ok_or(OfflineInputError::CounterOverflow("candidate"))?;
            let parsed = match parse_netflow_v5_datagram(candidate.payload) {
                Ok(parsed) => parsed,
                Err(_) => {
                    push_diagnostic(
                        &mut diagnostics,
                        &mut diagnostics_total,
                        config.max_diagnostics,
                        OfflineInputDiagnostic {
                            kind: OfflineInputDiagnosticKind::NetFlowV5Rejected,
                            packet_ordinal: Some(candidate.packet_ordinal),
                            datagram_ordinal: None,
                            record_ordinal: None,
                            flow_time: None,
                            limit_ms: None,
                        },
                    )?;
                    continue;
                }
            };
            let transport_source = format!("{}:{}", candidate.source_ip, candidate.source_port);
            let context = ExportDatagramContext::new_pcap(
                config.sensor_id.clone(),
                &artifact_sha256,
                config.exporter_id.clone(),
                Some(transport_source),
                candidate.observed_at,
                datagrams_accepted,
            )?;
            let normalized = normalizer.process_datagram(&parsed, &context);
            let next_observation_count = observations
                .len()
                .checked_add(normalized.observations.len())
                .ok_or(OfflineInputError::ObservationLimitExceeded {
                    limit: config.max_canonical_observations,
                })?;
            if next_observation_count > config.max_canonical_observations {
                return Err(OfflineInputError::ObservationLimitExceeded {
                    limit: config.max_canonical_observations,
                });
            }
            for diagnostic in &normalized.diagnostics {
                push_diagnostic(
                    &mut diagnostics,
                    &mut diagnostics_total,
                    config.max_diagnostics,
                    OfflineInputDiagnostic {
                        kind: OfflineInputDiagnosticKind::Normalization(diagnostic.kind),
                        packet_ordinal: Some(candidate.packet_ordinal),
                        datagram_ordinal: Some(datagrams_accepted),
                        record_ordinal: diagnostic.record_ordinal,
                        flow_time: diagnostic.flow_time,
                        limit_ms: diagnostic.limit_ms,
                    },
                )?;
            }
            observations.extend(normalized.observations);
            datagrams_accepted = datagrams_accepted
                .checked_add(1)
                .ok_or(OfflineInputError::CounterOverflow("datagram"))?;
        }
    }
    let parsed_sha256 = hashing_reader.digest_hex();
    if parsed_sha256 != artifact_sha256 {
        return Err(OfflineInputError::ArtifactChangedDuringRead {
            initial: artifact_sha256,
            parsed: parsed_sha256,
        });
    }
    let diagnostics_dropped = diagnostics_total.saturating_sub(diagnostics.len() as u64);
    Ok(OfflineQualificationResult {
        artifact_sha256,
        observations,
        diagnostics,
        diagnostics_total,
        diagnostics_dropped,
        packets_seen,
        candidates_seen,
        datagrams_accepted,
    })
}

pub fn write_raw_datagram_canonical_jsonl(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    config: &RawDatagramInputConfig,
) -> Result<OfflineQualificationResult, OfflineInputError> {
    let result = process_raw_datagram_file(input, config)?;
    write_canonical_observations_jsonl(output, &result.observations)?;
    Ok(result)
}

pub fn write_pcap_canonical_jsonl(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    config: &PcapInputConfig,
) -> Result<OfflineQualificationResult, OfflineInputError> {
    let result = process_pcap_file(input, config)?;
    write_canonical_observations_jsonl(output, &result.observations)?;
    Ok(result)
}

fn verify_expected_sha(expected: Option<&str>, actual: &str) -> Result<(), OfflineInputError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let expected =
        normalize_sha256(expected).map_err(|_| OfflineInputError::InvalidExpectedSha256)?;
    if expected != actual {
        return Err(OfflineInputError::ArtifactSha256Mismatch {
            expected,
            actual: actual.to_string(),
        });
    }
    Ok(())
}

fn push_diagnostic(
    diagnostics: &mut Vec<OfflineInputDiagnostic>,
    total: &mut u64,
    limit: usize,
    diagnostic: OfflineInputDiagnostic,
) -> Result<(), OfflineInputError> {
    *total = total
        .checked_add(1)
        .ok_or(OfflineInputError::CounterOverflow("diagnostic"))?;
    if diagnostics.len() < limit {
        diagnostics.push(diagnostic);
    }
    Ok(())
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn digest_hex(&self) -> String {
        format!("{:x}", self.hasher.clone().finalize())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..count]);
        Ok(count)
    }
}
