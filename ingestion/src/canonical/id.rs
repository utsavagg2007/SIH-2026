use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const ZEEK_ID_ALGORITHM_MARKER: &str = "co-zeek-id-v1";
pub const ZEEK_ID_NAMESPACE: Uuid = Uuid::from_u128(0x1a055b8571755118b36da7bb3f50c127);
pub const NETFLOW_V5_ID_ALGORITHM_MARKER: &str = "co-netflow-v5-id-v1";
pub const NETFLOW_V5_ID_NAMESPACE: Uuid = Uuid::from_u128(0x6f1b86b7eced5e6fa21f0e45fa7394d7);
pub const NETFLOW_V9_ID_ALGORITHM_MARKER: &str = "co-netflow-v9-id-v1";
/// UUIDv5(URL namespace, UTF-8 project URI ending in co-netflow-v9-id-v1).
pub const NETFLOW_V9_ID_NAMESPACE: Uuid = Uuid::from_u128(0x5a4b375042205f0eb5068f6080b3828c);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityObservationType {
    Flow,
    Dns,
    Tls,
    Http,
}

impl IdentityObservationType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Flow => "flow",
            Self::Dns => "dns",
            Self::Tls => "tls",
            Self::Http => "http",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeekLogName {
    Conn,
    Dns,
    Ssl,
    Http,
}

impl ZeekLogName {
    fn as_str(self) -> &'static str {
        match self {
            Self::Conn => "conn",
            Self::Dns => "dns",
            Self::Ssl => "ssl",
            Self::Http => "http",
        }
    }
}

#[derive(Debug)]
pub enum InputIdentityError {
    InvalidSha256,
    EmptySensorId,
    EmptyExporterId,
    EmptySessionId,
    ComponentTooLong { coordinate: &'static str },
    Io(io::Error),
}

impl fmt::Display for InputIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSha256 => {
                f.write_str("input SHA-256 must contain exactly 64 hexadecimal characters")
            }
            Self::EmptySensorId => f.write_str("sensor_id must be nonempty"),
            Self::EmptyExporterId => f.write_str("exporter_id must be nonempty"),
            Self::EmptySessionId => f.write_str("session_id must be nonempty"),
            Self::ComponentTooLong { coordinate } => {
                write!(
                    f,
                    "identity coordinate {coordinate} exceeds the u32 length encoding"
                )
            }
            Self::Io(error) => write!(f, "failed to hash input artifact: {error}"),
        }
    }
}

impl std::error::Error for InputIdentityError {}

impl From<io::Error> for InputIdentityError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn normalize_sha256(value: &str) -> Result<String, InputIdentityError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(InputIdentityError::InvalidSha256);
    }
    Ok(value.to_ascii_lowercase())
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<String, InputIdentityError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn component_length_prefix(
    coordinate: &'static str,
    byte_length: usize,
) -> Result<[u8; 4], InputIdentityError> {
    let length: u32 = byte_length
        .try_into()
        .map_err(|_| InputIdentityError::ComponentTooLong { coordinate })?;
    Ok(length.to_be_bytes())
}

fn append_component(
    encoded: &mut Vec<u8>,
    coordinate: &'static str,
    component: &str,
) -> Result<(), InputIdentityError> {
    let bytes = component.as_bytes();
    encoded.extend_from_slice(&component_length_prefix(coordinate, bytes.len())?);
    encoded.extend_from_slice(bytes);
    Ok(())
}

pub fn generate_zeek_record_id(
    sensor_id: &str,
    input_sha256: &str,
    observation_type: IdentityObservationType,
    log_name: ZeekLogName,
    zeek_uid: &str,
    row_ordinal: u64,
) -> Result<String, InputIdentityError> {
    if sensor_id.is_empty() {
        return Err(InputIdentityError::EmptySensorId);
    }
    let input_sha256 = normalize_sha256(input_sha256)?;
    let mut encoded = Vec::new();
    for (coordinate, component) in [
        ("algorithm_marker", ZEEK_ID_ALGORITHM_MARKER),
        ("sensor_id", sensor_id),
        ("input_sha256", input_sha256.as_str()),
        ("observation_type", observation_type.as_str()),
        ("log_name", log_name.as_str()),
        ("zeek_uid", zeek_uid),
    ] {
        append_component(&mut encoded, coordinate, component)?;
    }
    append_component(&mut encoded, "row_ordinal", &row_ordinal.to_string())?;
    Ok(Uuid::new_v5(&ZEEK_ID_NAMESPACE, &encoded).to_string())
}

pub struct NetFlowV5IdentityCoordinates<'a> {
    pub sensor_id: &'a str,
    pub input_sha256: &'a str,
    pub exporter_id: &'a str,
    pub engine_type: u8,
    pub engine_id: u8,
    pub flow_sequence: u32,
    pub datagram_ordinal: u64,
    pub record_ordinal: u8,
}

pub fn generate_netflow_v5_record_id(
    coordinates: &NetFlowV5IdentityCoordinates<'_>,
) -> Result<String, InputIdentityError> {
    if coordinates.sensor_id.is_empty() {
        return Err(InputIdentityError::EmptySensorId);
    }
    if coordinates.exporter_id.is_empty() {
        return Err(InputIdentityError::EmptyExporterId);
    }
    let input_sha256 = normalize_sha256(coordinates.input_sha256)?;
    let engine_type = coordinates.engine_type.to_string();
    let engine_id = coordinates.engine_id.to_string();
    let flow_sequence = coordinates.flow_sequence.to_string();
    let datagram_ordinal = coordinates.datagram_ordinal.to_string();
    let record_ordinal = coordinates.record_ordinal.to_string();
    let mut encoded = Vec::new();
    for (coordinate, component) in [
        ("algorithm_marker", NETFLOW_V5_ID_ALGORITHM_MARKER),
        ("sensor_id", coordinates.sensor_id),
        ("input_sha256", input_sha256.as_str()),
        ("exporter_id", coordinates.exporter_id),
        ("engine_type", engine_type.as_str()),
        ("engine_id", engine_id.as_str()),
        ("flow_sequence", flow_sequence.as_str()),
        ("datagram_ordinal", datagram_ordinal.as_str()),
        ("record_ordinal", record_ordinal.as_str()),
    ] {
        append_component(&mut encoded, coordinate, component)?;
    }
    Ok(Uuid::new_v5(&NETFLOW_V5_ID_NAMESPACE, &encoded).to_string())
}

/// Physical evidence coordinates. Template ID/generation and processing times
/// intentionally do not participate in the frozen v9 identity algorithm.
pub struct NetFlowV9IdentityCoordinates<'a> {
    pub sensor_id: &'a str,
    pub input_sha256: &'a str,
    pub exporter_id: &'a str,
    pub session_id: &'a str,
    pub source_id: u32,
    pub sequence_number: u32,
    pub datagram_ordinal: u64,
    pub flowset_ordinal: u32,
    pub record_ordinal: u32,
}

pub fn generate_netflow_v9_record_id(
    coordinates: &NetFlowV9IdentityCoordinates<'_>,
) -> Result<String, InputIdentityError> {
    if coordinates.sensor_id.is_empty() {
        return Err(InputIdentityError::EmptySensorId);
    }
    if coordinates.exporter_id.is_empty() {
        return Err(InputIdentityError::EmptyExporterId);
    }
    if coordinates.session_id.is_empty() {
        return Err(InputIdentityError::EmptySessionId);
    }
    let hash = normalize_sha256(coordinates.input_sha256)?;
    let source = coordinates.source_id.to_string();
    let sequence = coordinates.sequence_number.to_string();
    let datagram = coordinates.datagram_ordinal.to_string();
    let flowset = coordinates.flowset_ordinal.to_string();
    let record = coordinates.record_ordinal.to_string();
    let mut encoded = Vec::new();
    for (label, value) in [
        ("algorithm_marker", NETFLOW_V9_ID_ALGORITHM_MARKER),
        ("sensor_id", coordinates.sensor_id),
        ("input_sha256", hash.as_str()),
        ("exporter_id", coordinates.exporter_id),
        ("session_id", coordinates.session_id),
        ("source_id", source.as_str()),
        ("sequence_number", sequence.as_str()),
        ("datagram_ordinal", datagram.as_str()),
        ("flowset_ordinal", flowset.as_str()),
        ("record_ordinal", record.as_str()),
    ] {
        append_component(&mut encoded, label, value)?;
    }
    Ok(Uuid::new_v5(&NETFLOW_V9_ID_NAMESPACE, &encoded).to_string())
}

pub fn generate_netflow_v9_session_fingerprint(
    exporter_id: &str,
    session_id: &str,
) -> Result<String, InputIdentityError> {
    if exporter_id.is_empty() {
        return Err(InputIdentityError::EmptyExporterId);
    }
    if session_id.is_empty() {
        return Err(InputIdentityError::EmptySessionId);
    }
    let mut encoded = Vec::new();
    for (label, value) in [
        ("algorithm_marker", "co-netflow-v9-session-v1"),
        ("exporter_id", exporter_id),
        ("session_id", session_id),
    ] {
        append_component(&mut encoded, label, value)?;
    }
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

#[cfg(test)]
mod tests {
    use super::{component_length_prefix, InputIdentityError};

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn oversized_coordinate_length_returns_typed_error() {
        let error = component_length_prefix("sensor_id", u32::MAX as usize + 1).unwrap_err();
        assert!(matches!(
            error,
            InputIdentityError::ComponentTooLong {
                coordinate: "sensor_id"
            }
        ));
    }
}
