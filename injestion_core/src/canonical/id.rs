use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const ZEEK_ID_ALGORITHM_MARKER: &str = "co-zeek-id-v1";
pub const ZEEK_ID_NAMESPACE: Uuid = Uuid::from_u128(0x1a055b8571755118b36da7bb3f50c127);

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
