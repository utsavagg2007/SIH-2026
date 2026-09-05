use crate::zeek_parser::types::SslRecord;
use serde::{Deserialize, Serialize};

/// Features derived from a single TLS session (encrypted-malware detection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFeatures {
    pub uid: String,
    pub has_ja3: bool,
    pub has_ja3s: bool,
    pub ssl_version_encoded: u8,
    /// Coarse encoding of the cipher suite. Replace with a proper lookup table
    /// mapped to known malware JA3 signatures when wiring up models.
    pub cipher_encoded: u8,
}

pub fn encode_ssl_version(v: &str) -> u8 {
    match v {
        "TLSv10" => 1,
        "TLSv11" => 2,
        "TLSv12" => 3,
        "TLSv13" => 4,
        "SSLv3" => 5,
        _ => 0,
    }
}

impl TlsFeatures {
    pub fn from_ssl_record(s: &SslRecord) -> Self {
        let cipher_encoded = if s.cipher.is_empty() {
            0
        } else {
            (s.cipher.len() % 16) as u8 + 1
        };
        TlsFeatures {
            uid: s.uid.clone(),
            has_ja3: s.ja3.as_ref().is_some_and(|x| !x.is_empty()),
            has_ja3s: s.ja3s.as_ref().is_some_and(|x| !x.is_empty()),
            ssl_version_encoded: encode_ssl_version(&s.version),
            cipher_encoded,
        }
    }
}
