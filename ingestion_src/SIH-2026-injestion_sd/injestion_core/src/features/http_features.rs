use crate::utils::entropy::string_entropy;
use crate::zeek_parser::types::HttpRecord;
use serde::{Deserialize, Serialize};

/// Features derived from a single HTTP request (exfil / C2-over-HTTP signals).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFeatures {
    pub uid: String,
    pub method_encoded: u8,
    /// Length of the Host header (long/high-entropy hosts can indicate C2).
    pub host_length: u32,
    pub uri_length: u32,
    /// Shannon entropy of the URI (high => obfuscated/exfil URLs).
    pub uri_entropy: f64,
    pub has_user_agent: bool,
    pub user_agent_length: u32,
    pub request_body_len: u64,
    pub response_body_len: u64,
    pub status_code: u16,
}

pub fn encode_method(m: &str) -> u8 {
    match m.to_uppercase().as_str() {
        "GET" => 1,
        "POST" => 2,
        "HEAD" => 3,
        "PUT" => 4,
        "DELETE" => 5,
        "OPTIONS" => 6,
        "CONNECT" => 7,
        "TRACE" => 8,
        "PATCH" => 9,
        _ => 0,
    }
}

impl HttpFeatures {
    pub fn from_http_record(h: &HttpRecord) -> Self {
        HttpFeatures {
            uid: h.uid.clone(),
            method_encoded: encode_method(&h.method),
            host_length: h.host.chars().count() as u32,
            uri_length: h.uri.chars().count() as u32,
            uri_entropy: string_entropy(&h.uri),
            has_user_agent: !h.user_agent.is_empty(),
            user_agent_length: h.user_agent.chars().count() as u32,
            request_body_len: h.request_body_len,
            response_body_len: h.response_body_len,
            status_code: h.status_code,
        }
    }
}
