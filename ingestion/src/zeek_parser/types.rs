use serde::{Deserialize, Serialize};

/// A connection record parsed from Zeek's conn.log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowRecord {
    pub uid: String,
    pub timestamp: f64,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub service: String,
    pub duration: f64,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    pub conn_state: String,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_ip_bytes: u64,
    pub resp_ip_bytes: u64,
}

/// A DNS record parsed from Zeek's dns.log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub uid: String,
    pub timestamp: f64,
    pub query: String,
    pub qtype: String,
    pub rcode: String,
}

/// An SSL/TLS record parsed from Zeek's ssl.log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslRecord {
    pub uid: String,
    pub timestamp: f64,
    pub version: String,
    pub cipher: String,
    pub ja3: Option<String>,
    pub ja3s: Option<String>,
    pub server_name: String,
}

/// An HTTP record parsed from Zeek's http.log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRecord {
    pub uid: String,
    pub timestamp: f64,
    pub method: String,
    pub host: String,
    pub uri: String,
    pub user_agent: String,
    pub request_body_len: u64,
    pub response_body_len: u64,
    pub status_code: u16,
}
