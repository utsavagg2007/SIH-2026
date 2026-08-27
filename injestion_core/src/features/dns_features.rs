use crate::utils::entropy::{string_entropy, subdomain_entropy};
use crate::zeek_parser::types::DnsRecord;
use serde::{Deserialize, Serialize};

/// Features derived from a single DNS query (DGA / tunnelling detection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFeatures {
    pub uid: String,
    pub query_length: u32,
    /// Shannon entropy of the full query name (high => likely DGA).
    pub query_entropy: f64,
    /// Entropy of the subdomain portion only.
    pub subdomain_entropy: f64,
    pub is_txt: bool,
    pub label_count: u32,
}

impl DnsFeatures {
    pub fn from_dns_record(d: &DnsRecord) -> Self {
        let q = &d.query;
        DnsFeatures {
            uid: d.uid.clone(),
            query_length: q.chars().count() as u32,
            query_entropy: string_entropy(q),
            subdomain_entropy: subdomain_entropy(q),
            is_txt: d.qtype.eq_ignore_ascii_case("TXT"),
            label_count: q.trim_end_matches('.').split('.').count() as u32,
        }
    }
}
