use crate::zeek_parser::types::FlowRecord;
use serde::{Deserialize, Serialize};

/// Core per-flow features derived directly from a single conn.log record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowFeatures {
    pub flow_id: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub duration: f64,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
    /// resp_bytes / (orig_bytes + 1). Low values suggest exfiltration.
    pub byte_ratio: f64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub pkt_ratio: f64,
    /// Numeric encoding of Zeek's conn_state (see [`encode_conn_state`]).
    pub conn_state_encoded: u8,
}

impl FlowFeatures {
    pub fn from_flow_record(r: &FlowRecord) -> Self {
        let byte_ratio = r.resp_bytes as f64 / (r.orig_bytes as f64 + 1.0);
        let pkt_ratio = r.resp_pkts as f64 / (r.orig_pkts as f64 + 1.0);
        FlowFeatures {
            flow_id: format!(
                "{}:{}:{}:{}:{:.3}",
                r.src_ip, r.dst_ip, r.dst_port, r.proto, r.timestamp
            ),
            src_ip: r.src_ip.clone(),
            dst_ip: r.dst_ip.clone(),
            dst_port: r.dst_port,
            proto: r.proto.clone(),
            duration: r.duration,
            orig_bytes: r.orig_bytes,
            resp_bytes: r.resp_bytes,
            byte_ratio,
            orig_pkts: r.orig_pkts,
            resp_pkts: r.resp_pkts,
            pkt_ratio,
            conn_state_encoded: encode_conn_state(&r.conn_state),
        }
    }
}

/// Encode Zeek's connection-state enum into a small integer for ML features.
pub fn encode_conn_state(state: &str) -> u8 {
    match state {
        "S1" => 1,
        "S2" => 2,
        "S3" => 3,
        "SF" => 4,
        "REJ" => 5,
        "RSTO" => 6,
        "RSTOS0" => 7,
        "RSTR" => 8,
        "RSTRH" => 9,
        "SH" => 10,
        "SHR" => 11,
        "OTH" => 12,
        _ => 0,
    }
}
