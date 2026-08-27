use crate::zeek_parser::header::{field_value, parse_header, split_log};
use crate::zeek_parser::types::FlowRecord;

/// Parse Zeek's conn.log into a list of [`FlowRecord`].
pub fn parse_conn_log(content: &str) -> Result<Vec<FlowRecord>, String> {
    let (header_lines, data_lines) = split_log(content);
    let header = parse_header(&header_lines)?;
    let expected = header.field_index.len();

    let mut records = Vec::with_capacity(data_lines.len());
    for line in data_lines {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < expected {
            continue; // skip malformed line
        }
        let get = |name: &str| field_value(&cols, &header, name);
        let u64f = |name: &str| get(name).and_then(|v| v.parse::<u64>().ok());
        let u16f = |name: &str| get(name).and_then(|v| v.parse::<u16>().ok());
        let f64f = |name: &str| get(name).and_then(|v| v.parse::<f64>().ok());

        records.push(FlowRecord {
            uid: get("uid").unwrap_or_default(),
            timestamp: f64f("ts").unwrap_or(0.0),
            src_ip: get("id.orig_h").unwrap_or_default(),
            src_port: u16f("id.orig_p").unwrap_or(0),
            dst_ip: get("id.resp_h").unwrap_or_default(),
            dst_port: u16f("id.resp_p").unwrap_or(0),
            proto: get("proto").unwrap_or_default(),
            service: get("service").unwrap_or_default(),
            duration: f64f("duration").unwrap_or(0.0),
            orig_bytes: u64f("orig_bytes").unwrap_or(0),
            resp_bytes: u64f("resp_bytes").unwrap_or(0),
            conn_state: get("conn_state").unwrap_or_default(),
            orig_pkts: u64f("orig_pkts").unwrap_or(0),
            resp_pkts: u64f("resp_pkts").unwrap_or(0),
            orig_ip_bytes: u64f("orig_ip_bytes").unwrap_or(0),
            resp_ip_bytes: u64f("resp_ip_bytes").unwrap_or(0),
        });
    }
    Ok(records)
}
