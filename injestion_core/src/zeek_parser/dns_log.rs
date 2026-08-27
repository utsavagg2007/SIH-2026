use crate::zeek_parser::header::{field_value, parse_header, split_log};
use crate::zeek_parser::types::DnsRecord;

/// Parse Zeek's dns.log into a list of [`DnsRecord`].
pub fn parse_dns_log(content: &str) -> Result<Vec<DnsRecord>, String> {
    let (header_lines, data_lines) = split_log(content);
    let header = parse_header(&header_lines)?;
    let expected = header.field_index.len();

    let mut records = Vec::with_capacity(data_lines.len());
    for line in data_lines {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < expected {
            continue;
        }
        let get = |name: &str| field_value(&cols, &header, name);

        records.push(DnsRecord {
            uid: get("uid").unwrap_or_default(),
            timestamp: get("ts")
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0),
            query: get("query").unwrap_or_default(),
            qtype: get("qtype").unwrap_or_default(),
            rcode: get("rcode").unwrap_or_default(),
        });
    }
    Ok(records)
}
