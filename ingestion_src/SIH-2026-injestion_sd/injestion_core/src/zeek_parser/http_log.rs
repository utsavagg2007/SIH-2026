use crate::zeek_parser::header::{field_value, parse_header, split_log};
use crate::zeek_parser::types::HttpRecord;

/// Parse Zeek's http.log into a list of [`HttpRecord`].
pub fn parse_http_log(content: &str) -> Result<Vec<HttpRecord>, String> {
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
        let u64f = |name: &str| get(name).and_then(|v| v.parse::<u64>().ok());
        let u16f = |name: &str| get(name).and_then(|v| v.parse::<u16>().ok());

        records.push(HttpRecord {
            uid: get("uid").unwrap_or_default(),
            timestamp: get("ts")
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0),
            method: get("method").unwrap_or_default(),
            host: get("host").unwrap_or_default(),
            uri: get("uri").unwrap_or_default(),
            user_agent: get("user_agent").unwrap_or_default(),
            request_body_len: u64f("request_body_len").unwrap_or(0),
            response_body_len: u64f("response_body_len").unwrap_or(0),
            status_code: u16f("status_code").unwrap_or(0),
        });
    }
    Ok(records)
}
