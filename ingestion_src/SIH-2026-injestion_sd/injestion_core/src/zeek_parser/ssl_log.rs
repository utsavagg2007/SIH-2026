use crate::zeek_parser::header::{field_value, parse_header, split_log};
use crate::zeek_parser::types::SslRecord;

/// Parse Zeek's ssl.log into a list of [`SslRecord`].
/// Requires a Zeek build with JA3/JA4 support (e.g. activecm/zeek) for the
/// `ja3` / `ja3s` columns to be populated.
pub fn parse_ssl_log(content: &str) -> Result<Vec<SslRecord>, String> {
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

        records.push(SslRecord {
            uid: get("uid").unwrap_or_default(),
            timestamp: get("ts")
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0),
            version: get("version").unwrap_or_default(),
            cipher: get("cipher").unwrap_or_default(),
            ja3: get("ja3"),
            ja3s: get("ja3s"),
            server_name: get("server_name").unwrap_or_default(),
        });
    }
    Ok(records)
}
