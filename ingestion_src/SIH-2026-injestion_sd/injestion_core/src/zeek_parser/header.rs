use std::collections::HashMap;

/// Parsed Zeek log header metadata.
pub struct ZeekHeader {
    /// Maps a field name (from `#fields`) to its column index.
    pub field_index: HashMap<String, usize>,
    /// Separator used inside set-typed fields (from `#set_separator`).
    pub set_separator: String,
    /// String representing an empty value (from `#empty_field`).
    pub empty_field: String,
    /// String representing an unset value (from `#unset_field`).
    pub unset_field: String,
}

/// Parse the `#`-prefixed header lines of a Zeek log into a [`ZeekHeader`].
pub fn parse_header(header_lines: &[&str]) -> Result<ZeekHeader, String> {
    let mut field_index: HashMap<String, usize> = HashMap::new();
    let mut set_separator = ",".to_string();
    let mut empty_field = "(empty)".to_string();
    let mut unset_field = "-".to_string();

    for line in header_lines {
        if let Some(rest) = line.strip_prefix("#fields\t") {
            for (i, name) in rest.split('\t').enumerate() {
                field_index.insert(name.to_string(), i);
            }
        } else if let Some(rest) = line.strip_prefix("#set_separator\t") {
            set_separator = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("#empty_field\t") {
            empty_field = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("#unset_field\t") {
            unset_field = rest.to_string();
        }
    }

    if field_index.is_empty() {
        return Err("No #fields header found in Zeek log".to_string());
    }

    Ok(ZeekHeader {
        field_index,
        set_separator,
        empty_field,
        unset_field,
    })
}

/// Return the string value of a named field, or `None` if it is unset/empty.
pub fn field_value<'a>(cols: &'a [&'a str], header: &ZeekHeader, name: &str) -> Option<String> {
    let idx = *header.field_index.get(name)?;
    let v = cols.get(idx)?;
    if *v == header.unset_field || *v == header.empty_field {
        None
    } else {
        Some(v.to_string())
    }
}

/// Split a data line into columns by tab and extract the header lines.
pub fn split_log(content: &str) -> (Vec<&str>, Vec<&str>) {
    let lines: Vec<&str> = content.lines().collect();
    let header_lines: Vec<&str> = lines.iter().filter(|l| l.starts_with('#')).copied().collect();
    let data_lines: Vec<&str> = lines
        .iter()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .copied()
        .collect();
    (header_lines, data_lines)
}
