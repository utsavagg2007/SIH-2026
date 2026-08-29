use pyo3::prelude::*;
use pyo3::types::PyModule;

pub mod zeek_parser;
pub mod features;
pub mod utils;

use zeek_parser::{conn_log, dns_log, ssl_log, http_log};
use zeek_parser::types::{FlowRecord, DnsRecord, SslRecord, HttpRecord};
use features::{flow, temporal, dns_features, tls_features, http_features};

fn read_file(path: &str) -> PyResult<String> {
    std::fs::read_to_string(path).map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))
}

fn to_py_err<T, E: std::fmt::Display>(r: Result<T, E>) -> PyResult<T> {
    r.map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

// ---- Parsers ----

#[pyfunction]
fn parse_conn_log(path: String) -> PyResult<String> {
    let content = read_file(&path)?;
    let records = to_py_err(conn_log::parse_conn_log(&content))?;
    to_py_err(serde_json::to_string(&records))
}

#[pyfunction]
fn parse_dns_log(path: String) -> PyResult<String> {
    let content = read_file(&path)?;
    let records = to_py_err(dns_log::parse_dns_log(&content))?;
    to_py_err(serde_json::to_string(&records))
}

#[pyfunction]
fn parse_ssl_log(path: String) -> PyResult<String> {
    let content = read_file(&path)?;
    let records = to_py_err(ssl_log::parse_ssl_log(&content))?;
    to_py_err(serde_json::to_string(&records))
}

#[pyfunction]
fn parse_http_log(path: String) -> PyResult<String> {
    let content = read_file(&path)?;
    let records = to_py_err(http_log::parse_http_log(&content))?;
    to_py_err(serde_json::to_string(&records))
}

// ---- Feature extraction ----

#[pyfunction]
fn extract_flow_features(conn_json: String) -> PyResult<String> {
    let records: Vec<FlowRecord> = to_py_err(serde_json::from_str(&conn_json))?;
    let feats: Vec<flow::FlowFeatures> = records.iter().map(flow::FlowFeatures::from_flow_record).collect();
    to_py_err(serde_json::to_string(&feats))
}

#[pyfunction]
fn extract_window_features(conn_json: String, window_secs: f64) -> PyResult<String> {
    let records: Vec<FlowRecord> = to_py_err(serde_json::from_str(&conn_json))?;
    let feats = temporal::sliding_window_features(&records, window_secs);
    to_py_err(serde_json::to_string(&feats))
}

#[pyfunction]
fn extract_dns_features(dns_json: String) -> PyResult<String> {
    let records: Vec<DnsRecord> = to_py_err(serde_json::from_str(&dns_json))?;
    let feats: Vec<dns_features::DnsFeatures> = records.iter().map(dns_features::DnsFeatures::from_dns_record).collect();
    to_py_err(serde_json::to_string(&feats))
}

#[pyfunction]
fn extract_tls_features(ssl_json: String) -> PyResult<String> {
    let records: Vec<SslRecord> = to_py_err(serde_json::from_str(&ssl_json))?;
    let feats: Vec<tls_features::TlsFeatures> = records.iter().map(tls_features::TlsFeatures::from_ssl_record).collect();
    to_py_err(serde_json::to_string(&feats))
}

#[pyfunction]
fn extract_http_features(http_json: String) -> PyResult<String> {
    let records: Vec<HttpRecord> = to_py_err(serde_json::from_str(&http_json))?;
    let feats: Vec<http_features::HttpFeatures> = records.iter().map(http_features::HttpFeatures::from_http_record).collect();
    to_py_err(serde_json::to_string(&feats))
}

#[pymodule]
fn ingestion_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_conn_log, m)?)?;
    m.add_function(wrap_pyfunction!(parse_dns_log, m)?)?;
    m.add_function(wrap_pyfunction!(parse_ssl_log, m)?)?;
    m.add_function(wrap_pyfunction!(parse_http_log, m)?)?;
    m.add_function(wrap_pyfunction!(extract_flow_features, m)?)?;
    m.add_function(wrap_pyfunction!(extract_window_features, m)?)?;
    m.add_function(wrap_pyfunction!(extract_dns_features, m)?)?;
    m.add_function(wrap_pyfunction!(extract_tls_features, m)?)?;
    m.add_function(wrap_pyfunction!(extract_http_features, m)?)?;
    Ok(())
}
