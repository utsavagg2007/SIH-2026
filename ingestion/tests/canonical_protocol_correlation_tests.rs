use ingestion_core::canonical::correlation::FlowCorrelationIndex;
use ingestion_core::canonical::http_producer::produce_http_observations_from_parse;
use ingestion_core::canonical::producer::{
    produce_flow_observations_from_parse, FlowProducerConfig,
};
use ingestion_core::canonical::tls_producer::produce_tls_observations_from_parse;
use ingestion_core::canonical::CanonicalData;
use ingestion_core::zeek_parser::conn_log::parse_conn_log_lossless;
use ingestion_core::zeek_parser::http_log::parse_http_log_lossless;
use ingestion_core::zeek_parser::ssl_log::parse_ssl_log_lossless;

const INPUT_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn config() -> FlowProducerConfig {
    FlowProducerConfig::new("sensor-alpha", INPUT_HASH, "2026-08-30T12:34:56Z").unwrap()
}

#[test]
fn one_flow_one_tls_and_three_http_rows_remain_independent_and_safely_linked() {
    let conn = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tip_proto\tduration\torig_pkts\n\
1\tC1\t192.0.2.1\t50000\t198.51.100.2\t8443\ttcp\t6\t1\t1\n";
    let flows =
        produce_flow_observations_from_parse(&parse_conn_log_lossless(conn).unwrap(), &config());
    assert_eq!(flows.observations.len(), 1);
    let flow_id = flows.observations[0].record_id.clone();
    let index = FlowCorrelationIndex::from_flow_observations(&flows.observations);

    let tls = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\n\
1.1\tC1\t192.0.2.1\t50000\t198.51.100.2\t8443\tTLSv13\tTLS_AES_128_GCM_SHA256\n";
    let tls_result = produce_tls_observations_from_parse(
        &parse_ssl_log_lossless(tls).unwrap(),
        &config(),
        Some(&index),
    );
    assert_eq!(tls_result.observations.len(), 1);
    let CanonicalData::Tls(tls_data) = &tls_result.observations[0].data else {
        panic!("expected TLS data");
    };
    assert_eq!(tls_data.flow_record_id.as_deref(), Some(flow_id.as_str()));
    assert_eq!(tls_data.ip_protocol, 6);

    let http = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tmethod\thost\turi\tstatus_code\trequest_body_len\tresponse_body_len\n\
1.2\tC1\t192.0.2.1\t50000\t198.51.100.2\t8443\tGET\ta.example\t/one\t200\t0\t1\n\
1.3\tC1\t192.0.2.1\t50000\t198.51.100.2\t8443\tPOST\tb.example\t/two\t201\t2\t3\n\
1.4\tC1\t192.0.2.1\t50000\t198.51.100.2\t8443\tPATCH\tc.example\t/three\t204\t4\t0\n";
    let http_result = produce_http_observations_from_parse(
        &parse_http_log_lossless(http).unwrap(),
        &config(),
        Some(&index),
    );
    assert_eq!(http_result.observations.len(), 3);
    assert_eq!(
        http_result
            .observations
            .iter()
            .map(|observation| {
                let CanonicalData::Http(data) = &observation.data else {
                    panic!("expected HTTP data");
                };
                data.uri.as_deref()
            })
            .collect::<Vec<_>>(),
        vec![Some("/one"), Some("/two"), Some("/three")]
    );
    assert!(http_result.observations.iter().all(|observation| {
        let CanonicalData::Http(data) = &observation.data else {
            return false;
        };
        data.flow_record_id.as_deref() == Some(flow_id.as_str()) && data.ip_protocol == 6
    }));

    let protocol_ids = tls_result
        .observations
        .iter()
        .chain(&http_result.observations)
        .map(|observation| observation.record_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(protocol_ids.len(), 4);
}
