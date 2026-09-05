use ingestion_core::features::{dns_features, flow, temporal, tls_features};
use ingestion_core::utils::entropy::string_entropy;
use ingestion_core::zeek_parser::types::{DnsRecord, FlowRecord, SslRecord};

fn sample_flows() -> Vec<FlowRecord> {
    vec![
        FlowRecord {
            uid: "C1".into(),
            timestamp: 100.0,
            src_ip: "192.168.1.100".into(),
            src_port: 1111,
            dst_ip: "10.0.0.1".into(),
            dst_port: 80,
            proto: "tcp".into(),
            service: "http".into(),
            duration: 0.1,
            orig_bytes: 1000,
            resp_bytes: 200,
            conn_state: "SF".into(),
            orig_pkts: 10,
            resp_pkts: 8,
            orig_ip_bytes: 1200,
            resp_ip_bytes: 400,
        },
        FlowRecord {
            uid: "C2".into(),
            timestamp: 100.5,
            src_ip: "192.168.1.100".into(),
            src_port: 1112,
            dst_ip: "10.0.0.2".into(),
            dst_port: 443,
            proto: "tcp".into(),
            service: "ssl".into(),
            duration: 0.2,
            orig_bytes: 50,
            resp_bytes: 5000,
            conn_state: "SF".into(),
            orig_pkts: 5,
            resp_pkts: 12,
            orig_ip_bytes: 300,
            resp_ip_bytes: 6000,
        },
    ]
}

#[test]
fn flow_features_compute_ratios() {
    let f = flow::FlowFeatures::from_flow_record(&sample_flows()[1]);
    // resp_bytes / (orig_bytes + 1) ~= 5000/51
    assert!(f.byte_ratio > 90.0);
    assert_eq!(f.conn_state_encoded, flow::encode_conn_state("SF"));
    assert_eq!(f.conn_state_encoded, 4);
}

#[test]
fn window_features_capture_rate_and_entropy() {
    let feats = temporal::sliding_window_features(&sample_flows(), 60.0);
    assert_eq!(feats.len(), 2);
    assert!(feats[1].flow_rate > 0.0);
    // same source IP in window => entropy 0
    assert_eq!(feats[1].src_ip_entropy, 0.0);
    assert_eq!(feats[1].unique_dst_ips, 2);
}

#[test]
fn dns_entropy_detects_random_query() {
    let dga = DnsRecord {
        uid: "D1".into(),
        timestamp: 0.0,
        query: "xkcdnsxqzmxyxq.example.com".into(),
        qtype: "A".into(),
        rcode: "NXDOMAIN".into(),
    };
    let normal = DnsRecord {
        uid: "D2".into(),
        timestamp: 0.0,
        query: "mail.google.com".into(),
        qtype: "A".into(),
        rcode: "NOERROR".into(),
    };
    let df = dns_features::DnsFeatures::from_dns_record(&dga);
    let nf = dns_features::DnsFeatures::from_dns_record(&normal);
    assert!(df.query_entropy > nf.query_entropy);
    assert!(!df.is_txt);
}

#[test]
fn tls_features_flag_ja3() {
    let s = SslRecord {
        uid: "S1".into(),
        timestamp: 0.0,
        version: "TLSv13".into(),
        cipher: "TLS_AES_128_GCM_SHA256".into(),
        ja3: Some("abc".into()),
        ja3s: Some("xyz".into()),
        server_name: "example.com".into(),
    };
    let tf = tls_features::TlsFeatures::from_ssl_record(&s);
    assert!(tf.has_ja3);
    assert_eq!(tf.ssl_version_encoded, 4);
}

#[test]
fn entropy_of_uniform_is_higher_than_constant() {
    let constant = string_entropy("aaaaaaaa");
    let mixed = string_entropy("abcdefgh");
    assert!(mixed > constant);
}
