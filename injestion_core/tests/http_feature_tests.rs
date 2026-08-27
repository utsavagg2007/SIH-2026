use ingestion_core::features::http_features::HttpFeatures;
use ingestion_core::zeek_parser::types::HttpRecord;

fn sample() -> HttpRecord {
    HttpRecord {
        uid: "H1".into(),
        timestamp: 100.0,
        method: "POST".into(),
        host: "example.com".into(),
        uri: "/a/b/c?x=1".into(),
        user_agent: "curl/8.0".into(),
        request_body_len: 10,
        response_body_len: 200,
        status_code: 200,
    }
}

#[test]
fn http_feature_fields() {
    let f = HttpFeatures::from_http_record(&sample());
    assert_eq!(f.uid, "H1");
    assert_eq!(f.method_encoded, 2);
    assert!(f.has_user_agent);
    assert_eq!(f.status_code, 200);
    assert_eq!(f.uri_length, 10);
    assert!(f.uri_entropy > 0.0);
}

#[test]
fn http_missing_user_agent() {
    let mut r = sample();
    r.user_agent = String::new();
    let f = HttpFeatures::from_http_record(&r);
    assert!(!f.has_user_agent);
    assert_eq!(f.user_agent_length, 0);
}
