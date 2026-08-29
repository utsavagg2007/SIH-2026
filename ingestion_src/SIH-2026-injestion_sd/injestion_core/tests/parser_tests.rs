use ingestion_core::zeek_parser::{conn_log, dns_log, ssl_log, http_log};

/// A minimal but realistic Zeek conn.log (tabs are literal \t in this string).
fn conn_sample() -> &'static str {
    "#separator \x09\n\
#set_separator\t,\n\
#empty_field\t(empty)\n\
#unset_field\t-\n\
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\ttorig_ip_bytes\tresp_ip_bytes\n\
#types\tstring\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tcount\tcount\tcount\tcount\n\
1712345678.123456\tC1\t192.168.1.100\t49152\t10.0.0.1\t80\ttcp\thttp\t0.123\t1234\t5678\tSF\t10\t8\t1674\t972\n\
1712345679.000000\tC2\t192.168.1.101\t49153\t10.0.0.1\t443\ttcp\tssl\t1.5\t0\t2000\tSF\t5\t6\t500\t2500\n\
1712345680.500000\tC3\t192.168.1.100\t49154\t10.0.0.2\t22\ttcp\t-\t0.0\t0\t0\tREJ\t1\t0\t40\t0\n"
}

fn dns_sample() -> &'static str {
    "#separator \x09\n\
#set_separator\t,\n\
#empty_field\t(empty)\n\
#unset_field\t-\n\
#fields\tts\tuid\tquery\tqtype\trcode\n\
#types\tstring\tstring\tstring\tstring\tstring\n\
1712345678.200000\tD1\txkcdnsxqzmxyxq.example.com\tA\tNXDOMAIN\n\
1712345679.300000\tD2\tmail.google.com\tA\tNOERROR\n\
1712345680.100000\tD3\ttunneldataabcdefghijklmnopqrstuvwxyz.example.org\tTXT\tNOERROR\n"
}

fn ssl_sample() -> &'static str {
    "#separator \x09\n\
#set_separator\t,\n\
#empty_field\t(empty)\n\
#unset_field\t-\n\
#fields\tts\tuid\tversion\tcipher\tja3\tja3s\tserver_name\n\
#types\tstring\tstring\tstring\tstring\tstring\tstring\tstring\n\
1712345679.000000\tS1\tTLSv13\tTLS_AES_128_GCM_SHA256\tja3hashabc\tja3shashxyz\texample.com\n\
1712345681.000000\tS2\tTLSv12\tTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\t-\t-\t-\n"
}

fn http_sample() -> &'static str {
    "#separator \x09\n\
#set_separator\t,\n\
#empty_field\t(empty)\n\
#unset_field\t-\n\
#fields\tts\tuid\tmethod\thost\turi\tuser_agent\trequest_body_len\tresponse_body_len\tstatus_code\n\
#types\tstring\tstring\tstring\tstring\tstring\tstring\tcount\tcount\tcount\n\
1712345678.500000\tH1\tPOST\t10.0.0.5\t/upload\tcurl/8.0\t50000\t200\t200\n"
}

#[test]
fn parses_conn_log() {
    let recs = conn_log::parse_conn_log(conn_sample()).unwrap();
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[0].src_ip, "192.168.1.100");
    assert_eq!(recs[0].dst_port, 80);
    assert_eq!(recs[0].proto, "tcp");
    assert_eq!(recs[0].conn_state, "SF");
    assert_eq!(recs[2].conn_state, "REJ");
    assert_eq!(recs[2].orig_bytes, 0);
}

#[test]
fn parses_dns_log() {
    let recs = dns_log::parse_dns_log(dns_sample()).unwrap();
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[0].rcode, "NXDOMAIN");
    assert_eq!(recs[2].qtype, "TXT");
}

#[test]
fn parses_ssl_log() {
    let recs = ssl_log::parse_ssl_log(ssl_sample()).unwrap();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].ja3.as_deref(), Some("ja3hashabc"));
    assert_eq!(recs[1].ja3, None);
}

#[test]
fn parses_http_log() {
    let recs = http_log::parse_http_log(http_sample()).unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].method, "POST");
    assert_eq!(recs[0].request_body_len, 50000);
    assert_eq!(recs[0].status_code, 200);
}
