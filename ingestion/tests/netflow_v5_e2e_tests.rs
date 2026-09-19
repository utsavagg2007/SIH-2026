use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ingestion_core::canonical::id::{
    generate_netflow_v5_record_id, generate_zeek_record_id, IdentityObservationType,
    NetFlowV5IdentityCoordinates, ZeekLogName, NETFLOW_V5_ID_ALGORITHM_MARKER,
    NETFLOW_V5_ID_NAMESPACE, ZEEK_ID_ALGORITHM_MARKER, ZEEK_ID_NAMESPACE,
};
use ingestion_core::canonical::{CanonicalData, InputMode};
use ingestion_core::netflow::input::{
    process_pcap_file, process_raw_datagram_file, write_pcap_canonical_jsonl,
    write_raw_datagram_canonical_jsonl, OfflineInputDiagnosticKind, OfflineInputError,
    PcapInputConfig, RawDatagramInputConfig,
};
use ingestion_core::netflow::normalize::NetFlowV5NormalizationConfig;
use ingestion_core::netflow::pcap::{ClassicPcapError, PcapPacketDiagnosticKind, PcapUdpFilters};
use ingestion_core::netflow::v5::{parse_netflow_v5_datagram, NetFlowV5Datagram};
use sha2::{Digest, Sha256};

const TEST_MAX_FLOW_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const EXPORTER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 50);
const COLLECTOR_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 60);
const NETFLOW_PORT: u16 = 2055;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("export")
        .join("netflow_v5")
}

fn fixture(name: &str) -> Vec<u8> {
    fs::read(fixture_dir().join(format!("{name}.bin"))).expect("fixture must be readable")
}

fn decode_hex_fixture(path: PathBuf) -> Vec<u8> {
    let text = fs::read_to_string(path).expect("hex fixture must be readable");
    let digits = text.trim().as_bytes();
    assert_eq!(digits.len() % 2, 0, "hex fixture length");
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for index in (0..digits.len()).step_by(2) {
        let high = (digits[index] as char)
            .to_digit(16)
            .expect("hex high nibble");
        let low = (digits[index + 1] as char)
            .to_digit(16)
            .expect("hex low nibble");
        bytes.push(((high << 4) | low) as u8);
    }
    bytes
}

fn test_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "sih-netflow-f4-{name}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).expect("test directory");
    path
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn canonical_jsonl(observations: &[ingestion_core::canonical::CanonicalObservation]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for observation in observations {
        serde_json::to_writer(&mut bytes, observation).expect("serialize canonical observation");
        bytes.push(b'\n');
    }
    bytes
}

#[test]
fn zeek_and_netflow_v5_record_ids_use_distinct_namespaces() {
    const SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    assert_ne!(ZEEK_ID_ALGORITHM_MARKER, NETFLOW_V5_ID_ALGORITHM_MARKER);
    assert_ne!(ZEEK_ID_NAMESPACE, NETFLOW_V5_ID_NAMESPACE);

    let zeek = generate_zeek_record_id(
        "same-sensor",
        SHA256,
        IdentityObservationType::Flow,
        ZeekLogName::Conn,
        "same-source-coordinate",
        0,
    )
    .expect("valid Zeek identity coordinates");
    let netflow = generate_netflow_v5_record_id(&NetFlowV5IdentityCoordinates {
        sensor_id: "same-sensor",
        input_sha256: SHA256,
        exporter_id: "same-source-coordinate",
        engine_type: 0,
        engine_id: 0,
        flow_sequence: 0,
        datagram_ordinal: 0,
        record_ordinal: 0,
    })
    .expect("valid NetFlow identity coordinates");

    assert_ne!(zeek, netflow);
}

fn raw_config(exporter: &str) -> RawDatagramInputConfig {
    let mut config = RawDatagramInputConfig::new("sensor-f4", exporter, "2026-09-18T00:00:00Z");
    config.normalization = NetFlowV5NormalizationConfig {
        max_flow_age_ms: TEST_MAX_FLOW_AGE_MS,
    };
    config
}

fn filters() -> PcapUdpFilters {
    PcapUdpFilters::new(
        Some(EXPORTER_IP),
        Some(COLLECTOR_IP),
        Vec::new(),
        vec![NETFLOW_PORT],
    )
    .expect("valid filters")
}

fn pcap_config(exporter: &str) -> PcapInputConfig {
    let mut config = PcapInputConfig::new("sensor-f4", exporter, filters());
    config.normalization = NetFlowV5NormalizationConfig {
        max_flow_age_ms: TEST_MAX_FLOW_AGE_MS,
    };
    config
}

#[derive(Clone, Copy)]
enum PcapEncoding {
    LittleMicroseconds,
    BigMicroseconds,
    LittleNanoseconds,
    BigNanoseconds,
}

fn push_u16(target: &mut Vec<u8>, value: u16, encoding: PcapEncoding) {
    let bytes = match encoding {
        PcapEncoding::LittleMicroseconds | PcapEncoding::LittleNanoseconds => value.to_le_bytes(),
        PcapEncoding::BigMicroseconds | PcapEncoding::BigNanoseconds => value.to_be_bytes(),
    };
    target.extend_from_slice(&bytes);
}

fn push_u32(target: &mut Vec<u8>, value: u32, encoding: PcapEncoding) {
    let bytes = match encoding {
        PcapEncoding::LittleMicroseconds | PcapEncoding::LittleNanoseconds => value.to_le_bytes(),
        PcapEncoding::BigMicroseconds | PcapEncoding::BigNanoseconds => value.to_be_bytes(),
    };
    target.extend_from_slice(&bytes);
}

fn classic_pcap(encoding: PcapEncoding, packets: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(match encoding {
        PcapEncoding::LittleMicroseconds => &[0xd4, 0xc3, 0xb2, 0xa1],
        PcapEncoding::BigMicroseconds => &[0xa1, 0xb2, 0xc3, 0xd4],
        PcapEncoding::LittleNanoseconds => &[0x4d, 0x3c, 0xb2, 0xa1],
        PcapEncoding::BigNanoseconds => &[0xa1, 0xb2, 0x3c, 0x4d],
    });
    push_u16(&mut bytes, 2, encoding);
    push_u16(&mut bytes, 4, encoding);
    push_u32(&mut bytes, 0, encoding);
    push_u32(&mut bytes, 0, encoding);
    push_u32(&mut bytes, 65_535, encoding);
    push_u32(&mut bytes, 1, encoding);
    for (seconds, fraction, packet) in packets {
        push_u32(&mut bytes, *seconds, encoding);
        push_u32(&mut bytes, *fraction, encoding);
        push_u32(
            &mut bytes,
            u32::try_from(packet.len()).expect("small packet"),
            encoding,
        );
        push_u32(
            &mut bytes,
            u32::try_from(packet.len()).expect("small packet"),
            encoding,
        );
        bytes.extend_from_slice(packet);
    }
    bytes
}

fn ethernet_ipv4_udp(
    payload: &[u8],
    source_port: u16,
    destination_port: u16,
    vlan: bool,
) -> Vec<u8> {
    let ethernet_len = if vlan { 18 } else { 14 };
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let mut frame = Vec::with_capacity(ethernet_len + ip_len);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    if vlan {
        frame.extend_from_slice(&0x8100_u16.to_be_bytes());
        frame.extend_from_slice(&7_u16.to_be_bytes());
        frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    } else {
        frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    }
    frame.push(0x45);
    frame.push(0);
    frame.extend_from_slice(&u16::try_from(ip_len).expect("small packet").to_be_bytes());
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.push(64);
    frame.push(17);
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&EXPORTER_IP.octets());
    frame.extend_from_slice(&COLLECTOR_IP.octets());
    frame.extend_from_slice(&source_port.to_be_bytes());
    frame.extend_from_slice(&destination_port.to_be_bytes());
    frame.extend_from_slice(&u16::try_from(udp_len).expect("small UDP").to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn unrelated_tcp_frame() -> Vec<u8> {
    let mut frame = ethernet_ipv4_udp(b"not considered", 1234, NETFLOW_PORT, false);
    frame[23] = 6;
    frame
}

fn with_sequence(mut payload: Vec<u8>, sequence: u32) -> Vec<u8> {
    payload[16..20].copy_from_slice(&sequence.to_be_bytes());
    payload
}

fn encode_parsed_v5(datagram: &NetFlowV5Datagram) -> Vec<u8> {
    let header = &datagram.header;
    let mut bytes = Vec::with_capacity(24 + datagram.records.len() * 48);
    bytes.extend_from_slice(&header.version.to_be_bytes());
    bytes.extend_from_slice(&header.count.to_be_bytes());
    bytes.extend_from_slice(&header.sys_uptime_ms.to_be_bytes());
    bytes.extend_from_slice(&header.unix_secs.to_be_bytes());
    bytes.extend_from_slice(&header.unix_nsecs.to_be_bytes());
    bytes.extend_from_slice(&header.flow_sequence.to_be_bytes());
    bytes.push(header.engine_type);
    bytes.push(header.engine_id);
    bytes.extend_from_slice(&header.raw_sampling.to_be_bytes());
    for record in &datagram.records {
        bytes.extend_from_slice(&record.src_addr.octets());
        bytes.extend_from_slice(&record.dst_addr.octets());
        bytes.extend_from_slice(&record.next_hop.octets());
        bytes.extend_from_slice(&record.input_ifindex.to_be_bytes());
        bytes.extend_from_slice(&record.output_ifindex.to_be_bytes());
        bytes.extend_from_slice(&record.packet_count.to_be_bytes());
        bytes.extend_from_slice(&record.octet_count.to_be_bytes());
        bytes.extend_from_slice(&record.first_sys_uptime_ms.to_be_bytes());
        bytes.extend_from_slice(&record.last_sys_uptime_ms.to_be_bytes());
        bytes.extend_from_slice(&record.src_port.to_be_bytes());
        bytes.extend_from_slice(&record.dst_port.to_be_bytes());
        bytes.push(record.pad1);
        bytes.push(record.tcp_flags);
        bytes.push(record.protocol);
        bytes.push(record.tos);
        bytes.extend_from_slice(&record.src_as.to_be_bytes());
        bytes.extend_from_slice(&record.dst_as.to_be_bytes());
        bytes.push(record.src_mask);
        bytes.push(record.dst_mask);
        bytes.extend_from_slice(&record.pad2.to_be_bytes());
    }
    bytes
}

fn mixed_pcap() -> Vec<u8> {
    let first = fixture("minimal_valid_one_record");
    let first_sequence = u32::from_be_bytes(first[16..20].try_into().expect("sequence"));
    let second = with_sequence(fixture("multiple_records"), first_sequence.wrapping_add(1));
    classic_pcap(
        PcapEncoding::LittleMicroseconds,
        &[
            (1_700_000_000, 100_000, unrelated_tcp_frame()),
            (
                1_700_000_000,
                200_000,
                ethernet_ipv4_udp(b"unrelated", 50000, 9999, false),
            ),
            (
                1_700_000_000,
                300_000,
                ethernet_ipv4_udp(b"malformed candidate", 50000, NETFLOW_PORT, false),
            ),
            (
                1_700_000_000,
                400_000,
                ethernet_ipv4_udp(&first, 50000, NETFLOW_PORT, false),
            ),
            (
                1_700_000_001,
                500_000,
                ethernet_ipv4_udp(&second, 50000, NETFLOW_PORT, true),
            ),
        ],
    )
}

#[test]
fn raw_artifact_wrapper_hashes_bytes_replays_deterministically_and_is_path_independent() {
    let dir = test_dir("raw");
    let bytes = fixture("minimal_valid_one_record");
    let expected_sha = digest(&bytes);
    let original = dir.join("original.bin");
    let renamed = dir.join("renamed.dat");
    fs::write(&original, &bytes).expect("write original");
    fs::write(&renamed, &bytes).expect("write renamed");
    let mut config = raw_config("exporter-a");
    config.expected_sha256 = Some(expected_sha.clone());

    let baseline = process_raw_datagram_file(&original, &config).expect("raw processing");
    assert_eq!(baseline.artifact_sha256, expected_sha);
    assert_eq!(baseline.observations.len(), 1);
    assert_eq!(baseline.datagrams_accepted, 1);
    let expected_jsonl = canonical_jsonl(&baseline.observations);
    for _ in 0..10 {
        let replay = process_raw_datagram_file(&original, &config).expect("raw replay");
        assert_eq!(canonical_jsonl(&replay.observations), expected_jsonl);
    }
    let renamed_result = process_raw_datagram_file(&renamed, &config).expect("renamed raw");
    assert_eq!(
        canonical_jsonl(&renamed_result.observations),
        expected_jsonl
    );

    let output = dir.join("raw.canonical.jsonl");
    write_raw_datagram_canonical_jsonl(&original, &output, &config).expect("atomic raw output");
    assert_eq!(fs::read(&output).expect("output bytes"), expected_jsonl);
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn raw_hash_mismatch_mutation_and_exporter_identity_fail_or_change_as_required() {
    let dir = test_dir("raw-negative");
    let bytes = fixture("minimal_valid_one_record");
    let input = dir.join("input.bin");
    fs::write(&input, &bytes).expect("write input");
    let original =
        process_raw_datagram_file(&input, &raw_config("exporter-a")).expect("original processing");

    let mut wrong = raw_config("exporter-a");
    wrong.expected_sha256 = Some("00".repeat(32));
    assert!(matches!(
        process_raw_datagram_file(&input, &wrong),
        Err(OfflineInputError::ArtifactSha256Mismatch { .. })
    ));

    let mut mutated = bytes;
    mutated[24] ^= 1;
    fs::write(&input, &mutated).expect("mutate input");
    let changed =
        process_raw_datagram_file(&input, &raw_config("exporter-a")).expect("mutated valid input");
    assert_ne!(original.artifact_sha256, changed.artifact_sha256);
    assert_ne!(
        original.observations[0].record_id,
        changed.observations[0].record_id
    );

    fs::write(&input, fixture("minimal_valid_one_record")).expect("restore input");
    let other_exporter =
        process_raw_datagram_file(&input, &raw_config("exporter-b")).expect("other exporter");
    assert_ne!(
        original.observations[0].record_id,
        other_exporter.observations[0].record_id
    );
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn pcap_e2e_filters_validates_orders_hashes_and_replays_ten_times() {
    let dir = test_dir("pcap-e2e");
    let bytes = mixed_pcap();
    let input = dir.join("capture.pcap");
    let renamed = dir.join("renamed.capture");
    fs::write(&input, &bytes).expect("write PCAP");
    fs::write(&renamed, &bytes).expect("write renamed PCAP");
    let mut config = pcap_config("pcap-exporter");
    config.expected_sha256 = Some(digest(&bytes));

    let baseline = process_pcap_file(&input, &config).expect("PCAP processing");
    assert_eq!(baseline.packets_seen, 5);
    assert_eq!(baseline.candidates_seen, 3);
    assert_eq!(baseline.datagrams_accepted, 2);
    assert_eq!(baseline.observations.len(), 4);
    assert!(baseline.diagnostics.iter().any(|diagnostic| {
        diagnostic.kind == OfflineInputDiagnosticKind::NetFlowV5Rejected
            && diagnostic.packet_ordinal == Some(2)
    }));
    assert_eq!(
        baseline.observations[0].observed_at,
        "2023-11-14T22:13:20.400Z"
    );
    assert_eq!(
        baseline.observations[1].observed_at,
        "2023-11-14T22:13:21.500Z"
    );
    assert_eq!(
        baseline.observations[0].provenance.input_mode,
        InputMode::PcapFile
    );
    let expected_pcap_sha = digest(&bytes);
    assert_eq!(
        baseline.observations[0].provenance.input_sha256.as_deref(),
        Some(expected_pcap_sha.as_str())
    );
    let source_ips = baseline
        .observations
        .iter()
        .map(|observation| match &observation.data {
            CanonicalData::Flow(flow) => flow.src_ip.as_str(),
            _ => panic!("expected flow"),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        source_ips,
        vec!["192.0.2.10", "192.0.2.200", "192.0.2.1", "192.0.2.150"]
    );

    let expected_jsonl = canonical_jsonl(&baseline.observations);
    assert_eq!(
        digest(&expected_jsonl),
        "c03f1713825e13ba84e40d1e8b95379b8e9be43707dca79bf87b1ee466203e99"
    );
    for _ in 0..10 {
        let replay = process_pcap_file(&input, &config).expect("PCAP replay");
        assert_eq!(canonical_jsonl(&replay.observations), expected_jsonl);
    }
    let renamed_result = process_pcap_file(&renamed, &config).expect("renamed PCAP");
    assert_eq!(
        canonical_jsonl(&renamed_result.observations),
        expected_jsonl
    );

    let output = dir.join("pcap.canonical.jsonl");
    write_pcap_canonical_jsonl(&input, &output, &config).expect("atomic PCAP output");
    assert_eq!(fs::read(&output).expect("output bytes"), expected_jsonl);
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn pcap_microsecond_nanosecond_and_byte_orders_map_capture_time_exactly() {
    let dir = test_dir("pcap-time");
    let payload = fixture("minimal_valid_one_record");
    for (index, encoding, fraction, expected) in [
        (
            0,
            PcapEncoding::LittleMicroseconds,
            123_456,
            "2023-11-14T22:13:20.123456Z",
        ),
        (
            1,
            PcapEncoding::BigMicroseconds,
            123_456,
            "2023-11-14T22:13:20.123456Z",
        ),
        (
            2,
            PcapEncoding::LittleNanoseconds,
            123_456_789,
            "2023-11-14T22:13:20.123456789Z",
        ),
        (
            3,
            PcapEncoding::BigNanoseconds,
            123_456_789,
            "2023-11-14T22:13:20.123456789Z",
        ),
    ] {
        let bytes = classic_pcap(
            encoding,
            &[(
                1_700_000_000,
                fraction,
                ethernet_ipv4_udp(&payload, 50000, NETFLOW_PORT, false),
            )],
        );
        let path = dir.join(format!("precision-{index}.pcap"));
        fs::write(&path, bytes).expect("write precision fixture");
        let result =
            process_pcap_file(&path, &pcap_config("precision-exporter")).expect("precision PCAP");
        assert_eq!(result.observations[0].observed_at, expected);
    }
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn malformed_classic_pcap_headers_fail_without_publishing() {
    let dir = test_dir("pcap-fatal");
    let output = dir.join("must-not-exist.jsonl");
    for (name, bytes, expected) in [
        (
            "global",
            vec![0xd4, 0xc3, 0xb2],
            "classic PCAP global header is truncated",
        ),
        (
            "packet-header",
            {
                let mut value = classic_pcap(PcapEncoding::LittleMicroseconds, &[]);
                value.extend_from_slice(&[0_u8; 7]);
                value
            },
            "truncated PCAP record header",
        ),
        (
            "packet-data",
            {
                let mut value = classic_pcap(PcapEncoding::LittleMicroseconds, &[]);
                value.extend_from_slice(&1_700_000_000_u32.to_le_bytes());
                value.extend_from_slice(&0_u32.to_le_bytes());
                value.extend_from_slice(&100_u32.to_le_bytes());
                value.extend_from_slice(&100_u32.to_le_bytes());
                value.extend_from_slice(&[0_u8; 10]);
                value
            },
            "data is truncated",
        ),
    ] {
        let path = dir.join(format!("{name}.pcap"));
        fs::write(&path, bytes).expect("write malformed PCAP");
        let error = write_pcap_canonical_jsonl(&path, &output, &pcap_config("malformed-exporter"))
            .expect_err("malformed PCAP must fail");
        assert!(error.to_string().contains(expected));
        assert!(!output.exists());
    }
    fs::remove_dir_all(dir).expect("cleanup");
}

fn one_packet_result(frame: Vec<u8>) -> ingestion_core::netflow::input::OfflineQualificationResult {
    let dir = test_dir("packet-diagnostic");
    let bytes = classic_pcap(
        PcapEncoding::LittleMicroseconds,
        &[(1_700_000_000, 0, frame)],
    );
    let path = dir.join("input.pcap");
    fs::write(&path, bytes).expect("write packet diagnostic PCAP");
    let result = process_pcap_file(&path, &pcap_config("diagnostic-exporter"))
        .expect("packet-level fault must be diagnosed, not fatal");
    fs::remove_dir_all(dir).expect("cleanup");
    result
}

#[test]
fn malformed_packet_layers_are_bounded_diagnostics_and_never_fake_flows() {
    let payload = fixture("minimal_valid_one_record");
    let valid = ethernet_ipv4_udp(&payload, 50000, NETFLOW_PORT, false);
    let cases = [
        (
            vec![0_u8; 10],
            OfflineInputDiagnosticKind::Packet(PcapPacketDiagnosticKind::EthernetTooShort),
        ),
        (
            {
                let mut frame = valid.clone();
                frame[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
                frame
            },
            OfflineInputDiagnosticKind::Packet(PcapPacketDiagnosticKind::Ipv6Unsupported),
        ),
        (
            {
                let mut frame = valid.clone();
                frame[14] = 0x44;
                frame
            },
            OfflineInputDiagnosticKind::Packet(PcapPacketDiagnosticKind::Ipv4HeaderLengthInvalid),
        ),
        (
            {
                let mut frame = valid.clone();
                frame[16..18].copy_from_slice(&10_u16.to_be_bytes());
                frame
            },
            OfflineInputDiagnosticKind::Packet(PcapPacketDiagnosticKind::Ipv4TotalLengthInvalid),
        ),
        (
            {
                let mut frame = valid.clone();
                frame[38..40].copy_from_slice(&7_u16.to_be_bytes());
                frame
            },
            OfflineInputDiagnosticKind::Packet(PcapPacketDiagnosticKind::UdpLengthInvalid),
        ),
        (
            {
                let mut frame = valid.clone();
                frame[38..40].copy_from_slice(&u16::MAX.to_be_bytes());
                frame
            },
            OfflineInputDiagnosticKind::Packet(PcapPacketDiagnosticKind::UdpPayloadTruncated),
        ),
        (
            {
                let mut frame = valid.clone();
                frame[20..22].copy_from_slice(&0x2000_u16.to_be_bytes());
                frame
            },
            OfflineInputDiagnosticKind::Packet(PcapPacketDiagnosticKind::FragmentedUdpUnsupported),
        ),
    ];
    for (frame, expected) in cases {
        let result = one_packet_result(frame);
        assert!(result.observations.is_empty());
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(result.diagnostics[0].kind, expected);
    }
}

#[test]
fn malformed_netflow_candidate_is_diagnosed_after_port_filter_and_f2_validation() {
    let mut malformed = fixture("minimal_valid_one_record");
    malformed[2..4].copy_from_slice(&2_u16.to_be_bytes());
    let result = one_packet_result(ethernet_ipv4_udp(&malformed, 50000, NETFLOW_PORT, false));
    assert!(result.observations.is_empty());
    assert_eq!(result.candidates_seen, 1);
    assert_eq!(result.datagrams_accepted, 0);
    assert_eq!(
        result.diagnostics[0].kind,
        OfflineInputDiagnosticKind::NetFlowV5Rejected
    );
}

#[test]
fn existing_output_is_never_overwritten_and_processing_failure_has_no_partial_output() {
    let dir = test_dir("atomic");
    let raw = dir.join("input.bin");
    fs::write(&raw, fixture("minimal_valid_one_record")).expect("write raw");
    let output = dir.join("canonical.jsonl");
    fs::write(&output, b"existing evidence").expect("write existing output");
    assert!(
        write_raw_datagram_canonical_jsonl(&raw, &output, &raw_config("atomic-exporter")).is_err()
    );
    assert_eq!(
        fs::read(&output).expect("existing bytes"),
        b"existing evidence"
    );

    let malformed = dir.join("malformed.pcap");
    fs::write(&malformed, [0xd4, 0xc3]).expect("write malformed");
    let absent = dir.join("absent.jsonl");
    assert!(
        write_pcap_canonical_jsonl(&malformed, &absent, &pcap_config("atomic-exporter")).is_err()
    );
    assert!(!absent.exists());
    let companions = fs::read_dir(&dir)
        .expect("read dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.contains("canonical.lock") || name.ends_with(".tmp"))
        .collect::<Vec<_>>();
    assert!(
        companions.is_empty(),
        "unexpected output companions: {companions:?}"
    );
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn pcap_limits_and_filter_configuration_fail_closed() {
    assert!(PcapUdpFilters::new(None, None, Vec::new(), Vec::new()).is_err());
    let dir = test_dir("limits");
    let bytes = mixed_pcap();
    let path = dir.join("input.pcap");
    fs::write(&path, bytes).expect("write PCAP");
    let mut packet_limited = pcap_config("limited-exporter");
    packet_limited.max_captured_packet_bytes = 8;
    assert!(matches!(
        process_pcap_file(&path, &packet_limited),
        Err(OfflineInputError::Pcap(
            ClassicPcapError::CapturedLengthExceedsLimit { .. }
        ))
    ));
    let mut observation_limited = pcap_config("limited-exporter");
    observation_limited.max_canonical_observations = 1;
    assert!(matches!(
        process_pcap_file(&path, &observation_limited),
        Err(OfflineInputError::ObservationLimitExceeded { limit: 1 })
    ));
    let malformed_only = classic_pcap(
        PcapEncoding::LittleMicroseconds,
        &[(1_700_000_000, 0, vec![0_u8; 10])],
    );
    let malformed_path = dir.join("malformed-only.pcap");
    fs::write(&malformed_path, malformed_only).expect("write malformed-only PCAP");
    let mut diagnostic_limited = pcap_config("limited-exporter");
    diagnostic_limited.max_diagnostics = 0;
    let limited = process_pcap_file(&malformed_path, &diagnostic_limited)
        .expect("bounded diagnostic processing");
    assert!(limited.diagnostics.is_empty());
    assert_eq!(limited.diagnostics_total, 1);
    assert_eq!(limited.diagnostics_dropped, 1);
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn canonical_semantics_remain_unidirectional_ip_byte_based_and_minimized() {
    let dir = test_dir("semantics");
    let path = dir.join("input.pcap");
    fs::write(&path, mixed_pcap()).expect("write PCAP");
    let result =
        process_pcap_file(&path, &pcap_config("semantic-exporter")).expect("process semantic PCAP");
    for observation in &result.observations {
        let serialized = serde_json::to_value(observation).expect("serialize");
        let flow = serialized.get("data").expect("flow data");
        assert_eq!(
            flow.get("direction_mode").and_then(|value| value.as_str()),
            Some("unidirectional")
        );
        assert!(flow["counters"].get("dst_to_src").is_none());
        assert!(flow["counters"]["src_to_dst"].get("ip_bytes").is_some());
        assert!(flow["counters"]["src_to_dst"]
            .get("payload_bytes")
            .is_none());
        assert!(flow["counters"]["src_to_dst"].get("l2_bytes").is_none());
        for absent in [
            "service",
            "connection_state",
            "connection_history",
            "end_reason",
        ] {
            assert!(flow.get(absent).is_none(), "fabricated {absent}");
        }
    }
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn open_source_exporter_fixture_matches_independent_decode_and_f3_mapping() {
    let real_dir = fixture_dir().join("real");
    let bytes = decode_hex_fixture(real_dir.join("nflow_generator_b7cd119_v5.hex"));
    let expected_artifact_sha =
        fs::read_to_string(real_dir.join("nflow_generator_b7cd119_v5.sha256"))
            .expect("artifact SHA sidecar");
    let provenance: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(real_dir.join("nflow_generator_b7cd119_v5.provenance.json"))
            .expect("provenance manifest"),
    )
    .expect("valid provenance manifest");
    assert_eq!(
        provenance["source_commit"],
        "b7cd1199871c7ad9a74d8e0efae1768277019d0e"
    );
    assert_eq!(provenance["license"], "Apache-2.0");
    assert_eq!(bytes.len(), 792);
    let actual_artifact_sha = digest(&bytes);
    assert_eq!(
        actual_artifact_sha,
        "e40591d1386a13d5d95d754c583e747b58921d17991db77b8cd1fd3a7225ba87"
    );
    assert_eq!(
        expected_artifact_sha.split_whitespace().next(),
        Some(actual_artifact_sha.as_str())
    );
    let parsed = parse_netflow_v5_datagram(&bytes).expect("exporter fixture must parse");
    assert_eq!(parsed.header.version, 5);
    assert_eq!(parsed.header.count, 16);
    assert_eq!(parsed.header.sys_uptime_ms, 1003);
    assert_eq!(parsed.header.unix_secs, 1_789_738_677);
    assert_eq!(parsed.header.unix_nsecs, 783_806_000);
    assert_eq!(parsed.header.flow_sequence, 1);
    assert_eq!(parsed.header.engine_type, 1);
    assert_eq!(parsed.header.engine_id, 0);
    assert_eq!(parsed.header.sampling_mode, 0);
    assert_eq!(parsed.header.sampling_interval, 0);
    assert_eq!(
        encode_parsed_v5(&parsed),
        bytes,
        "every F2 field must round-trip"
    );

    let dir = test_dir("exporter-evidence");
    let input = dir.join("exporter-produced.bin");
    fs::write(&input, &bytes).expect("write decoded exporter fixture");
    let mut config = raw_config("nflow-generator-b7cd119");
    config.expected_sha256 = Some(digest(&bytes));
    config.observed_at = "2026-09-18T13:37:57.783806Z".to_string();
    let result = process_raw_datagram_file(&input, &config).expect("normalize exporter fixture");
    assert_eq!(result.observations.len(), 16);
    assert_eq!(result.diagnostics_total, 0);

    let mut semantic = format!(
        "H|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
        parsed.header.version,
        parsed.header.count,
        parsed.header.sys_uptime_ms,
        parsed.header.unix_secs,
        parsed.header.unix_nsecs,
        parsed.header.flow_sequence,
        parsed.header.engine_type,
        parsed.header.engine_id,
        parsed.header.raw_sampling
    );
    let mut maximum_end_age_ms = 0_u32;
    let mut maximum_duration_ms = 0_u32;
    for (record, observation) in parsed.records.iter().zip(&result.observations) {
        let flow = match &observation.data {
            CanonicalData::Flow(flow) => flow,
            _ => panic!("expected canonical flow"),
        };
        let end_age_ms = parsed
            .header
            .sys_uptime_ms
            .wrapping_sub(record.last_sys_uptime_ms);
        let duration_ms = record
            .last_sys_uptime_ms
            .wrapping_sub(record.first_sys_uptime_ms);
        maximum_end_age_ms = maximum_end_age_ms.max(end_age_ms);
        maximum_duration_ms = maximum_duration_ms.max(duration_ms);
        semantic.push_str(&format!(
            "R|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}\n",
            record.record_ordinal,
            record.src_addr,
            record.dst_addr,
            record.next_hop,
            record.input_ifindex,
            record.output_ifindex,
            record.packet_count,
            record.octet_count,
            record.first_sys_uptime_ms,
            record.last_sys_uptime_ms,
            record.src_port,
            record.dst_port,
            record.pad1,
            record.tcp_flags,
            record.protocol,
            record.tos,
            record.src_as,
            record.dst_as,
            record.src_mask,
            record.dst_mask,
            record.pad2
        ));
        semantic.push_str(&format!(
            "T|{}|{}|{}|{}|{}\n",
            record.record_ordinal,
            flow.start_time,
            flow.end_time.as_deref().expect("v5 end time"),
            end_age_ms,
            duration_ms
        ));
        assert_eq!(flow.src_ip, record.src_addr.to_string());
        assert_eq!(flow.dst_ip, record.dst_addr.to_string());
        assert_eq!(flow.ip_protocol, record.protocol);
        assert_eq!(
            flow.counters.src_to_dst.packets,
            Some(u64::from(record.packet_count))
        );
        assert_eq!(
            flow.counters.src_to_dst.ip_bytes,
            Some(u64::from(record.octet_count))
        );
        assert_eq!(flow.counters.src_to_dst.payload_bytes, None);
        assert_eq!(flow.counters.src_to_dst.l2_bytes, None);
        assert_eq!(flow.counters.dst_to_src, None);
        let expected_ingress = format!("ifindex:{}", record.input_ifindex);
        let expected_egress = format!("ifindex:{}", record.output_ifindex);
        assert_eq!(
            flow.ingress_interface.as_deref(),
            Some(expected_ingress.as_str())
        );
        assert_eq!(
            flow.egress_interface.as_deref(),
            Some(expected_egress.as_str())
        );
        if matches!(record.protocol, 6 | 17 | 132) {
            assert_eq!(flow.src_port, Some(record.src_port));
            assert_eq!(flow.dst_port, Some(record.dst_port));
        } else {
            assert_eq!(flow.src_port, None);
            assert_eq!(flow.dst_port, None);
        }
    }
    assert_eq!(maximum_end_age_ms, 469);
    assert_eq!(maximum_duration_ms, 494);
    assert_eq!(
        digest(semantic.as_bytes()),
        "4674db2fa25879afc9461621b7f7322db43dcecc5ed0c4c4e93ca0b6a8b42947"
    );
    let expected_jsonl = canonical_jsonl(&result.observations);
    for _ in 0..10 {
        let replay = process_raw_datagram_file(&input, &config).expect("exporter replay");
        assert_eq!(canonical_jsonl(&replay.observations), expected_jsonl);
    }
    let actual_canonical_sha = digest(&expected_jsonl);
    assert_eq!(
        actual_canonical_sha,
        "ad4e7dc432a3200a89dba1c3c029b49472535c2ac68800c4aeffdc56a75cf60f"
    );
    let expected_canonical_sha =
        fs::read_to_string(real_dir.join("nflow_generator_b7cd119_v5.canonical_expected.sha256"))
            .expect("canonical SHA sidecar");
    assert_eq!(
        expected_canonical_sha.split_whitespace().next(),
        Some(actual_canonical_sha.as_str())
    );
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn generated_synthetic_f4_pcap_has_a_frozen_sha() {
    let bytes = mixed_pcap();
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            fixture_dir()
                .join("pcap")
                .join("qualification_manifest.json"),
        )
        .expect("PCAP manifest"),
    )
    .expect("valid PCAP manifest");
    assert_eq!(bytes.len(), 600);
    assert_eq!(
        digest(&bytes),
        "489ffca136283afcb4c95d6b737def29c478a69409f80900f8239e5c7f41ce5a"
    );
    assert_eq!(manifest["sha256"], digest(&bytes));
    assert_eq!(
        manifest["canonical_sha256"],
        "c03f1713825e13ba84e40d1e8b95379b8e9be43707dca79bf87b1ee466203e99"
    );
}

#[test]
#[ignore = "qualification-only canonical artifacts for external frozen-schema validation"]
fn emit_f4_canonical_artifacts_for_external_schema_validation() {
    let root = PathBuf::from(
        std::env::var_os("SIH_F4_QUALIFICATION_OUTPUT_DIR")
            .expect("SIH_F4_QUALIFICATION_OUTPUT_DIR is required"),
    );
    fs::create_dir_all(&root).expect("create qualification output directory");

    let real_bytes = decode_hex_fixture(
        fixture_dir()
            .join("real")
            .join("nflow_generator_b7cd119_v5.hex"),
    );
    let real_input = root.join("exporter-produced.bin");
    fs::write(&real_input, &real_bytes).expect("write real input");
    let mut real_config = raw_config("nflow-generator-b7cd119");
    real_config.expected_sha256 = Some(digest(&real_bytes));
    real_config.observed_at = "2026-09-18T13:37:57.783806Z".to_string();
    write_raw_datagram_canonical_jsonl(
        &real_input,
        root.join("real.canonical.jsonl"),
        &real_config,
    )
    .expect("write real canonical output");

    let pcap_bytes = mixed_pcap();
    let pcap_input = root.join("synthetic-mixed.pcap");
    fs::write(&pcap_input, &pcap_bytes).expect("write synthetic PCAP");
    let mut pcap_config = pcap_config("pcap-exporter");
    pcap_config.expected_sha256 = Some(digest(&pcap_bytes));
    write_pcap_canonical_jsonl(&pcap_input, root.join("pcap.canonical.jsonl"), &pcap_config)
        .expect("write PCAP canonical output");
}

#[test]
#[ignore = "informational release-mode F4 offline-path throughput"]
fn informational_release_offline_path_throughput() {
    const DATAGRAMS: u32 = 10_000;
    let dir = test_dir("performance");
    let base = fixture("minimal_valid_one_record");
    let initial_sequence = u32::from_be_bytes(base[16..20].try_into().expect("sequence"));
    let packets = (0..DATAGRAMS)
        .map(|ordinal| {
            let payload = with_sequence(base.clone(), initial_sequence.wrapping_add(ordinal));
            (
                1_700_000_000 + ordinal / 1_000_000,
                ordinal % 1_000_000,
                ethernet_ipv4_udp(&payload, 50000, NETFLOW_PORT, false),
            )
        })
        .collect::<Vec<_>>();
    let bytes = classic_pcap(PcapEncoding::LittleMicroseconds, &packets);
    let input = dir.join("performance.pcap");
    fs::write(&input, &bytes).expect("write performance PCAP");
    let output = dir.join("performance.canonical.jsonl");
    let mut config = pcap_config("performance-exporter");
    config.max_canonical_observations = DATAGRAMS as usize;
    let started = Instant::now();
    let result = write_pcap_canonical_jsonl(&input, &output, &config)
        .expect("performance processing and canonical publication");
    let elapsed = started.elapsed();
    assert_eq!(result.datagrams_accepted, u64::from(DATAGRAMS));
    assert_eq!(result.observations.len(), DATAGRAMS as usize);
    let elapsed_ns = elapsed.as_nanos().max(1);
    let records_per_second = u128::from(DATAGRAMS) * 1_000_000_000 / elapsed_ns;
    println!(
        "f4_offline_benchmark artifact_bytes={} datagrams={} records={} elapsed_ns={} records_per_second={}",
        bytes.len(),
        DATAGRAMS,
        result.observations.len(),
        elapsed_ns,
        records_per_second
    );
    fs::remove_dir_all(dir).expect("cleanup");
}
