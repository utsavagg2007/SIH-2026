use ingestion_core::netflow::v5::{
    parse_netflow_v5_datagram, NetFlowV5DiagnosticKind, NETFLOW_V5_HEADER_LEN,
    NETFLOW_V5_MAX_RECORDS, NETFLOW_V5_RECORD_LEN,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Instant;

const FIXTURE_NAMES: [&str; 13] = [
    "minimal_valid_one_record",
    "multiple_records",
    "maximum_30_records",
    "zero_counters",
    "max_u32_counters",
    "reported_zero_ports",
    "tcp_flags",
    "sampling_disabled",
    "sampling_deterministic",
    "sampling_random",
    "sampling_reserved",
    "nonzero_padding",
    "repeated_5tuple_distinct_rows",
];

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

fn expected_json(name: &str) -> Value {
    let text = fs::read_to_string(fixture_dir().join(format!("{name}.json")))
        .expect("fixture interpretation must be readable");
    serde_json::from_str(&text).expect("fixture interpretation must be valid JSON")
}

fn set_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn set_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn with_repeated_record(count: u16) -> Vec<u8> {
    let golden = fixture("minimal_valid_one_record");
    let mut bytes = golden[..NETFLOW_V5_HEADER_LEN].to_vec();
    set_u16(&mut bytes, 2, count);
    for _ in 0..count {
        bytes.extend_from_slice(&golden[NETFLOW_V5_HEADER_LEN..]);
    }
    bytes
}

fn error_kind(bytes: &[u8]) -> NetFlowV5DiagnosticKind {
    parse_netflow_v5_datagram(bytes)
        .expect_err("input should be rejected")
        .diagnostic
        .kind
}

#[test]
fn wire_sizes_and_exact_big_endian_golden_offsets_are_correct() {
    assert_eq!(NETFLOW_V5_HEADER_LEN, 24);
    assert_eq!(NETFLOW_V5_RECORD_LEN, 48);

    let bytes = fixture("minimal_valid_one_record");
    assert_eq!(bytes.len(), 24 + 48);
    let parsed = parse_netflow_v5_datagram(&bytes).expect("golden vector should parse");

    let header = &parsed.header;
    assert_eq!(header.version, 5);
    assert_eq!(header.count, 1);
    assert_eq!(header.sys_uptime_ms, 0x0102_0304);
    assert_eq!(header.unix_secs, 1_700_000_000);
    assert_eq!(header.unix_nsecs, 123_456_789);
    assert_eq!(header.flow_sequence, 0x1122_3344);
    assert_eq!(header.engine_type, 7);
    assert_eq!(header.engine_id, 9);
    assert_eq!(header.raw_sampling, 0);
    assert_eq!(header.sampling_mode, 0);
    assert_eq!(header.sampling_interval, 0);

    let record = &parsed.records[0];
    assert_eq!(record.record_ordinal, 0);
    assert_eq!(record.src_addr, Ipv4Addr::new(192, 0, 2, 10));
    assert_eq!(record.dst_addr, Ipv4Addr::new(198, 51, 100, 20));
    assert_eq!(record.next_hop, Ipv4Addr::new(203, 0, 113, 30));
    assert_eq!(record.input_ifindex, 0x1234);
    assert_eq!(record.output_ifindex, 0x5678);
    assert_eq!(record.packet_count, 0x0102_0304);
    assert_eq!(record.octet_count, 0x1122_3344);
    assert_eq!(record.first_sys_uptime_ms, 0x5566_7788);
    assert_eq!(record.last_sys_uptime_ms, 0x99aa_bbcc);
    assert_eq!(record.src_port, 12_345);
    assert_eq!(record.dst_port, 443);
    assert_eq!(record.pad1, 0);
    assert_eq!(record.tcp_flags, 0x1b);
    assert_eq!(record.protocol, 6);
    assert_eq!(record.tos, 0x2e);
    assert_eq!(record.src_as, 64_512);
    assert_eq!(record.dst_as, 64_513);
    assert_eq!(record.src_mask, 24);
    assert_eq!(record.dst_mask, 25);
    assert_eq!(record.pad2, 0);
    assert!(parsed.diagnostics.is_empty());
}

#[test]
fn independent_golden_interpretation_matches_decoded_values() {
    let expected = expected_json("minimal_valid_one_record");
    let parsed = parse_netflow_v5_datagram(&fixture("minimal_valid_one_record"))
        .expect("golden vector should parse");
    let record = &parsed.records[0];

    assert_eq!(
        expected["header"]["sys_uptime_ms"],
        parsed.header.sys_uptime_ms
    );
    assert_eq!(expected["header"]["unix_secs"], parsed.header.unix_secs);
    assert_eq!(expected["header"]["unix_nsecs"], parsed.header.unix_nsecs);
    assert_eq!(
        expected["header"]["flow_sequence"],
        parsed.header.flow_sequence
    );
    assert_eq!(
        expected["records"][0]["src_addr"],
        record.src_addr.to_string()
    );
    assert_eq!(
        expected["records"][0]["dst_addr"],
        record.dst_addr.to_string()
    );
    assert_eq!(
        expected["records"][0]["next_hop"],
        record.next_hop.to_string()
    );
    assert_eq!(expected["records"][0]["packet_count"], record.packet_count);
    assert_eq!(expected["records"][0]["octet_count"], record.octet_count);
    assert_eq!(
        expected["records"][0]["first_sys_uptime_ms"],
        record.first_sys_uptime_ms
    );
    assert_eq!(
        expected["records"][0]["last_sys_uptime_ms"],
        record.last_sys_uptime_ms
    );
    assert_eq!(expected["records"][0]["tcp_flags"], record.tcp_flags);
    assert_eq!(expected["records"][0]["protocol"], record.protocol);
    assert_eq!(expected["records"][0]["tos"], record.tos);
}

#[test]
fn every_binary_fixture_has_frozen_sha_and_human_readable_interpretation() {
    for name in FIXTURE_NAMES {
        let bytes = fixture(name);
        let sidecar = fs::read_to_string(fixture_dir().join(format!("{name}.sha256")))
            .expect("SHA sidecar must be readable");
        let expected_hash = sidecar
            .split_whitespace()
            .next()
            .expect("SHA sidecar must contain a digest");
        let actual_hash = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(actual_hash, expected_hash, "fixture hash drift: {name}");
        let interpretation = expected_json(name);
        assert!(
            interpretation.is_object(),
            "expected JSON must be an object: {name}"
        );
    }
}

#[test]
fn physical_order_is_preserved_without_sorting() {
    let parsed = parse_netflow_v5_datagram(&fixture("multiple_records"))
        .expect("multi-record fixture should parse");
    assert_eq!(parsed.header.count, 3);
    assert_eq!(
        parsed
            .records
            .iter()
            .map(|row| row.record_ordinal)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(
        parsed
            .records
            .iter()
            .map(|row| row.src_addr)
            .collect::<Vec<_>>(),
        [
            Ipv4Addr::new(192, 0, 2, 200),
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 150),
        ]
    );
    assert_eq!(
        parsed
            .records
            .iter()
            .map(|row| row.src_port)
            .collect::<Vec<_>>(),
        [60_000, 53, 443]
    );
    assert_eq!(
        parsed
            .records
            .iter()
            .map(|row| row.first_sys_uptime_ms)
            .collect::<Vec<_>>(),
        [900, 100, 500]
    );
}

#[test]
fn maximum_thirty_records_are_accepted_and_thirty_one_is_rejected() {
    let bytes = fixture("maximum_30_records");
    assert_eq!(bytes.len(), 24 + 30 * 48);
    let parsed = parse_netflow_v5_datagram(&bytes).expect("30 records should parse");
    assert_eq!(parsed.header.count, NETFLOW_V5_MAX_RECORDS);
    assert_eq!(parsed.records.len(), 30);
    assert_eq!(parsed.records.first().expect("first row").record_ordinal, 0);
    assert_eq!(parsed.records.last().expect("last row").record_ordinal, 29);

    let mut count_31 = bytes;
    set_u16(&mut count_31, 2, 31);
    assert_eq!(
        error_kind(&count_31),
        NetFlowV5DiagnosticKind::InvalidRecordCount
    );
}

#[test]
fn reported_zero_values_remain_present_zero_values() {
    let zero =
        parse_netflow_v5_datagram(&fixture("zero_counters")).expect("zero fixture should parse");
    let row = &zero.records[0];
    assert_eq!(row.packet_count, 0);
    assert_eq!(row.octet_count, 0);
    assert_eq!(row.input_ifindex, 0);
    assert_eq!(row.output_ifindex, 0);
    assert_eq!(row.src_as, 0);
    assert_eq!(row.dst_as, 0);

    let zero_ports = parse_netflow_v5_datagram(&fixture("reported_zero_ports"))
        .expect("zero-port fixture should parse");
    assert_eq!(zero_ports.records[0].src_port, 0);
    assert_eq!(zero_ports.records[0].dst_port, 0);
}

#[test]
fn unsigned_maxima_are_preserved_without_overflow_or_sign_conversion() {
    let parsed = parse_netflow_v5_datagram(&fixture("max_u32_counters"))
        .expect("maximum fixture should parse");
    let row = &parsed.records[0];
    assert_eq!(parsed.header.sys_uptime_ms, u32::MAX);
    assert_eq!(parsed.header.flow_sequence, u32::MAX);
    assert_eq!(row.packet_count, u32::MAX);
    assert_eq!(row.octet_count, u32::MAX);
    assert_eq!(row.first_sys_uptime_ms, u32::MAX);
    assert_eq!(row.last_sys_uptime_ms, u32::MAX);
    assert_eq!(row.input_ifindex, u16::MAX);
    assert_eq!(row.output_ifindex, u16::MAX);
    assert_eq!(row.src_port, u16::MAX);
    assert_eq!(row.dst_port, u16::MAX);
    assert_eq!(row.src_as, u16::MAX);
    assert_eq!(row.dst_as, u16::MAX);
}

#[test]
fn tcp_flags_are_preserved_without_interpretation() {
    let parsed =
        parse_netflow_v5_datagram(&fixture("tcp_flags")).expect("TCP flags fixture should parse");
    assert_eq!(parsed.records[0].tcp_flags, u8::MAX);
    assert_eq!(parsed.records[0].protocol, 6);
}

#[test]
fn sampling_bits_are_lossless_and_never_scale_counters() {
    let cases = [
        ("sampling_disabled", 0, 0, 0, false),
        ("sampling_deterministic", (1 << 14) | 100, 1, 100, false),
        ("sampling_random", (2 << 14) | 0x3fff, 2, 0x3fff, false),
        ("sampling_reserved", (3 << 14) | 1, 3, 1, true),
    ];
    for (name, raw, mode, interval, should_diagnose) in cases {
        let parsed =
            parse_netflow_v5_datagram(&fixture(name)).expect("sampling fixture should parse");
        assert_eq!(parsed.header.raw_sampling, raw);
        assert_eq!(parsed.header.sampling_mode, mode);
        assert_eq!(parsed.header.sampling_interval, interval);
        assert_eq!(
            parsed
                .diagnostics
                .iter()
                .any(|item| item.kind == NetFlowV5DiagnosticKind::SamplingConfigurationInvalid),
            should_diagnose
        );
    }

    let sampled = parse_netflow_v5_datagram(&fixture("sampling_deterministic"))
        .expect("sampled fixture should parse");
    assert_eq!(sampled.records[0].packet_count, 0x0102_0304);
    assert_eq!(sampled.records[0].octet_count, 0x1122_3344);
}

#[test]
fn all_sampling_modes_and_interval_boundaries_are_decoded() {
    for mode in 0u16..=3 {
        for interval in [0u16, 1, 0x3fff] {
            let mut bytes = fixture("minimal_valid_one_record");
            let raw = (mode << 14) | interval;
            set_u16(&mut bytes, 22, raw);
            let parsed =
                parse_netflow_v5_datagram(&bytes).expect("sampling bits are structural data");
            assert_eq!(parsed.header.raw_sampling, raw);
            assert_eq!(parsed.header.sampling_mode, mode as u8);
            assert_eq!(parsed.header.sampling_interval, interval);

            let contradictory = (mode == 0 && interval != 0)
                || ((mode == 1 || mode == 2) && interval == 0)
                || mode == 3;
            assert_eq!(
                parsed
                    .diagnostics
                    .iter()
                    .any(|item| item.kind == NetFlowV5DiagnosticKind::SamplingConfigurationInvalid),
                contradictory
            );
        }
    }
}

#[test]
fn nonzero_padding_is_preserved_and_diagnosed_nonfatally() {
    let bytes = fixture("nonzero_padding");
    let parsed = parse_netflow_v5_datagram(&bytes).expect("padding anomaly is nonfatal");
    assert_eq!(parsed.records[0].pad1, 0x7f);
    assert_eq!(parsed.records[0].pad2, 0xbeef);
    assert_eq!(parsed.diagnostics.len(), 2);
    assert_eq!(
        parsed.diagnostics[0].kind,
        NetFlowV5DiagnosticKind::NonzeroPadding
    );
    assert_eq!(parsed.diagnostics[0].byte_offset, 60);
    assert_eq!(parsed.diagnostics[0].record_ordinal, Some(0));
    assert_eq!(parsed.diagnostics[0].field, "pad1");
    assert_eq!(
        parsed.diagnostics[1].kind,
        NetFlowV5DiagnosticKind::NonzeroPadding
    );
    assert_eq!(parsed.diagnostics[1].byte_offset, 70);
    assert_eq!(parsed.diagnostics[1].record_ordinal, Some(0));
    assert_eq!(parsed.diagnostics[1].field, "pad2");
    assert!(parsed
        .diagnostics
        .iter()
        .all(|item| item.byte_offset < bytes.len()));
}

#[test]
fn identical_five_tuples_remain_distinct_physical_rows() {
    let parsed = parse_netflow_v5_datagram(&fixture("repeated_5tuple_distinct_rows"))
        .expect("repeated tuple fixture should parse");
    assert_eq!(parsed.records.len(), 3);
    assert_eq!(
        parsed
            .records
            .iter()
            .map(|row| row.record_ordinal)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert!(parsed.records.windows(2).all(|rows| {
        rows[0].src_addr == rows[1].src_addr
            && rows[0].dst_addr == rows[1].dst_addr
            && rows[0].src_port == rows[1].src_port
            && rows[0].dst_port == rows[1].dst_port
            && rows[0].protocol == rows[1].protocol
    }));
    assert_eq!(
        parsed
            .records
            .iter()
            .map(|row| row.packet_count)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(
        parsed
            .records
            .iter()
            .map(|row| row.first_sys_uptime_ms)
            .collect::<Vec<_>>(),
        [100, 300, 500]
    );
}

#[test]
fn structural_validation_rejects_all_required_malformed_classes() {
    let golden = fixture("minimal_valid_one_record");

    assert_eq!(
        error_kind(&golden[..23]),
        NetFlowV5DiagnosticKind::TruncatedHeader
    );

    let mut unsupported = golden.clone();
    set_u16(&mut unsupported, 0, 9);
    assert_eq!(
        error_kind(&unsupported),
        NetFlowV5DiagnosticKind::UnsupportedVersion
    );

    let mut zero_count = golden.clone();
    set_u16(&mut zero_count, 2, 0);
    assert_eq!(
        error_kind(&zero_count),
        NetFlowV5DiagnosticKind::InvalidRecordCount
    );

    let mut count_31 = golden.clone();
    set_u16(&mut count_31, 2, 31);
    assert_eq!(
        error_kind(&count_31),
        NetFlowV5DiagnosticKind::InvalidRecordCount
    );

    assert_eq!(
        error_kind(&golden[..71]),
        NetFlowV5DiagnosticKind::InvalidDatagramLength
    );

    let mut trailing = golden.clone();
    trailing.push(0);
    assert_eq!(
        error_kind(&trailing),
        NetFlowV5DiagnosticKind::InvalidDatagramLength
    );

    let mut count_mismatch = golden.clone();
    set_u16(&mut count_mismatch, 2, 2);
    assert_eq!(
        error_kind(&count_mismatch),
        NetFlowV5DiagnosticKind::InvalidDatagramLength
    );

    let mut invalid_nsecs = golden;
    set_u32(&mut invalid_nsecs, 12, 1_000_000_000);
    assert_eq!(
        error_kind(&invalid_nsecs),
        NetFlowV5DiagnosticKind::InvalidUnixNanoseconds
    );
}

#[test]
fn exact_length_boundaries_are_deterministic_and_never_resynchronize() {
    let golden = fixture("minimal_valid_one_record");
    for length in [0usize, 1, 23, 24, 24 + 47, 24 + 48] {
        let result = parse_netflow_v5_datagram(&golden[..length.min(golden.len())]);
        if length == 24 + 48 {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err(), "length {length} must fail");
        }
    }

    let mut plus_one = golden;
    plus_one.push(0);
    assert_eq!(plus_one.len(), 24 + 49);
    assert_eq!(
        error_kind(&plus_one),
        NetFlowV5DiagnosticKind::InvalidDatagramLength
    );

    for count in [2u16, 5, 30] {
        let complete = with_repeated_record(count);
        assert!(parse_netflow_v5_datagram(&complete).is_ok());
        assert_eq!(
            error_kind(&complete[..complete.len() - 1]),
            NetFlowV5DiagnosticKind::InvalidDatagramLength
        );
    }
}

#[test]
fn truncation_and_deterministic_mutations_never_panic() {
    let golden = fixture("minimal_valid_one_record");
    for end in 0..=golden.len() {
        let first = std::panic::catch_unwind(|| parse_netflow_v5_datagram(&golden[..end]));
        let second = std::panic::catch_unwind(|| parse_netflow_v5_datagram(&golden[..end]));
        assert!(
            first.is_ok(),
            "parser panicked at truncation boundary {end}"
        );
        assert!(second.is_ok(), "parser panicked on repeated boundary {end}");
        assert_eq!(
            first.expect("checked above"),
            second.expect("checked above")
        );
    }

    for offset in 0..golden.len() {
        let mut mutated = golden.clone();
        mutated[offset] ^= 0xff;
        let first = std::panic::catch_unwind(|| parse_netflow_v5_datagram(&mutated));
        let second = std::panic::catch_unwind(|| parse_netflow_v5_datagram(&mutated));
        assert!(
            first.is_ok(),
            "parser panicked after mutating byte {offset}"
        );
        assert!(
            second.is_ok(),
            "parser panicked on repeated mutation {offset}"
        );
        let first = first.expect("checked above");
        let second = second.expect("checked above");
        assert_eq!(first, second);
        if let Ok(parsed) = first {
            assert!(parsed
                .diagnostics
                .iter()
                .all(|item| item.byte_offset < mutated.len()));
        }
    }
}

#[test]
fn parser_is_context_free_clock_free_and_deterministic() {
    let bytes = fixture("minimal_valid_one_record");
    let first = parse_netflow_v5_datagram(&bytes);
    let second = parse_netflow_v5_datagram(&bytes);
    assert_eq!(first, second);
}

#[test]
#[ignore = "informational release-mode boundedness/throughput sanity"]
fn informational_max_datagram_throughput() {
    let bytes = fixture("maximum_30_records");
    const ITERATIONS: usize = 25_000;
    let started = Instant::now();
    let mut records = 0usize;
    for _ in 0..ITERATIONS {
        let parsed = parse_netflow_v5_datagram(black_box(&bytes))
            .expect("maximum datagram should remain valid");
        records += parsed.records.len();
        black_box(parsed);
    }
    let elapsed = started.elapsed();
    let records_per_second = records as f64 / elapsed.as_secs_f64();
    println!(
        "parsed {records} records from {ITERATIONS} independent datagrams in {elapsed:?} ({records_per_second:.0} records/sec)"
    );
    assert_eq!(records, ITERATIONS * usize::from(NETFLOW_V5_MAX_RECORDS));
}
