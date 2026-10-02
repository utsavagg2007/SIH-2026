use ingestion_core::canonical::id::*;
use ingestion_core::canonical::*;
use ingestion_core::netflow::template::*;
use ingestion_core::netflow::v9::*;
use ingestion_core::netflow::v9_normalize::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

type Field = (u16, Vec<u8>);
const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OBSERVED: &str = "2026-10-03T00:00:00Z";

fn n(id: u16, value: u64, width: usize) -> Field {
    let mut bytes = vec![0; width];
    let raw = value.to_be_bytes();
    let count = width.min(8);
    bytes[width - count..].copy_from_slice(&raw[8 - count..]);
    (id, bytes)
}
fn base(protocol: u8) -> Vec<Field> {
    vec![
        (8, vec![192, 0, 2, 1]),
        (12, vec![198, 51, 100, 2]),
        n(4, u64::from(protocol), 1),
        n(22, 8000, 4),
        n(21, 9000, 4),
        n(2, 5, 4),
    ]
}
fn v6(protocol: u8) -> Vec<Field> {
    let mut fields = base(protocol);
    fields.retain(|f| !matches!(f.0, 8 | 12));
    fields.extend([
        (
            27,
            "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        ),
        (
            28,
            "2001:db8::2"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        ),
        n(60, 6, 1),
    ]);
    fields
}
fn set(fields: &mut [Field], id: u16, value: u64, width: usize) {
    fields.iter_mut().find(|f| f.0 == id).unwrap().1 = n(id, value, width).1;
}
fn fs(id: u16, payload: &[u8], aligned: bool) -> Vec<u8> {
    let mut payload = payload.to_vec();
    if aligned {
        payload.resize((payload.len() + 3) & !3, 0);
    }
    let mut bytes = id.to_be_bytes().to_vec();
    bytes.extend(u16::try_from(payload.len() + 4).unwrap().to_be_bytes());
    bytes.extend(payload);
    bytes
}
fn template(id: u16, fields: &[Field]) -> Vec<u8> {
    let mut bytes = id.to_be_bytes().to_vec();
    bytes.extend(u16::try_from(fields.len()).unwrap().to_be_bytes());
    for (id, value) in fields {
        bytes.extend(id.to_be_bytes());
        bytes.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
    }
    bytes
}
fn payload(fields: &[Field]) -> Vec<u8> {
    fields.iter().flat_map(|f| f.1.iter().copied()).collect()
}
fn packet(sets: &[Vec<u8>], count: u16, uptime: u32, seconds: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(9_u16.to_be_bytes());
    bytes.extend(count.to_be_bytes());
    for value in [uptime, seconds, 123, 42] {
        bytes.extend(value.to_be_bytes());
    }
    for set in sets {
        bytes.extend(set);
    }
    bytes
}
fn wire(fields: &[Field], repeat: usize, uptime: u32, seconds: u32) -> Vec<u8> {
    packet(
        &[
            fs(0, &template(256, fields), true),
            fs(256, &payload(fields).repeat(repeat), true),
        ],
        u16::try_from(repeat + 1).unwrap(),
        uptime,
        seconds,
    )
}
fn context() -> NetFlowV9ParseContext {
    NetFlowV9ParseContext {
        session: TransportSessionKey::new("exporter-a", "collector-a.udp.epoch-1", 256).unwrap(),
        datagram_ordinal: 0,
    }
}
fn source(basis: NetFlowV9ByteBasisProfile) -> NetFlowV9SourceContext {
    NetFlowV9SourceContext::new("sensor-v9-a", InputMode::ExportFile, HASH, OBSERVED, basis)
        .unwrap()
}
fn parse(bytes: &[u8]) -> NetFlowV9ParseOutcome<'_> {
    parse_netflow_v9(
        bytes,
        context(),
        &mut TemplateRegistry::new(Default::default()),
        Default::default(),
    )
    .unwrap()
}

#[derive(Debug, PartialEq)]
struct Checked {
    observations: Vec<CanonicalObservation>,
    diagnostics: Vec<NetFlowV9NormalizationDiagnostic>,
    audit: Vec<NetFlowV9AuditEntry>,
    status: NetFlowV9NormalizationStatus,
    count: CountValidation,
    completion: ParseCompletion,
    disposition: SessionDisposition,
    parser_total: usize,
    parser_dropped: usize,
    parser_retained: usize,
    inspected: usize,
    emitted: usize,
    rejected: usize,
    options: usize,
    total: usize,
    dropped: usize,
}
impl Checked {
    fn flow(&self) -> &FlowData {
        match &self.observations[0].data {
            CanonicalData::Flow(flow) => flow,
            _ => panic!("flow only"),
        }
    }
    fn json(&self) -> Value {
        serde_json::to_value(&self.observations[0]).unwrap()
    }
    fn failure(&self, kind: NetFlowV9NormalizationDiagnosticKind) {
        assert!(
            self.observations.is_empty(),
            "unexpected observation: {self:?}"
        );
        assert!(
            self.diagnostics.iter().any(|d| d.kind == kind),
            "missing {kind:?}: {self:?}"
        );
    }
}
fn checked(
    out: &NetFlowV9ParseOutcome<'_>,
    src: &NetFlowV9SourceContext,
    cfg: NetFlowV9NormalizationConfig,
) -> Checked {
    let result = normalize_netflow_v9(out, src, cfg).unwrap();
    Checked {
        observations: result.observations,
        diagnostics: result.diagnostics,
        audit: result.audit,
        status: result.normalization_status,
        count: result.parser_status.count_validation,
        completion: result.parser_status.completion,
        disposition: result.parser_status.session_disposition,
        parser_total: result.parser_status.diagnostics_total,
        parser_dropped: result.parser_status.diagnostics_dropped,
        parser_retained: result.parser_status.diagnostics.len(),
        inspected: result.records_inspected,
        emitted: result.records_emitted,
        rejected: result.records_rejected,
        options: result.options_records_ignored,
        total: result.diagnostics_total,
        dropped: result.diagnostics_dropped,
    }
}
fn run(fields: &[Field]) -> Checked {
    custom(
        fields,
        NetFlowV9ByteBasisProfile::Unknown,
        10000,
        1700000100,
        Default::default(),
        1,
    )
}
fn custom(
    fields: &[Field],
    basis: NetFlowV9ByteBasisProfile,
    uptime: u32,
    seconds: u32,
    cfg: NetFlowV9NormalizationConfig,
    repeats: usize,
) -> Checked {
    let bytes = wire(fields, repeats, uptime, seconds);
    checked(&parse(&bytes), &source(basis), cfg)
}
fn age(fields: &[Field], uptime: u32, seconds: u32, maximum: u64) -> Checked {
    custom(
        fields,
        NetFlowV9ByteBasisProfile::Unknown,
        uptime,
        seconds,
        NetFlowV9NormalizationConfig::new(maximum, 16384, 16384, 128, 16384).unwrap(),
        1,
    )
}
fn config(
    records: usize,
    observations: usize,
    diagnostics: usize,
    audit: usize,
) -> NetFlowV9NormalizationConfig {
    NetFlowV9NormalizationConfig::new(
        DEFAULT_MAX_FLOW_AGE_MS,
        records,
        observations,
        diagnostics,
        audit,
    )
    .unwrap()
}
use NetFlowV9NormalizationDiagnosticKind as K;
macro_rules! case { ($name:ident,$body:block) => { #[test] fn $name() $body }; }

case!(minimal_udp, {
    assert_eq!(run(&base(17)).emitted, 1);
});
case!(minimal_tcp, {
    assert_eq!(run(&base(6)).emitted, 1);
});
case!(minimal_ipv6, {
    assert_eq!(run(&v6(17)).flow().src_ip, "2001:db8::1");
});
macro_rules! missing {
    ($name:ident,$id:expr) => {
        case!($name, {
            let mut f = base(17);
            f.retain(|v| v.0 != $id);
            run(&f).failure(K::MissingRequiredField);
        });
    };
}
missing!(missing_source, 8);
missing!(missing_destination, 12);
missing!(missing_protocol, 4);
missing!(missing_first, 22);
missing!(missing_last, 21);
missing!(missing_counter, 2);
case!(zero_counter_is_usable, {
    let mut f = base(17);
    set(&mut f, 2, 0, 4);
    assert_eq!(run(&f).flow().counters.src_to_dst.packets, Some(0));
});
case!(verified_byte_only, {
    let mut f = base(17);
    f.retain(|f| f.0 != 2);
    f.push(n(1, 250, 8));
    assert_eq!(
        custom(
            &f,
            NetFlowV9ByteBasisProfile::VerifiedIpLayer,
            10000,
            1700000100,
            Default::default(),
            1
        )
        .flow()
        .counters
        .src_to_dst
        .ip_bytes,
        Some(250)
    );
});
case!(unknown_byte_only_rejected, {
    let mut f = base(17);
    f.retain(|f| f.0 != 2);
    f.push(n(1, 250, 4));
    run(&f).failure(K::MissingRequiredField);
});
case!(options_zero_flows, {
    let f = base(17);
    let mut t = 256_u16.to_be_bytes().to_vec();
    t.extend(4_u16.to_be_bytes());
    t.extend(u16::try_from((f.len() - 1) * 4).unwrap().to_be_bytes());
    for (id, value) in &f {
        t.extend(id.to_be_bytes());
        t.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
    }
    let p = packet(
        &[fs(1, &t, true), fs(256, &payload(&f), true)],
        2,
        10000,
        1700000100,
    );
    let out = checked(
        &parse(&p),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(out.emitted, 0);
    assert_eq!(out.options, 1);
    assert_eq!(out.rejected, 0);
});
case!(ipv4_default_without_selector, {
    assert_eq!(run(&base(17)).flow().dst_ip, "198.51.100.2");
});
case!(ipv6_without_selector_rejected, {
    let mut f = v6(17);
    f.retain(|f| f.0 != 60);
    run(&f).failure(K::AddressFamilyConflict);
});
case!(both_without_selector_rejected, {
    let mut f = base(17);
    f.extend(v6(17).into_iter().filter(|f| matches!(f.0, 27 | 28)));
    run(&f).failure(K::AddressFamilyConflict);
});
case!(selector_four_selects_ipv4, {
    let mut f = base(17);
    f.extend(v6(17).into_iter().filter(|f| matches!(f.0, 27 | 28)));
    f.push(n(60, 4, 1));
    assert_eq!(run(&f).flow().src_ip, "192.0.2.1");
});
case!(selector_six_selects_ipv6, {
    let mut f = base(17);
    f.extend(v6(17).into_iter().filter(|f| matches!(f.0, 27 | 28 | 60)));
    assert_eq!(run(&f).flow().src_ip, "2001:db8::1");
});
case!(invalid_selector, {
    let mut f = base(17);
    f.push(n(60, 5, 1));
    run(&f).failure(K::InvalidSemanticValue);
});
case!(mixed_family_rejected, {
    let mut f = base(17);
    f.retain(|f| f.0 != 12);
    f.extend(v6(17).into_iter().filter(|f| f.0 == 28));
    run(&f).failure(K::AddressFamilyConflict);
});
case!(selected_family_incomplete, {
    let mut f = base(17);
    f.push(n(60, 6, 1));
    run(&f).failure(K::MissingRequiredField);
});
case!(zero_ipv4_preserved, {
    let mut f = base(17);
    set(&mut f, 8, 0, 4);
    assert_eq!(run(&f).flow().src_ip, "0.0.0.0");
});
case!(zero_ipv6_preserved, {
    let mut f = v6(17);
    f.iter_mut().find(|f| f.0 == 27).unwrap().1 = vec![0; 16];
    assert_eq!(run(&f).flow().src_ip, "::");
});
case!(selector_duplicate_conflict, {
    let mut f = base(17);
    f.extend([n(60, 4, 1), n(60, 6, 1)]);
    run(&f).failure(K::AmbiguousField);
});
case!(address_duplicate_equal, {
    let mut f = base(17);
    f.push(f[0].clone());
    assert_eq!(run(&f).total, 1);
});
case!(address_duplicate_conflict, {
    let mut f = base(17);
    f.push(n(8, 0, 4));
    run(&f).failure(K::AmbiguousField);
});
macro_rules! ports {
    ($name:ident,$proto:expr) => {
        case!($name, {
            let mut f = base($proto);
            f.extend([n(7, 1234, 2), n(11, 4321, 2)]);
            let out = run(&f);
            assert_eq!(out.flow().src_port, Some(1234));
            assert_eq!(out.flow().dst_port, Some(4321));
        });
    };
}
ports!(tcp_ports, 6);
ports!(udp_ports, 17);
case!(zero_ports, {
    let mut f = base(6);
    f.extend([n(7, 0, 2), n(11, 0, 2)]);
    assert_eq!(run(&f).flow().src_port, Some(0));
});
macro_rules! no_ports {
    ($name:ident,$proto:expr) => {
        case!($name, {
            let mut f = base($proto);
            f.extend([n(7, 1234, 2), n(11, 4321, 2)]);
            let out = run(&f);
            assert_eq!(out.flow().ip_protocol, $proto);
            assert_eq!(out.flow().src_port, None);
            assert_eq!(out.flow().dst_port, None);
        });
    };
}
no_ports!(sctp_ports_omitted, 132);
no_ports!(icmp_ports_omitted, 1);
no_ports!(icmpv6_ports_omitted, 58);
no_ports!(gre_ports_omitted, 47);
no_ports!(esp_ports_omitted, 50);
no_ports!(ospf_ports_omitted, 89);
no_ports!(unknown_protocol_ports_omitted, 255);
no_ports!(protocol_zero_preserved, 0);
case!(icmp_normal, {
    let mut f = base(1);
    f.push(n(32, 0x0803, 2));
    let out = run(&f);
    assert_eq!(out.flow().icmp_type, Some(8));
    assert_eq!(out.flow().icmp_code, Some(3));
});
case!(icmp_zero, {
    let mut f = base(1);
    f.push(n(32, 0, 2));
    let out = run(&f);
    assert_eq!(out.flow().icmp_type, Some(0));
    assert_eq!(out.flow().icmp_code, Some(0));
});
case!(icmp_equal_duplicate, {
    let mut f = base(1);
    f.extend([n(32, 0x0800, 2), n(32, 0x0800, 2)]);
    assert_eq!(run(&f).diagnostics[0].kind, K::DuplicateEquivalent);
});
case!(icmp_conflict_duplicate, {
    let mut f = base(1);
    f.extend([n(32, 0x0800, 2), n(32, 0x0300, 2)]);
    run(&f).failure(K::AmbiguousField);
});
case!(icmp_bad_width, {
    let mut f = base(1);
    f.push(n(32, 0, 1));
    run(&f).failure(K::UnsupportedFieldWidth);
});
case!(icmpv6_details_omitted, {
    let mut f = v6(58);
    f.extend([n(32, 0x8000, 2), n(139, 0x8000, 2)]);
    assert_eq!(run(&f).flow().icmp_type, None);
});
case!(nonicmp_details_omitted, {
    let mut f = base(17);
    f.push(n(32, 0x0800, 2));
    assert_eq!(run(&f).flow().icmp_type, None);
});
case!(v5_icmp_port_encoding_not_reused, {
    let mut f = base(1);
    f.push(n(11, 0x0800, 2));
    assert_eq!(run(&f).flow().icmp_type, None);
});
case!(tcp_each_flag_bit, {
    for (bit, flag) in [
        (1, TcpFlag::Fin),
        (2, TcpFlag::Syn),
        (4, TcpFlag::Rst),
        (8, TcpFlag::Psh),
        (16, TcpFlag::Ack),
        (32, TcpFlag::Urg),
        (64, TcpFlag::Ece),
        (128, TcpFlag::Cwr),
    ] {
        let mut f = base(6);
        f.push(n(6, bit, 1));
        assert_eq!(run(&f).flow().tcp_flags, Some(vec![flag]));
    }
});
case!(tcp_multibit_order, {
    let mut f = base(6);
    f.push(n(6, 255, 1));
    assert_eq!(
        run(&f).flow().tcp_flags,
        Some(vec![
            TcpFlag::Fin,
            TcpFlag::Syn,
            TcpFlag::Rst,
            TcpFlag::Psh,
            TcpFlag::Ack,
            TcpFlag::Urg,
            TcpFlag::Ece,
            TcpFlag::Cwr
        ])
    );
});
case!(tcp_zero_flags, {
    let mut f = base(6);
    f.push(n(6, 0, 1));
    assert_eq!(run(&f).flow().tcp_flags, Some(vec![]));
});
case!(non_tcp_flags_omitted, {
    let mut f = base(17);
    f.push(n(6, 255, 1));
    assert_eq!(run(&f).flow().tcp_flags, None);
});
case!(flags_duplicate_equal, {
    let mut f = base(6);
    f.extend([n(6, 1, 1), n(6, 1, 1)]);
    assert_eq!(run(&f).total, 1);
});
case!(flags_duplicate_conflict_not_or, {
    let mut f = base(6);
    f.extend([n(6, 1, 1), n(6, 2, 1)]);
    run(&f).failure(K::AmbiguousField);
});
macro_rules! ifwidth {
    ($name:ident,$width:expr) => {
        case!($name, {
            let mut f = base(17);
            f.push(n(10, 123, $width));
            assert_eq!(
                run(&f).flow().ingress_interface.as_deref(),
                Some("ifindex:123")
            );
        });
    };
}
ifwidth!(interface_width2, 2);
ifwidth!(interface_width4, 4);
ifwidth!(interface_width8, 8);
case!(interface_width1_rejected, {
    let mut f = base(17);
    f.push(n(10, 1, 1));
    run(&f).failure(K::UnsupportedFieldWidth);
});
case!(interface_width9_rejected, {
    let mut f = base(17);
    f.push(n(14, 1, 9));
    run(&f).failure(K::UnsupportedFieldWidth);
});
case!(zero_ingress_omitted, {
    let mut f = base(17);
    f.push(n(10, 0, 2));
    assert_eq!(run(&f).flow().ingress_interface, None);
});
case!(zero_egress_omitted, {
    let mut f = base(17);
    f.push(n(14, 0, 8));
    assert_eq!(run(&f).flow().egress_interface, None);
});
case!(interface_nonzero_decimal, {
    let mut f = base(17);
    f.push(n(14, u64::MAX, 8));
    assert_eq!(
        run(&f).flow().egress_interface.as_deref(),
        Some("ifindex:18446744073709551615")
    );
});
case!(interface_duplicate_equal, {
    let mut f = base(17);
    f.extend([n(10, 1, 2), n(10, 1, 8)]);
    assert_eq!(run(&f).total, 1);
});
case!(interface_duplicate_conflict, {
    let mut f = base(17);
    f.extend([n(10, 1, 2), n(10, 2, 4)]);
    run(&f).failure(K::AmbiguousField);
});
case!(all_packet_widths, {
    for width in 1..=8 {
        let mut f = base(17);
        set(&mut f, 2, 5, width);
        assert_eq!(run(&f).flow().counters.src_to_dst.packets, Some(5));
    }
});
case!(counter_u64_max_exact, {
    let mut f = base(17);
    set(&mut f, 2, u64::MAX, 8);
    assert_eq!(
        run(&f).json()["data"]["counters"]["src_to_dst"]["packets"].as_u64(),
        Some(u64::MAX)
    );
});
case!(counter_width9_no_truncation, {
    let mut f = base(17);
    set(&mut f, 2, 5, 9);
    run(&f).failure(K::UnsupportedFieldWidth);
});
case!(counter_duplicate_equal_different_width, {
    let mut f = base(17);
    f.push(n(2, 5, 8));
    assert_eq!(run(&f).flow().counters.src_to_dst.packets, Some(5));
});
case!(counter_duplicate_conflict, {
    let mut f = base(17);
    f.push(n(2, 6, 8));
    run(&f).failure(K::AmbiguousField);
});
case!(verified_ip_bytes, {
    let mut f = base(17);
    f.push(n(1, 250, 8));
    let out = custom(
        &f,
        NetFlowV9ByteBasisProfile::VerifiedIpLayer,
        10000,
        1700000100,
        Default::default(),
        1,
    );
    assert_eq!(out.flow().counters.src_to_dst.ip_bytes, Some(250));
});
case!(all_byte_widths, {
    for width in 1..=8 {
        let mut f = base(17);
        f.push(n(1, 250, width));
        assert_eq!(
            custom(
                &f,
                NetFlowV9ByteBasisProfile::VerifiedIpLayer,
                10000,
                1700000100,
                Default::default(),
                1
            )
            .flow()
            .counters
            .src_to_dst
            .ip_bytes,
            Some(250)
        );
    }
});
case!(unknown_bytes_deferred, {
    let mut f = base(17);
    f.push(n(1, 250, 4));
    let out = run(&f);
    assert_eq!(out.flow().counters.src_to_dst.ip_bytes, None);
    assert_eq!(out.diagnostics[0].kind, K::DeferredSemanticsObserved);
});
case!(unknown_bytes_wrong_width_ignored, {
    let mut f = base(17);
    f.push(n(1, 250, 9));
    assert_eq!(run(&f).emitted, 1);
});
case!(unknown_bytes_conflict_ignored, {
    let mut f = base(17);
    f.extend([n(1, 1, 4), n(1, 2, 8)]);
    assert_eq!(run(&f).total, 1);
});
case!(verified_bytes_wrong_width_rejected, {
    let mut f = base(17);
    f.push(n(1, 0, 9));
    custom(
        &f,
        NetFlowV9ByteBasisProfile::VerifiedIpLayer,
        10000,
        1700000100,
        Default::default(),
        1,
    )
    .failure(K::UnsupportedFieldWidth);
});
case!(byte_bases_not_substituted, {
    let mut f = base(17);
    f.push(n(1, 250, 4));
    let out = custom(
        &f,
        NetFlowV9ByteBasisProfile::VerifiedIpLayer,
        10000,
        1700000100,
        Default::default(),
        1,
    );
    assert_eq!(out.flow().counters.src_to_dst.payload_bytes, None);
    assert_eq!(out.flow().counters.src_to_dst.l2_bytes, None);
});
case!(out_bytes_ignored, {
    let mut f = base(17);
    f.push(n(23, 999, 8));
    assert_eq!(run(&f).flow().counters.src_to_dst.ip_bytes, None);
});
case!(out_packets_not_added, {
    let mut f = base(17);
    f.push(n(24, 999, 8));
    assert_eq!(run(&f).flow().counters.src_to_dst.packets, Some(5));
});
case!(out_not_counter_fallback, {
    let mut f = base(17);
    f.retain(|f| f.0 != 2);
    f.extend([n(23, 999, 8), n(24, 999, 8)]);
    run(&f).failure(K::MissingRequiredField);
});
case!(no_reverse_counters, {
    assert_eq!(run(&base(17)).flow().counters.dst_to_src, None);
});
case!(direction_unidirectional, {
    assert_eq!(
        run(&base(17)).flow().direction_mode,
        DirectionMode::Unidirectional
    );
});
case!(direction_field_no_swap, {
    let mut f = base(17);
    f.push(n(61, 1, 1));
    assert_eq!(run(&f).flow().src_ip, "192.0.2.1");
});
case!(no_sampling_scaling, {
    let mut f = base(17);
    f.extend([
        n(34, 10, 4),
        n(35, 2, 1),
        n(48, 4, 4),
        n(49, 2, 1),
        n(50, 10, 4),
    ]);
    assert_eq!(run(&f).flow().counters.src_to_dst.packets, Some(5));
});
case!(normal_time, {
    let out = run(&base(17));
    assert_eq!(out.flow().start_time, "2023-11-14T22:14:58Z");
    assert_eq!(out.flow().end_time.as_deref(), Some("2023-11-14T22:14:59Z"));
});
case!(first_zero_valid, {
    let mut f = base(17);
    set(&mut f, 22, 0, 4);
    assert_eq!(run(&f).emitted, 1);
});
case!(last_zero_valid, {
    let mut f = base(17);
    set(&mut f, 22, 0, 4);
    set(&mut f, 21, 0, 4);
    assert_eq!(age(&f, 0, 1700000100, DEFAULT_MAX_FLOW_AGE_MS).emitted, 1);
});
case!(first_equals_last, {
    let mut f = base(17);
    set(&mut f, 22, 9000, 4);
    let out = run(&f);
    assert_eq!(out.flow().end_time.as_ref(), Some(&out.flow().start_time));
});
case!(last_equals_uptime, {
    let mut f = base(17);
    set(&mut f, 21, 10000, 4);
    assert_eq!(
        run(&f).flow().end_time.as_deref(),
        Some("2023-11-14T22:15:00Z")
    );
});
case!(last_one_future_rejected, {
    let mut f = base(17);
    set(&mut f, 21, 10001, 4);
    run(&f).failure(K::FlowTimeOrderingInvalid);
});
case!(valid_end_wrap, {
    let mut f = base(17);
    set(&mut f, 22, u64::from(u32::MAX) - 31, 4);
    set(&mut f, 21, u64::from(u32::MAX) - 15, 4);
    assert_eq!(
        age(&f, 16, 1700000100, DEFAULT_MAX_FLOW_AGE_MS)
            .flow()
            .end_time
            .as_deref(),
        Some("2023-11-14T22:14:59.968Z")
    );
});
case!(valid_duration_wrap, {
    let mut f = base(17);
    set(&mut f, 22, u64::from(u32::MAX) - 15, 4);
    set(&mut f, 21, 16, 4);
    assert_eq!(age(&f, 32, 1700000100, DEFAULT_MAX_FLOW_AGE_MS).emitted, 1);
});
case!(gross_inversion, {
    let mut f = base(17);
    set(&mut f, 22, 10000, 4);
    set(&mut f, 21, 8000, 4);
    run(&f).failure(K::FlowTimeOrderingInvalid);
});
case!(age_exact_boundary, {
    assert_eq!(
        age(&base(17), 86409000, 1700000100, DEFAULT_MAX_FLOW_AGE_MS).emitted,
        1
    );
});
case!(age_one_over, {
    age(&base(17), 86409001, 1700000100, DEFAULT_MAX_FLOW_AGE_MS).failure(K::FlowAgeExceeded);
});
case!(duration_exact_boundary, {
    let mut f = base(17);
    set(&mut f, 22, 0, 4);
    set(&mut f, 21, 86400000, 4);
    assert_eq!(
        age(&f, 86400000, 1700000100, DEFAULT_MAX_FLOW_AGE_MS).emitted,
        1
    );
});
case!(duration_one_over, {
    let mut f = base(17);
    set(&mut f, 22, 0, 4);
    set(&mut f, 21, 86400001, 4);
    age(&f, 86400001, 1700000100, DEFAULT_MAX_FLOW_AGE_MS).failure(K::FlowAgeExceeded);
});
case!(half_cycle_rejected, {
    let mut f = base(17);
    set(&mut f, 21, 1_u64 << 31, 4);
    age(&f, 0, 1700000100, MAX_FLOW_AGE_MS).failure(K::FlowTimeOrderingInvalid);
});
case!(full_cycle_ambiguity_rejected, {
    let mut f = base(17);
    set(&mut f, 22, 0, 4);
    set(&mut f, 21, 3000000000, 4);
    let end_age = u64::from(1000000000_u32.wrapping_sub(3000000000));
    assert!(end_age + 3000000000 >= 1_u64 << 32);
    age(&f, 1000000000, 1700000100, MAX_FLOW_AGE_MS).failure(K::FlowTimeOrderingInvalid);
});
case!(unix_zero_valid, {
    let mut f = base(17);
    set(&mut f, 22, 0, 4);
    set(&mut f, 21, 0, 4);
    assert_eq!(age(&f, 0, 0, 0).flow().start_time, "1970-01-01T00:00:00Z");
});
case!(unix_zero_underflow, {
    age(&base(17), 10000, 0, DEFAULT_MAX_FLOW_AGE_MS).failure(K::TimestampArithmeticFailure);
});
case!(unix_u32_max, {
    let mut f = base(17);
    set(&mut f, 22, 10000, 4);
    set(&mut f, 21, 10000, 4);
    assert_eq!(
        age(&f, 10000, u32::MAX, 0).flow().start_time,
        "2106-02-07T06:28:15Z"
    );
});
case!(age_zero_only_instant, {
    let mut f = base(17);
    set(&mut f, 22, 10000, 4);
    set(&mut f, 21, 10000, 4);
    assert_eq!(age(&f, 10000, 1700000100, 0).emitted, 1);
    age(&base(17), 10000, 1700000100, 0).failure(K::FlowAgeExceeded);
});
case!(age_above_half_config_rejected, {
    assert!(NetFlowV9NormalizationConfig::new(1_u64 << 31, 1, 1, 0, 1).is_err());
});
case!(integer_millisecond_precision, {
    let mut f = base(17);
    set(&mut f, 22, 8123, 4);
    set(&mut f, 21, 9456, 4);
    assert_eq!(run(&f).flow().start_time, "2023-11-14T22:14:58.123Z");
    assert_eq!(
        run(&f).flow().end_time.as_deref(),
        Some("2023-11-14T22:14:59.456Z")
    );
});
case!(default_age_is_separate_intervals, {
    assert_eq!(
        NetFlowV9NormalizationConfig::default().max_flow_age_ms(),
        86400000
    );
    let mut f = base(17);
    set(&mut f, 22, 0, 4);
    set(&mut f, 21, 86400000, 4);
    assert_eq!(age(&f, 172800000, 1700000100, 86400000).emitted, 1);
});
case!(required_duplicate_equal, {
    let mut f = base(17);
    f.push(n(4, 17, 1));
    assert_eq!(run(&f).emitted, 1);
});
case!(required_duplicate_conflict, {
    let mut f = base(17);
    f.push(n(4, 6, 1));
    run(&f).failure(K::AmbiguousField);
});
case!(optional_duplicate_equal, {
    let mut f = base(17);
    f.extend([n(7, 53, 2), n(7, 53, 2)]);
    assert_eq!(run(&f).flow().src_port, Some(53));
});
case!(optional_duplicate_conflict, {
    let mut f = base(17);
    f.extend([n(7, 53, 2), n(7, 54, 2)]);
    run(&f).failure(K::AmbiguousField);
});
case!(optional_bad_width_rejects, {
    let mut f = base(17);
    f.push(n(11, 53, 1));
    run(&f).failure(K::UnsupportedFieldWidth);
});
case!(unknown_fields_ignored, {
    let mut f = base(17);
    f.extend([n(136, 3, 1), n(139, 1, 2), (65000, b"not canon".to_vec())]);
    assert_eq!(run(&f).total, 0);
});
case!(arbitrary_field_order, {
    let mut f = base(17);
    f.reverse();
    assert_eq!(run(&f).flow(), run(&base(17)).flow());
});
case!(one_primary_rejection, {
    let mut f = base(17);
    f.extend([n(4, 6, 1), n(7, 53, 1)]);
    let out = run(&f);
    assert_eq!(out.rejected, 1);
    assert_eq!(out.total, 1);
});
case!(many_duplicates_one_notice, {
    let mut f = base(17);
    for _ in 0..100 {
        f.push(n(2, 5, 4));
    }
    assert_eq!(run(&f).total, 1);
});
case!(many_unknown_no_diagnostic_amplification, {
    let mut f = base(17);
    for id in 1000..1100 {
        f.push(n(id, 1, 1));
    }
    assert_eq!(run(&f).total, 0);
});
case!(all_supported_fixed_width_boundaries, {
    for (id, width) in [
        (4, 1),
        (6, 1),
        (7, 2),
        (8, 4),
        (11, 2),
        (12, 4),
        (21, 4),
        (22, 4),
        (27, 16),
        (28, 16),
        (32, 2),
        (60, 1),
    ] {
        for wrong in [width - 1, width + 1] {
            let mut f = base(17);
            f.retain(|f| f.0 != id);
            f.push((id, vec![0; wrong]));
            let out = run(&f);
            assert_eq!(out.emitted, 0, "id={id} width={wrong}");
            if wrong > 0 {
                assert!(out
                    .diagnostics
                    .iter()
                    .any(|d| d.kind == K::UnsupportedFieldWidth));
            }
        }
    }
});
case!(telemetry_source_serialization, {
    assert_eq!(
        serde_json::to_value(TelemetrySource::NetFlowV9).unwrap(),
        json!("netflow_v9")
    );
});
case!(existing_source_serialization_unchanged, {
    assert_eq!(
        serde_json::to_value(TelemetrySource::Zeek).unwrap(),
        json!("zeek")
    );
    assert_eq!(
        serde_json::to_value(TelemetrySource::NetFlowV5).unwrap(),
        json!("netflow_v5")
    );
});

fn coords() -> NetFlowV9IdentityCoordinates<'static> {
    NetFlowV9IdentityCoordinates {
        sensor_id: "sensor-v9-a",
        input_sha256: HASH,
        exporter_id: "exporter-a",
        session_id: "collector-a.udp.epoch-1",
        source_id: 42,
        sequence_number: 123,
        datagram_ordinal: 0,
        flowset_ordinal: 1,
        record_ordinal: 0,
    }
}
case!(frozen_uuid_vector, {
    assert_eq!(
        generate_netflow_v9_record_id(&coords()).unwrap(),
        "3a5978ca-df78-52f8-97f8-9e47e3af8dde"
    );
});
case!(namespace_derivation, {
    assert_eq!(
        uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_URL,
            b"https://utsavagg2007.github.io/SIH-2026/contracts/co-netflow-v9-id-v1"
        ),
        NETFLOW_V9_ID_NAMESPACE
    );
});
case!(uuid_replay_identical, {
    assert_eq!(
        generate_netflow_v9_record_id(&coords()).unwrap(),
        generate_netflow_v9_record_id(&coords()).unwrap()
    );
});
macro_rules! identity_string {
    ($name:ident,$field:ident,$value:expr) => {
        case!($name, {
            let a = coords();
            let original = generate_netflow_v9_record_id(&a).unwrap();
            let b = NetFlowV9IdentityCoordinates {
                $field: $value,
                ..a
            };
            assert_ne!(original, generate_netflow_v9_record_id(&b).unwrap());
        });
    };
}
identity_string!(
    identity_hash,
    input_sha256,
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
);
identity_string!(identity_sensor, sensor_id, "sensor-b");
identity_string!(identity_exporter, exporter_id, "exporter-b");
identity_string!(identity_session, session_id, "session-b");
identity_string!(identity_domain, source_id, 43);
identity_string!(identity_sequence, sequence_number, 124);
identity_string!(identity_datagram, datagram_ordinal, 1);
identity_string!(identity_flowset, flowset_ordinal, 2);
identity_string!(identity_record, record_ordinal, 1);
case!(identity_observed_at_independent, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let out = parse(&p);
    let a = checked(
        &out,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    let src = NetFlowV9SourceContext::new(
        "sensor-v9-a",
        InputMode::ExportFile,
        HASH,
        "2026-10-04T00:00:00Z",
        NetFlowV9ByteBasisProfile::Unknown,
    )
    .unwrap();
    let b = checked(&out, &src, Default::default());
    assert_eq!(a.observations[0].record_id, b.observations[0].record_id);
    assert_ne!(a.observations[0].observed_at, b.observations[0].observed_at);
});
case!(identity_input_mode_independent, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let out = parse(&p);
    let a = checked(
        &out,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    let src = NetFlowV9SourceContext::new(
        "sensor-v9-a",
        InputMode::PcapFile,
        HASH,
        OBSERVED,
        NetFlowV9ByteBasisProfile::Unknown,
    )
    .unwrap();
    assert_eq!(
        a.observations[0].record_id,
        checked(&out, &src, Default::default()).observations[0].record_id
    );
});
case!(identity_hash_case_normalized, {
    let a = coords();
    let b = NetFlowV9IdentityCoordinates {
        input_sha256: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        ..coords()
    };
    assert_eq!(
        generate_netflow_v9_record_id(&a).unwrap(),
        generate_netflow_v9_record_id(&b).unwrap()
    );
});
case!(identity_bad_hash, {
    let a = NetFlowV9IdentityCoordinates {
        input_sha256: "no",
        ..coords()
    };
    assert!(generate_netflow_v9_record_id(&a).is_err());
});
case!(identity_empty_components, {
    for index in 0..3 {
        let mut a = coords();
        match index {
            0 => a.sensor_id = "",
            1 => a.exporter_id = "",
            _ => a.session_id = "",
        };
        assert!(generate_netflow_v9_record_id(&a).is_err());
    }
});
case!(identity_length_prefix_distinguishes_boundaries, {
    let a = NetFlowV9IdentityCoordinates {
        exporter_id: "a",
        session_id: "bc",
        ..coords()
    };
    let b = NetFlowV9IdentityCoordinates {
        exporter_id: "ab",
        session_id: "c",
        ..coords()
    };
    assert_ne!(
        generate_netflow_v9_record_id(&a).unwrap(),
        generate_netflow_v9_record_id(&b).unwrap()
    );
});
case!(source_fingerprint_vector, {
    assert_eq!(
        generate_netflow_v9_session_fingerprint("exporter-a", "collector-a.udp.epoch-1").unwrap(),
        "f0f0f0284a571157be5520ac62d11fb0a6139e3c758527240772d0607c30dab6"
    );
});
case!(source_record_exact_format, {
    assert_eq!(run(&base(17)).observations[0].source_record_id.as_deref(),Some("netflow_v9/exporter-a/f0f0f0284a571157be5520ac62d11fb0a6139e3c758527240772d0607c30dab6/42/123/0/1/0"));
});
case!(source_record_no_raw_session, {
    assert!(!run(&base(17)).observations[0]
        .source_record_id
        .as_ref()
        .unwrap()
        .contains("collector-a.udp.epoch-1"));
});
case!(source_record_bound_and_max_coordinates, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let mut out = parse(&p);
    out.context = NetFlowV9ParseContext {
        session: TransportSessionKey::new(&"e".repeat(256), &"s".repeat(256), 256).unwrap(),
        datagram_ordinal: u64::MAX,
    };
    let key = TemplateKey::new(
        TemplateProtocol::NetFlowV9,
        out.context.session.clone(),
        42,
        256,
    )
    .unwrap();
    let mut registry = TemplateRegistry::new(Default::default());
    let definition = TemplateDefinition::new(
        TemplateKind::Data,
        0,
        &base(17)
            .iter()
            .map(|f| TemplateFieldSpecifier {
                field_id: f.0,
                encoded_length: u16::try_from(f.1.len()).unwrap(),
                enterprise_number: None,
            })
            .collect::<Vec<_>>(),
        256,
    )
    .unwrap();
    registry
        .insert(key, definition, 1700000100000000000)
        .unwrap();
    let bound =
        parse_netflow_v9(&p, out.context.clone(), &mut registry, Default::default()).unwrap();
    let result = checked(
        &bound,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    let source = result.observations[0].source_record_id.as_ref().unwrap();
    assert!(source.len() <= 512);
    assert!(source.contains("/18446744073709551615/"));
});
case!(provenance_names_version, {
    let out = run(&base(17));
    assert_eq!(out.observations[0].provenance.parser_name, PARSER_NAME);
    assert_eq!(
        out.observations[0].provenance.parser_version,
        env!("CARGO_PKG_VERSION")
    );
});
case!(provenance_template_id, {
    assert_eq!(
        run(&base(17)).observations[0].provenance.template_id,
        Some(256)
    );
});
case!(provenance_export_file, {
    assert_eq!(
        run(&base(17)).observations[0].provenance.input_mode,
        InputMode::ExportFile
    );
});
case!(provenance_capture_interface, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let src = source(NetFlowV9ByteBasisProfile::Unknown)
        .with_capture_interface("capture-a")
        .unwrap();
    assert_eq!(
        checked(&parse(&p), &src, Default::default()).observations[0]
            .provenance
            .capture_interface
            .as_deref(),
        Some("capture-a")
    );
});
case!(observed_at_fixed, {
    assert_eq!(run(&base(17)).observations[0].observed_at, OBSERVED);
});
case!(quality_unknown, {
    assert_eq!(
        run(&base(17)).observations[0].quality.fidelity,
        Fidelity::Unknown
    );
});
case!(quality_no_sampling_fields, {
    let out = run(&base(17));
    let q = &out.observations[0].quality;
    assert_eq!(q.sampling_rate, None);
    assert_eq!(q.sampling_probability, None);
    assert_eq!(q.missed_content_bytes, None);
});
case!(quality_no_guessed_truncation_loss, {
    let q = run(&base(17)).observations[0].quality.clone();
    assert!(!q.truncated);
    assert!(!q.loss_detected);
});
case!(no_new_flow_fields, {
    let out = run(&base(17));
    let j = out.json();
    assert!(j["data"].get("event_time").is_none());
    assert!(j["data"].get("duration").is_none());
    assert!(j["provenance"].get("generation").is_none());
});
case!(context_empty_sensor, {
    assert!(NetFlowV9SourceContext::new(
        "",
        InputMode::ExportFile,
        HASH,
        OBSERVED,
        NetFlowV9ByteBasisProfile::Unknown
    )
    .is_err());
});
case!(context_sensor_byte_bound, {
    assert!(NetFlowV9SourceContext::new(
        &"é".repeat(129),
        InputMode::ExportFile,
        HASH,
        OBSERVED,
        NetFlowV9ByteBasisProfile::Unknown
    )
    .is_err());
});
case!(context_no_live_modes, {
    for mode in [InputMode::LiveInterface, InputMode::ExportStream] {
        assert!(NetFlowV9SourceContext::new(
            "sensor",
            mode,
            HASH,
            OBSERVED,
            NetFlowV9ByteBasisProfile::Unknown
        )
        .is_err());
    }
});
case!(context_bad_hash, {
    assert!(NetFlowV9SourceContext::new(
        "sensor",
        InputMode::ExportFile,
        "bad",
        OBSERVED,
        NetFlowV9ByteBasisProfile::Unknown
    )
    .is_err());
});
case!(context_invalid_calendar, {
    assert!(NetFlowV9SourceContext::new(
        "sensor",
        InputMode::ExportFile,
        HASH,
        "2026-02-30T00:00:00Z",
        NetFlowV9ByteBasisProfile::Unknown
    )
    .is_err());
});
case!(context_non_z, {
    assert!(NetFlowV9SourceContext::new(
        "sensor",
        InputMode::ExportFile,
        HASH,
        "2026-10-03T00:00:00+00:00",
        NetFlowV9ByteBasisProfile::Unknown
    )
    .is_err());
});
case!(context_capture_bounds, {
    assert!(source(NetFlowV9ByteBasisProfile::Unknown)
        .with_capture_interface("")
        .is_err());
    assert!(source(NetFlowV9ByteBasisProfile::Unknown)
        .with_capture_interface(&"c".repeat(257))
        .is_err());
});
case!(positive_resource_caps, {
    for (r, o, a) in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
        assert!(NetFlowV9NormalizationConfig::new(0, r, o, 0, a).is_err());
    }
});

case!(count_match_preserved, {
    assert_eq!(run(&base(17)).count, CountValidation::Match);
});
case!(count_mismatch_eligible, {
    let mut p = wire(&base(17), 1, 10000, 1700000100);
    p[2..4].copy_from_slice(&0_u16.to_be_bytes());
    let out = checked(
        &parse(&p),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(out.emitted, 1);
    assert_eq!(
        out.count,
        CountValidation::Mismatch {
            declared: 0,
            parsed: 2
        }
    );
    assert!(!out.observations[0].quality.loss_detected);
});
case!(count_inconclusive_subset, {
    let f = base(17);
    let p = packet(
        &[
            fs(0, &template(256, &f), true),
            fs(256, &payload(&f), true),
            fs(999, &[1, 2, 3, 4], true),
        ],
        3,
        10000,
        1700000100,
    );
    let out = checked(
        &parse(&p),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(out.count, CountValidation::Inconclusive);
    assert_eq!(out.emitted, 1);
});
case!(complete_preserved, {
    assert_eq!(run(&base(17)).completion, ParseCompletion::Complete);
});
case!(complete_with_diagnostics_preserved, {
    let f = base(17);
    let p = packet(
        &[
            fs(0, &template(256, &f), true),
            fs(256, &payload(&f), false),
        ],
        2,
        10000,
        1700000100,
    );
    let out = checked(
        &parse(&p),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(out.completion, ParseCompletion::CompleteWithDiagnostics);
    assert_eq!(out.emitted, 1);
});
case!(stopped_at_limit_prefix, {
    let f = base(17);
    let p = packet(
        &[
            fs(0, &template(256, &f), true),
            fs(256, &payload(&f), true),
            fs(256, &payload(&f).repeat(2), true),
            fs(256, &payload(&f), true),
        ],
        5,
        10000,
        1700000100,
    );
    let cfg = NetFlowV9ParserConfig::new(65535, 8, 8, 8, 8, 2, 128).unwrap();
    let parsed = parse_netflow_v9(
        &p,
        context(),
        &mut TemplateRegistry::new(Default::default()),
        cfg,
    )
    .unwrap();
    let out = checked(
        &parsed,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(out.completion, ParseCompletion::StoppedAtLimit);
    assert_eq!(out.emitted, 1);
});
case!(stopped_for_reset_prefix, {
    let f = base(17);
    let p = packet(
        &[
            fs(0, &template(256, &f), true),
            fs(256, &payload(&f), true),
            fs(0, &template(255, &f), true),
            fs(256, &payload(&f), true),
        ],
        4,
        10000,
        1700000100,
    );
    let out = checked(
        &parse(&p),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(out.completion, ParseCompletion::StoppedForReset);
    assert_eq!(out.disposition, SessionDisposition::ResetRequired);
    assert_eq!(out.emitted, 1);
});
case!(reset_required_never_laundered, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let mut out = parse(&p);
    out.session_disposition = SessionDisposition::ResetRequired;
    let result = normalize_netflow_v9(
        &out,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    )
    .unwrap();
    assert_eq!(result.observations.len(), 1);
    assert!(result.parser_status.reset_required());
});
macro_rules! gate {
    ($name:ident,$state:expr) => {
        case!($name, {
            let p = wire(&base(17), 1, 10000, 1700000100);
            let mut out = parse(&p);
            if let FlowSetContent::Data(d) = &mut out.flowsets[1].content {
                d.state = $state;
            }
            let result = checked(
                &out,
                &source(NetFlowV9ByteBasisProfile::Unknown),
                Default::default(),
            );
            assert_eq!(result.emitted, 0);
            assert_eq!(result.inspected, 0);
        });
    };
}
gate!(skipped_unknown_gate, DataFlowSetState::SkippedUnknown);
gate!(skipped_expired_gate, DataFlowSetState::SkippedExpired);
gate!(rejected_gate, DataFlowSetState::Rejected);
gate!(unprocessed_gate, DataFlowSetState::Unprocessed);
case!(unprocessed_parent_gate, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let mut out = parse(&p);
    out.flowsets[1].processed = false;
    assert_eq!(
        checked(
            &out,
            &source(NetFlowV9ByteBasisProfile::Unknown),
            Default::default()
        )
        .emitted,
        0
    );
});
case!(zero_parser_diagnostic_retention_preserves_status, {
    let mut p = wire(&base(17), 1, 10000, 1700000100);
    p[2..4].copy_from_slice(&0_u16.to_be_bytes());
    let cfg = NetFlowV9ParserConfig::new(65535, 1024, 512, 2048, 4096, 16384, 0).unwrap();
    let parsed = parse_netflow_v9(
        &p,
        context(),
        &mut TemplateRegistry::new(Default::default()),
        cfg,
    )
    .unwrap();
    let out = checked(
        &parsed,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(out.emitted, 1);
    assert_eq!(out.parser_retained, 0);
    assert!(out.parser_total > 0);
    assert_eq!(out.parser_total, out.parser_dropped);
    assert!(matches!(out.count, CountValidation::Mismatch { .. }));
});
case!(diagnostic_cap_exact, {
    let mut f = base(17);
    f.push(n(4, 6, 1));
    let out = custom(
        &f,
        NetFlowV9ByteBasisProfile::Unknown,
        10000,
        1700000100,
        config(10, 10, 2, 10),
        2,
    );
    assert_eq!(out.total, 2);
    assert_eq!(out.dropped, 0);
});
case!(diagnostic_cap_plus_one, {
    let mut f = base(17);
    f.push(n(4, 6, 1));
    let out = custom(
        &f,
        NetFlowV9ByteBasisProfile::Unknown,
        10000,
        1700000100,
        config(10, 10, 2, 10),
        3,
    );
    assert_eq!(out.total, 3);
    assert_eq!(out.diagnostics.len(), 2);
    assert_eq!(out.dropped, 1);
});
case!(diagnostic_zero_retention, {
    let mut f = base(17);
    f.push(n(4, 6, 1));
    let out = custom(
        &f,
        NetFlowV9ByteBasisProfile::Unknown,
        10000,
        1700000100,
        config(10, 10, 0, 10),
        3,
    );
    assert_eq!(out.total, 3);
    assert_eq!(out.dropped, 3);
    assert!(out.diagnostics.is_empty());
    assert_eq!(
        out.status,
        NetFlowV9NormalizationStatus::CompleteWithRejectionsOrWarnings
    );
});
case!(inspection_cap, {
    let out = custom(
        &base(17),
        NetFlowV9ByteBasisProfile::Unknown,
        10000,
        1700000100,
        config(1, 10, 128, 10),
        2,
    );
    assert_eq!(out.inspected, 1);
    assert_eq!(out.emitted, 1);
    assert_eq!(out.status, NetFlowV9NormalizationStatus::StoppedAtLimit);
});
case!(observation_cap, {
    let out = custom(
        &base(17),
        NetFlowV9ByteBasisProfile::Unknown,
        10000,
        1700000100,
        config(10, 1, 128, 10),
        2,
    );
    assert_eq!(out.emitted, 1);
    assert_eq!(out.status, NetFlowV9NormalizationStatus::StoppedAtLimit);
});
case!(audit_cap, {
    let out = custom(
        &base(17),
        NetFlowV9ByteBasisProfile::Unknown,
        10000,
        1700000100,
        config(10, 10, 128, 1),
        2,
    );
    assert_eq!(out.audit.len(), 1);
    assert_eq!(out.inspected, 1);
    assert_eq!(out.status, NetFlowV9NormalizationStatus::StoppedAtLimit);
});
case!(limit_exact_not_stopped, {
    let out = custom(
        &base(17),
        NetFlowV9ByteBasisProfile::Unknown,
        10000,
        1700000100,
        config(1, 1, 0, 1),
        1,
    );
    assert_eq!(out.status, NetFlowV9NormalizationStatus::Complete);
});
case!(huge_config_no_eager_allocation, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let out = normalize_netflow_v9(
        &parse(&p),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        config(usize::MAX, usize::MAX, usize::MAX, usize::MAX),
    )
    .unwrap()
    .observations;
    assert_eq!(out.len(), 1);
});
case!(many_records_no_collapse, {
    assert_eq!(
        custom(
            &base(17),
            NetFlowV9ByteBasisProfile::Unknown,
            10000,
            1700000100,
            Default::default(),
            25
        )
        .emitted,
        25
    );
});
case!(identical_records_distinct_ids, {
    let out = custom(
        &base(17),
        NetFlowV9ByteBasisProfile::Unknown,
        10000,
        1700000100,
        Default::default(),
        2,
    );
    assert_ne!(out.observations[0].record_id, out.observations[1].record_id);
});
case!(sibling_rejection_preserves_valid, {
    let f = base(17);
    let mut bad = f.clone();
    set(&mut bad, 21, 10001, 4);
    let mut records = payload(&bad);
    records.extend(payload(&f));
    let p = packet(
        &[fs(0, &template(256, &f), true), fs(256, &records, true)],
        3,
        10000,
        1700000100,
    );
    let out = checked(
        &parse(&p),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(out.emitted, 1);
    assert_eq!(out.rejected, 1);
    assert_eq!(out.audit[1].record_ordinal, 1);
});
case!(multiple_flowsets_physical_order, {
    let f = base(17);
    let p = packet(
        &[
            fs(0, &template(256, &f), true),
            fs(256, &payload(&f), true),
            fs(256, &payload(&f), true),
        ],
        3,
        10000,
        1700000100,
    );
    let out = checked(
        &parse(&p),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(out.audit[0].flowset_ordinal, 1);
    assert_eq!(out.audit[1].flowset_ordinal, 2);
    assert_ne!(out.observations[0].record_id, out.observations[1].record_id);
});
case!(reverse_tuples_separate, {
    let f = base(17);
    let mut reverse = f.clone();
    reverse[0].1 = f[1].1.clone();
    reverse[1].1 = f[0].1.clone();
    let mut bytes = payload(&f);
    bytes.extend(payload(&reverse));
    let p = packet(
        &[fs(0, &template(256, &f), true), fs(256, &bytes, true)],
        3,
        10000,
        1700000100,
    );
    let out = checked(
        &parse(&p),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(out.emitted, 2);
    assert_ne!(out.observations[0].record_id, out.observations[1].record_id);
});
case!(immutable_snapshot_survives_registry_replacement, {
    let f = base(17);
    let p = wire(&f, 1, 10000, 1700000100);
    let mut registry = TemplateRegistry::new(Default::default());
    let out = parse_netflow_v9(&p, context(), &mut registry, Default::default()).unwrap();
    let before = checked(
        &out,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    let key = TemplateKey::new(TemplateProtocol::NetFlowV9, context().session, 42, 256).unwrap();
    let definition = TemplateDefinition::new(
        TemplateKind::Data,
        0,
        &[TemplateFieldSpecifier {
            field_id: 2,
            encoded_length: 8,
            enterprise_number: None,
        }],
        256,
    )
    .unwrap();
    registry
        .insert(key, definition, out.source_time_ns + 1)
        .unwrap();
    assert_eq!(
        before,
        checked(
            &out,
            &source(NetFlowV9ByteBasisProfile::Unknown),
            Default::default()
        )
    );
});
case!(old_new_snapshots_separate, {
    let f = base(17);
    let mut newer = f.clone();
    set(&mut newer, 2, 6, 8);
    let p = packet(
        &[
            fs(0, &template(256, &f), true),
            fs(256, &payload(&f), true),
            fs(0, &template(256, &newer), true),
            fs(256, &payload(&newer), true),
        ],
        4,
        10000,
        1700000100,
    );
    let out = checked(
        &parse(&p),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(out.emitted, 2);
    assert_eq!(out.audit[0].generation, 1);
    assert_eq!(out.audit[1].generation, 2);
    assert_ne!(out.observations[0].record_id, out.observations[1].record_id);
});
case!(template_generation_excluded_from_identity, {
    let f = base(17);
    let p = wire(&f, 1, 10000, 1700000100);
    let a = run(&f);
    let key = TemplateKey::new(TemplateProtocol::NetFlowV9, context().session, 42, 256).unwrap();
    let definition = TemplateDefinition::new(
        TemplateKind::Data,
        0,
        &[TemplateFieldSpecifier {
            field_id: 2,
            encoded_length: 8,
            enterprise_number: None,
        }],
        256,
    )
    .unwrap();
    let mut registry = TemplateRegistry::new(Default::default());
    registry
        .insert(key, definition, 1700000100000000000)
        .unwrap();
    let parsed = parse_netflow_v9(&p, context(), &mut registry, Default::default()).unwrap();
    let b = checked(
        &parsed,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_ne!(a.audit[0].generation, b.audit[0].generation);
    assert_eq!(a.observations[0].record_id, b.observations[0].record_id);
});
case!(template_id_excluded_from_identity, {
    let f = base(17);
    let p = packet(
        &[fs(0, &template(257, &f), true), fs(257, &payload(&f), true)],
        2,
        10000,
        1700000100,
    );
    let a = run(&f);
    let b = checked(
        &parse(&p),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(a.observations[0].record_id, b.observations[0].record_id);
    assert_ne!(
        a.observations[0].provenance.template_id,
        b.observations[0].provenance.template_id
    );
});
case!(snapshot_session_mismatch, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let mut out = parse(&p);
    out.context.session = TransportSessionKey::new("other", "other", 256).unwrap();
    checked(
        &out,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    )
    .failure(K::InputBindingMismatch);
});
case!(snapshot_domain_mismatch, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let mut out = parse(&p);
    out.header.source_id = 43;
    checked(
        &out,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    )
    .failure(K::InputBindingMismatch);
});
case!(snapshot_template_mismatch, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let mut out = parse(&p);
    out.flowsets[1].flowset_id = 257;
    checked(
        &out,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    )
    .failure(K::InputBindingMismatch);
});
case!(physical_flowset_mismatch, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let mut out = parse(&p);
    out.flowsets[1].flowset_ordinal = 0;
    checked(
        &out,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    )
    .failure(K::InputBindingMismatch);
});
case!(metadata_record_count_mismatch, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let mut out = parse(&p);
    if let FlowSetContent::Data(data) = &mut out.flowsets[1].content {
        data.record_count = 2;
    }
    checked(
        &out,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    )
    .failure(K::InputBindingMismatch);
});
case!(header_time_binding_mismatch, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let mut out = parse(&p);
    out.source_time_ns += 1;
    checked(
        &out,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    )
    .failure(K::InputBindingMismatch);
});
case!(oversized_session_supported_assumption_rejected, {
    let p = wire(&base(17), 1, 10000, 1700000100);
    let mut out = parse(&p);
    out.context.session = TransportSessionKey::new("exporter-a", &"s".repeat(257), 512).unwrap();
    checked(
        &out,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    )
    .failure(K::InputBindingMismatch);
});
case!(replay_full_result_deterministic, {
    let p = wire(&base(17), 2, 10000, 1700000100);
    let out = parse(&p);
    let a = checked(
        &out,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    for _ in 0..5 {
        assert_eq!(
            a,
            checked(
                &out,
                &source(NetFlowV9ByteBasisProfile::Unknown),
                Default::default()
            )
        );
    }
});

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/export/netflow_v9_canonical")
}
fn read_hex(path: &Path) -> Vec<u8> {
    let value = std::fs::read_to_string(path).unwrap();
    let text = value.trim();
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}
fn golden(name: &str) {
    let root = fixture_root();
    let m: Value =
        serde_json::from_slice(&std::fs::read(root.join(format!("metadata/{name}.json"))).unwrap())
            .unwrap();
    let bytes = if let Some(existing) = m["existing_wire"].as_str() {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join(existing),
        )
        .unwrap()
    } else {
        read_hex(&root.join(format!("wire/{name}.hex")))
    };
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        m["wire_sha256"].as_str().unwrap()
    );
    let s = &m["source_context"];
    let ctx = NetFlowV9ParseContext {
        session: TransportSessionKey::new(
            s["exporter_id"].as_str().unwrap(),
            s["session_id"].as_str().unwrap(),
            256,
        )
        .unwrap(),
        datagram_ordinal: 0,
    };
    let basis = if m["byte_basis_profile"] == "VerifiedIpLayer" {
        NetFlowV9ByteBasisProfile::VerifiedIpLayer
    } else {
        NetFlowV9ByteBasisProfile::Unknown
    };
    let src = NetFlowV9SourceContext::new(
        s["sensor_id"].as_str().unwrap(),
        InputMode::ExportFile,
        s["input_sha256"].as_str().unwrap(),
        m["observed_at"].as_str().unwrap(),
        basis,
    )
    .unwrap();
    let parsed = parse_netflow_v9(
        &bytes,
        ctx,
        &mut TemplateRegistry::new(Default::default()),
        Default::default(),
    )
    .unwrap();
    let cfg = NetFlowV9NormalizationConfig::new(
        m["max_flow_age_ms"].as_u64().unwrap(),
        16384,
        16384,
        128,
        16384,
    )
    .unwrap();
    let result = normalize_netflow_v9(&parsed, &src, cfg).unwrap();
    let mut actual = Vec::new();
    for observation in &result.observations {
        serde_json::to_writer(&mut actual, observation).unwrap();
        actual.push(b'\n');
    }
    let expected = std::fs::read(root.join(format!("golden/{name}.jsonl"))).unwrap();
    assert_eq!(actual, expected, "golden {name}");
    assert_eq!(
        format!("{:x}", Sha256::digest(&actual)),
        m["golden_sha256"].as_str().unwrap()
    );
    assert_eq!(
        result.records_inspected as u64,
        m["records_inspected"].as_u64().unwrap()
    );
    assert_eq!(
        result.records_emitted as u64,
        m["records_emitted"].as_u64().unwrap()
    );
    assert_eq!(
        result.records_rejected as u64,
        m["records_rejected"].as_u64().unwrap()
    );
    assert_eq!(
        result.options_records_ignored as u64,
        m["options_records_ignored"].as_u64().unwrap()
    );
    assert_eq!(
        result
            .diagnostics
            .iter()
            .map(|d| format!("{:?}", d.kind))
            .collect::<Vec<_>>(),
        m["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        format!("{:?}", result.normalization_status),
        m["normalization_status"].as_str().unwrap()
    );
    assert_eq!(
        format!("{:?}", result.parser_status.completion),
        m["parser_completion"].as_str().unwrap()
    );
    assert_eq!(
        format!("{:?}", result.parser_status.session_disposition),
        m["session_disposition"].as_str().unwrap()
    );
    let count = match result.parser_status.count_validation {
        CountValidation::Match => "Match",
        CountValidation::Mismatch { declared, parsed } => {
            assert_eq!(u64::from(declared), m["declared_count"].as_u64().unwrap());
            assert_eq!(parsed as u64, m["parsed_count"].as_u64().unwrap());
            "Mismatch"
        }
        CountValidation::Inconclusive => "Inconclusive",
    };
    assert_eq!(count, m["parser_count"].as_str().unwrap());
    assert_eq!(
        result.audit.len(),
        m["coordinates"].as_array().unwrap().len()
    );
    for (audit, coordinate) in result
        .audit
        .iter()
        .zip(m["coordinates"].as_array().unwrap())
    {
        assert_eq!(
            u64::from(audit.flowset_ordinal),
            coordinate["flowset_ordinal"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(audit.record_ordinal),
            coordinate["record_ordinal"].as_u64().unwrap()
        );
        assert_eq!(
            u64::from(audit.template_id),
            coordinate["template_id"].as_u64().unwrap()
        );
    }
    for _ in 0..3 {
        assert_eq!(result, normalize_netflow_v9(&parsed, &src, cfg).unwrap());
    }
}
macro_rules! gold {
    ($name:ident,$fixture:literal) => {
        case!($name, {
            golden($fixture);
        });
    };
}
gold!(gold_udp, "udp_min");
gold!(gold_tcp, "tcp_min");
gold!(gold_ipv6, "ipv6");
gold!(gold_icmp, "icmpv4");
gold!(gold_packet_only, "packet_only");
gold!(gold_byte_only, "byte_only");
gold!(gold_both, "both_counters");
gold!(gold_zero, "zero_counter");
gold!(gold_wrap, "uptime_wrap");
gold!(gold_repeated, "repeated");
gold!(gold_details, "tcp_details");
gold!(gold_v6zero, "ipv6_zero");
gold!(gold_max, "u64_max");
gold!(gold_equal, "duplicate_equal");
gold!(gold_deferred, "deferred_bad_bytes");
gold!(gold_sctp, "sctp");
gold!(gold_icmpv6, "icmpv6");
gold!(gold_selected, "both_families_selected");
gold!(gold_milliseconds, "millisecond_time");
gold!(gold_missing_src, "missing_src");
gold!(gold_missing_dst, "missing_dst");
gold!(gold_missing_protocol, "missing_protocol");
gold!(gold_missing_first, "missing_first");
gold!(gold_missing_last, "missing_last");
gold!(gold_no_counter, "no_counter");
gold!(gold_unknown_bytes, "byte_only_unknown");
gold!(gold_counter_width, "counter_width9");
gold!(gold_byte_width, "active_byte_width9");
gold!(gold_conflict, "duplicate_conflict");
gold!(gold_optional_width, "optional_wrong_width");
gold!(gold_no_v6_selector, "ipv6_no_selector");
gold!(gold_no_both_selector, "both_no_selector");
gold!(gold_mixed, "mixed_endpoints");
gold!(gold_bad_selector, "invalid_selector");
gold!(gold_future, "future_last");
gold!(gold_age, "age_exceeded");
gold!(gold_underflow, "unix_underflow");
gold!(gold_softflowd_negative, "softflowd_negative");

case!(fixture_inventory_38, {
    assert_eq!(
        std::fs::read_dir(fixture_root().join("metadata"))
            .unwrap()
            .count(),
        38
    );
});
case!(production_no_reparse_or_registry_lookup, {
    let text = include_str!("../src/netflow/v9_normalize.rs");
    for forbidden in [
        "parse_netflow_v9(",
        "parse_netflow_v9_wire(",
        "resolve_netflow_v9(",
        "registry.lookup(",
        "SystemTime::now(",
        "Utc::now(",
        "unsafe {",
    ] {
        assert!(!text.contains(forbidden), "{forbidden}");
    }
});
case!(diagnostics_no_payload_leak, {
    let mut f = base(17);
    f.push(n(4, 6, 1));
    let out = run(&f);
    let text = format!("{:?}", out.diagnostics);
    assert!(!text.contains("192.0.2.1"));
    assert!(!text.contains("collector-a"));
    assert!(!text.contains(HASH));
});

case!(verified_zero_bytes_affirmative, {
    let mut fields = base(17);
    fields.push(n(1, 0, 8));
    assert_eq!(
        custom(
            &fields,
            NetFlowV9ByteBasisProfile::VerifiedIpLayer,
            10000,
            1700000100,
            Default::default(),
            1
        )
        .flow()
        .counters
        .src_to_dst
        .ip_bytes,
        Some(0)
    );
});
case!(f7_evidence_lf_checkout_policy, {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(".gitattributes");
    let policy = std::fs::read_to_string(path).unwrap();
    for suffix in [
        "golden/*.jsonl",
        "golden/*.sha256",
        "wire/*.hex",
        "wire/*.sha256",
        "metadata/*.json",
    ] {
        assert!(policy.lines().any(|line| line
            == format!(
                "/ingestion/tests/fixtures/export/netflow_v9_canonical/{suffix} text eol=lf"
            )));
    }
});
case!(bounded_wire_mutations_f6_to_f7_have_no_panic, {
    // Adversarial bytes always enter F6 first; this is not a raw-wire F7 API.
    let root = fixture_root();
    let mut inputs = std::fs::read_dir(root.join("wire"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "hex"))
        .map(|path| read_hex(&path))
        .collect::<Vec<_>>();
    inputs.push(
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/export/netflow_v9/real/softflowd_000.bin"),
        )
        .unwrap(),
    );
    for input in inputs {
        for offset in 0..input.len() {
            for value in [0, 255, input[offset] ^ 128] {
                let mut mutated = input.clone();
                mutated[offset] = value;
                let check = std::panic::catch_unwind(|| {
                    let mut registry = TemplateRegistry::new(Default::default());
                    if let Ok(parsed) =
                        parse_netflow_v9(&mutated, context(), &mut registry, Default::default())
                    {
                        let src = source(NetFlowV9ByteBasisProfile::VerifiedIpLayer);
                        let result =
                            normalize_netflow_v9(&parsed, &src, config(32, 16, 3, 32)).unwrap();
                        assert!(result.observations.len() <= 16);
                        assert!(result.audit.len() <= 32);
                        assert!(result.diagnostics.len() <= 3);
                        assert_eq!(
                            result.parser_status.session_disposition,
                            parsed.session_disposition
                        );
                    }
                });
                assert!(check.is_ok(), "source-controlled panic at offset {offset}");
            }
        }
    }
});
case!(every_supported_ie_duplicate_equal_and_conflict, {
    for (id, width) in [
        (1, 4),
        (2, 4),
        (4, 1),
        (6, 1),
        (7, 2),
        (8, 4),
        (10, 2),
        (11, 2),
        (12, 4),
        (14, 2),
        (21, 4),
        (22, 4),
        (27, 16),
        (28, 16),
        (32, 2),
        (60, 1),
    ] {
        let mut fields = if matches!(id, 27 | 28 | 60) {
            v6(17)
        } else if id == 32 {
            base(1)
        } else {
            base(6)
        };
        if !fields.iter().any(|field| field.0 == id) {
            fields.push(n(id, 1, width));
        }
        let original = fields.iter().find(|field| field.0 == id).unwrap().clone();
        fields.push(original.clone());
        let equal = custom(
            &fields,
            NetFlowV9ByteBasisProfile::VerifiedIpLayer,
            10000,
            1700000100,
            Default::default(),
            1,
        );
        assert_eq!(equal.emitted, 1, "id={id}");
        assert_eq!(equal.diagnostics[0].kind, K::DuplicateEquivalent);
        let last = fields.last_mut().unwrap();
        last.1[0] ^= 1;
        custom(
            &fields,
            NetFlowV9ByteBasisProfile::VerifiedIpLayer,
            10000,
            1700000100,
            Default::default(),
            1,
        )
        .failure(K::AmbiguousField);
    }
});
case!(all_interface_widths_two_through_eight, {
    for width in 2..=8 {
        let mut fields = base(17);
        fields.extend([n(10, 123, width), n(14, 456, width)]);
        let result = run(&fields);
        assert_eq!(
            result.flow().ingress_interface.as_deref(),
            Some("ifindex:123")
        );
        assert_eq!(
            result.flow().egress_interface.as_deref(),
            Some("ifindex:456")
        );
    }
});
case!(verified_max_bytes_exact, {
    let mut fields = base(17);
    fields.push(n(1, u64::MAX, 8));
    let result = custom(
        &fields,
        NetFlowV9ByteBasisProfile::VerifiedIpLayer,
        10000,
        1700000100,
        Default::default(),
        1,
    );
    assert_eq!(
        result.json()["data"]["counters"]["src_to_dst"]["ip_bytes"].as_u64(),
        Some(u64::MAX)
    );
});
case!(domain_and_sequence_zero_preserved, {
    let mut bytes = wire(&base(17), 1, 10000, 1700000100);
    bytes[12..20].fill(0);
    let result = checked(
        &parse(&bytes),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(
        result.observations[0].provenance.observation_domain_id,
        Some(0)
    );
    assert_eq!(result.observations[0].provenance.message_sequence, Some(0));
    assert!(result.observations[0]
        .source_record_id
        .as_ref()
        .unwrap()
        .ends_with("/0/0/0/1/0"));
});
case!(domain_and_sequence_max_preserved, {
    let mut bytes = wire(&base(17), 1, 10000, 1700000100);
    bytes[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    bytes[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
    let result = checked(
        &parse(&bytes),
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(
        result.observations[0].provenance.observation_domain_id,
        Some(u32::MAX)
    );
    assert_eq!(
        result.observations[0].provenance.message_sequence,
        Some(u64::from(u32::MAX))
    );
    assert!(result.observations[0]
        .source_record_id
        .as_ref()
        .unwrap()
        .contains("/4294967295/4294967295/"));
});
case!(pcap_input_mode_populated, {
    let bytes = wire(&base(17), 1, 10000, 1700000100);
    let src = NetFlowV9SourceContext::new(
        "sensor-v9-a",
        InputMode::PcapFile,
        HASH,
        OBSERVED,
        NetFlowV9ByteBasisProfile::Unknown,
    )
    .unwrap();
    assert_eq!(
        checked(&parse(&bytes), &src, Default::default()).observations[0]
            .provenance
            .input_mode,
        InputMode::PcapFile
    );
});
case!(renamed_artifact_same_hash_and_uuid, {
    // Test-only reviewable hex storage; production F7 accepts no filesystem path.
    let original = fixture_root().join("wire/udp_min.hex");
    let directory = std::env::temp_dir().join(format!("sih-f7-rename-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let renamed = directory.join("renamed-export.hex");
    std::fs::copy(&original, &renamed).unwrap();
    let a_hash = sha256_file(&original).unwrap();
    let b_hash = sha256_file(&renamed).unwrap();
    assert_eq!(a_hash, b_hash);
    let a_bytes = read_hex(&original);
    let b_bytes = read_hex(&renamed);
    let src = NetFlowV9SourceContext::new(
        "sensor-v9-a",
        InputMode::ExportFile,
        &a_hash,
        OBSERVED,
        NetFlowV9ByteBasisProfile::Unknown,
    )
    .unwrap();
    let a = checked(&parse(&a_bytes), &src, Default::default());
    let b = checked(&parse(&b_bytes), &src, Default::default());
    assert_eq!(a, b);
    std::fs::remove_file(renamed).unwrap();
    std::fs::remove_dir(directory).unwrap();
});
case!(softflowd_negative_exact_accounting_and_hash, {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/export/netflow_v9/real/softflowd_000.bin");
    assert_eq!(
        sha256_file(&path).unwrap(),
        "31cc964436b85c9f8a82e825956c3fa2ea13c47d35374050ac8f13bb769e2cb2"
    );
    let bytes = std::fs::read(path).unwrap();
    let result = checked(
        &parse(&bytes),
        &source(NetFlowV9ByteBasisProfile::VerifiedIpLayer),
        Default::default(),
    );
    assert_eq!((result.emitted, result.rejected, result.options), (0, 8, 1));
    assert_eq!(
        result.count,
        CountValidation::Mismatch {
            declared: 8,
            parsed: 14
        }
    );
    assert!(result
        .diagnostics
        .iter()
        .all(|d| d.kind == K::FlowTimeOrderingInvalid));
});

// LOW-03: retain one bounded registry across each ordered wire transcript.
// Capture every parser result, normalization result and registry checkpoint;
// replay equality therefore includes snapshots, IDs, diagnostics and audit.
const TRANSCRIPT_SECONDS: u32 = 1_700_000_100;
const TRANSCRIPT_EPOCH: &str = "transcript.epoch-1";

#[derive(Clone, Debug)]
struct TranscriptPacket {
    bytes: Vec<u8>,
    session: TransportSessionKey,
}

#[derive(Debug, PartialEq)]
struct TranscriptFrame<'a> {
    parser: Result<NetFlowV9ParseOutcome<'a>, NetFlowV9ParseError>,
    normalized: Option<Checked>,
    registry: TemplateRegistry,
}

#[derive(Debug, PartialEq)]
struct TranscriptRun<'a> {
    frames: Vec<TranscriptFrame<'a>>,
    quarantined: Vec<TransportSessionKey>,
    registry: TemplateRegistry,
}

fn transcript_message(
    epoch: &str,
    domain: u32,
    seconds: u32,
    sets: Vec<Vec<u8>>,
    count: u16,
) -> TranscriptPacket {
    let mut bytes = packet(&sets, count, 10000, seconds);
    bytes[16..20].copy_from_slice(&domain.to_be_bytes());
    TranscriptPacket {
        bytes,
        session: TransportSessionKey::new("exporter-a", epoch, 256).unwrap(),
    }
}

fn transcript_install(
    epoch: &str,
    domain: u32,
    seconds: u32,
    fields: &[Field],
) -> TranscriptPacket {
    transcript_message(
        epoch,
        domain,
        seconds,
        vec![fs(0, &template(256, fields), true)],
        1,
    )
}

fn transcript_data(epoch: &str, domain: u32, seconds: u32, fields: &[Field]) -> TranscriptPacket {
    transcript_message(
        epoch,
        domain,
        seconds,
        vec![fs(256, &payload(fields), true)],
        1,
    )
}

fn transcript_source(bytes: &[u8]) -> NetFlowV9SourceContext {
    NetFlowV9SourceContext::new(
        "sensor-transcript",
        InputMode::ExportFile,
        &format!("{:x}", Sha256::digest(bytes)),
        OBSERVED,
        NetFlowV9ByteBasisProfile::Unknown,
    )
    .unwrap()
}

fn replay_transcript<'a>(
    messages: &'a [TranscriptPacket],
    sentinel: Option<&(TemplateKey, TemplateDefinition)>,
) -> TranscriptRun<'a> {
    let mut registry = TemplateRegistry::new(TemplateRegistryConfig::new(8, 256, 256).unwrap());
    if let Some((key, definition)) = sentinel {
        registry
            .insert(
                key.clone(),
                definition.clone(),
                u64::from(TRANSCRIPT_SECONDS) * 1_000_000_000,
            )
            .unwrap();
    }
    let mut frames = Vec::new();
    let mut quarantined = Vec::new();
    for (ordinal, message) in messages.iter().enumerate() {
        // Model the frozen caller obligation, never silently reuse a reset epoch.
        assert!(
            !quarantined.contains(&message.session),
            "caller reused a quarantined epoch"
        );
        let before = registry.clone();
        let parsed = parse_netflow_v9(
            &message.bytes,
            NetFlowV9ParseContext {
                session: message.session.clone(),
                datagram_ordinal: u64::try_from(ordinal).unwrap(),
            },
            &mut registry,
            Default::default(),
        );
        let disposition = match &parsed {
            Ok(out) => out.session_disposition,
            Err(error) => {
                assert_eq!(registry, before, "ordinary Err hid registry mutation");
                error.session_disposition()
            }
        };
        let normalized = parsed.as_ref().ok().map(|out| {
            let result = checked(
                out,
                &transcript_source(&message.bytes),
                config(32, 16, 3, 32),
            );
            assert_eq!(result.disposition, disposition);
            assert!(result.observations.len() <= 16);
            assert!(result.audit.len() <= 32);
            assert!(result.diagnostics.len() <= 3);
            assert_eq!(result.total, result.diagnostics.len() + result.dropped);
            result
        });
        if disposition == SessionDisposition::ResetRequired {
            quarantined.push(message.session.clone());
        }
        assert!(registry.len() <= 8);
        assert!(registry.timeline_count() <= registry.len());
        assert!(registry
            .entries()
            .all(|(_, entry)| entry.definition().fields().len() <= 256));
        frames.push(TranscriptFrame {
            parser: parsed,
            normalized,
            registry: registry.clone(),
        });
    }
    TranscriptRun {
        frames,
        quarantined,
        registry,
    }
}

fn transcript_twice<'a>(
    messages: &'a [TranscriptPacket],
    sentinel: Option<&(TemplateKey, TemplateDefinition)>,
) -> TranscriptRun<'a> {
    let first = replay_transcript(messages, sentinel);
    let second = replay_transcript(messages, sentinel);
    assert_eq!(first, second, "complete transcript replay changed");
    first
}

fn transcript_output<'a>(frame: &'a TranscriptFrame<'_>) -> &'a Checked {
    frame.normalized.as_ref().unwrap()
}

fn transcript_flowset<'a, 'b>(
    frame: &'a TranscriptFrame<'b>,
    ordinal: usize,
) -> &'a DataFlowSetOutcome<'b> {
    match &frame.parser.as_ref().unwrap().flowsets[ordinal].content {
        FlowSetContent::Data(data) => data,
        _ => panic!("expected a Data FlowSet"),
    }
}

fn transcript_transition(frame: &TranscriptFrame<'_>) -> TemplateTransition {
    match &frame.parser.as_ref().unwrap().flowsets[0].content {
        FlowSetContent::Templates { records, .. } => match records[0].state {
            TemplateRecordState::Applied(transition) => transition,
            _ => panic!("expected an applied template"),
        },
        _ => panic!("expected a Template FlowSet"),
    }
}

fn assert_transcript_flow(frame: &TranscriptFrame<'_>, packets: u64, generation: u64) {
    let out = transcript_output(frame);
    assert_eq!(out.emitted, 1);
    assert_eq!(out.rejected, 0);
    assert_eq!(out.flow().src_ip, "192.0.2.1");
    assert_eq!(out.flow().dst_ip, "198.51.100.2");
    assert_eq!(out.flow().ip_protocol, 17);
    assert_eq!(out.flow().counters.src_to_dst.packets, Some(packets));
    assert!(out.flow().counters.dst_to_src.is_none());
    assert_eq!(out.audit[0].generation, generation);
    assert_eq!(out.disposition, SessionDisposition::Continue);
}

fn rejected_transcript_template() -> Vec<Field> {
    let mut fields = base(17);
    fields[0].1.clear(); // Trustworthy extent/ID, unsupported zero-width field.
    fields
}

case!(low03_template_install_then_valid_data, {
    let fields = base(17);
    let messages = [
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS, &fields),
        transcript_data(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 1, &fields),
    ];
    let run = transcript_twice(&messages, None);
    assert_eq!(
        transcript_transition(&run.frames[0]).kind,
        TemplateTransitionKind::Inserted
    );
    assert_eq!(transcript_transition(&run.frames[0]).generation, 1);
    assert_eq!(transcript_output(&run.frames[0]).emitted, 0);
    assert_eq!(
        transcript_flowset(&run.frames[1], 0).state,
        DataFlowSetState::Decoded
    );
    assert_transcript_flow(&run.frames[1], 5, 1);
});

case!(low03_install_mutated_data_then_trusted_data, {
    let fields = base(17);
    let original = transcript_data(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 1, &fields);
    // 42 curated attempts: Count, sequence, Source ID, FlowSet ID/length,
    // address/protocol/counter bytes. This supplements, not replaces, the sweep.
    let offsets = [2, 3, 12, 15, 16, 19, 20, 21, 22, 23, 24, 28, 32, 41];
    let mut attempts = 0;
    let mut reset_attempts = 0;
    for offset in offsets {
        for replacement in [0, 255, original.bytes[offset] ^ 1] {
            let mut corrupted = original.clone();
            corrupted.bytes[offset] = replacement;
            let mut messages = vec![
                transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS, &fields),
                corrupted,
            ];
            let prefix = replay_transcript(&messages, None);
            let reset = !prefix.quarantined.is_empty();
            // Do not process more input in the old epoch when F6 demands reset.
            if reset {
                reset_attempts += 1;
                messages.push(transcript_install(
                    "transcript.epoch-2",
                    42,
                    TRANSCRIPT_SECONDS + 2,
                    &fields,
                ));
                messages.push(transcript_data(
                    "transcript.epoch-2",
                    42,
                    TRANSCRIPT_SECONDS + 3,
                    &fields,
                ));
            } else {
                messages.push(transcript_data(
                    TRANSCRIPT_EPOCH,
                    42,
                    TRANSCRIPT_SECONDS + 2,
                    &fields,
                ));
            }
            let result = std::panic::catch_unwind(|| {
                let run = transcript_twice(&messages, None);
                // Corrupt data cannot install a template under another key.
                let before = &run.frames[0].registry;
                let after = &run.frames[1].registry;
                assert_eq!(
                    after.entries().collect::<Vec<_>>(),
                    before.entries().collect::<Vec<_>>()
                );
                assert_eq!(after.config(), before.config());
                assert_eq!(after.timeline_count(), before.timeline_count());
                // F5 lookup advances an existing timeline even for unknown
                // template IDs; it does not refresh the definition/lifetime.
                let lookup_in_original_domain = run.frames[1].parser.as_ref().is_ok_and(|out| {
                    out.header.source_id == 42
                        && matches!(out.flowsets[0].content, FlowSetContent::Data(_))
                });
                let timeline = before.entries().next().unwrap().0.timeline();
                let expected_time = TRANSCRIPT_SECONDS + u32::from(lookup_in_original_domain);
                assert_eq!(
                    after.timeline_last_source_time_ns(timeline),
                    Some(u64::from(expected_time) * 1_000_000_000)
                );
                assert_transcript_flow(run.frames.last().unwrap(), 5, 1);
                assert_eq!(run.quarantined.is_empty(), !reset);
            });
            assert!(
                result.is_ok(),
                "stateful data mutation offset={offset} replacement={replacement}"
            );
            attempts += 1;
        }
    }
    assert_eq!(attempts, 42);
    assert!(
        reset_attempts > 0,
        "curated set must actually exercise reset"
    );
});

case!(low03_identical_refresh_then_data, {
    let fields = base(17);
    let messages = [
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS, &fields),
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 1, &fields),
        transcript_data(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 2, &fields),
    ];
    let run = transcript_twice(&messages, None);
    let transition = transcript_transition(&run.frames[1]);
    assert_eq!(transition.kind, TemplateTransitionKind::Refreshed);
    assert_eq!(transition.generation, 1);
    let entry = run.registry.entries().next().unwrap().1;
    assert_eq!(
        entry.first_seen_ns(),
        u64::from(TRANSCRIPT_SECONDS) * 1_000_000_000
    );
    assert_eq!(
        entry.last_seen_ns(),
        u64::from(TRANSCRIPT_SECONDS + 1) * 1_000_000_000
    );
    assert_transcript_flow(&run.frames[2], 5, 1);
});

case!(low03_changed_definition_keeps_old_snapshot, {
    let old = base(17);
    let mut new = old.clone();
    set(&mut new, 2, 6, 8);
    let messages = [
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS, &old),
        transcript_data(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 1, &old),
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 2, &new),
        transcript_data(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 3, &new),
    ];
    let run = transcript_twice(&messages, None);
    assert_eq!(
        transcript_transition(&run.frames[2]).kind,
        TemplateTransitionKind::Replaced
    );
    assert_eq!(transcript_transition(&run.frames[2]).generation, 2);
    assert_transcript_flow(&run.frames[1], 5, 1);
    assert_transcript_flow(&run.frames[3], 6, 2);
    let prior = run.frames[1].parser.as_ref().unwrap();
    assert_eq!(
        run.frames[1].normalized.as_ref().unwrap(),
        &checked(
            prior,
            &transcript_source(&messages[1].bytes),
            config(32, 16, 3, 32)
        )
    );
    assert_eq!(
        transcript_flowset(&run.frames[1], 0)
            .snapshot()
            .unwrap()
            .generation,
        1
    );
    assert_eq!(
        transcript_flowset(&run.frames[3], 0)
            .snapshot()
            .unwrap()
            .generation,
        2
    );
});

case!(low03_rejected_replacement_invalidates_later_data, {
    let fields = base(17);
    let messages = [
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS, &fields),
        transcript_install(
            TRANSCRIPT_EPOCH,
            42,
            TRANSCRIPT_SECONDS + 1,
            &rejected_transcript_template(),
        ),
        transcript_data(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 2, &fields),
    ];
    let run = transcript_twice(&messages, None);
    let parsed = run.frames[1].parser.as_ref().unwrap();
    match &parsed.flowsets[0].content {
        FlowSetContent::Templates { records, .. } => assert!(matches!(
            records[0].state,
            TemplateRecordState::Rejected {
                local_invalidation: Some(TemplateWithdrawal::Withdrawn { generation: 1 }),
                ..
            }
        )),
        _ => panic!("expected rejected template"),
    }
    assert!(run.frames[1].registry.is_empty());
    assert_eq!(
        transcript_flowset(&run.frames[2], 0).state,
        DataFlowSetState::SkippedUnknown
    );
    assert_eq!(transcript_output(&run.frames[2]).emitted, 0);
    assert!(run.quarantined.is_empty());
});

case!(low03_valid_reinstall_after_invalidation, {
    let fields = base(17);
    let messages = [
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS, &fields),
        transcript_install(
            TRANSCRIPT_EPOCH,
            42,
            TRANSCRIPT_SECONDS + 1,
            &rejected_transcript_template(),
        ),
        transcript_data(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 2, &fields),
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 3, &fields),
        transcript_data(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 4, &fields),
    ];
    let run = transcript_twice(&messages, None);
    assert_eq!(
        transcript_flowset(&run.frames[2], 0).state,
        DataFlowSetState::SkippedUnknown
    );
    let transition = transcript_transition(&run.frames[3]);
    assert_eq!(transition.kind, TemplateTransitionKind::Inserted);
    assert_eq!(transition.generation, 1);
    assert_transcript_flow(&run.frames[4], 5, 1);
});

case!(low03_reset_required_preserves_prefix_and_new_epoch, {
    let fields = base(17);
    let mut untrustworthy = template(256, &fields);
    untrustworthy[2..4].copy_from_slice(&u16::MAX.to_be_bytes()); // Extent cannot be trusted.
    let messages = [
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS, &fields),
        transcript_message(
            TRANSCRIPT_EPOCH,
            42,
            TRANSCRIPT_SECONDS + 1,
            vec![
                fs(256, &payload(&fields), true),
                fs(0, &untrustworthy, true),
                fs(256, &payload(&fields), true),
            ],
            3,
        ),
        transcript_install("transcript.epoch-2", 42, TRANSCRIPT_SECONDS + 2, &fields),
        transcript_data("transcript.epoch-2", 42, TRANSCRIPT_SECONDS + 3, &fields),
    ];
    let run = transcript_twice(&messages, None);
    let reset = transcript_output(&run.frames[1]);
    assert_eq!(reset.emitted, 1);
    assert_eq!(reset.completion, ParseCompletion::StoppedForReset);
    assert_eq!(reset.disposition, SessionDisposition::ResetRequired);
    assert_eq!(reset.count, CountValidation::Inconclusive);
    assert_eq!(
        transcript_flowset(&run.frames[1], 0).state,
        DataFlowSetState::Decoded
    );
    assert_eq!(
        transcript_flowset(&run.frames[1], 2).state,
        DataFlowSetState::Unprocessed
    );
    assert_eq!(run.quarantined, vec![messages[0].session.clone()]);
    assert_ne!(messages[2].session, messages[0].session);
    assert_eq!(transcript_transition(&run.frames[2]).generation, 1);
    assert_transcript_flow(&run.frames[3], 5, 1);
});

case!(low03_exact_ttl_expiry_unknown_then_reinsert, {
    let fields = base(17);
    let boundary = TRANSCRIPT_SECONDS + u32::try_from(DEFAULT_TEMPLATE_TTL_SECONDS).unwrap();
    let messages = [
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS, &fields),
        transcript_data(TRANSCRIPT_EPOCH, 42, boundary - 1, &fields),
        transcript_data(TRANSCRIPT_EPOCH, 42, boundary, &fields),
        transcript_data(TRANSCRIPT_EPOCH, 42, boundary + 1, &fields),
        transcript_install(TRANSCRIPT_EPOCH, 42, boundary + 2, &fields),
        transcript_data(TRANSCRIPT_EPOCH, 42, boundary + 3, &fields),
    ];
    let run = transcript_twice(&messages, None);
    assert_transcript_flow(&run.frames[1], 5, 1);
    assert_eq!(
        transcript_flowset(&run.frames[2], 0).state,
        DataFlowSetState::SkippedExpired
    );
    assert!(run.frames[2].registry.is_empty());
    assert_eq!(
        transcript_flowset(&run.frames[3], 0).state,
        DataFlowSetState::SkippedUnknown
    );
    assert_eq!(transcript_transition(&run.frames[4]).generation, 1);
    assert_transcript_flow(&run.frames[5], 5, 1);
});

fn transcript_sentinel(
    protocol: TemplateProtocol,
    epoch: &str,
    domain: u32,
) -> (TemplateKey, TemplateDefinition) {
    let key = TemplateKey::new(
        protocol,
        TransportSessionKey::new("exporter-a", epoch, 256).unwrap(),
        domain,
        256,
    )
    .unwrap();
    let fields = base(17)
        .iter()
        .map(|(id, value)| TemplateFieldSpecifier {
            field_id: *id,
            encoded_length: u16::try_from(value.len()).unwrap(),
            enterprise_number: None,
        })
        .collect::<Vec<_>>();
    (
        key,
        TemplateDefinition::new(TemplateKind::Data, 0, &fields, 256).unwrap(),
    )
}

fn assert_transcript_mutation_isolation(sentinel: (TemplateKey, TemplateDefinition)) {
    let fields = base(17);
    let original = transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 1, &fields);
    // 48 attempts include Count/sequence/Source ID, template ID/count and widths.
    // Domain 4242 differs in multiple bytes, so a one-byte mutation of domain 42
    // cannot legitimately retarget that sentinel's domain.
    let offsets = [2, 3, 12, 15, 16, 19, 24, 25, 26, 27, 30, 31, 34, 35, 46, 47];
    let mut attempts = 0;
    for offset in offsets {
        for replacement in [0, 255, original.bytes[offset] ^ 1] {
            let mut mutated = original.clone();
            mutated.bytes[offset] = replacement;
            let messages = [
                transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS, &fields),
                mutated,
            ];
            let result = std::panic::catch_unwind(|| {
                let run = transcript_twice(&messages, Some(&sentinel));
                let before = &run.frames[0].registry;
                let after = &run.frames[1].registry;
                let entry_before = before
                    .entries()
                    .find(|(key, _)| *key == &sentinel.0)
                    .unwrap()
                    .1;
                let entry_after = after
                    .entries()
                    .find(|(key, _)| *key == &sentinel.0)
                    .unwrap()
                    .1;
                assert_eq!(entry_before, entry_after);
                assert_eq!(
                    before.timeline_last_source_time_ns(sentinel.0.timeline()),
                    after.timeline_last_source_time_ns(sentinel.0.timeline())
                );
                assert!(after.len() <= 3);
                if let Ok(parsed) = &run.frames[1].parser {
                    assert_eq!(
                        transcript_output(&run.frames[1]).disposition,
                        parsed.session_disposition
                    );
                    assert_eq!(
                        !run.quarantined.is_empty(),
                        parsed.session_disposition == SessionDisposition::ResetRequired
                    );
                }
            });
            assert!(
                result.is_ok(),
                "isolation mutation offset={offset} replacement={replacement}"
            );
            attempts += 1;
        }
    }
    assert_eq!(attempts, 48);
}

case!(low03_cross_session_mutation_isolation, {
    assert_transcript_mutation_isolation(transcript_sentinel(
        TemplateProtocol::NetFlowV9,
        "transcript.session-b",
        42,
    ));
});
case!(low03_cross_source_id_mutation_isolation, {
    assert_transcript_mutation_isolation(transcript_sentinel(
        TemplateProtocol::NetFlowV9,
        TRANSCRIPT_EPOCH,
        4242,
    ));
});
case!(low03_cross_protocol_sentinel_isolation, {
    // Generic registry sentinel only: no IPFIX wire parser/normalizer is added.
    assert_transcript_mutation_isolation(transcript_sentinel(
        TemplateProtocol::Ipfix,
        TRANSCRIPT_EPOCH,
        42,
    ));
});
case!(low03_complete_transcript_replay_equality, {
    let fields = base(17);
    let messages = [
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS, &fields),
        transcript_data(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 1, &fields),
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 2, &fields),
        transcript_install(
            TRANSCRIPT_EPOCH,
            42,
            TRANSCRIPT_SECONDS + 3,
            &rejected_transcript_template(),
        ),
        transcript_data(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 4, &fields),
        transcript_install(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 5, &fields),
        transcript_data(TRANSCRIPT_EPOCH, 42, TRANSCRIPT_SECONDS + 6, &fields),
    ];
    let run = transcript_twice(&messages, None);
    assert_eq!(run.frames.len(), 7);
    assert_eq!(
        transcript_flowset(&run.frames[4], 0).state,
        DataFlowSetState::SkippedUnknown
    );
    assert_transcript_flow(&run.frames[6], 5, 1);
});

// LOW-04: exercise byte bounds without truncating or changing production policy.
fn low04_context(
    sensor: &str,
    hash: &str,
    observed: &str,
) -> Result<NetFlowV9SourceContext, NetFlowV9ContextError> {
    NetFlowV9SourceContext::new(
        sensor,
        InputMode::ExportFile,
        hash,
        observed,
        NetFlowV9ByteBasisProfile::Unknown,
    )
}

fn low04_context_output(src: &NetFlowV9SourceContext) -> CanonicalObservation {
    let bytes = wire(&base(17), 1, 10000, TRANSCRIPT_SECONDS);
    checked(&parse(&bytes), src, Default::default())
        .observations
        .remove(0)
}

case!(low04_sensor_255_bytes, {
    let sensor = "a".repeat(255);
    let src = low04_context(&sensor, HASH, OBSERVED).unwrap();
    assert_eq!(src.sensor_id(), sensor);
    assert_eq!(low04_context_output(&src).sensor_id, sensor);
});
case!(low04_sensor_256_bytes, {
    let sensor = "a".repeat(256);
    let src = low04_context(&sensor, HASH, OBSERVED).unwrap();
    assert_eq!(src.sensor_id().len(), 256);
    assert_eq!(low04_context_output(&src).sensor_id, sensor);
});
case!(low04_sensor_257_bytes_rejected, {
    assert_eq!(
        low04_context(&"a".repeat(257), HASH, OBSERVED)
            .unwrap_err()
            .field,
        "sensor_id"
    );
});
case!(low04_sensor_multibyte_byte_bound, {
    for sensor in [format!("{}a", "é".repeat(127)), "é".repeat(128)] {
        assert!(matches!(sensor.len(), 255 | 256));
        let src = low04_context(&sensor, HASH, OBSERVED).unwrap();
        assert_eq!(low04_context_output(&src).sensor_id, sensor);
    }
    let over = format!("{}a", "é".repeat(128));
    assert_eq!(over.len(), 257);
    assert_eq!(over.chars().count(), 129);
    assert_eq!(
        low04_context(&over, HASH, OBSERVED).unwrap_err().field,
        "sensor_id"
    );
});

case!(low04_capture_absent_and_short, {
    let src = low04_context("sensor", HASH, OBSERVED).unwrap();
    assert!(low04_context_output(&src)
        .provenance
        .capture_interface
        .is_none());
    let src = src.with_capture_interface("capture-a").unwrap();
    assert_eq!(
        low04_context_output(&src)
            .provenance
            .capture_interface
            .as_deref(),
        Some("capture-a")
    );
});
case!(low04_capture_exact_256_bytes, {
    let capture = "c".repeat(256);
    let src = low04_context("sensor", HASH, OBSERVED)
        .unwrap()
        .with_capture_interface(&capture)
        .unwrap();
    assert_eq!(
        low04_context_output(&src)
            .provenance
            .capture_interface
            .as_deref(),
        Some(capture.as_str())
    );
});
case!(low04_capture_257_bytes_rejected, {
    let error = low04_context("sensor", HASH, OBSERVED)
        .unwrap()
        .with_capture_interface(&"c".repeat(257))
        .unwrap_err();
    assert_eq!(error.field, "capture_interface");
    // Empty capture identity is already covered by context_capture_bounds.
});
case!(low04_capture_multibyte_byte_bound, {
    let exact = "é".repeat(128);
    assert_eq!(exact.len(), 256);
    let src = low04_context("sensor", HASH, OBSERVED)
        .unwrap()
        .with_capture_interface(&exact)
        .unwrap();
    assert_eq!(
        low04_context_output(&src)
            .provenance
            .capture_interface
            .as_deref(),
        Some(exact.as_str())
    );
    let over = format!("{exact}a");
    assert_eq!(over.len(), 257);
    assert_eq!(
        low04_context("sensor", HASH, OBSERVED)
            .unwrap()
            .with_capture_interface(&over)
            .unwrap_err()
            .field,
        "capture_interface"
    );
});

case!(low04_observed_at_short_valid, {
    let src = low04_context("sensor", HASH, OBSERVED).unwrap();
    assert_eq!(src.observed_at(), OBSERVED);
    assert_eq!(low04_context_output(&src).observed_at, OBSERVED);
});
case!(low04_observed_at_valid_64_bytes, {
    // RFC3339 fractional digits are retained, not re-emitted from chrono's
    // nanosecond value. The existing parser accepts 43 zero fractional digits.
    let observed = format!("2026-10-03T00:00:00.{}Z", "0".repeat(43));
    assert_eq!(observed.len(), 64);
    let src = low04_context("sensor", HASH, &observed).unwrap();
    assert_eq!(src.observed_at(), observed);
    assert_eq!(low04_context_output(&src).observed_at, observed);
});
case!(low04_observed_at_65_bytes_rejected, {
    let observed = format!("2026-10-03T00:00:00.{}Z", "0".repeat(44));
    assert_eq!(observed.len(), 65);
    // The otherwise-valid grammar is rejected by the defensive context bound.
    assert_eq!(
        low04_context("sensor", HASH, &observed).unwrap_err().field,
        "observed_at"
    );
});
case!(low04_observed_at_missing_z_rejected, {
    assert_eq!(
        low04_context("sensor", HASH, "2026-10-03T00:00:00")
            .unwrap_err()
            .field,
        "observed_at"
    );
    // Existing invalid-calendar and non-Z-offset tests remain unchanged.
});

case!(low04_input_sha_63_rejected, {
    assert_eq!(
        low04_context("sensor", &"a".repeat(63), OBSERVED)
            .unwrap_err()
            .field,
        "input_sha256"
    );
});
case!(low04_input_sha_64_and_uppercase_normalized, {
    assert_eq!(HASH.len(), 64);
    let lower = low04_context("sensor", HASH, OBSERVED).unwrap();
    let upper = low04_context("sensor", &HASH.to_ascii_uppercase(), OBSERVED).unwrap();
    assert_eq!(upper.input_sha256(), HASH);
    assert_eq!(upper, lower);
    assert_eq!(
        low04_context_output(&upper)
            .provenance
            .input_sha256
            .as_deref(),
        Some(HASH)
    );
});
case!(low04_input_sha_65_rejected, {
    assert_eq!(
        low04_context("sensor", &"a".repeat(65), OBSERVED)
            .unwrap_err()
            .field,
        "input_sha256"
    );
});
case!(low04_input_sha_nonhex_64_rejected, {
    let mut hash = "a".repeat(64);
    hash.replace_range(31..32, "g");
    assert_eq!(hash.len(), 64);
    assert_eq!(
        low04_context("sensor", &hash, OBSERVED).unwrap_err().field,
        "input_sha256"
    );
});

fn low04_expected_fingerprint(exporter: &str, session: &str) -> String {
    let mut digest = Sha256::new();
    for value in ["co-netflow-v9-session-v1", exporter, session] {
        digest.update(u32::try_from(value.len()).unwrap().to_be_bytes());
        digest.update(value.as_bytes());
    }
    format!("{digest:x}", digest = digest.finalize())
}

fn low04_expected_source_id(c: &NetFlowV9IdentityCoordinates<'_>) -> String {
    format!(
        "netflow_v9/{}/{}/{}/{}/{}/{}/{}",
        c.exporter_id,
        low04_expected_fingerprint(c.exporter_id, c.session_id),
        c.source_id,
        c.sequence_number,
        c.datagram_ordinal,
        c.flowset_ordinal,
        c.record_ordinal
    )
}

fn low04_expected_uuid(c: &NetFlowV9IdentityCoordinates<'_>) -> String {
    // Independent assembly of the frozen name, not production-generated truth.
    let namespace = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        b"https://utsavagg2007.github.io/SIH-2026/contracts/co-netflow-v9-id-v1",
    );
    let components = [
        "co-netflow-v9-id-v1".to_string(),
        c.sensor_id.into(),
        c.input_sha256.to_ascii_lowercase(),
        c.exporter_id.into(),
        c.session_id.into(),
        c.source_id.to_string(),
        c.sequence_number.to_string(),
        c.datagram_ordinal.to_string(),
        c.flowset_ordinal.to_string(),
        c.record_ordinal.to_string(),
    ];
    let mut name = Vec::new();
    for component in components {
        name.extend(u32::try_from(component.len()).unwrap().to_be_bytes());
        name.extend(component.as_bytes());
    }
    uuid::Uuid::new_v5(&namespace, &name).to_string()
}

fn low04_assert_identity(observation: &CanonicalObservation, c: &NetFlowV9IdentityCoordinates<'_>) {
    assert_eq!(observation.record_id, low04_expected_uuid(c));
    let actual = observation.source_record_id.as_ref().unwrap();
    assert_eq!(actual, &low04_expected_source_id(c));
    assert!(actual.len() <= MAX_SOURCE_RECORD_ID_BYTES);
    assert!(!actual.contains(c.session_id));
    // All five numeric components round-trip as unsigned, unpadded decimal.
    for component in actual.rsplit('/').take(5) {
        assert_eq!(component.parse::<u64>().unwrap().to_string(), component);
    }
    assert_eq!(
        generate_netflow_v9_session_fingerprint(c.exporter_id, c.session_id).unwrap(),
        low04_expected_fingerprint(c.exporter_id, c.session_id)
    );
}

fn low04_minimal_fields() -> Vec<Field> {
    let mut fields = base(17);
    set(&mut fields, 2, 5, 1);
    assert_eq!(payload(&fields).len(), 18);
    fields
}

fn low04_seeded_registry(
    session: &TransportSessionKey,
    domain: u32,
    fields: &[Field],
) -> TemplateRegistry {
    let mut registry = TemplateRegistry::new(Default::default());
    let key = TemplateKey::new(TemplateProtocol::NetFlowV9, session.clone(), domain, 256).unwrap();
    let definition = TemplateDefinition::new(
        TemplateKind::Data,
        0,
        &fields
            .iter()
            .map(|(id, value)| TemplateFieldSpecifier {
                field_id: *id,
                encoded_length: u16::try_from(value.len()).unwrap(),
                enterprise_number: None,
            })
            .collect::<Vec<_>>(),
        256,
    )
    .unwrap();
    registry
        .insert(
            key,
            definition,
            u64::from(TRANSCRIPT_SECONDS) * 1_000_000_000,
        )
        .unwrap();
    registry
}

case!(low04_combined_reachable_maximum_source_record_id, {
    let exporter = "e".repeat(256);
    let session_id = "s".repeat(256);
    let sensor = "é".repeat(128);
    let session = TransportSessionKey::new(&exporter, &session_id, 256).unwrap();
    let fields = low04_minimal_fields();
    let parser_config = NetFlowV9ParserConfig::default();
    let max_flowset = parser_config.max_flowsets_per_datagram() - 1;
    // Maximize both physical coordinates under the unchanged default envelope.
    // Prior template installation is represented by a valid seeded F5 entry.
    let record_budget = parser_config.max_datagram_bytes()
        - NETFLOW_V9_HEADER_LEN
        - parser_config.max_flowsets_per_datagram() * 4;
    let repeats = record_budget / payload(&fields).len();
    assert_eq!((max_flowset, repeats), (1023, 3412));
    let mut sets = vec![fs(2, &[], false); max_flowset];
    sets.push(fs(256, &payload(&fields).repeat(repeats), true));
    let mut bytes = packet(
        &sets,
        u16::try_from(repeats).unwrap(),
        10000,
        TRANSCRIPT_SECONDS,
    );
    bytes[12..20].fill(255); // sequence and Source ID are both u32::MAX.
    assert_eq!(bytes.len(), 65532);
    assert!(bytes.len() <= parser_config.max_datagram_bytes());
    let parsed = parse_netflow_v9(
        &bytes,
        NetFlowV9ParseContext {
            session: session.clone(),
            datagram_ordinal: u64::MAX,
        },
        &mut low04_seeded_registry(&session, u32::MAX, &fields),
        parser_config,
    )
    .unwrap();
    let src = low04_context(&sensor, HASH, OBSERVED).unwrap();
    let result = checked(&parsed, &src, Default::default());
    assert_eq!(result.emitted, repeats);
    assert_eq!(result.disposition, SessionDisposition::Continue);
    assert_eq!(result.count, CountValidation::Inconclusive); // Reserved FlowSets, not reset.
    let c = NetFlowV9IdentityCoordinates {
        sensor_id: &sensor,
        input_sha256: HASH,
        exporter_id: &exporter,
        session_id: &session_id,
        source_id: u32::MAX,
        sequence_number: u32::MAX,
        datagram_ordinal: u64::MAX,
        flowset_ordinal: u32::try_from(max_flowset).unwrap(),
        record_ordinal: u32::try_from(repeats - 1).unwrap(),
    };
    let observation = result.observations.last().unwrap();
    low04_assert_identity(observation, &c);
    assert_eq!(observation.sensor_id, sensor);
    assert_eq!(observation.source_record_id.as_ref().unwrap().len(), 385);
    assert_eq!(
        (
            result.audit.last().unwrap().flowset_ordinal,
            result.audit.last().unwrap().record_ordinal
        ),
        (1023, 3411)
    );
    // F5 already directly tests exact 256-byte exporter/session acceptance and
    // individual 257-byte rejection; do not duplicate those constructor tests.
});

case!(low04_maximum_practical_record_ordinal, {
    let fields = low04_minimal_fields();
    let session = context().session;
    let cfg = NetFlowV9ParserConfig::default();
    let repeats = (cfg.max_datagram_bytes() - NETFLOW_V9_HEADER_LEN - 4) / payload(&fields).len();
    assert_eq!(repeats, 3639);
    let bytes = packet(
        &[fs(256, &payload(&fields).repeat(repeats), true)],
        u16::try_from(repeats).unwrap(),
        10000,
        TRANSCRIPT_SECONDS,
    );
    assert!(bytes.len() <= cfg.max_datagram_bytes());
    // One more minimum-width eligible record cannot fit the default datagram.
    assert!(NETFLOW_V9_HEADER_LEN + 4 + (repeats + 1) * 18 > cfg.max_datagram_bytes());
    let parsed = parse_netflow_v9(
        &bytes,
        context(),
        &mut low04_seeded_registry(&session, 42, &fields),
        cfg,
    )
    .unwrap();
    let result = checked(
        &parsed,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    assert_eq!(result.emitted, repeats);
    let c = NetFlowV9IdentityCoordinates {
        flowset_ordinal: 0,
        record_ordinal: 3638,
        ..coords()
    };
    low04_assert_identity(result.observations.last().unwrap(), &c);
});

case!(low04_all_zero_numeric_coordinates, {
    let fields = low04_minimal_fields();
    let mut bytes = packet(
        &[fs(256, &payload(&fields), true)],
        1,
        10000,
        TRANSCRIPT_SECONDS,
    );
    bytes[12..20].fill(0);
    let parsed = parse_netflow_v9(
        &bytes,
        context(),
        &mut low04_seeded_registry(&context().session, 0, &fields),
        Default::default(),
    )
    .unwrap();
    let result = checked(
        &parsed,
        &source(NetFlowV9ByteBasisProfile::Unknown),
        Default::default(),
    );
    let c = NetFlowV9IdentityCoordinates {
        source_id: 0,
        sequence_number: 0,
        datagram_ordinal: 0,
        flowset_ordinal: 0,
        record_ordinal: 0,
        ..coords()
    };
    low04_assert_identity(&result.observations[0], &c);
    assert!(result.observations[0]
        .source_record_id
        .as_ref()
        .unwrap()
        .ends_with("/0/0/0/0/0"));
});

case!(low04_source_record_id_397_byte_defensive_type_bound, {
    let exporter = "e".repeat(256);
    let session = "s".repeat(256);
    let sensor = "é".repeat(128);
    let c = NetFlowV9IdentityCoordinates {
        sensor_id: &sensor,
        input_sha256: HASH,
        exporter_id: &exporter,
        session_id: &session,
        source_id: u32::MAX,
        sequence_number: u32::MAX,
        datagram_ordinal: u64::MAX,
        flowset_ordinal: u32::MAX,
        record_ordinal: u32::MAX,
    };
    assert_eq!(
        generate_netflow_v9_record_id(&c).unwrap(),
        low04_expected_uuid(&c)
    );
    assert_eq!(
        generate_netflow_v9_session_fingerprint(&exporter, &session).unwrap(),
        low04_expected_fingerprint(&exporter, &session)
    );
    let upper_bound = low04_expected_source_id(&c);
    assert_eq!(upper_bound.len(), 397);
    assert_eq!(
        upper_bound.len(),
        "netflow_v9".len() + 7 + 256 + 64 + 10 + 10 + 20 + 10 + 10
    );
    assert!(upper_bound.len() <= MAX_SOURCE_RECORD_ID_BYTES);
    assert!(!upper_bound.contains(&session));
    // 397 is the conservative numeric-type ceiling, NOT an emitted record at
    // impossible physical u32::MAX indices. The actual default-envelope case
    // above emits 385 bytes. All valid upstream identity/coordinate combinations
    // remain below 512, so that error branch is currently defensive/unreachable.
    // Keep the production guard in case supported profile bounds expand later.
});
