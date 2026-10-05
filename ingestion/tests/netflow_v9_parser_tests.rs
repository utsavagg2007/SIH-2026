use ingestion_core::netflow::template::*;
use ingestion_core::netflow::v9::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn context() -> NetFlowV9ParseContext {
    NetFlowV9ParseContext {
        session: TransportSessionKey::new("sensor-exporter", "collector-udp-epoch1", 256).unwrap(),
        datagram_ordinal: 777,
    }
}
fn registry() -> TemplateRegistry {
    TemplateRegistry::new(TemplateRegistryConfig::default())
}
fn fs(id: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = id.to_be_bytes().to_vec();
    bytes.extend(u16::try_from(payload.len() + 4).unwrap().to_be_bytes());
    bytes.extend(payload);
    bytes
}
fn template(id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
    let mut bytes = id.to_be_bytes().to_vec();
    bytes.extend(u16::try_from(fields.len()).unwrap().to_be_bytes());
    for (id, width) in fields {
        bytes.extend(id.to_be_bytes());
        bytes.extend(width.to_be_bytes());
    }
    bytes
}
fn options(id: u16, scopes: &[(u16, u16)], fields: &[(u16, u16)]) -> Vec<u8> {
    let mut bytes = id.to_be_bytes().to_vec();
    bytes.extend(u16::try_from(scopes.len() * 4).unwrap().to_be_bytes());
    bytes.extend(u16::try_from(fields.len() * 4).unwrap().to_be_bytes());
    for (id, width) in scopes.iter().chain(fields) {
        bytes.extend(id.to_be_bytes());
        bytes.extend(width.to_be_bytes());
    }
    bytes
}
fn packet(count: u16, flowsets: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(9_u16.to_be_bytes());
    bytes.extend(count.to_be_bytes());
    for value in [9000_u32, 100, 123, 42] {
        bytes.extend(value.to_be_bytes());
    }
    for flowset in flowsets {
        bytes.extend(flowset);
    }
    bytes
}
fn set32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn key(id: u16) -> TemplateKey {
    TemplateKey::new(TemplateProtocol::NetFlowV9, context().session, 42, id).unwrap()
}
fn run(bytes: &[u8]) -> NetFlowV9ParseOutcome<'_> {
    parse_netflow_v9(
        bytes,
        context(),
        &mut registry(),
        NetFlowV9ParserConfig::default(),
    )
    .unwrap()
}
fn with_registry<'a>(bytes: &'a [u8], r: &mut TemplateRegistry) -> NetFlowV9ParseOutcome<'a> {
    parse_netflow_v9(bytes, context(), r, NetFlowV9ParserConfig::default()).unwrap()
}
fn data<'a, 'b>(out: &'b NetFlowV9ParseOutcome<'a>, index: usize) -> &'b DataFlowSetOutcome<'a> {
    match &out.flowsets[index].content {
        FlowSetContent::Data(d) => d,
        _ => panic!("expected data"),
    }
}
fn records<'a, 'b>(
    out: &'b NetFlowV9ParseOutcome<'a>,
    index: usize,
) -> &'b [TemplateRecordOutcome<'a>] {
    match &out.flowsets[index].content {
        FlowSetContent::Templates { records, .. } => records,
        _ => panic!("expected templates"),
    }
}
fn cfg(
    flowsets: usize,
    template_fs: usize,
    template_total: usize,
    data_fs: usize,
    data_total: usize,
    diagnostics: usize,
) -> NetFlowV9ParserConfig {
    NetFlowV9ParserConfig::new(
        65535,
        flowsets,
        template_fs,
        template_total,
        data_fs,
        data_total,
        diagnostics,
    )
    .unwrap()
}
fn simple(width: u16, payload: &[u8], count: u16) -> Vec<u8> {
    packet(
        count,
        &[fs(0, &template(256, &[(1, width)])), fs(256, payload)],
    )
}
fn has(out: &NetFlowV9ParseOutcome<'_>, kind: NetFlowV9DiagnosticKind) -> bool {
    out.diagnostics.iter().any(|d| d.kind == kind)
}
fn rejected(out: &NetFlowV9ParseOutcome<'_>) {
    assert!(matches!(
        records(out, 0)[0].state,
        TemplateRecordState::Rejected { .. }
    ));
    assert_eq!(out.count_validation, CountValidation::Inconclusive);
}
macro_rules! case { ($name:ident, $body:block) => { #[test] fn $name() $body }; }

case!(header_minimal_framing, {
    let p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
    let out = run(&p);
    assert_eq!(out.count_validation, CountValidation::Match);
    assert_eq!(out.flowsets.len(), 1);
});
case!(header_unsupported_version, {
    let mut p = packet(0, &[]);
    p[..2].copy_from_slice(&10_u16.to_be_bytes());
    assert!(matches!(
        parse_netflow_v9_wire(&p, Default::default()),
        Err(NetFlowV9ParseError::UnsupportedVersion { version: 10 })
    ));
});
case!(header_every_truncation, {
    let p = packet(0, &[]);
    for n in 0..20 {
        assert_eq!(
            parse_netflow_v9_wire(&p[..n], Default::default()),
            Err(NetFlowV9ParseError::TruncatedHeader { available: n })
        );
    }
});
case!(header_source_zero, {
    let mut p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
    set32(&mut p, 16, 0);
    let mut r = registry();
    let out = with_registry(&p, &mut r);
    assert_eq!(out.header.source_id, 0);
    assert_eq!(r.entries().next().unwrap().0.observation_scope_id(), 0);
});
case!(header_source_max, {
    let mut p = packet(0, &[fs(2, &[])]);
    set32(&mut p, 16, u32::MAX);
    assert_eq!(run(&p).header.source_id, u32::MAX);
});
case!(header_sequence_zero, {
    let mut p = packet(0, &[fs(2, &[])]);
    set32(&mut p, 12, 0);
    assert_eq!(run(&p).header.sequence_number, 0);
});
case!(header_sequence_max, {
    let mut p = packet(0, &[fs(2, &[])]);
    set32(&mut p, 12, u32::MAX);
    assert_eq!(run(&p).header.sequence_number, u32::MAX);
});
case!(header_uptime_zero_and_max, {
    for value in [0, u32::MAX] {
        let mut p = packet(0, &[fs(2, &[])]);
        set32(&mut p, 4, value);
        assert_eq!(run(&p).header.sys_uptime_ms, value);
    }
});
case!(header_unix_max_checked_integer_conversion, {
    let mut p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
    set32(&mut p, 8, u32::MAX);
    let out = run(&p);
    assert_eq!(out.source_time_ns, u64::from(u32::MAX) * 1_000_000_000);
});

case!(template_ordinary, {
    let p = simple(4, &[1, 2, 3, 4], 2);
    let out = run(&p);
    assert!(matches!(
        records(&out, 0)[0].state,
        TemplateRecordState::Applied(_)
    ));
    assert_eq!(out.count_validation, CountValidation::Match);
});
case!(template_multiple_records, {
    let mut t = template(256, &[(1, 2)]);
    t.extend(template(300, &[(2, 3)]));
    let p = packet(2, &[fs(0, &t)]);
    let out = run(&p);
    assert_eq!(records(&out, 0).len(), 2);
    assert_eq!(out.count_validation, CountValidation::Match);
});
case!(template_255_rejected_reset, {
    let p = packet(1, &[fs(0, &template(255, &[(1, 1)]))]);
    let out = run(&p);
    rejected(&out);
    assert_eq!(out.session_disposition, SessionDisposition::ResetRequired);
});
case!(template_256_accepted, {
    let p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
    assert_eq!(run(&p).count_validation, CountValidation::Match);
});
case!(template_65535_accepted, {
    let p = packet(1, &[fs(0, &template(65535, &[(1, 1)]))]);
    let mut r = registry();
    with_registry(&p, &mut r);
    assert_eq!(r.entries().next().unwrap().0.template_id(), 65535);
});
case!(template_zero_fields_not_wire_withdrawal, {
    let p = packet(1, &[fs(0, &template(256, &[]))]);
    let out = run(&p);
    rejected(&out);
    assert!(matches!(
        records(&out, 0)[0].state,
        TemplateRecordState::Rejected {
            reason: NetFlowV9DiagnosticKind::InvalidTemplateFieldCount,
            local_invalidation: Some(TemplateWithdrawal::Unknown)
        }
    ));
});
case!(template_field_bound_exact, {
    let p = packet(1, &[fs(0, &template(256, &[(1, 1); 256]))]);
    let out = run(&p);
    assert_eq!(records(&out, 0)[0].descriptors().count(), 256);
    assert_eq!(out.count_validation, CountValidation::Match);
});
case!(template_field_bound_one_over, {
    let p = packet(1, &[fs(0, &template(256, &[(1, 1); 257]))]);
    let mut r = registry();
    rejected(&with_registry(&p, &mut r));
    assert!(r.is_empty());
});
case!(template_configured_field_bound, {
    let mut r = TemplateRegistry::new(TemplateRegistryConfig::new(8, 2, 256).unwrap());
    let p = packet(1, &[fs(0, &template(256, &[(1, 1); 3]))]);
    rejected(&with_registry(&p, &mut r));
    assert!(r.is_empty());
});
case!(template_duplicate_ids_preserved, {
    let p = simple_multi(&[(8, 1), (8, 2)], &[1, 2, 3]);
    let out = run(&p);
    let values: Vec<_> = data(&out, 1).records().next().unwrap().fields().collect();
    assert_eq!(
        values
            .iter()
            .map(|v| v.specifier.field_id)
            .collect::<Vec<_>>(),
        [8, 8]
    );
    assert_eq!(values[1].bytes, [2, 3]);
});
fn simple_multi(fields: &[(u16, u16)], payload: &[u8]) -> Vec<u8> {
    packet(2, &[fs(0, &template(256, fields)), fs(256, payload)])
}
case!(template_unknown_id_preserved, {
    let p = simple_multi(&[(999, 1)], &[7]);
    let out = run(&p);
    assert_eq!(
        data(&out, 1)
            .records()
            .next()
            .unwrap()
            .fields()
            .next()
            .unwrap()
            .specifier
            .field_id,
        999
    );
});
case!(template_high_bit_not_enterprise_flag, {
    let p = simple_multi(&[(0x8008, 1)], &[7]);
    let out = run(&p);
    let field = data(&out, 1)
        .records()
        .next()
        .unwrap()
        .fields()
        .next()
        .unwrap();
    assert_eq!(field.specifier.field_id, 0x8008);
    assert_eq!(field.specifier.enterprise_number, None);
});
case!(template_zero_width_preserved_but_unsupported, {
    let p = packet(1, &[fs(0, &template(256, &[(1, 0), (2, 4)]))]);
    let out = run(&p);
    rejected(&out);
    assert_eq!(
        records(&out, 0)[0]
            .descriptors()
            .next()
            .unwrap()
            .encoded_length,
        0
    );
    assert!(has(
        &out,
        NetFlowV9DiagnosticKind::UnsupportedTemplateLayout
    ));
});
case!(template_literal_65535_not_variable_prefix, {
    let p = packet(1, &[fs(0, &template(256, &[(1, 65535)]))]);
    let out = run(&p);
    rejected(&out);
    assert_eq!(
        records(&out, 0)[0]
            .descriptors()
            .next()
            .unwrap()
            .encoded_length,
        65535
    );
});
case!(template_maximum_useful_width, {
    let p = simple(65531, &vec![1; 65531], 2);
    let config = NetFlowV9ParserConfig::new(70000, 10, 10, 10, 10, 10, 10).unwrap();
    let out = parse_netflow_v9(&p, context(), &mut registry(), config).unwrap();
    assert_eq!(data(&out, 1).record_count, 1);
});
case!(template_width_sum_over_legal_flowset, {
    let p = packet(1, &[fs(0, &template(256, &[(1, 40000), (2, 30000)]))]);
    rejected(&run(&p));
});

fn options_packet(scopes: &[(u16, u16)], fields: &[(u16, u16)], payload: &[u8]) -> Vec<u8> {
    packet(2, &[fs(1, &options(256, scopes, fields)), fs(256, payload)])
}
case!(options_positive_scope, {
    let p = options_packet(&[(1, 2)], &[(48, 1)], &[1, 2, 3]);
    let out = run(&p);
    assert_eq!(records(&out, 0)[0].scope_field_count, 1);
    assert_eq!(
        data(&out, 1).snapshot().unwrap().definition().kind(),
        TemplateKind::Options
    );
});
case!(options_zero_scope_supported, {
    let p = options_packet(&[], &[(50, 1)], &[3]);
    let out = run(&p);
    assert_eq!(
        data(&out, 1)
            .snapshot()
            .unwrap()
            .definition()
            .scope_field_count(),
        0
    );
    assert_eq!(out.count_validation, CountValidation::Match);
});
case!(options_zero_option_supported, {
    let p = options_packet(&[(1, 2)], &[], &[1, 2]);
    assert_eq!(run(&p).count_validation, CountValidation::Match);
});
case!(options_both_zero_rejected, {
    let p = packet(1, &[fs(1, &options(256, &[], &[]))]);
    rejected(&run(&p));
});
fn malformed_option(scope: u16, option: u16) -> Vec<u8> {
    let mut t = 256_u16.to_be_bytes().to_vec();
    t.extend(scope.to_be_bytes());
    t.extend(option.to_be_bytes());
    t.extend(vec![0; usize::from(scope) + usize::from(option)]);
    t
}
case!(options_scope_byte_length_mod_four, {
    let p = packet(1, &[fs(1, &malformed_option(3, 4))]);
    let out = run(&p);
    rejected(&out);
    assert!(has(
        &out,
        NetFlowV9DiagnosticKind::MalformedOptionsTemplateLengths
    ));
    assert_eq!(out.session_disposition, SessionDisposition::Continue);
});
case!(options_option_byte_length_mod_four, {
    let p = packet(1, &[fs(1, &malformed_option(4, 3))]);
    rejected(&run(&p));
});
case!(options_multiple_records, {
    let mut t = options(256, &[], &[(50, 1)]);
    t.extend(options(257, &[(1, 2)], &[]));
    let p = packet(2, &[fs(1, &t)]);
    let out = run(&p);
    assert_eq!(records(&out, 0).len(), 2);
    assert_eq!(out.count_validation, CountValidation::Match);
});
case!(options_scope_roles, {
    let p = options_packet(&[(1, 2), (2, 1)], &[(50, 1)], &[1, 2, 3, 4]);
    let out = run(&p);
    let roles: Vec<_> = data(&out, 1)
        .records()
        .next()
        .unwrap()
        .fields()
        .map(|f| f.role)
        .collect();
    assert_eq!(
        roles,
        [FieldRole::Scope, FieldRole::Scope, FieldRole::Option]
    );
});
case!(options_option_roles, {
    let p = options_packet(&[], &[(1, 1), (1, 1)], &[5, 6]);
    let out = run(&p);
    assert!(data(&out, 1)
        .records()
        .next()
        .unwrap()
        .fields()
        .all(|f| f.role == FieldRole::Option));
});
case!(options_byte_lengths_widen_without_u16_overflow, {
    let mut t = 256_u16.to_be_bytes().to_vec();
    t.extend(65532_u16.to_be_bytes());
    t.extend(65532_u16.to_be_bytes());
    let p = packet(1, &[fs(1, &t)]);
    let out = run(&p);
    assert_eq!(out.completion, ParseCompletion::StoppedForReset);
    assert_eq!(records(&out, 0)[0].field_count, 32766);
});

case!(data_known_template, {
    let p = simple(2, &[1, 2], 2);
    let out = run(&p);
    assert_eq!(data(&out, 1).state, DataFlowSetState::Decoded);
    assert_eq!(data(&out, 1).records().next().unwrap().bytes(), [1, 2]);
});
case!(data_multiple_records, {
    let p = simple(2, &[1, 2, 3, 4, 5, 6], 4);
    let out = run(&p);
    assert_eq!(
        data(&out, 1)
            .records()
            .map(|r| r.record_ordinal)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
});
case!(data_unknown_template, {
    let p = packet(1, &[fs(256, &[1, 2])]);
    let out = run(&p);
    assert_eq!(data(&out, 0).state, DataFlowSetState::SkippedUnknown);
    assert!(data(&out, 0).snapshot().is_none());
});
fn expiry_test(delta_secs: u32) -> (DataFlowSetState, usize) {
    let mut r = TemplateRegistry::new(
        TemplateRegistryConfig::default()
            .with_ttl_ns(2_000_000_000)
            .unwrap(),
    );
    let p = packet(1, &[fs(0, &template(256, &[(1, 2)]))]);
    with_registry(&p, &mut r);
    let mut p = packet(1, &[fs(256, &[1, 2])]);
    set32(&mut p, 8, 100 + delta_secs);
    let out = with_registry(&p, &mut r);
    (data(&out, 0).state, r.len())
}
case!(data_expired_template, {
    assert_eq!(expiry_test(3), (DataFlowSetState::SkippedExpired, 0));
});
case!(data_options_record, {
    let p = options_packet(&[(1, 1)], &[(48, 1)], &[8, 9]);
    let out = run(&p);
    assert_eq!(data(&out, 1).record_count, 1);
});
case!(data_complete_all_zero_record_retained, {
    let p = simple(2, &[0, 0, 0, 0], 3);
    let out = run(&p);
    assert_eq!(data(&out, 1).record_count, 2);
    assert_eq!(data(&out, 1).padding.len(), 0);
});
fn padding_case(n: usize) {
    let mut payload = vec![1; 5];
    payload.extend(vec![0; n]);
    let p = simple(5, &payload, 2);
    let out = run(&p);
    assert_eq!(data(&out, 1).record_count, 1);
    assert_eq!(data(&out, 1).padding, vec![0; n]);
    assert_eq!(out.count_validation, CountValidation::Match);
}
case!(padding_zero_bytes, {
    padding_case(0);
});
case!(padding_one_zero, {
    padding_case(1);
});
case!(padding_two_zeros, {
    padding_case(2);
});
case!(padding_three_zeros, {
    padding_case(3);
});
case!(padding_nonzero_rejects_entire_output, {
    let p = simple(5, &[1, 2, 3, 4, 5, 1], 2);
    let out = run(&p);
    assert_eq!(data(&out, 1).state, DataFlowSetState::Rejected);
    assert_eq!(data(&out, 1).records().count(), 0);
});
case!(padding_above_three_rejected, {
    let p = simple(5, &[1, 2, 3, 4, 5, 0, 0, 0, 0], 2);
    assert_eq!(data(&run(&p), 1).state, DataFlowSetState::Rejected);
});
case!(
    padding_at_least_record_length_is_never_stripped_count_flags_intent_mismatch,
    {
        let p = simple(2, &[1, 2, 0, 0], 2);
        let out = run(&p);
        assert_eq!(data(&out, 1).record_count, 2);
        assert_eq!(
            out.count_validation,
            CountValidation::Mismatch {
                declared: 2,
                parsed: 3
            }
        );
    }
);
case!(padding_complete_zero_record_can_legitimately_match_count, {
    let p = simple(2, &[1, 2, 0, 0], 3);
    assert_eq!(run(&p).count_validation, CountValidation::Match);
});
case!(data_zero_progress_impossible, {
    let p = packet(1, &[fs(0, &template(256, &[(1, 0)])), fs(256, &[0; 100])]);
    let out = run(&p);
    assert_eq!(data(&out, 1).state, DataFlowSetState::SkippedUnknown);
});
case!(
    data_empty_payload_rejected_not_fabricated_as_valid_zero_records,
    {
        let p = simple(4, &[], 1);
        let out = run(&p);
        assert_eq!(data(&out, 1).record_count, 0);
        assert_eq!(out.count_validation, CountValidation::Inconclusive);
        assert_eq!(data(&out, 1).state, DataFlowSetState::Rejected);
    }
);
case!(data_borrowed_exact_input_slice, {
    let p = simple_multi(&[(1, 1), (2, 2)], &[7, 8, 9]);
    let out = run(&p);
    let rec = data(&out, 1).records().next().unwrap();
    let values: Vec<_> = rec.fields().collect();
    assert_eq!(values[0].bytes.as_ptr(), p[rec.byte_offset..].as_ptr());
    assert_eq!(values[1].bytes.as_ptr(), p[rec.byte_offset + 1..].as_ptr());
});

case!(order_template_then_data, {
    let p = simple(1, &[7], 2);
    assert_eq!(data(&run(&p), 1).state, DataFlowSetState::Decoded);
});
case!(order_data_then_template_no_retroactive_decode, {
    let p = packet(
        2,
        &[
            fs(256, &[7]),
            fs(0, &template(256, &[(1, 1)])),
            fs(256, &[8]),
        ],
    );
    let out = run(&p);
    assert_eq!(data(&out, 0).state, DataFlowSetState::SkippedUnknown);
    assert_eq!(data(&out, 2).state, DataFlowSetState::Decoded);
});
fn redefinition_packet() -> Vec<u8> {
    packet(
        4,
        &[
            fs(0, &template(256, &[(1, 2)])),
            fs(256, &[1, 2]),
            fs(0, &template(256, &[(2, 1)])),
            fs(256, &[3]),
        ],
    )
}
case!(order_a_data_b_data, {
    let p = redefinition_packet();
    let out = run(&p);
    assert_eq!(data(&out, 1).snapshot().unwrap().record_length(), 2);
    assert_eq!(data(&out, 3).snapshot().unwrap().record_length(), 1);
});
case!(order_identical_refresh_generation_stable, {
    let t = fs(0, &template(256, &[(1, 2)]));
    let p = packet(2, &[t.clone(), t]);
    let out = run(&p);
    assert!(matches!(
        records(&out, 1)[0].state,
        TemplateRecordState::Applied(TemplateTransition {
            kind: TemplateTransitionKind::Refreshed,
            generation: 1,
            ..
        })
    ));
});
case!(order_changed_definition_increments_generation, {
    let p = redefinition_packet();
    let out = run(&p);
    assert_eq!(data(&out, 1).snapshot().unwrap().generation, 1);
    assert_eq!(data(&out, 3).snapshot().unwrap().generation, 2);
});
case!(order_snapshot_survives_registry_replacement, {
    let p = redefinition_packet();
    let mut r = registry();
    let out = with_registry(&p, &mut r);
    r.withdraw(&key(256), 100_000_000_000).unwrap();
    assert_eq!(
        data(&out, 1)
            .records()
            .next()
            .unwrap()
            .fields()
            .next()
            .unwrap()
            .specifier
            .field_id,
        1
    );
    assert_eq!(
        data(&out, 3)
            .records()
            .next()
            .unwrap()
            .fields()
            .next()
            .unwrap()
            .specifier
            .field_id,
        2
    );
});
case!(order_two_definitions_within_same_flowset, {
    let mut t = template(256, &[(1, 2)]);
    t.extend(template(256, &[(2, 1)]));
    let p = packet(3, &[fs(0, &t), fs(256, &[4])]);
    assert_eq!(data(&run(&p), 1).snapshot().unwrap().generation, 2);
});

case!(isolation_cross_session, {
    let mut r = registry();
    let p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
    with_registry(&p, &mut r);
    let p = packet(1, &[fs(256, &[7])]);
    let mut c = context();
    c.session = TransportSessionKey::new("sensor-exporter", "other-epoch", 256).unwrap();
    let out = parse_netflow_v9(&p, c, &mut r, Default::default()).unwrap();
    assert_eq!(data(&out, 0).state, DataFlowSetState::SkippedUnknown);
    assert_eq!(r.len(), 1);
});
case!(isolation_cross_source_id, {
    let mut r = registry();
    let p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
    with_registry(&p, &mut r);
    let mut p = packet(1, &[fs(256, &[7])]);
    set32(&mut p, 16, 43);
    assert_eq!(
        data(&with_registry(&p, &mut r), 0).state,
        DataFlowSetState::SkippedUnknown
    );
});
case!(isolation_cross_protocol, {
    let mut r = registry();
    let k = TemplateKey::new(TemplateProtocol::Ipfix, context().session, 42, 256).unwrap();
    r.insert(
        k,
        TemplateDefinition::new(
            TemplateKind::Data,
            0,
            &[TemplateFieldSpecifier {
                field_id: 1,
                encoded_length: 1,
                enterprise_number: None,
            }],
            256,
        )
        .unwrap(),
        0,
    )
    .unwrap();
    let before = r.clone();
    let p = packet(1, &[fs(256, &[7])]);
    assert_eq!(
        data(&with_registry(&p, &mut r), 0).state,
        DataFlowSetState::SkippedUnknown
    );
    assert_eq!(r, before);
});
case!(isolation_cross_exporter, {
    let mut r = registry();
    let p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
    with_registry(&p, &mut r);
    let p = packet(1, &[fs(256, &[7])]);
    let mut c = context();
    c.session = TransportSessionKey::new("other", "collector-udp-epoch1", 256).unwrap();
    assert_eq!(
        data(
            &parse_netflow_v9(&p, c, &mut r, Default::default()).unwrap(),
            0
        )
        .state,
        DataFlowSetState::SkippedUnknown
    );
});

fn reject_replacement_packet() -> Vec<u8> {
    packet(
        4,
        &[
            fs(0, &template(256, &[(1, 1)])),
            fs(0, &template(257, &[(2, 1)])),
            fs(0, &template(256, &[(1, 0)])),
            fs(256, &[7]),
            fs(257, &[8]),
        ],
    )
}
case!(replacement_rejection_invalidates_exact_key, {
    let p = reject_replacement_packet();
    let out = run(&p);
    assert!(matches!(
        records(&out, 2)[0].state,
        TemplateRecordState::Rejected {
            local_invalidation: Some(TemplateWithdrawal::Withdrawn { generation: 1 }),
            ..
        }
    ));
});
case!(replacement_unrelated_key_survives, {
    let p = reject_replacement_packet();
    let mut r = registry();
    let out = with_registry(&p, &mut r);
    assert_eq!(data(&out, 4).state, DataFlowSetState::Decoded);
    assert_eq!(r.len(), 1);
    assert_eq!(r.entries().next().unwrap().0.template_id(), 257);
});
case!(replacement_later_data_unknown, {
    let p = reject_replacement_packet();
    assert_eq!(data(&run(&p), 3).state, DataFlowSetState::SkippedUnknown);
});
case!(
    replacement_untrusted_extent_requires_reset_preserves_prior_effects,
    {
        let mut malformed = template(256, &[(1, 2)]);
        malformed[2..4].copy_from_slice(&3_u16.to_be_bytes());
        let p = packet(
            3,
            &[
                fs(0, &template(256, &[(1, 1)])),
                fs(0, &malformed),
                fs(256, &[7]),
            ],
        );
        let mut r = registry();
        let out = with_registry(&p, &mut r);
        assert_eq!(out.completion, ParseCompletion::StoppedForReset);
        assert_eq!(r.len(), 1);
        assert_eq!(data(&out, 2).state, DataFlowSetState::Unprocessed);
    }
);
case!(replacement_no_stale_fallback_after_bad_field_count, {
    let p = packet(
        3,
        &[
            fs(0, &template(256, &[(1, 1)])),
            fs(0, &template(256, &[])),
            fs(256, &[7]),
        ],
    );
    let out = run(&p);
    assert_eq!(data(&out, 2).state, DataFlowSetState::SkippedUnknown);
});
case!(
    replacement_malformed_options_trusted_extent_invalidates_and_recovers,
    {
        let mut t = malformed_option(3, 4);
        t.extend(options(257, &[], &[(2, 1)]));
        let p = packet(
            4,
            &[
                fs(0, &template(256, &[(1, 1)])),
                fs(1, &t),
                fs(256, &[7]),
                fs(257, &[8]),
            ],
        );
        let out = run(&p);
        assert_eq!(out.session_disposition, SessionDisposition::Continue);
        assert_eq!(data(&out, 2).state, DataFlowSetState::SkippedUnknown);
        assert_eq!(data(&out, 3).state, DataFlowSetState::Decoded);
    }
);
case!(
    replacement_registry_capacity_failure_is_explicit_and_does_not_evict_neighbor,
    {
        let mut r = TemplateRegistry::new(TemplateRegistryConfig::new(1, 256, 256).unwrap());
        let p = packet(
            2,
            &[
                fs(0, &template(256, &[(1, 1)])),
                fs(0, &template(257, &[(2, 1)])),
            ],
        );
        let out = with_registry(&p, &mut r);
        assert_eq!(r.len(), 1);
        assert!(has(&out, NetFlowV9DiagnosticKind::TemplateRegistryFailure));
        assert!(matches!(
            records(&out, 1)[0].state,
            TemplateRecordState::Rejected {
                local_invalidation: Some(TemplateWithdrawal::Unknown),
                ..
            }
        ));
    }
);
case!(replacement_expiry_overflow_is_explicit_no_hidden_err, {
    let mut r = TemplateRegistry::new(
        TemplateRegistryConfig::default()
            .with_ttl_ns(u64::MAX)
            .unwrap(),
    );
    let p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
    let out = with_registry(&p, &mut r);
    assert!(has(&out, NetFlowV9DiagnosticKind::TemplateRegistryFailure));
    assert!(r.is_empty());
});

fn bad_length(length: u16) {
    let mut p = packet(0, &[]);
    p.extend(0_u16.to_be_bytes());
    p.extend(length.to_be_bytes());
    assert!(matches!(
        parse_netflow_v9_wire(&p, Default::default()),
        Err(NetFlowV9ParseError::InvalidFlowSetLength { .. })
    ));
}
case!(flowset_length_zero, {
    bad_length(0);
});
case!(flowset_length_one, {
    bad_length(1);
});
case!(flowset_length_two, {
    bad_length(2);
});
case!(flowset_length_three, {
    bad_length(3);
});
case!(flowset_beyond_packet, {
    let mut p = packet(0, &[]);
    p.extend([0, 0, 0, 10]);
    assert!(matches!(
        parse_netflow_v9_wire(&p, Default::default()),
        Err(NetFlowV9ParseError::FlowSetBeyondPacket { .. })
    ));
});
case!(flowset_reserved_skip_continue_raw_view, {
    let p = packet(
        1,
        &[fs(255, &[0x99, 0x88]), fs(0, &template(256, &[(1, 1)]))],
    );
    let out = run(&p);
    assert_eq!(out.flowsets[0].raw_payload, [0x99, 0x88]);
    assert!(has(&out, NetFlowV9DiagnosticKind::ReservedFlowSetId));
    assert!(matches!(
        records(&out, 1)[0].state,
        TemplateRecordState::Applied(_)
    ));
});
case!(flowset_unaligned_warning, {
    let p = simple(1, &[7], 2);
    let out = run(&p);
    assert!(has(&out, NetFlowV9DiagnosticKind::UnalignedFlowSet));
    assert_eq!(data(&out, 1).state, DataFlowSetState::Decoded);
});
fn footer(n: usize) {
    let mut p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
    p.extend(vec![0; n]);
    let mut r = registry();
    assert!(matches!(
        parse_netflow_v9(&p, context(), &mut r, Default::default()),
        Err(NetFlowV9ParseError::TrailingPacketBytes { .. })
    ));
    assert!(r.is_empty());
}
case!(footer_one_byte_fatal_no_effects, {
    footer(1);
});
case!(footer_two_bytes_fatal_no_effects, {
    footer(2);
});
case!(footer_three_bytes_fatal_no_effects, {
    footer(3);
});
case!(footer_four_zero_bytes_are_invalid_flowset_not_padding, {
    let mut p = packet(0, &[]);
    p.extend([0; 4]);
    assert!(matches!(
        parse_netflow_v9_wire(&p, Default::default()),
        Err(NetFlowV9ParseError::InvalidFlowSetLength { .. })
    ));
});
case!(framing_late_error_prevents_early_template_mutation, {
    let mut p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
    p.extend([0, 0, 0, 99]);
    let mut r = registry();
    let before = r.clone();
    assert!(parse_netflow_v9(&p, context(), &mut r, Default::default()).is_err());
    assert_eq!(r, before);
});
case!(template_terminal_padding_0_to_3, {
    for n in 0..=3 {
        let mut t = template(256, &[(1, 1)]);
        t.extend(vec![0; n]);
        let p = packet(1, &[fs(0, &t)]);
        assert_eq!(run(&p).count_validation, CountValidation::Match);
    }
});
case!(
    template_nonzero_suffix_reset_preserves_explicit_prior_transition,
    {
        let mut t = template(256, &[(1, 1)]);
        t.push(1);
        let p = packet(1, &[fs(0, &t)]);
        let mut r = registry();
        let out = with_registry(&p, &mut r);
        assert_eq!(out.completion, ParseCompletion::StoppedForReset);
        assert_eq!(r.len(), 1);
        assert!(matches!(
            records(&out, 0)[0].state,
            TemplateRecordState::Applied(_)
        ));
    }
);

case!(limit_flowset_exact, {
    let p = packet(0, &[fs(2, &[]), fs(3, &[])]);
    assert_eq!(
        parse_netflow_v9_wire(&p, cfg(2, 5, 5, 5, 5, 5))
            .unwrap()
            .flowset_count(),
        2
    );
});
case!(limit_flowset_plus_one_no_effects, {
    let p = simple(1, &[7], 2);
    let mut r = registry();
    assert!(parse_netflow_v9(&p, context(), &mut r, cfg(1, 5, 5, 5, 5, 5)).is_err());
    assert!(r.is_empty());
});
case!(limit_template_records_exact, {
    let mut t = template(256, &[(1, 1)]);
    t.extend(template(257, &[(2, 1)]));
    let p = packet(2, &[fs(0, &t)]);
    assert_eq!(
        parse_netflow_v9(&p, context(), &mut registry(), cfg(5, 2, 2, 5, 5, 5))
            .unwrap()
            .count_validation,
        CountValidation::Match
    );
});
case!(limit_template_records_plus_one_no_effects, {
    let mut t = template(256, &[(1, 1)]);
    t.extend(template(257, &[(2, 1)]));
    let p = packet(2, &[fs(0, &t)]);
    let mut r = registry();
    assert!(parse_netflow_v9(&p, context(), &mut r, cfg(5, 1, 5, 5, 5, 5)).is_err());
    assert!(r.is_empty());
});
case!(limit_template_packet_total_before_mutation, {
    let p = packet(
        2,
        &[
            fs(0, &template(256, &[(1, 1)])),
            fs(1, &options(257, &[], &[(2, 1)])),
        ],
    );
    let mut r = registry();
    assert!(parse_netflow_v9(&p, context(), &mut r, cfg(5, 1, 1, 5, 5, 5)).is_err());
    assert!(r.is_empty());
});
case!(limit_data_flowset_exact, {
    let p = simple(1, &[1, 2], 3);
    let out = parse_netflow_v9(&p, context(), &mut registry(), cfg(5, 5, 5, 2, 5, 5)).unwrap();
    assert_eq!(data(&out, 1).record_count, 2);
});
case!(limit_data_flowset_plus_one_no_prefix_output, {
    let p = simple(1, &[1, 2, 3], 4);
    let mut r = registry();
    let out = parse_netflow_v9(&p, context(), &mut r, cfg(5, 5, 5, 2, 5, 5)).unwrap();
    assert_eq!(data(&out, 1).state, DataFlowSetState::Rejected);
    assert_eq!(data(&out, 1).records().count(), 0);
    assert_eq!(r.len(), 1);
});
case!(
    limit_datagram_data_total_stops_after_prefix_no_later_template,
    {
        let p = packet(
            5,
            &[
                fs(0, &template(256, &[(1, 1)])),
                fs(256, &[1]),
                fs(256, &[2, 3]),
                fs(0, &template(257, &[(2, 1)])),
                fs(257, &[4]),
            ],
        );
        let mut r = registry();
        let out = parse_netflow_v9(&p, context(), &mut r, cfg(8, 8, 8, 8, 2, 8)).unwrap();
        assert_eq!(out.completion, ParseCompletion::StoppedAtLimit);
        assert_eq!(out.decoded_record_count, 1);
        assert_eq!(data(&out, 2).state, DataFlowSetState::Rejected);
        assert!(matches!(
            records(&out, 3)[0].state,
            TemplateRecordState::Unprocessed
        ));
        assert_eq!(data(&out, 4).state, DataFlowSetState::Unprocessed);
        assert_eq!(r.len(), 1);
    }
);
case!(limit_diagnostic_cap_checked_total_dropped, {
    let p = packet(0, &[fs(2, &[]), fs(3, &[]), fs(4, &[])]);
    let out = parse_netflow_v9(&p, context(), &mut registry(), cfg(5, 5, 5, 5, 5, 1)).unwrap();
    assert_eq!(out.diagnostics.len(), 1);
    assert_eq!(out.diagnostics_total, 3);
    assert_eq!(out.diagnostics_dropped, 2);
});
case!(
    limit_diagnostic_zero_retention_keeps_reset_and_count_semantics,
    {
        let p = packet(1, &[fs(0, &template(255, &[(1, 1)])), fs(256, &[1])]);
        let mut r = registry();
        let out = parse_netflow_v9(&p, context(), &mut r, cfg(5, 5, 5, 5, 5, 0)).unwrap();
        assert!(out.diagnostics.is_empty());
        assert_eq!(out.diagnostics_total, out.diagnostics_dropped);
        assert_eq!(out.completion, ParseCompletion::StoppedForReset);
        assert_eq!(out.session_disposition, SessionDisposition::ResetRequired);
        assert_eq!(out.count_validation, CountValidation::Inconclusive);
    }
);
case!(limit_oversized_datagram_no_effects, {
    let p = vec![0; 65536];
    let mut r = registry();
    assert!(matches!(
        parse_netflow_v9(&p, context(), &mut r, Default::default()),
        Err(NetFlowV9ParseError::LimitExceeded {
            field: "datagram_bytes",
            ..
        })
    ));
    assert!(r.is_empty());
});
case!(limit_datagram_bytes_exact_and_plus_one, {
    let p = packet(0, &[fs(2, &[])]);
    let config = NetFlowV9ParserConfig::new(24, 1, 1, 1, 1, 1, 0).unwrap();
    assert!(parse_netflow_v9_wire(&p, config).is_ok());
    let mut over = p;
    over.push(0);
    assert!(matches!(
        parse_netflow_v9_wire(&over, config),
        Err(NetFlowV9ParseError::LimitExceeded { .. })
    ));
});
case!(limit_default_values_exact, {
    let c = NetFlowV9ParserConfig::default();
    assert_eq!(
        [
            c.max_datagram_bytes(),
            c.max_flowsets_per_datagram(),
            c.max_template_records_per_flowset(),
            c.max_template_records_per_datagram(),
            c.max_data_records_per_flowset(),
            c.max_data_records_per_datagram(),
            c.max_diagnostics_per_datagram()
        ],
        [65535, 1024, 512, 2048, 4096, 16384, 128]
    );
});
case!(limit_config_zero_caps_rejected_except_diagnostics, {
    for i in 0..6 {
        let mut caps = [1; 7];
        caps[i] = 0;
        assert!(NetFlowV9ParserConfig::new(
            caps[0], caps[1], caps[2], caps[3], caps[4], caps[5], caps[6]
        )
        .is_err());
    }
    assert!(NetFlowV9ParserConfig::new(1, 1, 1, 1, 1, 1, 0).is_ok());
});
case!(limit_config_unrepresentable_budget_rejected, {
    assert!(NetFlowV9ParserConfig::new(usize::MAX, 1, 1, 1, 1, 1, 1).is_err());
    assert!(NetFlowV9ParserConfig::new(1, 1, 1, 1, 1, 1, usize::MAX).is_err());
});
case!(limit_suppression_changes_no_decode_or_registry_semantics, {
    let p = reject_replacement_packet();
    let mut a = registry();
    let mut b = registry();
    let out_a = parse_netflow_v9(&p, context(), &mut a, cfg(8, 8, 8, 8, 8, 100)).unwrap();
    let out_b = parse_netflow_v9(&p, context(), &mut b, cfg(8, 8, 8, 8, 8, 0)).unwrap();
    assert_eq!(a, b);
    assert_eq!(out_a.flowsets, out_b.flowsets);
    assert_eq!(out_a.count_validation, out_b.count_validation);
    assert_eq!(out_a.completion, out_b.completion);
    assert_eq!(out_a.diagnostics_total, out_b.diagnostics_total);
});

case!(count_exact_total_not_flowset_count, {
    let p = simple(1, &[1, 2, 3], 4);
    let out = run(&p);
    assert_eq!(out.flowsets.len(), 2);
    assert_eq!(out.count_validation, CountValidation::Match);
});
case!(count_mismatch_flags_without_rollback, {
    let p = simple(1, &[1], 50);
    let mut r = registry();
    let out = with_registry(&p, &mut r);
    assert_eq!(
        out.count_validation,
        CountValidation::Mismatch {
            declared: 50,
            parsed: 2
        }
    );
    assert!(has(&out, NetFlowV9DiagnosticKind::CountMismatch));
    assert_eq!(r.len(), 1);
});
case!(count_unknown_inconclusive, {
    let p = packet(1, &[fs(256, &[1])]);
    assert_eq!(run(&p).count_validation, CountValidation::Inconclusive);
});
case!(count_reserved_inconclusive, {
    let p = packet(0, &[fs(2, &[])]);
    assert_eq!(run(&p).count_validation, CountValidation::Inconclusive);
});
case!(count_malformed_inconclusive, {
    let p = packet(1, &[fs(0, &template(256, &[]))]);
    assert_eq!(run(&p).count_validation, CountValidation::Inconclusive);
});
case!(count_limit_rejection_inconclusive, {
    let p = simple(1, &[1, 2], 3);
    let out = parse_netflow_v9(&p, context(), &mut registry(), cfg(5, 5, 5, 1, 5, 5)).unwrap();
    assert_eq!(out.count_validation, CountValidation::Inconclusive);
});
case!(count_max_never_allocation_bound, {
    let p = packet(u16::MAX, &[fs(0, &template(256, &[(1, 1)]))]);
    let out = run(&p);
    assert_eq!(out.flowsets.len(), 1);
    assert_eq!(
        out.count_validation,
        CountValidation::Mismatch {
            declared: u16::MAX,
            parsed: 1
        }
    );
});
case!(count_options_and_templates_and_data, {
    let p = packet(
        4,
        &[
            fs(0, &template(256, &[(1, 1)])),
            fs(1, &options(257, &[], &[(50, 1)])),
            fs(256, &[1]),
            fs(257, &[2]),
        ],
    );
    assert_eq!(run(&p).count_validation, CountValidation::Match);
});

case!(time_every_packet_operation_uses_header_unix_ns, {
    let p = reject_replacement_packet();
    let mut r = registry();
    let out = with_registry(&p, &mut r);
    assert_eq!(out.source_time_ns, 100_000_000_000);
    for (k, e) in r.entries() {
        assert_eq!(e.first_seen_ns(), out.source_time_ns);
        assert_eq!(e.last_seen_ns(), out.source_time_ns);
        assert_eq!(
            r.timeline_last_source_time_ns(k.timeline()),
            Some(out.source_time_ns)
        );
    }
});
case!(time_equal_multiple_operations_valid, {
    let p = redefinition_packet();
    let out = run(&p);
    assert_eq!(out.session_disposition, SessionDisposition::Continue);
    assert_eq!(out.count_validation, CountValidation::Match);
});
case!(time_regression_precheck_before_any_packet_mutation, {
    let mut r = registry();
    let p = simple(1, &[7], 2);
    with_registry(&p, &mut r);
    let before = r.clone();
    let mut p = packet(1, &[fs(0, &template(257, &[(1, 1)]))]);
    set32(&mut p, 8, 99);
    assert!(matches!(
        parse_netflow_v9(&p, context(), &mut r, Default::default()),
        Err(NetFlowV9ParseError::RegistryPrecheck(
            TemplateRegistryError::SourceTimeRegression { .. }
        ))
    ));
    assert_eq!(r, before);
});
case!(time_unrelated_timeline_unaffected, {
    let mut r = registry();
    let p = simple(1, &[7], 2);
    with_registry(&p, &mut r);
    let mut p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
    set32(&mut p, 8, 1);
    set32(&mut p, 16, 43);
    with_registry(&p, &mut r);
    assert_eq!(r.len(), 2);
    let values: Vec<_> = r
        .entries()
        .map(|(k, e)| (k.observation_scope_id(), e.last_seen_ns()))
        .collect();
    assert_eq!(values, [(42, 100_000_000_000), (43, 1_000_000_000)]);
});
case!(time_ttl_exact_boundary_expired, {
    assert_eq!(expiry_test(2), (DataFlowSetState::SkippedExpired, 0));
});
case!(time_ttl_before_boundary_active, {
    assert_eq!(expiry_test(1), (DataFlowSetState::Decoded, 1));
});
case!(time_expired_lookup_reports_generation_and_expiry, {
    let mut r = TemplateRegistry::new(
        TemplateRegistryConfig::default()
            .with_ttl_ns(1_000_000_000)
            .unwrap(),
    );
    let p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
    with_registry(&p, &mut r);
    let mut p = packet(1, &[fs(256, &[1])]);
    set32(&mut p, 8, 101);
    let out = with_registry(&p, &mut r);
    let d = out
        .diagnostics
        .iter()
        .find(|d| d.kind == NetFlowV9DiagnosticKind::ExpiredTemplate)
        .unwrap();
    assert_eq!(d.generation, Some(1));
    assert_eq!(d.expires_at_ns, Some(101_000_000_000));
    assert_eq!(r.timeline_count(), 0);
    let second = with_registry(&p, &mut r);
    assert_eq!(data(&second, 0).state, DataFlowSetState::SkippedUnknown);
});
case!(time_context_identity_revalidated_no_mutation, {
    let mut r = TemplateRegistry::new(TemplateRegistryConfig::new(5, 5, 1).unwrap());
    let before = r.clone();
    let p = simple(1, &[7], 2);
    assert!(matches!(
        parse_netflow_v9(&p, context(), &mut r, Default::default()),
        Err(NetFlowV9ParseError::RegistryPrecheck(
            TemplateRegistryError::InvalidIdentity { .. }
        ))
    ));
    assert_eq!(r, before);
});
case!(time_wire_preflight_is_stateless, {
    let p = redefinition_packet();
    let wire = parse_netflow_v9_wire(&p, Default::default()).unwrap();
    assert_eq!(wire.flowset_count(), 4);
    assert_eq!(wire.header().count, 4);
});

case!(deterministic_replay_outcomes_and_registry, {
    let p = reject_replacement_packet();
    let mut a = registry();
    let mut b = registry();
    let oa = with_registry(&p, &mut a);
    let ob = with_registry(&p, &mut b);
    assert_eq!(oa, ob);
    assert_eq!(a, b);
});
case!(unknown_data_never_retained_in_registry_or_queue, {
    let mut r = registry();
    for ordinal in 0..1000 {
        let p = packet(1, &[fs(256, &[7; 100])]);
        let mut c = context();
        c.datagram_ordinal = ordinal;
        let out = parse_netflow_v9(&p, c, &mut r, Default::default()).unwrap();
        assert_eq!(out.context.datagram_ordinal, ordinal);
        assert_eq!(data(&out, 0).records().count(), 0);
    }
    assert_eq!(r.len(), 0);
    assert_eq!(r.timeline_count(), 0);
});
case!(diagnostics_never_contain_raw_payload_strings, {
    let marker = b"PRIVATE-PAYLOAD-SECRET";
    let p = packet(1, &[fs(256, marker)]);
    let out = run(&p);
    let text = format!("{:?}", out.diagnostics);
    assert!(!text.contains("PRIVATE"));
    assert!(!text.contains("sensor-exporter"));
});
case!(ordinals_caller_max_not_sequence_or_success_count, {
    let p = simple(1, &[7], 2);
    let mut c = context();
    c.datagram_ordinal = u64::MAX;
    let out = parse_netflow_v9(&p, c, &mut registry(), Default::default()).unwrap();
    assert_eq!(out.context.datagram_ordinal, u64::MAX);
    assert!(out
        .diagnostics
        .iter()
        .all(|d| d.datagram_ordinal == u64::MAX));
});
case!(ordinals_all_framed_flowsets_including_skips, {
    let p = packet(
        2,
        &[
            fs(2, &[]),
            fs(256, &[7]),
            fs(0, &template(256, &[(1, 1)])),
            fs(256, &[8]),
        ],
    );
    let out = run(&p);
    assert_eq!(
        out.flowsets
            .iter()
            .map(|f| f.flowset_ordinal)
            .collect::<Vec<_>>(),
        [0, 1, 2, 3]
    );
    assert_eq!(data(&out, 1).state, DataFlowSetState::SkippedUnknown);
    assert_eq!(data(&out, 3).state, DataFlowSetState::Decoded);
});
case!(ordinals_rejected_known_extent_does_not_renumber_records, {
    let mut t = template(256, &[]);
    t.extend(template(257, &[(1, 1)]));
    let p = packet(2, &[fs(0, &t)]);
    let out = run(&p);
    assert_eq!(records(&out, 0)[0].record_ordinal, 0);
    assert_eq!(records(&out, 0)[1].record_ordinal, 1);
    assert!(matches!(
        records(&out, 0)[1].state,
        TemplateRecordState::Applied(_)
    ));
});
case!(sampling_ids_widths_bytes_only_no_normalization, {
    let p = options_packet(&[], &[(48, 4), (49, 1), (50, 2)], &[0, 0, 0, 99, 1, 0, 10]);
    let out = run(&p);
    let values: Vec<_> = data(&out, 1).records().next().unwrap().fields().collect();
    assert_eq!(values[0].bytes, [0, 0, 0, 99]);
    assert_eq!(values[2].specifier.encoded_length, 2);
});
case!(sequence_decrease_is_raw_not_restart_or_loss, {
    let mut r = registry();
    let mut a = simple(1, &[7], 2);
    set32(&mut a, 12, u32::MAX);
    with_registry(&a, &mut r);
    let mut b = packet(1, &[fs(256, &[8])]);
    set32(&mut b, 12, 0);
    set32(&mut b, 4, 0);
    assert_eq!(
        data(&with_registry(&b, &mut r), 0).state,
        DataFlowSetState::Decoded
    );
});

fn fixture_paths() -> Vec<PathBuf> {
    fn visit(dir: &Path, result: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, result);
            } else if path.extension().is_some_and(|e| e == "bin") {
                result.push(path);
            }
        }
    }
    let mut paths = Vec::new();
    visit(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/export/netflow_v9"),
        &mut paths,
    );
    paths.sort();
    paths
}

case!(
    replacement_registry_expiry_failure_invalidates_old_live_layout_before_later_data,
    {
        let mut r = TemplateRegistry::new(
            TemplateRegistryConfig::default()
                .with_ttl_ns(u64::MAX)
                .unwrap(),
        );
        let definition = TemplateDefinition::new(
            TemplateKind::Data,
            0,
            &[TemplateFieldSpecifier {
                field_id: 1,
                encoded_length: 1,
                enterprise_number: None,
            }],
            256,
        )
        .unwrap();
        r.insert(key(256), definition, 0).unwrap();
        let p = packet(2, &[fs(0, &template(256, &[(2, 2)])), fs(256, &[1, 2])]);
        let out = with_registry(&p, &mut r);
        assert!(matches!(
            records(&out, 0)[0].state,
            TemplateRecordState::Rejected {
                reason: NetFlowV9DiagnosticKind::TemplateRegistryFailure,
                local_invalidation: Some(TemplateWithdrawal::Withdrawn { generation: 1 })
            }
        ));
        assert_eq!(data(&out, 1).state, DataFlowSetState::SkippedUnknown);
        assert!(r.is_empty());
    }
);

case!(header_only_export_rejected_without_effects, {
    let p = packet(0, &[]);
    let mut r = registry();
    assert_eq!(
        parse_netflow_v9(&p, context(), &mut r, Default::default()),
        Err(NetFlowV9ParseError::MissingFlowSets)
    );
    assert!(r.is_empty());
});
case!(
    template_and_options_empty_or_padding_only_reset_not_valid_empty_flowsets,
    {
        for id in [0, 1] {
            for n in 0..=3 {
                let p = packet(0, &[fs(id, &vec![0; n])]);
                let out = run(&p);
                assert_eq!(out.completion, ParseCompletion::StoppedForReset);
                assert_eq!(out.count_validation, CountValidation::Inconclusive);
                assert!(records(&out, 0).is_empty());
            }
        }
    }
);
case!(
    data_short_padding_only_rejected_without_removing_valid_template,
    {
        for n in 1..=3 {
            let p = simple(8, &vec![0; n], 1);
            let mut r = registry();
            let out = with_registry(&p, &mut r);
            assert_eq!(data(&out, 1).state, DataFlowSetState::Rejected);
            assert_eq!(out.count_validation, CountValidation::Inconclusive);
            assert_eq!(r.len(), 1);
        }
    }
);
case!(
    empty_template_after_applied_prefix_keeps_explicit_effects_and_stops,
    {
        let p = packet(
            2,
            &[fs(0, &template(256, &[(1, 1)])), fs(0, &[]), fs(256, &[1])],
        );
        let mut r = registry();
        let out = with_registry(&p, &mut r);
        assert_eq!(r.len(), 1);
        assert!(matches!(
            records(&out, 0)[0].state,
            TemplateRecordState::Applied(_)
        ));
        assert_eq!(data(&out, 2).state, DataFlowSetState::Unprocessed);
        assert_eq!(out.session_disposition, SessionDisposition::ResetRequired);
    }
);

case!(default_flowset_cap_1024_and_one_over, {
    for count in [1024, 1025] {
        let p = packet(0, &vec![fs(2, &[]); count]);
        let mut r = registry();
        let result = parse_netflow_v9(&p, context(), &mut r, Default::default());
        if count == 1024 {
            assert_eq!(result.unwrap().flowsets.len(), count);
        } else {
            assert!(matches!(
                result,
                Err(NetFlowV9ParseError::LimitExceeded {
                    field: "flowsets",
                    ..
                })
            ));
        }
        assert!(r.is_empty());
    }
});
case!(default_template_flowset_cap_512_and_one_over, {
    for count in [512, 513] {
        let t = template(256, &[(1, 1)]).repeat(count);
        let p = packet(count as u16, &[fs(0, &t)]);
        let mut r = registry();
        let result = parse_netflow_v9(&p, context(), &mut r, Default::default());
        if count == 512 {
            assert_eq!(records(&result.unwrap(), 0).len(), count);
            assert_eq!(r.len(), 1);
        } else {
            assert!(result.is_err());
            assert!(r.is_empty());
        }
    }
});
case!(default_template_datagram_cap_2048_and_one_over, {
    for count in [2048, 2049] {
        let t = fs(0, &template(256, &[(1, 1)]).repeat(512));
        let mut sets = vec![t; 4];
        if count == 2049 {
            sets.push(fs(0, &template(256, &[(1, 1)])));
        }
        let p = packet(count, &sets);
        let mut r = registry();
        let result = parse_netflow_v9(&p, context(), &mut r, Default::default());
        if count == 2048 {
            assert_eq!(result.unwrap().count_validation, CountValidation::Match);
            assert_eq!(r.len(), 1);
        } else {
            assert!(result.is_err());
            assert!(r.is_empty());
        }
    }
});
case!(default_data_flowset_cap_4096_and_one_over, {
    for count in [4096, 4097] {
        let p = simple(1, &vec![1; count], (count + 1) as u16);
        let out = run(&p);
        if count == 4096 {
            assert_eq!(data(&out, 1).record_count, count);
        } else {
            assert_eq!(data(&out, 1).state, DataFlowSetState::Rejected);
            assert_eq!(data(&out, 1).records().count(), 0);
        }
    }
});
case!(default_data_datagram_cap_16384_and_one_over, {
    for over in [false, true] {
        let mut sets = vec![fs(0, &template(256, &[(1, 1)]))];
        sets.extend(vec![fs(256, &[1; 4096]); 4]);
        if over {
            sets.push(fs(256, &[1]));
            sets.push(fs(0, &template(257, &[(2, 1)])));
        }
        let p = packet(if over { 16387 } else { 16385 }, &sets);
        let mut r = registry();
        let out = with_registry(&p, &mut r);
        assert_eq!(out.decoded_record_count, 16384);
        if over {
            assert_eq!(out.completion, ParseCompletion::StoppedAtLimit);
            assert!(matches!(
                records(&out, 6)[0].state,
                TemplateRecordState::Unprocessed
            ));
        } else {
            assert_eq!(out.count_validation, CountValidation::Match);
        }
        assert_eq!(r.len(), 1);
    }
});
case!(default_diagnostic_cap_128_and_one_over, {
    let p = packet(0, &vec![fs(2, &[]); 129]);
    let out = run(&p);
    assert_eq!(out.diagnostics.len(), 128);
    assert_eq!(out.diagnostics_total, 129);
    assert_eq!(out.diagnostics_dropped, 1);
});
case!(default_datagram_byte_cap_65535_exact, {
    let p = packet(0, &[fs(2, &[0; 65511])]);
    assert_eq!(p.len(), 65535);
    let out = run(&p);
    assert_eq!(out.flowsets[0].raw_payload.len(), 65511);
});
case!(
    options_f5_field_bound_exact_and_one_over_before_construction,
    {
        for count in [256, 257] {
            let t = options(256, &[(1, 1); 128], &vec![(50, 1); count - 128]);
            let p = packet(1, &[fs(1, &t)]);
            let mut r = registry();
            let out = with_registry(&p, &mut r);
            assert_eq!(records(&out, 0)[0].descriptors().count(), count);
            if count == 256 {
                assert_eq!(out.count_validation, CountValidation::Match);
                assert_eq!(r.len(), 1);
            } else {
                rejected(&out);
                assert!(r.is_empty());
            }
        }
    }
);

case!(
    fatal_preflight_errors_require_quarantine_without_registry_mutation,
    {
        let mut p = packet(1, &[fs(0, &template(256, &[(1, 1)]))]);
        p.push(0);
        let mut r = registry();
        let error = parse_netflow_v9(&p, context(), &mut r, Default::default()).unwrap_err();
        assert_eq!(
            error.session_disposition(),
            SessionDisposition::ResetRequired
        );
        assert!(r.is_empty());
    }
);
case!(
    data_external_unsupported_registry_layout_invalidation_is_explicit,
    {
        let mut r = registry();
        let definition = TemplateDefinition::new(
            TemplateKind::Data,
            0,
            &[TemplateFieldSpecifier {
                field_id: 1,
                encoded_length: 0,
                enterprise_number: None,
            }],
            256,
        )
        .unwrap();
        r.insert(key(256), definition, 0).unwrap();
        let p = packet(1, &[fs(256, &[1])]);
        let out = with_registry(&p, &mut r);
        assert_eq!(data(&out, 0).state, DataFlowSetState::Rejected);
        assert_eq!(
            data(&out, 0).local_invalidation,
            Some(TemplateWithdrawal::Withdrawn { generation: 1 })
        );
        assert!(r.is_empty());
    }
);
case!(
    replacement_rejected_then_supported_definition_starts_new_f5_lifetime,
    {
        let p = packet(
            4,
            &[
                fs(0, &template(256, &[(1, 1)])),
                fs(0, &template(256, &[(1, 0)])),
                fs(0, &template(256, &[(2, 2)])),
                fs(256, &[3, 4]),
            ],
        );
        let out = run(&p);
        assert_eq!(data(&out, 3).snapshot().unwrap().generation, 1);
        assert_eq!(
            data(&out, 3)
                .records()
                .next()
                .unwrap()
                .fields()
                .next()
                .unwrap()
                .specifier
                .field_id,
            2
        );
    }
);
case!(
    real_softflowd_capture_decodes_without_relaxing_exporter_count_mismatch,
    {
        let bytes = include_bytes!("fixtures/export/netflow_v9/real/softflowd_000.bin");
        let out = run(bytes);
        assert_eq!(out.header.count, 8);
        assert_eq!(out.decoded_record_count, 9);
        assert_eq!(
            out.count_validation,
            CountValidation::Mismatch {
                declared: 8,
                parsed: 14
            }
        );
        assert_eq!(out.session_disposition, SessionDisposition::Continue);
        assert!(has(&out, NetFlowV9DiagnosticKind::CountMismatch));
        assert!(out
            .flowsets
            .iter()
            .filter_map(|f| match &f.content {
                FlowSetContent::Data(d) => Some(d),
                _ => None,
            })
            .all(|d| d.state == DataFlowSetState::Decoded));
    }
);
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn summarize(out: &NetFlowV9ParseOutcome<'_>) -> Value {
    let h = &out.header;
    let sets: Vec<_> = out.flowsets.iter().map(|f| {
        let mut value = json!({"id": f.flowset_id, "length": f.length, "offset": f.byte_offset, "ordinal": f.flowset_ordinal, "raw": hex(f.raw_payload), "processed": f.processed});
        match &f.content {
            FlowSetContent::Reserved => { value["kind"] = json!("reserved"); }
            FlowSetContent::Templates { records, padding, .. } => {
                value["kind"] = json!("templates"); value["padding"] = json!(hex(padding));
                value["records"] = json!(records.iter().map(|r| {
                    let state = match r.state { TemplateRecordState::Applied(_) => "Applied", TemplateRecordState::Rejected { .. } => "Rejected", TemplateRecordState::Unprocessed => "Unprocessed" };
                    json!({"id": r.template_id, "ordinal": r.record_ordinal, "offset": r.byte_offset, "scope": r.scope_field_count, "count": r.field_count, "fields": r.descriptors().map(|f| [f.field_id, f.encoded_length]).collect::<Vec<_>>(), "state": state, "raw": hex(r.raw_record)})
                }).collect::<Vec<_>>());
            }
            FlowSetContent::Data(d) => {
                value["kind"] = json!("data"); value["state"] = json!(format!("{:?}", d.state)); value["padding"] = json!(hex(d.padding));
                value["records"] = json!(d.records().map(|r| json!({"ordinal": r.record_ordinal, "offset": r.byte_offset, "raw": hex(r.bytes()), "fields": r.fields().map(|f| json!([f.specifier.field_id, f.specifier.encoded_length, format!("{:?}", f.role), hex(f.bytes)])).collect::<Vec<_>>() })).collect::<Vec<_>>());
            }
        } value
    }).collect();
    let (count, parsed) = match out.count_validation {
        CountValidation::Match => ("Match", Some(usize::from(h.count))),
        CountValidation::Mismatch { parsed, .. } => ("Mismatch", Some(parsed)),
        CountValidation::Inconclusive => ("Inconclusive", None),
    };
    json!({"header": [u64::from(h.version), u64::from(h.count), u64::from(h.sys_uptime_ms), u64::from(h.unix_seconds), u64::from(h.sequence_number), u64::from(h.source_id)], "flowsets": sets, "count": count, "parsed_count": parsed, "reset": out.session_disposition == SessionDisposition::ResetRequired})
}
case!(fixtures_independent_expected_structure_and_sha, {
    for path in fixture_paths() {
        let bytes = std::fs::read(&path).unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(
            std::fs::read_to_string(path.with_extension("sha256"))
                .unwrap()
                .trim(),
            digest,
            "{}",
            path.display()
        );
        let meta: Value =
            serde_json::from_slice(&std::fs::read(path.with_extension("json")).unwrap()).unwrap();
        assert_eq!(meta["sha256"], digest);
        let result = parse_netflow_v9(&bytes, context(), &mut registry(), Default::default());
        if let Some(error) = meta["expected"]["error"].as_str() {
            assert!(
                format!("{:?}", result.unwrap_err()).starts_with(error),
                "{}",
                path.display()
            );
        } else {
            assert_eq!(
                summarize(&result.unwrap()),
                meta["expected"],
                "{}",
                path.display()
            );
        }
    }
});
case!(
    fixtures_every_prefix_no_panic_atomic_errors_and_bounded_state,
    {
        for path in fixture_paths() {
            let bytes = std::fs::read(&path).unwrap();
            if bytes.len() > 4096 {
                continue;
            }
            for n in 0..=bytes.len() {
                let mut r = registry();
                let before = r.clone();
                let result = parse_netflow_v9(&bytes[..n], context(), &mut r, Default::default());
                if result.is_err() {
                    assert_eq!(r, before);
                }
                assert!(r.len() <= 4096);
                assert!(r.timeline_count() <= r.len());
            }
        }
    }
);
case!(
    fixtures_each_byte_deterministic_mutation_never_panics_or_crosses_key,
    {
        for path in fixture_paths() {
            let bytes = std::fs::read(&path).unwrap();
            if bytes.len() > 4096 {
                continue;
            }
            for index in 0..bytes.len() {
                for replacement in [0, 255, bytes[index] ^ 0x80] {
                    let mut mutated = bytes.clone();
                    mutated[index] = replacement;
                    let mut r =
                        TemplateRegistry::new(TemplateRegistryConfig::new(4, 8, 256).unwrap());
                    let sentinel =
                        TemplateKey::new(TemplateProtocol::Ipfix, context().session, 42, 256)
                            .unwrap();
                    let definition = TemplateDefinition::new(
                        TemplateKind::Data,
                        0,
                        &[TemplateFieldSpecifier {
                            field_id: 1,
                            encoded_length: 1,
                            enterprise_number: None,
                        }],
                        8,
                    )
                    .unwrap();
                    r.insert(sentinel.clone(), definition, 0).unwrap();
                    let before = r.clone();
                    let result =
                        parse_netflow_v9(&mutated, context(), &mut r, cfg(64, 16, 64, 64, 256, 3));
                    if result.is_err() {
                        assert_eq!(r, before);
                    }
                    assert!(r.len() <= 4);
                    assert!(r.timeline_count() <= r.len());
                    assert_eq!(
                        r.entries().find(|(k, _)| **k == sentinel).unwrap().1,
                        before.entries().next().unwrap().1
                    );
                    if let Ok(out) = result {
                        assert!(out.diagnostics.len() <= 3);
                        assert_eq!(
                            out.diagnostics_total,
                            out.diagnostics.len() + out.diagnostics_dropped
                        );
                        assert!(out.decoded_record_count <= 256);
                    }
                }
            }
        }
    }
);
case!(production_has_no_panic_io_clock_rng_or_unsafe_path, {
    let source = include_str!("../src/netflow/v9.rs");
    for forbidden in [
        "unsafe {",
        ".unwrap()",
        ".expect(",
        "panic!(",
        "SystemTime::",
        "std::fs",
        "std::net",
        "rand::",
        "CanonicalObservation",
    ] {
        assert!(!source.contains(forbidden), "{forbidden}");
    }
});
