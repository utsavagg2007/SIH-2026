use ingestion_core::netflow::template::*;

// Small explicit test policies, NOT approved production resource defaults.
fn config() -> TemplateRegistryConfig {
    TemplateRegistryConfig::new(4, 8, 64)
        .unwrap()
        .with_ttl_ns(10)
        .unwrap()
}

fn registry() -> TemplateRegistry {
    TemplateRegistry::new(config())
}

fn key_for(
    protocol: TemplateProtocol,
    exporter: &str,
    session: &str,
    scope: u32,
    id: u16,
) -> TemplateKey {
    TemplateKey::new(
        protocol,
        TransportSessionKey::new(exporter, session, 64).unwrap(),
        scope,
        id,
    )
    .unwrap()
}

fn key(id: u16) -> TemplateKey {
    key_for(TemplateProtocol::Ipfix, "exporter-1", "udp-epoch-1", 1, id)
}

fn field(id: u16) -> TemplateFieldSpecifier {
    TemplateFieldSpecifier {
        field_id: id,
        encoded_length: 4,
        enterprise_number: None,
    }
}

fn definition(id: u16) -> TemplateDefinition {
    TemplateDefinition::new(TemplateKind::Data, 0, &[field(id)], 8).unwrap()
}

fn found(registry: &mut TemplateRegistry, key: &TemplateKey, time: u64) -> TemplateEntry {
    match registry.lookup(key, time).unwrap() {
        TemplateLookup::Found(entry) => entry.clone(),
        other => panic!("expected active template, got {other:?}"),
    }
}

#[test]
fn inserts_new_data_template_generation_one() {
    let mut r = registry();
    let transition = r.insert(key(256), definition(1), 100).unwrap();
    assert_eq!(
        transition,
        TemplateTransition {
            kind: TemplateTransitionKind::Inserted,
            generation: 1,
            expired_pruned: 0
        }
    );
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
}

#[test]
fn lookup_exposes_exact_definition_and_source_time_metadata() {
    let mut r = registry();
    r.insert(key(256), definition(1), 100).unwrap();
    let e = found(&mut r, &key(256), 101);
    assert_eq!(e.definition(), &definition(1));
    assert_eq!(
        (
            e.generation(),
            e.first_seen_ns(),
            e.last_seen_ns(),
            e.expires_at_ns()
        ),
        (1, 100, 100, 110)
    );
}

#[test]
fn missing_lookup_is_safe_and_allocates_no_entries() {
    let mut r = registry();
    assert_eq!(r.lookup(&key(256), 1).unwrap(), TemplateLookup::Unknown);
    assert!(r.is_empty());
    assert_eq!(r.timeline_last_source_time_ns(key(256).timeline()), None);
    assert_eq!(r.timeline_count(), 0);
}

#[test]
fn identical_refresh_preserves_generation_and_first_seen() {
    let mut r = registry();
    r.insert(key(256), definition(1), 100).unwrap();
    let t = r.insert(key(256), definition(1), 105).unwrap();
    assert_eq!(t.kind, TemplateTransitionKind::Refreshed);
    assert_eq!(t.generation, 1);
    let e = found(&mut r, &key(256), 105);
    assert_eq!(
        (e.first_seen_ns(), e.last_seen_ns(), e.expires_at_ns()),
        (100, 105, 115)
    );
    assert_eq!(r.len(), 1);
}

#[test]
fn changed_definition_replaces_atomically_and_increments_generation() {
    let mut r = registry();
    r.insert(key(256), definition(1), 100).unwrap();
    for (time, id, generation) in [(101, 2, 2), (102, 3, 3)] {
        let t = r.insert(key(256), definition(id), time).unwrap();
        assert_eq!(
            (t.kind, t.generation),
            (TemplateTransitionKind::Replaced, generation)
        );
        let e = found(&mut r, &key(256), time);
        assert_eq!(e.definition(), &definition(id));
        assert_eq!(e.first_seen_ns(), 100);
    }
    assert_eq!(r.len(), 1);
}

#[test]
fn refresh_after_replacement_keeps_incremented_generation() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    r.insert(key(256), definition(2), 1).unwrap();
    assert_eq!(r.insert(key(256), definition(2), 2).unwrap().generation, 2);
}

#[test]
fn field_order_is_exact_and_reordering_is_a_replacement() {
    let a =
        TemplateDefinition::new(TemplateKind::Data, 0, &[field(9), field(2), field(1)], 8).unwrap();
    let b =
        TemplateDefinition::new(TemplateKind::Data, 0, &[field(1), field(2), field(9)], 8).unwrap();
    assert_eq!(a.fields(), &[field(9), field(2), field(1)]);
    let mut r = registry();
    r.insert(key(256), a, 0).unwrap();
    assert_eq!(r.insert(key(256), b.clone(), 1).unwrap().generation, 2);
    assert_eq!(found(&mut r, &key(256), 1).definition(), &b);
}

#[test]
fn duplicate_field_identifiers_are_not_deduplicated() {
    let fields = [
        field(1),
        field(1),
        TemplateFieldSpecifier {
            encoded_length: 8,
            ..field(1)
        },
    ];
    let d = TemplateDefinition::new(TemplateKind::Data, 0, &fields, 8).unwrap();
    let mut r = registry();
    r.insert(key(256), d, 0).unwrap();
    assert_eq!(found(&mut r, &key(256), 0).definition().fields(), &fields);
}

#[test]
fn enterprise_number_and_variable_length_are_preserved() {
    let fields = [
        TemplateFieldSpecifier {
            field_id: 42,
            encoded_length: u16::MAX,
            enterprise_number: Some(u32::MAX),
        },
        TemplateFieldSpecifier {
            field_id: 42,
            encoded_length: 1,
            enterprise_number: Some(0),
        },
        TemplateFieldSpecifier {
            field_id: u16::MAX,
            encoded_length: 0,
            enterprise_number: None,
        },
    ];
    let mut r = registry();
    r.insert(
        key(256),
        TemplateDefinition::new(TemplateKind::Data, 0, &fields, 8).unwrap(),
        0,
    )
    .unwrap();
    assert_eq!(found(&mut r, &key(256), 0).definition().fields(), &fields);
}

#[test]
fn v9_fields_do_not_require_enterprise_numbers() {
    let k = key_for(TemplateProtocol::NetFlowV9, "e", "s", 0, 256);
    let mut r = registry();
    r.insert(k.clone(), definition(u16::MAX), 0).unwrap();
    assert_eq!(
        found(&mut r, &k, 0).definition().fields()[0].enterprise_number,
        None
    );
}

#[test]
fn field_length_change_is_a_replacement() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    let d = TemplateDefinition::new(
        TemplateKind::Data,
        0,
        &[TemplateFieldSpecifier {
            encoded_length: 8,
            ..field(1)
        }],
        8,
    )
    .unwrap();
    assert_eq!(r.insert(key(256), d, 1).unwrap().generation, 2);
}

#[test]
fn enterprise_change_is_a_replacement() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    let d = TemplateDefinition::new(
        TemplateKind::Data,
        0,
        &[TemplateFieldSpecifier {
            enterprise_number: Some(9),
            ..field(1)
        }],
        8,
    )
    .unwrap();
    assert_eq!(r.insert(key(256), d, 1).unwrap().generation, 2);
}

#[test]
fn data_and_options_kinds_are_stored_without_parallel_same_key_entries() {
    let mut r = registry();
    let d = TemplateDefinition::new(TemplateKind::Options, 1, &[field(1), field(2)], 8).unwrap();
    r.insert(key(256), d.clone(), 0).unwrap();
    assert_eq!(found(&mut r, &key(256), 0).definition(), &d);
    let t = r.insert(key(256), definition(3), 1).unwrap();
    assert_eq!(
        (t.kind, t.generation),
        (TemplateTransitionKind::Replaced, 2)
    );
    assert_eq!(r.len(), 1);
    assert_eq!(
        found(&mut r, &key(256), 1).definition().kind(),
        TemplateKind::Data
    );
}

#[test]
fn data_to_options_replacement_preserves_scope_boundary() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    let d = TemplateDefinition::new(TemplateKind::Options, 2, &[field(1), field(2), field(3)], 8)
        .unwrap();
    assert_eq!(r.insert(key(256), d.clone(), 1).unwrap().generation, 2);
    let e = found(&mut r, &key(256), 1);
    assert_eq!(e.definition().scope_field_count(), 2);
    assert_eq!(e.definition().fields(), d.fields());
}

#[test]
fn scope_boundary_change_is_a_replacement() {
    let mut r = registry();
    for (time, count) in [(0, 1), (1, 2)] {
        let d = TemplateDefinition::new(TemplateKind::Options, count, &[field(1), field(2)], 8)
            .unwrap();
        assert_eq!(r.insert(key(256), d, time).unwrap().generation, time + 1);
    }
}

#[test]
fn options_require_an_in_range_scope_count() {
    for count in [3, u16::MAX] {
        assert!(matches!(
            TemplateDefinition::new(TemplateKind::Options, count, &[field(1), field(2)], 8),
            Err(TemplateRegistryError::InvalidScopeFieldCount { .. })
        ));
    }
    for count in [0, 1, 2] {
        assert!(
            TemplateDefinition::new(TemplateKind::Options, count, &[field(1), field(2)], 8).is_ok()
        );
    }
    assert!(matches!(
        TemplateDefinition::new(TemplateKind::Data, 1, &[field(1)], 8),
        Err(TemplateRegistryError::InvalidScopeFieldCount { .. })
    ));
}

fn zero_scope_options(fields: &[TemplateFieldSpecifier]) -> TemplateDefinition {
    TemplateDefinition::new(TemplateKind::Options, 0, fields, 8).unwrap()
}

#[test]
fn zero_scope_options_with_one_field_preserve_options_kind() {
    let d = zero_scope_options(&[field(1)]);
    assert_eq!(d.kind(), TemplateKind::Options);
    assert_eq!(d.scope_field_count(), 0);
    assert_eq!(d.fields(), &[field(1)]);
}

#[test]
fn zero_scope_options_with_multiple_fields_preserve_order_and_duplicates() {
    let fields = [field(2), field(1), field(2)];
    let d = zero_scope_options(&fields);
    assert_eq!(d.kind(), TemplateKind::Options);
    assert_eq!(d.scope_field_count(), 0);
    assert_eq!(d.fields(), &fields);
}

#[test]
fn options_scope_count_equal_to_total_fields_is_valid() {
    let fields = [field(1), field(2)];
    let d = TemplateDefinition::new(TemplateKind::Options, 2, &fields, 8).unwrap();
    assert_eq!(d.kind(), TemplateKind::Options);
    assert_eq!(d.scope_field_count(), 2);
    assert_eq!(d.fields(), &fields);
}

#[test]
fn options_scope_count_above_total_fields_is_rejected() {
    for count in [3, u16::MAX] {
        assert_eq!(
            TemplateDefinition::new(TemplateKind::Options, count, &[field(1), field(2)], 8),
            Err(TemplateRegistryError::InvalidScopeFieldCount {
                kind: TemplateKind::Options,
                count,
                total: 2,
            })
        );
    }
}

#[test]
fn empty_options_definitions_remain_rejected_for_zero_and_nonzero_scope() {
    for count in [0, 1, u16::MAX] {
        assert_eq!(
            TemplateDefinition::new(TemplateKind::Options, count, &[], 8),
            Err(TemplateRegistryError::EmptyDefinition)
        );
    }
}

#[test]
fn nonempty_data_definition_with_zero_scope_remains_valid() {
    let d = TemplateDefinition::new(TemplateKind::Data, 0, &[field(1)], 8).unwrap();
    assert_eq!(d.kind(), TemplateKind::Data);
    assert_eq!(d.scope_field_count(), 0);
    assert_eq!(d.fields(), &[field(1)]);
}

#[test]
fn data_definition_with_nonzero_scope_remains_rejected() {
    for count in [1, 2, u16::MAX] {
        assert_eq!(
            TemplateDefinition::new(TemplateKind::Data, count, &[field(1), field(2)], 8),
            Err(TemplateRegistryError::InvalidScopeFieldCount {
                kind: TemplateKind::Data,
                count,
                total: 2,
            })
        );
    }
}

#[test]
fn zero_scope_options_identical_refresh_keeps_generation_and_extends_ttl() {
    let k = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 300);
    let d = zero_scope_options(&[field(1), field(2)]);
    let mut r = registry();
    assert_eq!(r.insert(k.clone(), d.clone(), 100).unwrap().generation, 1);
    let transition = r.insert(k.clone(), d.clone(), 105).unwrap();
    assert_eq!(
        transition,
        TemplateTransition {
            kind: TemplateTransitionKind::Refreshed,
            generation: 1,
            expired_pruned: 0,
        }
    );
    let e = found(&mut r, &k, 106);
    assert_eq!(e.definition(), &d);
    assert_eq!(
        (e.first_seen_ns(), e.last_seen_ns(), e.expires_at_ns()),
        (100, 105, 115)
    );
    assert_eq!(r.len(), 1);
    assert_timeline_bound(&r);
}

#[test]
fn zero_scope_options_changed_definition_increments_generation() {
    let k = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 300);
    let mut r = registry();
    r.insert(k.clone(), zero_scope_options(&[field(1)]), 100)
        .unwrap();
    for (time, fields, generation) in [(101, vec![field(2)], 2), (102, vec![field(2), field(1)], 3)]
    {
        let d = zero_scope_options(&fields);
        let transition = r.insert(k.clone(), d.clone(), time).unwrap();
        assert_eq!(
            (transition.kind, transition.generation),
            (TemplateTransitionKind::Replaced, generation)
        );
        let e = found(&mut r, &k, time);
        assert_eq!(e.definition(), &d);
        assert_eq!(e.first_seen_ns(), 100);
        assert_eq!(e.last_seen_ns(), time);
        assert_eq!(e.expires_at_ns(), time + 10);
    }
    assert_eq!(r.len(), 1);
    assert_timeline_bound(&r);
}

#[test]
fn zero_scope_options_withdrawal_reinsert_resets_lifetime_and_watermark() {
    let k = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 300);
    let mut r = registry();
    r.insert(k.clone(), zero_scope_options(&[field(1)]), 100)
        .unwrap();
    r.insert(k.clone(), zero_scope_options(&[field(2)]), 101)
        .unwrap();
    assert_eq!(
        r.withdraw(&k, 102).unwrap(),
        TemplateWithdrawal::Withdrawn { generation: 2 }
    );
    assert!(r.is_empty());
    assert_eq!(r.timeline_count(), 0);
    assert_eq!(r.timeline_last_source_time_ns(k.timeline()), None);
    let d = zero_scope_options(&[field(3)]);
    let transition = r.insert(k.clone(), d.clone(), 10).unwrap();
    assert_eq!(
        (transition.kind, transition.generation),
        (TemplateTransitionKind::Inserted, 1)
    );
    let e = found(&mut r, &k, 10);
    assert_eq!(e.definition(), &d);
    assert_eq!(
        (e.first_seen_ns(), e.last_seen_ns(), e.expires_at_ns()),
        (10, 10, 20)
    );
    assert_timeline_bound(&r);
}

#[test]
fn zero_scope_options_expire_at_exact_boundary_without_tombstones() {
    let k = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 300);
    let mut r = registry();
    r.insert(k.clone(), zero_scope_options(&[field(1)]), 100)
        .unwrap();
    assert_eq!(found(&mut r, &k, 109).expires_at_ns(), 110);
    assert_eq!(
        r.lookup(&k, 110).unwrap(),
        TemplateLookup::Expired {
            generation: 1,
            expires_at_ns: 110,
        }
    );
    assert!(r.is_empty());
    assert_eq!(r.timeline_count(), 0);
    assert_eq!(r.lookup(&k, 111).unwrap(), TemplateLookup::Unknown);
    assert_eq!(r.timeline_count(), 0);
    assert_eq!(
        r.insert(k.clone(), zero_scope_options(&[field(2)]), 50)
            .unwrap()
            .generation,
        1
    );
    assert_eq!(found(&mut r, &k, 50).first_seen_ns(), 50);
    assert_timeline_bound(&r);
}

#[test]
fn zero_scope_options_storage_is_protocol_neutral_with_isolated_namespaces() {
    // Storage acceptance here does not assert IPFIX wire-template legality.
    let a = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 300);
    let b = key_for(TemplateProtocol::Ipfix, "e", "s", 1, 300);
    let mut r = registry();
    let original = zero_scope_options(&[field(1)]);
    r.insert(a.clone(), original.clone(), 100).unwrap();
    r.insert(b.clone(), original.clone(), 1).unwrap();
    r.insert(a.clone(), zero_scope_options(&[field(2)]), 101)
        .unwrap();
    assert_eq!(found(&mut r, &a, 101).generation(), 2);
    let e = found(&mut r, &b, 1);
    assert_eq!(e.definition(), &original);
    assert_eq!(e.generation(), 1);
    assert_eq!(e.expires_at_ns(), 11);
    assert_eq!(r.timeline_last_source_time_ns(b.timeline()), Some(1));
    assert_eq!(r.len(), 2);
    assert_timeline_bound(&r);
}

#[test]
fn v9_zero_scope_options_do_not_modify_existing_ipfix_definition_or_timeline() {
    let v9 = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 300);
    let ipfix = key_for(TemplateProtocol::Ipfix, "e", "s", 1, 300);
    let ipfix_definition =
        TemplateDefinition::new(TemplateKind::Options, 1, &[field(1), field(2)], 8).unwrap();
    let mut r = registry();
    r.insert(ipfix.clone(), ipfix_definition, 1).unwrap();
    let before = found(&mut r, &ipfix, 1);
    r.insert(v9.clone(), zero_scope_options(&[field(3)]), 5000)
        .unwrap();
    assert_eq!(found(&mut r, &ipfix, 1), before);
    r.withdraw(&v9, 5001).unwrap();
    assert_eq!(found(&mut r, &ipfix, 1), before);
    assert_eq!(r.timeline_last_source_time_ns(ipfix.timeline()), Some(1));
    assert_eq!(r.len(), 1);
    assert_timeline_bound(&r);
}

#[test]
fn zero_scope_options_registry_revalidates_field_bound_before_any_mutation() {
    let mut r = TemplateRegistry::new(
        TemplateRegistryConfig::new(2, 1, 64)
            .unwrap()
            .with_ttl_ns(10)
            .unwrap(),
    );
    let a = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 300);
    let b = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 301);
    r.insert(a, zero_scope_options(&[field(1)]), 0).unwrap();
    let before = r.clone();
    assert_eq!(
        r.insert(b, zero_scope_options(&[field(1), field(2)]), 10),
        Err(TemplateRegistryError::TooManyFields { count: 2, limit: 1 })
    );
    assert_eq!(r, before);
}

#[test]
fn zero_scope_options_capacity_failure_is_atomic_without_eviction() {
    let mut r = TemplateRegistry::new(
        TemplateRegistryConfig::new(1, 8, 64)
            .unwrap()
            .with_ttl_ns(10)
            .unwrap(),
    );
    let a = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 300);
    let b = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 301);
    let d = zero_scope_options(&[field(1)]);
    r.insert(a.clone(), d.clone(), 100).unwrap();
    let before = r.clone();
    assert_eq!(
        r.insert(b, zero_scope_options(&[field(2)]), 101),
        Err(TemplateRegistryError::CapacityExceeded { limit: 1 })
    );
    assert_eq!(r, before);
    assert_eq!(
        r.insert(a, d, 101).unwrap().kind,
        TemplateTransitionKind::Refreshed
    );
    assert_timeline_bound(&r);
}

#[test]
fn zero_scope_options_time_regression_on_all_operations_is_atomic() {
    let k = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 300);
    let mut r = registry();
    let d = zero_scope_options(&[field(1)]);
    r.insert(k.clone(), d.clone(), 100).unwrap();
    let before = r.clone();
    let expected = TemplateRegistryError::SourceTimeRegression {
        previous_ns: 100,
        provided_ns: 99,
    };
    assert_eq!(r.insert(k.clone(), d, 99), Err(expected.clone()));
    assert_eq!(r, before);
    assert_eq!(r.lookup(&k, 99), Err(expected.clone()));
    assert_eq!(r, before);
    assert_eq!(r.withdraw(&k, 99), Err(expected.clone()));
    assert_eq!(r, before);
    assert_eq!(r.expire_timeline(k.timeline(), 99), Err(expected));
    assert_eq!(r, before);
}

#[test]
fn zero_scope_options_identity_bound_is_revalidated_before_insertion() {
    let mut r = TemplateRegistry::new(TemplateRegistryConfig::new(2, 8, 3).unwrap());
    let a = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 300);
    r.insert(a, zero_scope_options(&[field(1)]), 0).unwrap();
    let invalid = key_for(TemplateProtocol::NetFlowV9, "long-exporter", "s", 1, 301);
    let before = r.clone();
    assert_eq!(
        r.insert(invalid, zero_scope_options(&[field(2)]), u64::MAX),
        Err(TemplateRegistryError::InvalidIdentity {
            field: "exporter_id",
            kind: IdentityErrorKind::TooLong { limit_bytes: 3 },
        })
    );
    assert_eq!(r, before);
}

#[test]
fn zero_scope_options_expiry_overflow_on_insert_and_replacement_is_atomic() {
    let a = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 300);
    let b = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 301);
    let mut r = registry();
    r.insert(a.clone(), zero_scope_options(&[field(1)]), 100)
        .unwrap();
    let before = r.clone();
    for k in [a, b] {
        assert_eq!(
            r.insert(k, zero_scope_options(&[field(2)]), u64::MAX),
            Err(TemplateRegistryError::ExpiryOverflow)
        );
        assert_eq!(r, before);
    }
}

#[test]
fn zero_scope_options_scope_changes_and_refresh_replay_deterministically() {
    fn run() -> (Vec<TemplateTransition>, TemplateRegistry) {
        let k = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 300);
        let mut r = registry();
        let mut events = Vec::new();
        for (time, scope, generation) in [(10, 0, 1), (11, 1, 2), (12, 2, 3), (13, 0, 4)] {
            let d = TemplateDefinition::new(TemplateKind::Options, scope, &[field(1), field(2)], 8)
                .unwrap();
            let transition = r.insert(k.clone(), d, time).unwrap();
            assert_eq!(transition.generation, generation);
            events.push(transition);
        }
        let refresh = r
            .insert(k.clone(), zero_scope_options(&[field(1), field(2)]), 14)
            .unwrap();
        assert_eq!(
            (refresh.kind, refresh.generation),
            (TemplateTransitionKind::Refreshed, 4)
        );
        events.push(refresh);
        let e = found(&mut r, &k, 14);
        assert_eq!(e.definition().scope_field_count(), 0);
        assert_eq!(
            (e.first_seen_ns(), e.last_seen_ns(), e.expires_at_ns()),
            (10, 14, 24)
        );
        assert_timeline_bound(&r);
        (events, r)
    }
    let expected = run();
    for _ in 0..20 {
        assert_eq!(run(), expected);
    }
}

#[test]
fn protocol_namespaces_are_independent() {
    let a = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 256);
    let b = key_for(TemplateProtocol::Ipfix, "e", "s", 1, 256);
    let mut r = registry();
    r.insert(a.clone(), definition(1), 0).unwrap();
    r.insert(b.clone(), definition(1), 0).unwrap();
    r.insert(a.clone(), definition(2), 1).unwrap();
    assert_eq!(found(&mut r, &a, 1).generation(), 2);
    assert_eq!(found(&mut r, &b, 1).definition(), &definition(1));
    assert_eq!(r.len(), 2);
}

#[test]
fn exporters_are_independent_even_with_same_session_label() {
    let a = key_for(TemplateProtocol::Ipfix, "exporter-a", "s", 1, 256);
    let b = key_for(TemplateProtocol::Ipfix, "exporter-b", "s", 1, 256);
    let mut r = registry();
    r.insert(a.clone(), definition(1), 0).unwrap();
    r.insert(b.clone(), definition(1), 0).unwrap();
    r.insert(a, definition(2), 1).unwrap();
    assert_eq!(found(&mut r, &b, 1).generation(), 1);
}

#[test]
fn session_epochs_are_independent_for_both_protocols() {
    for protocol in [TemplateProtocol::NetFlowV9, TemplateProtocol::Ipfix] {
        let mut r = registry();
        let a = key_for(protocol, "e", "epoch-1", 1, 256);
        let b = key_for(protocol, "e", "epoch-2", 1, 256);
        r.insert(a.clone(), definition(1), 0).unwrap();
        r.insert(b.clone(), definition(2), 0).unwrap();
        r.withdraw(&a, 1).unwrap();
        assert_eq!(found(&mut r, &b, 1).definition(), &definition(2));
    }
}

#[test]
fn domains_zero_and_max_are_isolated_for_both_protocols() {
    for protocol in [TemplateProtocol::NetFlowV9, TemplateProtocol::Ipfix] {
        let mut r = registry();
        let a = key_for(protocol, "e", "s", 0, 256);
        let b = key_for(protocol, "e", "s", u32::MAX, 256);
        r.insert(a.clone(), definition(1), 0).unwrap();
        r.insert(b.clone(), definition(2), 0).unwrap();
        r.insert(a, definition(3), 1).unwrap();
        assert_eq!(found(&mut r, &b, 1).definition(), &definition(2));
    }
}

#[test]
fn template_ids_are_independent() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    r.insert(key(u16::MAX), definition(2), 0).unwrap();
    assert_eq!(found(&mut r, &key(256), 0).definition(), &definition(1));
    assert_eq!(
        found(&mut r, &key(u16::MAX), 0).definition(),
        &definition(2)
    );
}

#[test]
fn template_id_boundaries_are_common_to_both_protocols() {
    for protocol in [TemplateProtocol::NetFlowV9, TemplateProtocol::Ipfix] {
        for id in [0, 1, 2, 3, 255] {
            assert_eq!(
                TemplateKey::new(
                    protocol,
                    TransportSessionKey::new("e", "s", 8).unwrap(),
                    0,
                    id
                ),
                Err(TemplateRegistryError::InvalidTemplateId { template_id: id })
            );
        }
        for id in [256, u16::MAX] {
            assert_eq!(key_for(protocol, "e", "s", 0, id).template_id(), id);
        }
    }
}

#[test]
fn structured_session_components_do_not_collide_by_concatenation() {
    let a = key_for(TemplateProtocol::Ipfix, "a:b", "c", 0, 256);
    let b = key_for(TemplateProtocol::Ipfix, "a", "b:c", 0, 256);
    assert_ne!(a, b);
    let mut r = registry();
    r.insert(a, definition(1), 0).unwrap();
    r.insert(b, definition(2), 0).unwrap();
    assert_eq!(r.len(), 2);
}

#[test]
fn default_ttl_is_approved_1800_seconds_in_integer_nanoseconds() {
    let c = TemplateRegistryConfig::new(1, 1, 1).unwrap();
    assert_eq!(c.ttl_ns(), 1800 * 1_000_000_000);
    assert_eq!(c.ttl_ns(), DEFAULT_TEMPLATE_TTL_NS);
    let mut r = TemplateRegistry::new(c);
    let k = key_for(TemplateProtocol::Ipfix, "e", "s", 0, 256);
    r.insert(k.clone(), definition(1), 0).unwrap();
    assert!(matches!(
        r.lookup(&k, DEFAULT_TEMPLATE_TTL_NS - 1).unwrap(),
        TemplateLookup::Found(_)
    ));
    assert!(matches!(
        r.lookup(&k, DEFAULT_TEMPLATE_TTL_NS).unwrap(),
        TemplateLookup::Expired { .. }
    ));
}

#[test]
fn ttl_before_boundary_is_active() {
    let mut r = registry();
    r.insert(key(256), definition(1), 100).unwrap();
    assert!(matches!(
        r.lookup(&key(256), 109).unwrap(),
        TemplateLookup::Found(_)
    ));
}

#[test]
fn ttl_exact_boundary_is_expired_and_removed() {
    let mut r = registry();
    r.insert(key(256), definition(1), 100).unwrap();
    assert_eq!(
        r.lookup(&key(256), 110).unwrap(),
        TemplateLookup::Expired {
            generation: 1,
            expires_at_ns: 110
        }
    );
    assert!(r.is_empty());
    assert_eq!(r.lookup(&key(256), 110).unwrap(), TemplateLookup::Unknown);
}

#[test]
fn ttl_after_boundary_is_expired() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    assert!(matches!(
        r.lookup(&key(256), 11).unwrap(),
        TemplateLookup::Expired { .. }
    ));
}

#[test]
fn refresh_extends_ttl_but_lookup_does_not() {
    let mut r = registry();
    r.insert(key(256), definition(1), 100).unwrap();
    assert_eq!(found(&mut r, &key(256), 105).expires_at_ns(), 110);
    r.insert(key(256), definition(1), 109).unwrap();
    assert_eq!(found(&mut r, &key(256), 110).expires_at_ns(), 119);
    assert!(matches!(
        r.lookup(&key(256), 119).unwrap(),
        TemplateLookup::Expired { .. }
    ));
}

#[test]
fn configurable_ttl_one_nanosecond_has_exact_boundary() {
    let mut r = TemplateRegistry::new(config().with_ttl_ns(1).unwrap());
    r.insert(key(256), definition(1), 0).unwrap();
    assert!(matches!(
        r.lookup(&key(256), 0).unwrap(),
        TemplateLookup::Found(_)
    ));
    assert!(matches!(
        r.lookup(&key(256), 1).unwrap(),
        TemplateLookup::Expired { .. }
    ));
}

#[test]
fn explicit_expire_prunes_only_expired_entries() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    r.insert(key(257), definition(2), 5).unwrap();
    assert_eq!(r.expire_timeline(key(256).timeline(), 10).unwrap(), 1);
    assert_eq!(r.len(), 1);
    assert_eq!(r.lookup(&key(256), 10).unwrap(), TemplateLookup::Unknown);
    assert!(matches!(
        r.lookup(&key(257), 10).unwrap(),
        TemplateLookup::Found(_)
    ));
    assert_eq!(r.expire_timeline(key(256).timeline(), 15).unwrap(), 1);
    assert_eq!(r.expire_timeline(key(256).timeline(), 15).unwrap(), 0);
}

#[test]
fn time_regression_on_every_operation_preserves_entire_state() {
    let mut r = registry();
    r.insert(key(256), definition(1), 100).unwrap();
    let before = r.clone();
    let error = TemplateRegistryError::SourceTimeRegression {
        previous_ns: 100,
        provided_ns: 99,
    };
    assert_eq!(r.insert(key(256), definition(2), 99), Err(error.clone()));
    assert_eq!(r, before);
    assert_eq!(r.lookup(&key(256), 99), Err(error.clone()));
    assert_eq!(r, before);
    assert_eq!(r.withdraw(&key(256), 99), Err(error.clone()));
    assert_eq!(r, before);
    assert_eq!(r.expire_timeline(key(256).timeline(), 99), Err(error));
    assert_eq!(r, before);
}

#[test]
fn lookup_watermark_prevents_stale_refresh_until_empty_timeline_lifetime_ends() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    found(&mut r, &key(256), 9);
    let before = r.clone();
    assert!(matches!(
        r.insert(key(256), definition(1), 8),
        Err(TemplateRegistryError::SourceTimeRegression { .. })
    ));
    assert_eq!(r, before);
    r.expire_timeline(key(256).timeline(), 10).unwrap();
    assert_eq!(r.timeline_last_source_time_ns(key(256).timeline()), None);
    assert_eq!(r.insert(key(256), definition(1), 9).unwrap().generation, 1);
}

#[test]
fn equal_source_timestamps_are_valid() {
    let mut r = registry();
    r.insert(key(256), definition(1), 1).unwrap();
    r.insert(key(256), definition(2), 1).unwrap();
    found(&mut r, &key(256), 1);
    assert_eq!(r.expire_timeline(key(256).timeline(), 1).unwrap(), 0);
    assert!(matches!(
        r.withdraw(&key(256), 1).unwrap(),
        TemplateWithdrawal::Withdrawn { .. }
    ));
}

#[test]
fn withdrawal_existing_and_missing_are_explicit() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    assert_eq!(
        r.withdraw(&key(256), 1).unwrap(),
        TemplateWithdrawal::Withdrawn { generation: 1 }
    );
    assert_eq!(
        r.withdraw(&key(256), 1).unwrap(),
        TemplateWithdrawal::Unknown
    );
    assert!(r.is_empty());
}

#[test]
fn withdrawal_expired_entry_is_distinct() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    assert_eq!(
        r.withdraw(&key(256), 10).unwrap(),
        TemplateWithdrawal::Expired { generation: 1 }
    );
    assert!(r.is_empty());
}

#[test]
fn reinsert_after_withdrawal_starts_new_lifetime_generation_one() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    r.insert(key(256), definition(2), 1).unwrap();
    r.withdraw(&key(256), 2).unwrap();
    assert_eq!(r.insert(key(256), definition(3), 3).unwrap().generation, 1);
    assert_eq!(found(&mut r, &key(256), 3).first_seen_ns(), 3);
}

#[test]
fn reinsert_at_expiry_starts_new_lifetime_generation_one() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    r.insert(key(256), definition(2), 1).unwrap();
    let t = r.insert(key(256), definition(2), 11).unwrap();
    assert_eq!(
        t,
        TemplateTransition {
            kind: TemplateTransitionKind::Inserted,
            generation: 1,
            expired_pruned: 1
        }
    );
    assert_eq!(found(&mut r, &key(256), 11).first_seen_ns(), 11);
}

#[test]
fn capacity_exact_boundary_is_allowed_and_overflow_is_atomic() {
    let mut r = registry();
    for id in 256..260 {
        r.insert(key(id), definition(1), 0).unwrap();
    }
    assert_eq!(r.len(), r.config().max_entries());
    let before = r.clone();
    assert_eq!(
        r.insert(key(260), definition(1), 1),
        Err(TemplateRegistryError::CapacityExceeded { limit: 4 })
    );
    assert_eq!(r, before);
}

#[test]
fn replacement_and_refresh_succeed_at_full_capacity() {
    let mut r = TemplateRegistry::new(
        TemplateRegistryConfig::new(1, 8, 64)
            .unwrap()
            .with_ttl_ns(10)
            .unwrap(),
    );
    r.insert(key(256), definition(1), 0).unwrap();
    assert_eq!(
        r.insert(key(256), definition(1), 1).unwrap().kind,
        TemplateTransitionKind::Refreshed
    );
    assert_eq!(
        r.insert(key(256), definition(2), 2).unwrap().kind,
        TemplateTransitionKind::Replaced
    );
    assert_eq!(r.len(), 1);
}

#[test]
fn expired_entries_are_pruned_before_capacity_decision_without_live_eviction() {
    let mut r = TemplateRegistry::new(
        TemplateRegistryConfig::new(2, 8, 64)
            .unwrap()
            .with_ttl_ns(10)
            .unwrap(),
    );
    r.insert(key(256), definition(1), 0).unwrap();
    r.insert(key(257), definition(2), 5).unwrap();
    assert_eq!(
        r.insert(key(258), definition(3), 10)
            .unwrap()
            .expired_pruned,
        1
    );
    assert_eq!(r.len(), 2);
    assert_eq!(r.lookup(&key(256), 10).unwrap(), TemplateLookup::Unknown);
    assert_eq!(found(&mut r, &key(257), 10).definition(), &definition(2));
}

#[test]
fn failed_replacement_validation_keeps_old_definition_and_expired_neighbors() {
    let mut r = TemplateRegistry::new(
        TemplateRegistryConfig::new(2, 1, 64)
            .unwrap()
            .with_ttl_ns(10)
            .unwrap(),
    );
    r.insert(key(257), definition(1), 0).unwrap();
    r.insert(key(256), definition(2), 5).unwrap();
    let before = r.clone();
    let too_large =
        TemplateDefinition::new(TemplateKind::Data, 0, &[field(3), field(4)], 2).unwrap();
    assert_eq!(
        r.insert(key(256), too_large, 10),
        Err(TemplateRegistryError::TooManyFields { count: 2, limit: 1 })
    );
    assert_eq!(r, before);
}

#[test]
fn oversized_template_rejected_before_owned_definition_allocation() {
    let fields = vec![field(1); 100_000];
    assert_eq!(
        TemplateDefinition::new(TemplateKind::Data, 0, &fields, 8),
        Err(TemplateRegistryError::TooManyFields {
            count: 100_000,
            limit: 8
        })
    );
    assert!(TemplateDefinition::new(TemplateKind::Data, 0, &[field(1); 8], 8).is_ok());
}

#[test]
fn zero_field_templates_rejected_not_treated_as_withdrawal() {
    for kind in [TemplateKind::Data, TemplateKind::Options] {
        assert_eq!(
            TemplateDefinition::new(kind, 0, &[], 8),
            Err(TemplateRegistryError::EmptyDefinition)
        );
    }
}

#[test]
fn config_requires_explicit_positive_resource_bounds_and_ttl() {
    for bounds in [(0, 1, 1), (1, 0, 1), (1, 1, 0)] {
        assert!(matches!(
            TemplateRegistryConfig::new(bounds.0, bounds.1, bounds.2),
            Err(TemplateRegistryError::InvalidConfig { .. })
        ));
    }
    assert_eq!(
        config().with_ttl_ns(0),
        Err(TemplateRegistryError::InvalidConfig { field: "ttl_ns" })
    );
    assert_eq!(config().max_fields_per_template(), 8);
    assert_eq!(config().max_identity_bytes(), 64);
}

#[test]
fn config_rejects_unrepresentable_budgets_and_field_count() {
    assert!(TemplateRegistryConfig::new(usize::MAX, 1, 1).is_err());
    assert!(TemplateRegistryConfig::new(1, 1, usize::MAX).is_err());
    assert!(TemplateRegistryConfig::new(1, usize::from(u16::MAX) + 1, 1).is_err());
    assert!(TemplateRegistryConfig::new(1, usize::from(u16::MAX), 1).is_ok());
    assert!(TemplateDefinition::new(TemplateKind::Data, 0, &[field(1)], 0).is_err());
    assert!(TemplateDefinition::new(TemplateKind::Data, 0, &[field(1)], usize::MAX).is_err());
}

#[test]
fn session_identity_rejects_empty_overlimit_non_ascii_and_path_labels() {
    for (exporter, session) in [
        ("", "s"),
        ("e", ""),
        ("long", "s"),
        ("e", "long"),
        ("é", "s"),
        ("e", "a/b"),
        ("e", "a\\b"),
        ("e", "a\nb"),
        ("e", "a b"),
    ] {
        assert!(TransportSessionKey::new(exporter, session, 3).is_err());
    }
    assert!(TransportSessionKey::new("e", "s", 0).is_err());
    let s = TransportSessionKey::new("e.:", "s_-", 3).unwrap();
    assert_eq!((s.exporter_id(), s.session_id()), ("e.:", "s_-"));
}

#[test]
fn registry_revalidates_identity_against_its_own_bound_on_all_key_operations() {
    for k in [
        key_for(TemplateProtocol::Ipfix, "long-exporter", "s", 0, 256),
        key_for(TemplateProtocol::Ipfix, "e", "long-session", 0, 256),
    ] {
        let mut r = TemplateRegistry::new(TemplateRegistryConfig::new(1, 8, 3).unwrap());
        let before = r.clone();
        assert!(matches!(
            r.insert(k.clone(), definition(1), 0),
            Err(TemplateRegistryError::InvalidIdentity { .. })
        ));
        assert_eq!(r, before);
        assert!(matches!(
            r.lookup(&k, 0),
            Err(TemplateRegistryError::InvalidIdentity { .. })
        ));
        assert_eq!(r, before);
        assert!(matches!(
            r.withdraw(&k, 0),
            Err(TemplateRegistryError::InvalidIdentity { .. })
        ));
        assert_eq!(r, before);
    }
}

#[test]
fn error_messages_do_not_echo_hostile_source_strings() {
    let secret = "secret-session-name-too-long";
    let err = TransportSessionKey::new("e", secret, 3).unwrap_err();
    assert!(!err.to_string().contains(secret));
    assert!(!format!("{err:?}").contains(secret));
}

#[test]
fn expiry_overflow_on_new_insert_and_replacement_is_atomic() {
    let mut r = registry();
    let empty = r.clone();
    assert_eq!(
        r.insert(key(256), definition(1), u64::MAX),
        Err(TemplateRegistryError::ExpiryOverflow)
    );
    assert_eq!(r, empty);
    r.insert(key(256), definition(1), u64::MAX - 10).unwrap();
    let before = r.clone();
    assert_eq!(
        r.insert(key(256), definition(2), u64::MAX - 9),
        Err(TemplateRegistryError::ExpiryOverflow)
    );
    assert_eq!(r, before);
    assert!(matches!(
        r.lookup(&key(256), u64::MAX - 1).unwrap(),
        TemplateLookup::Found(_)
    ));
    assert_eq!(r.expire_timeline(key(256).timeline(), u64::MAX).unwrap(), 1);
}

#[test]
fn maximum_ttl_and_source_time_zero_are_supported_without_wrapping() {
    let mut r = TemplateRegistry::new(config().with_ttl_ns(u64::MAX).unwrap());
    r.insert(key(256), definition(1), 0).unwrap();
    assert_eq!(
        found(&mut r, &key(256), u64::MAX - 1).expires_at_ns(),
        u64::MAX
    );
    assert!(matches!(
        r.lookup(&key(256), u64::MAX).unwrap(),
        TemplateLookup::Expired { .. }
    ));
}

#[test]
fn ordered_audit_view_is_independent_of_insertion_order() {
    let mut a = registry();
    let mut b = registry();
    for id in [259, 257, 258, 256] {
        a.insert(key(id), definition(id), 0).unwrap();
    }
    for id in [256, 258, 257, 259] {
        b.insert(key(id), definition(id), 0).unwrap();
    }
    assert_eq!(
        a.entries()
            .map(|(k, _)| k.template_id())
            .collect::<Vec<_>>(),
        vec![256, 257, 258, 259]
    );
    assert_eq!(
        a.entries().collect::<Vec<_>>(),
        b.entries().collect::<Vec<_>>()
    );
}

#[test]
fn timeless_audit_view_does_not_pretend_to_be_active_lookup() {
    let mut r = registry();
    r.insert(key(256), definition(1), 0).unwrap();
    r.lookup(&key(257), 10).unwrap();
    assert_eq!(r.entries().next().unwrap().1.expires_at_ns(), 10);
    assert!(matches!(
        r.lookup(&key(256), 10).unwrap(),
        TemplateLookup::Expired { .. }
    ));
}

fn replay() -> (Vec<String>, TemplateRegistry) {
    let mut r = registry();
    let mut transitions = Vec::new();
    transitions.push(format!("{:?}", r.insert(key(256), definition(1), 0)));
    transitions.push(format!("{:?}", r.insert(key(256), definition(1), 1)));
    transitions.push(format!("{:?}", r.insert(key(256), definition(2), 2)));
    transitions.push(format!("{:?}", r.insert(key(257), definition(3), 3)));
    transitions.push(format!("{:?}", r.lookup(&key(256), 11)));
    transitions.push(format!("{:?}", r.expire_timeline(key(256).timeline(), 12)));
    transitions.push(format!("{:?}", r.lookup(&key(256), 12)));
    transitions.push(format!("{:?}", r.withdraw(&key(257), 12)));
    transitions.push(format!("{:?}", r.insert(key(256), definition(4), 12)));
    transitions.push(format!("{:?}", r.insert(key(256), definition(5), 11)));
    (transitions, r)
}

#[test]
fn replay_decisions_generations_expiry_and_ordered_snapshot_are_identical() {
    let expected = replay();
    for _ in 0..20 {
        assert_eq!(replay(), expected);
    }
}

#[test]
fn many_isolated_sessions_domains_and_unknown_lookups_remain_bounded() {
    let c = TemplateRegistryConfig::new(64, 8, 64)
        .unwrap()
        .with_ttl_ns(10)
        .unwrap();
    let mut r = TemplateRegistry::new(c);
    for index in 0..2000_u32 {
        let k = key_for(
            if index % 2 == 0 {
                TemplateProtocol::Ipfix
            } else {
                TemplateProtocol::NetFlowV9
            },
            "e",
            &format!("session-{index}"),
            index,
            256,
        );
        let result = r.insert(k, definition(1), 0);
        if index < 64 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(TemplateRegistryError::CapacityExceeded { .. })
            ));
        }
        assert!(r.len() <= 64);
    }
    let before = r
        .entries()
        .map(|(k, e)| (k.clone(), e.clone()))
        .collect::<Vec<_>>();
    for index in 2000..4000 {
        assert_eq!(
            r.lookup(
                &key_for(TemplateProtocol::Ipfix, "e", "unknown", index, 256),
                0
            )
            .unwrap(),
            TemplateLookup::Unknown
        );
    }
    assert_eq!(
        r.entries()
            .map(|(k, e)| (k.clone(), e.clone()))
            .collect::<Vec<_>>(),
        before
    );
    let timelines = r
        .entries()
        .map(|(k, _)| k.timeline().clone())
        .collect::<Vec<_>>();
    let removed: usize = timelines
        .iter()
        .map(|timeline| r.expire_timeline(timeline, 10).unwrap())
        .sum();
    assert_eq!(removed, 64);
    assert_eq!(r.timeline_count(), 0);
}

fn assert_timeline_bound(r: &TemplateRegistry) {
    let represented = r
        .entries()
        .map(|(k, _)| k.timeline())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(r.timeline_count(), represented.len());
    assert!(r.timeline_count() <= r.len());
    assert!(r.len() <= r.config().max_entries());
    for (k, entry) in r.entries() {
        assert!(r.timeline_last_source_time_ns(k.timeline()).unwrap() >= entry.last_seen_ns());
    }
}

#[test]
fn default_configuration_matches_exact_human_approved_policies_and_is_valid() {
    let c = TemplateRegistryConfig::default();
    assert_eq!(DEFAULT_TEMPLATE_TTL_SECONDS, 1800);
    assert_eq!(DEFAULT_TEMPLATE_TTL_NS, 1_800_000_000_000);
    assert_eq!(DEFAULT_MAX_TEMPLATE_ENTRIES, 4096);
    assert_eq!(DEFAULT_MAX_FIELDS_PER_TEMPLATE, 256);
    assert_eq!(DEFAULT_MAX_TEMPLATE_IDENTITY_BYTES, 256);
    assert_eq!(
        (
            c.max_entries(),
            c.max_fields_per_template(),
            c.max_identity_bytes(),
            c.ttl_ns()
        ),
        (4096, 256, 256, 1_800_000_000_000)
    );
    assert_eq!(c, TemplateRegistryConfig::new(4096, 256, 256).unwrap());
    let mut r = TemplateRegistry::new(c);
    r.insert(key(256), definition(1), 0).unwrap();
    assert_timeline_bound(&r);
}

#[test]
fn each_default_can_be_overridden_through_validated_configuration() {
    let d = TemplateRegistryConfig::default();
    for c in [
        TemplateRegistryConfig::new(7, d.max_fields_per_template(), d.max_identity_bytes())
            .unwrap(),
        TemplateRegistryConfig::new(d.max_entries(), 17, d.max_identity_bytes()).unwrap(),
        TemplateRegistryConfig::new(d.max_entries(), d.max_fields_per_template(), 31).unwrap(),
        d.with_ttl_ns(19).unwrap(),
    ] {
        assert_ne!(c, d);
    }
    let c = TemplateRegistryConfig::new(7, 17, 31)
        .unwrap()
        .with_ttl_ns(19)
        .unwrap();
    assert_eq!(
        (
            c.max_entries(),
            c.max_fields_per_template(),
            c.max_identity_bytes(),
            c.ttl_ns()
        ),
        (7, 17, 31, 19)
    );
    assert!(TemplateRegistryConfig::new(4097, 257, 257).is_ok());
}

#[test]
fn default_field_bound_is_enforced_and_not_a_protocol_maximum() {
    let fields = vec![field(1); 257];
    let c = TemplateRegistryConfig::default();
    assert!(TemplateDefinition::new(
        TemplateKind::Data,
        0,
        &fields[..256],
        c.max_fields_per_template()
    )
    .is_ok());
    assert!(matches!(
        TemplateDefinition::new(TemplateKind::Data, 0, &fields, c.max_fields_per_template()),
        Err(TemplateRegistryError::TooManyFields {
            count: 257,
            limit: 256
        })
    ));
    let d = TemplateDefinition::new(TemplateKind::Data, 0, &fields, 257).unwrap();
    let mut r = TemplateRegistry::new(c);
    let before = r.clone();
    assert!(r.insert(key(256), d.clone(), 0).is_err());
    assert_eq!(r, before);
    let mut custom = TemplateRegistry::new(TemplateRegistryConfig::new(1, 257, 256).unwrap());
    custom.insert(key(256), d, 0).unwrap();
}

#[test]
fn default_identity_bound_applies_to_each_component_and_is_overrideable() {
    let exact = "a".repeat(256);
    let longer = "b".repeat(257);
    assert!(TransportSessionKey::new(&exact, &exact, DEFAULT_MAX_TEMPLATE_IDENTITY_BYTES).is_ok());
    assert!(TransportSessionKey::new(&longer, "s", DEFAULT_MAX_TEMPLATE_IDENTITY_BYTES).is_err());
    assert!(TransportSessionKey::new("e", &longer, DEFAULT_MAX_TEMPLATE_IDENTITY_BYTES).is_err());
    let session = TransportSessionKey::new(&longer, &longer, 257).unwrap();
    let k = TemplateKey::new(TemplateProtocol::Ipfix, session, 0, 256).unwrap();
    let mut r = TemplateRegistry::new(TemplateRegistryConfig::default());
    let before = r.clone();
    assert!(r.insert(k.clone(), definition(1), 0).is_err());
    assert_eq!(r, before);
    let mut custom = TemplateRegistry::new(TemplateRegistryConfig::new(1, 256, 257).unwrap());
    custom.insert(k, definition(1), 0).unwrap();
}

#[test]
fn timeline_key_is_structured_orderable_and_excludes_template_id() {
    let a = key(256);
    let b = key(257);
    assert_eq!(a.timeline(), b.timeline());
    let timeline =
        TemplateTimelineKey::new(a.protocol(), a.session().clone(), a.observation_scope_id());
    assert_eq!(&timeline, a.timeline());
    assert_eq!(
        (
            timeline.protocol(),
            timeline.session().exporter_id(),
            timeline.observation_scope_id()
        ),
        (TemplateProtocol::Ipfix, "exporter-1", 1)
    );
    assert_ne!(a, b);
}

#[test]
fn cross_exporter_times_5000_then_3000_are_independent() {
    let a = key_for(TemplateProtocol::NetFlowV9, "exporter-A", "s", 1, 256);
    let b = key_for(TemplateProtocol::NetFlowV9, "exporter-B", "s", 1, 256);
    let mut r = registry();
    r.insert(a.clone(), definition(1), 5000).unwrap();
    r.insert(b.clone(), definition(2), 3000).unwrap();
    assert_eq!(found(&mut r, &a, 5000).definition(), &definition(1));
    assert_eq!(found(&mut r, &b, 3000).definition(), &definition(2));
    assert_timeline_bound(&r);
}

#[test]
fn cross_session_times_5000_then_3000_are_independent() {
    let a = key_for(TemplateProtocol::NetFlowV9, "e", "session-A", 1, 256);
    let b = key_for(TemplateProtocol::NetFlowV9, "e", "session-B", 1, 256);
    let mut r = registry();
    r.insert(a.clone(), definition(1), 5000).unwrap();
    r.insert(b.clone(), definition(2), 3000).unwrap();
    assert_eq!(r.timeline_last_source_time_ns(a.timeline()), Some(5000));
    assert_eq!(r.timeline_last_source_time_ns(b.timeline()), Some(3000));
    assert_timeline_bound(&r);
}

#[test]
fn cross_domain_times_9000_then_7000_are_independent() {
    let a = key_for(TemplateProtocol::Ipfix, "e", "s", 10, 256);
    let b = key_for(TemplateProtocol::Ipfix, "e", "s", 20, 256);
    let mut r = registry();
    r.insert(a.clone(), definition(1), 9000).unwrap();
    r.insert(b.clone(), definition(2), 7000).unwrap();
    assert_eq!(r.timeline_last_source_time_ns(a.timeline()), Some(9000));
    assert_eq!(r.timeline_last_source_time_ns(b.timeline()), Some(7000));
    assert_timeline_bound(&r);
}

#[test]
fn cross_protocol_times_5000_then_3000_are_independent() {
    let a = key_for(TemplateProtocol::NetFlowV9, "e", "s", 1, 256);
    let b = key_for(TemplateProtocol::Ipfix, "e", "s", 1, 256);
    let mut r = registry();
    r.insert(a.clone(), definition(1), 5000).unwrap();
    r.insert(b.clone(), definition(2), 3000).unwrap();
    assert_eq!(r.timeline_last_source_time_ns(a.timeline()), Some(5000));
    assert_eq!(r.timeline_last_source_time_ns(b.timeline()), Some(3000));
    assert_timeline_bound(&r);
}

#[test]
fn same_timeline_5000_then_3000_rejects_without_mutating_neighbor() {
    let a = key(256);
    let b = key_for(TemplateProtocol::NetFlowV9, "other", "s", 1, 256);
    let mut r = registry();
    r.insert(a.clone(), definition(1), 5000).unwrap();
    r.insert(b.clone(), definition(2), 1000).unwrap();
    let before = r.clone();
    assert_eq!(
        r.insert(a, definition(3), 3000),
        Err(TemplateRegistryError::SourceTimeRegression {
            previous_ns: 5000,
            provided_ns: 3000
        })
    );
    assert_eq!(r, before);
    assert_eq!(r.timeline_last_source_time_ns(b.timeline()), Some(1000));
}

#[test]
fn failed_capacity_and_validation_do_not_advance_any_timeline() {
    let mut r = TemplateRegistry::new(
        TemplateRegistryConfig::new(2, 1, 64)
            .unwrap()
            .with_ttl_ns(10)
            .unwrap(),
    );
    let a = key(256);
    let b = key_for(TemplateProtocol::NetFlowV9, "other", "s", 1, 256);
    r.insert(a.clone(), definition(1), 5000).unwrap();
    r.insert(b.clone(), definition(2), 1000).unwrap();
    let before = r.clone();
    assert_eq!(
        r.insert(key(257), definition(3), 5001),
        Err(TemplateRegistryError::CapacityExceeded { limit: 2 })
    );
    assert_eq!(r, before);
    let oversized =
        TemplateDefinition::new(TemplateKind::Data, 0, &[field(1), field(2)], 2).unwrap();
    assert!(r.insert(a, oversized, 5001).is_err());
    assert_eq!(r, before);
    assert_eq!(r.timeline_last_source_time_ns(b.timeline()), Some(1000));
    assert_timeline_bound(&r);
}

#[test]
fn unknown_lookup_advances_only_a_retained_timeline() {
    let mut r = registry();
    r.insert(key(256), definition(1), 100).unwrap();
    assert_eq!(r.lookup(&key(257), 105).unwrap(), TemplateLookup::Unknown);
    assert_eq!(
        r.timeline_last_source_time_ns(key(256).timeline()),
        Some(105)
    );
    assert_eq!(r.timeline_count(), 1);
    let before = r.clone();
    assert!(matches!(
        r.lookup(&key(257), 104),
        Err(TemplateRegistryError::SourceTimeRegression { .. })
    ));
    assert_eq!(r, before);
    assert_timeline_bound(&r);
}

#[test]
fn unknown_withdrawal_advances_only_a_retained_timeline() {
    let mut r = registry();
    r.insert(key(256), definition(1), 100).unwrap();
    assert_eq!(
        r.withdraw(&key(257), 105).unwrap(),
        TemplateWithdrawal::Unknown
    );
    assert_eq!(
        r.timeline_last_source_time_ns(key(256).timeline()),
        Some(105)
    );
    let before = r.clone();
    assert!(r.withdraw(&key(256), 104).is_err());
    assert_eq!(r, before);
    assert_timeline_bound(&r);
}

#[test]
fn thousands_of_unknown_timelines_create_no_watermarks_or_neighbor_mutations() {
    let mut r = registry();
    r.insert(key(256), definition(1), 10).unwrap();
    let before = r.clone();
    for scope in 0..5000 {
        let k = key_for(
            TemplateProtocol::NetFlowV9,
            "missing",
            &format!("session-{scope}"),
            scope,
            256,
        );
        assert_eq!(r.lookup(&k, u64::MAX).unwrap(), TemplateLookup::Unknown);
        assert_eq!(
            r.withdraw(&k, u64::MAX).unwrap(),
            TemplateWithdrawal::Unknown
        );
        assert_eq!(r.expire_timeline(k.timeline(), u64::MAX).unwrap(), 0);
        assert_eq!(r.timeline_last_source_time_ns(k.timeline()), None);
        assert_eq!(r, before);
        assert_timeline_bound(&r);
    }
}

#[test]
fn final_withdrawal_drops_watermark_and_allows_earlier_new_lifetime() {
    let mut r = registry();
    r.insert(key(256), definition(1), 5000).unwrap();
    found(&mut r, &key(256), 5001);
    r.withdraw(&key(256), 5002).unwrap();
    assert_eq!(r.timeline_count(), 0);
    assert_eq!(r.timeline_last_source_time_ns(key(256).timeline()), None);
    assert_eq!(
        r.insert(key(256), definition(2), 3000).unwrap().generation,
        1
    );
    assert_eq!(
        r.timeline_last_source_time_ns(key(256).timeline()),
        Some(3000)
    );
    assert_timeline_bound(&r);
}

#[test]
fn final_expiry_drops_watermark_and_allows_earlier_new_lifetime() {
    let mut r = registry();
    r.insert(key(256), definition(1), 5000).unwrap();
    assert_eq!(r.expire_timeline(key(256).timeline(), 5010).unwrap(), 1);
    assert_eq!(r.timeline_count(), 0);
    assert_eq!(
        r.insert(key(256), definition(2), 3000).unwrap().generation,
        1
    );
    assert_timeline_bound(&r);
}

#[test]
fn final_expired_lookup_drops_watermark_and_allows_earlier_new_lifetime() {
    let mut r = registry();
    r.insert(key(256), definition(1), 5000).unwrap();
    assert!(matches!(
        r.lookup(&key(256), 5010).unwrap(),
        TemplateLookup::Expired { .. }
    ));
    assert_eq!(r.timeline_count(), 0);
    r.insert(key(256), definition(2), 3000).unwrap();
    assert_timeline_bound(&r);
}

#[test]
fn multiple_templates_share_time_and_partial_withdrawal_keeps_watermark() {
    let mut r = registry();
    r.insert(key(256), definition(1), 5000).unwrap();
    r.insert(key(257), definition(2), 5000).unwrap();
    found(&mut r, &key(256), 5005);
    let before = r.clone();
    assert!(r.insert(key(257), definition(3), 5004).is_err());
    assert!(r.lookup(&key(257), 5004).is_err());
    assert!(r.withdraw(&key(257), 5004).is_err());
    assert_eq!(r, before);
    r.withdraw(&key(256), 5005).unwrap();
    assert_eq!(r.timeline_count(), 1);
    assert_eq!(
        r.timeline_last_source_time_ns(key(257).timeline()),
        Some(5005)
    );
    assert!(r.lookup(&key(257), 5004).is_err());
    r.withdraw(&key(257), 5005).unwrap();
    assert_eq!(r.timeline_count(), 0);
}

#[test]
fn timeline_expiry_does_not_expire_independent_clocks() {
    let a = key(256);
    let b = key_for(TemplateProtocol::NetFlowV9, "other", "s", 1, 256);
    let mut r = registry();
    r.insert(a.clone(), definition(1), 5000).unwrap();
    r.insert(b.clone(), definition(2), 3000).unwrap();
    assert_eq!(r.expire_timeline(a.timeline(), 5010).unwrap(), 1);
    assert_eq!(found(&mut r, &b, 3000).definition(), &definition(2));
    assert_eq!(r.timeline_count(), 1);
    assert_timeline_bound(&r);
}

#[test]
fn insertion_prunes_only_its_own_timeline_before_capacity_check() {
    let mut r = TemplateRegistry::new(
        TemplateRegistryConfig::new(2, 8, 64)
            .unwrap()
            .with_ttl_ns(10)
            .unwrap(),
    );
    let a = key(256);
    let b = key_for(TemplateProtocol::NetFlowV9, "other", "s", 1, 256);
    r.insert(a.clone(), definition(1), 5000).unwrap();
    r.insert(b.clone(), definition(2), 3000).unwrap();
    let t = r.insert(key(257), definition(3), 5010).unwrap();
    assert_eq!(t.expired_pruned, 1);
    assert_eq!(found(&mut r, &b, 3000).definition(), &definition(2));
    assert_eq!(r.timeline_count(), 2);
    assert_timeline_bound(&r);
}

#[test]
fn capacity_does_not_assume_other_timelines_are_expired_at_this_clock() {
    let mut r = TemplateRegistry::new(
        TemplateRegistryConfig::new(1, 8, 64)
            .unwrap()
            .with_ttl_ns(10)
            .unwrap(),
    );
    let a = key(256);
    let b = key_for(TemplateProtocol::NetFlowV9, "other", "s", 1, 256);
    r.insert(a.clone(), definition(1), 3000).unwrap();
    let before = r.clone();
    assert_eq!(
        r.insert(b.clone(), definition(2), 9000),
        Err(TemplateRegistryError::CapacityExceeded { limit: 1 })
    );
    assert_eq!(r, before);
    assert_eq!(r.timeline_last_source_time_ns(b.timeline()), None);
    assert_eq!(r.expire_timeline(a.timeline(), 3010).unwrap(), 1);
    r.insert(b, definition(2), 9000).unwrap();
    assert_timeline_bound(&r);
}

#[test]
fn repeated_timeline_churn_beyond_capacity_retains_no_watermark_tombstones() {
    let mut r = TemplateRegistry::new(
        TemplateRegistryConfig::new(1, 8, 64)
            .unwrap()
            .with_ttl_ns(10)
            .unwrap(),
    );
    for scope in 0..3000_u32 {
        let k = key_for(
            if scope % 2 == 0 {
                TemplateProtocol::Ipfix
            } else {
                TemplateProtocol::NetFlowV9
            },
            "e",
            &format!("session-{scope}"),
            scope,
            256,
        );
        r.insert(k.clone(), definition(1), u64::from(scope))
            .unwrap();
        assert_timeline_bound(&r);
        if scope % 3 == 0 {
            r.withdraw(&k, u64::from(scope)).unwrap();
        } else if scope % 3 == 1 {
            r.expire_timeline(k.timeline(), u64::from(scope) + 10)
                .unwrap();
        } else {
            assert!(matches!(
                r.lookup(&k, u64::from(scope) + 10).unwrap(),
                TemplateLookup::Expired { .. }
            ));
        }
        assert!(r.is_empty());
        assert_eq!(r.timeline_count(), 0);
        assert_timeline_bound(&r);
    }
}

#[test]
fn invalid_timeline_identity_cannot_mutate_expiry_or_watermarks() {
    let mut r = TemplateRegistry::new(TemplateRegistryConfig::new(1, 8, 3).unwrap());
    let k = key_for(TemplateProtocol::Ipfix, "e", "s", 0, 256);
    r.insert(k, definition(1), 0).unwrap();
    let invalid = key_for(
        TemplateProtocol::Ipfix,
        "long-exporter",
        "long-session",
        0,
        256,
    );
    let before = r.clone();
    assert!(matches!(
        r.expire_timeline(invalid.timeline(), u64::MAX),
        Err(TemplateRegistryError::InvalidIdentity { .. })
    ));
    assert_eq!(r, before);
}

#[test]
fn changed_replacement_extends_ttl_without_affecting_neighbor_time() {
    let a = key(256);
    let b = key_for(TemplateProtocol::NetFlowV9, "other", "s", 1, 256);
    let mut r = registry();
    r.insert(a.clone(), definition(1), 100).unwrap();
    r.insert(b.clone(), definition(2), 1).unwrap();
    assert_eq!(
        r.insert(a.clone(), definition(3), 109).unwrap().generation,
        2
    );
    assert_eq!(found(&mut r, &a, 110).expires_at_ns(), 119);
    assert_eq!(r.timeline_last_source_time_ns(b.timeline()), Some(1));
    assert!(matches!(
        r.lookup(&a, 119).unwrap(),
        TemplateLookup::Expired { .. }
    ));
    assert_timeline_bound(&r);
}

#[test]
fn per_timeline_replay_includes_independent_clocks_unknowns_and_lifetime_resets() {
    fn run() -> (Vec<String>, TemplateRegistry) {
        let mut r = registry();
        let a = key(256);
        let b = key_for(TemplateProtocol::NetFlowV9, "other", "s", 1, 256);
        let mut events = Vec::new();
        events.push(format!("{:?}", r.insert(a.clone(), definition(1), 5000)));
        events.push(format!("{:?}", r.insert(b.clone(), definition(2), 3000)));
        events.push(format!("{:?}", r.lookup(&key(257), 5001)));
        events.push(format!("{:?}", r.withdraw(&key(257), 5000)));
        events.push(format!("{:?}", r.expire_timeline(a.timeline(), 5010)));
        events.push(format!("{:?}", r.insert(a, definition(3), 2000)));
        events.push(format!("{:?}", r.lookup(&b, 3001)));
        assert_timeline_bound(&r);
        (events, r)
    }
    let expected = run();
    for _ in 0..20 {
        assert_eq!(run(), expected);
    }
}

#[test]
fn maximum_field_count_and_repeated_ids_preserved() {
    let fields = vec![
        TemplateFieldSpecifier {
            field_id: u16::MAX,
            encoded_length: u16::MAX,
            enterprise_number: Some(u32::MAX)
        };
        usize::from(u16::MAX)
    ];
    let d = TemplateDefinition::new(
        TemplateKind::Options,
        u16::MAX,
        &fields,
        usize::from(u16::MAX),
    )
    .unwrap();
    let mut r =
        TemplateRegistry::new(TemplateRegistryConfig::new(1, usize::from(u16::MAX), 64).unwrap());
    r.insert(key(u16::MAX), d, 0).unwrap();
    assert_eq!(
        found(&mut r, &key(u16::MAX), 0).definition().fields(),
        fields
    );
}

#[test]
fn bounded_adversarial_sequence_matches_independent_active_state_model() {
    use std::collections::BTreeMap;
    let mut r = registry();
    // Model stores only scalar definition ID, generation, and expiry.
    let mut model: BTreeMap<u16, (u16, u64, u64)> = BTreeMap::new();
    for time in 0..500_u64 {
        let id = 256 + u16::try_from((time * 17) % 7).unwrap();
        let value = u16::try_from(time % 3).unwrap();
        let live: BTreeMap<_, _> = model
            .iter()
            .filter(|(_, (_, _, expiry))| *expiry > time)
            .map(|(k, v)| (*k, *v))
            .collect();
        let before = r.clone();
        let result = r.insert(key(id), definition(value), time);
        if !live.contains_key(&id) && live.len() == 4 {
            assert_eq!(
                result,
                Err(TemplateRegistryError::CapacityExceeded { limit: 4 })
            );
            assert_eq!(r, before);
        } else {
            let (kind, generation) = match live.get(&id) {
                Some((old, generation, _)) if *old == value => {
                    (TemplateTransitionKind::Refreshed, *generation)
                }
                Some((_, generation, _)) => (TemplateTransitionKind::Replaced, generation + 1),
                None => (TemplateTransitionKind::Inserted, 1),
            };
            let t = result.unwrap();
            assert_eq!((t.kind, t.generation), (kind, generation));
            model = live;
            model.insert(id, (value, generation, time + 10));
        }
        let actual = r
            .entries()
            .map(|(k, e)| {
                (
                    k.template_id(),
                    (
                        e.definition().fields()[0].field_id,
                        e.generation(),
                        e.expires_at_ns(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(actual, model);
        assert!(r.len() <= 4);
    }
}

#[test]
fn production_module_has_no_clock_io_rng_wire_parser_or_panic_dependency() {
    let source = include_str!("../src/netflow/template.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    for forbidden in [
        "SystemTime",
        "Instant::",
        "::now(",
        "std::fs",
        "std::net",
        "HashMap",
        "unsafe",
        "unwrap(",
        "expect(",
        "panic!",
        "serde",
        "CanonicalObservation",
        "parse_netflow",
        "from_be_bytes",
        "thread::",
        "tokio",
    ] {
        assert!(
            !source.contains(forbidden),
            "unexpected production dependency: {forbidden}"
        );
    }
}
