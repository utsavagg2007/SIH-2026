//! Bounded, source-time-driven schema state; NOT a NetFlow v9/IPFIX wire decoder.
//!
//! Callers supply complete session identities and validated protocol field layouts.
//! Timed operations share a monotonic watermark only within one protocol/session/
//! observation-scope timeline. Every error leaves the entire registry unchanged.
//! Watermarks exist only while their timeline retains template entries; removing
//! its final entry removes its watermark. Lookup does not refresh template TTL.
//! Generations are local to an active key lifetime and reset after expiry/withdrawal;
//! later record identity must not use generation alone.

use std::collections::BTreeMap;
use std::fmt;

/// Human-approved configurable deployment policies, NOT protocol maxima.
pub const DEFAULT_TEMPLATE_TTL_SECONDS: u64 = 1_800;
pub const DEFAULT_TEMPLATE_TTL_NS: u64 = DEFAULT_TEMPLATE_TTL_SECONDS * 1_000_000_000;
pub const DEFAULT_MAX_TEMPLATE_ENTRIES: usize = 4_096;
pub const DEFAULT_MAX_FIELDS_PER_TEMPLATE: usize = 256;
pub const DEFAULT_MAX_TEMPLATE_IDENTITY_BYTES: usize = 256;
pub const MIN_TEMPLATE_ID: u16 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TemplateProtocol {
    NetFlowV9,
    Ipfix,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateKind {
    Data,
    Options,
}

/// Opaque decoder-supplied field identity and encoded octet length.
///
/// IPFIX adapters remove the enterprise flag from `field_id` and supply its
/// optional PEN separately. V9 adapters preserve the full field type without a
/// PEN. Length 65535 is preserved, not decoded; zero-length/unknown IE legality
/// and protocol-specific enterprise rules belong to the later wire decoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateFieldSpecifier {
    pub field_id: u16,
    pub encoded_length: u16,
    pub enterprise_number: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityErrorKind {
    Empty,
    TooLong { limit_bytes: usize },
    InvalidAscii,
}

/// Errors contain bounded numeric/static context, never source strings or fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateRegistryError {
    InvalidConfig {
        field: &'static str,
    },
    InvalidIdentity {
        field: &'static str,
        kind: IdentityErrorKind,
    },
    InvalidTemplateId {
        template_id: u16,
    },
    EmptyDefinition,
    TooManyFields {
        count: usize,
        limit: usize,
    },
    InvalidScopeFieldCount {
        kind: TemplateKind,
        count: u16,
        total: usize,
    },
    CapacityExceeded {
        limit: usize,
    },
    SourceTimeRegression {
        previous_ns: u64,
        provided_ns: u64,
    },
    ExpiryOverflow,
    GenerationOverflow,
}

impl fmt::Display for TemplateRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field } => {
                write!(formatter, "invalid template registry config: {field}")
            }
            Self::InvalidIdentity { field, kind } => write!(formatter, "invalid {field}: {kind:?}"),
            Self::InvalidTemplateId { template_id } => write!(
                formatter,
                "template ID {template_id} is reserved; minimum is {MIN_TEMPLATE_ID}"
            ),
            Self::EmptyDefinition => formatter
                .write_str("active template must contain fields; use withdrawal API for removal"),
            Self::TooManyFields { count, limit } => {
                write!(formatter, "template field count {count} exceeds {limit}")
            }
            Self::InvalidScopeFieldCount { kind, count, total } => write!(
                formatter,
                "invalid {kind:?} scope count {count} for {total} fields"
            ),
            Self::CapacityExceeded { limit } => {
                write!(formatter, "retained template capacity {limit} exhausted")
            }
            Self::SourceTimeRegression {
                previous_ns,
                provided_ns,
            } => write!(
                formatter,
                "source time {provided_ns} regressed below {previous_ns}"
            ),
            Self::ExpiryOverflow => {
                formatter.write_str("source time plus template TTL overflows u64")
            }
            Self::GenerationOverflow => formatter.write_str("template generation overflows u64"),
        }
    }
}

impl std::error::Error for TemplateRegistryError {}

/// Validated, overrideable deployment policy with human-approved safety defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateRegistryConfig {
    max_entries: usize,
    max_fields_per_template: usize,
    max_identity_bytes: usize,
    ttl_ns: u64,
}

impl Default for TemplateRegistryConfig {
    fn default() -> Self {
        // Fixed positive constants fit the representational and payload bounds.
        // Fields remain private; caller overrides go through validated builders.
        Self {
            max_entries: DEFAULT_MAX_TEMPLATE_ENTRIES,
            max_fields_per_template: DEFAULT_MAX_FIELDS_PER_TEMPLATE,
            max_identity_bytes: DEFAULT_MAX_TEMPLATE_IDENTITY_BYTES,
            ttl_ns: DEFAULT_TEMPLATE_TTL_NS,
        }
    }
}

impl TemplateRegistryConfig {
    pub fn new(
        max_entries: usize,
        max_fields_per_template: usize,
        max_identity_bytes: usize,
    ) -> Result<Self, TemplateRegistryError> {
        for (field, value) in [
            ("max_entries", max_entries),
            ("max_fields_per_template", max_fields_per_template),
            ("max_identity_bytes", max_identity_bytes),
        ] {
            if value == 0 {
                return Err(TemplateRegistryError::InvalidConfig { field });
            }
        }
        if max_fields_per_template > usize::from(u16::MAX) {
            return Err(TemplateRegistryError::InvalidConfig {
                field: "max_fields_per_template",
            });
        }
        // Reject bounds whose worst-case owned payload budget cannot fit usize.
        // Maps are grown incrementally, never preallocated from configured limits.
        let payload_budget = max_fields_per_template
            .checked_mul(std::mem::size_of::<TemplateFieldSpecifier>())
            .and_then(|fields| {
                max_identity_bytes
                    // Template key and at most one timeline key per entry.
                    .checked_mul(4)
                    .and_then(|ids| fields.checked_add(ids))
            })
            .and_then(|payload| payload.checked_add(std::mem::size_of::<TemplateKey>()))
            .and_then(|payload| payload.checked_add(std::mem::size_of::<TemplateEntry>()))
            .and_then(|payload| payload.checked_add(std::mem::size_of::<TemplateTimelineKey>()))
            .and_then(|payload| payload.checked_add(std::mem::size_of::<u64>()))
            .and_then(|per_entry| per_entry.checked_mul(max_entries));
        if payload_budget.is_none() {
            return Err(TemplateRegistryError::InvalidConfig {
                field: "payload_budget",
            });
        }
        Ok(Self {
            max_entries,
            max_fields_per_template,
            max_identity_bytes,
            ttl_ns: DEFAULT_TEMPLATE_TTL_NS,
        })
    }

    pub fn with_ttl_ns(mut self, ttl_ns: u64) -> Result<Self, TemplateRegistryError> {
        if ttl_ns == 0 {
            return Err(TemplateRegistryError::InvalidConfig { field: "ttl_ns" });
        }
        self.ttl_ns = ttl_ns;
        Ok(self)
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }
    pub fn max_fields_per_template(&self) -> usize {
        self.max_fields_per_template
    }
    pub fn max_identity_bytes(&self) -> usize {
        self.max_identity_bytes
    }
    pub fn ttl_ns(&self) -> u64 {
        self.ttl_ns
    }
}

/// Explicit exporter plus opaque transport/session epoch, NOT just a source IP.
///
/// The caller must include sensor/collector namespace, transport endpoints and
/// connection/restart epoch as appropriate in these deterministic labels. F5
/// neither infers nor authenticates them. Labels are case-sensitive ASCII using
/// the existing exporter-ID alphabet; structured components avoid delimiter
/// concatenation collisions. Exact-size boxed strings retain no spare capacity.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransportSessionKey {
    exporter_id: Box<str>,
    session_id: Box<str>,
}

fn validate_identity(
    value: &str,
    field: &'static str,
    limit: usize,
) -> Result<(), TemplateRegistryError> {
    let kind = if value.is_empty() {
        Some(IdentityErrorKind::Empty)
    } else if value.len() > limit {
        Some(IdentityErrorKind::TooLong { limit_bytes: limit })
    } else if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        Some(IdentityErrorKind::InvalidAscii)
    } else {
        None
    };
    match kind {
        Some(kind) => Err(TemplateRegistryError::InvalidIdentity { field, kind }),
        None => Ok(()),
    }
}

impl TransportSessionKey {
    pub fn new(
        exporter_id: &str,
        session_id: &str,
        max_identity_bytes: usize,
    ) -> Result<Self, TemplateRegistryError> {
        if max_identity_bytes == 0 {
            return Err(TemplateRegistryError::InvalidConfig {
                field: "max_identity_bytes",
            });
        }
        validate_identity(exporter_id, "exporter_id", max_identity_bytes)?;
        validate_identity(session_id, "session_id", max_identity_bytes)?;
        Ok(Self {
            exporter_id: exporter_id.into(),
            session_id: session_id.into(),
        })
    }

    pub fn exporter_id(&self) -> &str {
        &self.exporter_id
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TemplateTimelineKey {
    protocol: TemplateProtocol,
    session: TransportSessionKey,
    observation_scope_id: u32,
}

impl TemplateTimelineKey {
    pub fn new(
        protocol: TemplateProtocol,
        session: TransportSessionKey,
        observation_scope_id: u32,
    ) -> Self {
        Self {
            protocol,
            session,
            observation_scope_id,
        }
    }

    pub fn protocol(&self) -> TemplateProtocol {
        self.protocol
    }
    pub fn session(&self) -> &TransportSessionKey {
        &self.session
    }
    pub fn observation_scope_id(&self) -> u32 {
        self.observation_scope_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TemplateKey {
    timeline: TemplateTimelineKey,
    template_id: u16,
}

impl TemplateKey {
    pub fn new(
        protocol: TemplateProtocol,
        session: TransportSessionKey,
        observation_scope_id: u32,
        template_id: u16,
    ) -> Result<Self, TemplateRegistryError> {
        if template_id < MIN_TEMPLATE_ID {
            return Err(TemplateRegistryError::InvalidTemplateId { template_id });
        }
        Ok(Self {
            timeline: TemplateTimelineKey::new(protocol, session, observation_scope_id),
            template_id,
        })
    }

    pub fn timeline(&self) -> &TemplateTimelineKey {
        &self.timeline
    }
    pub fn protocol(&self) -> TemplateProtocol {
        self.timeline.protocol()
    }
    pub fn session(&self) -> &TransportSessionKey {
        self.timeline.session()
    }
    pub fn observation_scope_id(&self) -> u32 {
        self.timeline.observation_scope_id()
    }
    pub fn template_id(&self) -> u16 {
        self.template_id
    }
}

/// Protocol-neutral, nonempty physical layout. For Options the first N fields
/// are scope fields; N may be zero through the total field count. Wire adapters
/// enforce protocol-specific scope legality before construction/insertion.
/// V9 adapters later convert scope-definition byte lengths to this field count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateDefinition {
    kind: TemplateKind,
    scope_field_count: u16,
    fields: Box<[TemplateFieldSpecifier]>,
}

fn validate_definition(
    kind: TemplateKind,
    scope_field_count: u16,
    count: usize,
    limit: usize,
) -> Result<(), TemplateRegistryError> {
    if limit == 0 || limit > usize::from(u16::MAX) {
        return Err(TemplateRegistryError::InvalidConfig {
            field: "max_fields_per_template",
        });
    }
    if count == 0 {
        return Err(TemplateRegistryError::EmptyDefinition);
    }
    if count > limit {
        return Err(TemplateRegistryError::TooManyFields { count, limit });
    }
    let valid_scope = match kind {
        TemplateKind::Data => scope_field_count == 0,
        TemplateKind::Options => usize::from(scope_field_count) <= count,
    };
    if !valid_scope {
        return Err(TemplateRegistryError::InvalidScopeFieldCount {
            kind,
            count: scope_field_count,
            total: count,
        });
    }
    Ok(())
}

impl TemplateDefinition {
    /// Check count before allocating; decoders must also bound their own parsing.
    pub fn new(
        kind: TemplateKind,
        scope_field_count: u16,
        fields: &[TemplateFieldSpecifier],
        max_fields: usize,
    ) -> Result<Self, TemplateRegistryError> {
        validate_definition(kind, scope_field_count, fields.len(), max_fields)?;
        Ok(Self {
            kind,
            scope_field_count,
            fields: fields.into(),
        })
    }

    pub fn kind(&self) -> TemplateKind {
        self.kind
    }
    pub fn scope_field_count(&self) -> u16 {
        self.scope_field_count
    }
    pub fn fields(&self) -> &[TemplateFieldSpecifier] {
        &self.fields
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateEntry {
    definition: TemplateDefinition,
    generation: u64,
    first_seen_ns: u64,
    last_seen_ns: u64,
    expires_at_ns: u64,
}

impl TemplateEntry {
    pub fn definition(&self) -> &TemplateDefinition {
        &self.definition
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn first_seen_ns(&self) -> u64 {
        self.first_seen_ns
    }
    pub fn last_seen_ns(&self) -> u64 {
        self.last_seen_ns
    }
    pub fn expires_at_ns(&self) -> u64 {
        self.expires_at_ns
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateTransitionKind {
    Inserted,
    Refreshed,
    Replaced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateTransition {
    pub kind: TemplateTransitionKind,
    pub generation: u64,
    pub expired_pruned: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TemplateLookup<'a> {
    Found(&'a TemplateEntry),
    Unknown,
    /// Removed on this lookup; no unbounded expired-key tombstones are retained.
    Expired {
        generation: u64,
        expires_at_ns: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateWithdrawal {
    Withdrawn { generation: u64 },
    Unknown,
    Expired { generation: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateRegistry {
    config: TemplateRegistryConfig,
    entries: BTreeMap<TemplateKey, TemplateEntry>,
    // Exactly one watermark per represented retained timeline; no tombstones.
    timelines: BTreeMap<TemplateTimelineKey, u64>,
}

impl TemplateRegistry {
    pub fn new(config: TemplateRegistryConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
            timelines: BTreeMap::new(),
        }
    }

    pub fn config(&self) -> &TemplateRegistryConfig {
        &self.config
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn timeline_count(&self) -> usize {
        self.timelines.len()
    }
    pub fn timeline_last_source_time_ns(&self, timeline: &TemplateTimelineKey) -> Option<u64> {
        self.timelines.get(timeline).copied()
    }

    /// Ordered borrowed audit view; may include expired but not yet pruned entries.
    /// Use timed lookup for decoding, not this timeless introspection method.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (&TemplateKey, &TemplateEntry)> {
        self.entries.iter()
    }

    fn validate_timeline(
        &self,
        timeline: &TemplateTimelineKey,
    ) -> Result<(), TemplateRegistryError> {
        validate_identity(
            timeline.session.exporter_id(),
            "exporter_id",
            self.config.max_identity_bytes,
        )?;
        validate_identity(
            timeline.session.session_id(),
            "session_id",
            self.config.max_identity_bytes,
        )
    }

    fn validate_time(
        &self,
        timeline: &TemplateTimelineKey,
        source_time_ns: u64,
    ) -> Result<(), TemplateRegistryError> {
        if let Some(&previous_ns) = self.timelines.get(timeline) {
            if source_time_ns < previous_ns {
                return Err(TemplateRegistryError::SourceTimeRegression {
                    previous_ns,
                    provided_ns: source_time_ns,
                });
            }
        }
        Ok(())
    }

    /// Validate every prospective change before pruning or replacing any state.
    pub fn insert(
        &mut self,
        key: TemplateKey,
        definition: TemplateDefinition,
        source_time_ns: u64,
    ) -> Result<TemplateTransition, TemplateRegistryError> {
        self.validate_timeline(key.timeline())?;
        validate_definition(
            definition.kind,
            definition.scope_field_count,
            definition.fields.len(),
            self.config.max_fields_per_template,
        )?;
        self.validate_time(key.timeline(), source_time_ns)?;
        let expires_at_ns = source_time_ns
            .checked_add(self.config.ttl_ns)
            .ok_or(TemplateRegistryError::ExpiryOverflow)?;
        let active = self
            .entries
            .get(&key)
            .filter(|entry| entry.expires_at_ns > source_time_ns);
        let (kind, generation, first_seen_ns) = match active {
            Some(entry) if entry.definition == definition => (
                TemplateTransitionKind::Refreshed,
                entry.generation,
                entry.first_seen_ns,
            ),
            Some(entry) => (
                TemplateTransitionKind::Replaced,
                entry
                    .generation
                    .checked_add(1)
                    .ok_or(TemplateRegistryError::GenerationOverflow)?,
                entry.first_seen_ns,
            ),
            None => {
                // A timestamp in this timeline cannot expire unrelated clocks.
                let retained_count = self
                    .entries
                    .iter()
                    .filter(|(other_key, entry)| {
                        other_key.timeline() != key.timeline()
                            || entry.expires_at_ns > source_time_ns
                    })
                    .count();
                if retained_count >= self.config.max_entries {
                    return Err(TemplateRegistryError::CapacityExceeded {
                        limit: self.config.max_entries,
                    });
                }
                (TemplateTransitionKind::Inserted, 1, source_time_ns)
            }
        };
        // Prospective expiry is accounted for above; commit pruning only on success.
        let timeline = key.timeline().clone();
        let expired_pruned = self.prune_timeline(&timeline, source_time_ns);
        self.entries.insert(
            key,
            TemplateEntry {
                definition,
                generation,
                first_seen_ns,
                last_seen_ns: source_time_ns,
                expires_at_ns,
            },
        );
        self.timelines.insert(timeline, source_time_ns);
        Ok(TemplateTransition {
            kind,
            generation,
            expired_pruned,
        })
    }

    /// Unknown lookups advance an existing timeline, never create an empty one.
    pub fn lookup(
        &mut self,
        key: &TemplateKey,
        source_time_ns: u64,
    ) -> Result<TemplateLookup<'_>, TemplateRegistryError> {
        self.validate_timeline(key.timeline())?;
        self.validate_time(key.timeline(), source_time_ns)?;
        let expired = self
            .entries
            .get(key)
            .filter(|entry| entry.expires_at_ns <= source_time_ns)
            .map(|entry| (entry.generation, entry.expires_at_ns));
        if let Some((generation, expires_at_ns)) = expired {
            self.entries.remove(key);
            self.finish_timeline_operation(key.timeline(), source_time_ns);
            return Ok(TemplateLookup::Expired {
                generation,
                expires_at_ns,
            });
        }
        self.finish_timeline_operation(key.timeline(), source_time_ns);
        Ok(match self.entries.get(key) {
            Some(entry) => TemplateLookup::Found(entry),
            None => TemplateLookup::Unknown,
        })
    }

    pub fn withdraw(
        &mut self,
        key: &TemplateKey,
        source_time_ns: u64,
    ) -> Result<TemplateWithdrawal, TemplateRegistryError> {
        self.validate_timeline(key.timeline())?;
        self.validate_time(key.timeline(), source_time_ns)?;
        let result = match self.entries.remove(key) {
            Some(entry) if entry.expires_at_ns <= source_time_ns => TemplateWithdrawal::Expired {
                generation: entry.generation,
            },
            Some(entry) => TemplateWithdrawal::Withdrawn {
                generation: entry.generation,
            },
            None => TemplateWithdrawal::Unknown,
        };
        self.finish_timeline_operation(key.timeline(), source_time_ns);
        Ok(result)
    }

    /// Expire only this timeline, at expires_at_ns <= source_time_ns.
    /// An empty timeline returns zero without retaining a watermark.
    pub fn expire_timeline(
        &mut self,
        timeline: &TemplateTimelineKey,
        source_time_ns: u64,
    ) -> Result<usize, TemplateRegistryError> {
        self.validate_timeline(timeline)?;
        self.validate_time(timeline, source_time_ns)?;
        let removed = self.prune_timeline(timeline, source_time_ns);
        self.finish_timeline_operation(timeline, source_time_ns);
        Ok(removed)
    }

    fn prune_timeline(&mut self, timeline: &TemplateTimelineKey, source_time_ns: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|key, entry| {
            key.timeline() != timeline || entry.expires_at_ns > source_time_ns
        });
        before - self.entries.len()
    }

    fn finish_timeline_operation(&mut self, timeline: &TemplateTimelineKey, source_time_ns: u64) {
        if self.entries.keys().any(|key| key.timeline() == timeline) {
            // Created only by successful insertion; updating never allocates.
            if let Some(watermark) = self.timelines.get_mut(timeline) {
                *watermark = source_time_ns;
            }
        } else {
            self.timelines.remove(timeline);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_overflow_is_atomic_but_identical_refresh_still_works() {
        let config = TemplateRegistryConfig::new(2, 2, 32)
            .unwrap()
            .with_ttl_ns(10)
            .unwrap();
        let key = TemplateKey::new(
            TemplateProtocol::Ipfix,
            TransportSessionKey::new("e", "s", 32).unwrap(),
            0,
            256,
        )
        .unwrap();
        let definition = TemplateDefinition::new(
            TemplateKind::Data,
            0,
            &[TemplateFieldSpecifier {
                field_id: 1,
                encoded_length: 4,
                enterprise_number: None,
            }],
            2,
        )
        .unwrap();
        let mut registry = TemplateRegistry::new(config);
        registry.insert(key.clone(), definition.clone(), 0).unwrap();
        registry.entries.get_mut(&key).unwrap().generation = u64::MAX;
        let before = registry.clone();
        let changed = TemplateDefinition::new(
            TemplateKind::Data,
            0,
            &[TemplateFieldSpecifier {
                field_id: 2,
                encoded_length: 4,
                enterprise_number: None,
            }],
            2,
        )
        .unwrap();
        assert_eq!(
            registry.insert(key.clone(), changed, 1),
            Err(TemplateRegistryError::GenerationOverflow)
        );
        assert_eq!(registry, before);
        let refreshed = registry.insert(key, definition, 1).unwrap();
        assert_eq!(refreshed.kind, TemplateTransitionKind::Refreshed);
        assert_eq!(refreshed.generation, u64::MAX);
    }
}
