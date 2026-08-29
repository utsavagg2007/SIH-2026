# CanonicalObservation v1 contract

`canonical_observation_v1.schema.json` is the authoritative serialized boundary between source-specific telemetry normalization and downstream aggregation, feature extraction, and detection. Version 1.0 accepts exactly four observation types: `flow`, `dns`, `tls`, and `http`.

This milestone defines the contract only. It does not change the existing Zeek ingestion pipeline, produce canonical records, adapt records for current detectors, or implement NetFlow, IPFIX, or sFlow. `packet_sample` and `counter_sample` are deliberately deferred until a real sFlow producer is implemented and validated.

## Serialization rules

- JSON is the wire format. Object names and enum values are case-sensitive.
- All canonical timestamps are RFC 3339 UTC strings ending in `Z`, with optional fractional seconds. JSON floating-point Unix time is prohibited.
- Integer counters are nonnegative and bounded to an unsigned 64-bit range. Producers and consumers must not pass them through a representation that silently loses integer precision. In particular, JavaScript consumers must use a lossless integer strategy for values above `2^53 - 1`.
- An omitted optional property means the source did not report it or the normalizer cannot support its exact semantics. For nullable counters, explicit `null` has the same unavailable/unknown value meaning but is distinct on the wire from omission. Neither omission nor `null` means zero.
- A reported numeric zero is an affirmative source value and must not be converted to missing data.
- Unknown object properties are rejected. Additive fields or observation variants require a versioned contract update.
- Validators must implement JSON Schema Draft 2020-12 and enable assertion of the standard `date-time`, `ipv4`, and `ipv6` formats. The schema also contains patterns for deterministic validation by tooling that treats `format` as annotation-only. The M0 conformance harness independently checks every canonical timestamp with .NET calendar construction because PowerShell `Test-Json` does not assert `date-time` format validity.

## Common envelope

| Field | Required | Type | Semantics |
| --- | --- | --- | --- |
| `schema_version` | yes | string constant `1.0` | Selects this exact contract. It is not an application or parser version. |
| `record_id` | yes | non-empty string | Deterministic opaque canonical identity governed by the invariants below. |
| `source_record_id` | no | non-empty string | Source-native identity or correlation key, such as a Zeek UID. It is not required to be globally unique and can repeat across protocol observations. |
| `observation_type` | yes | `flow`, `dns`, `tls`, or `http` | Discriminator. The schema requires it to match the shape of `data`. |
| `telemetry_source` | yes | `zeek`, `netflow_v5`, `netflow_v9`, or `ipfix` | Identifies the system whose field semantics were normalized, not necessarily the original acquisition format. |
| `sensor_id` | yes | non-empty string | Stable deployment-assigned identity of the sensor/collector context that supplied the observation. It is not an IP-address role classification. |
| `observed_at` | yes | RFC 3339 UTC string | Time the canonicalizer observed/received the source observation. It is receipt/availability time, not a substitute for event time. |
| `quality` | yes | `Quality` object | Observation-level fidelity, sampling, truncation, and loss metadata. |
| `provenance` | yes | `Provenance` object | Minimal acquisition and parser context needed to interpret and reproduce normalization. |
| `data` | yes | type-specific object | Raw normalized telemetry facts for the selected observation type. |

### Identifier invariants

`record_id` is opaque to consumers: it must never carry timestamp, address, detector feature, or policy semantics. A producer must generate the same `record_id` when the same stable source observation is replayed under the same source namespace and ID-algorithm version. Distinct source observations must not be collapsed merely because they share timestamps, endpoints, a Zeek UID, or flow linkage. Protocol events generated from one flow each require their own canonical IDs.

The ID namespace must include enough stable source context to prevent cross-sensor and cross-input collisions. IDs must not be reconstructed from rounded timestamps. This contract does not prescribe or implement an algorithm; the producer milestone must document its namespace and algorithm version before generating IDs. Random UUIDv4 semantics do not meet this contract.

`source_record_id` remains separate because source IDs have source-specific uniqueness and correlation semantics. A Zeek UID is suitable source correlation metadata but is not, by itself, a safe canonical ID for every DNS, TLS, or HTTP row associated with that UID.

## Time semantics

`FlowData.start_time` is the source-reported beginning of the flow/connection interval. `FlowData.end_time`, when available, is its source-reported end. `DNSData.event_time`, `TLSData.event_time`, and `HTTPData.event_time` are source-reported event times for those protocol observations. `observed_at` is the canonicalizer receipt/availability time and can be later than event time.

All times may arrive late or out of order and are not required to be monotonic. Consumers must window on the appropriate event time and define their own lateness policy. The schema enforces the canonical UTC `Z` lexical representation; the conformance harness additionally rejects impossible calendar dates and times at every timestamp location. When `end_time` is present, it must be greater than or equal to `start_time`. Missing `end_time` means unavailable or an observation that did not expose a defensible end, not a zero-duration flow.

## FlowData

`src` and `dst` name the endpoints exactly as represented by the normalized source observation. They do not assert internal/external policy, ingress/egress direction, client/server roles, or attacker/victim roles.

| Field | Required | Type/unit | Semantics |
| --- | --- | --- | --- |
| `start_time` | yes | RFC 3339 UTC | Source-reported flow start event time. |
| `end_time` | no | RFC 3339 UTC | Source-reported flow end event time; must be `>= start_time`. |
| `src_ip` | yes | IPv4 or IPv6 string | Source endpoint network address. |
| `dst_ip` | yes | IPv4 or IPv6 string | Destination endpoint network address. |
| `src_port` | no | integer `0..65535` | Source transport port when the protocol has ports and the source reports it. Port zero is a reported value, not missing. |
| `dst_port` | no | integer `0..65535` | Destination transport port under the same rule. |
| `icmp_type` | no | integer `0..255` | ICMP/ICMPv6 type. It must not be encoded into a fake transport port. |
| `icmp_code` | no | integer `0..255` | ICMP/ICMPv6 code. It must not be encoded into a fake transport port. |
| `ip_protocol` | yes | integer `0..255` | IANA IP Protocol Number, such as 6 for TCP, 17 for UDP, 1 for ICMP, or 58 for ICMPv6. |
| `direction_mode` | yes | enum | Defines how the two endpoint directions must be interpreted. |
| `service` | no | non-empty string | Source-reported or source-analyzer-identified application service label. It is not a model encoding. |
| `connection_state` | no | non-empty string | Source-reported connection state in that source's documented vocabulary. It must not be replaced by a hash or modulo value. |
| `connection_history` | no | non-empty string | Source-reported packet/connection history notation, such as Zeek history, without pretending it is a TCP flag bitmask. |
| `tcp_flags` | no | unique array of flag names | TCP control flags observed/reported across the flow: `fin`, `syn`, `rst`, `psh`, `ack`, `urg`, `ece`, `cwr`, `ns`. |
| `end_reason` | no | non-empty string | Source-reported termination/end reason where distinct from connection state. |
| `ingress_interface` | no | non-empty string | Source/exporter interface identifier on which traffic entered its observation point. It does not mean internal source. |
| `egress_interface` | no | non-empty string | Source/exporter interface identifier on which traffic left its observation point. It does not mean external destination. |
| `counters` | yes | `FlowCounters` | Directional counters kept separate by counter basis. |

### Direction modes

- `originator_responder`: `src` is the source-defined connection originator and `dst` is its responder. For Zeek, this preserves `id.orig_*` to `id.resp_*`; it is not necessarily packet-capture wire order for every packet.
- `unidirectional`: the source reports one directed flow from `src` to `dst`. The schema prohibits `dst_to_src` counters in this mode. An independently exported reverse record can remain a separate observation.
- `unknown`: endpoint ordering is preserved but the normalizer cannot make a stronger direction claim. Reverse counters may be present only when the source actually reports them for the stated endpoint ordering.

`ingress_interface` and `egress_interface` describe an observation point and are not alternatives to endpoint direction. Deployment policy such as internal/external, inbound/outbound, and source/destination roles is downstream enrichment based on configured CIDRs. Canonical v1 contains no authoritative host-role fields and must not hardcode RFC1918 as deployment policy.

### FlowCounters and byte bases

`counters.src_to_dst` is required as a non-empty object; `counters.dst_to_src` is optional. Each direction can independently contain the following nullable unsigned counters:

| Counter | Unit | Exact meaning |
| --- | --- | --- |
| `packets` | packets | Number of packets represented for that direction under source/exporter accounting. |
| `payload_bytes` | octets | Application/transport payload octets, excluding headers according to the source's documented semantics. |
| `ip_bytes` | octets | IP-layer octets, normally including the IP header and upper-layer data under the source's documented semantics. |
| `l2_bytes` | octets | Link-layer frame octets under the source's documented inclusion/exclusion rules. |

These bases are not interchangeable. A producer must leave a basis absent or `null` rather than substitute a different basis. A detector must explicitly choose the basis it accepts. Sampled or estimated counter interpretation is declared by the observation-level `quality`; individual counters are not wrapped in `{value, fidelity}` in v1.

## Protocol observations

DNS, TLS, and HTTP observations are separate records because one flow can contain zero, one, or many protocol events. Each record carries its own required `event_time`, `src_ip`, `dst_ip`, and `ip_protocol`, so it remains independently usable; TLS and HTTP additionally require transport ports, while DNS ports are optional for partial or source-limited observations. Optional `flow_record_id` is correlation metadata referencing a canonical flow `record_id`; it is not ownership and never creates a mandatory stateful join. When a producer supplies both the tuple and `flow_record_id`, they must be semantically consistent with the referenced flow.

### DNSData

| Field | Required | Type | Semantics |
| --- | --- | --- | --- |
| `event_time` | yes | RFC 3339 UTC | Source-reported DNS event time. |
| `flow_record_id` | no | non-empty string | Optional canonical flow correlation ID. |
| `src_ip`, `dst_ip` | yes | IP strings | DNS message source and destination endpoints. |
| `src_port`, `dst_port` | no | integers `0..65535` | DNS transport endpoints when reported. Partial or source-limited observations may omit them. |
| `ip_protocol` | yes | integer `0..255` | DNS transport's IP protocol number, normally TCP or UDP. |
| `query` | no | string | Raw source-reported query name when available. Empty is allowed only if it is the reported value; absence must not be replaced by an empty default, entropy, or an encoding. |
| `qtype` | no | integer `0..65535` | Numeric DNS QTYPE code, not a textual name such as `TXT`. |
| `qclass` | no | integer `0..65535` | Numeric DNS QCLASS code. |
| `rcode` | no | integer `0..4095` | Numeric DNS response code, including extended response-code range. It may be absent for query-only, timed-out, malformed, or source-limited observations. |
| `authoritative_answer` | no | boolean | Source-reported DNS AA flag. |
| `dns_truncated` | no | boolean | DNS message TC flag; distinct from capture-level `quality.truncated`. |
| `recursion_desired` | no | boolean | Source-reported DNS RD flag. |
| `recursion_available` | no | boolean | Source-reported DNS RA flag. |
| `rejected` | no | boolean | Source-reported analyzer rejection indicator. |
| `answer_count` | no | integer `0..65535` | Number of answers reported for this event, without embedding answer payloads. |

Answer bodies and TTL arrays are deferred because current detectors do not require them and their normalization/retention semantics have not been approved. Domain entropy, label counts, lexical encodings, DGA scores, and rolling query features are detector-owned. Detectors that require `query`, such as DGA logic, must gate on its availability rather than making the entire DNS observation invalid.

### TLSData

The required tuple fields have the same definitions as above. TLS-specific fields are optional because visibility varies by protocol version, encryption, parser configuration, and telemetry source.

| Field | Type | Semantics |
| --- | --- | --- |
| `version` | non-empty string | Source-reported TLS protocol version without model encoding. |
| `cipher` | non-empty string | Raw source-reported negotiated cipher/cipher-suite label. |
| `server_name` | non-empty string | Source-reported SNI/server name. It must not be reduced to a boolean. |
| `ja3` | non-empty string | Source-reported JA3 fingerprint; never fabricated. |
| `ja3s` | non-empty string | Source-reported JA3S fingerprint; never fabricated. |
| `ja4` | non-empty string | Source-reported JA4 fingerprint only when the parser actually exposes it; never derived merely because a runtime image supports a JA4 package. |

Certificate bodies and full certificate chains are deferred. Fingerprint allow/deny checks and encrypted-malware scores are detector-owned.

### HTTPData

The required tuple fields have the same definitions as above. All HTTP-specific metadata is optional so partial request/response observations remain representable.

| Field | Type/unit | Semantics |
| --- | --- | --- |
| `method` | non-empty string | Raw request method. |
| `host` | non-empty string | Raw HTTP host/authority reported by the source. |
| `uri` | string | Raw request target/URI metadata. Payload bodies are excluded. |
| `user_agent` | string | Raw User-Agent metadata. |
| `status_code` | integer `100..599` | Reported HTTP response status. |
| `request_body_bytes` | nullable unsigned octets | Reported request message-body size, not flow payload bytes. |
| `response_body_bytes` | nullable unsigned octets | Reported response message-body size, not flow payload bytes. |

Schema preservation does not decide storage retention. URI, host, and user-agent privacy/retention policy belongs to deployment policy outside this wire contract. Entropy, hashed categories, and model encodings are not canonical fields.

## Quality

Quality describes the observation as a whole:

| Field | Required | Type | Semantics |
| --- | --- | --- | --- |
| `fidelity` | yes | enum | `exact`: normalized directly from source-reported facts without sampling or estimation; `sampled`: the source selected a subset; `estimated`: one or more represented values were extrapolated/estimated; `unknown`: the normalizer cannot establish one of the preceding states. `exact` does not promise that the network sensor saw traffic it never captured, and the schema forbids sampling metadata when fidelity is `exact`. |
| `sampling_rate` | no | integer `>=1` | Source-reported one-in-N sampling interval/scale denominator. `N=1` means no sampling under this convention. |
| `sampling_probability` | no | number `0 < p <= 1` | Source-reported probability that an eligible unit was selected. If both sampling fields are present, they must describe the same sampling process; consumers must not assume exact reciprocity for adaptive sampling. |
| `truncated` | yes | boolean | The represented source observation or captured content was cut short. It is distinct from the DNS TC flag. |
| `loss_detected` | yes | boolean | The sensor/exporter/collector reported or directly detected capture/export loss relevant to the observation. `false` means no loss was detected, not proof of zero loss. |
| `missed_content_bytes` | no | nullable unsigned octets | Narrow source-reported count of missing content bytes, such as a defensible Zeek `missed_bytes` value. It is not an estimate of all network bytes lost. |

The ambiguous field `lost_bytes` does not exist. NetFlow/IPFIX sequence gaps must not be converted into `missed_content_bytes`, because a record gap does not establish the number of network bytes lost. Missing fields do not receive an additional `missing` fidelity enum: property absence or `null` represents unavailable values, while `fidelity` characterizes the observation that is present.

The schema rejects `sampling_rate` or `sampling_probability` whenever `fidelity` is `exact`. When both sampling fields are present for another fidelity, they must describe the same sampling process; exact reciprocal floating-point equivalence is intentionally not schema-enforced. Other source-specific contradictions, such as non-null `missed_content_bytes` without a source capable of reporting that value, remain documented producer errors.

## Provenance

| Field | Required | Type | Semantics |
| --- | --- | --- | --- |
| `input_mode` | yes | enum | `pcap_file`, `live_interface`, `export_stream`, or `export_file`; describes the acquisition/runtime path into the semantic source. |
| `parser_name` | yes | non-empty string | Stable parser/normalizer implementation name. |
| `parser_version` | yes | non-empty string | Version or immutable build identity of that parser/normalizer. |
| `input_sha256` | no | 64 hexadecimal characters | SHA-256 of the input artifact when a stable file exists and hashing is appropriate. |
| `capture_interface` | no | non-empty string | Capture interface identity for live or recorded capture context. |
| `exporter_id` | no | non-empty string | Deployment-stable flow exporter identity where applicable. |
| `observation_domain_id` | no | unsigned 32-bit integer | NetFlow v9/IPFIX observation-domain/source identifier where applicable. |
| `template_id` | no | unsigned 16-bit integer | Template identifier used to interpret an export record where applicable. |
| `message_sequence` | no | unsigned 64-bit-compatible integer | Source/export-message sequence value when the telemetry source exposes meaningful sequencing. It has no implied meaning for Zeek records that do not provide one. |

For `PCAP -> Zeek -> ingestion`, `telemetry_source` is `zeek`, because canonical field meanings are Zeek observation meanings, and `provenance.input_mode` is `pcap_file`. `parser_name` and `parser_version` identify the normalizer consuming the Zeek records. There is no redundant top-level `original_telemetry_format` field.

## Feature ownership boundary

Canonical v1 preserves telemetry facts. It must not contain entropy, rolling/windowed cardinalities or rates, scaled values, categorical/model encodings, model predictions, thresholds, severity, detector scores, or attack labels. Those belong to shared detector aggregation, detector-specific feature extraction, model preprocessing, or detector output. This boundary also prohibits reconstructing timestamps from IDs and serializing deployment-specific host roles as telemetry facts.

## Semantic invariants not fully encoded in JSON Schema

1. `end_time >= start_time` whenever `end_time` exists.
2. Missing or `null` counters are unavailable; reported zero is known zero.
3. `unidirectional` observations never contain `dst_to_src`; this is enforced structurally by the schema.
4. ICMP/ICMPv6 type and code are represented only by `icmp_type` and `icmp_code`, never fake TCP/UDP ports.
5. Payload, IP, and L2 byte counters never substitute for one another.
6. Protocol records remain independently usable without `flow_record_id`; that field is optional correlation metadata.
7. A `record_id` is never reconstructed from a rounded timestamp.
8. Host roles are downstream policy, not canonical v1 facts.
9. When a protocol tuple and `flow_record_id` coexist, they refer to semantically consistent endpoint context.

The conformance test implements the first invariant and strict calendar validation as semantic checks. The unidirectional and ICMP compatibility rules are enforced structurally by the schema. The remaining rules require producer/source context or are intentionally not replaced with fragile custom schema machinery.

## Validation

From the repository root on PowerShell 7:

```powershell
pwsh -NoProfile -File contracts/tests/test_contract.ps1
```

The test first parses every fixture as JSON, then uses the built-in `Test-Json` command for schema validation, and finally performs strict .NET calendar validation plus the end-time ordering check. Expected schema rejection is distinguished from JSON parsing and validator-invocation errors; unexpected exceptions fail the test. The harness requires no added package or production dependency.
