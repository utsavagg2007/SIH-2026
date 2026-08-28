# detection_core schemas

The handshake document between the ingestion team, the detection/ML team and
the full-stack team. Two contracts matter:

* **`FlowEvent`** — the normalized input every detector consumes.
* **`ThreatAlert` v1.1** — the frozen output the full-stack team renders.

---

## 1. FlowEvent

One normalized network flow. Internal to the detection layer; not a wire
format.

### Core fields — required, strictly validated

| field | type | notes |
|---|---|---|
| `timestamp` | `float` | epoch seconds, finite |
| `src_ip` | `str` | non-empty |
| `dst_ip` | `str` | non-empty |
| `proto` | `str` | non-empty |
| `duration` | `float` | finite, `>= 0` |
| `orig_bytes` | `int` | `>= 0` |
| `resp_bytes` | `int` | `>= 0` |
| `orig_pkts` | `int` | `>= 0` |
| `resp_pkts` | `int` | `>= 0` |

A record that cannot supply all of these is **skipped**, logged and counted.
Core fields are never silently coerced to `None`.

### Optional fields

| field | type | notes |
|---|---|---|
| `flow_id` | `str \| None` | `src:dst:port:proto:ts` from ingestion |
| `uid` | `str \| None` | back-filled from a nested block if absent |
| `src_port` | `int \| None` | 0–65535 |
| `dst_port` | `int \| None` | 0–65535 |
| `service` | `str \| None` | |
| `conn_state` | `str \| None` | Zeek conn_state string |
| `dns` / `tls` / `http` | block \| `None` | present only when that data exists |
| `source` | `str` | provenance tag, e.g. `injestion_core.features_jsonl` |
| `extra` | `dict` | unrecognized upstream keys, for forward compatibility |

Core numeric fields and both ports must arrive as genuine JSON numbers. A
stringly-typed number (`"orig_bytes": "123"`, `"dst_port": "443"`) is
**rejected**, not coerced: a quoted number means the producer is malformed,
and skipping the record loudly beats detecting on laundered data. An `int`
still satisfies a float field and a lossless float still satisfies an int
field.

`timestamp` is epoch seconds because that is what the network layer speaks.
The conversion to alert time happens once, in `schemas/timeutil.py`.

### Nested blocks

* **`DnsInfo`** — `uid`, `query`, `qtype`, `rcode`, `query_length`,
  `query_entropy`, `subdomain_entropy`, `is_txt`, `label_count`
* **`TlsInfo`** — `uid`, `ja3`, `ja3s`, `ja4`, `server_name`, `version`,
  `has_ja3`, `has_ja3s`
* **`HttpInfo`** — `uid`, `host`, `uri`, `user_agent`, `method`,
  `host_length`, `uri_length`, `uri_entropy`, `has_user_agent`,
  `user_agent_length`, `request_body_len`, `response_body_len`, `status_code`

All block fields are optional. Every model is **frozen**: the engine hands one
instance to every detector, so immutability stops one detector corrupting the
next one's input.

---

## 2. ThreatAlert v1.1

The frozen wire contract. `extra="forbid"` — unknown fields are an error.

| field | type | notes |
|---|---|---|
| `alert_id` | `str` | UUID v4, auto-generated; a supplied value is validated as a real v4 and canonicalized |
| `schema_version` | `"1.1"` | pinned literal |
| `event_start` | ISO-8601 UTC | `2026-08-29T00:20:10Z` |
| `event_end` | ISO-8601 UTC | must not precede `event_start` |
| `detected_at` | ISO-8601 UTC | auto, defaults to now |
| `event_scope` | enum | see below |
| `flow_id` | `str \| None` | `None` is valid for aggregate scopes |
| `src_ip` / `dst_ip` | `str \| None` | |
| `dst_port` | `int \| None` | 0–65535 |
| `protocol` | `str \| None` | |
| `threat_class` | enum | see below |
| `severity` | enum | chosen by the detector, never auto-derived |
| `score` | `float` | **always finite, always 0.0–1.0** |
| `score_type` | enum | see below |
| `evidence` | `dict` | free-form "why", shown to the analyst |
| `detector` | `str` | non-empty |
| `detector_version` | `str` | non-empty |
| `mitre_techniques` | `list[str]` | `Tnnnn` or `Tnnnn.nnn` |
| `incident_id` | `str \| None` | set later by `aggregators/` |

### Frozen vocabularies

* **`threat_class`** — `dga_domain`, `dns_tunnelling`, `c2_beaconing`,
  `encrypted_malware`, `ddos`, `port_scan`, `data_exfiltration`
* **`severity`** — `low`, `medium`, `high`, `critical`
* **`score_type`** — `calibrated_model`, `rule_score`, `anomaly_score`,
  `signature_match`
* **`event_scope`** — `flow`, `source_host`, `destination_host`, `host_pair`,
  `network`

Do not add, rename or remove a member without bumping `schema_version`.

### Score

`score` is **always a finite float in the inclusive range 0.0–1.0, for every
`score_type`**. The semantics differ per score type — a calibrated model
probability, a rule score, a normalized anomaly score, a signature match
confidence — but the wire value is always a normalized threat score so the UI
renders it consistently. `NaN`, infinity, `< 0` and `> 1` are all rejected.

### Time

`event_start`, `event_end` and `detected_at` are timezone-aware datetimes,
serialized to ISO-8601 UTC with a literal `Z`. **No epoch floats cross this
boundary.** Naive datetimes are rejected rather than assumed to be UTC —
guessing a timezone is inventing data. Sub-second precision is preserved when
present (`2026-08-29T00:20:10.123456Z`).

Use `ThreatAlert.to_wire()` for the exact JSON-ready dict.

---

## 3. Ingestion mapping (current)

Handled entirely by `adapters/ingestion_jsonl.py` + `adapters/encodings.py`.
**Nothing else in `detection_core` may know this table.**

| FlowEvent | source in `features.jsonl` |
|---|---|
| `src_ip`, `dst_ip`, `dst_port`, `proto`, `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts` | direct |
| `timestamp` | substring after the **last** colon of `flow_id` (IPv6-safe), or a top-level `timestamp`/`ts` if ingestion adds one |
| `conn_state` | decoded from `conn_state_encoded` |
| `uid` | back-filled from `dns`/`tls`/`http` block `uid` |
| `tls.version` | decoded from `ssl_version_encoded` |
| `http.method` | decoded from `method_encoded` |
| dns/tls/http derived features | direct |

### Deliberately ignored

These ingestion fields are **not** mapped onto `FlowEvent` and **not** copied
into `FlowEvent.extra`:

```
flow_rate  byte_rate  inter_arrival_mean  inter_arrival_stddev
unique_dst_ports  unique_dst_ips  src_ip_entropy
```

The upstream global-window logic is still being corrected, so nothing
downstream may depend on these values. They are listed in
`encodings.IGNORED_WINDOW_FIELDS` only so they do not trigger a schema-drift
warning.

Correct rolling state is computed inside `aggregators/sliding_window.py`,
driven by `FlowEvent.timestamp`, so a PCAP replay behaves exactly like a live
stream. The window is keyed by whatever entity a detector cares about:
`PortScanDetector` keys it by `src_ip`, `DDoSDetector` by `dst_ip`.

---

## 4. Integration TODOs

Fields `FlowEvent` has slots for that current ingestion does not emit. They
stay `None` — never invented. When ingestion supplies them, **only the adapter
changes**; no detector needs rewriting.

| field | blocks |
|---|---|
| `uid` (top level) | reliable flow correlation for flows with no dns/tls/http block |
| `src_port` | source-port based scan/exfil heuristics |
| `service` | protocol-aware detection |
| `dns.query`, `dns.qtype`, `dns.rcode` | **real DGA and DNS-tunnelling detection** — only entropy/length features exist today |
| `tls.ja3`, `tls.ja3s`, `tls.ja4`, `tls.server_name` | **JA3/JA4 fingerprint matching** for encrypted malware — only `has_ja3` booleans exist today |
| `http.host`, `http.uri`, `http.user_agent` | C2-over-HTTP heuristics on raw strings |

Also worth noting: ingestion's `conn_state` encoding has **no entry for Zeek's
`S0`** (connection attempt, no reply). `S0` therefore encodes to `0` and is
indistinguishable from "unknown" here. `S0` is a primary port-scan signal, so a
scan detector cannot rely on `conn_state` alone until this is addressed
upstream.

None of these require any change from us to `injestion_core/`, which is
read-only and owned by another team.

---

## 5. Schema drift

The adapter compares each record's top-level keys against
`KNOWN_TOP_LEVEL_FIELDS` and warns **once per novel key** on:

* an unknown field (kept in `FlowEvent.extra`, so no data is lost);
* an expected core field that has gone missing.

Warnings are logged and collected in `AdapterStats.drift_warnings`. This is how
we find out the ingestion format moved — from a warning, not from a wrong
alert.
