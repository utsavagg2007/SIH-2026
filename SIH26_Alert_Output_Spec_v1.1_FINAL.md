# SIH26-26145 — Final Alert Output Contract (v1.1)

**Purpose:** This is the frozen interface between the **Detection/ML layer** and the **Full-Stack layer**.  
The detector team can change models, thresholds, feature engineering, or internal logic without forcing frontend/backend changes, as long as every emitted alert follows this contract.

---

## 1. System Boundary

```text
PCAP / Live Traffic
        ↓
Ingestion + Feature Extraction
        ↓
Detection / ML Layer
        ↓
STANDARD ALERT JSON  ← this document freezes this contract
        ↓
Backend API
   ├── PostgreSQL (history)
   └── WebSocket/SSE (live feed)
        ↓
Dashboard
```

The full-stack team should **not depend on raw ML/network feature rows**.  
They should consume only the standardized alert object defined below.

---

# 2. Frozen Alert Schema — v1.1

Every detector emits **one JSON object per detection event**.

```json
{
  "alert_id": "uuid-v4",
  "schema_version": "1.1",

  "event_start": "2026-08-28T23:44:03Z",
  "event_end": "2026-08-28T23:44:15Z",
  "detected_at": "2026-08-28T23:44:15.300Z",

  "event_scope": "source_host",

  "flow_id": null,

  "src_ip": "10.0.0.5",
  "dst_ip": null,
  "dst_port": null,
  "protocol": "tcp",

  "threat_class": "port_scan",
  "severity": "high",

  "score": 0.90,
  "score_type": "rule_score",

  "evidence": {
    "unique_dst_ports": 1024,
    "unique_dst_ips": 254,
    "duration_sec": 12.4,
    "syn_no_ack_ratio": 0.99
  },

  "detector": "portscan_detector",
  "detector_version": "1.0.0",

  "mitre_techniques": ["T1046"],

  "incident_id": null
}
```

---

# 3. Field Contract

| Field | Type | Required | Meaning |
|---|---|---:|---|
| `alert_id` | string (UUID v4) | yes | Unique identifier for this alert |
| `schema_version` | string | yes | Must be `"1.1"` for this contract |
| `event_start` | ISO-8601 UTC string | yes | Start of suspicious activity/window |
| `event_end` | ISO-8601 UTC string | yes | End of suspicious activity/window |
| `detected_at` | ISO-8601 UTC string | yes | Time detector emitted the alert |
| `event_scope` | enum | yes | What the alert represents: flow, host, pair, destination, etc. |
| `flow_id` | string or null | yes | Real flow ID when alert maps to one flow; `null` for aggregate/window alerts |
| `src_ip` | string or null | yes | Source IP if one specific source exists |
| `dst_ip` | string or null | yes | Destination IP if one specific destination exists |
| `dst_port` | integer or null | yes | Destination port if meaningful |
| `protocol` | string or null | yes | Usually `tcp`, `udp`, or `null` if mixed/not applicable |
| `threat_class` | enum | yes | Threat category |
| `severity` | enum | yes | Dashboard priority |
| `score` | float 0.0–1.0 | yes | Strength/confidence score from detector |
| `score_type` | enum | yes | Explains what the score means |
| `evidence` | object | yes | Detector-specific explanation values |
| `detector` | string | yes | Detector/model name |
| `detector_version` | string | yes | Version of detector/model logic |
| `mitre_techniques` | array of strings | yes | MITRE ATT&CK technique IDs; may be empty |
| `incident_id` | string or null | yes | Filled later by correlation/incident layer |

---

# 4. Frozen Enums

## `threat_class`

The dashboard should support all of these values:

```text
dga_domain
dns_tunnelling
c2_beaconing
encrypted_malware
ddos
port_scan
data_exfiltration
```

> `c2_beaconing` is included because the ML/detection plan contains a dedicated beaconing detector.  
> `dns_tunnelling` is retained because it is also part of the threat-detection scope.

---

## `severity`

```text
low
medium
high
critical
```

Suggested UI meaning:

| Severity | Meaning |
|---|---|
| `low` | suspicious / low urgency |
| `medium` | requires review |
| `high` | strong malicious indication |
| `critical` | immediate/high-impact threat |

The **backend/frontend must not calculate severity independently**.  
Severity is emitted by the detection layer so one common policy is used everywhere.

---

## `score_type`

```text
calibrated_model
rule_score
anomaly_score
signature_match
```

### Meaning

- `calibrated_model`  
  Score comes from a trained/calibrated classifier. It may be shown as model confidence.

- `rule_score`  
  Normalized strength/deviation of a statistical/rule detector.  
  **Do not describe it as a literal attack probability.**

- `anomaly_score`  
  Normalized anomaly strength from an anomaly detector.

- `signature_match`  
  Match against known intelligence/signature material such as JA3/JA4 fingerprints.

### Frontend display recommendation

Instead of labeling every value:

```text
Confidence: 92%
```

use the safer universal label:

```text
Threat Score: 92%
```

Optionally show a small badge:

```text
RULE
MODEL
ANOMALY
SIGNATURE
```

based on `score_type`.

---

## `event_scope`

```text
flow
source_host
destination_host
host_pair
network
```

### Typical usage

| Threat | Recommended `event_scope` |
|---|---|
| DGA | `flow` |
| DNS tunnelling | `source_host` or `host_pair` |
| C2 beaconing | `host_pair` |
| Encrypted malware | `flow` or `host_pair` |
| DDoS | `destination_host` |
| Port scan | `source_host` |
| Data exfiltration | `flow`, `source_host`, or `host_pair` |

---

# 5. Nullable Field Rules

Do **not** put fake values such as:

```json
"src_ip": "multiple"
```

or:

```json
"dst_port": 0
```

just to satisfy a field.

Use `null` when the concept does not apply.

### Correct DDoS-style example

```json
{
  "flow_id": null,
  "src_ip": null,
  "dst_ip": "10.0.0.80",
  "dst_port": 80,
  "protocol": "tcp"
}
```

The UI can display `—` for `null`.

---

# 6. Evidence Contract

`evidence` is intentionally flexible.

The frontend must **not hardcode one evidence schema**.

Render it as a generic key/value list.

Example:

```json
"evidence": {
  "unique_dst_ports": 1024,
  "unique_dst_ips": 254,
  "duration_sec": 12.4,
  "syn_no_ack_ratio": 0.99
}
```

Another detector may emit:

```json
"evidence": {
  "query": "x7k2p9qz3v1m.com",
  "query_entropy": 3.91,
  "query_length": 16,
  "ngram_score": 0.02
}
```

Frontend behavior:

```text
Evidence
• unique dst ports: 1024
• unique dst ips: 254
• duration sec: 12.4
• syn no ack ratio: 0.99
```

Human-friendly label formatting can happen in the UI.

---

# 7. Recommended Evidence Keys by Threat

These are **recommended**, not globally mandatory.

## DGA

```text
query
query_entropy
query_length
subdomain_entropy
ngram_score
```

## DNS tunnelling

```text
query
query_length
query_entropy
subdomain_entropy
queries_per_sec
record_type
```

## C2 beaconing

```text
connection_count
mean_interval_sec
interval_stddev_sec
periodicity_score
destination_repetition
```

## Encrypted malware

```text
ja3
ja3s
ja4
matched_family
ssl_version
sni
periodicity_score
```

## DDoS

```text
flows_per_sec
bytes_per_sec
unique_sources
source_ip_entropy
syn_no_ack_ratio
window_seconds
```

## Port scan

```text
unique_dst_ports
unique_dst_ips
connection_attempts
rejected_connections
syn_no_ack_ratio
window_seconds
```

## Data exfiltration

```text
outbound_bytes
inbound_bytes
out_in_byte_ratio
baseline_ratio
anomaly_score
destination_rarity
```

---

# 8. Sample Alerts for Frontend Mock Data

The full-stack team can use these immediately while the real detectors are being built.

---

## 8.1 Port Scan

```json
{
  "alert_id": "11111111-1111-4111-8111-111111111111",
  "schema_version": "1.1",
  "event_start": "2026-08-28T23:44:03Z",
  "event_end": "2026-08-28T23:44:15Z",
  "detected_at": "2026-08-28T23:44:15.300Z",
  "event_scope": "source_host",
  "flow_id": null,
  "src_ip": "10.0.0.5",
  "dst_ip": null,
  "dst_port": null,
  "protocol": "tcp",
  "threat_class": "port_scan",
  "severity": "high",
  "score": 0.90,
  "score_type": "rule_score",
  "evidence": {
    "unique_dst_ports": 1024,
    "unique_dst_ips": 254,
    "connection_attempts": 1300,
    "syn_no_ack_ratio": 0.99,
    "window_seconds": 12.4
  },
  "detector": "portscan_detector",
  "detector_version": "1.0.0",
  "mitre_techniques": ["T1046"],
  "incident_id": null
}
```

---

## 8.2 DDoS

```json
{
  "alert_id": "22222222-2222-4222-8222-222222222222",
  "schema_version": "1.1",
  "event_start": "2026-08-28T23:42:55Z",
  "event_end": "2026-08-28T23:43:00Z",
  "detected_at": "2026-08-28T23:43:00.250Z",
  "event_scope": "destination_host",
  "flow_id": null,
  "src_ip": null,
  "dst_ip": "10.0.0.80",
  "dst_port": 80,
  "protocol": "tcp",
  "threat_class": "ddos",
  "severity": "critical",
  "score": 0.92,
  "score_type": "rule_score",
  "evidence": {
    "flows_per_sec": 8400.0,
    "bytes_per_sec": 124000000.0,
    "source_ip_entropy": 9.7,
    "unique_sources": 5200,
    "syn_no_ack_ratio": 0.98,
    "window_seconds": 5
  },
  "detector": "ddos_detector",
  "detector_version": "1.0.0",
  "mitre_techniques": ["T1498"],
  "incident_id": null
}
```

---

## 8.3 DGA Domain

```json
{
  "alert_id": "33333333-3333-4333-8333-333333333333",
  "schema_version": "1.1",
  "event_start": "2026-08-28T23:40:12Z",
  "event_end": "2026-08-28T23:40:12Z",
  "detected_at": "2026-08-28T23:40:12.110Z",
  "event_scope": "flow",
  "flow_id": "10.0.0.5:8.8.8.8:53:udp:1747147647.669",
  "src_ip": "10.0.0.5",
  "dst_ip": "8.8.8.8",
  "dst_port": 53,
  "protocol": "udp",
  "threat_class": "dga_domain",
  "severity": "high",
  "score": 0.94,
  "score_type": "calibrated_model",
  "evidence": {
    "query": "x7k2p9qz3v1m.com",
    "query_entropy": 3.91,
    "query_length": 16,
    "ngram_score": 0.02
  },
  "detector": "dga_classifier",
  "detector_version": "1.0.0",
  "mitre_techniques": ["T1568.002"],
  "incident_id": null
}
```

---

## 8.4 DNS Tunnelling

```json
{
  "alert_id": "44444444-4444-4444-8444-444444444444",
  "schema_version": "1.1",
  "event_start": "2026-08-28T23:40:50Z",
  "event_end": "2026-08-28T23:41:03Z",
  "detected_at": "2026-08-28T23:41:03.180Z",
  "event_scope": "host_pair",
  "flow_id": null,
  "src_ip": "10.0.0.12",
  "dst_ip": "203.0.113.9",
  "dst_port": 53,
  "protocol": "udp",
  "threat_class": "dns_tunnelling",
  "severity": "high",
  "score": 0.88,
  "score_type": "rule_score",
  "evidence": {
    "query_length": 187,
    "query_entropy": 4.62,
    "queries_per_sec": 42.0,
    "record_type": "TXT"
  },
  "detector": "dns_tunnel_detector",
  "detector_version": "1.0.0",
  "mitre_techniques": ["T1071.004"],
  "incident_id": null
}
```

---

## 8.5 C2 Beaconing

```json
{
  "alert_id": "55555555-5555-4555-8555-555555555555",
  "schema_version": "1.1",
  "event_start": "2026-08-28T23:30:00Z",
  "event_end": "2026-08-28T23:40:00Z",
  "detected_at": "2026-08-28T23:40:00.250Z",
  "event_scope": "host_pair",
  "flow_id": null,
  "src_ip": "10.0.0.21",
  "dst_ip": "198.51.100.55",
  "dst_port": 443,
  "protocol": "tcp",
  "threat_class": "c2_beaconing",
  "severity": "high",
  "score": 0.91,
  "score_type": "rule_score",
  "evidence": {
    "connection_count": 10,
    "mean_interval_sec": 60.2,
    "interval_stddev_sec": 1.4,
    "periodicity_score": 0.96,
    "destination_repetition": 1.0
  },
  "detector": "beaconing_detector",
  "detector_version": "1.0.0",
  "mitre_techniques": ["T1071"],
  "incident_id": null
}
```

---

## 8.6 Encrypted Malware

```json
{
  "alert_id": "66666666-6666-4666-8666-666666666666",
  "schema_version": "1.1",
  "event_start": "2026-08-28T23:42:20Z",
  "event_end": "2026-08-28T23:42:24Z",
  "detected_at": "2026-08-28T23:42:24.090Z",
  "event_scope": "flow",
  "flow_id": "10.0.0.5:185.220.101.7:443:tcp:1747147740.001",
  "src_ip": "10.0.0.5",
  "dst_ip": "185.220.101.7",
  "dst_port": 443,
  "protocol": "tcp",
  "threat_class": "encrypted_malware",
  "severity": "critical",
  "score": 0.97,
  "score_type": "signature_match",
  "evidence": {
    "ja3": "e7d705a3286e19ea42f587b344ee6865",
    "matched_family": "Cobalt Strike",
    "ssl_version": "TLSv13",
    "sni": "cdn-update-service.net"
  },
  "detector": "ja3_matcher",
  "detector_version": "1.0.0",
  "mitre_techniques": ["T1071.001"],
  "incident_id": null
}
```

---

## 8.7 Data Exfiltration

```json
{
  "alert_id": "77777777-7777-4777-8777-777777777777",
  "schema_version": "1.1",
  "event_start": "2026-08-28T23:43:10Z",
  "event_end": "2026-08-28T23:45:40Z",
  "detected_at": "2026-08-28T23:45:40.200Z",
  "event_scope": "host_pair",
  "flow_id": null,
  "src_ip": "10.0.0.22",
  "dst_ip": "198.51.100.14",
  "dst_port": 443,
  "protocol": "tcp",
  "threat_class": "data_exfiltration",
  "severity": "high",
  "score": 0.91,
  "score_type": "anomaly_score",
  "evidence": {
    "outbound_bytes": 512000000,
    "inbound_bytes": 10800000,
    "out_in_byte_ratio": 47.3,
    "baseline_ratio": 1.2,
    "anomaly_score": 0.91
  },
  "detector": "exfil_anomaly",
  "detector_version": "1.0.0",
  "mitre_techniques": ["T1048"],
  "incident_id": null
}
```

---

# 9. Backend Integration Contract

Recommended detector → backend interface:

```http
POST /api/v1/alerts
Content-Type: application/json
```

Body:

```json
<one alert object from this specification>
```

### Recommended responses

Created:

```http
201 Created
```

```json
{
  "status": "accepted",
  "alert_id": "uuid"
}
```

Invalid schema:

```http
422 Unprocessable Entity
```

Duplicate handling may be added later.

---

# 10. Live Dashboard Contract

The backend should own browser connections.

```text
Detector
   ↓
POST /api/v1/alerts
   ↓
Backend
   ├── persist in PostgreSQL
   └── push alert to WebSocket
             ↓
          Dashboard
```

Recommended WebSocket endpoint:

```text
/ws/alerts
```

Recommended WebSocket message:

```json
{
  "type": "alert.created",
  "data": {
    "...": "full v1.1 alert object"
  }
}
```

This lets future WebSocket event types coexist, e.g.:

```text
alert.created
alert.updated
incident.created
system.status
```

---

# 11. History API Suggestions

The full-stack team may implement:

```text
GET /api/v1/alerts
GET /api/v1/alerts/{alert_id}
```

Useful filters:

```text
?threat_class=ddos
?severity=critical
?src_ip=10.0.0.5
?dst_ip=10.0.0.80
?from=...
?to=...
?limit=50
```

These API routes are a backend recommendation; the **JSON alert schema is the frozen part**.

---

# 12. TypeScript Interface for Frontend

The frontend team can start with:

```ts
export type ThreatClass =
  | "dga_domain"
  | "dns_tunnelling"
  | "c2_beaconing"
  | "encrypted_malware"
  | "ddos"
  | "port_scan"
  | "data_exfiltration";

export type Severity =
  | "low"
  | "medium"
  | "high"
  | "critical";

export type ScoreType =
  | "calibrated_model"
  | "rule_score"
  | "anomaly_score"
  | "signature_match";

export type EventScope =
  | "flow"
  | "source_host"
  | "destination_host"
  | "host_pair"
  | "network";

export interface ThreatAlert {
  alert_id: string;
  schema_version: "1.1";

  event_start: string;
  event_end: string;
  detected_at: string;

  event_scope: EventScope;

  flow_id: string | null;

  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: "tcp" | "udp" | string | null;

  threat_class: ThreatClass;
  severity: Severity;

  score: number;
  score_type: ScoreType;

  evidence: Record<string, string | number | boolean | null>;

  detector: string;
  detector_version: string;

  mitre_techniques: string[];

  incident_id: string | null;
}
```

---

# 13. Recommended Dashboard Card Layout

Each alert card can use the same component.

```text
┌─────────────────────────────────────────────┐
│ CRITICAL                     DDoS           │
│ Threat Score: 92%             RULE          │
│                                             │
│ Target: 10.0.0.80:80                        │
│ Protocol: TCP                               │
│ 23:42:55 → 23:43:00                         │
│                                             │
│ Evidence                                    │
│ • flows/sec: 8,400                          │
│ • unique sources: 5,200                     │
│ • SYN/no-ACK ratio: 0.98                    │
│                                             │
│ MITRE: T1498                                │
│ Detector: ddos_detector v1.0.0              │
└─────────────────────────────────────────────┘
```

The component should:

1. map `threat_class` → title/icon,
2. map `severity` → visual severity style,
3. show `score` as **Threat Score**,
4. show a small badge from `score_type`,
5. render `evidence` generically,
6. tolerate `null` IP/port/flow fields,
7. show MITRE technique IDs when present.

---

# 14. Database Mapping Recommendation

The backend may store common fields in columns:

```text
alert_id
schema_version
event_start
event_end
detected_at
event_scope
flow_id
src_ip
dst_ip
dst_port
protocol
threat_class
severity
score
score_type
detector
detector_version
incident_id
```

Store flexible fields as PostgreSQL JSON/JSONB:

```text
evidence
mitre_techniques
```

This is only a database recommendation. The detector output contract remains JSON.

---

# 15. What the Detection Team Guarantees

The detection/ML team guarantees:

- every alert follows schema v1.1,
- `score` is always between `0.0` and `1.0`,
- `score_type` explains the meaning of the score,
- timestamps are UTC ISO-8601,
- enum values use lowercase exact strings,
- `evidence` is valid JSON,
- non-applicable fields use `null`, not fake placeholder values,
- `alert_id` is unique,
- `detector_version` is always supplied.

---

# 16. What the Full-Stack Team Must NOT Assume

Do not assume:

- every alert has a real `flow_id`,
- every alert has one source IP,
- every alert has one destination IP,
- every alert has a destination port,
- every detector uses ML,
- `score` always means probability,
- all `evidence` objects have the same keys,
- one alert equals one network flow.

---

# 17. Future-Compatible Fields

## Incident correlation

For MVP:

```json
"incident_id": null
```

Later:

```text
Individual alerts
       ↓
Correlation Engine
       ↓
Incident
```

and alerts may become:

```json
"incident_id": "INC-2026-000123"
```

No frontend schema change is required.

---

## Deduplication

If retries/duplicate alerts become a problem later, v1.2 may add:

```json
"dedup_key": "stable-hash"
```

Do not block MVP development on this.

---

# 18. Versioning Rule

This document is frozen as:

```text
schema_version = "1.1"
```

### Compatible changes

The detector may:

- add new keys inside `evidence`,
- improve detector logic,
- retrain models,
- update `detector_version`.

These do **not** require a schema bump.

### Breaking changes

Changing/removing:

- top-level field names,
- field types,
- enum semantics,

requires a new `schema_version`.

---

# 19. Final Contract Summary

```text
INGESTION
    ↓
Detection / ML
    ↓
ThreatAlert v1.1 JSON
    ↓
POST /api/v1/alerts
    ↓
BACKEND
   ├── PostgreSQL
   └── /ws/alerts
        ↓
FRONTEND
```

The full-stack team can build with the mock alerts in Section 8 **before the real models are connected**.

When the detector layer is ready, mock data is simply replaced by real v1.1 alert objects.

---

# 20. Freeze Checklist

Before both teams start integrating, agree on:

- [x] `schema_version = "1.1"`
- [x] seven `threat_class` enum values
- [x] four severity values
- [x] four score types
- [x] nullable flow/IP/port fields
- [x] event time window + detection time
- [x] flexible `evidence`
- [x] detector name + version
- [x] MITRE array
- [x] `incident_id` reserved for later correlation

**After this is accepted by both ML/detection and full-stack teams, treat the top-level schema as frozen.**
