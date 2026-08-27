# ingestion_core

Rust + PyO3 library that parses Zeek logs (`conn.log`, `dns.log`, `ssl.log`,
`http.log`) into structured records and extracts security-relevant features for
the passive threat-detection pipeline.

## Layout

- `src/zeek_parser/` — header-aware parsers for each Zeek log type
- `src/features/` — flow-level, sliding-window, DNS, TLS, and HTTP feature extractors
- `src/utils/` — entropy helpers
- `pipeline.py` — orchestration: PCAP → Zeek → parse → join by uid → features (JSON lines)
- `scripts/run_zeek.sh` — Docker wrapper that runs Zeek on a PCAP

## Build & install (per-project venv)

```bash
python3 -m venv .venv
.venv/bin/pip install maturin
.venv/bin/maturin develop
```

Uses pyo3 0.25, which supports Python 3.14 natively (no compat flag needed).

## Running Zeek

Zeek runs in Docker (no local install). Two options depending on Docker access:

```bash
# As a user with docker socket access:
./scripts/run_zeek.sh pcaps/capture.pcap zeek_output

# If you need root (e.g. docker group / sudo):
sudo ./scripts/run_zeek.sh pcaps/capture.pcap zeek_output
```

For JA3/JA4 hashes add `--ja4` (uses the `activecm/zeek:8.0.6` image).

## Pipeline (feature extraction)

`pipeline.py` joins the log types by `uid` and emits one JSON-line feature
vector per flow. Because the Docker step needs socket access, the usual flow is
to run Zeek as root and the Python step as your normal user:

```bash
sudo ./scripts/run_zeek.sh pcaps/capture.pcap zeek_output
.venv/bin/python pipeline.py --skip-zeek -o features.jsonl --window 60
```

Or, if your user can run Docker, do it in one shot (Zeek runs automatically):

```bash
.venv/bin/python pipeline.py pcaps/capture.pcap -o features.jsonl --ja4
```

Output `features.jsonl` has one object per flow, with `dns`/`tls`/`http` nested
feature blocks when those records exist. Hand the file to the ML team.

## Library usage

```python
from ingestion_core import (
    parse_conn_log, parse_dns_log, parse_ssl_log, parse_http_log,
    extract_flow_features, extract_window_features,
    extract_dns_features, extract_tls_features, extract_http_features,
)

conn_json = parse_conn_log("zeek_output/conn.log")
flow_feats = extract_flow_features(conn_json)
window_feats = extract_window_features(conn_json, window_secs=60.0)
```

All functions take/return JSON strings; parse each in Python and join by `uid`.

---

## How the code works (internals)

### Architecture

The heavy lifting (parsing + feature math) lives in Rust and is exposed to
Python through PyO3. Python (`pipeline.py`) only orchestrates: it runs Zeek in
Docker, calls the Rust parsers, joins the four log types by `uid`, and writes
JSON lines. The FFI boundary between Rust and Python is **JSON strings**, so the
ML/Python side can evolve without touching the Rust core.

### Parsing layer — `src/zeek_parser/`

- `header.rs` reads Zeek's `#fields` and `#types` comment lines and builds a
  `field name → column index` map. Every value is then read **by name**, so the
  parser keeps working even if Zeek reorders columns between versions.
- `types.rs` defines the in-memory structs: `FlowRecord`, `DnsRecord`,
  `SslRecord`, `HttpRecord`.
- One parser file per log type (`conn_log.rs`, `dns_log.rs`, `ssl_log.rs`,
  `http_log.rs`) splits each tab-separated line and pulls fields by name into the
  matching struct.

### Feature layer — `src/features/`

- `flow.rs` — `FlowFeatures`: per-conn ratios (byte/packet), duration, and the
  `conn_state` enum encoded to an integer (see mapping below).
- `temporal.rs` — `SlidingWindow`: sorts records by timestamp, keeps only the
  last `window_secs` seconds of flows, and emits aggregate features per flow
  (flow/byte rate, inter-arrival stats, fan-out counts, source-IP entropy).
- `dns_features.rs` — entropy / length / label-count features for DGA and DNS
  tunneling detection.
- `tls_features.rs` — JA3/JA3s presence and TLS version / cipher encoding for
  encrypted-malware signals.
- `http_features.rs` — method/host/URI/body/status features for C2-over-HTTP and
  exfil detection.
- `utils/entropy.rs` — Shannon-entropy helpers used by DNS and HTTP.

### Binding layer — `src/lib.rs`

Exposes eight `#[pyfunction]`s: four parsers (file → JSON array of records) and
four extractors (JSON records → JSON array of feature objects). `maturin develop`
builds the `ingestion_core` importable module.

---

## Feature file format (for ML teammates)

### File shape

`features.jsonl` is **UTF-8, newline-delimited JSON** — one JSON object per
line, no header, no enclosing array. Each line is **one network flow** (one
`conn.log` record), enriched with sliding-window features and, when present,
nested DNS / TLS / HTTP feature blocks.

- `flow_id` (`"src_ip:dst_ip:dst_port:proto:ts"`) uniquely identifies the flow.
- `uid` inside each nested block links a flow to its DNS / TLS / HTTP sub-records.
- Lines follow `conn.log` order; window features are computed by timestamp, not
  line order.

### Top-level fields (present on every line)

| field | type | meaning | threat hint |
|---|---|---|---|
| `flow_id` | string | `src_ip:dst_ip:dst_port:proto:ts` | key |
| `src_ip` / `dst_ip` | string | endpoints | |
| `dst_port` | int | destination port | scanning / C2 ports |
| `proto` | string | transport protocol | |
| `duration` | float | connection duration (s) | |
| `orig_bytes` / `resp_bytes` | int | bytes sent / received | |
| `byte_ratio` | float | `resp_bytes / (orig_bytes + 1)` | **low ⇒ exfiltration** |
| `orig_pkts` / `resp_pkts` | int | packets sent / received | |
| `pkt_ratio` | float | `resp_pkts / (orig_pkts + 1)` | |
| `conn_state_encoded` | int (0–12) | see mapping below | REJ/RST ⇒ scanning |
| `flow_rate` | float | flows/sec in window | **high ⇒ DDoS / scanning** |
| `byte_rate` | float | bytes/sec in window | |
| `inter_arrival_mean` | float | mean inter-flow gap (s) | |
| `inter_arrival_stddev` | float | stddev of gap | **low ⇒ beaconing** |
| `unique_dst_ports` | int | distinct dst ports in window | **high ⇒ scanning** |
| `unique_dst_ips` | int | distinct dst IPs in window | |
| `src_ip_entropy` | float | Shannon entropy of src IPs | **low ⇒ spoofed DDoS** |

`conn_state_encoded` mapping: `S1`→1, `S2`→2, `S3`→3, `SF`→4, `REJ`→5,
`RSTO`→6, `RSTOS0`→7, `RSTR`→8, `RSTRH`→9, `SH`→10, `SHR`→11, `OTH`→12,
unknown→0.

### Optional `dns` block (present iff the flow had a DNS query)

| field | type | meaning | threat hint |
|---|---|---|---|
| `uid` | string | links to flow | |
| `query_length` | int | full query length | long ⇒ DGA |
| `query_entropy` | float | entropy of query name | **high ⇒ DGA** |
| `subdomain_entropy` | float | entropy of subdomain part | **high ⇒ DGA / tunneling** |
| `is_txt` | bool | query was TXT type | **TXT ⇒ tunneling** |
| `label_count` | int | number of DNS labels | many ⇒ DGA |

### Optional `tls` block (present iff the flow carried JA3/JA3s)

| field | type | meaning | threat hint |
|---|---|---|---|
| `uid` | string | links to flow | |
| `has_ja3` / `has_ja3s` | bool | client / server hash present | |
| `ssl_version_encoded` | int (0–5) | see mapping | old/rare ⇒ suspicious |
| `cipher_encoded` | int | coarse cipher encoding | **placeholder — needs a real JA3 lookup table** |

`ssl_version_encoded` mapping: `TLSv10`→1, `TLSv11`→2, `TLSv12`→3, `TLSv13`→4,
`SSLv3`→5, unknown→0.

### Optional `http` block (present iff the flow had an HTTP request)

| field | type | meaning | threat hint |
|---|---|---|---|
| `uid` | string | links to flow | |
| `method_encoded` | int (0–9) | GET→1, POST→2, HEAD→3, PUT→4, DELETE→5, OPTIONS→6, CONNECT→7, TRACE→8, PATCH→9, other→0 | |
| `host_length` | int | length of Host header | long/high-entropy ⇒ C2 |
| `uri_length` | int | length of request URI | |
| `uri_entropy` | float | entropy of URI | **high ⇒ obfuscated / exfil URL** |
| `has_user_agent` | bool | request had a User-Agent | missing ⇒ scripting/C2 |
| `user_agent_length` | int | length of User-Agent | |
| `request_body_len` | int | bytes in request body | **large ⇒ exfil** |
| `response_body_len` | int | bytes in response body | |
| `status_code` | int | HTTP status code | 4xx/5xx ⇒ probing |

### Example line

```json
{
  "flow_id": "192.168.1.100:10.0.0.1:80:tcp:1712345678.123",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.1",
  "dst_port": 80,
  "proto": "tcp",
  "duration": 0.123,
  "orig_bytes": 1234,
  "resp_bytes": 5678,
  "byte_ratio": 4.59757085020243,
  "orig_pkts": 10,
  "resp_pkts": 8,
  "pkt_ratio": 0.8,
  "conn_state_encoded": 4,
  "flow_rate": 1000000.0,
  "byte_rate": 6912000.0,
  "inter_arrival_mean": 0.0,
  "inter_arrival_stddev": 0.0,
  "unique_dst_ports": 1,
  "unique_dst_ips": 1,
  "src_ip_entropy": 0.0,
  "http": {
    "uid": "C1",
    "method_encoded": 2,
    "host_length": 11,
    "uri_length": 15,
    "uri_entropy": 3.589898095464287,
    "has_user_agent": true,
    "user_agent_length": 8,
    "request_body_len": 512,
    "response_body_len": 2048,
    "status_code": 200
  }
}
```

(When a flow also has DNS or TLS, the same line would additionally contain
`dns` / `tls` blocks.)

### Known limitation

If a single connection (`uid`) spans multiple HTTP requests, the `http` block
contains features for the **last** matching `http.log` row only (same collapse
applies to DNS/TLS when a uid repeats). For most captures this is one row per
uid; tighten this if your traffic has many requests per connection.

---

## Tests

```bash
cargo test
```
