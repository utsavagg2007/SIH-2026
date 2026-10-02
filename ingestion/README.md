# ingestion_core

Rust + PyO3 library that parses Zeek logs (`conn.log`, `dns.log`, `ssl.log`,
`http.log`) into structured records and extracts security-relevant features for
the passive threat-detection pipeline.

## Layout

- `src/zeek_parser/` — header-aware parsers for each Zeek log type
- `src/features/` — flow-level, sliding-window, DNS, TLS, and HTTP feature extractors
- `src/utils/` — entropy helpers
- `pipeline.py` — frozen legacy features, explicit detector-v2 features, and the opt-in canonical sidecar
- `scripts/run_zeek.sh` — Docker wrapper for standard, deterministic, canonical, JA4-only, and full-fingerprint Zeek runs
- `scripts/build_ja4_runtime.sh` — reproducible, integrity-checked JA4 image build
- `runtime/ja4-runtime.lock` — immutable JA4 build and image identities
- `vendor/ja4-zeek/` — minimal licensed and hash-pinned FoxIO JA4 source
- `scripts/build_tls_fingerprint_runtime.sh` — offline reproducible JA3/JA3S/JA4 image build
- `runtime/tls-fingerprint-runtime.lock` — immutable composite runtime identities
- `vendor/ja3-zeek/` — minimal BSD-licensed, commit- and hash-pinned Salesforce source
- `scripts/generate_synthetic_pcap.py` — dependency-free deterministic M1D PCAP generator

## Build & install (single canonical venv at repo root)

```bash
# from repository root
python3 -m venv .venv
.venv/bin/pip install "maturin>=1.0,<2.0>"
.venv/bin/maturin develop --manifest-path ingestion/Cargo.toml
# or: bash -c 'source .venv/bin/activate && maturin develop --manifest-path ingestion/Cargo.toml'
```

The PyO3 crate itself supports Python 3.14, but the integrated monorepo's pinned
backend dependencies currently require Python 3.11–3.13; Python 3.12 is the
qualified root environment. The `.venv` directory is ignored by git — do not
commit it and do not create a nested `ingestion/.venv`.

## Running Zeek

Zeek runs in Docker (no local install). Two options depending on Docker access:

```bash
# As a user with docker socket access:
./scripts/run_zeek.sh pcaps/capture.pcap zeek_output

# If you need root (e.g. docker group / sudo):
sudo ./scripts/run_zeek.sh pcaps/capture.pcap zeek_output
```

### Docker without sudo (local testing)

The Zeek wrapper and Docker E2E harnesses shell out to `docker`. If you see
`permission denied while trying to connect to the docker API at
unix:///var/run/docker.sock`, your user is not yet on the socket:

```bash
sudo usermod -aG docker $USER
# then ONE of: log out and back in, or refresh this shell with:
newgrp docker
docker run --rm hello-world        # no password prompt = fixed
docker images --digests | grep -E "73e80|sih-zeek"   # pinned fingerprint images visible
```

Notes: group membership is evaluated at login, which is why a fresh shell can
still fail right after `usermod` (compare `groups` vs `getent group docker`).
Membership in `docker` is root-equivalent by design — accepted tradeoff for a
dev box, never for shared/production hosts. Ingestion runs on the machine
watching the traffic and is not part of the deploy — see `DEPLOYMENT.md` §1.
Fingerprint images additionally need their explicit build scripts before
`--ja4` or `--tls-fingerprints` runs.

The supported official runtime is frozen to:

```text
zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3
platform: linux/amd64
canonical invocation: zeek -D -C -r <pcap> local
```

`-D` initializes random seeds deterministically, `-C` ignores invalid packet
checksums for offline analysis, and `local` loads the standard local policy.
Canonical replay must use all three. `pcap_dataset` also requests this exact
deterministic standard invocation through the internal `deterministic_zeek`
pipeline option; the ordinary pipeline CLI/default remains unchanged. The
package-free official profile does not install fingerprint packages, so
JA3/JA3S/JA4 remain optional there. The separate `--ja4` profile uses the same exact base digest plus the minimal
vendored FoxIO JA4 source and a JA4-only loader. Build it explicitly before use:

```bash
./scripts/build_ja4_runtime.sh
```

The build uses a fixed epoch and disabled provenance attestations, and must
reproduce the image/config digests in `runtime/ja4-runtime.lock`. Runtime use
verifies repository inputs, the vendored file manifest, image identity, and
image labels, then executes the immutable image ID without any network fetch or
fallback. Only `ssl.log.ja4` is added; JA4S/JA4H/JA4L/JA4T fields are rejected.

The mutually exclusive `--tls-fingerprints` profile composes that exact JA4
source with the minimum vendored Salesforce JA3/JA3S Zeek scripts. Build it
offline from repository-controlled inputs, then run it explicitly:

```bash
./scripts/build_tls_fingerprint_runtime.sh
./scripts/run_zeek.sh pcaps/capture.pcap zeek_output --tls-fingerprints
```

The composite lock binds the source repository/commit/tree/archive, both source
manifests, loader and Dockerfile hashes, base digest, image ID, and config
digest. Runtime execution uses `--network none`, verifies all inputs and image
labels, adds exactly `ja3`, `ja3s`, and `ja4` to `ssl.log`, and never falls back.

The one-command shell wrapper is supported on Linux, WSL2, compatible Linux
Docker environments, and native Windows when Git Bash is installed. Native
Windows without Git Bash can canonicalize existing logs with `--skip-zeek`.

## Pipeline (feature extraction)

`pipeline.py` joins the log types by `uid` and emits one JSON-line feature
vector per flow. Because the Docker step needs socket access, the usual flow is
to run Zeek as root and the Python step as your normal user:

```bash
sudo ./scripts/run_zeek.sh pcaps/capture.pcap zeek_output
# from repo root, or ../.venv/bin/python when inside ingestion/
.venv/bin/python ingestion/pipeline.py --skip-zeek --keep-logs ingestion/zeek_output -o features.jsonl --window 60
```

Or, if your user can run Docker, do it in one shot (Zeek runs automatically):

```bash
.venv/bin/python ingestion/pipeline.py pcaps/capture.pcap -o features.jsonl --ja4
.venv/bin/python ingestion/pipeline.py pcaps/capture.pcap -o features.jsonl --tls-fingerprints
```

Both fingerprint modes are valid with `--canonical-output` after their selected
image has been built. They fail closed if the locked image or any locked
source/loader input is unavailable or altered. `--skip-zeek` rejects either
fingerprint flag because a pre-existing log directory cannot prove which
runtime produced it; omit the flag to parse those logs, and source fingerprints
are still transported when present.

Output `features.jsonl` has one object per flow, with `dns`/`tls`/`http` nested
feature blocks when those records exist. Hand the file to the ML team.

The default feature contract is the frozen M1D legacy projection and remains
byte-compatible with its golden artifact. Detection must opt in to the richer,
versioned projection explicitly:

```bash
.venv/bin/python ingestion/pipeline.py capture.pcap \
  -o detector_features.jsonl \
  --feature-profile detector-v2 \
  --stats
```

`detector-v2` adds the observed event time, source port, service, raw connection
state and protocol observables required by the current detectors. Records are
stable-sorted by event time. For several protocol rows sharing one UID, it
keeps the earliest event-time row as the compatibility scalar, reports
`transaction_count`, and preserves every physical source row in the matching
`dns_transactions`, `tls_transactions`, or `http_transactions` array. Arrays
remain in source order and carry per-row timestamps and source ordinals.
Canonical output independently retains all DNS/TLS/HTTP rows. Global legacy window features remain off in detector-v2
because detection computes entity-keyed windows; they can be requested only
with `--window-features`. In detector-v2, `-o -` streams flushed JSONL to stdout
and all status/`--stats` text stays on stderr.

For TLS, detector-v2 uses a lossless-derived projection that adds exact source
`ja4` without changing the frozen legacy `SslRecord`; JA3 and JA3S retain their
existing exact-source transport. Missing, unset, and empty values become
`null`, and no fingerprint is derived from another fingerprint, SNI, cipher,
version, addresses, or ports. Standard mode emits none, JA4 mode emits only
JA4, and full mode emits source JA3/JA3S/JA4 when the handshake supports them.
The frozen `#fields` evidence lives under `tests/fixtures/runtime_headers/`.
The encrypted-malware signature path also requires a trusted local indicator
feed; no indicators ship by default.

## CanonicalObservation v1 sidecar

Canonical output is opt-in and does not replace or reshape `features.jsonl`:

```bash
# Normal PCAP mode: hashes the original PCAP and uses fresh deterministic logs.
.venv/bin/python ingestion/pipeline.py ingestion/pcaps/capture.pcap \
  -o features.jsonl \
  --canonical-output canonical_observations.jsonl \
  --sensor-id 'sensor/site-a'

# Existing-log mode with the original PCAP still available.
.venv/bin/python ingestion/pipeline.py ingestion/pcaps/capture.pcap --skip-zeek \
  --keep-logs ingestion/zeek_output -o features.jsonl \
  --canonical-output canonical_observations.jsonl \
  --sensor-id 'sensor/site-a'

# Existing-log mode without the PCAP: caller asserts its original SHA-256.
.venv/bin/python ingestion/pipeline.py --skip-zeek --keep-logs ingestion/zeek_output \
  -o features.jsonl \
  --canonical-output canonical_observations.jsonl \
  --sensor-id 'sensor/site-a' \
  --input-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

When running inside `ingestion/`, use `../.venv/bin/python pipeline.py ...` instead of `.venv/bin/python ...`.

Canonical mode requires the exact, nonempty `sensor_id`; it is preserved
without case conversion or trimming because it participates in record identity.
The original PCAP SHA-256 is authoritative when a readable PCAP is supplied.
Without it, `--skip-zeek` requires a 64-hex caller assertion. Canonical and
legacy output paths must differ, and an existing canonical target is rejected.
In normal canonical mode the PCAP is hashed before Zeek and again immediately
after Zeek. A mismatch stops before logs are copied and before either legacy or
canonical output is published; the fresh temporary log workspace is cleaned.

Normal canonical mode writes Zeek logs to a fresh run-scoped workspace, parses
only that workspace, then copies generated logs into `--keep-logs`. This prevents
stale optional logs from entering the canonical artifact. The artifact is
published atomically through a same-directory temporary file and narrow sidecar
reservation; it is compact UTF-8 JSONL with LF separators in flow, DNS, TLS,
HTTP type order and physical source-row order within each type. Publication uses
an atomic same-filesystem no-replace hard-link operation: an existing canonical
file is never overwritten, there is no force option, and a target created at the
publication instant wins unchanged. Concurrent writers fail safely. A successful
zero-observation run publishes a zero-byte file. The destination filesystem must
support hard links; an unsupported-filesystem error fails before publication and
leaves no final artifact rather than falling back to overwrite-capable rename.

`--keep-logs` is a **copy destination**, not an exact current-run snapshot.
Canonical and legacy processing consume only the fresh run-scoped workspace,
but the requested destination may retain unrelated files or older optional logs.
The pipeline never deletes those files. If copying a current-run log fails, the
operation stops before legacy/canonical publication and reports that the keep
directory may contain a partial set of current-run copies.

Missing optional-log behavior is explicit:

- missing `dns.log` emits zero DNS observations plus a notice;
- missing `ssl.log` emits zero TLS observations plus a notice;
- missing `http.log` emits zero HTTP observations plus a notice;
- external `--skip-zeek` input without `conn.log` fails;
- protocol logs without `conn.log` are an incomplete-set failure;
- a successful fresh Zeek run with no supported logs is allowed and publishes
  empty legacy and canonical JSONL files.

One UTC `observed_at` value is captured for the entire canonical run. Canonical
counts, bounded redacted row diagnostics, and missing optional-log notices go to
stderr; the existing legacy success line remains on stdout. If canonical
publication fails after legacy output succeeds, the valid legacy artifact is
preserved and the overall dual-output operation fails.

The checked-in non-sensitive E2E fixture is
`tests/fixtures/pcap/m1d_synthetic.pcap`. It uses only documentation addresses
and contains UDP DNS, TCP DNS, two HTTP transactions on one connection, and a
minimal TLS handshake. Regenerate it only with:

```bash
.venv/bin/python ingestion/scripts/generate_synthetic_pcap.py
# or from ingestion/: ../.venv/bin/python scripts/generate_synthetic_pcap.py
```

Its frozen digest is recorded beside the PCAP. Actual Zeek 8.0.10 `#fields`
evidence is stored in `tests/fixtures/runtime_headers/zeek_8.0.10_m1d_fields.txt`;
parsers remain header-driven rather than positional.

### Atomic output and stale-lock recovery

For target `canonical.jsonl`, the writer reservation is named exactly
`.canonical.jsonl.canonical.lock`. Temporary links are named
`.canonical.jsonl.canonical.<PID>.<SEQUENCE>.tmp` in the same directory. The
writer fails closed when the lock already exists and never removes an existing
lock automatically: age alone cannot distinguish a crashed writer from a slow,
active writer.

After a crash, first verify that no pipeline/writer process is active, inspect
the final target, and inspect same-directory `.tmp` files. A complete final
target is authoritative and must not be overwritten. Leftover temporary files
may be inspected and manually removed only after confirming no writer owns them.
Remove the sidecar lock manually only after the same confirmation; never remove
an active writer's lock. A subsequent run will then acquire a new lock normally.
Use the process supervisor that launched ingestion as the primary ownership
record. On Linux, corroborate with `ps -ef` and `lsof <lock-path>` when `lsof` is
available; on Windows, inspect the owning pipeline/service process and open-file
state with the deployment's process monitor. The lock intentionally contains no
PID lease and no age-based deletion rule, so an empty or old lock alone is never
proof that deletion is safe.

On POSIX, the parent directory is synced after the complete artifact appears. If
that durability confirmation fails, the API reports explicitly that the artifact
was published completely but durability is unconfirmed; it does not delete the
complete file or claim that no artifact exists. Windows flushes/syncs the complete
temporary file before atomic publication but does not currently expose an
equivalent directory-handle durability sync through this API.

### Pinned Docker M1D replay

With Docker Desktop/Engine available, this single repository-owned command
regenerates all PCAP fixtures into a temporary directory, compares their bytes,
runs fresh A/B and renamed-path C replays with the pinned Zeek image, compares
runtime headers, validates every canonical line against the frozen schema,
checks data minimization, and qualifies empty, ARP-only, and invalid PCAPs:

```powershell
pwsh -NoProfile -File tests/test_m1d_docker_e2e.ps1
```

The expected synthetic result is exactly 4 flow, 2 DNS, 1 TLS, and 2 HTTP
observations (9 total), with identical UIDs, record IDs, flow links, ordering,
and fixed-clock bytes across A/B/C.

## Library usage

```python
from ingestion_core import (
    parse_conn_log, parse_dns_log, parse_ssl_log, parse_http_log,
    extract_flow_features, extract_window_features,
    extract_dns_features, extract_tls_features, extract_http_features,
)

# requires: .venv/bin/maturin develop --manifest-path ingestion/Cargo.toml
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

Exposes four parsers, five feature extractors, the streaming SHA-256 helper, and
the narrow canonical JSONL orchestration binding. `maturin develop` builds the
`ingestion_core` importable module. Canonical observations are serialized in
Rust and are never returned to Python as one giant JSON array.

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

### Optional `tls` block (present iff the flow had a TLS record)

| field | type | meaning | threat hint |
|---|---|---|---|
| `uid` | string | links to flow | |
| `has_ja3` / `has_ja3s` | bool | client / server source hash present; true in full mode when the handshake supports it | |
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

In the frozen `legacy-m1d` projection, repeated protocol rows retain the
historical last-row collapse. `detector-v2` instead chooses the earliest row by
event time for scalar compatibility, exposes exact `transaction_count`, and
preserves every row in source-order transaction arrays. Canonical output also
preserves every row independently.

---

## NetFlow v5 F2/F3 Rust API

`netflow::v5::parse_netflow_v5_datagram` is the stateless, lossless decoder for
one complete v5 UDP payload. `netflow::normalize::NetFlowV5Normalizer` is a
separate stateful offline normalizer. It requires an explicit
`ExportDatagramContext` containing the sensor, artifact SHA-256, stable exporter
identity, capture/observation time, and physical datagram ordinal. No local path,
file name, modification time, or current wall clock participates in output.

F3 reconstructs start/end timestamps with checked integer nanosecond arithmetic.
The default maximum end age and duration is 24 hours; it is a configurable
normalization policy, not a NetFlow wire constant. Records outside the configured
limit are skipped individually with diagnostics.

Ordering is checked before the age limit. A numerically reversed `First/Last`
or `Last/SysUptime` pair is accepted as one wrap only when its modular forward
interval is within the configured age limit and strictly below half the u32
uptime cycle (2,147,483,648 ms). The reconstructed start-to-export interval must
also be below one complete cycle. Ambiguous/reversed intervals emit
`FlowTimeOrderingInvalid`, with bounded First, Last, SysUptime, modular duration
and end-age context. There is zero future-skew tolerance: `Last=SysUptime+1 ms`
is rejected. The one-second exporter boot-epoch tolerance does not apply to
record ordering. Ordinary ordered intervals exceeding the configured limit
still emit `FlowAgeExceeded`. Rejected rows do not supply exporter clock state;
sequence advancement still accounts for all records in a valid source header.

For IPv4 ICMP (`protocol=1`), the v5 destination-port word encodes
`type * 256 + code`; F3 maps its high/low bytes to `icmp_type`/`icmp_code` and
omits generic transport ports. This follows the
[Cisco v5 representation](https://docs.crossworkassurance.cisco.com/docs/netflow).
A zero word exposes type 0/code 0; v5 provides no separate presence bit, and F3
does not infer a different identity from the source-port word or other fields.
F2 preserves both raw port words unchanged. For interface metadata, zero input
or output ifIndex maps independently to absence; nonzero N maps to `ifindex:N`.

Record identity uses the versioned `co-netflow-v5-id-v1` UUIDv5 algorithm over
the sensor, input SHA-256, exporter, engine type/ID, flow sequence, datagram
ordinal, and physical record ordinal. Five-tuples and paths are not identity
coordinates.

Sequence state is scoped by exporter plus engine type/ID. NetFlow v5 progression
uses the previous message's record count. A forward discontinuity reports
missing exported flow records and sets `loss_detected`; it does not claim network,
capture, or collector packet loss and never populates `missed_content_bytes`.
Duplicate and regression events are reported without a reorder holdback in F3;
bounded reorder handling remains a later sequence-hardening milestone. Restart is
reported only when sequence regression, uptime decrease, and changed boot-epoch
evidence agree.

Quality precedence is deterministic: invalid/reserved sampling is `unknown`,
recognized configured sampling (including one-in-one) is `sampled`, and explicit
mode-zero/interval-zero is `exact`. Sequence loss is an independent
`loss_detected` flag and does not replace fidelity. Counters are never scaled.
v5 `dOctets` maps only to `ip_bytes`; reverse counters and application metadata
are never fabricated.

F3 is Rust-only and offline. It adds no CLI, Python, live UDP, detector-v2,
NetFlow v9, IPFIX, or sFlow integration.

## NetFlow v5 F4 offline artifact qualification

`netflow::input` adds two offline Rust entry points without changing the F2 wire
or F3 normalization semantics:

- `process_raw_datagram_file` reads one complete v5 UDP payload, computes and
  binds SHA-256 from the actual bytes, checks an optional expected digest, and
  passes the unchanged bytes through F2 and F3. Raw input is bounded to the v5
  maximum of 1,464 bytes by default.
- `process_pcap_file` hashes the complete PCAP artifact, streams packet records,
  extracts configured UDP candidates, requires F2 structural validation, and
  normalizes accepted datagrams in capture order. A second digest over the bytes
  consumed during parsing fails closed if the artifact changed between hashing
  and processing.

The narrow PCAP reader supports classic PCAP 2.4 in either byte order, with
microsecond or nanosecond timestamp magic, Ethernet link type, optional one-level
802.1Q VLAN, IPv4, and complete unfragmented UDP datagrams. It does not claim
PCAPNG, Linux cooked capture, provider/nested VLAN, IPv6 transport, or fragment
reassembly. Unsupported or malformed packet framing is diagnosed with bounded
metadata; partial UDP payloads are never passed to F2.

PCAP candidates require an explicit UDP source-port and/or destination-port
filter. Optional exporter-source and collector-destination IPv4 filters may also
be configured. The port filter only narrows candidates: F2 version/count/length
validation determines whether a payload is structurally NetFlow v5. Exporter
identity remains explicit configuration and is never inferred from the transport
source.

For PCAP input, `input_sha256` is the complete PCAP SHA-256, `observed_at` is the
integer-converted packet capture timestamp, and `datagram_ordinal` is the ordinal
of each structurally valid matching v5 datagram. Physical packet order and v5
record order are preserved. Paths, filenames, mtimes, and wall clock do not
participate in output.

PCAP processing holds one captured packet at a time. Defaults bound captured
packets to 262,144 bytes, retained canonical observations to 100,000, and retained
diagnostics to 1,000 while reporting the total/dropped diagnostic counts. The
`write_*_canonical_jsonl` wrappers publish only after successful processing and
reuse the existing non-overwriting atomic canonical publisher.

The F4 real-input evidence is an exact hex encoding of one 792-byte v5 payload
produced by Apache-2.0 `nflow-generator` commit
`b7cd1199871c7ad9a74d8e0efae1768277019d0e`. It is explicitly exporter-simulator
test evidence, not physical-router or user traffic. Its provenance, privacy
review, independent decode summary, source SHA, and canonical SHA are frozen
under `tests/fixtures/export/netflow_v5/real/`.

F4 remains offline and Rust-only. Live UDP, NetFlow v9, IPFIX, sFlow,
detector-v2/Detection integration, and ML integration are not implemented.

## F5 shared bounded template registry (Rust API only)

`netflow::template` implements deterministic schema/state infrastructure shared
by future NetFlow v9 and IPFIX decoders. It parses **no packet bytes**, emits no
canonical records, and adds no Python/CLI/runtime integration. NetFlow v9 wire
parsing/data decoding, IPFIX wire parsing/data decoding, live export collection,
Detection/ML integration, and sFlow are **not implemented** by F5.

### Identity and exact layout

`TemplateKey` has four distinct coordinates: `TemplateProtocol` (`NetFlowV9` or
`Ipfix`), `TransportSessionKey`, `observation_scope_id: u32`, and
`template_id: u16`. The scope means v9 Source ID or IPFIX Observation Domain ID
at the future adapter boundary. Both protocols reserve template IDs below 256;
the registry accepts 256 through 65535, including options templates. This follows
[RFC 3954 section 5.2](https://www.rfc-editor.org/rfc/rfc3954#section-5.2) and
[RFC 7011 section 3.4](https://www.rfc-editor.org/rfc/rfc7011#section-3.4).

`TemplateTimelineKey` contains protocol, transport/session, and observation scope
only. `TemplateKey::timeline()` returns that structured key; template ID is
excluded so multiple templates in one timeline share a monotonic source clock.

`TransportSessionKey` separates `exporter_id` and caller-supplied `session_id`
without concatenation or content hashing. Both are nonempty, case-sensitive ASCII
labels with the existing exporter alphabet: letters, digits, `.`, `_`, `:`, `-`.
Each string is validated before allocating and revalidated against the registry's
own byte bound on every keyed operation. The caller must supply a complete,
deterministic namespace covering the exporter, sensor/collector context,
transport endpoints and connection/restart epoch as appropriate. A path, wall
clock, source IP alone, or template contents are not a complete session key.
F5 does not infer or authenticate identity; epoch derivation belongs to callers
and input architecture, not the F6/F8 wire parsers.

`TemplateDefinition` stores `TemplateKind::{Data, Options}`, an explicit
`scope_field_count: u16`, and an exact-sized ordered boxed field slice. Data
templates require scope count zero; Options allow 0 through total field count.
The first N fields are scope fields; v9 adapters must later translate their scope
definition byte length into a count. Field order and duplicate identifiers are
preserved. Scope count is part of definition equality/replacement, not key
identity. Data and Options share one key namespace and never coexist at one key.

F5 definitions are **protocol-neutral structural storage**, not proof of wire
legality. Every active definition remains nonempty. Nonempty zero-scope Options
definitions retain `TemplateKind::Options`; all-fields-as-scope layouts remain
representable, and scope counts above the field count remain invalid. F6 must
validate NetFlow v9 layouts before F5 insertion and may supply zero-scope Options
definitions. Future F8 must enforce IPFIX-specific Options Template scope rules
before construction/insertion, including its nonzero-scope requirement. Neither
wire parser is implemented by this registry amendment; storage acceptance under
an `Ipfix` key does not establish IPFIX wire legality.

`TemplateFieldSpecifier` preserves `field_id: u16`, `encoded_length: u16`, and
`enterprise_number: Option<u32>`. IPFIX adapters later remove the enterprise flag
from the logical IE ID and populate the PEN; v9 adapters preserve their field
type without a PEN. No IE lookup, sorting, deduplication, length normalization,
canonical interpretation, or variable-length decoding happens here. In particular
65535 and optional PEN values are preserved per
[RFC 7011 section 3.2](https://www.rfc-editor.org/rfc/rfc7011#section-3.2).
Protocol-specific validation remains the decoder's job, including legality of
zero-length/unknown fields and enterprise flags. Empty active definitions are
rejected; wire withdrawal records must call the explicit withdrawal API later.

### Human-approved configurable deployment policy defaults

`TemplateRegistryConfig::default()` returns the final human-approved F5 policy:

| Policy | Named constant | Default |
|---|---|---|
| TTL | `DEFAULT_TEMPLATE_TTL_SECONDS` | 1800 seconds |
| Registry entries | `DEFAULT_MAX_TEMPLATE_ENTRIES` | 4096 |
| Fields per template | `DEFAULT_MAX_FIELDS_PER_TEMPLATE` | 256 |
| Bytes per exporter/session identity component | `DEFAULT_MAX_TEMPLATE_IDENTITY_BYTES` | 256 |

These are configurable deployment safety defaults, **not protocol limits**.
`DEFAULT_TEMPLATE_TTL_NS` is the same TTL in integer nanoseconds. Explicit
`TemplateRegistryConfig::new(max_entries, max_fields_per_template,
max_identity_bytes)` overrides the resource bounds and `with_ttl_ns` overrides
TTL. All four values must be positive. Field count remains at most 65535 (the
common u16 count space); the approved 256-field policy is overrideable within
that representation. Template IDs, scope IDs, field IDs, encoded lengths, and
optional enterprise numbers retain their original u16/u32 representations.

Checked budget arithmetic rejects unrepresentable configurations, including
duplicated bounded identity storage for timeline keys. Maps grow incrementally,
never preallocated from configuration. Definitions validate borrowed field
counts before copying; exact-sized boxed slices/strings prevent retention of
oversized caller buffer capacities. Registry insertion revalidates definitions
constructed using a different, larger limit.

Retained state is bounded by max entries times bounded fields, bounded template
and timeline identity strings, and bounded BTreeMap/allocator overhead. The
ordered timeline-watermark map has exactly one entry per represented retained
template timeline, therefore at most the number of retained templates and at
most max_entries. There are no empty-timeline watermark tombstones, auxiliary
per-key generation histories, expired-key tombstones, unknown-data buffers, or
retained diagnostic lists.
Caller-owned inputs, caller-retained clones, allocator failure/OOM, and future
decoder allocations are outside the registry's ownership/resource guarantee;
decoders must enforce bounds before building their own field buffers.

### Source-time lifecycle and atomic failures

All timed APIs take caller-supplied `u64` integer source/event nanoseconds, with
independent clocks per protocol/session/observation-scope timeline. F5 performs
no conversion through floats and reads no wall clock, file metadata, IO, RNG,
threads, or timers. The unit matches existing v5 integer-nanosecond processing;
a future adapter chooses the source event time.

- A new active key starts generation 1 with first/last seen equal to source time.
- An identical active definition refresh keeps generation and first seen, updates
  last seen, and extends expiry to checked `source_time + TTL`.
- A changed active definition (including kind, scope count, lengths, PEN, order,
  or duplicates) replaces the definition and increments generation with checked
  arithmetic, preserving the active lifetime's first seen.
- `expires_at <= source_time` is expired, including the exact boundary.
- Generations reset to 1 after expiry or withdrawal: they identify versions only
  within an active lifetime. No unbounded generation tombstones are retained.
  Later decoded-record identity must also carry source/session and physical
  template/message coordinates; generation alone is not a durable identity.

Successful insert, lookup, withdrawal, or timeline expiry updates only the
relevant retained timeline's watermark. Equal times are valid; lower time within
that timeline returns `SourceTimeRegression` without changing any state. All
template IDs in that timeline share its watermark, but other protocols,
sessions/exporters, and observation domains advance independently. For example,
exporter A at time 5000 followed by exporter B at time 3000 is valid.

Unknown lookups/withdrawals advance the watermark only if that timeline already
retains templates. Operations on empty timelines return Unknown (or zero for
expiry) without storing auxiliary state. Removing a timeline's final retained
template via withdrawal, expired lookup, or explicit expiry removes its
watermark. Reinsertion into an empty timeline begins a new lifetime and may use
an earlier timestamp. Partial removal preserves the shared watermark while any
template remains, including expired-but-not-yet-pruned templates. This bounded,
lifetime-local monotonicity is the approved F5 policy; no persistent clock or
generation tombstones are retained.

`insert` returns `TemplateTransition` with Inserted/Refreshed/Replaced,
generation and expired-pruned count. It validates identity/layout, time, expiry
addition, generation and prospective retained capacity before mutating anything.
Expired entries in the insertion's own timeline are accounted for before
capacity rejection and physically pruned only on successful insertion. One
timeline's timestamp cannot prune unrelated clocks: those retained templates
still consume capacity until explicitly expired using their own timeline time.
Capacity failure never evicts live state; every error preserves both complete
maps and all watermarks, even expired neighbors.

`lookup(key, source_time)` returns Found (a borrowed immutable entry), Unknown,
or Expired with bounded metadata. Expired lookup removes that key; subsequent
lookup returns Unknown. Lookup does not refresh TTL or last seen. Expired vs
unknown can only be distinguished before pruning; no expiry history is stored.
`withdraw` similarly returns Withdrawn, Unknown, or Expired and removes only the
specified key. Future decoders—not F5—decide whether wire withdrawal is legal.
`expire_timeline(timeline, source_time)` removes only that timeline's expired
entries and returns a count. The old global `expire` API is removed; no shared
collector/capture time is assumed. No background processing is required.

Read-only entry getters expose definition, generation, first seen, last seen,
and expiry. `entries()` is a borrowed BTreeMap-ordered audit view of retained
entries, including any expired but not yet pruned entries; use timed lookup for
decoding, not timeless introspection. `len`, `is_empty`, configuration,
`timeline_count`, and `timeline_last_source_time_ns(timeline)` are available
without exposing mutable internals. There is no global time accessor. Errors
contain only static/numeric bounded context, not exporter strings or packet/field
dumps.

### F5 qualification

`template_registry_tests` covers the lifecycle, full isolation matrix, exact TTL
boundary, bounded capacity/identity/layout/watermarks, approved defaults and
overrides, error atomicity, deterministic multi-timeline replay, an independent
scalar state model, and adversarial/max-value inputs. An internal
unit test constructs generation overflow without exposing a production mutation
API. F2/F3/F4, full Rust, contracts, Python regression, Windows Pass A, detached
Pass B and a clean Linux-container pass must remain green before freeze.

```bash
cargo test --locked --manifest-path ingestion/Cargo.toml --test template_registry_tests
cargo test --locked --manifest-path ingestion/Cargo.toml --lib netflow::template::tests
```

### F6 bounded lossless NetFlow v9 parser (frozen and committed)

F6 is frozen at commit `beb56a6020c8cdc8207c4758f93780bc7d6d4227`.

The separate F5 prerequisite amendment closes protocol-neutral zero-scope
Options representation. F6 now implements the Rust-only bounded lossless v9
parser in `src/netflow/v9.rs`, its tests, and independent binary fixtures. No v9
input wrapper/CLI, canonical normalizer or detector hook is added. The following
F6 policies are human-approved; numeric limits are configurable deployment
defaults, not protocol constants:

| Parser policy | Approved value |
|---|---|
| Retained diagnostics per datagram | 128; zero retention allowed |
| Input datagram bytes | 65535 |
| FlowSets per datagram | 1024 |
| Template/Options Template records | 512 per FlowSet; 2048 per datagram |
| Decoded Data Records | 4096 per FlowSet; 16384 per datagram |

- Lifecycle time is header UNIX seconds converted with checked integer
  multiplication to nanoseconds, identical for every F5 operation in a datagram.
  No capture/processing/file/wall-clock substitution or regression clamping is
  allowed. SysUptime stays raw; explicit restart/session epochs belong to callers.
- Initial padding accepts only a distinguishable 0..3-byte all-zero terminal
  suffix, shorter than the decoded record length for data. A complete all-zero
  record is never stripped. Safely framed unaligned FlowSets may warn; nonzero or
  longer suffixes are outside this initial profile, not blanket RFC prohibitions.
- Complete outer framing/resource preflight precedes mutation. Later stateful
  errors retain successful earlier transitions and expose partial effects;
  ordinary `Result::Err` must not conceal mutations. Count mismatch flags rather
  than rolls back valid earlier transitions; no whole-registry clone is required.
- Diagnostic totals/dropped counts use checked arithmetic. Suppression never
  changes decoding, state, completion, reset requirements, or count status.
- Enforce byte and FlowSet bounds at the parser boundary/preflight; future
  wrappers should also bound artifact retention. Never inherit the v5 raw limit.
  Enforce F5's configured field bound before temporary descriptor allocation.
- An over-limit Data FlowSet loses its decoded output as a unit. A datagram-total
  data limit returns `StoppedAtLimit` after the processed prefix, with no later
  FlowSets processed and prior transitions visible.
- Preserve zero-width descriptors but reject their templates as
  `UnsupportedTemplateLayout` in the initial F6 profile. Do not install/decode
  them or claim that v9 universally forbids zero widths.
- Support v9 `scope_length == 0`, `option_length > 0` as Options with scope count
  zero. Both-zero descriptor portions remain unsupported empty definitions.
- A rejected newer template with trustworthy key/boundary triggers exact-key
  **local invalidation**, explicitly reported, leaving unrelated keys intact.
  Later data is Unknown until a supported template arrives; old-layout fallback
  is forbidden. Unsafe/failed invalidation or untrustworthy key/boundary stops
  stateful processing with `ResetRequired`; callers must quarantine/use a new
  epoch. This is not a v9 wire withdrawal; no unbounded taint map is added.
- Unknown-template data is skipped with bounded raw view/diagnostic: no guessing,
  buffering, cross-key fallback, or retroactive decode. Expired data similarly
  emits `ExpiredTemplate`, never resurrects state, and adds no expiry tombstones.
- Strict physical order applies to templates and data: A/data/B/data binds each
  data segment to its then-active definition. Data before its template stays
  skipped; no second pass is allowed.
- Preserve raw Count. It totals Template, Options Template, Data, and Options
  Data Records. Emit Match/Mismatch only when a reliable total is established;
  unresolved/malformed/limit-stopped content yields Inconclusive. Count is never
  an allocation bound, FlowSet count, or v5 fixed-size packet formula.

`parse_netflow_v9_wire(bytes, config)` performs pure checked header/complete outer
framing and template-record resource preflight, with privately constructed wire
views. `resolve_netflow_v9(wire, context, &mut registry)` revalidates the complete
caller-supplied session identity against F5's bound, prechecks the relevant
timeline and resolves physical wire order. `parse_netflow_v9` combines the two.
The context contains `TransportSessionKey` and an unchanged caller datagram
ordinal; it does not infer sensor, endpoints, transport or restart/session epoch.
Header Source ID is the separate F5 observation-scope coordinate.

Each decoded Data FlowSet owns one immutable bounded definition/generation/key
snapshot. Records and field values borrow the original bytes; no per-field owned
value buffers, registry references, unknown-data queue or second decoding pass
exist. `records()` binds fields to that exact snapshot. Ordered descriptors,
duplicate/unknown/high-bit IDs and literal widths are preserved without a PEN or
IPFIX enterprise-bit/variable-length interpretation. Options roles are Scope
then Option, including zero scopes and nonempty scope-only definitions.

Results expose Complete / CompleteWithDiagnostics / StoppedAtLimit /
StoppedForReset, Continue / ResetRequired, Match / Mismatch / Inconclusive,
per-record template transitions/local invalidation and per-FlowSet data states.
Physical later views remain explicitly Unprocessed after stopping. Every ordinary
Err is pre-mutation; its `session_disposition()` tells callers to quarantine a
rejected source session whose hidden layout change cannot be excluded. Caller
configuration/identity errors are not source resets. ResetRequired outcomes do
not automatically clear F5 or infer epochs: callers must quarantine/use a fresh
explicit epoch before further resolution. Successful earlier effects remain
visible, including a current Data FlowSet's timed lookup at a total-record stop.
Defensively rejecting an unsupported externally populated F5 layout reports its
exact-key local invalidation on the Data FlowSet, too.

A header-only export is rejected as MissingFlowSets in pure preflight. Empty or
padding-only Template/Options Template FlowSets stop for reset with explicit
prior effects. Known Data FlowSets containing no complete record are Rejected,
not represented as valid empty records or given Count Match. These minimum
structure checks follow RFC 3954's packet/FlowSet definitions; full-zero complete
records remain records, as required by the padding policy.

Padding is only the remainder after complete fixed-width records. Zero bytes of
length >= R are indistinguishable from legitimate complete zero records: they
are NOT stripped or guessed to be padding. Count may reveal a discrepancy, but
cannot identify exporter intent; a matching Count does not prove intent either.
This is the necessary clarification of test-matrix item 43, consistent with the
approved never-strip-complete-zero-record policy. Template/Options suffix errors
stop for reset with earlier applied transitions explicit, not silently rolled
back. Unsupported template records with proven extents can recover at their
exact boundaries after exact-key invalidation; unproven extents cannot.

Diagnostics retain at most the configured cap (including zero), with checked
total/dropped counters and typed numeric/static context only. They never include
arbitrary raw payload/identity strings. Raw payloads are available only in the
bounded current result's borrowed views. Field-limit checks precede temporary
descriptor allocation; configuration validates representational/owned budgets.

Implemented: header/FlowSets, ordinary/Options templates, v9 zero-scope Options,
fixed-width Data/Options Data structure, F5 lifecycle integration, bounded
diagnostics, physical ordering, generation binding and no-buffer unknown data.
F6 itself does not perform canonical normalization or IE value interpretation;
the separate F7 module below adds the approved initial flow semantics. Sampling
association/scaling, loss/reordering/restart classification, Detection/ML,
IPFIX parsing, sFlow and live collection remain unimplemented. Frozen F6, v5,
PCAP and legacy production paths are unchanged.

Qualification fixtures have `.bin`, `.sha256` and independent expected `.json`
sidecars in `tests/fixtures/export/netflow_v9/{valid,malformed,stateful,real}`.
`tests/netflow_v9_fixture_oracle.py` uses Python stdlib struct/manual operations,
not Rust/PyO3. Default mode is read-only; `--generate` explicitly builds synthetic
fixtures and refuses replacement of differing evidence. Capture mode is a
test-only bounded loopback collector, not a production collection feature.

Genuine exporter evidence: softflowd v1.1.1, upstream commit
`8f83c2c4a784a72bf6eb2604e73d4029b21b7925`, independently built from the pinned
archive (SHA-256 `111c4b2c841c7143552d77fc7bbe5ab7d7f4604bc1d7acf522afb0ce8e00fccb`).
Only the existing non-sensitive `m1d_synthetic.pcap` was replayed. The 688-byte
capture SHA-256 is `31cc964436b85c9f8a82e825956c3fa2ea13c47d35374050ac8f13bb769e2cb2`.
`real/softflowd_000.json` records the exact generation command, source URL, PCAP
hash, producer version, complete upstream license/notices and independent decode.
This exporter declares Count 8 but emits 14 records: four ordinary templates,
one Options Template, eight flow records and one Options Data record. F6
deliberately reports CountMismatch (8 vs 14), not a relaxed Count rule. Structural
record slicing agrees with the independent oracle. This is one synthetic-traffic
software-exporter capture, not hardware/vendor fleet or live-operation evidence.

```bash
cargo test --locked --manifest-path ingestion/Cargo.toml --test netflow_v9_parser_tests
python ingestion/tests/netflow_v9_fixture_oracle.py
```

---

## F7: bounded NetFlow v9 canonical flow normalization

F7 is implemented and qualified, pending final human freeze, commit and PR.
The NetFlow PR is not yet merged; IPFIX work has not started.

`netflow::v9_normalize::normalize_netflow_v9` accepts an already-created F6
`NetFlowV9ParseOutcome`, a validated `NetFlowV9SourceContext`, and validated
`NetFlowV9NormalizationConfig`. It emits only CanonicalObservation v1 `flow`
records with `telemetry_source="netflow_v9"`. The serialized schema is unchanged.
It never reparses wire framing or looks up mutable F5 templates: field values
are interpreted using each Decoded Data FlowSet's immutable F6 snapshot.

Initial supported IE profile: 1,2,4,6,7,8,10,11,12,14,21,22,27,28,32,60.
Both selected endpoints, PROTOCOL, FIRST_SWITCHED, LAST_SWITCHED, and at least
one usable forward counter are required. Ports/details/interfaces are optional.
IE60 explicitly selects IPv4/IPv6; absent IE60 accepts only unambiguous IPv4.
IPv6-only/both-family/mixed-family records without a defensible selector fail
closed. One physical eligible Data Record yields one flow, in wire order; no
five-tuple deduplication or reverse-flow joining occurs.

TCP/UDP ports are supported and zero remains zero. ICMPv4 IE32 uses high-byte
type/low-byte code; no ICMP port fallback. SCTP protocol values remain available
but ports are omitted. ICMPv6 details and vendor IE139 are not interpreted.
TCP flags use the eight reported bits (no invented NS); reported zero yields
`[]`. Interface widths 2..8 decode unsigned; zero is absent, nonzero `ifindex:N`.
Equivalent semantic duplicates map once with one bounded notice per record;
conflicting duplicates or malformed active supported fields reject the record.
Unknown/deferred fields are not serialized and do not cause diagnostic floods.

IE2 maps unchanged to `src_to_dst.packets`; widths 1..8 and u64::MAX are valid.
IE1 maps unchanged to `src_to_dst.ip_bytes` ONLY when the caller explicitly selects
`NetFlowV9ByteBasisProfile::VerifiedIpLayer`. `Unknown` defers IE1, including its
semantic width checks, and IE1 then cannot satisfy the required-counter rule.
Exporter names/templates never auto-select a byte basis. No payload/L2 fallback,
OUT-counter summation/fallback, sampling multiplication, or rounding occurs.
Every flow is unidirectional and `dst_to_src` is absent. DIRECTION does not swap
endpoints. TOS/masks/AS/next-hop/MAC/VLAN/MPLS/export totals and vendor IE136 remain
opaque F6 evidence; no service, connection state/history, or end reason is guessed.

Timestamp reconstruction uses checked integer arithmetic: export seconds minus
bounded modular end age gives end_time; subtracting bounded duration gives
start_time. Default maximum end age AND duration is 86,400,000 ms separately;
their sum may reach 48 hours. Configured maximum is 0..=2^31-1 ms. Gross inversion,
half-cycle ambiguity, full-cycle ambiguity, underflow and future LAST=U+1 fail
closed. Small defensible uptime rollover is allowed. Neither missing timing IE
is replaced with export/capture/receipt time. There is no serialized flow
event_time or duration. The whole-second export anchor does not establish
millisecond wall-clock accuracy or uniquely recover historical multiple wraps.

Quality is always unknown, truncated=false, loss_detected=false. Sampling rate,
probability and missed_content_bytes are absent. These booleans do not promise
unsampled/lossless original traffic. Options Data emits zero flows and creates
ZERO persistent F7 sampler/Options entries. Association, scaling, sequence/loss/
reordering/restart confidence and cross-source quality policy remain F10.

The must-use batch result preserves CountValidation (including declared/parsed
mismatch), ParseCompletion, SessionDisposition, decoded count, retained parser
diagnostics and total/dropped counts. Individually eligible Decoded records may
survive mismatch/inconclusive or a trustworthy prefix before limit/reset. Never
recover SkippedUnknown/SkippedExpired/Rejected/Unprocessed suffix bytes.
ResetRequired stays ResetRequired: callers MUST quarantine/reset the session
epoch before subsequent use. F7 does not implement that session manager.

Limits default to 16,384 inspected records, 16,384 observations, 128 retained
normalization diagnostics, and 16,384 audit entries. Non-diagnostic caps must be
positive; diagnostic retention may be zero. Record/observation/audit exhaustion
stops before the next record with explicit F7 StoppedAtLimit; exact-cap completion
is not a stop. Counters use checked arithmetic and vectors grow incrementally.
Only one primary rejection and at most two aggregated notices occur per record.
Audit entries hold bounded numeric coordinates, template ID/generation and
action; parser state never enters serialized provenance. Metadata binding checks
do not constitute telemetry authentication. Diagnostics contain no payload,
pathname or raw identity dumps.

Source context supports export_file/pcap_file only. Sensor ID is nonempty and
<=256 UTF-8 bytes; observed_at is caller-supplied valid UTC Z and <=64 bytes;
optional capture interface is nonempty and <=256 bytes. F6 exporter/session
identities must fit the supported 256-byte profile. SHA-256 is validated and
lowercased. Callers must bind it to actual input content: a single raw artifact
or original whole PCAP with stable datagram coordinates. F7 reads no clock and
accepts no filesystem path. Receipt time is not flow time. Golden replay pins
observed_at explicitly. Live collection/persistence is not implemented.

Frozen UUIDv5 marker: `co-netflow-v9-id-v1`. Namespace
`5a4b3750-4220-5f0e-b506-8f6080b3828c` is UUIDv5(URL namespace, UTF-8
`https://utsavagg2007.github.io/SIH-2026/contracts/co-netflow-v9-id-v1`). Name
components are marker, sensor, lowercase input SHA, exporter, session, Source ID,
raw sequence, datagram ordinal, FlowSet ordinal, record ordinal, each prefixed by
u32 big-endian UTF-8 byte length. Numbers are unsigned decimal without padding.
Template ID/generation, tuple, path, observed_at and input mode are excluded.
The 175-byte frozen vector produces `3a5978ca-df78-52f8-97f8-9e47e3af8dde`.
Source correlation is `netflow_v9/exporter/session_fingerprint/domain/sequence/
datagram/flowset/record`, <=512 bytes. Fingerprint is SHA-256 of length-prefixed
`co-netflow-v9-session-v1`, exporter and session. Raw session is not exposed.
UUID is an opaque replay identifier, not an authenticity/security proof.

Separate F7 evidence lives in `tests/fixtures/export/netflow_v9_canonical`:
reviewable ASCII `.hex` wire storage (SHA identifies decoded datagram bytes),
exact compact UTF-8 LF JSONL goldens plus SHA sidecars, and explicit independent
metadata/context/status expectations. Empty negative output is a zero-byte file.
F7-only `.gitattributes` rules preserve LF bytes for wire storage, metadata,
goldens and SHA sidecars across Windows checkout; frozen-source rules are unchanged.
The stdlib oracle independently calculates mappings, time, identities,
correlation fingerprints and exact bytes; default mode never writes. Its explicit
`--emit-patch` mode only prints an apply_patch document. Goldens are checked
against Rust output AND the unchanged Draft 2020-12 schema/semantic harness.
Typed production construction is fail-closed, not a generic JSON Schema engine.

Frozen `softflowd_000.bin` remains NEGATIVE F7 timing evidence: zero emitted,
eight ordinary timing rejections, one ignored Options record, CountMismatch
8 versus 14 preserved. Original input packets are from November 2023 while the
export header anchors October 2026. Do not widen policy or rewrite that artifact
to claim positive chronology. Independent packet inspection establishes IE1's
IP-layer basis for this pinned software producer/sample only, not all exporters.
Fresh positive real-exporter evidence and Linux qualification require an
available external runtime; synthetic evidence is not hardware/vendor fleet proof.

Not implemented in F7: Detection/ML adapters, dataset/CLI/PyO3 v9 orchestration,
IPFIX, sFlow, live collector/session management, sampler association, counter
scaling, loss analysis, reverse reconstruction, SCTP ports, ICMPv6 type/code.

```bash
cargo test --locked --manifest-path ingestion/Cargo.toml --test netflow_v9_normalization_tests
python ingestion/tests/netflow_v9_normalization_oracle.py
pwsh -NoProfile -File ingestion/tests/test_netflow_v9_canonical_goldens.ps1
```

## Tests

```bash
cargo test --locked --manifest-path ingestion/Cargo.toml
# Run Python ingestion tests from ingestion/ so local pipeline imports are explicit.
cd ingestion
../.venv/bin/python -m pytest pytests -q
../.venv/bin/python -m pytest tests/test_pipeline_m1d.py tests/test_pipeline_cli_m1d.py tests/test_pipeline_detector_profile.py tests/test_pipeline_dataset_determinism.py -q
cd ..
.venv/bin/python -m pytest pcap_dataset/test_ingest.py -q
./.venv/bin/python pcap_dataset/replay_integrity_docker_e2e.py
.venv/bin/python ingestion/tests/test_ja4_docker_e2e.py
.venv/bin/python ingestion/tests/test_tls_fingerprint_docker_e2e.py
pwsh -NoProfile -File ingestion/tests/test_m1d_docker_e2e.ps1
pwsh -NoProfile -File contracts/tests/test_contract.ps1
```
