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
