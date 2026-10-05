# NetFlow v5/v9 offline Detection integration

NetFlow v5/v9 is wired end-to-end into compatible Detection consumers:
bounded raw export input -> unchanged Rust F2/F3/F4 or F5/F6/F7 -> frozen
CanonicalObservation v1 JSONL -> strict Python canonical-flow adapter -> the
existing production factory, DetectionEngine and ThreatAlert v1.1 sink.
This is an additional offline path, not a replacement for `features.jsonl`.

## Setup and commands

From the repository root, use the project's Python 3.11+ environment with
Detection installed (`pip install -e './detection[dev,ml]'` for all test extras).
The runtime only needs the existing Pydantic dependency. Build the real Rust
executable (not the PyO3 extension) once:

```sh
cargo build --locked --manifest-path ingestion/Cargo.toml --bin netflow_export
```

From `detection/`, these cross-platform commands use qualified frozen inputs.
The output parent must exist and each run directory must be NEW. The command
invokes Rust and production Detection; no separately generated Python dicts
or legacy feature file stand in for the canonical output.

```sh
python -m detection_core.netflow_run --source netflow-v5 --input ../ingestion/tests/fixtures/export/netflow_v5/repeated_5tuple_distinct_rows.bin --output-dir ../run-v5 --sensor-id sensor-netflow-golden --exporter-id exporter-golden --observed-at 2026-09-18T00:00:00Z
python -m detection_core.netflow_run --source netflow-v9 --input ../ingestion/tests/fixtures/export/netflow_v9_canonical/wire/tcp_min.hex --wire-format hex --output-dir ../run-v9 --sensor-id sensor-v9-a --exporter-id exporter-a --session-id collector-a.udp.epoch-1 --observed-at 2026-10-03T00:00:00Z
```

Expected: v5 3 canonical events / 3 DDoS invocations; v9 1 / 1; benign inputs
emit zero alerts. Use a real one-datagram `.bin` export with `--wire-format raw`
(the default). v9 needs templates in that same datagram: this is not a live
collector, persistent session manager, or arbitrary concatenated export reader.
Use `--rust-binary` for an explicitly trusted separately built local executable,
for example a release build or a Linux target in disposable build storage.
Use `--detector-config` for the existing Detection TOML threshold configuration;
no scaler, learned weights or new attack rule is fitted from input data.

`--byte-basis unknown` is the v9 default. `--byte-basis ip` is an explicit
deployment assertion that the exporter counter is verified IP-layer bytes;
it must not be selected merely to unlock a detector. It never supplies payload
bytes. v5 uses its frozen F3 semantics and does not accept this override.

## Artifacts and status

Each run produces:

- `canonical_observations.jsonl`: existing Rust serializer/publisher, one compact
  UTF-8 JSON object per line, no BOM, LF after every record; zero output is empty.
- `ingestion_status.json`: source; artifact and decoded wire SHA-256; record
  accounting; bounded parser/normalizer diagnostics and dropped totals; v9
  CountValidation, ParseCompletion, SessionDisposition, ResetRequired/action;
  ignored Options count and bounded physical record audit coordinates.
- `ingestion_complete.json`: Rust ingestion completion marker.
- `detection_events.jsonl`: streamed actual internal event values plus invocation
  or explicit skip reason for each registered consumer. Canonical/source IDs,
  quality and provenance are retained even when no alert is emitted.
- `alerts.jsonl`: the production sink's normal ThreatAlert v1.1 serialization.
- `detection_status.json`: normal run counts plus bounded per-consumer invocation
  and skip-reason counts; an actual zero-alert result is not a detector stub.
- `run_complete.json`: E2E completion marker published LAST, with output hashes,
  observation/alert counts, review-required and reset flags.

Exit 0 means a complete run without ingestion warnings and with an invoked
consumer. Exit 2 means a complete but review-required run (warnings, reset,
rejected/empty input, or no compatible event). Exit 1 means failure, not a
successful empty run. Count mismatch can coexist with valid emitted flows.
For a partial/reset prefix, read status before using the results; never reuse
that exporter/session epoch. Each offline invocation discards its own registry.

Rust canonical output reuses the existing atomic no-overwrite publisher.
Python works in a private sibling staging directory and publishes whole files
with exclusive hard links. Existing output paths are refused. This is a
commit-marker bundle, NOT an atomic directory rename: an I/O failure during
final publication can leave an incomplete directory without `run_complete.json`.
Consumers MUST require that marker. No user-owned output is overwritten or
automatically removed. Hard-link support on the output filesystem is required.

For raw input, artifact and wire hashes coincide. For an ASCII hex fixture,
artifact SHA hashes the original text; canonical `input_sha256` hashes the
decoded NetFlow input, matching frozen F7 identity vectors. Both hashes are
recorded. Changes in explicit sensor/exporter/session identity change canonical
identity as defined by frozen F3/F7; do not reconstruct an ID from the tuple.

## Exact event mappings / missing data

Legacy event time comes from `timestamp`/`ts`, or the trailing Zeek connection
start timestamp in `flow_id` (ingestion flow.rs). Canonical Detection therefore
uses `data.start_time`, NOT receipt `observed_at`, end time, or wall clock.
Calendar validation and Decimal subtraction precede the detector's existing
float epoch boundary. `duration = end_time - start_time` only when end exists;
otherwise None. A measured zero duration stays zero. Raw RFC3339 strings are
retained; sub-float-resolution timestamps may collapse in existing float
windows, which then report an unmeasurable rate as None rather than epsilon.

`flow_id = record_id`. Canonical src/dst map directly, without assigning TCP
initiator/responder roles. `orig_pkts = src_to_dst.packets`; reverse is only
`dst_to_src.packets` if explicitly present. `orig_bytes`/`resp_bytes` mean
PAYLOAD bytes in the existing Zeek-trained/rule path, so only the corresponding
canonical `payload_bytes` can fill them. `ip_bytes` goes to the separate
`orig_ip_bytes`/`resp_ip_bytes`; L2 counters remain metadata. Missing and null
counters stay None, measured zero stays zero, u64 integers stay exact. A total
whose direction/measurement is unavailable stays None, not a known subtotal.

The `CanonicalFlowEvent` subtype is missing-aware; the legacy `FlowEvent`
required numeric validation is unchanged. Shared windows track missing counts
and return None for incomplete totals, maxima and responder-byte fractions.
Gate decisions precede consumer invocation; exceptions are not feature probes.
DNS/TLS/HTTP, service, connection state and ports are not invented. Known IP
protocols map to existing labels; an unknown protocol stays `ip_protocol_N`.
Quality/provenance propagate unchanged; unknown fidelity is not exact, no
unsampled assumption is made, and no sampling extrapolation or loss model runs.
The existing numeric-only backend throughput reporter rejects this subtype
rather than publishing absent payload/reverse measurements as zero.

## Production consumer compatibility

| Consumer | Decision requirements | Current NetFlow result |
| --- | --- | --- |
| DDoS | event start, source/destination, forward packets; destination fan-in and observation count | Compatible with existing derived window statistics when packets exist. Bytes are evidence only and may be null. |
| Port scan | source/destination/port/time fanout PLUS classified responder state or observed responder payload-byte refusal proxy | Incompatible; neither unavailable reverse bytes nor missing state proves refusal. |
| C2 beaconing | tuple/time intervals, periodicity/persistence PLUS mean forward payload-byte check-in size | Incompatible; IP bytes cannot replace the established payload-byte basis. |
| Data exfiltration | forward payload-byte sums/peak/share/persistence; packet/reverse context | Incompatible; NetFlow IP bytes cannot replace payload-volume thresholds. |
| DNS tunnelling | actual DNS observations (query length/entropy, labels, type/rcode) and windows | Incompatible; exported flows carry no DNS transaction content. |
| Encrypted malware | observed TLS fingerprints and/or raw SNI with heuristic window features/configured feeds | Incompatible; no JA3/JA3S/JA4/SNI or TLS fields are fabricated. |
| DGA (opt-in) | actual DNS query + separately trained trusted model and its existing preprocessing | Incompatible regardless of model availability; the offline command does not load an unnecessary model. |

All five incompatible default consumers are counted as skips. DGA is explicitly
reported as not loaded/unsupported telemetry; if registered programmatically it
is gated too. Unknown/custom canonical consumers fail closed, including a
custom class borrowing a production detector's name. The policy is conservative
for current F3/F7 producers, not a claim of future canonical-source support.

DDoS uses its existing destination-keyed 10-second event-time window. Breadth is
unique sources; intensity is observation count OR forward packet sum. Rule
score averages threshold ratios, using the existing saturating score function;
no new learned features or preprocessing. Rates are count/window-span only
when span > 0. Payload byte evidence is null when unmeasured. Aggregate alerts
retain `evidence.canonical_trigger` (record/source/sensor/source-record/quality/
provenance); this is the TRIGGER, not the identity or provenance of every flow
in that aggregate. Full streamed inputs supply the rest of the correlation.

Operational limitations: exported flow fragments/repeated exports count as
observations, not proven independent TCP connections. There is no cross-file
deduplication or reverse-flow stitching. Input physical order is preserved;
the existing windows assume roughly increasing event time and are NOT given a
new reordering policy. Shipped DDoS thresholds are demo heuristics, not a
validated NetFlow attack classifier. Do not claim all ML models support NetFlow.

## Qualification

After building the Rust executable, from repository root:

```sh
cargo test --locked --manifest-path ingestion/Cargo.toml
cargo fmt --check --manifest-path ingestion/Cargo.toml
cargo clippy --locked --manifest-path ingestion/Cargo.toml --all-targets --all-features -- -D warnings
python -m pytest -p no:cacheprovider ingestion/pytests/test_netflow_detection_e2e.py -q
```

Run the existing ingestion Python regression against a freshly built isolated
extension as documented by that pipeline. From `detection/`, run its full
`python -m pytest -p no:cacheprovider -q`; all old tests are unchanged. The new
unit tests cover all frozen F3/F7 flow goldens, malformed envelopes/flow fields,
exact u64, missing versus zero, timestamp and duration, byte basis, compatibility
and null-safe expiry. E2E tests consume real Rust-generated files, match exact
goldens, test replay, partial/reset status, malformed input, write/detection
failure, and a clearly labelled synthetic wire flood using the real default
DDoS detector. No positive attack is fabricated for the benign manual demos.

Validate emitted run files with the unchanged full contract harness on
PowerShell 7.5+ (PowerShell array syntax shown):

```powershell
& ./ingestion/tests/test_netflow_e2e_jsonl_contract.ps1 -RunDirectories @('./run-v5', './run-v9')
```

On Linux, build with read-only source and writable disposable target/cache,
then set `NETFLOW_EXPORT_BINARY` to that real executable for Python E2E tests.
Full Rust tests require PowerShell 7 in PATH and Python development libraries
for PyO3. No project dependency or schema file is changed by this milestone.

### Pinned softflowd positive evidence (opt-in)

Independently build irino/softflowd v1.1.1 commit
`8f83c2c4a784a72bf6eb2604e73d4029b21b7925`; archive SHA-256
`111c4b2c841c7143552d77fc7bbe5ab7d7f4604bc1d7acf522afb0ce8e00fccb`.
Use the upstream source archive with libpcap development libraries, autoreconf,
configure, and make, in a disposable Linux container (no new project dependency).
As an unprivileged user:

```sh
python ingestion/tests/netflow_softflowd_e2e_qualification.py --softflowd /tmp/producer/softflowd --producer-source /tmp/producer --rust-binary /tmp/target/debug/netflow_export --evidence-dir /tmp/new-softflowd-e2e-evidence
```

This tool keeps every packet byte of the synthetic PCAP and documents an
independent near-boot capture-time adjustment ONLY in a new temporary PCAP.
It never edits exported NetFlow fields, parser semantics, or frozen negative
evidence. Actual loopback UDP datagrams go through the complete new command,
then are replayed unchanged with fixed context. It records producer/input/output
hashes, real consumer invocations, warnings, Options accounting and results.
Artifact hashes vary when regenerating producer exports; replay of each fixed
captured artifact is deterministic. Positive-alert IDs (UUID4) and detected_at
remain intentionally nondeterministic in the unchanged ThreatAlert contract;
compare rule scores/event times/evidence separately, not those issuance fields.

Linux qualification of the unchanged ingestion tests has one known platform
harness limitation: `test_windows_git_bash_initializes_bundled_posix_tools`
patches the global OS name to Windows and then instantiates `WindowsPath`,
which raises on Linux. It passes on Windows. Do not conceal this as a full
Linux-suite pass: report the original failure and, separately, the relevant
Linux rerun with that exact Windows-only test deselected. Its source and the
legacy pipeline remain unchanged. A disposable environment without the
optional pytest-asyncio plugin also reports the repository's pre-existing
unused asyncio config option; this is a test-environment warning, not a new
runtime dependency or production telemetry error.

Still outside scope: IPFIX, sFlow, F10 sampling/loss inference, live export
collection/session management, byte-basis/training redesign for unsupported
models, backend/frontend changes, commits/pushes/PRs.
