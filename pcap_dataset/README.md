# pcap_dataset - reproducible replay workspace

This repository-root directory turns PCAPs into integrity-bound feature
artifacts for model training and detector qualification. Raw captures and
generated replay directories remain ignored; the ingestion code, registry, and
qualification tests are versioned.

## Setup and use

```bash
python3 -m venv .venv
.venv/bin/pip install "maturin>=1.0,<2.0>"
.venv/bin/maturin develop --manifest-path ingestion/Cargo.toml

.venv/bin/python ingestion/scripts/generate_synthetic_pcap.py \
  --output pcap_dataset/raw/synthetic.pcap

# detector-v2 is the dataset default.
.venv/bin/python pcap_dataset/ingest.py \
  --pcap pcap_dataset/raw/synthetic.pcap --label benign

# Frozen legacy projection, still using deterministic dataset-only Zeek.
.venv/bin/python pcap_dataset/ingest.py \
  --pcap pcap_dataset/raw/synthetic.pcap --label benign \
  --feature-profile legacy-m1d

# Qualified JA4 runtime; no fallback is permitted.
.venv/bin/python pcap_dataset/ingest.py \
  --pcap pcap_dataset/raw/ja4.pcap --label encrypted_malware --ja4

# Qualified source JA3 + JA3S + JA4 runtime; mutually exclusive with --ja4.
.venv/bin/python pcap_dataset/ingest.py \
  --pcap pcap_dataset/raw/tls.pcap --label encrypted_malware \
  --tls-fingerprints
```

Docker-backed Zeek must be available. On Linux, see "Docker without sudo" in
`ingestion/README.md`.

## Identity and configuration contract

The stable directory/replay identity remains:

```text
replay_id = UUIDv5(DATASET_NS, "<pcap-sha256>:<label>")
```

Because this identifier intentionally does not contain configuration, reuse is
permitted only after the complete stored production configuration is verified.
The normalized configuration binds:

* configuration format version;
* `feature_profile`;
* `runtime_mode` and explicit `tls_fingerprint_mode`;
* detector-facing `feature_profile_revision`;
* immutable Zeek image digest;
* selected fingerprint runtime-lock SHA-256 and qualified image-config digest;
* deterministic Zeek mode;
* `window_secs`;
* dataset sensor identity.

Canonical JSON (sorted keys, compact separators, UTF-8, no timestamps or local
paths) is SHA-256 hashed into `config_sha256`.

Standard dataset runs explicitly request deterministic Zeek and execute the
pinned standard runtime with `-D -C -r`. This is dataset-specific: the global
`ingestion/pipeline.py` default and the frozen legacy-m1d transformation remain
unchanged.

## Integrity metadata

The central `metadata.json` entry records the replay/SHA/label binding,
portable `features_path`, human-readable configuration fields, the complete
normalized `config`, `config_sha256`, immutable runtime image, and
`features_sha256`.

Each ignored `output/<replay_id>/meta.json` independently records the same
identity, configuration, configuration fingerprint, artifact names, and
feature digest. Before reuse, ingestion verifies:

1. requested PCAP SHA and label produce the expected replay ID;
2. central and per-replay identity fields agree;
3. both configurations parse and have valid fingerprints;
4. stored configuration exactly equals the requested configuration;
5. central and per-replay runtime identities agree;
6. `features.jsonl` is a regular file at the expected path;
7. its recomputed SHA-256 equals both recorded digests.

File existence alone is never sufficient for success.

Serialized paths use `/` and remain dataset/repository-relative. External PCAP
locations are recorded descriptively as `external/<filename>`; PCAP SHA-256,
not a workstation path, is authoritative.

## Migration and recovery policy

Missing configuration is never guessed. In particular, an old central entry
is not assumed to be legacy-m1d/non-JA4.

| State | Behavior |
|---|---|
| Central missing/incomplete; complete modern per-replay metadata and artifact valid | Recover central metadata, then reuse only if requested configuration matches |
| Central incomplete; old/insufficient per-replay metadata | Fail closed; use `--force` to rebuild explicitly |
| Central entry present; both local artifact files absent | Rebuild under the requested configuration |
| Only one of `features.jsonl` or `meta.json` exists | Fail closed |
| Per-replay metadata missing, malformed, or contradictory | Fail closed |
| Feature/runtime/configuration digest mismatch | Fail closed |
| Complete artifact exists without central entry | Recover central only after full validation |
| Malformed/partial central registry | Fail closed |
| Orphan staging/backup state from an interrupted publication | Fail closed with a recovery diagnostic |

`--force` generates and validates a replacement in a private staging directory.
The existing replay is moved aside only when the candidate is complete. If
artifact publication or central-registry publication fails, the previous
artifact is restored and the previous central registry remains authoritative.
JSON files are written through flushed temporary files and atomic replacement.

## Same-PCAP label warnings

When identical PCAP bytes are registered with different labels, ingestion warns
about the contradictory training signal. The message distinguishes creation,
rebuild, and reuse; it does not claim that features are identical across
different configurations.

## Telemetry profiles

Allowed labels are `port_scan`, `ddos`, `dns_tunnelling`,
`encrypted_malware`, `data_exfiltration`, `c2_beaconing`, `dga_domain`, and
`benign`.

`detector-v2` retains raw detector telemetry including DNS query/qtype/rcode,
TLS server name/version/cipher, HTTP host/URI/method/user-agent/status,
`src_port`, `service`, `conn_state`, timestamps, and UIDs.

The standard runtime emits no TLS fingerprints. Explicit `--ja4` selects the
locked JA4-only runtime. Explicit `--tls-fingerprints` selects the independently
locked runtime that emits source JA3, JA3S, and JA4. The modes are mutually
exclusive; unavailable source values remain `null` and are never fabricated.

`detector-v2` keeps the earliest event-time DNS/TLS/HTTP row as its compatibility
scalar and preserves every source row in `dns_transactions`, `tls_transactions`,
or `http_transactions` in physical source order. The scalar
`transaction_count` must equal the corresponding array length.

## Qualification

Fast integrity/corruption/force tests:

```bash
python -m pytest pcap_dataset/test_ingest.py -q
```

Real Docker replay, ten-run standard/JA4/full-fingerprint determinism,
renamed-path determinism, metadata binding, and Detection adapter seam:

```bash
python pcap_dataset/replay_integrity_docker_e2e.py
```

The synthetic fixtures are demonstrations and qualification inputs, not a basis
for quoting production detection rates.
