# pcap_dataset — replay workspace (outside core source)

Raw PCAPs and derived features for model training. This directory is **at the repo root** so it is not part of `ingestion/` source.

## What is versioned

* `ingest.py` — automation script (tracked)
* `metadata.json` — central registry of `replay_id → {pcap, sha256, label, timestamp}`
* `raw/.gitkeep` + `output/.gitkeep` — keep dirs tracked when empty
* This `README.md` + root `.gitignore` entry

## What is ignored (recreated per machine)

* `raw/*.pcap`, `raw/*.pcapng`, `raw/*.sha256` — large captures (your `iperf3/Ostinato/TRex`, `hping3/Slowloris/dnscat2/DGA` sources)
* `output/<replay_id>/` — `features.jsonl` + `meta.json` (reproducible from `raw/` + `ingest.py`)
* `pcap_dataset/.tmp*/` — ephemeral Zeek logs

## How teammates use after `git pull`

They get `ingest.py` + `metadata.json` but no binaries:

```bash
# 1. one-time setup (same single venv as ingestion)
python3 -m venv .venv
.venv/bin/pip install "maturin>=1.0,<2.0>"
.venv/bin/maturin develop --manifest-path ingestion/Cargo.toml

# Docker note: ingestion shells out to `docker` for Zeek. For passwordless
# local runs see "Docker without sudo" in `ingestion/README.md` (add yourself
# to the `docker` group once, then re-login or `newgrp docker`).

# 2. populate raw/ — either generate synthetic or fetch your captures out-of-git
.venv/bin/python ingestion/scripts/generate_synthetic_pcap.py --output pcap_dataset/raw/synthetic.pcap
# or: scp user@share:/pcaps/*.pcap pcap_dataset/raw/

# 3. ingest — deterministic replay_id = uuid5(NS, f"{sha256}:{label}")
.venv/bin/python pcap_dataset/ingest.py --pcap pcap_dataset/raw/synthetic.pcap --label ddos
# re-running same pcap+label is idempotent (same output/<id>/, same metadata entry)

# 4. verify central registry + per-replay binding
cat pcap_dataset/metadata.json
cat pcap_dataset/output/<replay_id>/meta.json
```

If `raw/*.pcap` is missing but `metadata.json` lists a `replay_id`, `ingest.py` will re-create it deterministically when the same `pcap` (same bytes) + `label` is supplied — the `replay_id` and `output/<id>/` path will match the original author's.

The registry is validated before use: its root must be an object, each key must
be the UUIDv5 derived from the recorded SHA-256 and label, paths must remain
inside the declared raw/output roots, labels must be from the enforced set, and
per-replay metadata must match the central binding. Invalid metadata fails
closed before ingestion writes an output.

## Threat classes (enforced)

`port_scan, ddos, dns_tunnelling, encrypted_malware, data_exfiltration, c2_beaconing, dga_domain` plus `benign` negatives. Dataset defaults to `--feature-profile detector-v2` so raw fields survive: `dns.query`/`qtype`/`rcode`, `tls.server_name`, `http.host`/`uri`/`user_agent`, top-level `uid`/`timestamp`/`src_port`/`service`/`conn_state`. Add `--feature-profile legacy-m1d` only for frozen M1D byte-for-byte comparison. `tls.ja3`/`ja3s`/`ja4` are transported when the runtime emits them, but neither qualified runtime emits JA3/JA3S today (base `8.0.10` installs no fingerprint packages; the JA4 image adds only `ssl.log.ja4`), so real output carries them as `null` — fixtures and tests inject them synthetically. Add `--ja4` when the PCAP contains TLS handshakes and the qualified `sih-zeek-ja4` image is built; otherwise `tls.ja4` stays absent rather than faked. The encrypted-malware signature path needs an emitting runtime plus a local feed before it fires on real captures.

## Fixtures: why the three demo replays share bytes

`raw/verify_{benign,ddos,dga}.pcap` are byte-identical copies of the deterministic 2,799-byte synthetic fixture. They produce identical `features.jsonl` — only `replay_id` (uuid5 of SHA+label) and `meta.json:label` differ. The `[warn] same PCAP bytes already registered as ...` line from `ingest.py` flags this label noise. For real training, populate `raw/` per `detection/INTEGRATION.md §2`:

* `iperf3`/`Ostinato`/`TRex` → `benign` (and `ddos` for floods)
* `hping3` SYN/UDP → `ddos` / `port_scan`
* `Slowloris` → `c2_beaconing`
* `dnscat2`/`iodine` → `dns_tunnelling`
* DGArchive samples / sandboxed C2 emulator → `dga_domain` (+ `c2_beaconing`)

Then `tools/evaluate.py` thresholds can be re-derived on real benign traffic — do not quote a detection rate from synthetic-only data.
