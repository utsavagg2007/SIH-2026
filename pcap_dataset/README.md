# pcap_dataset — replay workspace (outside core source)

Raw PCAPs and derived features for model training. This directory is **at the repo root** so it is not part of `injestion_core/` source.

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
.venv/bin/maturin develop --manifest-path injestion_core/Cargo.toml

# 2. populate raw/ — either generate synthetic or fetch your captures out-of-git
.venv/bin/python injestion_core/scripts/generate_synthetic_pcap.py --output pcap_dataset/raw/synthetic.pcap
# or: scp user@share:/pcaps/*.pcap pcap_dataset/raw/

# 3. ingest — deterministic replay_id = uuid5(NS, f"{sha256}:{label}")
.venv/bin/python pcap_dataset/ingest.py --pcap pcap_dataset/raw/synthetic.pcap --label ddos
# re-running same pcap+label is idempotent (same output/<id>/, same metadata entry)

# 4. verify central registry + per-replay binding
cat pcap_dataset/metadata.json
cat pcap_dataset/output/<replay_id>/meta.json
```

If `raw/*.pcap` is missing but `metadata.json` lists a `replay_id`, `ingest.py` will re-create it deterministically when the same `pcap` (same bytes) + `label` is supplied — the `replay_id` and `output/<id>/` path will match the original author's.

## Threat classes (enforced)

`port_scan, ddos, dns_tunnelling, encrypted_malware, data_exfiltration, c2_beaconing, dga_domain`
