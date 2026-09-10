# AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

Passive, evidence-first threat detection for receive-only network taps.

**Live demo:** https://sih-2026-three-rosy.vercel.app

## 1. Project Information

- **Project Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
- **PS ID:** SIH26145
- **PS Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
- **Category:** Software
- **Theme:** Blockchain & Cybersecurity
- **Organisation:** National Technical Research Organisation (NTRO)
- **Team Name:** Forward Bias

## 2. Problem Statement

A national monitoring enclave receives only a one-way, mirrored copy of gateway traffic. The sensor can observe but never transmit, so it cannot probe a host, complete a handshake, intercept TLS, or query an endpoint to confirm a suspicion. Most of that traffic is encrypted, so payload inspection yields nothing.

Conventional inline IDS/IPS assumes two-way visibility and the ability to act, and therefore cannot be deployed in this position at all — yet the traffic still has to be assessed for threats.

## 3. Proposed Solution

A passive detection system that converts a unidirectional traffic feed into evidence-backed threat alerts.

It ingests PCAP or NetFlow/IPFIX records, parses them with Zeek, computes windowed statistical features in a Rust core, and runs seven detectors — six statistical and one machine-learning classifier for algorithmically generated domains. A fusion layer calibrates confidence, removes duplicates, and correlates related alerts into single incidents. Results stream to a live web dashboard alongside an AI analyst that explains each finding in plain language.

The system runs end to end today across nine layers.

## 4. Key Features

- **Seven threat classes** — port scanning, DDoS, C2 beaconing, DNS tunnelling, DGA, encrypted malware, data exfiltration — each mapped to MITRE ATT&CK
- **Detection on encrypted traffic without decryption** — TLS handshake fingerprints (JA3/JA3S/JA4), SNI, packet timing and volume patterns. No key is ever held
- **Evidence attached to every alert** — the exact features that fired and the thresholds crossed, so an analyst can verify the reasoning rather than trust a score
- **Incident correlation** — dozens of repeat beacons collapse into one incident tracing the kill chain
- **Streaming architecture** — alerts reach the screen before they reach storage; the live path never waits on the durable one
- **Grounded AI analyst** — any figure it states that no stored field supports is discarded, and a deterministic explanation returned instead
- **Provable read-only posture** — a live endpoint walks the running route table to show no path out exists
- **Frozen alert contract** — ThreatAlert v1.1, with its freeze checklist enforced as executable tests

## 5. Technology Stack

- **Frontend:** React, TypeScript, Vite, Framer Motion, WebSocket API
- **Backend:** Python, FastAPI, Uvicorn, Pydantic
- **Feature Engineering:** Rust, PyO3, Maturin
- **Database:** PostgreSQL, asyncpg, Supabase
- **AI/ML:** scikit-learn (RandomForest), NumPy, joblib, Google Gemini API
- **Network Analysis:** Zeek, JA3/JA3S, JA4+, NetFlow/IPFIX
- **Cloud:** Vercel, Docker
- **Hardware:** None (software-only)
- **Dev Tools:** Git/GitHub, pytest, Vitest, Cargo

## 6. Architecture

See [docs/](docs/) for the layer-by-layer documentation.

```text
Traffic in (PCAP / live mirror / NetFlow / IPFIX)
  |                    one-way, receive-only
  v
Zeek  (conn, dns, ssl, x509 + JA3/JA3S/JA4)
  |
  v
Feature core  (Rust + PyO3, bounded-memory windows)
  |
  v
Detection  (6 statistical detectors + DGA ML)
  |
  v
Fusion  (calibrate, dedupe, correlate -> incidents)
  |
  v
Alert Bus  (ThreatAlert v1.1: confidence, evidence, MITRE)
  |
  +----> WebSocket ----> Live Dashboard
  |
  +----> PostgreSQL ---> AI Analyst (RAG, read-only)
```

## 7. Repository Structure

```text
SIH-2026/
├── README.md
├── DEPLOYMENT.md
├── ingestion/              # Layer 1-3: Zeek runtime + Rust feature core
│   ├── src/                #   Rust: features, canonical observations
│   ├── docker/             #   pinned Zeek images (JA3, JA4)
│   ├── runtime/            #   Zeek scripts
│   └── vendor/             #   vendored ja3-zeek, ja4-zeek
├── detection/              # Layer 4-5: detectors + DGA model
│   └── detection_core/
│       ├── detectors/      #   6 statistical detectors
│       └── ml/dga/         #   RandomForest classifier + corpus
├── backend/                # Layer 6: FastAPI, fusion, alert bus
│   ├── app/                #   api, fusion, projection, storage
│   ├── db/                 #   migrations
│   └── fixtures/           #   replay captures
├── frontend/               # Layer 7: React dashboard
│   └── src/
├── analyst/                # Layer 8: read-only AI analyst
├── contracts/              # ThreatAlert v1.1 — frozen alert contract
├── pcap_dataset/           # Layer 9: real-capture ingest + replay integrity
├── tools/                  # run_demo.py, verify_e2e.py, evaluate.py
├── docs/                   # architecture, evaluation records
├── pytest.ini
└── render.yaml
```

### What goes where?

| Item | Location |
|---|---|
| Source code | `ingestion/`, `detection/`, `backend/`, `frontend/`, `analyst/` |
| Architecture / technical documentation | `docs/` |
| Evaluation records | `docs/REAL_DATA_EVAL.md`, `docs/DGA_PRECISION.md` |
| Alert contract | `contracts/threat_alert_v1.1.md` |
| Project screenshots | `assets/screenshots/` |
| Final PPT / presentation | `submission/` |
| Demo video link | `submission/DEMO.md` |
| Project overview | `README.md` |

## 8. Final Presentation

The SIH idea presentation is in [submission/](submission/).

See [submission/PRESENTATION.md](submission/PRESENTATION.md) for the required format.

## 9. Demo Video

Add the demo link in [submission/DEMO.md](submission/DEMO.md).

## 10. Screenshots / Prototype Photos

Dashboard screenshots are in `assets/screenshots/`.

## 11. Installation

**Prerequisites:** Python 3.11–3.13, Node 22.22.2+ / 24.15.0+ / 26+. Rust and Docker are needed **only** for the real Zeek ingestion path over a PCAP.

```bash
git clone https://github.com/utsavagg2007/SIH-2026
cd SIH-2026
python -m venv .venv
```

**macOS / Linux:**

```bash
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r backend/requirements.txt
.venv/bin/python -m pip install -e "detection[ml,dev]"
.venv/bin/python -m pip install -e "analyst[dev]"
```

**Windows (PowerShell):**

```bash
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.venv\Scripts\python.exe -m pip install -e "detection[ml,dev]"
.venv\Scripts\python.exe -m pip install -e "analyst[dev]"
```

Build the dashboard:

```bash
cd frontend && npm ci && npm run build && cd ..
```

## 12. Run

One command starts every layer and opens the dashboard:

```bash
python tools/run_demo.py --ui
```

Verify that all layers actually connect:

```bash
python tools/verify_e2e.py
```

Run against a real capture (needs Rust + Docker):

```bash
python tools/run_demo.py --pcap path/to/capture.pcap --ui
```

Tests:

```bash
python -m pytest tests -q      # Python
cargo test --locked            # Rust
cd frontend && npm test        # Frontend
```

## 13. Future Scope

Carried over from the project's own `Known gaps` section — these are measured, not guessed.

- **Persist incidents.** They currently live in process memory and are lost on restart or after the correlation window closes. The `incidents` tables exist but are never written.
- **Improve `c2_beaconing` precision on real traffic** — 0.056 on the labelled bot capture. What remains is periodic HTTPS to ordinary internet hosts; a destination-popularity rule was measured against it and rejected, with the numbers recorded in `docs/REAL_DATA_EVAL.md` §10.7.
- **Promote `detector-v2` to the default feature profile.** Under the legacy projection the numeric `conn_state` folds `S0` into "unknown", costing recall 0.500 against 1.000 on banner-grabbing recon.
- **Apply and test the Supabase migrations against a live database.** The SQL and runner are written but were never run against a reachable Postgres.
- **Plot observed timestamps in `BeaconComb`** rather than reconstructing tick rows from summary statistics.
- **Remove the Rust toolchain requirement for ingestion**, or ship prebuilt `ingestion_core` wheels.

## Important

Do not upload passwords, API keys, access tokens, `.env` files containing secrets, or other confidential credentials.

The AI analyst's language model is optional and off by default. It activates only when `ANALYST_GEMINI_API_KEY` is set — keep that key out of the repository.
