# SIH26-26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

A passive threat-detection system for a monitoring enclave: it sees a one-way
copy of gateway traffic, and it cannot send anything back. Everything it
produces is intelligence — labelled alerts, scored, with the evidence that
produced them.

```
PCAP / NetFlow ──▶ Zeek ──▶ ingestion_core (Rust) ──▶ flow records
                                                          │
                                              detection engine (7 detectors + DGA ML)
                                                          │
                                              fusion · calibrate · dedupe · correlate
                                                          │
                                                     alert bus
                                                    ╱          ╲
                                          WebSocket              Postgres / Supabase
                                              │                        │
                                          dashboard            AI analyst (RAG)
```

## Run it

```bash
python tools/run_demo.py
```

That generates a labelled capture, starts the backend and the analyst, drives
the capture through the real detection engine into the ingest route with
throughput telemetry alongside, and scores the result against ground truth. It
needs Python and nothing else — no Zeek, no Docker, no Rust.

To run the real ingestion path instead, add `--pcap capture.pcap` (needs the
compiled Rust extension and Zeek via Docker).

To prove the system meets every requirement with the AI layer switched off:

```bash
python tools/run_demo.py --no-analyst
```

## Verify it

```bash
python tools/verify_e2e.py
```

29 checks across every seam: that raw `dns.query` and `tls.ja3` survive
ingestion, that all seven threat classes fire, that the frames reaching the
dashboard are the shape it expects, that deduplication collapses repeats, that
incidents span the kill chain, and that every analyst sentence carries the
evidence field it came from. It starts and stops its own services.

This exists because **every layer had a green test suite while the seams
between them were broken.** A per-layer suite cannot catch a disagreement about
an interface; this can.

## Layout

| Directory | Layer | What it owns |
|---|---|---|
| [`contracts/`](contracts/) | 0 | `canonical_observation_v1.schema.json`, the frozen `ThreatAlert v1.1` contract, and fixtures |
| [`ingestion/`](ingestion/) | 1–3 | Zeek log parsing and feature extraction — Rust crate (PyO3) plus the pipeline driver |
| [`detection/`](detection/) | 4–5 | Seven detectors, the DGA model, windowed aggregation, `ThreatAlert` emission |
| [`backend/`](backend/) | 6 | FastAPI: ingest, dedup, correlation, projection, alert bus, storage, replay |
| [`frontend/`](frontend/) | 7 | React dashboard — the Wire, alert stream, evidence drill-down, incidents, system, replay |
| [`analyst/`](analyst/) | 8 | Read-only AI analyst over the persisted alert store |
| [`tools/`](tools/) | 9 | Orchestration, labelled traffic generation, evaluation harness, end-to-end verification |
| [`docs/`](docs/) | — | The design specifications this build is measured against |

Each layer keeps its own README and its own test suite.

## Tests

```bash
cd detection && python -m pytest -q     # 1638
cd backend   && python -m pytest -q     #  130
cd analyst   && python -m pytest -q     #   24
cd ingestion && python -m pytest pytests -q   # 16
cd frontend  && npm test                #   59
```

Plus `tools/verify_e2e.py` for the seams between them.

## How the problem statement's constraints are met

**(a) Read-only ingest.** No component emits anything toward the monitored
network. `GET /api/v1/system/constraints` walks the live route table rather than
asserting a boolean, and discloses the one outbound connection the backend makes
— to the alert database inside the enclave. The analyst layer's egress is
disclosed separately at `GET /api/v1/analyst/constraints`, and is off unless a
model API key is configured.

**(b) No payload decryption.** TLS and QUIC are analysed from handshake metadata
only — JA3/JA3S, SNI, negotiated version, packet and byte counts. No component
holds a key or parses ciphertext.

**(c) Streaming, not batch.** `ingestion/pipeline.py -o -` writes and flushes
each record as it is produced; `detection_core.runner -` reads stdin and scores
incrementally; `AlertBus.publish` is synchronous and does no I/O, so alerts
reach connected dashboards before they reach storage. The live path never waits
on the durable one.

```bash
python ingestion/pipeline.py capture.pcap -o - | \
  python -m detection_core.runner - --api-url http://localhost:8000/api/v1/alerts
```

**(d) Stated throughput.** Measured on this machine, not estimated:

| Stage | Measured |
|---|---|
| Detection (detectors only) | 13,012 flows/sec |
| Detection (through the JSONL adapter) | 8,685 flows/sec, p95 101.8 µs |
| Alert delivery — detection-loop cost | ~704,000 enqueues/sec (delivery is off the loop) |
| Alert delivery — end to end incl. drain | 2,536 alerts/sec |
| Backend alert handling | 500 alerts/sec sustained, p95 under 200 ms |

The backend figure was measured against the in-memory store; it has **not** been
re-measured against Supabase, and the durable path is the more likely limiter.
Reproduce with `backend/tools/benchmark.py --ramp`.

**(e) Standardised alert schema.** `ThreatAlert v1.1`
([contracts/threat_alert_v1.1.md](contracts/threat_alert_v1.1.md)) is frozen and
transcribed into `backend/app/schemas/alert_v11.py`, with the freeze checklist as
executable tests.

## Detection quality, stated honestly

From `tools/evaluate.py` over the labelled synthetic capture:

| Threat class | Precision | Recall |
|---|---|---|
| port_scan | 1.00 | 1.00 |
| ddos | 1.00 | 1.00 |
| dns_tunnelling | 1.00 | 1.00 |
| encrypted_malware | 1.00 | 1.00 |
| data_exfiltration | 1.00 | 1.00 |
| **c2_beaconing** | **0.50** | 1.00 |
| **dga_domain** | **0.17** | 1.00 |

No overall accuracy figure is reported. With rare positives it is dominated by
the negative class, and a detector that fires on nothing scores extremely well.

**The two weak numbers are the honest ones, and they come from deliberately
planted confounders.** The benign traffic contains a time daemon (perfectly
periodic), a cloud backup (99% outbound), CDN hostnames (long and
high-entropy), and an authorised inventory sweep — the four things that look
exactly like beaconing, exfiltration, DGA and recon:

- The **beacon** detector fires on the NTP daemon at score 0.79 — *higher* than
  the real C2 channel at 0.76. It has no benign-periodicity discrimination.
- The **DGA** model flags legitimate CDN hostnames as `critical` at 0.97. Its
  training corpus contains no content-delivery or cloud-storage names.

Both are detector-tuning problems with known fixes (destination novelty and a
known-service allowlist for beaconing; CDN/cloud-storage hostnames in the DGA
benign corpus). They are reported rather than hidden because a precision figure
measured without confounders is meaningless — see
[docs/SIH-Layered-Build-Plan.txt](docs/SIH-Layered-Build-Plan.txt) §3.2.

The DGA model itself, measured family-disjoint (no DGA family in both train and
test): precision 0.944, recall 0.711, F1 0.811 at its live threshold of 0.75.

## Known gaps

- **Ingestion needs a Rust toolchain.** `ingestion_core` is a PyO3 extension;
  `cargo` and `maturin` are required to build it. `tools/synth_flows.py` exists
  so every layer above can be run and demonstrated without one.
- **The canonical observation contract has no producer wired in.**
  `ingestion/src/canonical/` implements a genuinely lossless
  `CanonicalObservation` producer for `conn.log`, but it is not exported through
  PyO3 and has no DNS/TLS/HTTP producer, so nothing calls it. The live path is
  the older `features.jsonl` shape, now repaired to carry the raw fields.
- **JA4 is parsed by nothing.** `--ja4` selects a Zeek image that produces the
  column; `SslRecord` has no field for it. Absent rather than faked.
- **Incidents are not persisted.** They live in process memory and are lost on
  restart or after the correlation window; the `incidents` tables exist but are
  never written.
- **Supabase migrations are untested against a live database.** The SQL and the
  runner are written; no Postgres was reachable here to apply them.
- **`BeaconComb` still fabricates its tick rows** from summary statistics rather
  than plotting observed timestamps. It carries a `reconstructed` badge, but the
  detector should ship the series.
