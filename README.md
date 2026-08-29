# SIH26-26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

Backend and verification frontend for the passive threat-detection prototype.

```
PCAP / NetFlow ──▶ Zeek ──▶ ingestion_core (Rust) ──▶ detection / ML layer
                                                            │
                                              ThreatAlert v1.1 JSON
                                                            │
                                                            ▼
                                                        BACKEND        ◀── this repo
                                                            ├── WebSocket ──▶ dashboard
                                                            └── Postgres / Supabase
```

| Directory | Contents |
|---|---|
| [`backend/`](backend/) | FastAPI service: ingest, fusion, fan-out, storage, replay |
| [`frontend/`](frontend/) | React verification console for checking the backend end to end |
| [`ingestion_src/`](ingestion_src/) | The Rust ingestion core, unpacked from the supplied archive |

Start with [`backend/README.md`](backend/README.md).

## Running both

Two terminals. The backend needs no database and no configuration:

```bash
cd backend && python -m venv .venv && .venv/Scripts/pip install -r requirements.txt && .venv/Scripts/python tools/make_fixtures.py && .venv/Scripts/python -m uvicorn app.main:app --port 8000
```

```bash
cd frontend && npm install && npm run dev
```

Open <http://127.0.0.1:5173>, go to the **Replay** view, and start
`demo_scenario.jsonl` with loop enabled.

## What this half of the system does

The detection/ML layer emits alerts. This backend:

1. **Ingests** them against the frozen `ThreatAlert v1.1` contract, strictly —
   an alert that has drifted from the contract is rejected with a 422 that names
   the offending field.
2. **Deduplicates** repeat findings for the same entity, class and detector into
   one alert with an occurrence count. A beacon firing every sixty seconds for an
   hour produces one row, not sixty.
3. **Correlates** alerts touching the same host into incidents ordered along the
   kill chain — reconnaissance, then command and control, then exfiltration —
   and escalates severity when the sequence itself is evidence.
4. **Projects** the flat v1.1 evidence bag into the ordered, thresholded
   evidence bars and per-class visuals the dashboard contract asks for.
5. **Fans out** to a live WebSocket and a batched durable writer, in that order,
   with the live path never waiting on the durable one.

## The three problem-statement constraints, and where they are honoured

**(a) Read-only ingest.** No route in this service emits anything toward the
monitored network. `GET /api/v1/system/constraints` returns a proof that walks
the live route table rather than asserting a hardcoded boolean, and discloses
the one outbound connection the process does make — to the alert database inside
the enclave — rather than pretending to be hermetic. It also states its own
scope: that the enclave has no physical return path is a property of the data
diode, verified outside this service.

**(b) No payload decryption.** This backend holds no keys and parses no
ciphertext. TLS/QUIC alerts are built from metadata fields the detection layer
supplies — JA3/JA3S/JA4, SNI, version, packet sizes.

**(c) Streaming, not batch.** `bus.publish` is synchronous and does no I/O.
Alerts reach connected dashboards before they reach storage. Routing them
through the database first would be a batch pattern wearing streaming clothes.

**(d) Stated throughput.** Measured, not estimated:
**500 alerts/sec sustained with p95 packet-to-alert latency under 200 ms**,
saturating above that. Reproduce with `backend/tools/benchmark.py --ramp`. This
is the alert-handling stage only — capture, parsing, feature extraction and
inference are upstream and measured separately. The saturation point varied
between 650 and 1,060 alerts/sec across runs on a development laptop; 500/s is
the figure that reproduced every time.

**(e) Standardised alert schema.** `ThreatAlert v1.1` is transcribed directly
into `backend/app/schemas/alert_v11.py`, with the freeze checklist from §20 of
the spec as executable tests.

## Verification

```bash
cd backend && .venv/Scripts/python -m pytest -q
```

95 unit and integration tests. With the server running:

```bash
cd backend && .venv/Scripts/python tools/smoke.py
```

40 end-to-end checks covering the whole demo path.

## One decision to be aware of

The project documents specify two different alert shapes — the frozen v1.1
contract the ML layer emits, and a richer shape the frontend spec asks for. The
backend treats bridging them as its job rather than a conflict to escalate: it
ingests v1.1 verbatim and produces the frontend view model on the way out, with
the untouched original travelling along as `raw`. Details and the field-by-field
comparison are in [`backend/README.md`](backend/README.md).
