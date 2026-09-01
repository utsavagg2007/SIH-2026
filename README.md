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

---

# Running the project

Two commands once set up. The full walkthrough is below.

```bash
python tools/run_demo.py --ui        # start everything
python tools/verify_e2e.py           # prove all seven layers connect
```

## Step 0 — prerequisites

| Needed | Version | For |
|---|---|---|
| **Python** | 3.11 or newer | every backend layer (`detection` uses `tomllib`, which is 3.11+) |
| **Node.js** | 20 or newer | the dashboard |

That is the whole list for the default path. Rust and Docker are needed **only**
to run the real Zeek ingestion over a PCAP — see [Step 7](#step-7--optional-the-real-ingestion-path).

```bash
python --version     # 3.11+
node --version       # 20+
```

## Step 1 — create the Python environment

One virtualenv at the repository root serves every Python layer. Run these from
`SIH-project/`:

```bash
python -m venv .venv
```

**Windows (PowerShell):**

```bash
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.venv\Scripts\python.exe -m pip install -e "detection[ml,dev]"
.venv\Scripts\python.exe -m pip install -e "analyst[dev]"
```

**macOS / Linux:**

```bash
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r backend/requirements.txt
.venv/bin/python -m pip install -e "detection[ml,dev]"
.venv/bin/python -m pip install -e "analyst[dev]"
```

`detection` and `analyst` are installed editable, so edits take effect without
reinstalling. The `[ml]` extra pulls in scikit-learn, numpy and joblib — without
it the six rule detectors still run and DGA stays unregistered.

> You do **not** need to activate the venv. `tools/run_demo.py` and
> `tools/verify_e2e.py` both find `.venv` themselves and re-exec into it.

## Step 2 — build the dashboard

```bash
cd frontend
npm install
npm run build
cd ..
```

`npm run build` runs a full TypeScript typecheck (`tsc -b`) before bundling, so
it doubles as the frontend's compile gate. The backend serves the resulting
`frontend/dist/` automatically when it exists.

## Step 3 — run it

Two ways. **Option A** is one command. **Option B** is the same thing by hand,
which is what you want while working on a single layer — and it is the answer to
"how do I start the backend / the frontend".

### Option A — one command

```bash
python tools/run_demo.py --ui
```

This does, in order:

1. trains the DGA model from the committed sample dataset if `artifacts/` is
   empty — first run only, a few seconds;
2. generates a labelled synthetic capture into `data/features.jsonl` with a
   ground-truth manifest beside it;
3. starts the **backend** on `:8000` and the **analyst** on `:8100`;
4. starts the **Vite dev server** on `:5173` (that is what `--ui` adds);
5. runs the real detection engine over the capture, POSTing every alert to the
   backend's ingest route with throughput telemetry alongside;
6. scores the result against ground truth and prints the report;
7. leaves everything running. **Ctrl-C stops all of it.**

Nothing here is mocked: these are the same processes, the same contracts and the
same code paths a live capture would use.

### Option B — start each service yourself

Four terminals, each starting from `SIH-project/`. Every command uses the venv
interpreter; pick the column for your platform.

| | Windows (PowerShell / cmd) | macOS / Linux |
|---|---|---|
| venv Python, from the repo root | `.venv\Scripts\python.exe` | `.venv/bin/python` |
| venv Python, from a subdirectory | `..\.venv\Scripts\python.exe` | `../.venv/bin/python` |

**Terminal 1 — backend (Layer 6), port 8000**

*Windows*

```bash
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000
```

*macOS / Linux*

```bash
cd backend
../.venv/bin/python -m uvicorn app.main:app --reload --port 8000
```

Serves the REST API, the `/ws/alerts` WebSocket, and — when `frontend/dist`
exists — the dashboard itself at `/`. Drop `--reload` for a demo; it is a
development convenience that restarts on every file change.

**Terminal 2 — analyst (Layer 8), port 8100**

*Windows*

```bash
cd analyst
..\.venv\Scripts\python.exe -m uvicorn analyst.main:app --reload --port 8100
```

*macOS / Linux*

```bash
cd analyst
../.venv/bin/python -m uvicorn analyst.main:app --reload --port 8100
```

Optional. Skip this terminal entirely to demonstrate that the system meets every
requirement with the AI layer switched off — the panel will say
`Analyst unavailable. Detection is unaffected.` and nothing else changes.

**Terminal 3 — dashboard (Layer 7), port 5173**

```bash
cd frontend
npm run dev
```

Same on every platform. Hot-reloads on save, and proxies `/api` to the backend
and `/api/v1/analyst` to the analyst, so the browser only ever sees one origin.

> Open **<http://localhost:5173>**, not `127.0.0.1:5173`. Vite binds IPv6
> `::1`, so the dotted-quad form refuses the connection. The backend on `:8000`
> is the opposite — it binds `127.0.0.1` explicitly.

**Terminal 4 — generate traffic and run detection (Layers 1–5)**

Nothing appears on the dashboard until something produces alerts. From the repo
root — Windows commands are one line each, because `\` is not a line
continuation in PowerShell or cmd:

**Windows**

```bash
.venv\Scripts\python.exe tools/synth_flows.py -o data/features.jsonl
.venv\Scripts\python.exe -m detection_core.runner data/features.jsonl --output data/alerts.jsonl --ja3-feed tools/ja3_feed.example.txt --api-url http://127.0.0.1:8000/api/v1/alerts --telemetry-url http://127.0.0.1:8000/api/v1/telemetry
.venv\Scripts\python.exe tools/evaluate.py
```

**macOS / Linux**

```bash
.venv/bin/python tools/synth_flows.py -o data/features.jsonl

.venv/bin/python -m detection_core.runner data/features.jsonl   --output data/alerts.jsonl   --ja3-feed tools/ja3_feed.example.txt   --api-url http://127.0.0.1:8000/api/v1/alerts   --telemetry-url http://127.0.0.1:8000/api/v1/telemetry

.venv/bin/python tools/evaluate.py
```

`--api-url` is the flag that joins detection to the backend. Without it,
detection writes JSONL to disk and **nothing reaches the dashboard** — the single
most common reason for an empty screen. `--telemetry-url` is what makes the
flows/sec and Mb/s readouts real rather than a dash.

Alerts arrive in one burst this way, which is fine for checking the wiring. To
watch them stream in at a controlled rate instead, replay a committed fixture
through the backend — see [Command reference](#command-reference).

## Step 4 — look at it

| URL | What it shows |
|---|---|
| <http://localhost:5173> | **the dashboard** — start here (`localhost`, not `127.0.0.1`) |
| <http://127.0.0.1:8000/docs> | the API, browsable |
| <http://127.0.0.1:8000/api/v1/system/constraints> | the read-only proof — point at this during the demo |
| <http://127.0.0.1:8100/api/v1/analyst/constraints> | the analyst's own egress disclosure |

> **Why `--ui`.** The backend also serves the built bundle at
> <http://127.0.0.1:8000> with no dev server at all, and that works for
> everything except the Analyst panel: without Vite's proxy the panel's calls
> land on the backend, which does not serve those routes. Use `--ui` for the
> demo, or see [the note on serving the built bundle](#troubleshooting) to make
> `:8000` work standalone.

On the dashboard, in the order worth showing:

1. **Live** — the Wire across the top, alerts arriving in the stream.
2. Click any alert → the **Evidence** panel names the features that fired and the
   thresholds they crossed. This is the graded requirement.
3. **Incidents** — host `10.4.2.19` walks the kill chain: port scan → beaconing →
   exfiltration, correlated into one incident with its severity escalated on the
   sequence.
4. **System** — throughput, latency distribution, per-detector state, and the
   constraint panel.
5. Press **`a`** (or the *Explain* control on any alert) for the **Analyst**
   panel. Every sentence carries the stored evidence field it came from.

## Step 5 — verify every seam

```bash
python tools/verify_e2e.py
```

29 checks: that raw `dns.query` and `tls.ja3` survive ingestion, that all seven
threat classes fire, that the frames reaching the dashboard are the shape it
expects, that deduplication collapses repeats, that incidents span the kill
chain, and that every analyst sentence is traceable to a stored field. It starts
and stops its own services, so run it with nothing else running.

This exists because **every layer had a green test suite while the seams between
them were broken.** A per-layer suite cannot catch a disagreement about an
interface; this can. Run it after any change that touches a contract.

## Step 6 — optional: turn on the AI analyst's language model

The analyst works with no configuration at all — it renders explanations locally
from stored evidence and opens no outbound connection. Generation is what a key
turns on:

```bash
cp analyst/.env.example analyst/.env
```

Then edit `analyst/.env`:

```
ANALYST_GEMINI_API_KEY=your-key-here
ANALYST_GEMINI_MODEL=gemini-2.5-flash-lite
```

> Set `ANALYST_GEMINI_MODEL` to a model **your key can actually reach**. This
> project does not hardcode a family, and `GET /api/v1/analyst/health` reports
> the configured id — so a wrong value shows up before the demo rather than
> during it.

Turning this on means the analyst process makes outbound HTTPS calls to
`generativelanguage.googleapis.com`. That is disclosed at
`/api/v1/analyst/constraints`, it is the only outbound-capable module in the
repository, and what it sends is the derived fact sheet — the same text already
on screen — never a capture, payload or raw flow record. To switch it back off,
set `ANALYST_PROVIDER=template`.

## Step 7 — optional: the real ingestion path

The default run uses a synthetic capture so the system is demonstrable with
Python alone. To drive a real PCAP through Zeek and the Rust core you also need
**Rust** (`rustup`), **maturin**, and **Docker** (for Zeek):

```bash
pip install maturin
cd ingestion
maturin develop --release          # builds and installs ingestion_core
cd ..
python tools/run_demo.py --pcap path/to/capture.pcap --ui
```

Or run the two halves as a genuine stream, which is what requirement (c) asks for:

```bash
python ingestion/pipeline.py capture.pcap -o - --stats | \
  python -m detection_core.runner - \
    --api-url http://127.0.0.1:8000/api/v1/alerts \
    --telemetry-url http://127.0.0.1:8000/api/v1/telemetry
```

## Step 8 — optional: persist to Supabase

Alerts default to an in-memory store that needs no setup and loses history on
restart. To keep them:

```bash
cp backend/.env.example backend/.env
```

Set in `backend/.env` either the whole connection string:

```
STORAGE_BACKEND=postgres
DATABASE_URL=postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:6543/postgres
```

or the parts, and let it be derived:

```
STORAGE_BACKEND=postgres
SUPABASE_PROJECT_REF=<ref>
SUPABASE_DB_PASSWORD=<password>
SUPABASE_REGION=<region>
```

> `SUPABASE_REGION` is **not guessable** — read it off the pooler hostname in
> Project Settings → Database. The password is percent-encoded for you, so one
> containing `@` or `/` needs no escaping.

Then apply the schema:

```bash
.venv\Scripts\python.exe backend/tools/migrate.py --status     # what is pending
.venv\Scripts\python.exe backend/tools/migrate.py              # apply it
```

Migration `0002` enables Row Level Security with no policies, which stops
Supabase's PostgREST API from returning the alert corpus to the anon key while
leaving the backend's own connection unaffected. There is **no login gate** —
the dashboard opens straight into the live view, as the design spec requires.

If the database is unreachable the backend logs it and falls back to the
in-memory store rather than refusing to start. The System view reports which
backend is actually in use, so the fallback is visible rather than silent.

## Command reference

Every command, from the repository root, with `PY` standing for
`.venv\Scripts\python.exe` (Windows) or `.venv/bin/python` (macOS / Linux).

| What | Command |
|---|---|
| Everything at once | `python tools/run_demo.py --ui` |
| Verify all seven layers | `python tools/verify_e2e.py` |
| Backend only | `cd backend && $PY -m uvicorn app.main:app --reload --port 8000` |
| Analyst only | `cd analyst && $PY -m uvicorn analyst.main:app --reload --port 8100` |
| Dashboard, hot reload | `cd frontend && npm run dev` |
| Dashboard, production build | `cd frontend && npm run build` |
| Generate labelled traffic | `$PY tools/synth_flows.py -o data/features.jsonl` |
| Run detection into the backend | `$PY -m detection_core.runner data/features.jsonl --api-url http://127.0.0.1:8000/api/v1/alerts` |
| Score against ground truth | `$PY tools/evaluate.py` |
| Train the DGA model | `cd detection && $PY -m detection_core.ml.dga.training -i detection_core/ml/dga/data/dga_dataset.sample.csv -o ../artifacts/dga_model.joblib` |
| Apply database migrations | `$PY backend/tools/migrate.py --status` then without `--status` |
| Ingestion over a PCAP | `cd ingestion && $PY pipeline.py capture.pcap -o ../data/features.jsonl --stats` |
| Benchmark the alert bus | `cd backend && $PY tools/benchmark.py --ramp` |

Replaying a committed fixture through the backend's own engine, which is the
demo fallback if the pipeline misbehaves on stage — `demo_scenario.jsonl`,
`beacon_hour.jsonl` and `flood.jsonl` are in `backend/fixtures/`:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/replay/start   -H "Content-Type: application/json"   -d '{"capture":"demo_scenario.jsonl","speed":8,"loop":true}'

curl -X POST http://127.0.0.1:8000/api/v1/replay/stop
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Dashboard is blank, no alerts | Detection has not run, or ran without `--api-url`. Check the backend is up: `curl http://127.0.0.1:8000/health` |
| `flows/sec` and `Mb/s` read `—` | No throughput telemetry has arrived. That is honest, not broken — the backend never sees a packet. Pass `--telemetry-url` to the detection runner (`run_demo.py` does). |
| Only six detectors register | No trained DGA model. `run_demo.py` builds it on first run; otherwise `cd detection && python -m detection_core.ml.dga.training -i detection_core/ml/dga/data/dga_dataset.sample.csv -o ../artifacts/dga_model.joblib` |
| `encrypted_malware` never fires | The signature path needs a fingerprint list: `--ja3-feed tools/ja3_feed.example.txt`. Nothing is ever downloaded. |
| "Analyst unavailable" in the panel | The analyst is not running on `:8100`. If you are serving the built bundle from the backend rather than using `--ui`, rebuild with `VITE_ANALYST_BASE=http://127.0.0.1:8100/api/v1/analyst npm run build` — see below. |
| `ModuleNotFoundError` running a tool | Use the venv interpreter, or let `tools/run_demo.py` / `tools/verify_e2e.py` find it for you. |
| Port already in use | A previous run did not stop. Kill whatever holds 8000, 8100 or 5173 and retry. |
| `http://127.0.0.1:5173` refuses the connection | The Vite dev server binds IPv6 `::1`. Use **`http://localhost:5173`**. The backend on `:8000` is the reverse — it binds `127.0.0.1`. |
| `uvicorn: command not found` | Use the module form shown above (`python -m uvicorn ...`) with the venv interpreter, rather than a bare `uvicorn`. |

**A note on serving the built bundle.** Under `--ui`, Vite proxies
`/api/v1/analyst` to `:8100` and everything is same-origin. When the backend
serves `frontend/dist` on `:8000` instead, that proxy does not exist, so the
analyst's base URL has to be absolute at build time:

```bash
cd frontend
VITE_ANALYST_BASE=http://127.0.0.1:8100/api/v1/analyst npm run build
```

The analyst allows that origin in its CORS list. Everything else — alerts, the
WebSocket, incidents — is served by the backend itself and needs no flag.

---

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

Use the venv interpreter (`.venv\Scripts\python.exe` on Windows,
`.venv/bin/python` elsewhere); `python` below is shorthand for it.

```bash
cd detection && python -m pytest -q            # 1638
cd backend   && python -m pytest -q            #  135
cd analyst   && python -m pytest -q            #   24
cd ingestion && python -m pytest pytests -q    #   16
cd frontend  && npm test                       #   59
python -m pytest tools/tests -q                #   17   (from the repo root)
```

**1,889 tests.** Plus `tools/verify_e2e.py` — 29 checks across the seams
between them, which is where the defects actually were.

`ingestion` uses `pytests/`, not `tests/`: that directory holds the Rust crate's
integration tests, and its Python suite fakes the compiled extension so the join
logic can be tested without a Rust toolchain.

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
| **dga_domain** | ~~0.17~~ → **1.00** | 1.00 |

No overall accuracy figure is reported. With rare positives it is dominated by
the negative class, and a detector that fires on nothing scores extremely well.

**The two weak numbers are the honest ones, and they come from deliberately
planted confounders.** The benign traffic contains a time daemon (perfectly
periodic), a cloud backup (99% outbound), CDN hostnames (long and
high-entropy), and an authorised inventory sweep — the four things that look
exactly like beaconing, exfiltration, DGA and recon:

- The **beacon** detector fires on the NTP daemon at score 0.79 — *higher* than
  the real C2 channel at 0.76. It has no benign-periodicity discrimination.
  **Still open.**
- The **DGA** model flagged legitimate CDN hostnames as `critical` at 0.97,
  because its training corpus contained no content-delivery or cloud-storage
  names. **Fixed** — see below.

They are reported rather than hidden because a precision figure measured
without confounders is meaningless — see
[docs/SIH-Layered-Build-Plan.txt](docs/SIH-Layered-Build-Plan.txt) §3.2.

### DGA precision: fixed

The benign corpus now also carries **1 824 real CDN / object-storage hostnames**
from the Cisco Umbrella top 1M — the machine-assigned names
(`d9ojso6xukdhq.cloudfront.net`) that Tranco's registrable domains never
contain. The confounder that scored 0.985 now scores 0.285, and `dga_domain`
goes from **precision 0.17 → 1.00 with recall unchanged at 1.00**; the run's
overall false positives fall from 48/hr to 18/hr. Measured on real held-out
CDN providers the model has never seen, false positives drop 14×.

The decision threshold was re-derived with it: **0.65**, shipped as
`detection/detectors.dga-precision.toml` for the runner's `--config` flag, so
no detection code changes. The cost is stated in the doc — subdomain-hosted DGA
sensitivity is largely lost, because the DGA corpus is 99.5% two-label while
CDN hostnames are all three-or-more.

Full evidence, the sweeps behind every parameter, and what is flagged for the
detector owner: **[docs/DGA_PRECISION.md](docs/DGA_PRECISION.md)**.

The DGA model itself, measured family-disjoint (no DGA family in both train and
test): precision 0.895, recall 0.569 at 0.75 and 0.711 at the recommended 0.65
— on a test fold whose composition changed with the corpus, so compare it to
the old 0.944/0.711 only via the identical-population table in that doc.

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
