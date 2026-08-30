# SIH26-26145 — Backend

Ingests `ThreatAlert v1.1` from the detection/ML layer, deduplicates and
correlates it, and serves it to the dashboard over WebSocket and REST.

```
detector ──POST /api/v1/alerts──▶  AlertBus
                                     ├── WebSocket /ws/alerts   (live, never blocked)
                                     └── write-behind batch ──▶ Postgres / Supabase
```

## Quick start

No database, no configuration:

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
```

```bash
.venv/Scripts/python -m uvicorn app.main:app --port 8000
```

Then open <http://127.0.0.1:8000/docs>. Generate fixtures and replay one:

```bash
.venv/Scripts/python tools/make_fixtures.py
```

```bash
curl -X POST localhost:8000/api/v1/replay/start -H "Content-Type: application/json" -d "{\"capture\":\"demo_scenario.jsonl\",\"speed\":8,\"loop\":true}"
```

---

## The schema decision you should know about

The three project documents specify **two different alert shapes**:

| | `SIH26_Alert_Output_Spec_v1.1_FINAL.md` | Frontend Spec §7 / Build Plan Layer 0 |
|---|---|---|
| score | `score` + `score_type` | `confidence` |
| evidence | flat **object** | **array** of bars with `threshold`, `direction`, `scale` |
| time | ISO-8601 strings | Unix float epoch |
| MITRE | `mitre_techniques[]` | `mitre_technique` |
| extras | — | `visual{}`, `occurrences`, `first_seen` |

This backend treats that as its job rather than a conflict to escalate:

```
detector ──ThreatAlert v1.1──▶ backend ──view model──▶ dashboard
           (frozen, unchanged)                          (frontend contract)
```

The v1.1 contract is ingested **verbatim and strictly**; the view model is
produced on the way out. `occurrences`/`first_seen` come from the dedup layer,
evidence bars from a threshold registry, `visual` from per-class builders —
exactly the fusion layer the Downstream Architecture document describes in §7.
Neither team changes anything, and the untouched v1.1 object travels along on
every alert as `raw`.

---

## Layout

```
app/
  schemas/
    alert_v11.py     the frozen ingest contract, strictly validated
    enums.py         frozen vocabulary + kill-chain mapping
    view.py          what the dashboard consumes
  fusion/
    dedup.py         occurrence counting, bounded LRU
    correlate.py     incidents, kill-chain ordering, escalation
  projection/
    thresholds.py    per-threat-class evidence threshold registry
    evidence.py      evidence object -> ordered bars
    visuals.py       per-class visual builders (comb, fan-out, ...)
    project.py       v1.1 alert -> view model
  core/
    bus.py           ingest -> fusion -> fan-out. The spine.
    hub.py           WebSocket fan-out with backpressure
    metrics.py       throughput + latency accounting
    constraints.py   the read-only proof
  storage/
    memory.py        zero-config ring buffer (demo fallback)
    postgres.py      asyncpg, batched writes, JSONB evidence
  api/               routes
  replay/            capture replay for demos and load tests
db/schema.sql        paste into the Supabase SQL editor
fixtures/            replayable captures + ground-truth manifests
tools/               fixture generator, benchmark, smoke test, profiler
```

---

## API

### Ingest

| Route | Purpose |
|---|---|
| `POST /api/v1/alerts` | one v1.1 alert → `201` / `422` |
| `POST /api/v1/alerts/bulk` | a batch → `202` with a per-alert summary |
| `POST /api/v1/telemetry` | traffic rates from the ingestion layer |

Ingest does **no I/O**. It validates, hands the alert to the bus, and returns —
so a detector's POST latency is independent of how many dashboards are connected
or how far behind the database is.

Bulk validation is per-alert and partial by design: one malformed alert in a
batch of five hundred must not discard the other four hundred and ninety-nine.

### History and investigation

```
GET /api/v1/alerts?from=&to=&threat_class=&severity=&src_ip=&dst_ip=&host=&detector=&incident_id=&min_score=&limit=&offset=
GET /api/v1/alerts/{alert_id}
GET /api/v1/incidents
GET /api/v1/incidents/{incident_id}
GET /api/v1/hosts
GET /api/v1/hosts/{ip}
```

### System

```
GET  /api/v1/system/health        readiness, storage state, detector rows
GET  /api/v1/system/metrics       the current metrics frame
GET  /api/v1/system/throughput    requirement (d), with provenance attached
GET  /api/v1/system/constraints   the read-only proof
GET  /api/v1/system/detectors     per-detector state
```

### Replay

```
GET  /api/v1/replay/captures      available captures + ground-truth manifests
POST /api/v1/replay/start         { capture, speed, loop, max_rate }
POST /api/v1/replay/stop
GET  /api/v1/replay/status
```

### Live feed — `/ws/alerts`

| Frame | When |
|---|---|
| `snapshot` | once on connect, so a reconnecting dashboard is never blank |
| `alert.created` | a new deduplicated finding |
| `alert.updated` | a repeat folding into an existing one |
| `incident.created` / `incident.updated` | correlation opened or materially changed an incident |
| `metrics` | once per second |
| `system.status` | storage or replay state changed |

The connection is write-mostly. The dashboard has nothing to command, because
this system has nothing to command.

---

## Design decisions worth defending

**The live path never waits on the durable path.** `bus.publish` is synchronous
and does no I/O: it dedups, correlates, projects, broadcasts to in-process
queues, and appends to a write-behind queue. Routing alerts through the database
before display would convert a streaming system into a micro-batch one and
forfeit requirement (c).

**One slow dashboard cannot slow detection.** Every WebSocket connection owns a
bounded queue and its own writer task. When a queue fills, the oldest frames are
dropped and `ws_dropped` reports how many. A dashboard showing 400 of the last
500 alerts and saying so is useful; one that stalls the pipeline to stay
complete is not.

**Storage failure degrades, it does not halt.** A write error is logged and
counted; detection continues. `/system/health` reports `degraded` so the loss is
visible rather than silent. If the durable queue fills, writes are shed — the
alert already reached every dashboard, and the alternative is unbounded memory
growth during a flood.

**Severity is never recalculated.** It arrives from the detector and is passed
through untouched, per alert spec §4.

**Memory is bounded everywhere.** The deduplicator and incident engine both use
time-based expiry first with a hard entry ceiling as a backstop. Under a spoofed
flood the key space explodes, and an unbounded map dies at exactly the moment it
is being graded.

**Reconstructed visuals are labelled.** Some class visuals need a *series* — the
beacon comb needs connection timestamps. When the evidence bag carries one, we
plot observations. When it does not, we can sometimes rebuild a plausible series
from the summary statistics, and every such payload is stamped
`"source": "reconstructed_from_summary_statistics"`. This matters: a comb drawn
from `mean_interval_sec` and `connection_count` looks like a perfect beacon *by
construction*, because we built it that way. The honest fix is for detectors to
ship `timestamps` in evidence; until they do, the flag keeps the claim accurate.

---

## Measured performance

Requirement (d) asks for a demonstrated rate, so this is measured, not
estimated:

```bash
.venv/Scripts/python tools/benchmark.py --ramp --duration 12
```

On the development machine (Windows 11, Python 3.11, single uvicorn worker,
in-memory store), two consecutive runs:

```
      100 req/s | achieved     99.9/s | p50  16.0ms | p95   38.6ms
      250 req/s | achieved    249.9/s | p50  17.4ms | p95   41.3ms
      500 req/s | achieved    499.8/s | p50  20.6ms | p95   59.0ms
     1000 req/s | achieved    789.2/s | p50 1892.0ms | p95 3801.6ms  <- saturated

      100 req/s | achieved     99.9/s | p50  21.2ms | p95   44.0ms
      250 req/s | achieved    249.6/s | p50  20.4ms | p95   50.5ms
      500 req/s | achieved    499.3/s | p50  27.9ms | p95  195.9ms
     1000 req/s | achieved    652.2/s | p50 3763.6ms | p95 7614.6ms  <- saturated
```

**Sustained 500 alerts/sec with p95 packet-to-alert latency under 200 ms.**
Saturation sets in above that; the highest achieved rate observed under
saturation ranged from 650 to 1,060 alerts/sec across runs.

Four things worth stating rather than glossing:

* **Scope.** This is the *alert-handling* stage — ingest, fusion, fan-out,
  durable enqueue. Capture, Zeek parsing, feature extraction and model inference
  are upstream and have their own harness. Reporting this figure as the whole
  pipeline's would be wrong.
* **"Sustained" means held.** The harness reports the highest rate that both kept
  up with the offered load *and* stayed inside a latency budget
  (`--latency-budget-ms`, default 250). Reporting the saturated phase instead
  would give a bigger number describing a system falling over.
* **Run-to-run variance is real.** The saturation point moved between 650 and
  1,060 alerts/sec depending on what else the laptop was doing. 500/s is the
  figure that reproduced on every run; treat the higher numbers as headroom, not
  as the claim.
* **Latency is scoped to the phase.** `/api/v1/system/throughput` keeps a 60 s
  rolling window; the harness passes `?window_s=` so a short burst is not
  measured against the previous phase's samples. Reading the raw window after a
  12 s phase reports the wrong phase's numbers — an early version of this
  harness did exactly that.

Latency is `event_end` (last packet of the observed window) → backend receipt.
Browser rendering is not included.

The dominant per-alert cost is projection and pydantic serialisation, not
fusion. `tools/profile_bus.py` measures the hot path with no HTTP or event loop
in the way (~2,300 publishes/sec in-process on the same machine).

---

## Storage

`STORAGE_BACKEND=memory` (default) needs nothing and is the demo-day fallback.

For Supabase, run `db/schema.sql` in the SQL editor, then set the pooler
connection string:

```bash
STORAGE_BACKEND=postgres DATABASE_URL="postgresql://postgres.<ref>:<pw>@aws-0-<region>.pooler.supabase.com:6543/postgres" .venv/Scripts/python -m uvicorn app.main:app
```

A Supabase project *is* a Postgres instance, and connecting directly with
asyncpg gets three things PostgREST cannot: real batched writes
(`executemany` over one connection), native JSONB with a GIN index on
`evidence`, and a persistent pool so the write-behind task is not paying a TLS
handshake per batch.

If the configured database is unreachable at startup, the service logs the
failure and falls back to the in-memory store rather than refusing to boot. The
System view reports which backend is actually in use, so the fallback is visible.

---

## Tests

```bash
.venv/Scripts/python -m pytest -q
```

95 tests: schema conformance (the executable half of the freeze checklist in
alert spec §20), fusion behaviour, evidence and visual projection, and
end-to-end API and WebSocket paths.

End-to-end against a running server:

```bash
.venv/Scripts/python tools/smoke.py
```

40 checks walking the whole demo path: constraint proof, schema enforcement,
replay → live feed, projection, correlation, deduplication, history API, and
requirement (d).

---

## Known limitations

* **Incidents live in memory.** The engine is the authority on what is currently
  correlated; the database copy is history. An incident evicted after its
  correlation window is reconstructable from
  `GET /api/v1/alerts?incident_id=...` but is no longer served by
  `GET /api/v1/incidents/{id}`.
* **Traffic rates are reported, not measured.** The backend only ever sees
  alerts, so it cannot infer flows/sec or Mb/s — a quiet link and a
  perfectly-defended one look identical from here. Those figures come from
  `POST /api/v1/telemetry` and are marked stale when nothing has reported, rather
  than being shown as a confident zero.
* **The constraint proof covers this process only.** That the enclave has no
  physical return path is a property of the data diode or SPAN configuration and
  is verified outside this service. The endpoint says so rather than overstating.
* **No authentication.** Deliberate for the prototype (Frontend spec §1.1 puts
  it explicitly out of scope). If this is ever exposed beyond the enclave,
  enabling RLS and putting a gate in front of the whole app is the first task.
