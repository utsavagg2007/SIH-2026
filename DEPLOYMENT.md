# Deployment

Deploying this project with the dashboard on **Vercel** and the two Python
services on **Render**. No VM, no Docker, no SSH. Both free.

Read [§1](#1-what-actually-deploys) first — it decides what you host and what you
do not, and it explains the one architectural rule that shapes every step after
it. Then work through [§3](#3-step-1--push-the-blueprint) onward in order.

> **The two costs of this setup, stated up front.** The origin splits in two, so
> CORS is load-bearing rather than incidental. And free Render instances **sleep
> after 15 minutes idle** — the first request afterwards takes 50–60 s, during
> which the dashboard is indistinguishable from a broken one.
> [§10](#10-the-cold-start-and-demo-day) is how you avoid meeting that in front
> of a judge. Neither is a blocker; both are worse to discover late.

---

## 1. What actually deploys

Five directories, three different deployment stories.

| Layer | What it is | Deploys as |
|---|---|---|
| `frontend/` | Vite + React, relative URLs by default, absolute when `VITE_*` is set | **Vercel.** A static bundle on a CDN, and nothing else. |
| `backend/` | FastAPI, WebSocket hub, in-memory fusion, Postgres write-behind | **Render web service.** `/api/v1/*` and `wss://…/ws/alerts`. |
| `analyst/` | FastAPI, calls the backend's REST API + Gemini | **Render web service.** Optional — the dashboard degrades gracefully without it. |
| `detection/` | CLI: `python -m detection_core.runner` — reads feature JSONL, POSTs alerts | **A worker you run, not a service you host.** Runs anywhere with network access to the backend. |
| `ingestion/` | Rust/PyO3 parser + Zeek in Docker, reads PCAP | **Never deploys.** It runs on the machine watching the traffic. |

### The three facts that decide the architecture

**Fact 1 — the frontend's addresses are build-time settings.**
`lib/api.ts` reads `VITE_API_BASE`, `VITE_WS_URL` and `VITE_ANALYST_BASE`, and
each falls back to a same-origin relative path. Left unset, the bundle assumes
the API is on its own origin — correct under the Vite dev proxy, and correct
again when `backend/app/main.py::_mount_dashboard` serves the built bundle
itself. It is **not** correct on Vercel, where nothing sits behind the CDN to
proxy those paths. Setting the three variables is what makes a split origin work,
and it is the whole of [§6](#6-step-4--deploy-the-frontend-to-vercel).

`useFeed.ts` imports `WS_URL` from `lib/api.ts` rather than rebuilding it, so
there is exactly one definition of the socket's address. A split-origin deploy
cannot be corrected in one file and left wrong in the other.

**Fact 2 — the backend is stateful and must be a single instance.**
`AlertBus`, `ConnectionHub` (WebSocket fan-out), the 300 s dedup window and the
1800 s correlation window all live in process memory. Two instances means dedup
splits (duplicate alerts on screen), correlation splits (incidents fragment), and
a browser connected to instance A never receives an alert POSTed to instance B.

A free Render service is one instance with one worker, so this is satisfied by
default. It is also the thing you must not "fix" later by scaling up.

**Fact 3 — a Vercel rewrite cannot carry the WebSocket.**
`/ws/alerts` is the live feed — it *is* the product. A Vercel `rewrites` rule
passes HTTP through but drops the `Upgrade` handshake, so the one thing that
would fail is the one thing that matters. This is not a configuration you can
find; it is a platform limitation.

The consequence is the shape of this whole deployment: **the browser talks to
Render directly**, at an absolute `wss://` URL, and both Python services
therefore need CORS. Do not attempt a rewrite for `/api` either — it would work,
but it would leave you with a setup where REST goes one way and the socket goes
another, and two different failure modes to debug.

---

## 2. What you are building

```
        Vercel (CDN)                        Render (two free web services)
   ┌────────────────────┐            ┌──────────────────────────────────────┐
   │  frontend/dist     │            │                                      │
   │  the dashboard     │            │   sih-backend                        │
   │                    │            │     /api/v1/*      REST              │
   │  built with:       │──REST────▶ │     /ws/alerts     live feed         │
   │   VITE_API_BASE    │            │     /health        liveness          │
   │   VITE_WS_URL      │──WSS─────▶ │        │                             │
   │   VITE_ANALYST_BASE│            │        │ (optional) Supabase §11     │
   │                    │──REST────▶ │   sih-analyst                        │
   └────────────────────┘            │     /api/v1/analyst/*                │
                                     │        │                             │
      CORS_ORIGINS  ◀────────────────┤        └──HTTPS──▶ Google Gemini     │
      must name the Vercel origin    └──────────────────────────────────────┘

  ingestion/ + Zeek ──features.jsonl──▶ detection/ runner
  detection/ runner ──POST /api/v1/alerts──▶ sih-backend
      (both run from your laptop — or skip them and use replay, §9)
```

**Cost: $0/month.** Vercel's Hobby tier and Render's free tier, neither a trial.

**New files: 1.** `render.yaml`, already at the repo root. No application code
changes — Fact 1's variables are already wired.

**What you give up versus a single always-on box:** the cold start
([§10](#10-the-cold-start-and-demo-day)), and persistence unless you attach a
database ([§11](#11-persistence-optional)). In exchange you provision nothing,
patch nothing, and there is no instance to reclaim or reboot.

---

## 3. Step 1 — Push the blueprint

`render.yaml` declares both services: runtime, root directory, build and start
commands, health check paths, and which environment variables Render should
prompt you for. Commit it to the branch you intend to deploy.

```bash
git add render.yaml && git commit -m "Deploy: Render blueprint" && git push
```

Two things in that file are load-bearing and worth understanding before Render
runs them:

- **`startCommand` binds `$PORT`.** Render assigns the port and expects the
  process on `0.0.0.0`. A service that hardcodes `:8000` never passes the port
  scan and is killed as unhealthy.
- **`healthCheckPath: /health`, not `/api/v1/system/health`.** The latter reports
  degraded states honestly — including `storage=memory`, which is the intended
  configuration here. Pointing a health check at it would restart-loop the
  instance on a condition that is by design. `/health` is unconditional liveness,
  which is exactly what a platform probe should ask for.

Neither service declares a worker count, so both run one worker. That is Fact 2,
and it is not a knob to turn.

---

## 4. Step 2 — Create the Render services

Render Dashboard → **New** → **Blueprint** → select this repo and branch. Render
reads `render.yaml`, offers **sih-backend** and **sih-analyst**, and prompts for
the four values marked `sync: false`.

The Vercel URL does not exist yet, so the CORS fields get a placeholder now and
their real value in [§7](#7-step-5--close-the-cors-loop). This is the one
genuinely unavoidable two-pass step: each host needs a URL the other has not
issued yet.

| Key | Service | Value now |
|---|---|---|
| `CORS_ORIGINS` | sih-backend | `["http://localhost:5173"]` |
| `ANALYST_BACKEND_URL` | sih-analyst | leave blank, set in [§5](#5-step-3--join-the-two-services) |
| `ANALYST_CORS_ORIGINS` | sih-analyst | `["http://localhost:5173"]` |
| `ANALYST_GEMINI_API_KEY` | sih-analyst | your key, or blank |

> **Both CORS values are parsed as JSON**, because the underlying setting is a
> `list[str]`. `["https://foo.vercel.app"]` — brackets and double quotes, always.
> A bare `https://foo.vercel.app` raises during settings construction, which
> happens at import, so the service does not start at all. The logs show a
> pydantic validation error, not a CORS error, which is a confusing place to
> land from a value that looks obviously correct.

Leaving `ANALYST_GEMINI_API_KEY` blank is a **supported configuration, not a
degraded one**: the analyst falls back to its deterministic template provider,
answers from the same evidence with the same grounding rules, and opens no
outbound connection at all. `/api/v1/analyst/health` reports which provider is
live, so this is visible rather than assumed.

First build takes a few minutes. `pip install` on the free tier is not fast.

---

## 5. Step 3 — Join the two services

The build gives each service a URL. Copy the backend's, then on **sih-analyst →
Environment**:

```
ANALYST_BACKEND_URL = https://sih-backend.onrender.com
```

**No trailing slash, and no `/api/v1`.** The analyst appends its own paths; a
trailing slash produces `//api/v1/...` and a 404 on every retrieval, which
surfaces as the analyst answering "no evidence" rather than as a connection
error. Save — Render redeploys.

The analyst reaches the backend over the **public URL**, not an internal
hostname. That is deliberate: it consumes exactly the read-only REST API the
dashboard consumes, which is what keeps "the analyst reads only from the alert
store" checkable rather than asserted.

Verify both services before touching Vercel. The analyst's own readout answers
the only question that matters here — `alert_store_reachable`:

```bash
curl https://sih-analyst.onrender.com/api/v1/analyst/health
```

```bash
curl https://sih-backend.onrender.com/health
```

If the first call takes a minute, that is the cold start, not a fault.

---

## 6. Step 4 — Deploy the frontend to Vercel

Vercel → **Add New** → **Project** → import the repo. Vercel detects Vite; the
only thing it cannot infer is that the app lives in a subdirectory.

| Setting | Value |
|---|---|
| Framework Preset | Vite |
| **Root Directory** | **`frontend`** |
| Build Command | `npm run build` |
| Output Directory | `dist` |

Then add three **Environment Variables**, substituting your own Render URLs:

```
VITE_API_BASE     = https://sih-backend.onrender.com/api/v1
VITE_WS_URL       = wss://sih-backend.onrender.com/ws/alerts
VITE_ANALYST_BASE = https://sih-analyst.onrender.com/api/v1/analyst
```

These are read by Vite **at build time** and compiled into the bundle. Changing
one later requires a redeploy, not just a save — editing the value and reloading
the page does nothing, because the old value is already inside the JavaScript.

Three details fail silently if you get them wrong, so they are worth checking
once now rather than debugging later:

- **`VITE_API_BASE` ends at `/api/v1`.** The client appends `/alerts`, `/hosts`,
  `/system/health` and the rest. An extra trailing segment or slash produces 404s
  on every panel while the socket keeps working — a confusing half-alive state.
- **`VITE_WS_URL` is the entire URL, including `/ws/alerts`, and the scheme is
  `wss:`.** A page served over HTTPS cannot open a `ws:` socket. The browser
  blocks it as mixed content and the server never sees a connection attempt, so
  there is nothing in the Render logs to find.
- **`VITE_ANALYST_BASE` includes `/api/v1/analyst`**, because that is the
  router's prefix *inside* the analyst service. Its host also differs from the
  backend's — this is the variable most often pointed at the wrong service.

**No `vercel.json` is needed.** The dashboard navigates in component state rather
than by URL, so there are no client-side routes to rewrite and no SPA fallback to
configure. And per Fact 3, do not add rewrite rules for `/api` or `/ws`.

---

## 7. Step 5 — Close the CORS loop

Deploying gives you the real Vercel URL. Return to Render and replace both
placeholders with it, as JSON lists:

```
sih-backend  →  CORS_ORIGINS         = ["https://your-app.vercel.app"]
sih-analyst  →  ANALYST_CORS_ORIGINS = ["https://your-app.vercel.app"]
```

Use the **production** domain, with no trailing slash and no path.

> Vercel issues a **fresh preview URL for every commit**, and each is a different
> origin. A preview deploy will therefore fail CORS against this list even though
> production works perfectly. Demo on the production domain, or add the specific
> preview origin when you need one.

Both services redeploy on save. Then [§8](#8-step-6--verify).

---

## 8. Step 6 — Verify

Open the Vercel URL and check these in order. The order matters: each one isolates
a different seam, so the first failure tells you where to look.

1. **The instrument bar shows connected.** That is the WebSocket, reaching Render
   directly. If it never connects, the browser console names the cause — mixed
   content (`ws:` where `wss:` belongs) or a bad host in `VITE_WS_URL`. Nothing
   appears in the Render logs for either.
2. **System view populates.** That is REST plus CORS. A failure here with a
   working socket means `CORS_ORIGINS` — sockets do not do preflight, which is
   why these two can disagree.
3. **Replay → start `demo_scenario.jsonl`.** Alerts stream in. The fixtures are
   committed, so this needs nothing else deployed
   ([§9](#9-step-7--getting-data-in)).
4. **Click an alert → Explain.** That is the analyst. "Analyst unavailable" here
   while everything above works is `ANALYST_CORS_ORIGINS` or `VITE_ANALYST_BASE`,
   and proves nothing upstream is wrong — which is the point of the layer being
   optional by construction.

From the command line, the same seams:

```bash
curl https://sih-backend.onrender.com/api/v1/system/health
```

```bash
npx wscat -c wss://sih-backend.onrender.com/ws/alerts
```

`wscat` should print a `snapshot` frame immediately, then `metrics` every second.
If `curl` works and `wscat` does not, the problem is the socket path specifically
— which on this setup means the URL, since nothing is proxying it.

---

## 9. Step 7 — Getting data in

Ingestion needs a network tap and detection needs feature JSONL. Neither belongs
on Render. Two ways to make the deployed dashboard show real alerts.

### Option A — Replay (nothing else required; use this for judging)

`backend/fixtures/*.jsonl` is committed, so it deploys with the repo. The backend
replays it through the full fusion and WebSocket path — a genuine end-to-end
exercise of everything above the detection layer, not a canned animation.

```bash
curl https://sih-backend.onrender.com/api/v1/replay/captures
```

```bash
curl -X POST https://sih-backend.onrender.com/api/v1/replay/start -H 'Content-Type: application/json' -d '{"capture":"demo_scenario","speed":1.0,"loop":true}'
```

Captures: `demo_scenario` (the narrative run), `beacon_hour` (slow C2 beaconing —
sixty check-ins that must dedup to one alert with `occurrences=60`), `flood`
(throughput stress; pair with `"max_rate": 400`). Stop with
`POST /api/v1/replay/stop`. The Replay view drives all of this without curl.

A **looping** replay is also the simplest defence against the idle sleep — see
[§10](#10-the-cold-start-and-demo-day).

### Option B — Live detection from your machine

Run ingestion and detection locally, POST to Render:

```bash
python -m detection_core.runner data/features.jsonl --api-url https://sih-backend.onrender.com/api/v1/alerts --telemetry-url https://sih-backend.onrender.com/api/v1/telemetry --ja3-feed tools/ja3_feed.example.txt --output data/alerts.jsonl
```

Or stream straight from Zeek with no file in between:

```bash
python -m ingestion.pipeline ... -o - | python -m detection_core.runner - --api-url https://sih-backend.onrender.com/api/v1/alerts
```

`data/features.jsonl` is gitignored and regenerated deterministically:

```bash
python tools/synth_flows.py -o data/features.jsonl
```

> This opens a real trust boundary: `POST /api/v1/alerts` is unauthenticated, and
> a Render URL is public and guessable. Anyone who finds it can inject alerts
> into your dashboard. Acceptable for a hackathon; see
> [§12](#12-environment-variable-reference) and
> [§13](#13-hardening-before-anything-real) if not.

---

## 10. The cold start, and demo day

A free Render service **sleeps after 15 minutes with no traffic**. The next
request wakes it in 50–60 s. During that window the dashboard shows a
disconnected socket and an empty ledger, which to anyone watching is
indistinguishable from a system that does not work.

Both free services also draw from a single **750 instance-hour/month** pool. Two
services awake around the clock would exceed it; sleeping ones do not come close.
The sleep is what keeps this free, so the answer is to schedule around it rather
than defeat it.

**Open the dashboard five minutes before you present and start a looping
replay.** That wakes both services — the analyst too, via its health check — and
fills the ledger, and the ongoing traffic keeps them awake for as long as the
page is open. It costs nothing and removes the only failure mode of this setup
that is purely about timing.

If you would rather not think about it:

- A cron ping (`cron-job.org`, GitHub Actions, anything) hitting `/health` every
  10 minutes keeps the backend awake permanently. Hit the analyst too if you want
  it warm — they sleep independently.
- Render's Starter tier ($7/mo per service) removes the sleep entirely.

Rehearse the local `run_demo.py` fallback regardless. A laptop that works is
worth more than an explanation of why the internet does not.

---

## 11. Persistence (optional)

`render.yaml` sets `STORAGE_BACKEND=memory`, the zero-config default: nothing to
provision, every screen works, and **history is lost on every sleep and every
redeploy**. For a judged demo driven by replay this is usually the right trade —
the data is regenerated in seconds.

To keep history, point the backend at any Postgres. Supabase's free tier is the
path of least resistance:

```
STORAGE_BACKEND = postgres
DATABASE_URL    = postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:6543/postgres
```

Use the **pooler** URI (port 6543), not the direct one (5432). Take it from
Supabase → Project Settings → Database → Connection string → URI. Render's own
free Postgres works too, but it expires after 30 days, which is a worse surprise
than no persistence at all.

> A wrong or unreachable DSN does **not** crash the backend — it logs an error
> and **falls back to memory**, because a bad database on demo day should cost
> durability, not the demo. That fallback is quiet unless you look: the System
> view reports which backend is actually in use. Check it after switching, rather
> than assuming the change took.

Migrations live in `backend/db/`. Run them against the new database before
switching `STORAGE_BACKEND`; `schema.sql` is `CREATE IF NOT EXISTS` throughout
and cannot apply the later migrations on its own.

---

## 12. Environment variable reference

Fully annotated lists live in `backend/.env.example`, `backend/app/config.py` and
`analyst/analyst/config.py`. These are the ones this deployment sets.

### Frontend (Vercel, **build-time**)

| Variable | Set to | Notes |
|---|---|---|
| `VITE_API_BASE` | `https://sih-backend.onrender.com/api/v1` | Ends at `/api/v1`. Unset ⇒ same-origin, which 404s on Vercel. |
| `VITE_WS_URL` | `wss://sih-backend.onrender.com/ws/alerts` | Whole URL. Must be `wss:`, not `ws:`. |
| `VITE_ANALYST_BASE` | `https://sih-analyst.onrender.com/api/v1/analyst` | Different host from the other two. Includes the router prefix. |

### Backend (`backend/app/config.py`, **no prefix**)

| Variable | Set to | Notes |
|---|---|---|
| `CORS_ORIGINS` | `["https://your-app.vercel.app"]` | **JSON list.** Load-bearing here — the browser is on another origin. |
| `STORAGE_BACKEND` | `memory` | `postgres` needs `DATABASE_URL` — [§11](#11-persistence-optional). |
| `DATABASE_URL` | Supabase pooler URI | Absent or wrong ⇒ **quiet** fallback to memory, logged as an error. |
| `LOG_LEVEL` | `INFO` | |
| `PORT` | set by Render | Do not set it yourself. |
| `DEDUP_WINDOW_S` / `CORRELATION_WINDOW_S` | `300` / `1800` | Fusion windows. Fine as-is. |

### Analyst (`analyst/analyst/config.py`, **`ANALYST_` prefix on every key**)

| Variable | Set to | Notes |
|---|---|---|
| `ANALYST_BACKEND_URL` | `https://sih-backend.onrender.com` | The public URL. No trailing slash, no `/api/v1`. |
| `ANALYST_CORS_ORIGINS` | `["https://your-app.vercel.app"]` | **JSON list.** Separate from the backend's. |
| `ANALYST_GEMINI_API_KEY` | your key | Omit ⇒ template provider, no egress. Both are valid. |
| `ANALYST_GEMINI_MODEL` | `gemini-2.5-flash-lite` | Reported by `/health`, so a wrong id is visible immediately. |

> Both list-typed settings are parsed as **JSON**: `["https://a","https://b"]`.
> A comma-separated string crashes the service at startup.

---

## 13. Hardening before anything real

Deliberately out of scope for a hackathon deploy; listed so each gap is a
decision rather than an oversight.

- `POST /api/v1/alerts` and `POST /api/v1/telemetry` are unauthenticated, on a public URL. Add a shared-secret header check in `backend/app/api/alerts.py` if that matters.
- `/api/v1/replay/*` lets any caller start and stop replays on your deployment.
- No rate limiting anywhere. Render's free tier has no WAF in front of it.
- `DATABASE_URL` sits in Render's environment. That is the right place for it, but anyone with dashboard access can read it.
- CORS restricts *browsers*, not `curl`. It is not an access control, and nothing above is protected by getting it right.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Everything is slow or dead for ~60 s, then fine | Free-tier cold start | Expected — [§10](#10-the-cold-start-and-demo-day). Not a fault. |
| Service never starts; logs show a pydantic validation error | `CORS_ORIGINS` set to a bare string | It is parsed as JSON. `["https://your-app.vercel.app"]`, with brackets and quotes. |
| Render marks the service unhealthy and restarts it | Not bound to `$PORT`, or health check pointed at `/api/v1/system/health` | `startCommand` must use `--host 0.0.0.0 --port $PORT`; health check is `/health`. |
| Dashboard loads, every panel empty, socket disconnected | `VITE_WS_URL` wrong, or `ws:` instead of `wss:` | Browser console names it. Mixed content leaves **no** trace in Render's logs. |
| Socket connects, but panels 404 | `VITE_API_BASE` wrong | It ends at `/api/v1`, with no trailing slash. |
| Panels blocked by CORS, socket fine | `CORS_ORIGINS` does not match the origin | Sockets do not preflight, so these fail independently. Match the exact origin, no trailing slash. |
| Works on production, CORS fails on a preview deploy | Every Vercel preview is a distinct origin | Use production, or add that preview origin — [§7](#7-step-5--close-the-cors-loop). |
| Changed a `VITE_*` value, nothing happened | They are compiled into the bundle at build time | Redeploy on Vercel. Saving the variable is not enough. |
| "Analyst unavailable" while everything else works | `ANALYST_CORS_ORIGINS`, or `VITE_ANALYST_BASE` pointing at the backend | Layer 8 is independent by design; nothing upstream is implicated. |
| Analyst answers, badged not-generated | No Gemini key ⇒ template provider | Set `ANALYST_GEMINI_API_KEY`; confirm via `/api/v1/analyst/health`. |
| Analyst returns "no evidence" for everything | `ANALYST_BACKEND_URL` has a trailing slash or `/api/v1` | Bare origin only. Check `alert_store_reachable` on its `/health`. |
| System view says storage is `memory` after setting `DATABASE_URL` | Bad DSN — the backend fell back rather than crashing | Render logs show the connect error. Use the **pooler** URI, port 6543. |
| History vanishes every so often | `STORAGE_BACKEND=memory` plus the idle sleep | Expected — [§11](#11-persistence-optional). |
| Duplicate alerts, or incidents fragmenting | More than one instance | Fact 2. Scale back to one; do not add workers. |
| Only six detectors register | No trained DGA model — affects the local runner, not this deployment | `python -m detection_core.ml.dga.training -i detection_core/ml/dga/data/dga_dataset.sample.csv -o ../artifacts/dga_model.joblib` |

---

## Deployment checklist

**Render**

- [ ] `render.yaml` committed and pushed to the deployed branch
- [ ] Blueprint created; **sih-backend** and **sih-analyst** both building
- [ ] `ANALYST_BACKEND_URL` set to the backend's public URL — no trailing slash, no `/api/v1`
- [ ] `curl .../health` answers on both services
- [ ] `/api/v1/analyst/health` reports `alert_store_reachable: true`
- [ ] Decided on `ANALYST_GEMINI_API_KEY` — set, or deliberately blank

**Vercel**

- [ ] **Root Directory set to `frontend`** — the one setting Vercel cannot infer
- [ ] All three `VITE_*` variables set, and the deploy run *after* setting them
- [ ] `VITE_WS_URL` uses `wss:` and includes `/ws/alerts`
- [ ] `VITE_ANALYST_BASE` points at the **analyst** host, not the backend
- [ ] No `vercel.json`, no rewrite rules for `/api` or `/ws`

**Joining them**

- [ ] `CORS_ORIGINS` and `ANALYST_CORS_ORIGINS` both hold the production Vercel origin
- [ ] Both are **JSON lists**, with brackets and double quotes
- [ ] Both services redeployed after that change

**Verification**

- [ ] Instrument bar shows connected — the WebSocket
- [ ] System view populates — REST plus CORS
- [ ] `wscat` receives a `snapshot` frame, then `metrics` every second
- [ ] Replay starts and the dashboard animates
- [ ] Explain returns an answer, or the panel says unavailable *without* affecting anything else

**Demo day**

- [ ] Cold start understood; services woken ~5 minutes before presenting
- [ ] Looping replay rehearsed as the warm-up
- [ ] Local `run_demo.py` fallback rehearsed
- [ ] Presenting on the **production** domain, not a preview URL
