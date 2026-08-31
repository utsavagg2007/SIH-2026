# Deployment

Deploying this project to Oracle Cloud's Always Free tier: a permanent **$0**
host, in **Mumbai**, with no cold start and no sleep.

Read [§1](#1-what-actually-deploys) first — it decides what you host and what you
do not. Then work through [§3](#3-step-1--the-oracle-account) onward in order;
step 1 contains an **irreversible** choice.

> **Start the account and VM steps at least a week before your deadline.** Not
> because they take long — because ARM capacity in popular regions is frequently
> unavailable and you may have to retry over a few days. Everything else here is
> an afternoon. See [§4c](#4c-when-it-says-out-of-capacity).

---

## 1. What actually deploys

Five directories, three different deployment stories.

| Layer | What it is | Deploys as |
|---|---|---|
| `frontend/` | Vite + React, **relative URLs only** (`/api/v1`, `/ws/alerts`) | **Not its own host.** Built into `frontend/dist/` and served by the backend. |
| `backend/` | FastAPI, WebSocket hub, in-memory fusion, Postgres write-behind | **One always-on container.** Serves the API, the WS feed, *and* the dashboard. |
| `analyst/` | FastAPI on `:8100`, calls the backend's REST API + Gemini | A second container. Optional — the dashboard degrades gracefully without it. |
| `detection/` | CLI: `python -m detection_core.runner` — reads feature JSONL, POSTs alerts | **A worker you run, not a service you host.** Runs anywhere with network access to the backend. |
| `ingestion/` | Rust/PyO3 parser + Zeek in Docker, reads PCAP | **Never deploys.** It runs on the machine watching the traffic. |

### The two facts that decide the architecture

**Fact 1 — the frontend is already served by the backend.**
`backend/app/main.py::_mount_dashboard` mounts `frontend/dist` at `/`. The
frontend's `useFeed.ts` hardcodes `WS_PATH = "/ws/alerts"` and `lib/api.ts`
hardcodes `const BASE = "/api/v1"` — both relative, both same-origin. Ship the
backend with `dist` inside it and routing is solved for free: no CORS, no
`VITE_API_BASE`, no code change.

**Fact 2 — the backend is stateful and must be a single instance.**
`AlertBus`, `ConnectionHub` (WebSocket fan-out), the 300 s dedup window and the
1800 s correlation window all live in process memory. Two instances means dedup
splits (duplicate alerts on screen), correlation splits (incidents fragment), and
a browser connected to instance A never receives an alert POSTed to instance B.

On a single VM this is free — there is only one of everything. It is the reason
serverless hosts were rejected, and one less thing to get wrong here.

### Why not Firebase, Vercel, or anything serverless

Your original plan was Firebase for the backend, detection, ingestion and
analyst. It cannot work:

1. **Firebase Hosting is a static CDN.** It can host `frontend/dist` and nothing else.
2. **Firebase Hosting rewrites do not proxy WebSockets.** `/ws/alerts` is the live feed — it *is* the product. A rewrite to Cloud Run passes HTTP but drops the `Upgrade` handshake. Vercel rewrites have the same limitation.
3. **Cloud Functions do not hold long-lived connections.** No WS hub, no 1-second metrics frames.
4. **Autoscaling breaks the fusion layer**, per Fact 2.

A single VM running Docker has none of these problems, costs nothing on Always
Free, and puts the whole stack behind one origin.

---

## 2. What you are building

```
                        Oracle Cloud VM  (ap-mumbai-1, Always Free)
        ┌───────────────────────────────────────────────────────────┐
        │                                                           │
 :443 ──┤  caddy       TLS + one origin                             │
 :80    │    │  /api/v1/analyst/*  ──▶ analyst:8100                 │
        │    │  everything else    ──▶ backend:8000                 │
        │    │                                                      │
        │    ├──▶ backend    /  → frontend/dist  (the dashboard)    │
        │    │               /api/v1/*, /ws/alerts                  │
        │    │                   │                                  │
        │    │                   ▼                                  │
        │    │               postgres   (container, local volume)   │
        │    │                                                      │
        │    └──▶ analyst   ──HTTPS──▶ Google Gemini (free key)     │
        └───────────────────────────────────────────────────────────┘

  ingestion/ + Zeek ──features.jsonl──▶ detection/ runner
  detection/ runner ──POST /api/v1/alerts──▶ the VM
      (both run from your laptop — or skip them and use replay, §11)
```

**Everything is on one box behind one origin.** That is what makes this simpler
than the PaaS options, not just cheaper:

- Caddy puts the analyst at `/api/v1/analyst/*` on the **same origin**, so the frontend's default relative URL is correct. **`VITE_ANALYST_BASE` is not needed at all**, and neither is CORS on either service.
- Postgres is a container on the same box: no connection pooler, no external account, no free-project pausing, sub-millisecond writes.

**Cost: $0/month, permanently.** Not a trial, not credits.

**New files: 6.** `Dockerfile`, `analyst/Dockerfile`, `.dockerignore`,
`docker-compose.yml`, `Caddyfile`, `.env`. Zero application code changes.

### What Always Free actually costs you

Honest ledger, so nothing is a surprise:

| | |
|---|---|
| A credit card at signup | Required for identity verification. Not charged on Always Free shapes. |
| Home region is permanent | Chosen at signup, **cannot be changed**. Get this right — [§3](#3-step-1--the-oracle-account). |
| ARM capacity | Often "Out of Capacity". Retrying over days is normal. Fallback in [§4c](#4c-when-it-says-out-of-capacity). |
| Idle reclaim | Oracle may reclaim instances under 20% CPU (95th pct) over 7 days. Mitigations in [§13](#13-keeping-it-alive). |
| You own uptime | No managed health checks. `restart: unless-stopped` and a boot-enabled Docker cover most of it. |

---

## 3. Step 1 — The Oracle account

### 3a. Sign up

Go to [oracle.com/cloud/free](https://www.oracle.com/cloud/free/) → **Start for
free**. You will need a card for identity verification; Always Free shapes are
not billed against it.

### 3b. Choose the home region — this is permanent

> **Read this before clicking.** Always Free compute can be provisioned **only in
> your tenancy's home region**, and the home region **cannot be changed after
> the account is created**. Pick wrong and your only remedy is a new account.

For an India-based team, pick one of:

- **`ap-mumbai-1`** — Asia Pacific (Mumbai) ← recommended
- **`ap-hyderabad-1`** — India Southeast (Hyderabad)

Mumbai is usually the lower-latency of the two from most of India, but Hyderabad
sometimes has **better ARM capacity** precisely because it is less popular. If
you hit repeated capacity failures in Mumbai and have not yet created the
account, Hyderabad is a reasonable hedge.

This choice matters for more than feel: the System view reports p50/p95 latency
measured from `detected_at` to receipt. If you run the detection runner from your
laptop ([§11 Option B](#option-b--live-detection-from-your-machine)), the round
trip to the VM lands inside the number you are graded on.

### 3c. Generate an SSH key

On your machine, before creating the instance:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/oracle_sih -C "sih-deploy"
```

Leave the passphrase empty if you want unattended `scp`. You will paste
`~/.ssh/oracle_sih.pub` into the instance creation form.

---

## 4. Step 2 — Provision the VM

### 4a. Create the instance

Console → **Compute → Instances → Create instance**.

| Field | Value |
|---|---|
| Name | `sih-demo` |
| Image | **Canonical Ubuntu 22.04** (Change image → Canonical Ubuntu) |
| Shape | **Ampere → `VM.Standard.A1.Flex`** |
| OCPUs | **2** |
| Memory | **12 GB** |
| Primary VNIC → Assign public IPv4 | **Yes** |
| SSH keys | Paste the contents of `~/.ssh/oracle_sih.pub` |
| Boot volume | 50 GB is plenty (Always Free allows 200 GB total) |

2 OCPU / 12 GB is the full Always Free Ampere allocation as of June 2026, when
Oracle halved it from 4 OCPU / 24 GB. Anything at or below that is free; above it
bills.

Note the **public IP address** once it provisions.

### 4b. Confirm SSH works

```bash
ssh -i ~/.ssh/oracle_sih ubuntu@<PUBLIC_IP>
```

The user is `ubuntu` on Canonical images, `opc` on Oracle Linux.

### 4c. When it says "Out of Capacity"

`Out of host capacity` on A1.Flex is common, not a mistake on your part. In
order of what to try:

1. **Ask for less.** 1 OCPU / 6 GB is often available when 2 / 12 is not. You can raise it later when capacity frees up, and this app runs fine on it.
2. **Retry on a schedule.** Capacity is released continuously. Try every few hours, including off-peak hours for the region.
3. **Upgrade to Pay As You Go.** Counter-intuitive but effective: PAYG accounts get capacity priority, and **you are still charged nothing** as long as you stay within Always Free limits. It also exempts you from idle reclaim ([§13](#13-keeping-it-alive)). The risk is real though — exceed the limits and you *will* be billed, so set a budget alert at $1 immediately after upgrading.
4. **Fall back to the AMD shape.** `VM.Standard.E2.1.Micro` is Always Free and essentially always available: 1 OCPU, **1 GB RAM**, and you get two of them.

**On the 1 GB micro shape**, two adjustments are mandatory:

- **Add swap** ([§5b](#5b-add-swap)) or the `npm run build` stage will be OOM-killed mid-build.
- Set `MEMORY_ALERT_CAPACITY=2000` in `.env`. The 20 000 default will not fit.

Everything else in this document works unchanged.

---

## 5. Step 3 — Prepare the VM

SSH in. All of the following runs on the VM.

### 5a. Install Docker and git

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-v2 git
```

```bash
sudo usermod -aG docker $USER && sudo systemctl enable --now docker
```

Log out and back in for the group change to take effect, then confirm:

```bash
docker run --rm hello-world
```

### 5b. Add swap

Oracle images ship without swap. On the 1 GB micro shape this is required; on
the 12 GB ARM shape it is cheap insurance against a build spike.

```bash
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
```

```bash
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

### 5c. Open the ports — **both** firewalls

This is the step that costs people an afternoon. Oracle has **two independent
firewalls** and traffic must pass both. Opening one and not the other produces a
connection that hangs with no error anywhere.

**Firewall 1 — the VCN Security List** (in the web console):

Console → **Networking → Virtual Cloud Networks** → your VCN → **Security Lists**
→ *Default Security List* → **Add Ingress Rules**. Add two:

| Source CIDR | IP Protocol | Destination Port |
|---|---|---|
| `0.0.0.0/0` | TCP | `80` |
| `0.0.0.0/0` | TCP | `443` |

Leave *Stateless* unchecked.

**Firewall 2 — `iptables` on the instance itself.** Oracle's Ubuntu images ship
with a restrictive `INPUT` chain ending in a REJECT rule, so new rules must be
*inserted above* it, not appended:

```bash
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
```

```bash
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
```

```bash
sudo netfilter-persistent save
```

Verify both rules sit above the REJECT line:

```bash
sudo iptables -L INPUT -n --line-numbers
```

### 5d. Get the code onto the VM

```bash
git clone <your-repo-url> sih && cd sih
```

If the repo is private and you would rather not deal with credentials on the VM,
copy from your laptop instead:

```bash
scp -i ~/.ssh/oracle_sih -r ./SIH-project ubuntu@<PUBLIC_IP>:~/sih
```

---

## 6. Step 4 — Build files

Create these in the repository, on the VM (or commit them and pull).

### 6a. `Dockerfile` — backend with the dashboard baked in

```dockerfile
# ---- stage 1: build the dashboard -----------------------------------------
FROM node:20-slim AS dashboard
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# Deliberately NOT setting VITE_ANALYST_BASE. Caddy serves the analyst at
# /api/v1/analyst on this same origin, which is exactly what lib/api.ts
# defaults to. Setting it here would only break that.
RUN npm run build

# ---- stage 2: the service --------------------------------------------------
FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
# _mount_dashboard() resolves dist as <repo>/frontend/dist, i.e. one level
# above backend/. Keep this destination path exactly as-is.
COPY --from=dashboard /app/frontend/dist ./frontend/dist
WORKDIR /app/backend
# One worker, on purpose — see Fact 2.
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
```

### 6b. `analyst/Dockerfile`

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY analyst/pyproject.toml ./
COPY analyst/analyst/ ./analyst/
RUN pip install --no-cache-dir .
CMD ["python", "-m", "uvicorn", "analyst.main:app", "--host", "0.0.0.0", "--port", "8100"]
```

The `analyst/` path prefixes are correct because the build context is the repo
root — `docker-compose.yml` sets that explicitly.

### 6c. `.dockerignore` — not optional

`COPY` does **not** respect `.gitignore`. Without this file, two things go wrong,
one of them a genuine leak:

- **`backend/.env` gets baked into the image.** It is gitignored, so it feels safe, but Docker copies it anyway — along with whatever real credentials are in it.
- **`frontend/node_modules` gets copied over the `npm ci` result.** The dashboard stage runs `npm ci` and then `COPY frontend/ ./`, which overwrites the freshly installed tree with your host's — including any Windows-built native binaries, which will not run in the Linux image.

It also cuts the build context from hundreds of megabytes to a few, which on a
free-tier VM is the difference between a two-minute build and a twenty-minute one.

Create **`.dockerignore`** in the repository root:

```
# Secrets — gitignored, but COPY does not care
**/.env
**/.env.local

# Reinstalled inside the image; the host copy is the wrong platform
**/node_modules
**/dist
**/*.tsbuildinfo

# Python build artifacts and local venvs
**/__pycache__
**/*.py[cod]
.venv/
venv/
**/*.egg-info
**/.pytest_cache
**/.mypy_cache
**/.ruff_cache

# Rust — ingestion does not deploy
target/
**/*.so
**/*.pyd

# Generated data; the backend needs none of it (fixtures/ is separate and IS needed)
data/
artifacts/
zeek_output/
**/*.pcap

# Repo noise
.git/
SIH-2026-*/
*.zip
*.pdf
```

Note `fixtures/` is deliberately **not** excluded — `backend/fixtures/*.jsonl` is
what makes replay work on the deployed box ([§11](#11-step-9--getting-data-in)).

> **If you already built before adding this**, the old image still contains your
> `.env`. Rebuild without cache: `docker compose build --no-cache`.

---

## 7. Step 5 — Caddy, one origin, free TLS

Create **`Caddyfile`** in the repository root:

```
{$SITE_ADDRESS} {
	# The analyst rule must come first. Caddy matches in order, and the
	# catch-all below would otherwise hand /api/v1/analyst/* to the backend,
	# which does not serve those routes — the panel would report a healthy
	# service as broken. Same ordering trap as the Vite dev proxy.
	reverse_proxy /api/v1/analyst/* analyst:8100
	reverse_proxy backend:8000
}
```

`reverse_proxy` handles the WebSocket upgrade on `/ws/alerts` transparently —
this is the thing Firebase Hosting and Vercel cannot do, and it needs no
configuration in Caddy.

### 7a. Pick your address

**Fast path — plain HTTP on the IP.** No DNS, works immediately:

```
SITE_ADDRESS=:80
```

The dashboard is then `http://<PUBLIC_IP>`. The frontend derives its WebSocket
scheme from `location.protocol`, so `http:` → `ws:` and everything works. Judges
will see a browser "Not secure" label.

**Polished path — a free subdomain with automatic HTTPS.** Register a name at
[duckdns.org](https://www.duckdns.org) (sign in, pick a subdomain, point it at
your public IP), then:

```
SITE_ADDRESS=sih-demo.duckdns.org
```

Caddy obtains and renews a Let's Encrypt certificate on first start, with no
further configuration. Give DNS a few minutes to propagate before starting the
stack, or the first certificate attempt fails and Caddy backs off.

Do the polished path if you have ten minutes. `https://sih-demo.duckdns.org`
presents considerably better than a bare IP with a security warning.

---

## 8. Step 6 — Compose the stack

Create **`docker-compose.yml`** in the repository root:

```yaml
services:
  db:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD:?set DB_PASSWORD in .env}
      POSTGRES_DB: sih
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d sih"]
      interval: 5s
      timeout: 3s
      retries: 12

  # One-shot. tools/migrate.py records applied versions in schema_migrations,
  # so re-running on every `up` is safe and is how 0002/0003 land on an
  # existing database. Do NOT paste db/schema.sql instead — it is
  # CREATE IF NOT EXISTS throughout and cannot apply those two.
  migrate:
    build: .
    command: python tools/migrate.py
    environment:
      DATABASE_URL: postgresql://postgres:${DB_PASSWORD}@db:5432/sih
    depends_on:
      db:
        condition: service_healthy
    restart: "no"

  backend:
    build: .
    restart: unless-stopped
    environment:
      STORAGE_BACKEND: postgres
      DATABASE_URL: postgresql://postgres:${DB_PASSWORD}@db:5432/sih
      LOG_LEVEL: INFO
      MEMORY_ALERT_CAPACITY: ${MEMORY_ALERT_CAPACITY:-20000}
    depends_on:
      migrate:
        condition: service_completed_successfully

  analyst:
    build:
      context: .
      dockerfile: analyst/Dockerfile
    restart: unless-stopped
    environment:
      # Container-to-container over the compose network. Not the public URL.
      ANALYST_BACKEND_URL: http://backend:8000
      ANALYST_GEMINI_API_KEY: ${GEMINI_API_KEY:-}
    depends_on:
      - backend

  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    environment:
      SITE_ADDRESS: ${SITE_ADDRESS:-:80}
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - backend
      - analyst

volumes:
  pgdata:
  caddy_data:
  caddy_config:
```

Note what is **not** here: no `ports:` on `backend`, `analyst` or `db`. Only
Caddy is reachable from the internet; the rest are on the private compose network.
That is one origin for the browser and a smaller attack surface for free.

Create **`.env`** next to it:

```bash
cat > .env <<'EOF'
DB_PASSWORD=change-this-to-something-long
SITE_ADDRESS=:80
GEMINI_API_KEY=
MEMORY_ALERT_CAPACITY=20000
EOF
```

```bash
chmod 600 .env && echo ".env" >> .gitignore
```

Fill in `GEMINI_API_KEY` from [aistudio.google.com](https://aistudio.google.com)
if you want generated analyst narration. Leaving it empty is fine — the analyst
falls back to a deterministic template provider that needs no network and still
answers, badged as not-generated.

---

## 9. Step 7 — Build and start

```bash
docker compose up -d --build
```

First build takes 5–15 minutes (npm install and the Python wheels). On the 1 GB
micro shape, expect longer and make sure swap is on.

```bash
docker compose ps
```

All five should be present: `db` healthy, `migrate` exited `0`, and `backend`,
`analyst`, `caddy` running. A `migrate` container that exited non-zero is the
one to read first:

```bash
docker compose logs migrate
```

Confirm the migration ledger landed:

```bash
docker compose exec db psql -U postgres -d sih -c "SELECT version FROM schema_migrations ORDER BY version;"
```

You should see `0001`, `0002`, `0003`.

---

## 10. Step 8 — Verify

From your laptop, against the public address. `BE=http://<PUBLIC_IP>` or your
duckdns URL.

```bash
BE=http://<PUBLIC_IP>; curl -s $BE/health; curl -s $BE/api; curl -s $BE/api/v1/system/health; curl -s $BE/api/v1/system/constraints; curl -s $BE/api/v1/system/detectors
```

Expected in order: `{"status":"ok"}`, the service descriptor, the storage backend
actually in use, the read-only constraint proof, and per-detector state.

**The dashboard is mounted** — this must return `text/html`, not JSON:

```bash
curl -s -o /dev/null -w '%{content_type}\n' $BE/
```

**Storage is really Postgres** — the backend falls back to memory rather than
crashing on a bad DSN, so check rather than assume:

```bash
curl -s $BE/api/v1/system/health
```

**The analyst is reachable on the same origin** — this is what Caddy's ordering
rule buys, and the one most likely to be misconfigured:

```bash
curl -s $BE/api/v1/analyst/health
```

**The WebSocket** — the capability that disqualified Firebase and Vercel:

```bash
npx wscat -c ws://<PUBLIC_IP>/ws/alerts
```

Use `wss://` if you took the HTTPS path. You should receive a
`{"type":"snapshot",...}` frame immediately, then `{"type":"metrics",...}` every
second.

**Then open it in a browser.** The System view should name the storage backend,
the analyst panel should not say "unavailable", and devtools → Network → WS
should show one open connection rather than a reconnect loop.

`tools/verify_e2e.py` is the local equivalent — it starts both services and walks
the whole path. It is hardcoded to `127.0.0.1:8000` / `:8100`, so it validates a
local stack, not this deployment.

---

## 11. Step 9 — Getting data in

Ingestion needs a network tap and detection needs feature JSONL. Neither belongs
on the VM. Two ways to make the deployed dashboard show real alerts.

### Option A — Replay (nothing else required; use this for judging)

`backend/fixtures/*.jsonl` is committed and ships inside the image. The backend
replays it through the full fusion and WebSocket path — a genuine end-to-end
exercise of everything above the detection layer.

```bash
curl http://<PUBLIC_IP>/api/v1/replay/captures
```

```bash
curl -X POST http://<PUBLIC_IP>/api/v1/replay/start -H 'Content-Type: application/json' -d '{"capture":"demo_scenario","speed":1.0,"loop":true}'
```

Captures: `demo_scenario` (the narrative run), `beacon_hour` (slow C2 beaconing),
`flood` (throughput stress — pair with `"max_rate": 400`). Stop with
`POST /api/v1/replay/stop`. The Replay view in the dashboard drives all of this
without curl.

A looping replay is also the simplest defence against idle reclaim — see
[§13](#13-keeping-it-alive).

### Option B — Live detection from your machine

Run ingestion and detection locally, POST to the VM:

```bash
python -m detection_core.runner data/features.jsonl --api-url http://<PUBLIC_IP>/api/v1/alerts --telemetry-url http://<PUBLIC_IP>/api/v1/telemetry --ja3-feed tools/ja3_feed.example.txt --output data/alerts.jsonl
```

Or stream straight from Zeek with no file in between:

```bash
python -m ingestion.pipeline ... -o - | python -m detection_core.runner - --api-url http://<PUBLIC_IP>/api/v1/alerts
```

`data/features.jsonl` is gitignored and regenerated deterministically:

```bash
python tools/synth_flows.py -o data/features.jsonl
```

> This opens a real trust boundary: `POST /api/v1/alerts` is unauthenticated, so
> on a public IP anyone can inject alerts into your dashboard. Acceptable for a
> hackathon; see [§14](#14-hardening-before-anything-real) if not.

---

## 12. Environment variable reference

Fully annotated lists live in `backend/.env.example`, `backend/app/config.py` and
`analyst/analyst/config.py`. These are the ones this deployment sets.

### `.env` (read by docker compose)

| Variable | Value | Notes |
|---|---|---|
| `DB_PASSWORD` | anything long | Used by both `db` and the DSN. Compose fails loudly if unset. |
| `SITE_ADDRESS` | `:80` or `your.duckdns.org` | Plain HTTP on the IP, or a domain for automatic HTTPS. |
| `GEMINI_API_KEY` | your key, or empty | Empty ⇒ deterministic template provider, no network. |
| `MEMORY_ALERT_CAPACITY` | `20000`, or `2000` on the 1 GB shape | In-memory ring buffer size. |

### Backend (`backend/app/config.py`, no prefix)

| Variable | Set to | Notes |
|---|---|---|
| `STORAGE_BACKEND` | `postgres` | `memory` is the zero-config fallback; history dies on restart. |
| `DATABASE_URL` | `postgresql://postgres:...@db:5432/sih` | `db` is the compose service name. Absent or wrong ⇒ **silent** fallback to memory, logged as an error. |
| `LOG_LEVEL` | `INFO` | |
| `CORS_ORIGINS` | leave default | Not needed — Caddy makes everything same-origin. |
| `DEDUP_WINDOW_S` / `CORRELATION_WINDOW_S` | `300` / `1800` | Fusion windows. Fine as-is. |

### Analyst (`analyst/analyst/config.py`, **`ANALYST_` prefix on every key**)

| Variable | Set to | Notes |
|---|---|---|
| `ANALYST_BACKEND_URL` | `http://backend:8000` | Container-to-container. **Not** the public URL, and no trailing slash. |
| `ANALYST_GEMINI_API_KEY` | your key | Omit ⇒ template provider. |
| `ANALYST_GEMINI_MODEL` | `gemini-2.5-flash-lite` | Reported by `/health`, so a wrong id is visible immediately. |
| `ANALYST_CORS_ORIGINS` | leave default | Not needed — same origin, so no preflight. |

> If you ever *do* need to set a list-typed setting, pydantic-settings parses
> these as **JSON**: `["https://a","https://b"]`. A comma-separated string
> crashes the service at startup.

---

## 13. Keeping it alive

Three distinct ways this deployment can quietly die. All three are cheap to
prevent.

### 13a. Idle reclaim

Oracle deems an instance idle when its **95th-percentile CPU stays under 20% over
a 7-day window**, and may reclaim it. A dashboard nobody is looking at qualifies.

Pick one:

1. **Leave a looping replay running.** `{"loop": true}` on `demo_scenario` keeps the fusion path and WebSocket busy continuously. You want this before a demo anyway, and it is zero extra infrastructure.
2. **Upgrade to Pay As You Go.** PAYG accounts are exempt from idle reclaim and are **still billed nothing** while usage stays inside Always Free limits. Set a budget alert at $1 the moment you upgrade — exceeding the limits does bill you.

A reclaimed-and-stopped instance can usually just be restarted, provided the
shape still has capacity in your region. That proviso is the problem: capacity is
exactly what you could not rely on in the first place.

### 13b. Reboots

`restart: unless-stopped` on every service plus `systemctl enable docker` (done in
[§5a](#5a-install-docker-and-git)) brings the whole stack back after a reboot.
Verify once, deliberately, well before you need it:

```bash
sudo reboot
```

Wait a minute, then re-run the [§10](#10-step-8--verify) checks.

### 13c. Demo day

- **Check the morning of.** `docker compose ps` — all running, `migrate` exited 0.
- **Read the storage line.** `docker compose logs backend | grep storage` names the backend actually in use, so a silent Postgres fallback surfaces before a judge asks about persistence.
- **Start the looping replay** before the session so the dashboard is alive when you switch to it.
- **Keep the local stack as a fallback.** `python tools/run_demo.py` runs everything on localhost with no network dependency at all. The public URL is the "it's really deployed" proof; the local run is your insurance against venue Wi-Fi.

---

## 14. Hardening before anything real

Deliberately out of scope for a hackathon deploy; listed so each gap is a
decision rather than an oversight.

- `POST /api/v1/alerts` and `POST /api/v1/telemetry` are unauthenticated. On a public IP, anyone can inject alerts. Add a shared-secret header check in `backend/app/api/alerts.py`, or restrict those paths in the `Caddyfile` to your own IP.
- `/api/v1/replay/*` lets any caller start and stop replays on your deployment.
- Postgres has no `ports:` mapping, so it is not internet-reachable — but `DB_PASSWORD` still lives in plaintext in `.env`. `chmod 600` is the floor, not a solution.
- No rate limiting anywhere.
- SSH is open to `0.0.0.0/0` on port 22 by default. Narrow the Security List rule to your own IP range if you can.

---

## 15. If a budget appears later

Nothing here requires migrating off Oracle — but for reference, and because the
same Dockerfiles work:

- **Fly.io, `bom` (Mumbai)** — ~$3–5/mo for both services. Managed, never sleeps, no VM to babysit, no idle reclaim. Needs a `fly.toml` per service with `auto_stop_machines = "off"`, `min_machines_running = 1`, and `fly scale count 1` to satisfy Fact 2. The analyst then needs `VITE_ANALYST_BASE` at build time and CORS, because there is no shared origin.
- **Render** — free tier sleeps after 15 minutes (~50 s cold start); Starter is $7/mo, more than Fly for worse latency from India.
- **Google Cloud Run** — always-on 1 vCPU/512 MB runs ~$40–50/mo, and `asia-south1` (Mumbai) is invitation-only. Poor value for a service that must not autoscale.

Verify current rates before committing; free-tier terms move.

---

## Appendix A — Splitting the frontend onto Vercel

Only if you specifically want a Vercel URL. It requires application code changes,
which is why this is an appendix. On this Oracle setup it also throws away the
same-origin property Caddy just gave you.

**1. Absolute API base** — `frontend/src/lib/api.ts`:

```ts
const BASE = (import.meta.env?.VITE_API_BASE as string | undefined) ?? "/api/v1";
```

**2. Absolute WebSocket URL** — `frontend/src/hooks/useFeed.ts` currently has
`const WS_PATH = "/ws/alerts"` and builds a same-origin URL from it. Replace that
construction with:

```ts
const WS_URL =
  (import.meta.env?.VITE_WS_URL as string | undefined) ??
  `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws/alerts`;
```

**3. Vercel settings** — Root Directory `frontend`, framework Vite, output `dist`:

```
VITE_API_BASE     = https://sih-demo.duckdns.org/api/v1
VITE_WS_URL       = wss://sih-demo.duckdns.org/ws/alerts
VITE_ANALYST_BASE = https://sih-demo.duckdns.org/api/v1/analyst
```

**4. CORS** — the browser is now on the Vercel origin, so both services need it:

```
CORS_ORIGINS         = ["https://your-app.vercel.app"]
ANALYST_CORS_ORIGINS = ["https://your-app.vercel.app"]
```

This requires the HTTPS path in [§7a](#7a-pick-your-address) — a page served over
HTTPS cannot open a `ws://` connection or call an `http://` API.

Do **not** try a Vercel `rewrites` rule for `/ws/alerts`; it will not upgrade the
connection. The absolute `wss://` URL above is the only thing that works.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Connection just hangs, no error | Only one of the two firewalls is open | Both the VCN Security List **and** `iptables` — [§5c](#5c-open-the-ports--both-firewalls). This is the single most common failure. |
| `iptables` rule added but still blocked | Appended below the REJECT rule | Use `-I INPUT 6`, not `-A`. Check order with `sudo iptables -L INPUT -n --line-numbers`. |
| `Out of host capacity` | ARM capacity, not your mistake | [§4c](#4c-when-it-says-out-of-capacity) — ask for less, retry, PAYG, or the AMD micro shape. |
| Build killed partway through `npm ci` | OOM on a 1 GB shape | Add swap — [§5b](#5b-add-swap). |
| Build is very slow, or fails with a native-module error | No `.dockerignore`; host `node_modules` copied over the install | Add [`.dockerignore`](#6c-dockerignore--not-optional), then `docker compose build --no-cache`. |
| Backend uses the wrong database despite `.env` in compose | A stale `backend/.env` baked into the image | Env vars from compose take precedence, so this is rare — but rebuild with `.dockerignore` in place to be sure the file is not in the image at all. |
| Root URL returns JSON, not the dashboard | `frontend/dist` missing from the image | The `COPY --from=dashboard` destination must land at `/app/frontend/dist`, a sibling of `backend/`. |
| Dashboard loads, all panels empty | WebSocket not connecting | `npx wscat -c ws://<IP>/ws/alerts`. If curl works and this does not, something in front is not proxying the upgrade. |
| System view says storage is `memory` | Bad DSN — the backend fell back rather than crashing | `docker compose logs backend` for the connect error. Check `DB_PASSWORD` matches in both places and the host is `db`, not `localhost`. |
| `migrate` container exits non-zero | DB not ready, or a bad DSN | `docker compose logs migrate`. The `service_healthy` condition should prevent the first; re-run with `docker compose up migrate`. |
| `0002`/`0003` missing from `schema_migrations` | Someone pasted `db/schema.sql` instead of running the migrator | `schema.sql` is `CREATE IF NOT EXISTS` throughout and cannot apply those. Run `docker compose run --rm migrate`. |
| "Analyst unavailable" in the panel | Caddy rule order | `/api/v1/analyst/*` must be the **first** `reverse_proxy` in the `Caddyfile`. Otherwise the catch-all sends it to the backend, which 404s. |
| Analyst answers, badged not-generated | No Gemini key ⇒ template provider | Set `GEMINI_API_KEY` in `.env`, `docker compose up -d analyst`, check `/api/v1/analyst/health` reports `provider: gemini`. |
| Analyst 500s on every question | `ANALYST_BACKEND_URL` wrong | Must be `http://backend:8000` — the compose service name, not the public URL. |
| HTTPS certificate never issues | DNS not propagated, or port 80 closed | Let's Encrypt validates over port 80. Confirm both firewalls, then `docker compose logs caddy`. |
| Everything vanished after a week | Idle reclaim | [§13a](#13a-idle-reclaim). Restart the instance, then leave a looping replay running. |
| Backend restarts under a flood replay | RAM vs `MEMORY_ALERT_CAPACITY` | Lower it in `.env`; `docker compose logs backend` shows the OOM. |
| Only six detectors register | No trained DGA model — affects the local runner, not this deployment | `python -m detection_core.ml.dga.training -i detection_core/ml/dga/data/dga_dataset.sample.csv -o ../artifacts/dga_model.joblib` |

---

## Deployment checklist

**Account and VM**

- [ ] Oracle account created with home region `ap-mumbai-1` or `ap-hyderabad-1` — **irreversible**
- [ ] SSH keypair generated; public key pasted at instance creation
- [ ] Instance running: `VM.Standard.A1.Flex`, 2 OCPU / 12 GB (or a documented fallback)
- [ ] Public IPv4 assigned and noted
- [ ] `ssh ubuntu@<IP>` works

**VM preparation**

- [ ] Docker installed, `systemctl enable docker` done, `docker run hello-world` passes
- [ ] Swap added (**mandatory** on the 1 GB shape)
- [ ] VCN Security List: ingress `0.0.0.0/0` TCP 80 and 443
- [ ] `iptables` rules **inserted above** the REJECT line, `netfilter-persistent save` run
- [ ] Repo on the VM

**Configuration**

- [ ] `Dockerfile`, `analyst/Dockerfile`, `docker-compose.yml`, `Caddyfile` created
- [ ] **`.dockerignore` created** — otherwise `backend/.env` is baked into the image
- [ ] `.env` created, `chmod 600`, listed in `.gitignore`, `DB_PASSWORD` set
- [ ] `SITE_ADDRESS` set (`:80`, or a duckdns name pointed at the IP)
- [ ] `/api/v1/analyst/*` is the **first** rule in the `Caddyfile`
- [ ] `VITE_ANALYST_BASE` deliberately **not** set

**Bring-up**

- [ ] `docker compose up -d --build` completes
- [ ] `docker compose ps`: `db` healthy, `migrate` exited 0, three services running
- [ ] `schema_migrations` contains `0001`, `0002`, `0003`

**Verification**

- [ ] `/health`, `/api/v1/system/health`, `/api/v1/system/constraints` all answer
- [ ] `/` returns `text/html`, and the dashboard renders in a browser
- [ ] `/api/v1/system/health` reports **postgres**, not memory
- [ ] `/api/v1/analyst/health` answers on the same origin
- [ ] `wscat` receives a `snapshot` frame, then `metrics` every second
- [ ] Replay starts and the dashboard animates

**Durability**

- [ ] Deliberate `sudo reboot`, then re-verify — the stack comes back on its own
- [ ] Idle-reclaim mitigation chosen: looping replay, or PAYG with a $1 budget alert
- [ ] Local `run_demo.py` fallback rehearsed for demo day
