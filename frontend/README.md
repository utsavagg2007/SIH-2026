# SIH26-26145 — Verification Console

A working frontend for checking that the backend's APIs and output behave as
specified.

**Scope.** This is the verification console, not the final dashboard. It exists
so that a regression anywhere in the API shows up on a screen rather than in a
log: it reads every REST route and handles every WebSocket frame type the
backend serves. It follows the Frontend Design Specification's tokens, type
scale and layout closely enough to be a credible starting point for the real
build, but several things the spec asks for are deliberately not here — see
[Not built](#not-built).

## Run it

The backend must be running on port 8000 first.

```bash
npm install
```

```bash
npm run dev
```

Open <http://127.0.0.1:5173>. Then start a replay from the **Replay** view, or:

```bash
curl -X POST localhost:8000/api/v1/replay/start -H "Content-Type: application/json" -d "{\"capture\":\"demo_scenario.jsonl\",\"speed\":8,\"loop\":true}"
```

Vite proxies `/api` and `/ws` to `127.0.0.1:8000` in development. That proxy is
a dev convenience only — React talks to FastAPI directly, with no Node tier in
between, which the design spec rules out for exactly the path where latency is
graded.

## Views

| View | What it verifies |
|---|---|
| **Live** | `/ws/alerts` streaming, alert projection, evidence bars, class visuals |
| **Incidents** | correlation, kill-chain ordering, escalation, narratives |
| **Host** | `/hosts` and `/hosts/{ip}` — timeline, peers, JA3 history |
| **System** | throughput, latency histogram, detector rows, the constraint proof |
| **Replay** | capture control and the ground-truth manifest |

The Wire runs across the top of every view: a canvas trace of the last sixty
seconds with detections marked in their severity colour. It owns its own
`requestAnimationFrame` loop and reads from a ring buffer the WebSocket handler
writes to, so the animation never triggers a React render.

Keyboard: `j` / `k` move through the alert stream, `Esc` clears the selection.

## Design rules being followed

These come from the Frontend Design Specification and are worth not undoing:

* **Colour is reserved entirely for severity and threat class.** Nothing else on
  screen is saturated. When an alert appears, its colour is the only vivid thing
  on the display.
* **Severity is colour; confidence is a number plus a bar.** They are different
  quantities and never share an encoding. Severity also always carries a text
  label, so the display survives projection and colour-vision differences.
* **Mono for anything a machine produced, sans for anything a human wrote.** A
  reader can tell at a glance which parts of the screen are observed data.
* **`tabular-nums` globally.** Without it, digits change width as values update
  and the whole display shivers.
* **Near-zero border radius**, 2px on interactive elements only, so buttons are
  distinguishable from readouts by shape alone.
* **Alerts batch onto an animation frame**, never one state setter per message,
  and the stream is capped at a 500-alert ring buffer so memory stays flat
  during a flood.
* **Nothing apologises.** Empty states name what the system is doing; errors
  state what failed and what still works.

## What the console surfaces deliberately

* **Reconstructed visuals are badged.** When the backend rebuilt a chart from
  summary statistics instead of an observed series, the panel says
  `reconstructed`. Showing that distinction is the whole reason the backend
  flags it.
* **Traffic figures read `—`, not `0`, when no telemetry has arrived.** The
  backend never sees a packet; flow and bit rates come from the ingestion layer.
* **Dropped frames are reported.** If the browser falls behind the feed, the
  instrument bar says how many frames were dropped rather than implying the
  stream is complete.
* **The feed never fakes movement.** When the WebSocket drops, the Wire freezes
  and the bar reads `feed stopped`.

## Not built

Present in the design spec, out of scope for a verification console:

* The Analyst panel (spec §6.5) — it is the last item in the spec's own build
  order and never on the critical path.
* Alert-list virtualisation (§8.2). The 500-row ring buffer renders acceptably
  at demo rates, but this needs doing before the flood demo at several hundred
  alerts per second.
* Fan-out matrix axis labels, the host baseline-comparison chart, and the Wire's
  hover tooltip.
* `prefers-reduced-motion` is honoured for the Wire and alert rows, but the
  remaining polish items in §2.5 are untested.

## Build

```bash
npm run build
```

TypeScript is `strict` with `noUnusedLocals` and `noUnusedParameters`; the build
runs a full typecheck.
