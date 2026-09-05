# DESIGN.md — Passive Threat Detection Console

**Design brief for the UI pass. Read this whole file before writing any component.**

Audience: the designer/implementer rebuilding the visual and interaction layer of this
frontend. The data layer, contracts and performance architecture are already correct and are
**not** in scope for redesign — see §12 for what must not be touched.

Authority: this document extends `../docs/SIH-Frontend-Design-Spec.txt` (v1). Where the two
disagree, **this file wins**, and the disagreement is deliberate and explained. Everything v1
says that is not restated here still stands.

---

## 0. What we are building and for whom

A passive network threat detection console for a national technical intelligence organisation
(NTRO). The backend watches a **one-directional mirrored copy** of network traffic and produces
scored alerts. It cannot block, quarantine, reset a connection, or query a host. It can only
observe and report.

That constraint is the design thesis. **This is an instrument, not a console.** There are no
action buttons on alerts because there are no actions, and that absence is deliberate and worth
pointing at during the demo.

Two audiences, both served by the same screen:

| Audience | Time on screen | What they need |
| --- | --- | --- |
| Evaluators / judges, standing behind an operator | 5–10 min, poor lighting, projector | "This is detecting real threats *right now*, and here is why it fired" — inside 8 seconds |
| An analyst | A shift | Full detail on every alert, keyboard-driven, no hunting for a field |

The redesign must serve both without splitting into two products. Density serves the analyst;
hierarchy serves the judge. Where they conflict, add hierarchy — never remove detail.

### The aesthetic target, stated precisely

**Aesthetic here means calibrated, not decorated.** The reference points are measurement
instruments: oscilloscopes, spectrum analysers, seismographs, flight recorders, signals
intelligence terminals. Precise gridlines, tick marks with calibration values, fixed-decimal
readouts that do not jitter in width, restraint everywhere except where a signal appears.

**Explicitly forbidden**, because every one of them makes this look like a SaaS dashboard and
undermines an intelligence-agency deliverable:

- Gradients of any kind, glassmorphism, blur, translucency, drop shadows, glow
- Rounded cards (radius > 2px), pill buttons, floating action buttons
- Neon cyan / purple / magenta accents; any "tech" palette
- Emoji, illustrations, mascots, hero sections, marketing copy
- Loading skeletons that shimmer, spinners on data that is already in memory
- Pulsing or glowing alerts, sliding or bouncing rows, animated number counters
- Charts of benign traffic in colour
- Any decorative motion whatsoever

If a change would look at home in a startup's analytics product, it is wrong for this one.

---

## 1. Assessment of the current build

The existing implementation is competent and on-thesis. It is not yet *legible at a glance*.
These are the specific failures the redesign must fix, in priority order.

### 1.1 Critical — hierarchy failures (the "hard to interpret" problem)

**A. Every alert row looks the same.** In `src/components/AlertStream.tsx`, all five fields sit
between 10–12px in `--text-2`/`--text-3`. A CRITICAL exfiltration and a LOW port scan are
separated by a 2px rail and one small coloured word. A judge scanning the list cannot rank the
screen by importance. **The severity ramp exists but carries almost no visual weight.**

**B. There is no "how bad is it right now" summary anywhere.** Severity counts, alert rate,
which class is most active — none of it is on screen. The viewer has to read and tally rows.
This is the single largest gap and the reason the interface "doesn't present metrics with ease".

**C. The instrument bar under-reports.** `InstrumentBar.tsx` shows five readouts. The
`Throughput` and `MetricsFrame` contracts already carry `alerts_per_sec`, `alerts_total`,
`alerts_deduplicated`, `packets_per_sec`, `latency_p50_ms`, `traffic_source` — none shown.
**`alerts/sec` is the most important "is it detecting" number in the product and it is absent.**

**D. The evidence panel omits most of what it was given.** `EvidencePanel.tsx` renders class,
severity, endpoints, confidence, evidence bars, one visual, and a raw JSON dump. The `Alert`
type also carries `score` + `score_type`, `kill_chain_stage`, `mitre_technique(s)`,
`occurrences`, `first_seen`/`last_seen`, `detector` + `detector_version`, `pipeline_latency_ms`,
`incident_id`, `flow_id` and `evidence_raw`. **The ask was "full information details" — the data
is already on the wire and is being thrown away.**

**E. The class visual — the most convincing image in the product — is below the fold.** It sits
third in a single scrolling column after the header and the evidence bars. On a 1080p projector
the beacon comb is usually off-screen when an alert is selected.

**F. The Wire under-encodes.** `Wire.tsx` draws every detection mark at identical height and
weight regardless of severity, and spec 3.1's stated interaction — hover for tooltip, click to
select — is not implemented. The signature element is currently a decoration.

### 1.2 Serious — integrity and correctness

**G. Fabricated data is being rendered as measurement.** This is the most damaging item in the
list, because the product's entire claim is that it reports only what it observed:

- `SystemView.tsx` → `rand(0.4, 3.2)` for per-detector mean scoring time; hardcoded version
  `"0.3.1"`; `dns_tunnel` hardcoded as `degraded`.
- `App.tsx` → `latencySamples` built from `metrics.p95 + (Math.random() - 0.5) * 10`.
- `BeaconComb.tsx` → the "typical host" comparison row is `Math.random()` scatter, regenerated
  on mount, presented next to the real beacon as if it were a measurement.

The backend already serves `Health.detectors: DetectorStatus[]` (real state, real versions, real
`mean_detector_latency_ms`) and `Throughput.latency_histogram`. **See §11 — this is
non-negotiable.**

**H. The design system is written twice and neither copy is authoritative.** `src/styles.css`
defines a complete system (`.app` grid, `.row`, `.ev-*`, `.bar`, `.chip`, `table.grid`,
`prefers-reduced-motion` handling) that **no component uses** — every component inlines styles
from `src/lib/tokens.ts` instead. Consequences: `.row:hover` never fires, so **alert rows have
no hover state at all**; `:focus-visible` never fires; the reduced-motion block is dead; and any
token change must be made in two places. §12.1 resolves this.

**I. Rows and nav items are `<div onClick>`.** Not focusable, not keyboard-reachable, not
announced. The v1 spec's own quality floor requires visible focus rings and keyboard operation.

### 1.3 Moderate

**J. Critical is dimmer than High.** `--sev-crit #C8453D` has a lower perceived luminance (≈107)
than `--sev-high #DB7038` (≈138). On a projector in a lit room, **the most severe class is the
least visible.** The ramp inverts at the top. Fixed in §2.

**K. Raw JSON dump.** `<pre>{JSON.stringify(alert, null, 2)}</pre>` is always expanded and
dominates the bottom of the panel. v1 spec says `[expand]`.

**L. No time-since context.** Alerts show absolute timestamps only. "12s ago" is what tells a
viewer the feed is live; an absolute clock does not.

**M. Filtering is severity-only.** No filter by threat class, no host filter, though `CLASS_META`
and the alert payload support both.

**N. Host and Replay views are thin** relative to `HostView` / `Capture` / `ReplayStatus`, which
serve considerably more than is drawn.

---

## 2. Colour system

### 2.1 The governing rule (unchanged, and it is the whole aesthetic)

> **Colour is reserved entirely for severity and threat state. Nothing else on screen is
> saturated** — not headers, not borders, not buttons, not icons, not charts of benign traffic.
> When an alert appears, its colour is the only vivid thing on the display, so it commands
> attention without needing to glow, pulse or animate.

This one constraint does more for the look of this product than any other decision. Every
proposal below that adds colour must justify itself against it. **A palette that is 95% neutral
is not a limitation here; it is the design.**

### 2.2 Surface and structure

Nine neutral steps, cool-grey with a slight blue cast. Two are new.

| Token | Value | Use |
| --- | --- | --- |
| `--bg-deep` | `#07090A` | **NEW.** The frame behind panels: gutters between panels, the 1px grid gaps in the System view, the area under the Wire. Gives depth without a single shadow. |
| `--bg` | `#0B0D0F` | Application background, canvas backgrounds |
| `--panel` | `#14181B` | Panel surfaces, nav rail, instrument bar |
| `--panel-2` | `#1B2024` | Raised surfaces, selected row, active chip |
| `--panel-3` | `#222930` | **NEW.** Hover only. Hover must be visible on a projector; `--panel-2` doing double duty as both hover and selected is why the current build reads as stateless. |
| `--rule` | `#252C31` | Borders, dividers, chart gridlines, bar tracks |
| `--rule-bright` | `#38424A` | Axis lines, active borders, threshold rules |
| `--text` | `#E9ECED` | Primary text, readout values |
| `--text-2` | `#8B959C` | Labels, units, secondary data, evidence bar fills |
| `--text-3` | `#5A646B` | Axis ticks, disabled, placeholder, timestamps |

### 2.3 Severity ramp — the only saturated colours in the product

| Token | Value | Was | Note |
| --- | --- | --- | --- |
| `--sev-low` | `#4E9C7F` | unchanged | Desaturated green. Must never read as "success". |
| `--sev-med` | `#D2A03E` | unchanged | Amber |
| `--sev-high` | `#DB7038` | unchanged | Orange |
| `--sev-crit` | `#E04B3F` | ⚠ was `#C8453D` | **Raised.** Fixes item J — critical now outranks high in luminance as well as hue. |
| `--baseline` | `#41718F` | unchanged | Learned-normal bands, reference traces, **and focus rings** (§2.6). Never an alert colour. |

**Wash variants** — the same four hues at 12% alpha, for exactly two uses (fill of a ledger bar,
tint of a selected row's first 64px). Nowhere else. A wash is never a full panel background: a
wall of red destroys the discipline that makes the ramp work.

```
--sev-low-wash:  rgba(78,156,127,0.12)
--sev-med-wash:  rgba(210,160,62,0.12)
--sev-high-wash: rgba(219,112,56,0.12)
--sev-crit-wash: rgba(224,75,63,0.12)
```

### 2.4 Critical gets a second channel

Hue alone cannot make critical outrank high on a projector at 4m. Critical therefore carries
**three** encodings where high carries two:

| | rail width | severity chip | wash |
| --- | --- | --- | --- |
| low / medium / high | 2px | outlined, text in severity colour | none |
| **critical** | **3px** | **filled**, `--bg` text on severity ground | tint on selected row |

This is instrument convention — the redline on a gauge is thicker than the gradations — and it
costs no new colour.

### 2.5 Severity is not confidence

Different quantities, never a shared encoding. **Severity is colour. Confidence is a numeric
readout plus a thin neutral bar in `--text-2`.** An alert can be `critical` at `0.62` confidence
and the interface must make that combination readable at a glance. A confidence bar is never
tinted by severity.

Likewise `score` + `score_type`: a `rule` score is not a probability and must not be rendered as
a percentage. Render it as `score 4.20 · rule` — value then provenance, no bar.

### 2.6 Where colour is allowed — the complete list

Nothing outside this list may be saturated. Treat additions as spec changes.

1. Alert severity rail, severity chip, severity label text
2. Detection marks on the Wire
3. The observed marker on an evidence bar, **only when it crossed the threshold**
4. Class-visual signal traces (beacon ticks, rejected scan cells, breakout region) — severity
   colour, passed in, never chosen by the visual (`visuals/chrome.tsx` already enforces this)
5. `--baseline` for learned-normal bands, reference traces, and focus rings
6. Feed-state indicator in the instrument bar, **only when disconnected or degraded**
7. Detector state text in the System view (`online` / `degraded` / `unseen`)
8. Severity counts in the Threat Ledger (§4.1)

Everything else — nav, headings, buttons, chips, panel chrome, benign traffic, throughput traces,
latency histograms, axes, the density trace on the Wire — is neutral. Always.

### 2.7 Threat class marks stay monochrome

Detectors need distinguishing in dense listings. Do **not** give each a colour: it breaks
severity discipline and that many hues exceed what anyone learns in a demo. Keep the two-letter
monospace code in a 1px `--rule-bright` box at `--text-2`. Same mark on the Wire, so it is
learned within a minute of watching.

**The vocabulary is the backend's, not this document's.** `backend/app/schemas/enums.py` is
authoritative — `ThreatClass` with `THREAT_CODE` and `THREAT_LABEL` beside it. It carries
**seven** classes: `DF` DDoS Flood, `DG` DGA Domain, `DT` DNS Tunnelling, `PS` Port Scanning,
`EC` Encrypted-Session Malware, `BC` Beaconing, `EX` Exfiltration. There is no amplification
detector. Earlier drafts of this file and of `lib/tokens.ts` listed eight classes under four
names nothing emits, so those four missed every lookup silently. Prefer an alert's own
`threat_code` / `threat_label` wherever one is in hand; `src/lib/__tests__/contract.test.ts`
pins the table against the enum.

### 2.8 Projector check — required before sign-off

Screenshot the Live view, apply +40% brightness and −25% contrast (approximating a projector in a
lit room), and confirm: the four severities remain distinguishable from each other; hover is
distinguishable from selected; `--text-3` remains readable at 11px. If any fails, adjust the
neutral steps, not the ramp.

---

## 3. Typography, geometry, motion

### 3.1 Type — two faces, one family, one rule

**IBM Plex Mono** for anything a machine produced: IPs, ports, timestamps, hashes, byte counts,
domains, confidence, feature values, counts. **IBM Plex Sans** for anything a human wrote: labels,
headings, navigation, descriptions, empty states, analyst prose.

The split is a rule, not a suggestion, and it does real work: a reader can tell at a glance which
parts of the screen are observed data and which are interface chrome. Never mix within a value.

```
readout-xl   32px / 1.0  / Plex Mono 500 / tabular    NEW — ledger severity counts
readout-lg   28px / 1.0  / Plex Mono 500 / tabular    throughput figures
readout      18px / 1.1  / Plex Mono 500 / tabular    confidence, key values
data         13px / 1.4  / Plex Mono 400 / tabular    alert rows, feature values
data-sm      11px / 1.35 / Plex Mono 400 / tabular    axis ticks, timestamps
heading      15px / 1.3  / Plex Sans 600              panel titles
body         13px / 1.5  / Plex Sans 400              descriptions, analyst text
label        10px / 1.2  / Plex Sans 600 / +0.08em uppercase   field labels
micro         9px / 1.2  / Plex Sans 600 / +0.07em uppercase   chips, badges
```

**`font-variant-numeric: tabular-nums` is mandatory and global.** Without it every live number
changes width as it updates and the whole display shivers — which looks broken, and on a
projector looks catastrophic. Already set in `index.html` and `styles.css`; keep it.

### 3.2 Space and geometry

```
Space scale (px):   4  8  12  16  24  32  48
Border radius:      2px on interactive elements, 0 everywhere else
Border width:       1px rules · 2px severity rails · 3px critical rails
Panel padding:      16px  (12px in dense sub-panels)
Row height:         40px alert stream (FIXED — see §12.2) · 32px dense listings
Gutter:             1px --rule over --bg-deep between panels
```

Near-zero radius is deliberate: instruments have square bezels; rounded cards read as consumer
software. Keep 2px on buttons and inputs only, so interactive elements are distinguishable from
readouts **by shape alone**.

**No shadows, ever.** Depth comes from the `--bg-deep` → `--panel-3` surface ladder.

### 3.3 Motion — five animations, all information-bearing

Motion exists for exactly two purposes: **showing that data is flowing**, and **showing that
something new has arrived**. Nothing else moves. Every animation below encodes a fact; if one can
be removed without losing information, remove it.

| # | Event | Treatment | Duration / easing |
| --- | --- | --- | --- |
| 1 | Wire advancing | Continuous, constant velocity, canvas. Never eases, never pauses, never fakes movement | rAF, linear |
| 2 | New alert row arrives | Opacity 0→1 **and** the severity rail draws top→bottom. No slide, no bounce, no scale | 140ms `cubic-bezier(0.2,0,0,1)` |
| 3 | **Recency decay** *(new, signature)* | A newly arrived row's rail sits at 100% chroma and decays to 55% over 6s. Recency becomes visible without a "NEW" badge, and the stream visibly *breathes* under load | 6000ms linear, opacity only |
| 4 | Dedup increment | When `occurrences` changes on a visible row, its `×N` count flashes to `--text` once and returns | 90ms in, 300ms out |
| 5 | Ledger bar length | Severity-count bars ease to their new width at 1Hz | 240ms `cubic-bezier(0.2,0,0,1)` |

Everything else:

| Event | Treatment |
| --- | --- |
| Panel / view change | **Instant.** Cross-fades on a live monitoring tool make it feel sluggish |
| Row hover | Background → `--panel-3`, 90ms. No scale, no shadow, no lift, no border change |
| Selection change | Evidence panel content swaps instantly. The *frame* never animates |
| Value updates | **No transition.** A readout that tweens between numbers is lying about when the value changed |
| Analyst panel open/close | Width 0→380px, 240ms. It is the only panel permitted to move |
| Loading | There is none. Everything needed is already in the alert payload. **If a spinner appears in the Live view, the API contract is wrong** |

**`prefers-reduced-motion: reduce`** — Wire redraws in 1s steps; #2 rail draw and fade are
dropped; #3 becomes a static `--text-2` dot on the row for 6s; #4 and #5 snap. Everything stays
fully functional. The dead media query in `styles.css` must actually apply once §12.1 lands.

---

## 4. Layout

The shell gains one new element. Everything else keeps its footprint.

```
┌────┬───────────────────────────────────────────────────────────────────────────┐
│    │  THE WIRE                                                          88px   │
│    ├───────────────────────────────────────────────────────────────────────────┤
│    │  THREAT LEDGER   ◄── NEW                                           44px   │
│ N  ├─────────────────────────┬─────────────────────────────────────────────────┤
│ A  │  ALERT STREAM     34%   │  EVIDENCE                                 66%   │
│ V  │                         │  ┌───────────────────┬───────────────────────┐  │
│    │                         │  │ identity ·        │  class visual         │  │
│ 56 │                         │  │ confidence ·      │  (large, above fold)  │  │
│ px │                         │  │ provenance        │                       │  │
│    │                         │  ├───────────────────┴───────────────────────┤  │
│    │                         │  │ WHY THIS FIRED — evidence bars            │  │
│    │                         │  ├───────────────────────────────────────────┤  │
│    │                         │  │ RAW FLOW RECORD                [expand]   │  │
│    │                         │  └───────────────────────────────────────────┘  │
│    ├─────────────────────────┴─────────────────────────────────────────────────┤
│    │  INSTRUMENT BAR                                                    48px   │
└────┴───────────────────────────────────────────────────────────────────────────┘
```

Evidence keeps the larger pane because it is the graded requirement and the thing that convinces.
**The alert stream is a selector; the evidence panel is the product.**

Responsive rules — this is a wall-display product; there are no phone layouts:

- `≥1600px` — as drawn. Evidence panel is two columns; class visual is above the fold.
- `1280–1599px` — evidence panel collapses to one column, class visual **first**, evidence bars
  second. The image outranks the bars when only one can be seen.
- `<1280px` — out of scope. Do not spend time here.

### 4.1 The Threat Ledger *(new, 44px, full width, under the Wire)*

**This is the fix for "can't see the metrics at a glance" and it is the highest-value single
addition in this document.** One strip that answers *how bad is it right now* before anyone reads
a row.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  CRIT  3 ████▌     HIGH  11 ███████▌   MED  24 ██▌   LOW  7 █▌  │ 14.2 alerts/s  │
│                                                                 │ BC most active │
│  ── last 5 min ──                                               │ 412 total      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

- Four severity cells, ordered **critical first** — descending severity, not alphabetical.
- Count at `readout-xl` (32px mono) in the severity colour. This is the one place a large number
  is allowed to be coloured, and it is why the strip works from across a room.
- Bar beneath each count: proportional width, filled with that severity's **wash**, so the strip
  reads as a distribution and not four unrelated numbers.
- Window is **the last 5 minutes**, labelled. A rolling window, not an all-time total — an
  all-time total only ever goes up and stops carrying information after a minute.
- Right cell: `alerts/sec` (live, throttled to 4Hz), the most active threat class as its
  two-letter code + full name, and the session total.
- Zero counts render as a dim `0` in `--text-3` with no bar. **Never hide a zero** — "0 critical"
  is itself the finding.
- Each severity cell is a filter toggle, synced with the stream's filter chips. Clicking `CRIT`
  filters the stream to critical. This makes the ledger a control surface, not just a readout, and
  removes a whole row of duplicate chips.

### 4.2 Nav rail (56px)

Keep the five destinations and the icon+label treatment. Two changes:

- Items become real `<button>`s with `aria-current`, a 2px `--rule-bright` left border when
  active, and a visible focus ring.
- At the foot of the rail, a small permanent plate — two lines, `micro`, `--text-3`, 1px `--rule`
  box:

  ```
  PASSIVE
  READ-ONLY
  ```

  It states the architectural constraint on every screen, in the register of an equipment label.
  It is not decoration; it is the thesis, and it is the thing a judge should notice.

---

## 5. The alert row — redesign

The most-looked-at 40 pixels in the product. **Height stays exactly 40px** (§12.2).

Current (one flat line, everything the same weight):

```
▌ 14:22:07.412  BC  CRITICAL   10.4.2.19 → 185.62.11.4                 0.91
```

Proposed — two lines inside the same 40px, with real hierarchy:

```
┃ 10.4.2.19 → 185.62.11.4:443                    ×42   ▓▓▓▓▓▓▓▓▓░ 0.91
┃ BC  beaconing · CRITICAL · 12s ago                              ⛓ i2c9f
```

Anatomy, left to right:

| Element | Type | Colour | Note |
| --- | --- | --- | --- |
| Severity rail | 2px (3px critical) | severity | Full row height. Draws top→bottom on arrival; chroma decays over 6s (motion #3) |
| Endpoints | `data` 13px | `--text` | **The brightest thing in the row.** This is what a viewer reads first and what identifies the alert |
| `×N` occurrences | `data-sm` | `--text-2` | Only when `occurrences > 1`. Flashes on increment (motion #4). Currently not rendered at all — it is the difference between one probe and a sustained campaign |
| Confidence bar + value | 40px track + `data-sm` | `--text-2` neutral | **Never severity-tinted** (§2.5) |
| Class code | `micro` mono in 1px box | `--text-2` | `BC` |
| Class name | `body` 11px lowercase | `--text-2` | `beaconing` |
| Severity label | `micro` chip | severity; **filled for critical** | Text label always present — severity is never colour alone |
| Relative age | `data-sm` | `--text-3` | `12s ago`, `4m ago`. Ticks at 1Hz. Absolute timestamp moves to the tooltip and the evidence panel |
| Incident glyph | 11px | `--text-3` | Only when `incident_id` is set. Clicking it opens Incidents scoped to that incident |

States:

| State | Treatment |
| --- | --- |
| Default | `transparent` |
| Hover | `--panel-3`, 90ms |
| Selected | `--panel-2` + left 64px carries the severity wash + rail brightens to 100% |
| Focused (keyboard) | 1px `--baseline` inset ring, never removed |

Rows must be `<button role="option">` inside a `role="listbox"`, with `aria-selected` and a
roving `tabIndex`. Keyboard (`j`/`k`/`Enter`/`Esc`/`a`) already works in `App.tsx` — keep it, and
add `1`–`4` to jump the ledger filter to a severity, `0` to clear.

### 5.1 Stream chrome

- Filter row: severity chips (synced to the ledger) **+ a class filter** — eight code chips,
  monochrome, `aria-pressed`. Selecting classes is how an analyst isolates a campaign.
- A host filter field (`data-sm` mono, placeholder `filter host…`) matching `src_ip`/`dst_ip` as a
  substring. One input, no dropdown.
- The `shown / total` counter stays, at 4Hz, right-aligned.
- The keyboard-hint footer stays. It signals a tool built for operators.

---

### 5.2 Incident grouping — the stream is a list of situations, not of events

**This is the fix for "there is too much on screen to tell what is happening", and it is a
structural change rather than a visual one.**

On the demo capture the stream renders ~95 rows. Those rows are about **seven actual
situations**: eighteen of them are one host being scanned, then beaconing over TLS, then
exfiltrating — and the correlation layer had already worked that out and stamped every one of
them with the same `incident_id`. The flat list threw that away, so the display asked a viewer to
re-derive by eye a grouping the backend had already computed and put on the wire.

Note what the failure was *not*. It was not density — density is the point of this product, and
§0 is explicit that detail is never removed to serve the judge. It was that the panel showed
**events where the reader needed situations**. Adding hierarchy, per §0, is the correct response;
this is that hierarchy.

Default view is grouped. A collapsed header is one 40px row:

```
┃ ▾ 10.4.2.19   ESCALATED                              4 of 35  ALERTS
┃   PS › EC › EX › BC                                 CRITICAL  6s ago
```

- **The code sequence is the argument.** `PS › EC › EX › BC` is "scanned, then ran encrypted C2,
  then exfiltrated, then beaconed" in four tokens, oldest first, and it is legible before any row
  underneath it is. It is the kill-chain narrative of §8.1 made visible without leaving the Live
  view.
- Severity is the **worst member on screen**, carrying the usual rail and chip so the collapsed
  list still ranks by urgency from 4m.
- `4 of 35` — members in the buffer against `Incident.alert_count`, the correlator's own exact
  figure. Two numbers, because one number would misreport the incident every time a filter is
  pressed or the ring buffer lets go of an older member.
- A **`Grouped` / `Flat` toggle** sits with the filter chips. Grouped answers "what is happening"
  for someone who has been watching for eight seconds; flat is the firehose an analyst reads
  during a shift. §0 requires both audiences to be served by one screen, and neither has to live
  in the other's view.

**What is and is not derived.** §11 forbids inventing structure as firmly as it forbids inventing
numbers, so the rule is narrow: **a group is an incident the backend opened, and nothing else.**
Alerts the correlator left uncorrelated are never bundled by shared host, shared class or
proximity in time — a client-side "these look related" grouping would be a correlation claim made
by the presentation layer, which is precisely the assertion this console exists not to make. A
single-member incident gets no header, because a group of one costs 40px and says nothing.

Group headers are named by a fixed precedence: the incident's own `pivot_host`; failing that, the
source address **every** member shares; failing that, the incident id. The middle rule is not an
edge case — the backend expires incidents long before the client's 500-alert ring lets go of
their members, so on the demo capture the correlator holds five incidents while the buffer still
carries alerts from thirteen. A header named by that rule prints the incident id beside it, so a
derived label and the correlator's own finding never look identical.

**Fixed pitch is preserved.** §12.2 makes `ROW_H = 40` load-bearing. Group headers are therefore
40px rows in the *same flat array* as the alerts (`lib/group.ts` flattens the tree), so windowing
stays fixed-pitch arithmetic and `windowRange` / `scrollToIndex` are untouched. The stream is
still a fixed-pitch virtualized list; it simply has two kinds of row in it.

Keyboard is unchanged: `j`/`k` walk the flat filtered list as before, and the group holding the
selection is always expanded, so a keystroke can never move the selection somewhere invisible.

---

## 6. The Wire — v2

Keep everything in `Wire.tsx` that is right: canvas, one rAF loop, ring buffer, React state never
in the animation path, `feed stopped` on disconnect, 1s stepping under reduced motion. **Never
fake movement.** Add:

1. **Severity-encoded marks.** Mark height and weight scale with severity — low draws a short
   1.5px tick from the baseline; critical draws a full-height 2.5px tick. A wall of criticals
   should look visibly different from a wall of lows *without reading a single code*.
2. **A now-edge hairline.** A 1px `--rule-bright` vertical at the right edge with the `now` label
   anchored to it, so the eye has a fixed reference for where new data enters.
3. **Hover tooltip** (spec 3.1, currently missing). Hovering within 4px of a mark shows a compact
   readout: time, code, severity, endpoints. Rendered as a positioned DOM node driven by a
   mousemove hit-test against the ring buffer — **not** by putting the marks in the DOM.
4. **Click selects.** Clicking a mark selects that alert in the stream below and scrolls it into
   view. This is what makes the Wire an instrument rather than an ornament.
5. **Density trace stays neutral** (`--text-3`). Benign traffic is never coloured.
6. **Baseline band.** If a learned-normal flow-rate band is available, draw it behind the density
   trace in `--baseline` at low alpha. If it is not available, **draw nothing** — do not invent a
   band (§11).

---

## 7. Evidence panel — full detail

The graded requirement and the screen that wins. It currently shows about half of what it is
handed. Rebuild as four regions; on `≥1600px` the first two sit side by side.

### 7.1 Identity block

```
┌──────────────────────────────────────────────────────────────────────┐
│ BC  BEACONING                                            ▐ CRITICAL  │
│ 10.4.2.19 → 185.62.11.4:443                                          │
│                                                                      │
│ confidence  0.91  ▓▓▓▓▓▓▓▓▓░        score 4.20 · rule                │
│                                                                      │
│ occurrences   ×42        first seen  14:02:11   last seen  14:22:07  │
│ stage         command_and_control    MITRE      T1071.001            │
│ detector      beacon_periodicity 0.3.1          latency    38ms      │
│ incident      i2c9f004 →             flow       10.4.2.19:185…:443   │
└──────────────────────────────────────────────────────────────────────┘
```

Every field above exists in the `Alert` type today and is currently dropped. Rules:

- Both IPs are links to the Host view — **every IP everywhere in this product is a link to its
  host view.** That one interaction rule is what makes the whole thing feel navigable.
- `kill_chain_stage` renders as a **6-segment mini-ribbon** with the current stage filled, not as
  a text string. It shows position in the chain, which is the point of having a stage.
- `mitre_technique` / `mitre_techniques` render as monospace chips. No external links (the console
  has no egress; a dead link contradicts the thesis).
- `incident_id` is a link to the Incidents view scoped to that incident.
- **Any field the backend did not send is omitted entirely.** No `—`, no `unknown`, no placeholder
  row. An absent field is information: the detector did not report it.

### 7.2 "Why this fired" — evidence bars

Keep the existing bar mechanics from `EvidencePanel.tsx`; they are correct. Refinements:

- **Order by `rank` ascending, most decisive first** (spec 5.1). The current sort only pushes
  thresholded items ahead of contextual ones and ignores `rank` — fix it.
- Label uses `item.label` when present, falls back to `item.feature`. Append `item.unit`.
- The observed marker takes the severity colour **only** when `exceeded` — trust the backend's
  `exceeded` flag over a recomputed comparison, as the current code correctly does.
- Show the *distance past the line*, e.g. `0.041 · 3.7× below threshold 0.15`. "How far past" is
  the analytical content; the bar alone only says "past".
- Features with no threshold render as a plain label–value pair with no bar. **Do not invent a
  scale to make them look uniform.**
- Track `--rule`, fill `--text-2`, threshold a 1px `--rule-bright` rule with its value labelled.

### 7.3 Class visual

Promoted to the top-right column on wide screens. Rules that apply to all eight:

- **Severity colour is passed in, never chosen** — `visuals/chrome.tsx` already enforces this;
  keep it.
- **`SourceBadge` is mandatory and must stay visible.** A comb reconstructed from
  `mean_interval_sec` looks like a perfect beacon *by construction*, so presenting it as observed
  would fabricate the most convincing image in the product. The badge is what keeps the image an
  argument rather than an assertion. Do not shrink it into a tooltip.
- Unknown `visual.kind` falls back to evidence bars alone. A new detector must never break the
  interface.
- Give each visual a one-line caption in `body`/`--text-2` naming what the reader is seeing
  (`"Evenly spaced connections. Human traffic clusters; this does not."`). One line, factual, no
  adjectives.
- **`BeaconComb`'s "typical host" row must stop being random** — see §11.

### 7.4 Raw flow record

Collapsed by default, `[expand]` control. When expanded, render `evidence_raw` as a two-column
mono key/value grid (sorted, zebra-free, 1px `--rule` row separators) rather than
`JSON.stringify`. Keep a "copy JSON" control for the full payload. A JSON blob is a debugging
artifact, not an interface.

---

## 8. Remaining views

### 8.1 Incidents

The kill-chain ribbon is the argument: these findings are one story, and the sequence is itself
evidence. Worth a full minute of the demo. Improve:

- Position nodes on a **real elapsed-time axis**, not equal flex spacing. The gap between a port
  scan and exfiltration 20 minutes later *is* the finding; equal spacing erases it.
- Label the stage under each node, and draw the connecting line in `--rule-bright` with
  severity-coloured node rings (as now).
- `escalated` gets a prominent explanation, not just a badge: one sentence stating that the
  incident spans more than one kill-chain stage and that the sequence is why it outranks its
  highest member severity.
- Render `narrative` when present, in `body`, above the ribbon.
- Sort by `updated_at` descending so a still-growing incident stays at the top.
- Honour `members_truncated` — `12 of 47 shown`, never silently truncate.

### 8.2 System — the requirement (d) screen

Four panels, all fed from real endpoints (`GET /system/health`, throughput). See §11.

- **Throughput** — flows/sec, packets/sec, Mb/s over time; sustained figure as `readout-lg`,
  tested peak labelled beside it. Trace neutral.
- **Latency** — histogram from `Throughput.latency_histogram` (**do not synthesise samples**), p50
  and p95 marked on the axis, and `latency_definition` printed under it so the number is not
  ambiguous.
- **Detector status** — one row per detector from `Health.detectors`: name, `state`
  (`online`/`degraded`/`unseen`), `alerts_produced`, `mean_detector_latency_ms`,
  `detector_version`. A degraded detector shows as degraded rather than disappearing. **`unseen`
  is not `offline`** — the backend cannot tell a down detector from one with nothing to report,
  and the label must not claim otherwise.
- **Constraint proof** — `ConstraintProof` rendered as plain readouts: egress blocked, ingest
  direction inbound-only, payload decryption never, outbound attempts `0`, write routes toward
  network `0`, checked at. Three lines that say the system sent nothing, received one way only, and
  decrypted nothing. **Point at this panel during the demo** — give it the strongest typography on
  the screen.

Also surface `storage_backend`, `storage_healthy`, `storage_queue_depth`, `storage_writes_shed`,
`ws_clients`, `alerts_deduplicated`, `alerts_rejected` — currently all served and none shown.

### 8.3 Host

Investigation view for one machine, reached by clicking any IP anywhere. Render what `HostView`
actually serves: `severity_counts` and `threat_class_counts` as small distribution bars, an alert
timeline, `peers` (with the honest note that novelty is a detector-side judgement and the backend
reports what it saw rather than guessing), `ja3_history`, and every incident the host appears in.

### 8.4 Replay

Deliberately plain: capture select, speed multiplier, start/stop, position + elapsed readout, loop
state. One control earns its place — **the scenario label from the ground-truth manifest**, naming
which attacks the loaded capture is known to contain. Being able to say *"this capture contains a
beacon at minute seven, and here it is at minute seven"* is a strong demo moment; give it real
estate.

### 8.5 Analyst panel

Right-docked, 380px, toggled by `a` or the Explain control. Not a page, not a floating chat bubble.

- Opening it with an alert selected produces the explanation immediately, without typing.
- Every claim renders with its `Citation.source` as a small inline mono reference. **Statements
  that cannot be traced to a stored field must not be shown at all.**
- `generated: false` is badged as the deterministic local rendering, not hidden. So is
  `degraded_reason`.
- Unavailable → *"Analyst unavailable. Detection is unaffected."* This layer is never on the
  critical path.

---

## 9. States

Every view needs all five. Empty states name what the system is doing and what happens next;
errors state what failed and what still works. **Nothing apologises — an instrument that
apologises is an instrument nobody trusts.**

| State | Treatment |
| --- | --- |
| Empty | `body` in `--text-3`, centred, one line. *"Waiting for first detection. Replay running at 5×."* |
| Loading | Does not exist in the Live view. Elsewhere, a 1px `--rule` bar and a factual line — never a shimmer |
| Disconnected | Wire freezes with `feed stopped`; instrument bar feed cell turns `--sev-crit`; stream shows *"Feed stopped. Last alert 00:04:12 ago."* Existing data stays on screen and is not dimmed |
| Degraded | Named plainly at its source (the detector row, the analyst panel), never as a global banner |
| Flood | The interface must hold 60fps. Ledger counts climb, the stream stays scrollable, the Wire never stutters. Test at several hundred alerts/sec |

---

## 10. Copy

Words here are readouts, not commentary: factual, present tense, no hedging, no personality.

| Write this | Not this |
| --- | --- |
| Waiting for first detection. Replay running at 5×. | No alerts found! |
| Feed stopped. Last alert 00:04:12 ago. | Oops — something went wrong |
| Analyst unavailable. Detection is unaffected. | Sorry, I couldn't process that request |
| Baseline learning. 14 minutes remaining. | Please wait… |
| No traffic on this interface. | Nothing to see here |

Threat classes are written out in full in headings and shortened to the two-letter code only in
dense listings. Never mix the two in one view.

---

## 11. Data integrity — non-negotiable

**The product's entire claim is that it reports only what it observed. A fabricated value on
screen is a correctness bug of the highest severity, not a design shortcut.** Every one of the
following must be fixed as part of this pass.

| Location | Problem | Fix |
| --- | --- | --- |
| `SystemView.tsx` | `rand(0.4, 3.2)` mean scoring time | `DetectorStatus.mean_detector_latency_ms` from `GET /system/health` |
| `SystemView.tsx` | Hardcoded `"0.3.1"` version | `DetectorStatus.detector_version` |
| `SystemView.tsx` | `dns_tunnel` hardcoded `degraded` | `DetectorStatus.state` |
| `App.tsx` | `latencySamples` = `p95 + Math.random()*10` | `Throughput.latency_histogram` |
| `BeaconComb.tsx` | Random "typical host" comparison row | Draw only if the backend supplies a real comparison series; otherwise **drop the row** and keep the observed comb alone |

Rules going forward:

1. **Never synthesise a series, sample, baseline or comparison for display.** If the backend did
   not send it, the component does not draw it.
2. **An absent value renders as an omission or a labelled dash, never as a plausible number.**
   `InstrumentBar.tsx` already does this correctly for traffic figures when `trafficLive === false`
   — that is the pattern; apply it everywhere.
3. **Reconstructed data is always badged.** `VisualSource.reconstructed_from_summary_statistics`
   must remain visible at full size.
4. **Never present a rule score as a probability**, and never render `severity` and `confidence`
   with the same encoding.
5. Counts shown as exact (`alert_count`, `occurrences`, `cells_total`) come from the backend's own
   field, never from `members.length` or a count of drawn elements.

---

## 12. Implementation constraints

### 12.1 Resolve the duplicated style system — do this first

Right now `src/styles.css` and `src/lib/tokens.ts` both define the design system, components use
only the latter, and the CSS is dead (item H). **Resolution: CSS custom properties are the single
source of truth.**

1. `styles.css` keeps and extends `:root` with the tokens in §2 (add `--bg-deep`, `--panel-3`,
   `--sev-*-wash`, and the raised `--sev-crit`).
2. `tokens.ts` stops holding literals and reads them: `bg: "var(--bg)"`, etc. The exported `T`
   shape stays identical so no component import changes. `SEV`, `CLASS_META`, `MONO`, `SANS` stay
   as they are.
3. Move state-dependent styling — hover, `:focus-visible`, `aria-selected`, `aria-pressed`,
   keyframes, `prefers-reduced-motion` — into `styles.css` classes. Inline styles cannot express
   `:hover`, which is precisely why alert rows currently have no hover state.
4. Keep inline styles only for values computed from data (bar widths, mark positions, per-alert
   severity colour via a `--sev` custom property set on the row).

This is a prerequisite for hover states, focus rings, and the reduced-motion behaviour — not a
tidy-up.

### 12.2 Do not break these

- **`ROW_H = 40` in `AlertStream.tsx` is load-bearing.** Virtualization is fixed-pitch arithmetic
  (`windowRange`, `scrollToIndex`); a variable row height means a dependency and a rewrite.
  Redesign *within* 40px.
- **The Wire stays on canvas with its own rAF loop.** React state must never enter the animation
  path. The hover tooltip is a hit-test, not DOM marks.
- **`EvidencePanel`'s memo comparator stays** (`alert_id` + `occurrences` + `last_seen`). It is the
  single largest avoidable cost during a flood.
- **The ring buffer stays capped at 500**, updates stay batched on animation frame, visible
  counters stay throttled to 4Hz. All existing and correct.
- **The type contract in `src/lib/types.ts` is authoritative.** Do not add fields the backend does
  not serve.
- **Do not add a component library.** Every one of them will fight the instrument aesthetic, and
  the distinctive components here are all custom anyway.
- **Existing tests must keep passing** (`npm test` — `AnalystPanel`, `EvidencePanel`, `visuals`,
  `useFeed`, `useThrottledValue`, `api`, `fanout`, `virtual`).

### 12.3 Accessibility floor

- Severity is **never** communicated by colour alone — every severity carries a text label.
- Alert rows, nav items and ribbon nodes are real buttons: focusable, `aria-selected` /
  `aria-current` / `aria-pressed`, reachable by Tab.
- Visible focus rings, 1px `--baseline`, never removed.
- `j` / `k` / `Enter` / `Esc` / `a` keep working; add `1`–`4` / `0` for severity filtering.
- `prefers-reduced-motion` honoured as §3.3.
- Layout holds to 1280px.

---

## 13. Build order

| # | Task | Why here |
| --- | --- | --- |
| 1 | CSS-variable consolidation (§12.1), new tokens, `--sev-crit` raise | Everything else depends on it; unblocks hover, focus, reduced motion |
| 2 | Alert row redesign (§5) | Most-looked-at pixels; largest legibility win |
| 3 | Threat Ledger (§4.1) | Largest "read the metrics at a glance" win |
| 4 | Evidence panel full detail + two-column layout (§7) | The graded requirement |
| 5 | Data-integrity fixes (§11) | Correctness. Do not ship the demo without these |
| 6 | Instrument bar v2 — add alerts/sec, p50, dedup, packets/sec (§1.1C) | Cheap, high value |
| 7 | Wire v2 — severity-encoded marks, hover, click-to-select (§6) | Signature element earns its place |
| 8 | Motion pass — the five animations and the reduced-motion branch (§3.3) | Only meaningful once 2–4 exist |
| 9 | System view rebuild against `/system/health` (§8.2) | Requirement (d) |
| 10 | Incidents time-axis ribbon (§8.1) | Makes the fusion layer visible |
| 11 | Host, Replay, Analyst refinements (§8.3–8.5) | Degrade gracefully if time runs short |

**If only three things get done well:** the alert row, the Threat Ledger, and the full-detail
evidence panel. Those three answer *is it detecting*, *how bad is it*, and *why did it fire* — the
only three questions anyone will actually ask.

---

## 14. Acceptance checklist

Design is done when every line is true.

**Legibility**
- [ ] Severity rank is readable from 4m without reading text
- [ ] Critical is visibly more urgent than high, in both hue and weight
- [ ] Severity counts for the last 5 minutes are visible without scrolling or reading rows
- [ ] `alerts/sec` is on screen at all times
- [ ] The stream reads as a list of situations, not of events: a full buffer collapses to one row
      per correlated incident, and each header states its kill-chain sequence (§5.2)
- [ ] The instrument bar has two tiers — a viewer can find "is it detecting" without reading ten
      equal-weight readouts
- [ ] Hover, selected and focused are three distinguishable states on every interactive element

**Information**
- [ ] Every field in the `Alert` type is reachable from the evidence panel
- [ ] Every IP in the product links to its host view
- [ ] `occurrences`, relative age and incident membership are visible on the alert row
- [ ] Kill-chain stage renders as a position in the chain, not a string
- [ ] Absent fields are omitted, never rendered as plausible values
- [ ] An endpoint the detector did not report renders as a labelled dash, never as the
      punctuation around a hole (`10.4.2.19 → :`)
- [ ] A quantity is never labelled with the name of something it cannot be — negative pipeline
      latency is clock skew, and says so

**Integrity**
- [ ] No `Math.random()` reaches the screen anywhere in `src/`
- [ ] No group is formed that the correlator did not open; a derived group label is marked as
      derived and shown beside the incident id (§5.2)
- [ ] Every rendered number traces to a backend field
- [ ] `SourceBadge` is visible at full size on every reconstructed visual
- [ ] Severity and confidence never share an encoding

**Discipline**
- [ ] No saturated colour outside the eight permitted uses in §2.6
- [ ] No gradients, shadows, blur, glow or radius > 2px
- [ ] Exactly five animations exist, each carrying information
- [ ] `prefers-reduced-motion` is honoured and the interface stays fully functional
- [ ] Projector check (§2.8) passes

**Performance**
- [ ] 60fps sustained at several hundred alerts/sec
- [ ] No spinner appears anywhere in the Live view
- [ ] `npm run build` and `npm test` both pass
