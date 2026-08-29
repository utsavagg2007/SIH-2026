# detection_core

The detection / ML layer.

```
ingestion output (features.jsonl)
    -> adapter
    -> normalized FlowEvent
    -> DetectionEngine
    -> statistical detectors / ML models      <- not implemented yet
    -> standardized ThreatAlert v1.1
```

This package **never imports `ingestion_core`** and never touches Zeek logs,
PCAPs, Docker or Rust. Its only contact with the ingestion team is the JSONL
file format, and that knowledge is confined to `detection_core/adapters/`.
`injestion_core/` is owned by another team and is read-only.

## Status

Schemas, adapter, engine and tests are complete. Five rule detectors ship:
**`PortScanDetector`**, **`DDoSDetector`**, **`C2BeaconingDetector`**,
**`DnsTunnellingDetector`** and **`DataExfiltrationDetector`**. No trained ML
model yet — `ml/` holds the offline DGA baseline only.

## Layout

```
detection_core/
├── schemas/          FlowEvent, ThreatAlert v1.1, frozen enums, time helpers
├── adapters/         the ONLY code that understands features.jsonl
├── engine/           Detector interface + DetectionEngine
├── aggregators/      rolling sliding windows, keyed by whatever a detector needs
├── detectors/        port_scan, ddos, c2_beaconing, dns_tunnelling,
│                      data_exfiltration + shared scoring helpers
└── ml/               offline DGA baseline (Part 1)
```

`fixtures/` holds mock ingestion records; `tests/` is the pytest suite.
`SCHEMA.md` is the contract document for the other two teams.

## Setup

From the repository root:

```powershell
cd detection_core
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Bash / macOS / Linux:

```bash
cd detection_core
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
```

The virtual environment is git-ignored and must not be committed.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest
```

## Usage

Reading ingestion output:

```python
from detection_core import IngestionJsonlAdapter

source = IngestionJsonlAdapter(path="../injestion_core/features.jsonl")
for flow in source:
    print(flow.src_ip, flow.dst_ip, flow.conn_state)

print(source.stats)   # parsed / skipped / drift warnings
```

Running detectors over it:

```python
from detection_core import DetectionEngine, IngestionJsonlAdapter, PortScanDetector

engine = DetectionEngine([PortScanDetector()])
source = IngestionJsonlAdapter(path="features.jsonl")

for alert in engine.run(source):
    print(alert.to_wire())                        # ThreatAlert v1.1 JSON
```

## Port scan detector

Rolling state is kept per `src_ip` inside a sliding window:

* **vertical** — the source reaches `min_unique_ports` distinct destination
  ports.
* **horizontal** — some *single* destination port reaches `min_unique_hosts`
  distinct destination hosts. Fan-out is measured **per port**, so a source
  contacting many hosts on assorted unrelated ports (ordinary CDN-heavy
  browsing) is not a scan, while sweeping `:22` across a subnet is.
* **combined** — both, in the same window.

```python
from detection_core import PortScanConfig, PortScanDetector

detector = PortScanDetector(PortScanConfig(
    window_seconds=60.0,      # rolling window, in event time
    min_unique_ports=15,      # vertical threshold
    min_unique_hosts=20,      # horizontal threshold, per destination port
    cooldown_seconds=300.0,   # per-source alert flood control
))
```

* Counts are over **distinct** values, so hammering one host on one port never
  trips a threshold. A flow with no `dst_port` counts toward neither
  threshold — there is no port to correlate it across hosts.
* Rolling state is computed here, keyed by source — ingestion's global window
  features are not used (see `SCHEMA.md`).
* The alert fires from `process()` on the exact flow that crosses the
  threshold. `flush()` returns nothing.
* `score` is a `rule_score`: 0.5 exactly at the threshold, rising to 1.0 at
  `saturation_multiple` × threshold, `+combined_bonus` when both signals fire.
  Severity: `>= 0.9` critical, `>= 0.75` high, `>= 0.6` medium, else low.
* `dst_ip` / `dst_port` are set only when unambiguous — a scan spanning many
  targets reports `None` rather than inventing a placeholder.

### Cooldown and escalation

After alerting on a source the detector stays quiet for `cooldown_seconds`
**unless the scan grows into a strictly higher severity band**, which is
allowed through immediately. A rising score inside the same band is not —
that is the spam the cooldown exists to stop. Each escalation restarts the
cooldown, so a widening scan produces at most one alert per band:

```
5 ports  -> LOW      alert
7 ports  -> LOW      suppressed
8 ports  -> MEDIUM   escalation alert
12 ports -> MEDIUM   suppressed
13 ports -> HIGH     escalation alert
```

### Evidence

`scan_type` (`vertical` / `horizontal` / `combined`), `unique_dst_ports`,
`unique_dst_ips`, `connection_attempts`, `window_seconds`,
`horizontal_dst_port` (the swept port, `None` unless horizontal fired),
`max_hosts_per_port`, plus the two thresholds in force.

## DDoS detector

Where port scanning asks *"what has this source touched?"*, DDoS asks *"who has
been hitting this destination?"* — so its rolling state is keyed by `dst_ip`.

A destination qualifies only when **both** hold inside the window:

* **breadth** — `unique_src_ips >= min_unique_sources`
* **intensity** — `flow_count >= min_flows` **or** `packet_count >= min_packets`

```python
from detection_core import DDoSConfig, DDoSDetector

detector = DDoSDetector(DDoSConfig(
    window_seconds=10.0,       # short - a flood is a burst
    min_unique_sources=50,     # breadth
    min_flows=200,             # intensity, either-or
    min_packets=1000,
    cooldown_seconds=60.0,
))
```

> These defaults are **initial heuristics for demo traffic, not tuned values.**
> They must be re-derived against real captures of this network's normal and
> attack traffic before anyone trusts them operationally.

* Requiring breadth stops one large legitimate transfer looking like an attack;
  requiring intensity stops a merely popular host doing so. **Bytes are tracked
  and reported but deliberately do not gate the decision** — a single big
  download would otherwise qualify.
* **Volume is counted originator-side only** (`orig_pkts` / `orig_bytes`) — what
  the sources sent *at* the victim. The responder counters are the victim's own
  replies; folding them in let 60 ordinary clients fetching one page each cross
  `min_packets` on the strength of the pages the server was serving.
* Repeat flows from one source never inflate `unique_src_ips`; destinations are
  fully isolated from each other.
* `dst_ip` is always the attacked host. `src_ip` is `None` whenever more than
  one attacker is involved; `dst_port` and `protocol` are populated only when
  unambiguous across the window. No placeholders, ever.
* `score` averages the breadth ratio and the stronger intensity ratio, then maps
  onto the same curve and severity bands as port scan. Cooldown and
  severity-escalation behave identically, keyed per destination.

### Evidence

`unique_src_ips`, `flow_count`, `packet_count`, `byte_count`, `window_seconds`,
`observed_span_seconds`, `flows_per_second`, `packets_per_second`, plus
`min_unique_sources` / `min_flows` / `min_packets`.

`packet_count` and `byte_count` are originator-side: traffic arriving at the
victim, not traffic it sent back.

## C2 beaconing detector

Looks for one source contacting one endpoint over and over on a suspiciously
even timer. State is keyed by the whole relationship —
`(src_ip, dst_ip, dst_port, proto)` — so two conversations never pool timing,
and a missing port stays `None` rather than collapsing onto a fake port 0.

A relationship qualifies only when all of these hold inside the window:

* **persistence** — `observation_count >= min_observations` **and**
  `interval_count >= min_observations - 1` genuinely usable intervals
* **plausible cadence** — mean interval within
  `[min_mean_interval_seconds, max_mean_interval_seconds]`
* **regularity** — `coefficient_of_variation <= max_interval_cv`

Persistence is checked on both counts deliberately. Zero-length gaps
(duplicate timestamps) are dropped from the interval list, so contact count
alone could otherwise clear the bar while the timing verdict rested on fewer
measurements than intended — and the intervals are the evidence here. With the
default `min_observations=6`, at least **5 valid positive intervals** are
required.

```python
from detection_core import C2BeaconingConfig, C2BeaconingDetector

detector = C2BeaconingDetector(C2BeaconingConfig(
    window_seconds=900.0,             # rolling history per relationship
    min_observations=6,               # contacts before timing is judged
    min_mean_interval_seconds=2.0,    # faster is a keep-alive, not a check-in
    max_mean_interval_seconds=120.0,  # slower cannot fill the window
    max_interval_cv=0.20,             # spread within ~20% of the mean
    cooldown_seconds=300.0,
))
```

> These defaults are **initial heuristics, not operationally tuned values.**
> They must be re-evaluated against captures of this network's benign periodic
> services *and* real C2 traffic.

Intervals are `t2-t1, t3-t2, …` computed here from `FlowEvent.timestamp`;
`CV = stddev / mean`, and **lower CV means more periodic, so more suspicious**.
Only strictly positive gaps are used, so duplicate timestamps are skipped rather
than producing a zero interval or a division by zero.

**Periodicity is not proof of malware.** Health checks, update pollers,
telemetry agents, keep-alives and monitoring probes all beacon. This is a
"possible C2 beaconing" lead to investigate, not a verdict. Volume is reported
as evidence but gates nothing — real C2 transfers vary in size.

### Evidence

`observation_count`, `interval_count`, `mean_interval_seconds`,
`interval_stddev_seconds`, `coefficient_of_variation`, `window_seconds`, the
four configured thresholds, plus `total_orig_bytes`, `total_orig_packets` and
`average_orig_bytes_per_flow` as context.

Rates are `None` when the window spans no event time (one flow, or several
sharing a timestamp). That is the honest answer — dividing by a fudged epsilon
is how ingestion ends up publishing `flow_rate: 1000000.0` on its first record.

## Data exfiltration detector

**What it means.** Exfiltration is data *leaving* — a host shipping files,
credentials or a database dump out of the network. The question is not "how
busy is this host?" but "how much did it **send**, and did nearly all of it go
to one place?"

State is keyed by `(src_ip, dst_ip)`, so bytes bound for different destinations
are never pooled. A second window keyed by `src_ip` alone supplies the
denominator for *destination concentration*.

### Direction is the whole point

Volume is measured with **`orig_bytes`** — originator → responder — and
**never** `total_bytes`.

> Somebody downloading a 500 MB file has a huge `resp_bytes` and a tiny
> `orig_bytes`. If volume were `orig + resp`, that download would be the
> loudest alert in the system, and it would be completely wrong.

`resp_bytes` is carried and reported as evidence — "uploaded 2 GB, received
4 KB" is a far more legible alert than the upload figure alone — but it gates
nothing and cannot raise the score. The target environment may be genuinely
unidirectional, so **nothing here requires a response stream to exist**;
`resp_bytes` may legitimately be zero throughout.

### Two ways to qualify

Both routes require concentration:

* **sustained** — `total_orig_bytes >= min_total_orig_bytes` **and**
  `flow_count >= min_flows` **and** concentration. Data leaving in chunks.
* **single large transfer** —
  `max_single_flow_orig_bytes >= min_single_flow_orig_bytes` **and**
  concentration. One bulk upload, which needs no repetition to be worth
  seeing. Its bar sits above the sustained one because a lone transfer gets
  no corroboration from being repeated.

`evidence["qualification_path"]` reports which fired: `sustained`,
`single_large_transfer`, or `both`.

### Destination concentration

```
destination_concentration = pair_total_orig_bytes / source_total_orig_bytes
```

Of everything this host uploaded in the window, what share went *here*. Both
windows are trimmed to the same instant before the ratio is taken, so every
byte in the numerator is also in the denominator and the result cannot exceed
1.0. A source that sent nothing scores **0.0**, not 1.0 — with no outbound data
there is no concentration to measure, and 0.0 is the reading that cannot
qualify.

Concentration gates both paths because volume alone is a poor signal: a backup
client legitimately moves gigabytes, and so does a developer pushing a repo.
What is less ordinary is a host whose outbound traffic is overwhelmingly aimed
at a single peer.

```python
from detection_core import DataExfiltrationConfig, DataExfiltrationDetector

detector = DataExfiltrationDetector(DataExfiltrationConfig(
    window_seconds=300.0,
    min_total_orig_bytes=50 * 1024 * 1024,          # 50 MiB, sustained path
    min_flows=10,                                    # sustained path
    min_single_flow_orig_bytes=100 * 1024 * 1024,   # 100 MiB, single path
    min_destination_concentration=0.60,              # both paths
    cooldown_seconds=300.0,
))
```

> **THESE ARE UNTUNED DEMO HEURISTICS.** They were picked so an obvious bulk
> transfer fires while ordinary browsing does not, on traffic nobody has
> measured yet. They must be re-derived against real captures of this network's
> normal uploads **and** simulated exfiltration before anyone trusts them.
> Expect the byte thresholds in particular to be wrong for any specific network
> by an order of magnitude in one direction or the other.

### This does not prove data theft

A large upload is not evidence of a crime. All of these look exactly like the
pattern above, and all of them are ordinary:

* cloud backups and sync clients (Drive, Dropbox, OneDrive, Backblaze)
* a large `git push`
* video uploads
* database replication
* software deployment and artefact publishing
* any legitimate bulk file transfer

An alert means *"this host sent a lot of data, concentrated on one
destination"* — a lead to investigate, not a verdict. The evidence block
carries the actual measurements so an analyst can see **why** it fired and
dismiss the benign cases quickly.

* `score` takes the stronger qualifying path's ratio, maps it onto the same
  curve and severity bands as the other detectors (exactly at threshold →
  0.5, `saturation_multiple`× → 1.0), then adds up to `concentration_bonus`
  scaled from the concentration floor. Component ratios are capped *before*
  averaging, so a huge flow count cannot ride one runaway component to
  critical. Nothing in the calculation reads `resp_bytes`.
* Cooldown and severity-escalation behave as elsewhere, keyed per pair. A
  pair's cooldown deliberately outlives its traffic window: it is released on
  elapsed cooldown, not on an empty window, so a pair cannot go quiet, return
  and re-alert inside a cooldown it was still serving.

### Evidence

`qualification_path`, `flow_count`, `total_orig_bytes`, `total_orig_packets`,
`max_single_flow_orig_bytes`, `source_total_orig_bytes`,
`destination_concentration`, `window_seconds` and the four configured
thresholds, plus `total_resp_bytes`, `observed_span_seconds` and
`orig_bytes_per_second` as context.

`total_orig_bytes` is originator-side: what the host **sent**.
`total_resp_bytes` is what came back — reported, never scored.
`orig_bytes_per_second` is `None` when the window spans no event time.

## DGA ML baseline (offline — Part 1)

**What DGA is.** Malware often does not hardcode its controller's address.
Instead it runs a *domain generation algorithm*: both the malware and the
attacker derive the same list of pseudo-random domains from a shared seed
(often the date), and the malware tries them until one resolves. Blocking a
single domain therefore achieves nothing — the next batch appears tomorrow.
The tell is that generated names look nothing like names humans register:
`kqxvbzmwjrph.com` versus `wikipedia.org`.

**Pipeline.** `raw domain → lexical features → Random Forest → dga_score`

> ### ⚠ Live integration is NOT complete
> `injestion_core`'s `features.jsonl` does **not** expose the raw
> `dns.query` string. It carries only derived values — `query_entropy`,
> `query_length`, `subdomain_entropy`, `is_txt`, `label_count`. A classifier
> needs the actual domain text, and reconstructing it from an entropy number
> is impossible, so **there is no live `DGADetector` wired to the engine.**
> This milestone is offline training infrastructure only. When ingestion
> supplies `dns.query`, only an adapter change and a thin detector are
> needed — the model and features are ready.

### Features, in plain terms

Each domain becomes 19 numbers. The character statistics are computed on the
**body** (everything except the final label), since the TLD is picked from a
tiny fixed set and says nothing about how the name was generated.

| feature | what it means | why it helps |
|---|---|---|
| **entropy** | how unpredictable the characters are, in bits. `aaaaaa` scores 0; a varied string scores high | generated names are near-random, so they score higher than real words |
| **digit_ratio** | fraction of characters that are digits | many DGAs splice in digits; `github.com` has none |
| **length** | total characters | generated names are often longer than memorable brands |
| **vowel_ratio** | fraction of letters that are a/e/i/o/u | human-chosen names are pronounceable (~40% vowels); random ones are vowel-starved |
| **unique_char_ratio** | distinct characters ÷ length | random strings rarely repeat characters, so this sits near 1.0 |
| **longest_consonant_run** | longest unbroken consonant stretch | `kqxvbz` is a classic generated-looking cluster |

The rest: `body_length`, `tld_length`, `label_count`, `max_label_length`,
`mean_label_length`, `digit_count`, `alpha_ratio`, `consonant_ratio`,
`hyphen_count`, `hyphen_ratio`, `unique_char_count`, `longest_digit_run`,
`longest_alpha_run`.

### Dataset format

A CSV with exactly two required columns. `0 = benign`, `1 = DGA` (DGA is
always the positive class):

```csv
domain,label
google.com,0
github.com,0
xj3kq9zv.com,1
```

Labels also accept `benign`/`dga` spellings. The loader rejects a missing
column, an unusable label, an empty domain, and — importantly — a duplicate
domain carrying *conflicting* labels, rather than silently picking one.

**No leakage:** domains are normalized, *then* deduplicated, *then* split. Since
duplicates are removed outright, the same normalized domain cannot appear in
both train and test. The split is stratified whenever class counts allow, with
`random_state=42`.

### Training

```bash
pip install -e ".[ml]"

python -m detection_core.ml.dga.training \
    --input domains.csv \
    --output artifacts/dga_model.joblib
```

Reports raw rows, rows after deduplication, benign/DGA counts, train/test
sizes, accuracy, precision, recall, F1, confusion matrix, and ROC-AUC when the
test set contains both classes. Add `--json` for machine-readable metrics.

The output is a `joblib` bundle carrying the estimator plus metadata — format
version, feature names and order, model type, training config, class mapping,
sklearn version. Loading validates that the feature schema still matches this
build and **refuses** a stale bundle rather than predicting on a mismatched
vector. Artifacts are git-ignored; retrain rather than committing binaries.

```python
from detection_core.ml.dga import DGAModel

model = DGAModel.load("artifacts/dga_model.joblib")
print(model.predict_domain("kqxvbzmwjrph.com"))   # label + dga_score
model.feature_importances()                        # for the demo/explanation
```

### Limitations — read before quoting any number

* **`dga_score` is not a calibrated probability.** It is a Random Forest vote
  fraction in `[0, 1]`. That is why it is not called a probability and why no
  `ThreatAlert.score_type` is assigned yet — `calibrated_model` would be a
  false claim until calibration is actually done.
* **Metrics from a small or synthetic dataset prove the plumbing works, not
  that the model is good.** The test fixture exists to exercise code paths.
  Real performance depends entirely on representative benign *and* DGA
  training data, which will be supplied separately.
* **Dictionary-based DGAs evade lexical models.** Families that assemble real
  words (`correct-horse-battery.com`) look statistically like human names.
  Catching those needs different signals — resolution behaviour, NXDOMAIN
  rates, registration age.
* **No Public Suffix List.** `shop.example.co.uk` treats `uk` as the TLD and
  `shopexampleco` as the body. Deterministic, but imprecise for multi-part
  suffixes. Adding a PSL dependency was judged not worth it here.
* **Punycode is not decoded.** An `xn--` label is scored as the literal ASCII
  it already is.

## Writing a detector

Subclass `Detector` and implement `process()`. A detector that keeps rolling
state also implements `reset()`, and `flush()` only if it can be left holding
incomplete state when a finite replay ends.

```python
from detection_core import Detector, FlowEvent, ThreatAlert

class MyDetector(Detector):
    name = "my_detector"
    version = "0.1.0"

    def process(self, flow: FlowEvent) -> list[ThreatAlert]:
        # Alert from here, as soon as the condition is satisfied.
        return []

    def reset(self) -> None:
        # Clear rolling state; run() calls this before each source.
        return None

    def flush(self) -> list[ThreatAlert]:
        # Only to settle state still pending at end of a finite stream.
        return []
```

Rules:

* depend on `FlowEvent`, never on `features.jsonl` or `injestion_core`;
* **alert from `process()`, immediately.** This is a near-real-time streaming
  system: emit the moment a sliding window, threshold or statistical test
  crosses its bound. `flush()` is not the normal alerting path — it exists
  only to finalize pending state when a bounded source (a PCAP replay, a test)
  runs out. A live stream may never end;
* `score` is always a finite float in 0.0–1.0, whatever the `score_type`;
* put the reasoning in `evidence` — that is what an analyst sees;
* a detector that raises is isolated by the engine, logged and counted, but it
  produces nothing. Handle your own errors.

`DetectionEngine.run()` resets every detector before consuming a source, so
replaying a second PCAP through the same engine cannot inherit state from the
first. Pass `reset_first=False` to deliberately accumulate across calls.

## Design notes

* **Adapter isolation.** When ingestion changes its output, only
  `adapters/ingestion_jsonl.py` and `adapters/encodings.py` should change.
* **Strict core, honest optionals.** Required flow fields validate or the
  record is skipped; fields ingestion cannot supply are `None`, never invented.
  See "Integration TODOs" in `SCHEMA.md`.
* **Frozen models.** The engine hands one `FlowEvent` to every detector, so
  immutability prevents cross-detector contamination.
* **Ingestion's global window features are deliberately ignored** — that
  upstream logic is still being corrected. See `SCHEMA.md`.
