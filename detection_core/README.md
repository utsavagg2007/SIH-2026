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

Schemas, adapter, engine and tests are complete. **`PortScanDetector` is the
first and so far only detector.** No ML model yet — `ml/` is still a reserved
namespace.

## Layout

```
detection_core/
├── schemas/          FlowEvent, ThreatAlert v1.1, frozen enums, time helpers
├── adapters/         the ONLY code that understands features.jsonl
├── engine/           Detector interface + DetectionEngine
├── aggregators/      rolling per-source sliding windows
├── detectors/        port_scan (vertical + horizontal)
└── ml/               reserved - empty
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
