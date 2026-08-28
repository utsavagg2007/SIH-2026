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

Foundation only. Schemas, adapter, engine and tests are complete.
**No detector and no ML model is implemented yet** — `detectors/`, `ml/` and
`aggregators/` are reserved namespaces.

## Layout

```
detection_core/
├── schemas/          FlowEvent, ThreatAlert v1.1, frozen enums, time helpers
├── adapters/         the ONLY code that understands features.jsonl
├── engine/           Detector interface + DetectionEngine
├── detectors/        reserved - empty
├── ml/               reserved - empty
└── aggregators/      reserved - empty
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
from detection_core import DetectionEngine, IngestionJsonlAdapter

engine = DetectionEngine([MyDetector()])          # once detectors exist
source = IngestionJsonlAdapter(path="features.jsonl")

for alert in engine.run(source):
    print(alert.to_wire())                        # ThreatAlert v1.1 JSON
```

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
