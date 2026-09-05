# detection_core

The detection / ML layer.

```
ingestion output (features.jsonl)
    -> adapter
    -> normalized FlowEvent
    -> DetectionEngine
    -> statistical detectors / ML models
    -> standardized ThreatAlert v1.1
```

This package **never imports `ingestion_core`** and never touches Zeek logs,
PCAPs, Docker or Rust. Its ingestion boundary is the JSONL feature format, and
that format-specific knowledge is confined to `detection_core/adapters/`.

## Status

Schemas, adapter, engine and tests are complete. Seven detectors ship: the
six rule/heuristic ones — **`PortScanDetector`**, **`DDoSDetector`**,
**`C2BeaconingDetector`**, **`DnsTunnellingDetector`**,
**`DataExfiltrationDetector`**, **`EncryptedMalwareDetector`** — plus the ML
**`DGADetector`**. Every threat class in the v1.1 enum has a detector.

DGA is opt-in for two reasons: **no trained model binary ships here**, and its
ML dependencies are an optional extra. So `build_default_detectors()` returns
the six rule detectors, and `--dga-model` / `dga_model_path=` adds the
seventh. With a valid model artifact all seven threat classes can be active.

## Layout

```
detection_core/
├── schemas/          FlowEvent, ThreatAlert v1.1, frozen enums, time helpers
├── adapters/         the ONLY code that understands features.jsonl
├── engine/           Detector interface + DetectionEngine
├── aggregators/      rolling sliding windows, keyed by whatever a detector needs
├── detectors/        port_scan, ddos, c2_beaconing, dns_tunnelling,
│                      data_exfiltration, encrypted_malware, dga
│                      + shared scoring helpers
├── pipeline.py       detector factory, alert sinks, streaming run loop
├── runner.py         `python -m detection_core.runner` CLI
└── ml/               offline DGA baseline (Phase 1)
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

source = IngestionJsonlAdapter(path="../ingestion/features.jsonl")
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

## Running Detection

The whole subsystem runs as one command — adapter, engine, every detector,
and alert output:

```bash
# Basic: alert JSONL to stdout
python -m detection_core.runner ../ingestion/features.jsonl

# Include the DGA detector (needs a trained model; none ships here)
python -m detection_core.runner input.jsonl --dga-model artifacts/dga_model.joblib

# Write alerts to a file
python -m detection_core.runner input.jsonl --output alerts.jsonl

# Also POST each alert to the backend
python -m detection_core.runner input.jsonl \
  --api-url http://localhost:8000/api/v1/alerts
```

**stdout is alert JSONL and nothing else.** Every log line goes to stderr, so
`| jq` and `> alerts.jsonl` work without extra flags. Records stream: nothing
loads the whole capture into memory, and each alert is flushed as it is
produced.

`--api-url` POSTs one ThreatAlert per request as `application/json`, using
only the standard library. It is an *additional* destination — the JSONL
output still happens — so a run that feeds the backend also leaves a local
record of exactly what was sent. A POST that fails is logged as an error and
counted in `RunStats.delivery_failures`, and the run **continues** — a backend
being down must not turn into a detection outage. Nothing is queued or
retried, and no alert is ever reported as delivered when it was not, so the
local JSONL is the record of anything the backend missed.

### Configuring detectors: `--config`

Thresholds live in the detector config dataclasses and those remain the
defaults. `--config` lets a run override them without editing source:

```bash
python -m detection_core.runner input.jsonl --config detectors.toml
```

```toml
# detectors.toml - only what you want to change
[port_scan]
cooldown_seconds = 120.0        # every other port_scan setting stays default

[c2_beaconing]
max_interval_cv = 0.25

[encrypted_malware]
ja3_fingerprints = ["0123456789abcdef0123456789abcdef"]   # synthetic example
```

TOML, because Python ships `tomllib` — reading a settings file is not worth a
new runtime dependency.

* **Sections are detector names**, which are also the threat-class values:
  `port_scan`, `ddos`, `c2_beaconing`, `dns_tunnelling`, `data_exfiltration`,
  `encrypted_malware`, `dga_domain`. One vocabulary, no abbreviations.
* **Partial.** Only the settings you name change; the rest keep the shipped
  defaults, because the override is applied by constructing the real config
  dataclass. There is no second copy of the defaults to drift.
* **Strict.** An unknown section, an unknown setting, or a wrong type is a
  startup error naming exactly where. `min_unique_prts = 15` fails rather
  than silently doing nothing. A boolean is never accepted as a number, and
  values the config dataclass already rejects still fail.
* Omitting `--config` entirely is identical to the behaviour before the flag
  existed — an empty file means the same thing.
* Scope is detector behaviour only. `--output`, `--api-url` and `--api-timeout`
  stay CLI options; this is not an application-config framework.

`[dga_domain]` is parsed and validated like any other section, but DGA still
needs `--dga-model`: configuration cannot conjure a model, and a run without
one says so on stderr rather than letting the section look effective.

### JA3/JA3S/JA4 fingerprints: `--ja3-feed`

The encrypted-malware signature path matches TLS fingerprints against
configured sets. **Those sets ship empty and no indicator list is bundled
here**, so the path is inert until you supply one:

```bash
python -m detection_core.runner input.jsonl --ja3-feed fingerprints.txt
```

```
# fingerprints.txt - all values below are synthetic examples, not real IOCs
ja3:0123456789abcdef0123456789abcdef
ja3s:fedcba9876543210fedcba9876543210
ja4:t13d1516h2_8daaf6152771_02713d6af862

# a bare MD5 is read as ja3 - the shape of most public JA3 lists
00112233445566778899aabbccddeeff
```

* **Local file only.** The loader opens a path and nothing else: no
  downloads, no URLs, no includes, no environment expansion, no evaluation.
  Keeping the feed current is an operational task, deliberately outside this
  code.
* JA3/JA3S must be 32-character hex MD5 digests; JA4 is checked against a
  deliberately conservative token shape rather than an invented spec. All are
  trimmed and lowercased, matching how the detector normalizes what it reads
  off a flow.
* A bare digest is **only** ever read as `ja3` — never `ja3s`. They are
  different measurements that happen to share a format.
* Blank lines and `#` comments are fine; duplicates collapse. A malformed
  line is an error naming the file, line number and reason — a silently
  skipped indicator is a detection that quietly does not happen.
* Fingerprints from `--ja3-feed` are **unioned** with any given in
  `--config`, so a feed supplements your configured indicators instead of
  silently replacing them.

Two honest limitations. `detector-v2` emits TLS fingerprints only when its Zeek
source log contains them; JA4 therefore requires the separately qualified JA4
runtime, and a capture without observed fingerprints gives the signature path
nothing to match on however good the indicator list is. This remains metadata
matching: **nothing here decrypts anything**.

### Startup safety and exit codes

* **`--output` cannot destroy an input.** A path that resolves to the same
  file as the input JSONL, or as the supplied `--dga-model`, is rejected
  *before* the output is opened — opening it truncates it. Relative and
  absolute aliases resolve to the same target, so `data/../data/x.jsonl` is
  caught too.
* **The six rule detectors need no ML dependency.** `--dga-model` needs the
  `ml` extra (`numpy`, `scikit-learn`, `joblib`); when it is absent the run
  fails at startup with a message naming the extra, rather than an
  `ImportError` traceback or a silently dropped detector.

| exit | meaning |
|---|---|
| `0` | ran to completion, nothing failed |
| `1` | startup or fatal error — missing input, unsafe `--output`, missing ML extra, invalid `--dga-model`, unreadable/invalid `--config` or `--ja3-feed`, unopenable output, I/O failure mid-run |
| `2` | the whole capture was processed, but one or more alerts failed delivery to `--api-url`; the local output is complete |

### Which detectors run

```python
from detection_core import build_default_detectors

build_default_detectors()                                   # six rule detectors
build_default_detectors(dga_model_path="artifacts/dga.joblib")   # + dga_domain
```

The six rule/heuristic detectors always run on their shipped defaults. **DGA
is opt-in**: it cannot work without a trained model, this package ships none,
and a missing artifact must not take the rest of the subsystem offline. Pass
`--dga-model` / `dga_model_path=` to include it. An *invalid* path is a
different matter and fails loudly at startup — you asked for DGA explicitly.

### What the integrated ingestion profiles supply

All seven detectors are built and tested. The frozen default `legacy-m1d`
feature profile intentionally retains the old omissions. The explicit
`detector-v2` profile supplies the raw strings and event-time fields needed by
the integrated detector path:

| detector | needs |
|---|---|
| `port_scan`, `ddos`, `c2_beaconing`, `data_exfiltration` | supplied by `detector-v2` |
| `dns_tunnelling` | supplied; derived DNS features qualify it and raw `dns.query` is retained as evidence |
| `dga_domain` | `detector-v2` supplies raw `dns.query`; a separately trained, explicitly configured model artifact is still required |
| `encrypted_malware` | SNI, JA3, JA3S, version, cipher, and qualified-runtime JA4 are supplied when Zeek observed them; none are fabricated |

The adapter preserves top-level `uid`, `timestamp`, `src_port`, `service`, raw
`conn_state`, IP-byte counters, decoded and numeric DNS codes, raw DNS/TLS/HTTP
fields, and protocol-row multiplicity. Missing source observations remain
`None`; encoded placeholders are never substituted for raw strings. See
"Profile capabilities" in `SCHEMA.md`.

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

## DNS tunnelling detector

**What it means.** Tunnelling encodes payload into the DNS query name itself,
so the queries come out long, high-entropy, deeply labelled and often TXT. No
single query proves anything — a long random-looking name is also what a CDN,
a cloud bucket or a reputation lookup emits all day. What is unusual is a host
doing it *over and over* to *one resolver*, so state is keyed by
`(src_ip, dst_ip)` and the detector is aggregate-first.

Two levels, both required:

* **per query** — at least `min_signals_per_observation` (2) of five
  indicators fire: long query, high query entropy, high subdomain entropy,
  deep label stack, TXT. A single metric is never sufficient; the config
  rejects `min_signals_per_observation=1` outright.
* **per pair** — `observation_count >= min_dns_observations` **and**
  `suspicious_ratio >= min_suspicious_ratio`.

```python
from detection_core import DnsTunnellingConfig, DnsTunnellingDetector

detector = DnsTunnellingDetector(DnsTunnellingConfig(
    window_seconds=300.0,
    min_dns_observations=20,
    suspicious_query_length=50,
    suspicious_entropy=4.0,          # bits/char, base-2 Shannon
    suspicious_subdomain_entropy=3.5,
    suspicious_label_count=5,
    min_suspicious_ratio=0.5,
))
```

> **Untuned demo heuristics.** Re-derive them against this network's normal
> DNS *and* real tunnelling traffic (iodine, dnscat2, dns2tcp) before trusting
> them.

**Working from derived features only.** Qualification reads exactly the five
normalized features — `query_length`, `query_entropy`, `subdomain_entropy`,
`label_count`, `is_txt` — and a raw `dns.query` is **not required** for this
detector to work. `detector-v2` carries the observed query, qtype, and rcode;
the frozen `legacy-m1d` projection does not, and nothing reconstructs a query.

The evidence key `raw_query_available` reports truthfully whether any query in
the *contributing rolling window* carried a real name, with
`raw_query_observation_count` giving how many. It is true on a `detector-v2`
record when Zeek supplied a query and false when the source did not — the verdict
is identical either way, because the raw name is evidence for the analyst, not an
input to the rule. It follows that this cannot confirm data actually left,
identify the tunnel domain or tool, or tell one repeated name from fifty
distinct ones.

## Encrypted malware detector

**Nothing here decrypts anything.** TLS payload is opaque to this project and
stays that way. All this detector reads is handshake *metadata*: which
fingerprint the client presented, what hostname it asked for, which version
was negotiated.

Two independent paths, answering different questions.

### Path A — known fingerprint (`signature_match`)

Does this flow's JA3/JA3S/JA4 appear in a configured list of known-malicious
fingerprints? That is a signature decision about one flow, so it alerts on
that flow (`event_scope=flow`, the flow's own `flow_id`), at score 1.0,
immediately — no repetition required.

> **The three fingerprint sets ship EMPTY and must stay that way.** They are
> only meaningful once loaded from a threat-intelligence source the operator
> trusts. This project does not invent fingerprints, and a test asserts the
> defaults stay empty.

```python
from detection_core import EncryptedMalwareConfig, EncryptedMalwareDetector

detector = EncryptedMalwareDetector(EncryptedMalwareConfig(
    malicious_ja3=load_from_your_feed(),   # empty by default
    malicious_ja3s=(),
    malicious_ja4=(),
))
```

Fingerprints are trimmed and lowercased on both sides — JA3/JA3S are hex
digests and JA4 is a lowercase token grammar, so case folding cannot merge two
distinct values. Nothing else is normalized: separator stripping or
reformatting could collapse two different fingerprints onto one string, and a
signature match must mean exactly what it says. Cooldown is keyed by
`(src_ip, dst_ip, fingerprint_type, fingerprint)`, so two different
fingerprints are two findings and neither silences the other.

### Path B — metadata heuristic (`rule_score`)

With no feed configured there is still something to say: a host whose TLS
*repeatedly* asks for long, high-entropy hostnames is worth a look. Keyed by
`(src_ip, dst_ip)`, `event_scope=host_pair`, `flow_id=None`.

An observation is suspicious only when **long SNI AND high-entropy SNI** —
both, never either:

* Length alone is ordinary. `telemetry-prod-eu-west-1.example-cdn.net` is 40
  characters of entirely normal infrastructure.
* Entropy alone is ordinary. Short hashed CDN names look exactly like this.
* **A missing SNI contributes nothing at all.** Encrypted Client Hello hides
  it legitimately, and treating absence as evidence would flag the most
  privacy-preserving traffic on the network.

A pair qualifies on `observation_count >= min_tls_observations` **and**
`suspicious_ratio >= min_suspicious_ratio`, so one strange handshake can never
raise a malware alert.

```python
EncryptedMalwareConfig(
    window_seconds=300.0,
    min_tls_observations=6,
    suspicious_sni_length=38,
    suspicious_sni_entropy=4.2,   # bits/char
    min_suspicious_ratio=0.60,
    cooldown_seconds=300.0,
)
```

`suspicious_sni_entropy` sits above the 3.5–4.0 band this was first drafted
with, and the reason is measured rather than guessed:
`telemetry-prod-eu-west-1.example-cdn.net` scores **3.88 bits/char**, so a 3.8
threshold would call ordinary infrastructure generated. Random-looking labels
sit near 4.7–5.1.

> **Untuned demo heuristics.** "Long, random-looking hostname" describes a
> great deal of entirely legitimate CDN and cloud traffic. Real values need a
> capture of this network's normal TLS *and* malware samples.

### Which TLS fields actually exist

The explicit detector-v2 profile emits raw TLS metadata when Zeek observed it,
alongside its derived compatibility features. So:

| field | status | used? |
|---|---|---|
| `tls.version` | available (decoded from `ssl_version_encoded`) | yes — an obsolete version *strengthens* a finding that already stands on SNI evidence, and can never create one |
| `ja3` / `ja3s` | populated when the source log contains them | Path A exact signature matching |
| `ja4` | populated from real source telemetry when the qualified JA4 runtime is used | Path A exact signature matching |
| `server_name` | populated when Zeek observed SNI | SNI length and entropy evidence |
| `sni_length` / `sni_entropy` | supplied by detector-v2 when SNI is present | metadata heuristic |
| `has_ja3` / `has_ja3s` | available | no — presence of *a* fingerprint says nothing about which |
| `cipher_encoded` | available | **no, deliberately.** Upstream computes it as `(cipher_name_length % 16) + 1` — a function of how long the cipher's *name* is, not of which cipher was negotiated. Their own README marks it a placeholder. It is not mapped onto `TlsInfo` at all |

**Consequence:** the signature path can match configured JA4 indicators on
qualified PCAP ingestion. Captures without a real fingerprint or configured
indicator still produce no signature claim.

### This does not prove malware

* Encrypted traffic is **not decrypted**, and metadata is not proof.
* A high-entropy hostname is routine for CDNs, cloud buckets and ad exchanges.
* ECH hides SNI entirely, and so does plain absence of the field.
* Exact fingerprints are only as trustworthy as the feed they came from, and
  they change — JA3 in particular varies with TLS library versions.
* Timing and periodicity belong to `C2BeaconingDetector`; none of it is
  computed here. A flow can legitimately raise both.

### QUIC, and what "encrypted-traffic detection" means here

Worth stating precisely, because the phrase invites assumptions:

* Detection reads **observable TLS metadata** — SNI length and entropy,
  negotiated version, and JA3/JA3S/JA4 when those fields are present. That is
  handshake and header material a sensor can see without holding a key.
* **No payload is decrypted, ever.** Not TLS, not QUIC. There is no key
  material anywhere in this project and no code path that would use one.
* **QUIC-specific fingerprint extraction is not implemented.** Ingestion emits
  no QUIC metadata today, and nothing here derives a QUIC fingerprint. A
  detector that claimed otherwise would be reporting on data it does not have.
* **UDP/443 is not treated as malicious.** Neither the port nor the transport
  is a signal in any detector; a QUIC flow simply carries no TLS block and so
  contributes nothing to the encrypted-malware path.
* The extension point is real but unbuilt: `TlsInfo` already carries optional
  fingerprint and SNI fields, and the adapter preserves whatever ingestion
  supplies, so **observable** QUIC metadata (a QUIC Initial fingerprint, an
  SNI from an unencrypted ClientHello) could be populated and matched with no
  schema change. That is an ingestion capability, not a detection gap we can
  close on our own.

**If a reviewer asks "your problem statement mentions QUIC — do you support
it?"** — the accurate answer is: *we detect on encrypted traffic without
decrypting it, using observable TLS metadata such as SNI characteristics and
JA3/JA3S/JA4 fingerprints. QUIC-specific metadata extraction is an ingestion
integration we have not built, and we deliberately do not label UDP/443 as
malicious on its own. The schema already accepts observable QUIC metadata
when ingestion can provide it, and no part of the design depends on payload
decryption.*

## DGA ML baseline (offline — Part 1)

**What DGA is.** Malware often does not hardcode its controller's address.
Instead it runs a *domain generation algorithm*: both the malware and the
attacker derive the same list of pseudo-random domains from a shared seed
(often the date), and the malware tries them until one resolves. Blocking a
single domain therefore achieves nothing — the next batch appears tomorrow.
The tell is that generated names look nothing like names humans register:
`kqxvbzmwjrph.com` versus `wikipedia.org`.

**Pipeline.** `raw domain → lexical features → Random Forest → dga_score`

> ### Raw query and model requirements
> The live `DGADetector` **is** implemented and wired into the factory — see
> "Phase 2 — the live detector" below. Profile selection is explicit:
> The frozen legacy `ingestion/features.jsonl` profile does not expose the raw
> `dns.query`; the explicit `detector-v2` profile does. The legacy profile carries
> only derived values — `query_entropy`, `query_length`,
> `subdomain_entropy`, `is_txt`, `label_count`. A classifier needs the actual
> domain text and reconstructing it from an entropy number is impossible, so
> against the legacy profile the detector is correctly silent. The adapter already
> preserves `dns.query` whenever it appears; nothing further is needed on the
> detection side.

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
  fraction in `[0, 1]`. That is why it is not called a probability, and why
  the live detector publishes `score_type: rule_score` — `calibrated_model`
  would be a false claim until calibration is actually done.
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

### Phase 2 — the live detector

Phase 1 above is the *offline* half: features, dataset, model, training.
**Phase 2 is `DGADetector`** — a thin wrapper that puts that model on the
live path:

```
FlowEvent.dns.query → normalize_domain() → DGAModel.predict_domain() → ThreatAlert
```

No DGA feature logic lives in the detector. Normalization and feature
extraction are *imported from Phase 1 and called*, never reimplemented — a
second copy of that arithmetic would drift from whatever the model was
trained on and quietly invalidate every score. A test asserts the detector
source contains none of it.

```python
from detection_core import DGAConfig, DGADetector

detector = DGADetector(model=fitted_model)              # or
detector = DGADetector(model_path="artifacts/dga.joblib",
                       config=DGAConfig(score_threshold=0.75))
```

> **Trust the artifact.** A bundle is loaded with `joblib`, a pickle-style
> format that can execute code on load. Load only model files you produced
> yourself or otherwise trust — never one from an untrusted source, and never
> one fetched at runtime from somewhere unverified.

One of `model=` / `model_path=` is required. There is deliberately **no
fallback to an untrained or stub model**: a detector that silently scores
everything 0.0 looks healthy in a dashboard while detecting nothing. A
missing path, a non-bundle, a stale `format_version` and a feature-schema
mismatch each raise a message naming the problem.

**It needs a raw `dns.query`.** Run ingestion with `--feature-profile
detector-v2`; the adapter preserves `query` / `qtype` / `rcode` and leaves them
`None` when Zeek did not observe them. Live DGA classification additionally
requires an explicitly configured, compatible model bundle; no model artifact
is committed or silently fetched.

The derived `dns.query_entropy` / `query_length` that *are* available today
are deliberately not used as a stand-in: the model was trained on ~20 lexical
features extracted from the full name, and feeding it two of them would not
be the same model.

### The score is not a probability

`RandomForestClassifier.predict_proba` gives a class-1 vote fraction, and
Phase 1 documents it as **not calibrated**. So it is not published as one:

* `score_type` is **`rule_score`**, never `calibrated_model`.
* The alert `score` is a deterministic function of how far the model score
  exceeds `score_threshold` — at the threshold it is 0.5, at a model score of
  1.0 it is 1.0, linear between.
* The model's own number travels in the evidence as **`dga_model_score`**,
  alongside `model_score_is_calibrated: false` and a note saying so plainly.

> `score_threshold` defaults to **0.75** and is **untuned**. Re-derive it from
> a precision/recall sweep over a real benign+DGA dataset; the Phase-1
> training entry point already reports the numbers needed.

Repeats are suppressed per `(src_ip, normalized_domain)` for
`cooldown_seconds` — malware re-queries the same name constantly, and the
finding is the domain, not each lookup. There is no severity-escalation
escape hatch here, unlike the windowed detectors, because the model is
deterministic: the same domain always scores the same, so a repeat lookup is
the same finding rather than a worse one.

**Importing is cheap; constructing is not.** `detection_core.ml` pulls in
scikit-learn, joblib and numpy, which stay an optional extra so
`import detection_core` works with pydantic alone. The Phase-1 import
therefore happens inside `DGADetector.__init__`, not at module scope — a test
asserts sklearn never leaks into a plain `import detection_core`.

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

* depend on `FlowEvent`, never on `features.jsonl` or `ingestion`;
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

* **Adapter isolation.** When a detector profile changes its output, only
  `adapters/ingestion_jsonl.py` and `adapters/encodings.py` should change.
* **Strict core, honest optionals.** Required flow fields validate or the
  record is skipped; fields ingestion cannot supply are `None`, never invented.
  See "Profile capabilities" in `SCHEMA.md`.
* **Frozen models.** The engine hands one `FlowEvent` to every detector, so
  immutability prevents cross-detector contamination.
* **Event time, approximately in order.** Every rolling window, cooldown and
  expiry is driven by `FlowEvent.timestamp`, never wall clock, so a PCAP
  replay behaves exactly like a live stream. Records are expected to arrive in
  approximately non-decreasing event-time order. There is **no reorder
  buffer**: a badly out-of-order record is simply measured where it lands.
* **Ingestion's global window features are deliberately ignored** — that
  upstream logic is still being corrected. See `SCHEMA.md`.
