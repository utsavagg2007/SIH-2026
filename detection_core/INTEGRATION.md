# Detection integration handoff

What the Detection module needs from other people, and how to check it arrived.

Detection itself is finished and validated against controlled synthetic input:
all seven threat classes fire end to end through the real adapter, engine and
detectors, and every alert conforms to ThreatAlert v1.1. What remains is not
Detection code — it is **data**: ingestion fields we already parse but nobody
emits yet, and real captures we do not have.

Nothing in this document asks anyone to change Detection.

---

## 1. Ingestion fields Detection is waiting for

Detection **already parses and preserves every field below, losslessly**. They
are not implemented-and-untested; they are tested — see
`tests/test_seven_threat_integration.py::test_the_adapter_preserves_every_awaited_field`,
which feeds a record containing all of them and asserts each arrives unchanged.
The moment ingestion emits them they reach the detectors with no Detection-side
change at all.

### Critical — a detector is dormant without these

| field | who needs it | why it cannot be worked around |
|---|---|---|
| `dns.query` | `dga_domain` | The classifier reads 19 lexical features off the **domain text**. Entropy and length are two of them; the other 17 cannot be recovered from a number. Without the string the detector is correctly silent. |
| `tls.server_name` | `encrypted_malware` (metadata path) | SNI length and entropy are derived from the name. `sni_length`/`sni_entropy` are accepted as a fallback if ingestion computes them. |
| `tls.ja3` | `encrypted_malware` (signature path) | Exact-match against the configured local feed. |
| `tls.ja3s` | `encrypted_malware` | Server-side counterpart, matched separately. |
| `tls.ja4` | `encrypted_malware` | Matched separately again. |

### Useful — improves evidence, nothing is blocked

`dns.qtype`, `dns.rcode`, `tls.version`, top-level `uid`, `src_port`,
`service`, the raw `conn_state` string, and a numeric event `timestamp`.

> **Please send raw strings, not encoded ids.** A JA3 hash turned into an
> integer, or a domain replaced by a category code, is unusable: the
> fingerprint match is an exact string comparison and the DGA features are
> computed from the characters. If a field must be encoded for some other
> consumer, please send the raw value **as well**.
>
> One known upstream gap, for whoever owns the encoder: `conn_state`'s
> encoding has no entry for Zeek's `S0` (connection attempt, no reply), so
> `S0` encodes to `0` and is indistinguishable from "unknown". `S0` is a
> primary port-scan signal.

### Acceptance checks — how to confirm a field landed

Each is a one-command check against real ingestion output:

```bash
# 1. The adapter sees the raw values, unmodified.
python -c "
from detection_core.adapters import IngestionJsonlAdapter
for flow in IngestionJsonlAdapter(path='features.jsonl'):
    if flow.dns and flow.dns.query: print('dns.query   ->', flow.dns.query)
    if flow.tls and flow.tls.ja3:   print('tls.ja3     ->', flow.tls.ja3)
    if flow.tls and flow.tls.server_name: print('server_name ->', flow.tls.server_name)
"
```

| field | passes when |
|---|---|
| `dns.query` | the printed string equals the queried name exactly — same case, same dots, no truncation |
| `tls.ja3` / `ja3s` / `ja4` | the printed value is the full fingerprint; for JA3/JA3S a 32-character hex digest |
| `tls.server_name` | the printed hostname is the real SNI |
| `timestamp` | `flow.timestamp` matches the record's own numeric time rather than being recovered from `flow_id` |
| any of them | the run logs no schema-drift warning naming that field |

Then the end-to-end check:

```bash
python -m detection_core.runner features.jsonl --output alerts.jsonl \
    --dga-model artifacts/dga_model.joblib \
    --ja3-feed fingerprints.txt
```

`dga_domain` alerts require `dns.query` **and** a model; `encrypted_malware`
signature alerts require a fingerprint field **and** a feed entry that matches.
If a class stays silent, check the input has the field before suspecting the
detector — the seven-class test proves the wiring works when the field is
present.

---

## 2. Real data we do not have

| need | what for | what it unblocks |
|---|---|---|
| **Representative attack capture** — scan, DDoS, beacon, DNS tunnel, exfil, DGA, a TLS fingerprint/SNI case | demo and tuning | Every threshold currently ships as an untuned initial heuristic. They were chosen to fire on obvious synthetic cases and **must** be re-derived against real traffic before anyone quotes a detection rate. |
| **Real benign capture**, ideally hours of ordinary network traffic | false-positive measurement | Today we can only say: the repository's real sample is **2 flows, 0 alerts** — an integration smoke test, not a rate. Synthetic benign runs (10k and 50k flows, 0 alerts) describe the generator, not the world. **We cannot state an empirical false-positive rate without this.** |
| **Real DGA dataset with genuine family/seed metadata** | model quality | The committed fixture is 43 domains and scores 1.0 on everything, which proves the plumbing and nothing else. Family-aware splitting is implemented-ready but deliberately **not** enabled: the dataset contract has no family column, and deriving "families" from domain text would fabricate the very labels the split exists to respect. |
| **A trusted JA3/JA3S/JA4 list** | signature path | No indicator list ships here. The loader is local-file only and downloads nothing; keeping a feed current is an operational task. |

---

## 3. Running Detection today

Local output only — no backend needed:

```bash
python -m detection_core.runner features.jsonl --output alerts.jsonl
```

Everything enabled:

```bash
python -m detection_core.runner features.jsonl \
    --output alerts.jsonl \
    --config detector_config.toml \
    --ja3-feed fingerprints.txt \
    --dga-model artifacts/dga_model.joblib
```

With a backend as an additional destination (substitute your own endpoint):

```bash
python -m detection_core.runner features.jsonl \
    --output alerts.jsonl \
    --api-url http://<backend-host>:<port>/api/v1/alerts
```

Exit codes: `0` clean, `1` startup or fatal error, `2` the capture was fully
processed but some alerts did not reach the backend (the local file is still
complete). Alert JSONL goes to stdout when `--output` is omitted; logs always
go to stderr, so `| jq` and `> alerts.jsonl` both work.

Train a model from a labelled CSV (`domain,label`):

```bash
python -m detection_core.ml.dga.training --input domains.csv \
    --output artifacts/dga_model.joblib
```

---

## 4. What Detection does not do

Stated plainly so nobody promises it downstream:

* **No payload decryption**, TLS or QUIC. There is no key material in this
  project and no code path that would use one.
* **No QUIC fingerprint extraction.** UDP/443 is not treated as malicious;
  neither port nor transport is a signal in any detector. The schema can
  carry observable QUIC metadata when ingestion can produce it.
* **No incident correlation.** `incident_id` is always `null`; grouping alerts
  into incidents is the backend's job.
* **No alert storage, retry queue or WebSocket.** Detection POSTs one alert
  per request and keeps a local JSONL copy; persistence and broadcast belong
  to the backend.
* **No automatic threat-feed download.** Every input is a local file.
