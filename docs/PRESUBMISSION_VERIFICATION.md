# Final pre-submission verification — 2026-10-04

Scope: integrate Advitya's final ingestion work with the ML/detection pipeline,
confirm nothing regressed, and re-derive the documented accuracy figures. **No
model was re-tuned and no detector threshold was changed.** The only code change
in this commit is a reset of a leaked test-fixture file; everything else is
documentation corrections.

**`schemas/threat_alert.py` is byte-identical** — blob `0b087a49`, SHA-256
`81b6c44e…`, 4 824 bytes. Unchanged against HEAD, and **the same blob on
`origin/compiled`**, so merging Advitya's branch cannot alter it. Every alert
produced during verification round-tripped through `ThreatAlert.model_validate`
at `schema_version 1.1`.

Environment: Python 3.12.12, scikit-learn 1.9.1, numpy 2.5.3. The documented
figures were originally measured on scikit-learn 1.5.1 / numpy 1.26.4; where
that matters it is called out below.

---

## Part 1 — Advitya's final ingestion work

His final work is the **NetFlow v5 / v9 subsystem** (16 commits,
`228b9d7`…`d1e634a`, merged to `compiled` as `678728b` on 2026-10-04).

**It does not touch `detection/` at all.** `git diff bfd5062 origin/compiled --
detection/` is empty. The changes to the shared canonical layer are purely
additive: `canonical/time.rs` gains `unix_nanoseconds_to_rfc3339`,
`canonical/id.rs` gains NetFlow ID namespaces (the Zeek marker and namespace are
untouched, so existing Zeek record IDs are stable), and `TelemetrySource` gains
`netflow_v5` / `netflow_v9` alongside an unchanged `Zeek`.

`data/features.manifest.json` differs only in regenerated timestamps
(`generated_at`, `base_time`, interval bounds). Flow counts, labels, confounder
notes and `mimics` fields are identical — no detection semantics changed.

### What actually reaches Detection (empirical, through the real adapter)

Records fed through `IngestionJsonlAdapter.from_lines`, reading the resulting
`FlowEvent`:

| field | `legacy-m1d` | `detector-v2` | NetFlow-shaped |
|---|---|---|---|
| `conn_state` (S0) | `None` | `'S0'` | `None` |
| `dns.query` | `None` | raw string | `None` |
| `tls.server_name` | `None` | raw SNI | `None` |
| `tls.ja3` / `ja3s` / `ja4` | `None` | all three | `None` |

Under `legacy-m1d` all six detector-critical raw fields are absent. `S0`
specifically is unrecoverable there: `CONN_STATE_BY_CODE` has no entry for code
0, so a scan's `S0` is indistinguishable from "unknown" — the adapter's
`record.get("conn_state") or decode_conn_state(...)` prefers the raw field
precisely because of this.

### Is `detector-v2` the default now?

**It depends on the entry point, and Advitya's final work changed neither:**

* `ingestion/pipeline.py` — default **`legacy-m1d`** (`LEGACY_FEATURE_PROFILE`,
  line 65/635). Raw fields are lost unless `--feature-profile detector-v2` is
  passed.
* `pcap_dataset/ingest.py` — default **`detector-v2`**
  (`DATASET_FEATURE_PROFILE`, line 46). Raw fields carry by default.

So the PCAP dataset path is detector-ready by default; the Zeek pipeline CLI is
opt-in. This is unchanged from the previous integration.

### Detector consumption

`port_scan` reads `conn_state`/`S0` (with a documented byte-proxy fallback and a
`min_conn_state_coverage` gate), `dga_domain` reads raw `flow.dns.query`, and
`encrypted_malware` reads `tls.ja3`/`ja3s`/`ja4` and `server_name`. All three
consume the adapter's output losslessly. **No adapter reconciliation was
needed** — his changes shifted no field name or shape that detection reads.

### NetFlow cannot currently reach Detection

`pub mod netflow` is declared in `ingestion/src/lib.rs`, but the
`#[pymodule] ingestion_core` exports 14 functions and **none is NetFlow**. There
is no `[[bin]]` target, no `fn main`, and no NetFlow JSONL writer wired to
`pipeline.py` or `detector_profile.py`. The subsystem is a self-contained,
well-tested Rust library with no Python consumer.

This is not a regression — it is new additive work — but **"NetFlow support"
must not be presented as end-to-end**. A NetFlow-shaped record does degrade
safely if one is hand-fed to the adapter: no crash, no skip, a `schema drift:
unknown ingestion field 'source'` warning, and `source` retained in
`FlowEvent.extra`. It carries no DNS/TLS/conn_state, so the DNS- and
TLS-dependent detectors would starve on a NetFlow-only feed — inherent to
NetFlow, which has no DNS query strings, SNI or JA3.

---

## Part 2 — Regression check

* **Detection suite: 1 843 passed, 0 skipped.** Baseline on the same tree was
  1 842 passed + 1 skipped; the skip was the DGA-artifact test, which runs once
  `artifacts/dga_model.joblib` exists. No failures, no drop.
* `pcap_dataset/test_ingest.py`: 57 passed.
* ThreatAlert v1.1 byte-identical (above); 16/16 alerts validated, all
  `schema_version 1.1`, all `model_dump` round-trips clean.

---

## Part 3 — Do the documented numbers still hold?

### DGA model — reproduced

Corpus as shipped: 16 939 rows (benign 10 824 / DGA 6 115, 0 duplicates),
`group_disjoint` split, train 12 295 / test 4 644, 27 families → 20 train / 7
held out. Every structural figure matches the documentation exactly, including
`label_count` feature importance **0.0830** (documented 0.083).

The operating-point recall column in `detectors.dga-precision.toml` and
`DGA_PRECISION.md` §5 reproduces **exactly**:

| threshold | documented | re-run |
|---|---|---|
| 0.60 | 0.723 | 0.7229 |
| **0.65 (shipped)** | **0.711** | **0.7110** |
| 0.70 | 0.667 | 0.6667 |
| 0.75 | 0.569 | 0.5691 |

At 0.75: precision 0.8953 (documented 0.8981), ROC-AUC 0.8914 (0.8931), PR-AUC
0.8437 (0.8478). `DGA_PRECISION.md` §3 quotes recall 0.4732 at 0.75; that is the
scikit-learn 1.5.1 reading, which the document and the TOML both record
explicitly. On 1.9.1 it reads 0.5691 — matching the §5 column. Artifact size
33.9 MB, as documented.

### Per-detector matrix — `tools/detector_matrix.py --seeds 20` (1 820 trials)

| detector | documented | re-run | |
|---|---|---|---|
| `port_scan` | 1.000 / 1.000 | 1.000 / 1.000 | ✓ |
| `ddos` | 1.000 / 1.000 | 1.000 / 1.000 | ✓ |
| `dga_domain` | 1.000 / 1.000 | 1.000 / 1.000 | ✓ |
| `encrypted_malware` | 1.000 / 1.000 | 1.000 / 1.000 | ✓ |
| `data_exfiltration` | 1.000 / 1.000 | 1.000 / 1.000 | ✓ |
| `dns_tunnelling` | 0.741 / 1.000 | 0.741 / 1.000 | ✓ |
| `c2_beaconing` | 0.241 / 1.000 | **0.571 / 1.000** | **better** |

Six reproduce exactly. `c2_beaconing` is **better than documented**, not worse:
`c2_beaconing` 0.2.0 (commit `245e18d`) silenced the `conf_ntp` and
`conf_backup` confounders (both 20/20 → **0/20**) and the
`attack_exfiltration` cross-fire (8/20 → **0/20**). That commit updated the
real-data sections of `ML_E2E.md` but left its synthetic matrix stale; both that
table and `DGA_PRECISION.md` §7 are corrected in this commit. The detector
imports only stdlib, so this is genuine behaviour, not library drift.

### Full pipeline

`detection_core.runner` over the 2 041-flow capture with the shipped config:
2 041/2 041 parsed, 0 skipped, 0 detector errors, **16 alerts**, all 7 threat
classes firing. `dga_domain` emits exactly **1** alert — the real one,
`5d9ovxrkufbsf1o.com` from `10.4.2.19`, model score 0.99, `critical`, exactly as
documented. Documented total was 19; the 3-alert reduction is the same
`c2_beaconing` hardening described above.

### End-to-end — `tools/verify_e2e.py`: **30/30 checks passed**

Includes the three field checks that matter (`raw dns.query survives`, `raw
tls.ja3 and server_name survive`, `raw conn_state carries S0`), all seven threat
classes exercised, the dashboard WebSocket contract (`{type, data}` envelope,
evidence bars, class visual, two-letter threat code, throughput telemetry),
fusion dedup and kill-chain correlation across `10.4.2.19`, and analyst
citations.

### Not reproducible here

The **85 % real-traffic FP reduction** (1 797 → 267) and all CIC-IDS2017 /
UNSW-NB15 figures **could not be re-derived**: the datasets are not in the repo
(only `tools/cicids_to_features.py` and `tools/unsw_to_features.py`),
`pcap_dataset/raw/` is empty, and no Rust or Zeek toolchain is present on this
machine, so Advitya's NetFlow Rust tests and the real-PCAP path could not be
executed either. Those figures are carried forward from their original run, not
re-verified today. The synthetic proxy moved in the same direction — the two
benign confounders that drove the real `port_scan`/`c2_beaconing` FP volume are
now silent.

---

## Known weaknesses, unchanged and owned

* `c2_beaconing` precision is still the weakest (0.571 synthetic, **0.056 on
  real benign traffic**) — periodic-by-design benign sources remain the hard
  case.
* **DGA recall is the stated cost** of the CDN-corpus fix: 0.711 at 0.65, and
  subdomain-hosted DGA (`<random>.evil.com`) is largely missed — the corpus is
  99.5 % two-label. Needs multi-label DGA examples, not a threshold change.
* **No real-deployment FPR exists.** Every synthetic figure measures detector
  separation on generated flows, and Tranco/Umbrella are public lists, not a
  capture from the monitored network.
* DGA throughput ceiling ~14 DNS flows/sec — `n_jobs=-1` single-row predict
  overhead in frozen `model.py`, flagged for that file's owner.
