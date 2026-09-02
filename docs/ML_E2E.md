# ML detection pipeline: assembly, reproduction, and per-detector evaluation

Everything needed to rebuild the ML half of the pipeline from a clean clone and
to reproduce the numbers below. Nothing in `detection/detection_core/` was
changed to produce any of this — the detectors, `ThreatAlert v1.1`,
`ml/dga/features.py`, `ml/dga/model.py` and the DGA dataset/training code are
untouched.

Two things exist here that did not before: the **model artifact is
reproducible on demand** (`tools/build_dga_model.py`), and detector quality is
measured **per detector against every traffic type**, not only against its own
attack (`tools/detector_matrix.py`, `tools/dga_capture_eval.py`).

---

## 0. One-time environment

`detection_core` needs only `pydantic`. The DGA model needs the optional `ml`
extra, which is not installed by default so `import detection_core` stays cheap.

```bash
# pip
detection/.venv/Scripts/python -m pip install -e detection[ml]

# uv (what was used here)
uv pip install --python detection/.venv/Scripts/python.exe \
    "numpy>=1.26" "scikit-learn>=1.4" "joblib>=1.3" "pytest>=8"
```

Without it, `build_default_detectors()` returns **six** detectors and
`dga_domain` never fires. That is deliberate — there is no stand-in model,
because one scoring everything 0.0 would look healthy on a dashboard while
detecting nothing.

---

## 1. Rebuild the DGA model artifact

`artifacts/dga_model.joblib` is ~12.6 MB, is gitignored on purpose
(`.gitignore: artifacts/`, `detection/.gitignore: *.joblib`), and is therefore
**absent from a fresh clone**. It is a build product, deterministic from the
committed sample dataset, and takes seconds to rebuild.

```bash
python tools/build_dga_model.py            # build if absent
python tools/build_dga_model.py --force    # always retrain
python tools/build_dga_model.py --check-only
```

This wraps the frozen training entry point — there is only one training
implementation:

```bash
cd detection
python -m detection_core.ml.dga.training \
    -i detection_core/ml/dga/data/dga_dataset.sample.csv \
    -o ../artifacts/dga_model.joblib
```

`build_dga_model.py` adds verification that a zero exit code does not give you:
the bundle loads, its 19-feature schema matches this build of `features.py`,
`build_default_detectors(dga_model_path=…)` really returns **seven** detectors
with `dga_domain` among them, and the model separates a generated name from a
benign one (`kq7vbzxmwnrlpd.com → 0.965`, `www.google.com → 0.458`, threshold
0.75).

`tools/run_demo.py::ensure_dga_model()` already does the build silently on
first run; this is the explicit, verifying version for when you need to know
*why* only six detectors registered.

### Training result (committed sample, family-disjoint, deterministic)

```
rows              : 4008  (benign 2004 / dga 2004, 0 duplicates)
split             : group_disjoint  (group_aware=True)   train 2957 / test 1051
dga families      : 27 total -> 20 train, 7 held out for test (disjoint)
held-out families : banjori, necurs, newgoz, nymaim, pitou, qadars, simda
threshold         : 0.75
```

| metric @ unseen families | RandomForest | LogisticRegression baseline |
|---|---|---|
| PR-AUC (raw scores) | **0.9116** | 0.9177 |
| ROC-AUC (raw scores) | **0.8995** | 0.8946 |
| precision @ 0.75 | **0.9444** | 0.9395 |
| recall @ 0.75 | **0.7109** | 0.6782 |
| F1 @ 0.75 | **0.8112** | 0.7878 |
| tp/fp/tn/fn | 391/23/478/159 | 373/24/477/177 |

These reproduce `detection/docs/dga_model.md` §4 exactly (`random_state=42`).
That document's **"For the shipped model"** placeholder block is still empty and
should be filled in by whoever owns `detection/docs/` — the numbers above are
for the *sample* dataset, not a larger rebuild.

---

## 2. End-to-end run (all seven detectors)

The ingestion layer needs Zeek, Docker and a compiled Rust extension; none is
available in this environment (`cargo`, `docker` absent, `ingestion_core` not
importable). `tools/synth_flows.py` writes the **same record shape**
`ingestion/pipeline.py` writes, so everything downstream runs unchanged.

> **`ingestion/features.jsonl` is stale.** It is a 2-flow, HTTP-only sample
> (epoch 1747147647 ≈ 2025-05-13) from the *pre-fix* pipeline: no `dns` block,
> no `tls` block, `host`/`uri`/`user_agent` all null, and it still carries the
> globally-scoped window fields including the `flow_rate: 1000000.0` artefact
> the current `pipeline.py` docstring describes as a defect. Four of the seven
> detectors are structurally unable to fire on it. Do not use it to test
> detection.

```bash
# 1. labelled multi-attack capture (deterministic from --seed)
python tools/synth_flows.py -o data/features.jsonl --seed 26145 --duration 600

# 2. the real path: adapter -> engine -> 7 detectors -> ThreatAlert v1.1
cd detection
python -m detection_core.runner ../data/features.jsonl \
    --dga-model ../artifacts/dga_model.joblib \
    --ja3-feed ../tools/ja3_feed.example.txt \
    --output ../data/alerts.jsonl

# 3. alert-level scoring against the generator's ground truth
python tools/evaluate.py --alerts data/alerts.jsonl \
    --manifest data/features.manifest.json
```

`--ja3-feed` is not optional for a full demo: the `encrypted_malware`
signature path is inert without it by design (the detection layer never
downloads a feed).

---

## 3. Per-detector behaviour matrix

```bash
python tools/detector_matrix.py --seeds 20 -o data/detector_matrix.json
```

Runs **each detector alone against each traffic type alone** — its own attack,
the benign background, the four confounders, and the other six attacks. A
mixed-capture score cannot distinguish a precise detector from one that fires
on everything; this can.

The slices are labelled *by construction*: the harness replays
`synth_flows.generate`'s exact RNG sequence and keeps each producer's output
separately, so the concatenated slices are byte-identical to the capture
`synth_flows` writes. `--verify-against data/features.jsonl` asserts that
identity before scoring and refuses to run if it has drifted.

### Result — 20 seeds, 1 820 detector×slice trials

> **The `dga_domain` rows below are the BEFORE figures.** They were measured
> against the model trained on the Tranco-only corpus. The corpus has since
> gained 1 824 real CDN hostnames and the threshold has been re-derived, taking
> that detector from precision 0.333 to **1.000** on this same matrix with
> recall unchanged. See [`DGA_PRECISION.md`](DGA_PRECISION.md); the other six
> detectors are unaffected and their numbers still stand.

One trial = one detector over one traffic slice. TP/FN are counted over
target-slice trials; FP/TN over benign + other-attack trials.

| detector | TP | FP | FN | TN | FP on benign | FP cross-attack | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| port_scan | 40 | 0 | 0 | 220 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| ddos | 20 | 0 | 0 | 240 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| encrypted_malware | 20 | 0 | 0 | 240 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| data_exfiltration | 20 | 0 | 0 | 240 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| dns_tunnelling | 20 | 7 | 0 | 233 | 7 | 0 | 0.741 | 1.000 | 0.851 |
| **dga_domain** | 20 | 40 | 0 | 200 | 20 | 20 | **0.333** | 1.000 | 0.500 |
| **c2_beaconing** | 20 | 63 | 0 | 177 | 42 | 21 | **0.241** | 1.000 | 0.388 |

Where the false positives land:

| detector | slice | fired | mechanism |
|---|---|---|---|
| c2_beaconing | `conf_ntp` | 20/20 | NTP at 64 s, CoV **0.0040** → score 0.794 `high` |
| c2_beaconing | `conf_backup` | 20/20 | backup at ~56 s, CoV 0.106 → 0.641 `medium` |
| c2_beaconing | `attack_encrypted_malware` | 13/20 | implant sessions ~6.5 s apart, CoV 0.156 → 0.566 `low` |
| c2_beaconing | `attack_exfiltration` | 8/20 | uploads ~5.1 s apart, CoV 0.186 → 0.522 `low` |
| c2_beaconing | `benign_web` | 2/20 | ordinary browsing DNS to the resolver |
| dga_domain | `conf_cdn` | 20/20 | `d3f7k2mq9xz1lp.cloudfront.test` → model 0.985 → 0.97 `critical` |
| dga_domain | `attack_dns_tunnel` | 20/20 | 48-char tunnel subdomain → model 0.825 → 0.65 `medium` |
| dns_tunnelling | `conf_cdn` | 7/20 | CDN names ~33 chars, suspicious_ratio 0.8 → 0.65 `medium` |

### The same detectors, in situ (all seven together, 20 mixed captures)

Alert-level scoring against the generator's manifest, 490 alerts:

| threat class | runs fired | alerts | TP | FP | FN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|
| port_scan | 20/20 | 80 | 80 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| ddos | 20/20 | 60 | 60 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| dns_tunnelling | 20/20 | 20 | 20 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| encrypted_malware | 20/20 | 60 | 60 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| data_exfiltration | 20/20 | 20 | 20 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| **c2_beaconing** | 20/20 | 131 | 64 | 67 | 0 | **0.489** | 1.000 | 0.656 |
| **dga_domain** | 20/20 | 119 | 20 | 99 | 0 | **0.168** | 1.000 | 0.288 |

**The two views disagree, and the disagreement is the useful part.**
`dns_tunnelling` scores 0.741 isolated but 1.000 in situ: its two CDN
confounder hosts (`10.4.2.5`, `10.4.2.11`) also browse the web in the mixed
capture, so their share of long high-entropy queries falls below the ratio
threshold. Isolation removes that dilution, so it is the harsher and more
conservative test. `c2_beaconing` moves the same way (0.241 → 0.489).
Neither number is wrong; run both.

## 4. DGA model on capture domains

```bash
python tools/dga_capture_eval.py --seeds 20 --dedupe
```

The training report scores the model against Tranco top-sites. On the wire the
negative class is whatever this network looks up — including the CDN
confounder and 48-character DNS-tunnel subdomains, neither of which is in the
training distribution. This scores every DNS query in the capture instead.

### Result — 20 captures, threshold 0.75

| population | n | pos/neg | ROC-AUC | PR-AUC | P@0.75 | R@0.75 | F1 |
|---|---|---|---|---|---|---|---|
| every query | 15 703 | 600 / 15 103 | 0.9889 | 0.8197 | 0.232 | 0.985 | 0.375 |
| distinct domains | 1 810 | 600 / 1 210 | 0.9653 | 0.9737 | 0.329 | 0.985 | 0.494 |
| distinct, tunnel subdomains excluded | 610 | 600 / 10 | 0.9522 | **0.9989** | **0.995** | 0.985 | **0.990** |

Per-slice score distribution (distinct domains):

| slice | label | domains | ≥0.75 | min | mean | max |
|---|---|---|---|---|---|---|
| `benign_web` | benign | 6 | **0** | 0.268 | 0.378 | 0.548 |
| `conf_cdn` | benign | 4 | 3 | 0.460 | 0.757 | 0.985 |
| `attack_dga` | DGA | 600 | 591 | 0.365 | 0.972 | 1.000 |
| `attack_dns_tunnel` | benign* | 1 200 | **1 200** | 0.780 | 0.849 | 0.875 |

\* labelled negative because the *alert class* should be `dns_tunnelling`, not
`dga_domain`. Lexically the model is not wrong — those subdomains genuinely are
machine-generated — which is why the third row above (which excludes them) is
the fairer read of the classifier, and why the second row is the fairer read of
the **detector**: the alert it raises names the wrong threat.

Ranking is strong everywhere (ROC-AUC 0.95–0.99). Every decision-metric problem
is the **threshold**, not the model: 0.75 is documented as untuned
(`DGAConfig.score_threshold`) and it sits below the CDN and tunnel score bands.
Ordinary browsing tops out at 0.548, so the model does separate real benign
DNS cleanly.

## 5. Ingestion field audit

```bash
python tools/ingestion_field_audit.py data/features.jsonl
python tools/ingestion_field_audit.py ingestion/features.jsonl   # the stale sample
```

Pushes a capture through the **real** adapter and reports, per FlowEvent field,
how many flows came out with a usable value, then maps that against what each
detector actually dereferences. A field that is null on every flow is a field a
detector cannot use, whatever the schema promises.

### Result — for the ingestion team

Measured on 2 041 flows (817 with `dns`, 736 with `tls`, 0 with `http`), all
2 041 parsed, 0 json errors, 0 validation errors. `synth_flows.with_dns` /
`with_tls` emit key-for-key what `pipeline.py::_dns_block` / `_tls_block` emit,
so these findings transfer to the real feed.

**1. `tls.ja4` — the one hard gap. 0/736 flows.**
It is the only field any detector dereferences that never arrives.
`EncryptedMalwareDetector` reads it at `detectors/encrypted_malware.py:634-638`
(`for fingerprint_type in ("ja3","ja3s","ja4"): getattr(tls, fingerprint_type)`),
so a JA4 line in a `--ja3-feed` is silently unmatchable today. Chain:

| where | state |
|---|---|
| `scripts/run_zeek.sh --ja4` | selects the `activecm/zeek` image, which **does** write the column |
| `src/zeek_parser/types.rs:36-44` | `SslRecord` has `ja3`, `ja3s` — **no `ja4` field** |
| `src/zeek_parser/ssl_log.rs:27-28` | parser reads `ja3`/`ja3s` only |
| `src/features/tls_features.rs:8-9` | derives `has_ja3`/`has_ja3s` — no `has_ja4` |
| `pipeline.py:339` | `"ja4": None` — hard-coded, absent rather than faked |

Needs a Rust change (one field + one parser line + one derived flag).

**2. Everything else a detector reads does arrive.** Verified per field:
`src_ip`, `dst_ip`, `dst_port`, `proto`, `timestamp`, `duration`,
`orig_bytes`/`resp_bytes`, `orig_pkts`/`resp_pkts`, `conn_state`, `flow_id`,
`uid` at 100%; `service` at 77.1% (null where Zeek has none, which is correct);
every `dns.*` field at 100% of DNS flows; `tls.ja3`, `tls.ja3s`, `tls.version`,
`tls.has_ja3`, `tls.has_ja3s` at 100% of TLS flows; `tls.server_name`,
`tls.sni_length`, `tls.sni_entropy` at 97.8% (absent only where there is no
SNI). **All six non-DGA detectors and `dga_domain` report no missing input.**

**3. Two fields ingestion emits that the adapter does not know.**
`orig_ip_bytes` and `resp_ip_bytes` (`pipeline.py:484-485`) are on 2 041/2 041
lines and raise a schema-drift warning on every run:

```
WARNING adapters.ingestion_jsonl: schema drift: unknown ingestion field
  'orig_ip_bytes' (first seen line 1); kept in FlowEvent.extra
```

They are not lost — they land in `FlowEvent.extra` — but nothing reads them and
the warning is noise on every run. Either add them to
`adapters/encodings.py::KNOWN_TOP_LEVEL_FIELDS`, or drop them upstream.
**Detection-side change; not made here.**

**4. Four nested fields are silently dropped.** Nested blocks are not
drift-checked (only top-level keys are, `ingestion_jsonl.py:410`), so extra keys
inside `dns` / `tls` vanish without a warning:

| dropped | verdict |
|---|---|
| `dns.qtype_num`, `dns.rcode_num` | harmless — the named forms arrive and are what detectors read |
| `tls.ssl_version_encoded` | harmless — used as the fallback for `tls.version`, just not stored |
| `tls.cipher` | genuinely discarded; ingestion computes it, no detector reads it |

**5. `conn_state_encoded` still cannot express `S0` — and this now costs
recall.** `src/features/flow.rs:50-65` has no `"S0"` arm, so S0 falls to
`_ => 0` and `decode_conn_state(0)` returns `None` — the `encodings.py:25-28`
TODO is still accurate about the *encoded* field. Current `pipeline.py` works
around it by emitting the raw `conn_state` string as well.

**This item was "nothing is broken" when it was written, and it is not any
more.** `port_scan` 0.3.0 reads `conn_state` (`detectors/port_scan.py`,
`_responder_refused`) and falls back to a responder-payload proxy when a
window does not carry one. On UNSW-NB15, the one real dataset with a usable
connection state, the difference is measured: **recall 1.000 with `conn_state`
against 0.500 without**, at precision 1.000 either way
(`docs/REAL_DATA_EVAL.md` §10). The proxy is safe — it never suppresses a
window on evidence it does not have — but it cannot see banner-grabbing recon,
which completes its connections and is invisible without the state.

So the raw string is now load-bearing for a detector, and any path that keeps
only the encoded form loses the signal. The stale `ingestion/features.jsonl`
sample carries only the encoded form.

**6. HTTP is untested end to end.** No detector reads `http.*`, and the
synthetic capture emits no HTTP block, so `HttpInfo` is exercised only by the
stale 2-flow sample — where `host`, `uri` and `user_agent` are all null.

---

## Honesty note that applies to every number in §3–§4

These are measured on **synthetic labelled traffic**. They characterise
detector *behaviour and separation* — does it fire on its target, does it stay
quiet on confounders purpose-built to fool it. They are **not** a production
false-positive rate: a real network's benign traffic is far more varied than
four confounders, and no generator substitutes for a real benign capture.
A true FPR needs a real capture from the deployment network, which is a
dependency on the ingestion team, not on detection.
