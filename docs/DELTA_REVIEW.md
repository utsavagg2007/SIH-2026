# Delta review: the four flagged bugs, and the state of ingestion

Scope of this change: the four defects raised on `integration/ml-consolidated`,
plus the ingestion-capability verification that determined how BUG 1 and BUG 2
had to be fixed.

**`schemas/threat_alert.py` is byte-identical** — blob `0b087a49`, unchanged
against HEAD, against the merge base `a134d03`, and against `origin/compiled`.
It is not in this diff. Every alert produced during verification round-tripped
through `ThreatAlert.model_validate` at `schema_version 1.1`.

Full suite: **1 776 passed, 0 skipped** (baseline before this change: 1 701
passed, 1 skipped — the skip was the DGA artifact test, which now runs because
the model gets built during verification).

---

## Part 1 — Is Advitya's ingestion usable by Detection?

**Yes, but only under the `detector-v2` feature profile, which is not the
default everywhere.** Verified empirically by running Advitya's real
`ingestion/detector_profile.py` from `origin/compiled` and feeding its output
through Detection's real `adapters/ingestion_jsonl.py`.

| field | `legacy-m1d` (default in `pipeline.py`) | `detector-v2` |
|---|---|---|
| `FlowEvent.conn_state` on an S0 no-reply flow | `None` | **`'S0'`** |
| `FlowEvent.dns.query` | `None` | **raw string** |
| `FlowEvent.tls.server_name` | `None` | **raw string** |
| `FlowEvent.tls.ja3` / `ja3s` / `ja4` | `None` | **raw strings** |

Mechanism, per field:

* `encode_conn_state` (`ingestion/src/features/flow.rs:50`) **still has no
  `S0` arm** — S0 falls to `_ => 0`, and `decode_conn_state(0)` returns `None`.
  That has not been fixed.
* What changed is that `detector_profile.py` sets
  `vector["conn_state"] = _clean(conn.get("conn_state"))` from the parsed conn
  row, and the adapter already preferred a raw value:
  `record.get("conn_state") or decode_conn_state(record.get("conn_state_encoded"))`
  (`adapters/ingestion_jsonl.py:257`). So S0 survives *around* the encoder, not
  through it.
* `_dns_block` / `_tls_block` in the same file carry `query`, `ja3`, `ja3s`,
  `ja4`, `server_name` verbatim.

Caveats worth stating in the PR description:

1. **`pipeline.py` still defaults to `legacy-m1d`** (`feature_profile: str =
   LEGACY_FEATURE_PROFILE`). `pcap_dataset/ingest.py` defaults to
   `detector-v2`. The `features.jsonl` committed at `ingestion/features.jsonl`
   on `compiled` is legacy-shaped: `conn_state_encoded: 4`, no raw
   `conn_state`.
2. **JA3/JA3S are transported but not produced.** Per `pcap_dataset/README.md`,
   neither qualified Zeek runtime emits them — base 8.0.10 installs no
   fingerprint packages, and the JA4 image adds only `ssl.log.ja4` — so on real
   captures they arrive `null`. JA4 needs `--ja4` plus the built `sih-zeek-ja4`
   image. The Detection side is ready either way (verified below).
3. The Rust extension `ingestion_core` is not built in this environment and no
   Rust toolchain is present, so the Rust parse layer was read, not executed.
   The Python projection layer — which is where every raw field under test is
   attached — was run as-is with a transcribed stand-in for the numeric feature
   extractors. Those extractors do not touch the raw fields.

**Consequence for the fixes.** Because both profiles are live, the byte proxy
stays as the fallback and the `conn_state` path is used when it is genuinely
populated. The BUG 1 fix is what makes that safe in both worlds.

---

## Part 2 — The four bugs

### BUG 1 (P0) — OTH / unknown-state coverage inflation

`conn_state_coverage()` counted any non-`None` state, so `OTH`, an
unrecognised value or `""` reported full coverage with a zero incomplete
share — which reads as "the responder answered everything" and silenced a scan
the byte proxy caught immediately.

*Before / after, executed:* a 30-port no-reply sweep with `conn_state="OTH"`
produced **0 alerts**; the same sweep with `conn_state=None` produced 2. After
the fix, every variant produces 2.

| | |
|---|---|
| Code | `aggregators/sliding_window.py` — new `COMPLETE_CONN_STATES`, `CLASSIFIED_CONN_STATES`; `_add` / `_remove` count coverage only for classified states (both paths mirrored) |
| | `aggregators/__init__.py` — re-exports |
| | `detectors/port_scan.py` — `_responder_refused` docstring states the invariant |
| Tests | `tests/test_port_scan_responder_evidence.py` — all-OTH, unrecognised, empty, blank, mixed-coverage windows; `test_no_unclassified_state_silences_what_the_proxy_catches` states the invariant directly |
| | `tests/test_sliding_window.py` — the one test that asserted `OTH` counts as covered now asserts 0.8, with the reason |
| | `tests/test_sliding_window_equivalence.py` — reference updated to classified semantics, generator now emits `OTH` / `ZZ` / `""` |

A window of genuine `COMPLETE_CONN_STATES` still suppresses — that is the
intended behaviour and is pinned separately
(`test_a_completed_conn_state_window_is_still_suppressed`).

### BUG 2 (P0) — browsing suppresses a real scan

`established_fraction()` divides by the whole per-source window, so answered
browsing sharing that window diluted the gate.

*Before / after, executed:* 30-port no-reply sweep plus N answered browsing
flows in the same 60 s window.

| browsing flows | 0 | 4 | 6 | 7 | **8** | 10 | 16 |
|---|---|---|---|---|---|---|---|
| before | 2 | 2 | 1 | 1 | **0** | 0 | 0 |
| after | 2 | 2 | 2 | 2 | **2** | 2 | 2 |

Eight was enough to silence it, exactly as flagged.

**Fix:** responder engagement is scoped to distinct `(dst_ip, dst_port)`
endpoints rather than to flows — `endpoint_established_fraction()`. Browsing is
a couple of endpoints carrying many flows; a scan contributes one unanswered
endpoint per port (vertical) or per host (horizontal), which is the evidence
that qualified the window. Volume on browsing endpoints therefore has no
leverage. Fail-open is preserved: 0.0 on an empty window and on any capture
with no responder bytes.

| | |
|---|---|
| Code | `aggregators/sliding_window.py` — `_endpoint_counts` / `_established_endpoints` maintained in `_add`/`_remove`; `unique_endpoint_count()`, `established_endpoint_count()`, `endpoint_established_fraction()` |
| | `detectors/port_scan.py` — `_responder_refused` gates on the endpoint measure; alert evidence gains `endpoint_established_fraction`, `established_endpoints`, `unique_endpoints` (per-flow `established_fraction` retained for continuity) |
| Tests | `tests/test_port_scan_responder_evidence.py` — parametrized 0/4/8/16/40/200 browsing flows, browse-then-scan ordering, horizontal sweep with one answering host |
| | same file — `test_answered_browsing_alone_is_still_suppressed` guards the false-positive suppression this gate exists for |

`detector_version` bumped **0.3.0 → 0.3.1**: the gate's decision semantics
changed and alerts carry that field, so the two behaviours should not ship
under one version.

### BUG 3 (P1) — `unique_service_port_count()` was O(N) on the hot path

Maintained incrementally against a boundary pinned at construction
(`service_port_max`), with the scan retained as an exact fallback for any other
boundary. `PortScanDetector` pins `config.max_service_port`.

*Benchmark, attack-shaped (every flow brings an unseen port), per-flow cost:*

| ports | 500 | 1 000 | 2 000 | 4 000 | 8 000 | growth |
|---|---|---|---|---|---|---|
| before | 12.55 µs | 24.66 µs | 43.66 µs | 85.21 µs | 165.45 µs | **13.18×** |
| after | 2.58 µs | 2.59 µs | 2.53 µs | 2.59 µs | 3.28 µs | **1.27×** |

At 8 000 ports: 1.32 s → 0.026 s, ~50× faster.

| | |
|---|---|
| Code | `aggregators/sliding_window.py` — `service_port_max` ctor arg on `ActivityWindow` and `WindowIndex`, `_service_port_total` maintained symmetrically |
| | `detectors/port_scan.py` — pins the boundary |
| Tests | `tests/test_service_port_scaling.py` — differential vs a materialized reference across arrival/repeat/expiry/drain/refill at six boundaries; unpinned-boundary fallback; `clear()` reset; scaling test at 500/1k/2k/4k/8k |
| | `tests/test_sliding_window_equivalence.py` — randomized differential now parametrized over `service_port_max` ∈ {None, 1023, 49151}, ports straddling both boundaries |

The flatness assertion bounds growth at 4×; the pre-fix code measures 12.75×,
so the guard demonstrably fails on the old implementation rather than being
vacuous.

### BUG 4 (P1) — DGA corpus mismatch

The shipped CSV was 17 239 rows and reported 28 families; documentation says
16 939 / 27. Blob-to-blob diff confirmed the shipped blob (`bb5b9cde`) is the
reference blob (`017339946a`) **plus exactly 300 `benign_cdn,cdn_synthetic`
rows, with nothing removed**.

Restored to blob `017339946a` — verified byte-identical via `git hash-object`;
the staged diff is 0 insertions / 300 deletions.

Why it mattered: `training.py` derives its headline as `family_count - 1 if
BENIGN_FAMILY in breakdown`, subtracting the *one* benign family it knows by
name, so `benign_cdn` was counted as malware. `PROVENANCE.md` already warned
about exactly this; the data contradicted the doc.

*Regenerated from the restored CSV* (scikit-learn 1.5.1 / numpy 1.26.4):

```
rows          : 16939  (benign 10824 / dga 6115, 0 duplicates)
split         : group_disjoint  train 12295 / test 4644
dga families  : 27 -> 20 in train, 7 held out
held out      : banjori, necurs, newgoz, nymaim, pitou, qadars, simda
```

Every structural claim in `DGA_PRECISION.md` reproduces exactly, including the
held-out family list. The decision-threshold *values* moved: the `before`
column reproduces the published figures to within two samples (0.9424/0.7145
vs 0.9444/0.7109), while `after` reads lower (0.8981/0.4732 vs 0.8953/0.5691).
Recall is steep there — 8.5 points between thresholds 0.70 and 0.75 — so the
imbalanced corpus is far more sensitive to the library version than the small
balanced one. `pyproject.toml` pins only `scikit-learn>=1.4`. Both columns were
re-measured together so they stay comparable to each other.

| | |
|---|---|
| Data | `ml/dga/data/dga_dataset.sample.csv` restored to `017339946a` |
| Code | `ml/dga/data/build_dataset.py` — `_assert_one_benign_family` refuses to write a benign row whose family is not `BENIGN_FAMILY` |
| Docs | `docs/DGA_PRECISION.md` — §3 metrics re-measured, family-disjoint threshold sweep added, §5 re-run note |
| | `ml/dga/data/PROVENANCE.md` — addendum rewritten: the 300 synthetic rows are recorded as an experiment that is **not** shipped |
| Tests | `tests/test_dga_corpus_invariants.py` — pins rows / labels / sources / family count / one-benign-family / `benign_cdn` absence / uniqueness, plus the builder refusal |

5 of the 11 corpus invariants fail against the drifted CSV, so they are a real
guard.

`docs/DGA_PRECISION.md` §4 and the CDN columns of §5 need the Umbrella and
Tranco evaluation lists, which are not in the repo. They were **not** re-run
and are carried forward unchanged; the note in §5 says so. Both were originally
measured on this same restored corpus.

---

## Part 3 — Detectors wired to detector-v2

End-to-end on Advitya's real projection: Zeek-shaped rows →
`detector_profile.write_output` → `features.jsonl` → `IngestionJsonlAdapter`
→ `DetectionEngine`.

```
51 FlowEvents from 51 lines, json_errors=0 validation_errors=0
drift warnings: none
conn_state values reaching detectors : ['S0', 'SF']
raw dns.query 8 | tls.server_name 1 | tls.ja3 1 | tls.ja4 1

alerts: 3
  port_scan   low       src=10.0.0.66  responder_evidence=conn_state
                        coverage=1.0 incomplete=0.6842
                        established_fraction=0.3158 (per-flow, over the ceiling)
                        endpoint_established_fraction=0.1333 (what the gate reads)
  port_scan   medium    src=10.0.0.66  responder_evidence=conn_state
  dga_domain  critical  src=10.0.0.77  score=0.930  (from raw dns.query)
```

That first alert is both fixes visible at once: the window is judged on real
`conn_state` because detector-v2 supplies it, and the per-flow byte reading
(0.3158) is above the 0.20 ceiling while the endpoint-scoped one (0.1333) is
not.

`encrypted_malware` was verified separately against raw `tls.ja3` and
`tls.ja4` from the same projection: it fires `critical` on an
operator-configured feed and stays silent without one. It cannot fire on real
captures until a runtime actually emits JA3/JA3S (caveat 2 above).

Two adapter fixes fell out of this:

* `orig_ip_bytes` / `resp_ip_bytes` are now recognized in
  `KNOWN_TOP_LEVEL_FIELDS`, so detector-v2 output no longer raises a schema-drift
  warning on every record. They are deliberately not mapped onto `FlowEvent` —
  every volume threshold here is defined on payload bytes, and being recognized
  also keeps a header-inclusive counter out of `extra` where it would invite the
  wrong comparison.
* Comments asserting that raw `query` / `ja3` / `server_name` / `conn_state` are
  "absent upstream today" were corrected in `adapters/ingestion_jsonl.py`,
  `adapters/encodings.py` and `detectors/port_scan.py`. They now name which
  profile supplies what.
