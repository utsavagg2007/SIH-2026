# DGA classifier — model, features, and validation

The `dga_domain` detector classifies a queried domain name as
algorithmically generated (DGA) or not, from the **name alone**. This
document is the deliverable required by the problem statement:
*"documentation of the model(s) used, features engineered, and the
training/validation approach."*

Everything here is the **offline** half: `detection_core/ml/dga/`. The live
detector (`detection_core/detectors/dga.py`) loads a model this pipeline
produced and calls it per flow; it is not covered here.

---

## 1. Model

| | |
|---|---|
| Estimator | `sklearn.ensemble.RandomForestClassifier` |
| Parameters | `n_estimators=200`, `class_weight="balanced"`, `random_state=42`, `n_jobs=-1` |
| Input | one raw domain string → 19 lexical features (below) |
| Output | `dga_score` ∈ [0, 1] — the class-1 vote fraction |
| Positive class | `1 = DGA` (fixed everywhere in the package) |

**Why a random forest.** The signal is lexical and non-linear — short
high-entropy names, long low-entropy dictionary names, digit runs, consonant
clusters — and interactions between those matter. A forest captures them with
no feature scaling, gives per-feature importances for explanation, and
`class_weight="balanced"` blunts class imbalance. A `LogisticRegression`
baseline on the identical features and split is reported alongside every run
so the forest's added complexity has to justify itself.

**The score is not a calibrated probability.** It is a vote fraction. The
live detector publishes `score_type: rule_score`, never `calibrated_model`,
and the raw value travels in the alert evidence as `dga_model_score` next to
`model_score_is_calibrated: false`. Calibration is deferred until there is a
held-out calibration set.

**Bundle.** `DGAModel.save()` writes a joblib file of `{metadata, estimator}`.
`metadata` pins the exact `feature_names` and order, the sklearn version, and
a timestamp; `DGAModel.load()` refuses a bundle whose feature schema does not
match this build. Model binaries are **not** committed (`.gitignore` blocks
`*.joblib`) — retrain from the CSV.

---

## 2. Features engineered — 19 lexical features

Extracted by `detection_core/ml/dga/features.py::extract_features(domain)`.
The input is a raw domain string; the function normalizes it itself
(`normalize_domain`: strip, lowercase, drop the trailing dot; reject
whitespace / URLs / empty labels) so training and inference never see
differently-shaped input. IDN/punycode is scored as the literal ASCII it
already is.

Character statistics are computed on the **body** — every label except the
last, concatenated without dots — because the last label is a TLD drawn from
a tiny fixed set and says nothing about how the name was generated.

| # | feature | what it is | why it separates DGA from benign |
|---|---|---|---|
| 1 | `length` | length of the normalized name | generated names skew long |
| 2 | `body_length` | length of the body | same, TLD removed |
| 3 | `tld_length` | length of the last label | some DGAs favour odd TLDs |
| 4 | `label_count` | number of dot-separated labels | tunnelling-style names nest deeply |
| 5 | `max_label_length` | longest single label | one very long random label is a tell |
| 6 | `mean_label_length` | mean label length | benign names have short, word-like labels |
| 7 | `digit_count` | digits in the body | many DGAs mix in digits; brands rarely do |
| 8 | `digit_ratio` | digits ÷ body length | normalizes #7 for length |
| 9 | `alpha_ratio` | letters ÷ body length | low when a name is digit-heavy |
| 10 | `vowel_ratio` | vowels ÷ body length | human-chosen names are pronounceable (~40% vowels); random ones are vowel-starved |
| 11 | `consonant_ratio` | consonants ÷ body length | the complement — high for random names |
| 12 | `hyphen_count` | `-` in the body | benign brands hyphenate; most DGAs do not |
| 13 | `hyphen_ratio` | hyphens ÷ body length | normalized #12 |
| 14 | `unique_char_count` | distinct characters in the body | random strings use more of the alphabet |
| 15 | `unique_char_ratio` | distinct ÷ body length | near 1.0 for random, lower for repetitive words |
| 16 | `entropy` | Shannon entropy (bits/char) of the body | the headline randomness signal: `aaaa` → 0, a varied string → high |
| 17 | `longest_digit_run` | longest unbroken digit stretch | e.g. `...1234...` |
| 18 | `longest_alpha_run` | longest unbroken letter stretch | very long for one-word random labels |
| 19 | `longest_consonant_run` | longest unbroken consonant stretch | `kqxvbz`-style clusters that no English word has |

`FEATURE_NAMES` in `features.py` is the canonical order; the saved model
records it and load-time validation fails on any mismatch.

### Feature importance (committed sample, see §4)

Top contributors, by Gini importance:

```
longest_consonant_run   0.171
mean_label_length       0.103
max_label_length        0.101
length                  0.089
body_length             0.088
entropy                 0.073
vowel_ratio             0.070
consonant_ratio         0.066
unique_char_count       0.056
tld_length              0.046
```

Consonant-run length dominating, with entropy and the vowel/consonant ratios
close behind, matches the intuition: what most cleanly separates a generated
label from a human one is that it is unpronounceable.

---

## 3. Training / validation approach

### Pipeline

`CSV → normalize → validate → deduplicate → split → fit → evaluate → save`
(`detection_core/ml/dga/training.py`).

* **Deduplication before split.** Domains are normalized, then deduplicated,
  then split — a normalized domain cannot appear in both folds. A duplicate
  carrying conflicting labels (or conflicting families) is a hard error, not
  a silent pick. `train_dga` also asserts zero train/test domain overlap
  after the split.
* **Decision vs ranking metrics.** Precision / recall / F1 / the confusion
  counts are computed at an **explicit threshold** (default 0.75, the value
  the live detector uses) — not scikit-learn's implicit 0.5 argmax, which
  would describe a classifier nobody runs. ROC-AUC and **PR-AUC** (average
  precision) are computed from the **raw scores** and are threshold-free.
* **Baseline.** A `StandardScaler` + `LogisticRegression(class_weight=
  "balanced")` is fitted on the same 19 features and the same split, and
  evaluated the same way. Reported next to the forest so the nonlinearity's
  value is visible. Never saved, never used at detection time.
* **Threshold sweep.** Precision / recall / F1 / fp / fn are printed at
  0.50–0.90 for analysis. **Nothing selects a threshold from it** — choosing
  one off the same data it was measured on is how a number gets called
  optimal when it is merely overfitted. The live detector owns its own
  `DGAConfig.score_threshold`.

### Family-disjoint split (the important part)

DGA malware runs in **families**; every domain from one family is produced by
the same algorithm. Testing on other domains from a family already seen in
training measures an easy task. The operational question is: **does the model
catch a family it has never seen?**

When the training CSV carries a `family` column
(`domain,label,family`), `split_dataset` switches to a **family-disjoint**
split:

* the **DGA** rows are split with `sklearn.model_selection.GroupShuffleSplit`
  on the family, so **no malware family in the test fold appears in
  training**;
* the **benign** rows carry no meaningful family and are split with an
  ordinary shuffle at the same test size — grouping them (benign is one
  group) would push every benign row into a single fold. Both classes appear
  in both folds.

The run reports which split ran: `split_strategy` is `group_disjoint` /
`stratified` / `random`, `group_aware_split` is the boolean, and when grouped
the metrics carry the DGA family counts held out for test. Without a `family`
column the split is the original label-stratified one, unchanged.

Family labels come only from the data source (see
`ml/dga/data/PROVENANCE.md`) — they are **never** synthesized from the domain
text. Deriving "families" by clustering or hashing the strings would fabricate
the very labels the split exists to respect and would report leakage-free
numbers that are nothing of the kind.

### Data

`detection_core/ml/dga/data/`:

* **benign** — Tranco research top-sites list (label 0, family `benign`);
* **DGA** — per-family `example_domains.txt` from
  `baderj/domain_generation_algorithms` (label 1, family = the real malware
  family name).

Full provenance, URLs, licences and the exact `build_dataset.py` command are
in `ml/dga/data/PROVENANCE.md`. The committed `dga_dataset.sample.csv` is a
**capped sample** (~90 domains per family) sized to live in the repo; the
shipped model should be trained on a larger rebuild (higher
`--per-family-cap`, or `--families all`) with its parameters and metrics
recorded below.

---

## 4. Results — committed sample, family-disjoint

`python -m detection_core.ml.dga.training --input
detection_core/ml/dga/data/dga_dataset.sample.csv` (deterministic,
`random_state=42`):

```
rows                : 4008   (benign 2004 / dga 2004, 0 duplicates)
split               : group_disjoint   train 2957 / test 1051
dga families        : 27 total -> 20 in train, 7 held out for test (disjoint)
held-out families   : banjori, necurs, newgoz, nymaim, pitou, qadars, simda
threshold (decision): 0.75
```

| metric | RandomForest | LogisticRegression (baseline) |
|---|---|---|
| PR-AUC (avg precision, raw scores) | **0.912** | 0.918 |
| ROC-AUC (raw scores) | **0.900** | 0.895 |
| precision @ 0.75 | **0.944** | 0.940 |
| recall @ 0.75 | **0.711** | 0.678 |
| F1 @ 0.75 | **0.811** | 0.788 |
| confusion @ 0.75 `[[tn, fp], [fn, tp]]` | `[[478, 23], [159, 391]]` | — |

Threshold sweep (RandomForest):

| thr | precision | recall | F1 | fp | fn |
|---|---|---|---|---|---|
| 0.50 | 0.850 | 0.793 | 0.820 | 77 | 114 |
| 0.60 | 0.875 | 0.773 | 0.820 | 61 | 125 |
| 0.70 | 0.920 | 0.733 | 0.816 | 35 | 147 |
| **0.75** | **0.944** | **0.711** | **0.811** | 23 | 159 |
| 0.80 | 0.951 | 0.676 | 0.791 | 19 | 178 |
| 0.90 | 0.967 | 0.473 | 0.635 | 9 | 290 |

### Reading these numbers honestly

* These are **unseen-family** numbers. A label-stratified split on the same
  data reports far higher recall; that split is not the task.
* At the operating threshold the model catches ~71% of domains from families
  it was never trained on, at ~94% precision (23 false positives in 1051
  test domains). Raising the threshold trades recall for precision along the
  curve above.
* The forest beats the linear baseline by ~2–3 points of F1 and recall; on
  pure ranking (PR-AUC / ROC-AUC) the two are within noise. The nonlinearity
  earns its place at the decision boundary, not dramatically.
* **Known limits.** Dictionary DGAs (families that assemble real words —
  `suppobox`, `matsnu`) look lexically like human names and are the hardest
  case for any name-only model; resolution behaviour, NXDOMAIN rates and
  registration age are the signals that catch those, and they are out of
  scope here. Punycode is scored as literal ASCII. No Public Suffix List, so
  a multi-part suffix like `co.uk` is treated as body `…co` + TLD `uk`.

---

## 5. The shipped model

Everything above §4 describes the model trained on the original two-source
corpus (Tranco + malware families). That model had a false-positive problem
this section documents the fix for. The numbers here supersede §4 for the
artifact actually shipped; §4 is kept because the *method* is unchanged and the
comparison is the point.

### Build and train

```
build command    : python -m detection_core.ml.dga.data.build_dataset \
                       --out detection_core/ml/dga/data/dga_dataset.sample.csv \
                       --tranco-n 9000 --per-family-cap 400 \
                       --cdn-per-suffix-cap 40 --seed 42 --no-balance
train command    : python -m detection_core.ml.dga.training \
                       -i detection_core/ml/dga/data/dga_dataset.sample.csv \
                       -o ../artifacts/dga_model.joblib
rows             : 16 939  (benign 10 824 / dga 6 115, 0 duplicates)
                   of the benign side: 9 000 Tranco + 1 824 CDN
families         : 27 DGA families -> 20 in train, 7 held out (disjoint)
held-out families: banjori, necurs, newgoz, nymaim, pitou, qadars, simda
split            : group_disjoint, group_aware_split=True, zero family overlap
PR-AUC / ROC-AUC : 0.8437 / 0.8914
precision/recall/F1 @ 0.75 : 0.8953 / 0.5691 / 0.6959
recall              @ 0.65 : 0.711   (the recommended operating point)
confusion @ 0.75 [[tn,fp],[fn,tp]] : [[2577, 129], [835, 1103]]
baseline (LogReg)  : F1 0.7692, precision 0.8969, recall 0.6734, PR-AUC 0.8838
artifact           : 33.9 MB, gitignored, rebuilt by tools/build_dga_model.py
```

**Neither list is byte-reproducible.** Tranco's unpinned "latest" URL and the
Cisco Umbrella daily list are both regenerated every day; rebuilding on a
different date fetches a different set of domains and produces different
metrics. The committed `dga_dataset.sample.csv` is therefore the artifact of
record, not the command. Pin `--tranco-id` for the benign side if you need a
reproducible rebuild; Umbrella has no equivalent and would need the archived
file for the build date. See `ml/dga/data/PROVENANCE.md`.

### What changed in the corpus, and why

The model was trained on Tranco (benign) and malware-family example domains
(DGA). Tranco ranks **registrable** domains, so it contributed `cloudfront.net`
but never `d9ojso6xukdhq.cloudfront.net` — and the machine-assigned label a CDN
hands out is long, high-entropy and, to a name-only classifier, exactly what a
DGA looks like. The corpus had no example of one. Measured against 88 651 real
CDN hostnames, the old model scored **98% of sampled `cloudfront.net` names
above its threshold**.

So a third source was added: **Cisco Umbrella top 1M**, which is built from
public-resolver traffic and therefore carries full FQDNs. Hostnames matching 53
documented vendor suffixes (AWS, Akamai, Fastly, Cloudflare, Azure, Google
Cloud, and independent CDNs and object stores), each required to have a label
beyond the suffix and capped at 40 per provider: **1 824 rows**, label `0`.
Every row is a hostname a public resolver actually observed — none is
synthesized from a pattern. Licence and full provenance in `PROVENANCE.md`.

**Why `--tranco-n 9000` and not 3000.** DGA example domains are **99.5%
two-label** (`xxxx.com`); CDN hostnames are **100% three-or-more** by
construction. A benign side too small to cover the two-label stratum makes
"two labels" a near-perfect DGA marker: at `--tranco-n 3000` the two-label DGA
prior was 0.68, `label_count` became the top feature (0.166), and the model
flagged `tripadvisor.in` and `umweltbundesamt.de` at 1.000 — false positives on
ordinary domains rose from 8.1% to 11.0%. At 9 000 the prior is 0.42,
`label_count` importance falls to 0.083, and `mean_label_length` /
`longest_consonant_run` return to the top. **Change `--per-family-cap` and you
must change `--tranco-n` with it.**

The `family` column reads `benign` for both benign sources; a fourth `source`
column (`tranco` / `cdn` / `dga`) carries the distinction. That is not cosmetic
preference: `training.py` derives its family headline as
`family_count - 1 if "benign" in breakdown`, so a second benign family name is
counted as a malware family and the summary misreports 27 families as 28. The
`source` column is ignored by `load_dataset`, which requires only `domain` and
`label` and reads `family` when present.

### Feature importance (shipped model)

```
mean_label_length       0.134
max_label_length        0.110
longest_consonant_run   0.109
label_count             0.083
length                  0.080
entropy                 0.063
consonant_ratio         0.060
vowel_ratio             0.059
body_length             0.058
tld_length              0.053
```

Compared with §2's ranking, `label_count` and `mean_label_length` have risen —
the CDN rows are what taught the model that a long random label under a real
parent is not a rendezvous name. §6 is honest about what that costs.

### The decision threshold: 0.65, not 0.75

`DGAConfig.score_threshold` still **ships 0.75**, and that default is
deliberately unchanged. 0.75 was chosen for the pre-CDN corpus and is
documented in `DGAConfig` as untuned; adding the CDN rows moved the score
distribution down, so the same recall is now reached lower on the curve.

Measured on populations the model never trained on (real Tranco domains below
the training slice, real CDN hostnames, and CDN providers held out of training
entirely via `--cdn-holdout-suffixes`):

| threshold | DGA recall | CDN same-provider | CDN unseen-provider | ordinary domains | DNS-tunnel |
|---|---|---|---|---|---|
| 0.60 | 0.723 | 0.0022 | 0.1083 | 0.1017 | 0.0000 |
| **0.65** | **0.711** | **0.0019** | **0.0917** | **0.0937** | **0.0000** |
| 0.70 | 0.667 | 0.0007 | 0.0861 | 0.0757 | 0.0000 |
| 0.75 | 0.569 | 0.0005 | 0.0639 | 0.0657 | 0.0000 |

0.65 holds recall at parity with the old model's operating point (0.711 vs
0.727) while cutting CDN false positives 169x same-provider and 9.6x on a
provider never seen in training. Past 0.70 recall falls off a cliff — 0.711 →
0.667 → 0.569 — while the false-positive rates barely move, so the knee of the
curve is at 0.65. On a realistic name mix (60 000 random Umbrella FQDNs) this
is **185 686 → 34 984 alerts per million distinct names, 5.3x fewer**.

**It is applied as configuration, not code.** The runner's `--config` flag
overrides the frozen default per run, and
`detection/detectors.dga-precision.toml` ships that override:

```
python -m detection_core.runner <capture.jsonl> \
    --dga-model ../artifacts/dga_model.joblib \
    --config detectors.dga-precision.toml
```

`tools/run_demo.py` passes it automatically, so the demo runs at 0.65. Whether
the shipped default in `DGAConfig` should also become 0.65 is a one-line edit
to frozen detection code and is left to that file's owner.

## 6. What the fix cost — the honest part

**Subdomain-hosted DGA sensitivity is largely gone.** Probing with real
held-out-family DGA labels re-hosted as `<dga-label>.<cdn-parent>`:

| model | recall on that probe |
|---|---|
| before | 0.600 – 0.715 |
| after | 0.000 – 0.043 |

This is the residue of the label-count confound described above. It is much
reduced by the 9 000-row Tranco side but not eliminated, because no amount of
Tranco changes the fact that the DGA corpus contains almost no multi-label
examples.

How much it matters is a judgement call, stated so a reader can disagree: a
classic DGA *registers* a two-label rendezvous domain, and an attacker using
`random.cloudfront.net` does not control that label — AWS assigns it, and that
case is caught by destination novelty and reputation rather than by a name-only
classifier. But an attacker who owns `evil.com` and generates
`<random>.evil.com` is a real technique, and this model is now weak against it.
**Closing that gap needs multi-label DGA examples in the corpus — more data,
not a threshold.**

Three more things a reader should not have to discover for themselves:

* **PR-AUC 0.9116 → 0.8437 is not a regression.** Average precision depends on
  the positive rate, which fell from 0.50 to 0.36 when the benign side grew.
  The two figures come from differently-composed test folds and are not
  comparable. Compare on fixed populations instead.
* **In-distribution CDN numbers flatter the fix by roughly 130x**
  (0.0005 vs 0.0639). Benign rows are shuffle-split, so every provider in the
  test fold was also in training; the unseen-provider column is the one to
  quote.
* **None of this is a production false-positive rate.** Tranco and Umbrella are
  real public lists, not a capture from the deployment network. Re-derive
  against a real benign capture before treating any figure here as an error
  rate.

Full evidence, every sweep behind every parameter, and the DGA-vs-tunnel
routing issue flagged for the detector owner: **`docs/DGA_PRECISION.md`** at the
repository root.

### Known limits carried forward

The §4 limits still apply and are not addressed by this work: dictionary DGAs
(`suppobox`, `matsnu`) remain the hardest case for any name-only model,
punycode is scored as literal ASCII, and there is no Public Suffix List — so
`co.uk` is still treated as body `…co` + TLD `uk`. A PSL would also be the
principled fix for the CDN problem and for DNS-tunnel misrouting, since it
would let the detector classify the registrable domain rather than the FQDN.
