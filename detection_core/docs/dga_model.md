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

### For the shipped model

Rebuild on a larger dataset and fill in:

```
build command   : python -m detection_core.ml.dga.data.build_dataset --out <path> --per-family-cap <N> [--families all]
train command   : python -m detection_core.ml.dga.training --input <path> --output artifacts/dga_model.joblib
rows / families :
held-out families:
PR-AUC / ROC-AUC:
precision / recall / F1 @ 0.75:
```
