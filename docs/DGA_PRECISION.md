# DGA detector precision: what was wrong, what was changed, what it cost

The `dga_domain` detector had precision 0.17–0.33 against labelled synthetic
traffic. The model was not the problem — ROC-AUC was 0.95–0.99 and ordinary
browsing separated cleanly. Three things were:

1. the 0.75 threshold, documented in `DGAConfig` as untuned;
2. a benign corpus (Tranco + malware families) with **no CDN or object-storage
   hostnames**, so legitimate machine-assigned names scored as DGA at `critical`;
3. DNS-tunnel subdomains being filed as `dga_domain` rather than
   `dns_tunnelling`.

This document is the evidence for what was done about (1) and (2), the measured
cost, and what is being handed to the detector owner for (3).

**No model architecture, `features.py`, `model.py`, or frozen detector code was
changed.** The 19-feature schema is untouched, the estimator is the same
`RandomForestClassifier(n_estimators=200, class_weight="balanced")`, and the
threshold moves through the runner's existing `--config` flag.

---

## 1. How bad the CDN problem actually was

Scoring the **baseline** model against 88 651 real CDN / edge / object-storage
hostnames taken from the Cisco Umbrella top 1M (`tools/` sweep, sampled 400 per
suffix):

| provider suffix | hostnames in list | fraction scored ≥ 0.75 |
|---|---|---|
| `cloudfront.net` | 12 379 | **0.98** |
| `cdn77.org` | 476 | 0.99 |
| `cloudflare.net` | 5 153 | 0.95 |
| `cloudflare.com` | 803 | 0.89 |
| `impervadns.net` | 347 | 0.79 |
| `digitaloceanspaces.com` | 217 | 0.78 |
| `akamaihd.net` | 225 | 0.65 |
| `fastly.net` | 756 | 0.59 |

The synthetic capture's four CDN confounders had already flagged this; the real
list shows it is not a synthetic artefact. Three real CloudFront hostnames,
before and after:

| hostname | before | after |
|---|---|---|
| `d37unsldgykj8z.cloudfront.net` | 0.985 | 0.125 |
| `du11hjcvx0uqb.cloudfront.net` | 0.970 | 0.175 |
| `d9ojso6xukdhq.cloudfront.net` | 0.940 | 0.230 |

---

## 2. What went into the corpus

`build_dataset.py` gained a third source. Full licence and rationale in
`ml/dga/data/PROVENANCE.md`; the short version:

* **Cisco Umbrella top 1M** — the top million **fully-qualified** names by DNS
  query volume across Cisco's public resolvers. Tranco ranks *registrable*
  domains, so it contributes `cloudfront.net` but never
  `d9ojso6xukdhq.cloudfront.net`. Umbrella carries the full hostname, which is
  the only place the machine-assigned CDN label appears.
* Matched against **53 documented vendor suffixes** (`CDN_SUFFIXES`), each
  required to have at least one label beyond the suffix, capped at 40 per
  provider so none dominates. **1 824 rows**, label `0`, family `cdn`.
* Every row is a hostname a public resolver actually observed. Nothing is
  synthesized from a pattern.

Final dataset: **16 939 rows** — 9 000 Tranco + 1 824 CDN + 6 115 DGA across 27
families.

```
python -m detection_core.ml.dga.data.build_dataset \
    --out detection_core/ml/dga/data/dga_dataset.sample.csv \
    --tranco-n 9000 --per-family-cap 400 --cdn-per-suffix-cap 40 \
    --seed 42 --no-balance
```

### The mistake worth recording

The first augmented build used `--tranco-n 3000 --per-family-cap 400`, and it
**made the detector worse on the traffic that matters most**. CDN false
positives went to near-zero, but the fraction of ordinary Tranco domains
flagged rose from 8.1% to **11.0%**, with `tripadvisor.in`,
`umweltbundesamt.de` and `worldoftanks.eu` all scored at **1.000**.

Cause: DGA example domains are **99.5% two-label** (`xxxx.com`) and the CDN
hostnames are **100% three-or-more labels** by construction. With 6 115 DGA
rows against 3 000 two-label Tranco rows, the share of two-label rows that were
DGA hit **0.68**, and `label_count` became the model's single most important
feature (0.166, up from outside the top ten). The model had learned "two labels
means DGA".

The fix was to balance the two-label stratum, not to add fewer CDN rows:

| tranco rows | two-label DGA prior | ordinary-domain FP @0.75 |
|---|---|---|
| 3 000 | 0.68 | 0.1010 |
| 6 000 | 0.51 | 0.0790 |
| **9 000** | **0.42** | **0.0687** |
| 12 000 | 0.35 | 0.0610 |

At 9 000, `label_count` importance falls back to 0.083 and `mean_label_length`
/ `longest_consonant_run` return to the top. **If you change
`--per-family-cap`, change `--tranco-n` with it** — that is now recorded in
`PROVENANCE.md`.

---

## 3. Retrained metrics, and why PR-AUC is not comparable

```
python -m detection_core.ml.dga.training \
    -i detection_core/ml/dga/data/dga_dataset.sample.csv \
    -o ../artifacts/dga_model.joblib
```

```
rows              : 16939  (benign 10824 / dga 6115, 0 duplicates)
split             : group_disjoint  (group_aware=True)   train 12295 / test 4644
dga families      : 27 -> 20 in train, 7 held out for test (disjoint, zero overlap)
held-out families : banjori, necurs, newgoz, nymaim, pitou, qadars, simda
```

| metric @ 0.75, unseen families | before | after |
|---|---|---|
| PR-AUC | 0.9116 | 0.8437 |
| ROC-AUC | 0.8995 | 0.8914 |
| precision | 0.9444 | 0.8953 |
| recall | 0.7109 | 0.5691 |
| tp/fp/tn/fn | 391/23/478/159 | 1103/129/2577/835 |

**The split is still honest** — `group_disjoint`, `group_aware_split=True`,
zero train/test family overlap, and the *same seven* held-out families as
before, so the recall figures are measured on identical malware families.

**Do not read the PR-AUC row as a regression.** Average precision depends on
the positive rate, and the positive rate fell from 0.50 to 0.36 when the benign
side grew. The two numbers are computed on differently-composed test folds and
are not comparable. The same applies to precision and recall at a *fixed*
threshold when the score distribution has shifted — which it has, deliberately.
The comparison that means something is §4: both models, identical populations.

---

## 4. Before / after on identical populations

Neither model was trained on any of these. Held-out CDN providers
(`cloudfront.net`, `cdn77.org`, `digitaloceanspaces.com`) are scored with a
twin of each model built with `--cdn-holdout-suffixes`, because a provider that
was in training is not a test of generalization.

At each model's **0.75**:

| population | n | before | after | change |
|---|---|---|---|---|
| DGA, unseen families *(recall — higher better)* | 1 938 | 0.7270 | 0.5609 | −0.166 |
| ordinary Tranco domains | 3 000 | 0.0770 | 0.0657 | 1.2× fewer |
| CDN, same provider | 4 162 | 0.3210 | 0.0005 | **668× fewer** |
| CDN, **unseen** provider | 360 | 0.8806 | 0.0639 | **14× fewer** |
| DNS-tunnel subdomains | 400 | 1.0000 | 0.0000 | **eliminated** |

The recall drop at a *fixed* 0.75 is the whole reason the threshold has to move
— see §5. The score distribution shifted down; 0.75 is no longer the same
operating point it was.

---

## 5. The re-derived threshold: **0.65**

```
python tools/dga_threshold_sweep.py --model artifacts/dga_model.joblib \
    --cdn-eval <hostnames> --tranco-eval <domains> \
    --holdout-model <twin> --holdout-domains <held-out provider hostnames>
```

Score bands, new model — this is where each population actually sits:

| population | role | n | min | p5 | p95 | max |
|---|---|---|---|---|---|---|
| DGA, unseen families | **positive** | 1 938 | 0.000 | 0.037 | 1.000 | 1.000 |
| DNS-tunnel subdomains | negative | 400 | 0.030 | 0.035 | **0.075** | **0.145** |
| CDN, same provider | negative | 4 162 | 0.000 | 0.000 | **0.076** | 0.825 |
| CDN, unseen provider | negative | 360 | 0.000 | 0.000 | 0.785 | 0.900 |
| ordinary Tranco | negative | 3 000 | 0.000 | 0.000 | 0.824 | 1.000 |

The **tunnel band and the same-provider CDN band are now entirely below the
threshold instead of straddling it** — that was the point. Tunnel subdomains
top out at 0.145, so nothing fires on them at any usable threshold, and 95% of
same-provider CDN hostnames sit under 0.076.

The **unseen-provider** band is the honest exception: p95 0.785, max 0.900. A
CDN the model has never seen still has a tail above any threshold worth using,
which is why §5's unseen-provider column never reaches zero and why the
suffix-aware routing fix in §8 would be worth more than more corpus.

| threshold | DGA recall | tunnel FP | CDN same | CDN unseen | ordinary |
|---|---|---|---|---|---|
| 0.50 | 0.733 | 0.0000 | 0.0026 | 0.1667 | 0.1287 |
| 0.55 | 0.729 | 0.0000 | 0.0022 | 0.1417 | 0.1120 |
| 0.60 | 0.723 | 0.0000 | 0.0022 | 0.1083 | 0.1017 |
| **0.65** | **0.711** | **0.0000** | **0.0019** | **0.0917** | **0.0937** |
| 0.70 | 0.667 | 0.0000 | 0.0007 | 0.0861 | 0.0757 |
| 0.75 *(current)* | 0.569 | 0.0000 | 0.0005 | 0.0639 | 0.0657 |
| 0.80 | 0.378 | 0.0000 | 0.0002 | 0.0472 | 0.0593 |
| 0.90 | 0.257 | 0.0000 | 0.0000 | 0.0028 | 0.0337 |

*(The 0.569 recall at 0.75 here and the 0.561 in §4 are the same measurement on
two different 1 938-domain samples of the same seven held-out families — §4
takes the first 400 rows per family from the source file, this table takes the
dataset's own test fold. Neither model trained on any of those families in
either case; the 0.8 pt gap is sampling, not a discrepancy.)*

**Why 0.65.** It holds recall at parity with the old model's operating point
(0.711 vs 0.727) while cutting CDN false positives 169× same-provider and 9.6×
unseen-provider. Past 0.70 recall falls off a cliff — 0.711 → 0.667 → 0.569 —
while the false-positive rates barely move, so the knee is here.

### Alert volume on a realistic name mix

Equal-weight pooling across populations does not say how many alerts an analyst
gets. The Umbrella top 1M *is* a realistic mix — one million FQDNs in the
proportions a public resolver sees them, CDN hostnames at their real share. A
60 000-name random sample:

| | threshold | DGA recall | alerts per 1M distinct names |
|---|---|---|---|
| before | 0.75 | 0.727 | **185 686** |
| after | 0.65 | 0.704 | **34 984** — 5.3× fewer |
| after | 0.53 | 0.727 | 48 317 — 3.8× fewer at *identical* recall |

*(Upper bound: the Umbrella list is not a clean negative set — it contains some
genuinely malicious names. The contamination is identical for both models, so
the comparison holds.)*

### Applying it — no code change needed

`DGAConfig.score_threshold = 0.75` is frozen detection code. It does **not**
need editing: the runner's existing `--config` flag overrides it per run.

```
python -m detection_core.runner <capture.jsonl> \
    --dga-model ../artifacts/dga_model.joblib \
    --config detectors.dga-precision.toml
```

`detection/detectors.dga-precision.toml` ships that override and nothing else.

**`tools/run_demo.py` does not pass `--config`**, so the demo currently runs at
the 0.75 default. On the synthetic capture that changes nothing — the matrix in
§7 is 1.000/1.000 at both thresholds — but it does mean the recommended value
is not active in the demo. Adding `--config` to the demo's runner invocation is
a two-line change in `tools/run_demo.py`; it is **not made here** because it
changes demo behaviour and belongs with whoever owns that script.
**Optional, for the owner of `detectors/dga.py`:** changing the shipped default
from 0.75 to 0.65 would make it apply without the flag. That is a one-line edit
to frozen code and has deliberately **not** been made here.

---

## 6. What this cost — stated plainly

**Subdomain-hosted DGA sensitivity is largely gone.** Probe: real held-out
family DGA labels re-hosted as `<dga-label>.<cdn-parent>`.

| model | recall on that probe |
|---|---|
| before | 0.600–0.715 |
| after | 0.000–0.043 |

This is the residue of the label-count confound. It is much reduced by the
9 000-row Tranco side (`label_count` importance 0.166 → 0.083) but not
eliminated, because no amount of Tranco changes the fact that the DGA corpus
contains almost no multi-label examples.

How much it matters is a judgement call, stated so the reader can disagree: a
classic DGA *registers* a two-label rendezvous domain, and an attacker using
`random.cloudfront.net` does not control that label — AWS assigns it. That case
is caught by destination novelty and reputation, not by a name-only classifier.
But an attacker who owns `evil.com` and generates `<random>.evil.com` is a real
technique, and this model is now weak against it. **The corpus needs
multi-label DGA examples before that gap closes**; the fix is more data, not a
threshold.

### Cost in bytes and milliseconds

| | before | after |
|---|---|---|
| artifact size | 12.6 MB | **33.9 MB** (2.7×) |
| model load | 0.11 s | 0.14 s |
| batch predict, 2 000 domains | 133 ms | 194 ms |
| **single-domain call** (what the detector does) | 72.4 ms | 72.8 ms |
| full runner over the 2 041-flow capture | 61.2 s | 62.3 s |

The artifact nearly tripled because the training set did — a forest on 16 939
rows carries deeper trees than one on 4 008. It is still a gitignored build
product rebuilt in seconds, so the size costs nothing but disk.

**Runtime is unchanged, and that is worth reading carefully rather than as good
news.** The runner takes ~62 s for 2 041 flows *both before and after*, because
the cost is not tree depth — it is that `DGADetector` calls `predict_domain`
once per DNS flow, and a single-row predict on a `n_jobs=-1` forest spends
~72 ms almost entirely in parallel-dispatch overhead. Batched, the same model
scores a domain in ~0.1 ms — **700× faster per domain**. At 817 DNS flows in
this capture that is ~59 s of the 62 s total.

This is a **pre-existing** ceiling (~14 DNS flows/sec), not something this
change introduced, and it is not fixed here: `n_jobs` lives in the estimator
parameters in the frozen `model.py`. **Flagged for that file's owner** —
either `n_jobs=1` for the single-row path, or batching queries inside the
detector, should recover most of it.

Also worth knowing:

* **Ordinary-domain FPs at 0.65 are slightly worse than the old model at 0.75**
  (0.0937 vs 0.0770). Raise the threshold to 0.70 if a deployment weights that
  above recall — 0.0757, better than the old model, at recall 0.667.
* **In-distribution CDN numbers flatter the fix by ~130×** (0.0005 vs 0.0639).
  Benign rows are shuffle-split, so every provider in the test fold was in
  training. The unseen-provider column is the one to quote.
* **None of this is a production false-positive rate.** Tranco and Umbrella are
  real public lists, not a capture from the deployment network, and the tunnel
  names are generated. Re-derive against a real benign capture before treating
  any figure here as an error rate.

---

## 7. Re-run of the per-detector evaluation

`tools/detector_matrix.py`, 20 seeds, each detector run alone against each
traffic slice. Same harness, same capture, same seeds as the run that produced
the 0.333 figure, so the rows are directly comparable.

### Leakage check first

The matrix's CDN confounder is `d3f7k2mq9xz1lp.cloudfront.**test**`. The corpus
contains **zero** `.test` domains and none of the four confounder hostnames:

```
d3f7k2mq9xz1lp.cloudfront.test            -> 0 rows in training CSV
a7b2c9d4e1f6g8.akamai-edge.test           -> 0 rows
x9k2mq7z4lp1nv.fastly-cdn.test            -> 0 rows
storage-eu-west-2-b7f9c1.objectstore.test -> 0 rows
grep -c '\.test,' dga_dataset.sample.csv  -> 0
```

So the result below is generalization from real `*.cloudfront.net` hostnames to
a hostname under a TLD the model has never seen — not memorisation.

What the four confounders and the tunnel now score, directly:

| domain | before | after |
|---|---|---|
| `d3f7k2mq9xz1lp.cloudfront.test` | **0.985** | **0.285** |
| `a7b2c9d4e1f6g8.akamai-edge.test` | 0.810 | 0.120 |
| `x9k2mq7z4lp1nv.fastly-cdn.test` | 0.775 | 0.255 |
| `storage-eu-west-2-b7f9c1.objectstore.test` | 0.460 *(already under)* | 0.025 |
| DNS-tunnel subdomains (n=60) | 0.810 – 0.870 | **0.030 – 0.090** |
| ordinary `*.example.test` browsing (n=6) | 0.267 – 0.548 | 0.050 – 0.231 |
| the capture's real DGA domains (n=30) | 0.560 – 1.000, **29/30** fire | 0.530 – 1.000, **29/30** fire |

Three of the four CDN confounders were over the line and now none is; the whole
tunnel band moved from *above* 0.75 to below 0.10; and the true positives did
not move — 29 of 30 fire before and after, at 0.75 and at 0.65 alike. That last
row is why both thresholds give the same matrix result below: on this capture
every false-positive source is under 0.30 and every true positive is over 0.53.

### `dga_domain`, isolation matrix (20 seeds, 260 trials)

| model / threshold | TP | FP | FN | TN | FP benign | FP cross | precision | recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| before, 0.75 | 20 | 40 | 0 | 200 | 20 (`conf_cdn`) | 20 (`attack_dns_tunnel`) | **0.333** | 1.000 | 0.500 |
| after, 0.75 | 20 | 0 | 0 | 240 | 0 | 0 | **1.000** | 1.000 | 1.000 |
| after, 0.65 *(recommended)* | 20 | 0 | 0 | 240 | 0 | 0 | **1.000** | 1.000 | 1.000 |

The corpus fix alone clears both false-positive sources; the threshold change
is what buys back the recall the fixed 0.75 would otherwise cost on real
unseen-family DGA (§4/§5), and it costs nothing here.

**The other six detectors are unchanged**, as they must be — none of them
touches the DGA model. From the same run at 0.75: `port_scan` 1.000/1.000,
`ddos` 1.000/1.000, `encrypted_malware` 1.000/1.000, `data_exfiltration`
1.000/1.000, `dns_tunnelling` 0.741/1.000, `c2_beaconing` 0.241/1.000 — every
figure identical to the pre-change run. `c2_beaconing` remains the weak
detector and is out of scope here.

### Full pipeline, single capture

```
python -m detection_core.runner ../data/features.jsonl \
    --dga-model ../artifacts/dga_model.joblib \
    --ja3-feed ../tools/ja3_feed.example.txt \
    --config detectors.dga-precision.toml
```

| | before | after |
|---|---|---|
| total alerts | 24 | 19 |
| `dga_domain` alerts | 6 (1 TP, 5 FP) | **1 (1 TP, 0 FP)** |
| `dga_domain` precision / recall | 0.167 / 1.000 | **1.000 / 1.000** |
| false positives per hour | 48.0 | **18.0** |

The surviving alert is the real one: `5d9ovxrkufbsf1o.com` from the compromised
host `10.4.2.19`, model score 0.99, severity `critical`. The four CDN
confounder alerts and the tunnel cross-fire are gone. All seven detectors still
register and fire.

*(Synthetic capture — detector separation, not a production false-positive
rate. Same caveat as `ML_E2E.md`.)*

---

## 8. Cross-contamination — for the detector owner, not fixed here

DNS-tunnel subdomains no longer reach the threshold (band 0.030–0.145), so at
today's data the symptom is gone. **That is not the same as the routing being
correct**, and the mechanism is fragile: it works because tunnel names have 4–5
labels and the model now discounts those. A tunnel using two labels, or a
future corpus rebalance, brings it straight back.

The real defect is that two detectors can claim the same query and nothing
arbitrates. Options, smallest first — all are changes to
`detection_core/detectors/` or the engine and are therefore **flagged for their
owner, not made**:

1. **Parent-repetition guard in `DGADetector`** (self-contained in `dga.py`).
   Skip classification when the same source has queried many distinct first
   labels under one identical parent inside the window — that *is* the tunnel
   signature, and a DGA looks the opposite (many distinct parents). Smallest
   change; no cross-detector state.
2. **Classify the registrable domain, not the FQDN** (the principled fix).
   `payload.t.exfil-channel.test` → `exfil-channel.test`; `d9oj….cloudfront.net`
   → `cloudfront.net`. This is what a DGA actually is — a *registered*
   rendezvous name — and it fixes tunnel routing and CDN false positives at
   once, without any corpus change. Needs a Public Suffix List, whose absence
   `docs/dga_model.md` already records as a known limit. Biggest change,
   biggest payoff.
3. **Let `dns_tunnelling` claim first** — engine-level suppression when a
   `dns_tunnelling` finding already covers the same `(src_ip, parent, window)`.
   Correct ordering, but needs cross-detector state the engine does not have.
4. **Suppress at the fusion layer** — the backend drops a `dga_domain` alert
   overlapped by a `dns_tunnelling` alert on the same source and window. No
   detection change at all, but the wrong alert is still generated and counted.

Recommendation: **(1) now, (2) when a PSL dependency is acceptable.**
