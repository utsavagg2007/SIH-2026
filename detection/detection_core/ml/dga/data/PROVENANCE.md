# DGA dataset — provenance

`dga_dataset.sample.csv` in this directory is a **sampled**
`domain,label,family,source` dataset for the offline DGA classifier. It is built by `build_dataset.py` from
three public sources. Nothing here is scraped from private data, and the malware
**family** label is taken from the source, never inferred from the domain
string.

Regenerate (or build a larger set) with:

```
python -m detection_core.ml.dga.data.build_dataset \
    --out detection_core/ml/dga/data/dga_dataset.sample.csv \
    --tranco-n 9000 --per-family-cap 400 --cdn-per-suffix-cap 40 \
    --seed 42 --no-balance
```

Those are the parameters the committed file was built with on **2026-09-02**.
They are not arbitrary; each was chosen from a measured sweep recorded in
`docs/DGA_PRECISION.md`:

* `--cdn-per-suffix-cap 40` — enough CDN hostnames to fix the false positives,
  capped per provider so no single one dominates;
* `--per-family-cap 400` — restores the DGA-side lexical variety the CDN rows
  would otherwise swamp;
* `--tranco-n 9000` with `--no-balance` — **the important one.** DGA example
  domains are 99.5% two-label (`xxxx.com`) and CDN hostnames are 100%
  three-or-more by construction, so a small Tranco side makes "two labels"
  a near-perfect DGA marker and the model starts flagging ordinary domains
  like `tripadvisor.in` at 1.000. 9 000 Tranco rows against 6 115 DGA rows
  brings the two-label stratum back to a 0.42 DGA prior and the effect goes
  away. If you change `--per-family-cap`, change this with it.

---

## Sources

### Benign — Tranco research top-sites list

* **URL:** <https://tranco-list.eu/> — download `https://tranco-list.eu/top-1m.csv.zip`
  (a specific list can be pinned with `--tranco-id <id>` from a
  `tranco-list.eu` permalink; record the id here when you do).
* **What it is:** a research-oriented ranking of popular domains, aggregated
  from several public popularity lists to be harder to manipulate than any one
  of them. Introduced in *"Tranco: A Research-Oriented Top Sites Ranking
  Hardened Against Manipulation"* (Le Pochat et al., NDSS 2019).
* **Use here:** the top `--tranco-n` names that pass `normalize_domain`, label
  `0`, family `benign`, `source` `tranco`. With `--balance` they would then be
  trimmed to the DGA row count; the committed build uses `--no-balance`, for
  the reason given at the top of this file.
* **Licence / terms:** the Tranco list is published for free use in research;
  the list files are freely downloadable and redistributable, and the project
  asks that work using it cite the paper above. We redistribute only a few
  thousand of the ranked domain strings; no ranking data or list metadata is
  included.
* **Build date:** 2026-09-01
* **Tranco list id used:** latest as of the build date (no `--tranco-id`
  pinned). **The unpinned `latest` list is regenerated daily** — rebuilding on
  another date fetches a different set of domains, which was observed here:
  a rebuild one day later changed the domain set and moved every metric. Pin
  `--tranco-id` for a byte-reproducible benign side.

### Benign / CDN — Cisco Umbrella top 1M

* **URL:** <https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip>
  (the "Umbrella Popularity List", also published via
  <https://umbrella.cisco.com/blog/cisco-umbrella-1-million>). No key, no
  registration; regenerated daily at a stable URL.
* **What it is:** the top 1 000 000 **fully-qualified** domain names by DNS
  query volume across Cisco's public resolvers (OpenDNS), aggregated over the
  preceding day. Introduced as a free research counterpart to Alexa/Tranco.
* **Why this list and not Tranco.** Tranco ranks *registrable* domains, so it
  contributes `cloudfront.net` but never `d9ojso6xukdhq.cloudfront.net`.
  Umbrella is built from resolver traffic, so it carries the full hostname
  including the machine-assigned label a CDN hands out. Those labels are long,
  high-entropy and — to a name-only classifier — identical to a DGA. They were
  entirely absent from the corpus, and they are the dominant real-world false
  positive: before this source was added the model scored **98% of sampled
  `cloudfront.net` hostnames above its 0.75 threshold**.
* **Use here:** a hostname is kept when it ends with `"." + suffix` for one of
  the 53 documented provider suffixes in `build_dataset.CDN_SUFFIXES` (AWS,
  Akamai, Fastly, Cloudflare, Azure, Google Cloud, and independent CDNs and
  object stores — every one documented by its vendor and/or present in the
  Public Suffix List). The leading dot enforces "at least one label beyond the
  suffix", so the bare registrable name is never taken — Tranco already
  supplies those and they are not what the model gets wrong. Shuffled with
  `--seed` and capped at `--cdn-per-suffix-cap` per provider. Label `0`,
  family `benign`, `source` `cdn` (see "Why CDN rows say `family = benign`"
  below).
* **Nothing is fabricated.** Every row is a hostname that a public resolver
  actually observed and that Cisco published. No CDN hostname is synthesized
  from a pattern, and none is invented to fit the feature space.
* **Licence / terms:** Cisco publishes the list free of charge for research
  use and states no redistribution restriction on the domain strings. We
  redistribute a capped sample (1 824 of 88 651 matching hostnames) and
  attribute it here. As with the DGA side, if your organisation's policy is
  stricter, run `build_dataset.py` locally and do not commit the CSV.
* **Build date:** 2026-09-02. The list has no version id to pin; it is
  regenerated daily, so an exact rebuild needs the archived file for that date.
  This is the one source in this dataset that is **not** byte-reproducible from
  a URL alone — recorded here rather than glossed over.
* **Matching hostnames on the build date:** 88 651 across 53 suffixes.
  Largest contributors: `fbcdn.net` 14 308, `cloudfront.net` 12 379,
  `amazonaws.com` 10 370, `gvt1.com` 7 614, `cloudflare.net` 5 153.

### DGA — `baderj/domain_generation_algorithms` example domains

* **URL:** <https://github.com/baderj/domain_generation_algorithms> — one
  `raw.githubusercontent.com/.../<family>/example_domains.txt` per family.
* **What it is:** open reimplementations of the domain-generation algorithms of
  ~50 malware families, each accompanied by a checked-in `example_domains.txt`
  of domains that family's algorithm produces. The **family name is the
  directory name** — a real malware family identifier, published by the repo
  author, not derived from the strings.
* **Use here:** for each family in `--families`, the example domains that pass
  `normalize_domain`, deduplicated, capped at `--per-family-cap`, label `1`,
  `family = <directory name>`. A domain that would be claimed by two families,
  or that also appears on the benign side, is dropped.
* **What is NOT taken:** none of that repository's *code* is downloaded,
  imported or executed. `build_dataset.py` fetches only the plain-text
  `example_domains.txt` files — generated output data, not source.
* **Licence:** the repository is **GPL-2.0**. GPL-2.0 covers "the Program"
  (the DGA source code); a list of domain strings that the program emitted
  contains no portion of that source and is program *output*, which the GPL
  does not place under its terms. We redistribute only a capped sample of
  these output strings, and we attribute the source here. If your
  organisation's policy is stricter, run `build_dataset.py` locally and do not
  commit `dga_dataset.sample.csv` — the script plus this file are enough to
  reproduce it.
* **Build date:** 2026-08-30
* **Repo commit:** built against `master` at build time; pin a commit here for
  a fully reproducible build if needed.

---

## Why a family-disjoint split

Real DGA malware runs in *families*; every domain from one family shares the
same generation algorithm. A model that has seen `qakbot` domains in training
and is then tested on other `qakbot` domains is being asked an easy question.
The question that matters operationally is: **does it catch a family it has
never seen?**

So `split_dataset` (with a `family` column present) holds whole DGA families
out of training and evaluates only on those. The reported `pr_auc` / `roc_auc`
/ recall are therefore *unseen-family* numbers — lower than an in-family split
would show, and honest. Benign domains carry no family and are split normally,
so both classes appear in both folds.

### CDN rows are benign rows, and they are NOT group-split

`split_dataset` runs `GroupShuffleSplit` on the **DGA** rows only; benign rows
— whatever family string they carry — are split by ordinary shuffle, because
grouping them would push every benign row into one fold. The CDN rows are
benign rows, so they are shuffle-split like the Tranco ones. **Nothing here
holds a provider out.**

The consequence is that every CDN provider in the test fold was also in
training, so the in-run CDN numbers are *in-distribution*. To measure
generalization to a provider the model has never seen, build a second dataset
with `--cdn-holdout-suffixes cloudfront.net,cdn77.org,digitaloceanspaces.com`
and evaluate against those providers' hostnames. `docs/DGA_PRECISION.md`
reports both, and they differ by more than an order of magnitude — quoting only
the in-distribution one would badly overstate the fix.

### Why CDN rows say `family = benign`, and where the marker went

It reads better to write `cdn` in the `family` column, and this dataset did at
first. It is wrong. `training.py` derives its headline as
`family_count - 1 if "benign" in breakdown` — it subtracts the *one* benign
family it knows by name — so a second benign family name is counted as a
malware family and the run summary reports **28 families for a dataset with
27**. The split is unaffected (`20 in train, 7 held out` still sums correctly),
but a wrong number in a headline metric is not worth the convenience.

So both benign sources write `benign`, and the provenance moved to a fourth
column:

```
domain,label,family,source
0123tt.ru,0,benign,tranco
0.1.cn.akamaitech.net,0,benign,cdn
aaqzdxhtnnq.com,1,tinba,dga
```

`load_dataset` requires only `domain` and `label`, reads `family` when it is
present, and **ignores every other column**, so `source` travels with the data
for auditing without reaching the model, the split, or any metric. The
composition also stays visible in the build report (`of which tranco` /
`of which cdn`).

Row order matters and is preserved: `split_dataset` shuffles benign *indices*,
so the order rows are written in decides the benign train/test split. The CSV
is sorted by `(label, family, source-rank, domain)` with the rank pinned to
`tranco < cdn < dga`, which reproduces the order the earlier two-family sort
produced. Adding the column changed the file's shape and not the model —
verified by retraining and getting the same metrics to four decimals.

## Sample vs full

`dga_dataset.sample.csv` was originally a small sample (a per-family cap of
~90, ~4 000 rows). The committed file is now the **shipped** build: 16 939
rows at `--per-family-cap 400`, ~460 KB, still small enough to live in the
repository. Its parameters and metrics are recorded in `docs/dga_model.md` §5.
For a larger corpus, raise `--per-family-cap` and/or use `--families all` —
and raise `--tranco-n` with it, per the note at the top of this file.

**Because neither popularity list is pinnable, the committed CSV is the
artifact of record, not the build command.** Rebuilding on a later date is a
*new dataset*, not a reproduction of this one; retrain and re-measure if you
do it.

## What is committed

* `build_dataset.py` — the fetch/build script (standard library only).
* `PROVENANCE.md` — this file.
* `dga_dataset.sample.csv` — the sampled dataset.

No model binary is committed (`.gitignore` blocks `*.joblib`); retrain from the
CSV with `python -m detection_core.ml.dga.training`.

## Addendum: benign CDN-shaped hostnames (300 rows, `family=benign_cdn`)

Added because the corpus had a hole exactly the shape of the false positives it
produced. It contained 85 CDN *apex* domains (`akamai.com`, `akamaiedge.net`)
and not one example of the thing that actually appears in traffic: a random
looking label under a CDN or object-storage parent, like
`d3f7k2mq9xz1lp.cloudfront.net`. The model had therefore never been shown that
this shape is benign, and scored real CDN hostnames at 0.97 — above genuine DGA
traffic — on the labelled evaluation capture.

Generated deterministically (`random.seed(26145)`): hex, base36 and
`<word>-<region>-<id>` labels under fourteen real CDN and object-storage
parents. **Synthetic, not observed** — they are the right *shape*, and no claim
is made that these specific names were ever resolved by anyone.

Effect at the detector's live threshold of 0.75: precision 0.9127, recall
0.5891 on the held-out family-disjoint split (was 0.9444 / 0.7109). Recall is
genuinely lower — the model is now unwilling to call a random-looking string
generated on the string alone, which is the correct trade and the reason the
end-to-end false-positive count on the labelled capture went from 5 to 0.
