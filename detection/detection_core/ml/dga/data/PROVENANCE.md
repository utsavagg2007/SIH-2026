# DGA dataset — provenance

`dga_dataset.sample.csv` in this directory is a **sampled** `domain,label,family`
dataset for the offline DGA classifier. It is built by `build_dataset.py` from
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
  `0`, family `benign`. Then trimmed to roughly the DGA row count so the
  classes are balanced.
* **Licence / terms:** the Tranco list is published for free use in research;
  the list files are freely downloadable and redistributable, and the project
  asks that work using it cite the paper above. We redistribute only a few
  thousand of the ranked domain strings; no ranking data or list metadata is
  included.
* **Build date:** 2026-08-30
* **Tranco list id used:** latest as of the build date (no `--tranco-id`
  pinned). Pin one for a byte-reproducible benign side.

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
  family `cdn`.
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

### The `cdn` family is NOT group-split, and that matters

`split_dataset` runs `GroupShuffleSplit` on the **DGA** rows only; benign rows
— whatever family string they carry — are split by ordinary shuffle, because
grouping them would push every benign row into one fold. So the `cdn` family
name makes the composition of the negative class visible in
`family_breakdown`; it does **not** hold providers out.

The consequence is that every CDN provider in the test fold was also in
training, so the in-run CDN numbers are *in-distribution*. To measure
generalization to a provider the model has never seen, build a second dataset
with `--cdn-holdout-suffixes cloudfront.net,cdn77.org,digitaloceanspaces.com`
and evaluate against those providers' hostnames. `docs/DGA_PRECISION.md`
reports both, and they differ by more than an order of magnitude — quoting only
the in-distribution one would badly overstate the fix.

One cosmetic consequence, unfixed because it is in frozen training code: the
training summary's `dga families : N total` line computes
`family_count - 1 if "benign" in breakdown`, so the `cdn` family inflates it by
one (28 rather than 27). The split itself is unaffected — `20 in train, 7 held
out` sums to the true DGA family count.

## Sample vs full

`dga_dataset.sample.csv` is intentionally small (a per-family cap of ~90) so it
can live in the repository. For the model you actually ship, rebuild with a
higher `--per-family-cap` and/or `--families all`, and record the parameters
and resulting metrics in `docs/dga_model.md`.

## What is committed

* `build_dataset.py` — the fetch/build script (standard library only).
* `PROVENANCE.md` — this file.
* `dga_dataset.sample.csv` — the sampled dataset.

No model binary is committed (`.gitignore` blocks `*.joblib`); retrain from the
CSV with `python -m detection_core.ml.dga.training`.
