# DGA dataset — provenance

`dga_dataset.sample.csv` in this directory is a **sampled** `domain,label,family`
dataset for the offline DGA classifier. It is built by `build_dataset.py` from
two public sources. Nothing here is scraped from private data, and the malware
**family** label is taken from the source, never inferred from the domain
string.

Regenerate (or build a larger set) with:

```
python -m detection_core.ml.dga.data.build_dataset \
    --out detection_core/ml/dga/data/dga_dataset.sample.csv \
    --tranco-n 3000 --per-family-cap 90 --seed 42
```

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
