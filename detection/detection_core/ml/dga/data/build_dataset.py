"""Build a ``domain,label,family`` CSV for the offline DGA classifier.

    python -m detection_core.ml.dga.data.build_dataset --out dga_dataset.csv

Three public sources, fetched over HTTPS with the standard library only (no new
dependency):

* **Benign** - the Tranco research top-sites list (https://tranco-list.eu/).
  Ranked, aggregated from several public popularity rankings. The top
  ``--tranco-n`` names are taken, label ``0``, family ``benign``.
* **Benign / CDN** - CDN, edge and object-storage hostnames from the Cisco
  Umbrella top 1M (see :data:`UMBRELLA_URL`). Label ``0``, family ``benign``,
  ``source`` column ``cdn`` (see :data:`BENIGN_FAMILY` for why the marker is
  not in the ``family`` column). **Why this source and not Tranco:** Tranco
  ranks *registrable* domains, so it contributes ``cloudfront.net`` but never
  ``d9ojso6xukdhq.cloudfront.net``. The Umbrella list is built from resolver
  traffic and carries full FQDNs, so it is the only one of the two that
  contains the machine-assigned labels a CDN actually hands out - which are
  long, high-entropy and, to a name-only classifier, indistinguishable from a
  DGA. Those hostnames are the dominant real-world false positive for this
  model and they were entirely absent from the corpus. Hostnames are matched
  against a fixed list of documented vendor suffixes
  (:data:`CDN_SUFFIXES`), must carry at least one label *beyond* the suffix,
  and are capped per suffix so no single provider dominates.
* **DGA** - the *example domain* files from
  https://github.com/baderj/domain_generation_algorithms (one
  ``<family>/example_domains.txt`` per malware family). Label ``1``, family =
  the directory name, which is a real malware family and is **never derived
  from the domain text**. Only these generated example strings are fetched;
  none of that repository's code is downloaded or executed.

All three licences and the redistribution rationale are in ``PROVENANCE.md``
next to this file. Every fetched domain must pass the project's own
:func:`~detection_core.ml.dga.features.normalize_domain`; anything it rejects
is dropped. Domains are then deduplicated (a domain seen under two families,
or as both benign and DGA, is dropped), and each DGA family is capped at
``--per-family-cap`` rows.

The cross-family drop is decided over **all** families before any row is kept,
so it does not depend on the order of ``--families``, and the count is reported
as ``cross_family_dropped``. The 27 default families share no domain today, so
the shipped corpus is unaffected; ``--families all`` reaches many more of them,
which is where an ambiguous domain would otherwise be attributed to whichever
family happened to be fetched first.

With ``--balance`` (the default) the benign side is trimmed to the DGA total,
the CDN rows counting against that same budget rather than adding to it. The
committed dataset is built with ``--no-balance`` instead, because the two sides
have to be balanced *within each label-count stratum*, not only overall: DGA
example domains are 99.5% two-label and CDN hostnames are 100% three-or-more,
so a benign side too small to cover the two-label stratum teaches the model
that "two labels" means DGA and it starts flagging ordinary domains. See
``PROVENANCE.md`` for the measured sweep and the parameters that follow from
it.

The CSV has four columns: ``domain,label,family,source``. Only the first
three mean anything to ``dataset.load_dataset`` - ``source`` is provenance for
whoever audits the file, and is ignored on load.

``--cdn-holdout-suffixes`` excludes whole providers from the build. Benign
rows are split by ordinary shuffle (see ``dataset.split_dataset``), so a
provider present in training is also present in test and the in-run CDN
numbers are *in-distribution*. Holding providers out is the only way to
measure generalization to a CDN the model has never seen; do that in a
separate build and evaluate against it.

This script writes a CSV and prints a summary. It trains nothing and imports
nothing from the live detection layer.
"""

from __future__ import annotations

import argparse
import csv
import io
import random
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from ..features import normalize_domain

__all__ = [
    "TRANCO_URL",
    "UMBRELLA_URL",
    "BADERJ_RAW",
    "BENIGN_FAMILY",
    "SOURCE_COLUMN",
    "CDN_SUFFIXES",
    "fetch_benign_tail",
    "DEFAULT_FAMILIES",
    "fetch_benign",
    "fetch_cdn",
    "fetch_dga_family",
    "build",
    "main",
]

#: Tranco "latest" permanent download. A specific list can be pinned with
#: ``--tranco-id`` (the id from a tranco-list.eu permalink); recorded in
#: PROVENANCE.md so a build is reproducible.
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_ID_URL = "https://tranco-list.eu/download/{id}/1000000"

#: Cisco Umbrella top 1M. Unlike Tranco this is a list of *fully-qualified*
#: hostnames observed by a public resolver, so it carries the machine-assigned
#: CDN labels (``d9ojso6xukdhq.cloudfront.net``) that Tranco's registrable
#: domains never show. Published daily at a stable URL, no key required.
UMBRELLA_URL = (
    "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
)

#: Raw base for the baderj example-domain files.
BADERJ_RAW = (
    "https://raw.githubusercontent.com/baderj/"
    "domain_generation_algorithms/master/{family}/example_domains.txt"
)

#: ``family`` value written for EVERY benign row, CDN ones included.
#:
#: It would read better to write ``cdn`` here so the negative class's
#: composition were visible in ``family_breakdown``, and that is what this
#: built at first. It is wrong: ``training.py`` derives its "dga families"
#: headline as ``family_count - 1 if "benign" in breakdown``, subtracting the
#: one benign family it knows by name, so a second benign family name is
#: counted as a malware family and the summary reports 28 families for a
#: dataset with 27. The split is unaffected - ``split_dataset`` groups only
#: the DGA rows - but a wrong number in the headline metric is not worth the
#: convenience.
#:
#: So both benign sources write ``benign`` here, and provenance moves to the
#: :data:`SOURCE_COLUMN` below, which the loader ignores.
BENIGN_FAMILY = "benign"

#: Fourth CSV column: which source each row came from (``tranco`` / ``cdn`` /
#: ``dga``). Purely for auditing the dataset - ``dataset.load_dataset``
#: requires only ``domain`` and ``label``, reads ``family`` when present, and
#: ignores every other column, so this travels with the data without reaching
#: the model or the split. It is what ``family`` cannot carry, per above.
SOURCE_COLUMN = "source"
SOURCE_TRANCO = "tranco"
SOURCE_CDN = "cdn"
SOURCE_TRANCO_TAIL = "tranco_tail"
SOURCE_DGA = "dga"

#: Public suffixes operated by CDN, edge-delivery and object-storage providers.
#: Every one is documented by its vendor and appears in the Public Suffix List
#: or the vendor's own DNS documentation. A hostname counts only if it has at
#: least one label *beyond* the suffix, because the suffix alone
#: (``cloudfront.net``) is already in Tranco and is not what the model gets
#: wrong. Grouped by operator; the string is what the hostname must end with.
CDN_SUFFIXES = (
    # Amazon Web Services
    "cloudfront.net", "amazonaws.com", "awsstatic.com",
    # Akamai
    "akamai.net", "akamaiedge.net", "akamaihd.net", "akamaized.net",
    "akamaitech.net", "edgekey.net", "edgesuite.net", "akadns.net",
    # Fastly
    "fastly.net", "fastlylb.net",
    # Cloudflare
    "cloudflare.net", "cloudflare.com", "cloudflarestorage.com",
    "r2.dev", "pages.dev", "workers.dev",
    # Microsoft Azure
    "azureedge.net", "azurefd.net", "core.windows.net", "trafficmanager.net",
    "cloudapp.azure.com", "cloudapp.net", "azurewebsites.net", "vo.msecnd.net",
    # Google Cloud
    "storage.googleapis.com", "googleusercontent.com", "appspot.com",
    "ggpht.com", "gvt1.com", "gvt2.com", "1e100.net",
    # independent CDNs and object stores
    "b-cdn.net", "stackpathdns.com", "llnwd.net", "cdn77.org", "kxcdn.com",
    "cachefly.net", "edgecastcdn.net", "hwcdn.net", "cdnsun.net",
    "digitaloceanspaces.com", "impervadns.net", "incapdns.net",
    # regional / platform CDNs
    "alicdn.com", "aliyuncs.com", "cdngslb.com", "cdnhwc1.com",
    "wswebcdn.com", "bytefcdn.com", "lswcdn.net",
    "fbcdn.net", "cdninstagram.com", "twimg.com",
)

#: A spread of families with enough examples to survive per-family capping and
#: a family-disjoint split. Override with ``--families a,b,c`` or ``--families all``.
DEFAULT_FAMILIES = (
    "banjori",
    "chinad",
    "corebot",
    "dircrypt",
    "gozi",
    "locky",
    "m0yv",
    "mydoom",
    "necurs",
    "newgoz",
    "ngioweb",
    "nymaim",
    "nymaim2",
    "pitou",
    "proslikefan",
    "pushdo",
    "qadars",
    "qakbot",
    "ramnit",
    "reconyc",
    "shiotob",
    "simda",
    "sisron",
    "symmi",
    "tempedreve",
    "tinba",
    "tufik",
)

_UA = {"User-Agent": "detection-core-dga-dataset-builder/1.0 (+offline research use)"}
_ALL_FAMILIES_SENTINEL = "all"
_GITHUB_API_TREE = (
    "https://api.github.com/repos/baderj/"
    "domain_generation_algorithms/git/trees/master"
)


def _get(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _normalized(raw: str) -> str | None:
    """``normalize_domain`` if the string survives it, else ``None``."""
    try:
        return normalize_domain(raw)
    except (TypeError, ValueError):
        return None


def fetch_benign(count: int, *, tranco_id: str | None, timeout: float) -> list[str]:
    """The top ``count`` Tranco domains that pass ``normalize_domain``."""
    url = TRANCO_ID_URL.format(id=tranco_id) if tranco_id else TRANCO_URL
    payload = _get(url, timeout)

    # The permalink download is raw CSV; the "latest" URL is a zip of one CSV.
    if payload[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            name = archive.namelist()[0]
            text = archive.read(name).decode("utf-8", "replace")
    else:
        text = payload.decode("utf-8", "replace")

    domains: list[str] = []
    seen: set[str] = set()
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        candidate = row[-1].strip()  # rank,domain  (permalink) or just domain
        normalized = _normalized(candidate)
        if normalized and normalized not in seen:
            seen.add(normalized)
            domains.append(normalized)
        if len(domains) >= count:
            break
    return domains


def fetch_benign_tail(
    count: int,
    *,
    skip_first: int,
    tranco_id: str | None,
    timeout: float,
    seed: int = 42,
) -> list[str]:
    """Ordinary registered domains sampled from *below* the head of the list.

    **Off by default, because it was measured and it does not work.** Kept so
    the experiment is not repeated blind; see the numbers below before turning
    it on.

    The idea was sound. :func:`fetch_benign` takes the top ``n``, which is a
    specific and unrepresentative population - short, dictionary-word,
    heavily-trafficked names - and the domains the model actually gets wrong
    look nothing like them. Scoring 40 000 held-out Umbrella hostnames against
    the CDN-augmented model left 1 384 false positives at threshold 0.65, and
    they were overwhelmingly long-tail business names: ``logisticsmngmt.com``,
    ``pacificcandywhsle.com``, ``lambertvetsupply.com``, ``swymregistry.com`` -
    real companies whose domains are long, compound and full of abbreviations,
    which is exactly the surface a character model reads as algorithmic.

    Feeding that population back in as benign was tried at two doses, and both
    cost more recall than they bought precision. On 783 real DGA domains from
    nine families never trained on, against 39.6k held-out Umbrella hostnames,
    at the shipped threshold of 0.65::

        corpus                     PR-AUC   precision   recall   FP/1k benign
        CDN only (shipped)         0.2983      0.3353   0.8072          31.65
        + 1 500 tail               0.2357      0.3279   0.6909          28.01
        + 6 000 tail               0.1995      0.2241   0.3487          23.81

    The mechanism is not a tuning accident. A top-sites list is *what resolvers
    saw*, not *what is safe*: part of that tail genuinely is algorithmic, and
    the rest overlaps the DGA distribution honestly. Labelling it benign
    teaches the model that random-looking strings are fine, which is the one
    discrimination it exists to make. ROC-AUC barely moves (0.9230 -> 0.9276 at
    1 500) precisely because it is insensitive to a rare positive class; PR-AUC,
    which is not, falls in both directions.

    Samples uniformly from rank ``skip_first`` onward; ``seed`` makes the
    sample reproducible. Domains that also appear as DGA examples are dropped
    by the caller, as for every other benign source.
    """
    url = TRANCO_ID_URL.format(id=tranco_id) if tranco_id else TRANCO_URL
    payload = _get(url, timeout)
    if payload[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            text = archive.read(archive.namelist()[0]).decode("utf-8", "replace")
    else:
        text = payload.decode("utf-8", "replace")

    tail: list[str] = []
    seen: set[str] = set()
    for index, row in enumerate(csv.reader(io.StringIO(text))):
        if index < skip_first or not row:
            continue
        normalized = _normalized(row[-1].strip())
        if normalized and normalized not in seen:
            seen.add(normalized)
            tail.append(normalized)
    random.Random(seed).shuffle(tail)
    return tail[:count]


def fetch_cdn(
    *,
    per_suffix_cap: int,
    timeout: float,
    holdout_suffixes: frozenset[str] = frozenset(),
    seed: int = 42,
) -> tuple[list[str], dict[str, int]]:
    """CDN / object-storage hostnames from the Umbrella top 1M.

    Returns ``(domains, per_suffix_kept)``. A hostname qualifies when it ends
    with ``"." + suffix`` for some entry in :data:`CDN_SUFFIXES` - the leading
    dot is what enforces "at least one label beyond the suffix", so the bare
    registrable name is never taken (Tranco already supplies those, and they
    are not what the model gets wrong).

    Each suffix is shuffled with ``seed`` and capped at ``per_suffix_cap``, so
    a provider with 12 000 entries in the list does not swamp one with 200.
    Suffixes named in ``holdout_suffixes`` are skipped entirely, which is how a
    build is made to exclude a provider so it can serve as an unseen-provider
    test set.
    """
    payload = _get(UMBRELLA_URL, timeout)
    if payload[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            text = archive.read(archive.namelist()[0]).decode("utf-8", "replace")
    else:
        text = payload.decode("utf-8", "replace")

    # Longest suffix first, so `s3.amazonaws.com`-style nesting attributes a
    # hostname to the most specific provider suffix rather than the shortest.
    ordered = sorted(CDN_SUFFIXES, key=len, reverse=True)
    wanted = [s for s in ordered if s not in holdout_suffixes]

    by_suffix: dict[str, list[str]] = {s: [] for s in wanted}
    seen: set[str] = set()
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        host = row[-1].strip().lower()
        if not host:
            continue
        for suffix in wanted:
            if not host.endswith("." + suffix):
                continue
            normalized = _normalized(host)
            if normalized and normalized not in seen:
                seen.add(normalized)
                by_suffix[suffix].append(normalized)
            break

    rng = random.Random(seed)
    domains: list[str] = []
    kept: dict[str, int] = {}
    for suffix in wanted:
        pool = by_suffix[suffix]
        rng.shuffle(pool)
        chunk = pool[:per_suffix_cap]
        if chunk:
            kept[suffix] = len(chunk)
            domains.extend(chunk)
    return domains, kept


def _all_baderj_families(timeout: float) -> list[str]:
    import json

    tree = json.loads(_get(_GITHUB_API_TREE + "?recursive=1", timeout))
    return sorted(
        {
            item["path"].split("/", 1)[0]
            for item in tree.get("tree", [])
            if item.get("path", "").endswith("/example_domains.txt")
        }
    )


def fetch_dga_family(family: str, *, timeout: float) -> list[str]:
    """Normalized example domains for one baderj family. ``[]`` if it has none."""
    try:
        text = _get(BADERJ_RAW.format(family=family), timeout).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise

    out: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        normalized = _normalized(line)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


def build(
    *,
    tranco_n: int,
    families: list[str],
    per_family_cap: int,
    seed: int,
    tranco_id: str | None,
    timeout: float,
    balance: bool,
    cdn_per_suffix_cap: int = 0,
    cdn_holdout_suffixes: frozenset[str] = frozenset(),
    tranco_tail_n: int = 0,
) -> tuple[list[tuple[str, int, str, str]], dict[str, object]]:
    """Return ``(rows, report)``, rows being ``(domain, label, family, source)``."""
    rng = random.Random(seed)

    # --- DGA side -----------------------------------------------------------
    # Every family is fetched before any domain is kept. Which domains are
    # ambiguous is a property of the whole corpus, so it cannot be decided
    # while walking it.
    fetched_by_family: dict[str, list[str]] = {}
    per_family_fetched: dict[str, int] = {}
    for family in families:
        if family in fetched_by_family:  # `--families a,a`: fetch once
            continue
        fetched = fetch_dga_family(family, timeout=timeout)
        per_family_fetched[family] = len(fetched)
        fetched_by_family[family] = fetched

    # A domain published under more than one family has no defensible family
    # attribution, so it is dropped from all of them.
    #
    # It used to go to whichever family iterated first, which made the corpus
    # depend on the order of `--families` - the same request in a different
    # order produced a different dataset, and the module docstring said these
    # rows were dropped while the code kept them. `family` is not a label
    # here; it is the *grouping key* the family-disjoint split is built on, so
    # a wrong attribution puts a domain in the train fold on the strength of a
    # family it may not belong to, while its real family sits in the held-out
    # test fold. That leaks across the split the whole evaluation rests on.
    # Guessing is worth less than the row.
    claimed_by: dict[str, set[str]] = {}
    for family, fetched in fetched_by_family.items():
        for domain in fetched:
            claimed_by.setdefault(domain, set()).add(family)
    cross_family = {
        domain for domain, owners in claimed_by.items() if len(owners) > 1
    }

    dga_by_domain: dict[str, str] = {}
    per_family_kept: dict[str, int] = {}
    for family, fetched in fetched_by_family.items():
        if not fetched:
            continue
        rng.shuffle(fetched)
        kept = 0
        for domain in fetched:
            if kept >= per_family_cap:
                break
            if domain in cross_family:
                continue
            # `fetch_dga_family` already deduplicates within a family, and any
            # domain shared across families is in `cross_family` above, so no
            # domain can reach this line twice.
            dga_by_domain[domain] = family
            kept += 1
        per_family_kept[family] = kept

    dga_rows = [(d, 1, f, SOURCE_DGA) for d, f in dga_by_domain.items()]

    # --- CDN side (benign) -----------------------------------------------
    # Fetched before Tranco is trimmed, because balancing must divide the
    # benign budget between the two benign sources rather than trim one of
    # them away. A CDN hostname that somehow also appears as a DGA example is
    # dropped, same rule as Tranco.
    cdn_domains: list[str] = []
    cdn_per_suffix: dict[str, int] = {}
    if cdn_per_suffix_cap > 0:
        cdn_domains, cdn_per_suffix = fetch_cdn(
            per_suffix_cap=cdn_per_suffix_cap,
            timeout=timeout,
            holdout_suffixes=cdn_holdout_suffixes,
            seed=seed,
        )
        cdn_domains = [d for d in cdn_domains if d not in dga_by_domain]

    cdn_seen = set(cdn_domains)

    # --- long-tail benign side -------------------------------------------
    # Fetched before the head slice for the same reason the CDN side is: with
    # `--balance` the benign budget is shared, and a source fetched after the
    # trim would be trimmed away instead of sharing it.
    tail_domains: list[str] = []
    if tranco_tail_n > 0:
        tail_domains = fetch_benign_tail(
            tranco_tail_n,
            skip_first=tranco_n,
            tranco_id=tranco_id,
            timeout=timeout,
            seed=seed,
        )
        tail_domains = [
            d for d in tail_domains if d not in dga_by_domain and d not in cdn_seen
        ]
    tail_seen = set(tail_domains)

    # --- benign side -----------------------------------------------------
    benign = fetch_benign(tranco_n, tranco_id=tranco_id, timeout=timeout)
    benign = [d for d in benign if d not in dga_by_domain]  # no label conflict
    benign = [d for d in benign if d not in cdn_seen]  # no duplicate benign row
    benign = [d for d in benign if d not in tail_seen]
    if balance:
        # The CDN and long-tail rows are benign too, so the head slice is
        # trimmed to the *remaining* budget. Trimming to len(dga_rows) as
        # before would leave the negative class oversized by exactly the
        # count of the other benign sources.
        budget = max(len(dga_rows) - len(cdn_domains) - len(tail_domains), 0)
        if len(benign) > budget:
            rng.shuffle(benign)
            benign = benign[:budget]
    benign_rows = [(d, 0, BENIGN_FAMILY, SOURCE_TRANCO) for d in benign]
    cdn_rows = [(d, 0, BENIGN_FAMILY, SOURCE_CDN) for d in cdn_domains]
    tail_rows = [(d, 0, BENIGN_FAMILY, SOURCE_TRANCO_TAIL) for d in tail_domains]

    # Sorted by (label, family, source-rank, domain). The source key keeps the
    # two benign sources in contiguous blocks now that they share a family
    # name, so the CSV stays as readable as it was when they did not.
    #
    # It is a RANK and not the source string on purpose. Row order decides the
    # benign train/test split - `split_dataset` shuffles indices, not names -
    # so sorting benign rows by the literal source would put `cdn` before
    # `tranco` and silently retrain a different model than the one this
    # dataset's published metrics describe. The rank reproduces the order the
    # old two-family sort produced (tranco, then cdn, then DGA by family), so
    # adding the column changed the CSV's shape and nothing else.
    # `tranco_tail` sorts after `cdn` so the ranks of the sources that already
    # existed are untouched: adding a source must not silently reshuffle the
    # rows the published metrics were measured on.
    source_rank = {
        SOURCE_TRANCO: 0,
        SOURCE_CDN: 1,
        SOURCE_TRANCO_TAIL: 2,
        SOURCE_DGA: 3,
    }
    rows = sorted(
        benign_rows + cdn_rows + tail_rows + dga_rows,
        key=lambda r: (r[1], r[2], source_rank[r[3]], r[0]),
    )

    report = {
        "tranco_source": TRANCO_ID_URL.format(id=tranco_id) if tranco_id else TRANCO_URL,
        "umbrella_source": UMBRELLA_URL if cdn_per_suffix_cap > 0 else None,
        "families_requested": list(families),
        "families_with_examples": sorted(per_family_kept),
        "families_empty": sorted(f for f in families if not per_family_kept.get(f)),
        "per_family_fetched": per_family_fetched,
        "per_family_kept": per_family_kept,
        "per_family_cap": per_family_cap,
        # Domains published under more than one family, dropped from all of
        # them. Reported rather than silently discarded: a number that climbs
        # between rebuilds means the upstream families are diverging, and that
        # is worth seeing.
        "cross_family_dropped": len(cross_family),
        "cdn_per_suffix_cap": cdn_per_suffix_cap,
        "cdn_per_suffix_kept": cdn_per_suffix,
        "cdn_suffixes_held_out": sorted(cdn_holdout_suffixes),
        "cdn_count": len(cdn_rows),
        "tranco_tail_count": len(tail_rows),
        "tranco_tail_requested": tranco_tail_n,
        "benign_count": len(benign_rows) + len(cdn_rows) + len(tail_rows),
        "benign_tranco_count": len(benign_rows),
        "dga_count": len(dga_rows),
        "total_rows": len(rows),
        "seed": seed,
    }
    return rows, report


def _verify(rows: list[tuple[str, int, str, str]], *, sample: int, seed: int) -> None:
    """Assert a random sample round-trips through the real feature extractor."""
    from ..features import extract_features

    rng = random.Random(seed + 1)
    probe = rng.sample(rows, min(sample, len(rows)))
    for domain, _label, _family, _source in probe:
        vector = extract_features(domain)
        if len(vector) != 19 or not all(isinstance(v, float) for v in vector):
            raise AssertionError(f"feature extraction misbehaved on {domain!r}")


def _assert_one_benign_family(rows: list[tuple[str, int, str, str]]) -> None:
    """Every benign row must carry :data:`BENIGN_FAMILY`, and only it.

    ``training.py`` derives its family headline as ``family_count - 1 if
    BENIGN_FAMILY in breakdown`` - it subtracts the *one* benign family it
    knows by name. A second benign family name is therefore silently counted
    as a malware family, and the run summary overstates the corpus.

    That is not hypothetical: 300 rows marked ``benign_cdn`` were once folded
    into the shipped sample and made it report 28 families where there are 27.
    Provenance belongs in the ``source`` column, which travels with the data
    and reaches no metric. Refusing to write the file is the cheapest place to
    catch this - after it is committed, only a test that pins the composition
    will.
    """
    offenders = sorted(
        {family for domain, label, family, source in rows
         if label == 0 and family != BENIGN_FAMILY}
    )
    if offenders:
        raise ValueError(
            f"benign rows must carry family={BENIGN_FAMILY!r}; found "
            f"{offenders}. Record provenance in the {SOURCE_COLUMN!r} column "
            f"instead - a second benign family name is counted as malware by "
            f"the training headline."
        )


def _write_csv(rows: list[tuple[str, int, str, str]], path: Path) -> None:
    _assert_one_benign_family(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("domain", "label", "family", SOURCE_COLUMN))
        writer.writerows(rows)


def _print_report(report: dict[str, object], out: Path | None) -> None:
    print("DGA dataset build")
    print(f"  tranco source     : {report['tranco_source']}")
    if report.get("umbrella_source"):
        print(f"  umbrella source   : {report['umbrella_source']}")
    print(f"  seed              : {report['seed']}")
    print(f"  per-family cap     : {report['per_family_cap']}")
    print(f"  benign / dga       : {report['benign_count']} / {report['dga_count']}")
    if report.get("cdn_count"):
        print(f"    of which tranco  : {report['benign_tranco_count']}")
        if report.get("tranco_tail_count"):
            print(f"    of which tail    : {report['tranco_tail_count']}")
        print(f"    of which cdn     : {report['cdn_count']} "
              f"(cap {report['cdn_per_suffix_cap']}/suffix, "
              f"{len(report['cdn_per_suffix_kept'])} suffixes)")
        held = report.get("cdn_suffixes_held_out") or []
        if held:
            print(f"    cdn held out     : {', '.join(held)}")
    print(f"  total rows         : {report['total_rows']}")
    if report.get("cross_family_dropped"):
        print(f"  dropped (claimed by >1 family): "
              f"{report['cross_family_dropped']}")
    empty = report["families_empty"]
    if empty:
        print(f"  families with no examples (skipped): {', '.join(empty)}")
    print("  rows per DGA family:")
    for family, kept in sorted(
        report["per_family_kept"].items(), key=lambda kv: (-kv[1], kv[0])
    ):
        fetched = report["per_family_fetched"].get(family, 0)
        print(f"    {family:<22} {kept:>5}  (of {fetched} fetched)")
    if out is not None:
        print(f"  written            : {out}")
    print("  NOTE: family labels come from the source directory names, never "
          "from the domain text. See PROVENANCE.md.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m detection_core.ml.dga.data.build_dataset",
        description=__doc__.split("\n\n")[0],
    )
    parser.add_argument(
        "--out", type=Path, default=Path("dga_dataset.csv"),
        help="output CSV path (default: dga_dataset.csv)",
    )
    parser.add_argument(
        "--tranco-n", type=int, default=20_000,
        help="how many top Tranco names to consider for the benign side",
    )
    parser.add_argument(
        "--tranco-id", default=None,
        help="pin a specific Tranco list id (from a tranco-list.eu permalink)",
    )
    parser.add_argument(
        "--families", default=",".join(DEFAULT_FAMILIES),
        help=f"comma-separated family list, or '{_ALL_FAMILIES_SENTINEL}'",
    )
    parser.add_argument(
        "--per-family-cap", type=int, default=200,
        help="max rows kept per DGA family (default: 200)",
    )
    parser.add_argument(
        "--tranco-tail-n", type=int, default=0,
        help=(
            "benign domains sampled uniformly from BELOW the head slice (the "
            "long tail of ordinary registered names). DEFAULT 0 - measured at "
            "1 500 and 6 000 and it cost more recall than it bought precision; "
            "see fetch_benign_tail for the table before enabling it"
        ),
    )
    parser.add_argument(
        "--cdn-per-suffix-cap", type=int, default=40,
        help="max CDN/object-storage hostnames kept per provider suffix from the "
             "Umbrella list (default: 40; 0 disables the CDN source entirely)",
    )
    parser.add_argument(
        "--cdn-holdout-suffixes", default="",
        help="comma-separated CDN suffixes to EXCLUDE from this build, so they can "
             "serve as an unseen-provider test set (e.g. 'cloudfront.net,cdn77.org')",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--no-balance", action="store_true",
        help="keep all fetched benign names instead of trimming to the DGA total",
    )
    parser.add_argument(
        "--no-verify", action="store_true",
        help="skip the feature-extraction round-trip check",
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)

    try:
        if args.families.strip() == _ALL_FAMILIES_SENTINEL:
            families = _all_baderj_families(args.timeout)
        else:
            families = [f.strip() for f in args.families.split(",") if f.strip()]

        rows, report = build(
            tranco_n=args.tranco_n,
            families=families,
            per_family_cap=args.per_family_cap,
            seed=args.seed,
            tranco_id=args.tranco_id,
            timeout=args.timeout,
            balance=not args.no_balance,
            cdn_per_suffix_cap=args.cdn_per_suffix_cap,
            tranco_tail_n=args.tranco_tail_n,
            cdn_holdout_suffixes=frozenset(
                s.strip().lower()
                for s in args.cdn_holdout_suffixes.split(",")
                if s.strip()
            ),
        )
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if report["dga_count"] == 0 or report["benign_count"] == 0:
        print(
            f"ERROR: need both classes; got {report['benign_count']} benign, "
            f"{report['dga_count']} dga. Check network access and --families.",
            file=sys.stderr,
        )
        return 1

    if not args.no_verify:
        _verify(rows, sample=200, seed=args.seed)

    _write_csv(rows, args.out)

    if args.json:
        import json

        print(json.dumps(report, indent=2, default=list))
    else:
        _print_report(report, args.out)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
