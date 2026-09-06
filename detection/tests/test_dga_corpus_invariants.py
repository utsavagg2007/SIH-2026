"""Shape invariants for the shipped DGA corpus.

``dga_dataset.sample.csv`` is a committed artefact that the documented model
metrics, the 0.75 threshold and the family-disjoint split are all derived
from. Nothing pinned its composition, so a merge reshaped it without a single
test noticing: 300 rows carrying ``family=benign_cdn`` were folded back in,
taking the corpus from 16 939 rows to 17 239 and making the training summary
report 28 malware families where there are 27.

That miscount is not cosmetic. ``training.py`` derives its headline as
``family_count - 1 if BENIGN_FAMILY in breakdown`` - it subtracts the *one*
benign family it knows by name - so any second benign family name is counted
as malware. ``PROVENANCE.md`` says exactly this, and the corpus contradicted
it.

These tests pin the composition against the numbers the documentation quotes.
Regenerating the corpus deliberately means updating them, in the same commit,
alongside the docs - which is the point.
"""

from __future__ import annotations

import collections
import csv
from pathlib import Path

import pytest

from detection_core.ml.dga.data.build_dataset import BENIGN_FAMILY

CORPUS = (
    Path(__file__).resolve().parent.parent
    / "detection_core"
    / "ml"
    / "dga"
    / "data"
    / "dga_dataset.sample.csv"
)

# The documented composition - docs/DGA_PRECISION.md and PROVENANCE.md.
EXPECTED_ROWS = 16_939
EXPECTED_BENIGN = 10_824
EXPECTED_DGA = 6_115
EXPECTED_DGA_FAMILIES = 27
EXPECTED_SOURCES = {"tranco": 9_000, "cdn": 1_824, "dga": 6_115}
EXPECTED_COLUMNS = ["domain", "label", "family", "source"]


@pytest.fixture(scope="module")
def rows() -> list[dict[str, str]]:
    with CORPUS.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_the_corpus_has_the_documented_columns(rows):
    assert list(rows[0].keys()) == EXPECTED_COLUMNS


def test_the_corpus_has_the_documented_row_count(rows):
    assert len(rows) == EXPECTED_ROWS


def test_the_label_split_is_as_documented(rows):
    labels = collections.Counter(row["label"] for row in rows)
    assert labels == {"0": EXPECTED_BENIGN, "1": EXPECTED_DGA}
    assert EXPECTED_BENIGN + EXPECTED_DGA == EXPECTED_ROWS


def test_the_source_breakdown_is_as_documented(rows):
    """Row provenance lives in ``source``; the counts are quoted in the docs."""
    sources = collections.Counter(row["source"] for row in rows)
    assert dict(sources) == EXPECTED_SOURCES


def test_there_are_exactly_twenty_seven_dga_families(rows):
    """The number the training headline reports, and the docs quote."""
    families = {row["family"] for row in rows if row["label"] == "1"}
    assert len(families) == EXPECTED_DGA_FAMILIES


def test_every_benign_row_carries_the_single_benign_family(rows):
    """The invariant the 300 stray rows broke.

    A second benign family name is silently counted as malware by
    ``training.py``. Both benign sources - Tranco and CDN - must therefore
    write ``benign`` and record their provenance in ``source`` instead.
    """
    offenders = collections.Counter(
        row["family"] for row in rows if row["label"] == "0"
    )
    assert set(offenders) == {BENIGN_FAMILY}, (
        f"benign rows must all carry family={BENIGN_FAMILY!r}; "
        f"found {dict(offenders)}"
    )


def test_no_dga_row_claims_the_benign_family(rows):
    """The mirror of the above: a malware row must name its family."""
    assert not [row for row in rows if row["label"] == "1" and row["family"] == BENIGN_FAMILY]


def test_the_benign_cdn_marker_is_absent(rows):
    """Named directly, so a reintroduction fails loudly rather than by count."""
    assert not [r for r in rows if r["family"] == "benign_cdn"]
    assert not [r for r in rows if r["source"] == "cdn_synthetic"]


def test_the_family_column_is_never_empty(rows):
    assert all(row["family"] for row in rows)


def test_domains_are_unique(rows):
    """Duplicates would silently reweight the corpus; the docs claim 0."""
    domains = [row["domain"].strip().lower() for row in rows]
    duplicates = [d for d, n in collections.Counter(domains).items() if n > 1]
    assert not duplicates, f"duplicate domains: {duplicates[:5]}"


def test_labels_are_only_zero_or_one(rows):
    assert {row["label"] for row in rows} == {"0", "1"}


# --------------------------------------------------------------------------
# The builder must refuse to write the shape that caused this
# --------------------------------------------------------------------------


def test_the_builder_refuses_a_second_benign_family(tmp_path):
    """Catch it at write time, not at review time three merges later."""
    from detection_core.ml.dga.data.build_dataset import _write_csv

    rows = [
        ("good.com", 0, BENIGN_FAMILY, "tranco"),
        ("cdn-shaped.cloudfront.net", 0, "benign_cdn", "cdn_synthetic"),
        ("aaqzdxhtnnq.com", 1, "tinba", "dga"),
    ]
    with pytest.raises(ValueError, match="benign rows must carry family"):
        _write_csv(rows, tmp_path / "out.csv")

    assert not (tmp_path / "out.csv").exists(), "nothing may be written on refusal"


def test_the_builder_accepts_the_documented_shape(tmp_path):
    """Both benign sources share the family name and differ in ``source``."""
    from detection_core.ml.dga.data.build_dataset import _write_csv

    rows = [
        ("good.com", 0, BENIGN_FAMILY, "tranco"),
        ("0.1.cn.akamaitech.net", 0, BENIGN_FAMILY, "cdn"),
        ("aaqzdxhtnnq.com", 1, "tinba", "dga"),
    ]
    out = tmp_path / "out.csv"
    _write_csv(rows, out)

    with out.open(encoding="utf-8", newline="") as handle:
        written = list(csv.DictReader(handle))
    assert len(written) == 3
    assert {r["family"] for r in written if r["label"] == "0"} == {BENIGN_FAMILY}


# --------------------------------------------------------------------------
# Cross-family ambiguity: a domain under two families belongs to neither
# --------------------------------------------------------------------------
#
# `family` is not a label in this corpus - it is the *grouping key* the
# family-disjoint split is built on. So an arbitrary attribution is worse than
# a dropped row: it can place a domain in the train fold under a family it may
# not belong to while its real family is held out for test, which leaks across
# the split every published metric rests on.
#
# The builder used to award such a domain to whichever family iterated first,
# so the corpus depended on the order of `--families` - while the module
# docstring said these rows were dropped. These tests pin the docstring's
# reading, order-independently.


SHARED = "shared-by-two.com"


def _build_with_families(monkeypatch, families, per_family=None):
    """Run `build()` over stubbed family fetches - no network, no other source.

    Only the DGA side is exercised: the benign sources are stubbed empty, so
    what comes back is exactly the family attribution under test.
    """
    from detection_core.ml.dga.data import build_dataset as bd

    per_family = per_family or {}

    monkeypatch.setattr(bd, "fetch_dga_family", lambda f, **kw: list(per_family[f]))
    monkeypatch.setattr(bd, "fetch_benign", lambda *a, **kw: [])
    monkeypatch.setattr(bd, "fetch_benign_tail", lambda *a, **kw: [])
    monkeypatch.setattr(bd, "fetch_cdn", lambda *a, **kw: ([], {}))

    rows, report = bd.build(
        tranco_n=0,
        families=list(families),
        per_family_cap=100,
        seed=42,
        tranco_id=None,
        timeout=5.0,
        balance=False,
    )
    return rows, report


CORPORA = {
    "alpha": [SHARED, "alpha-only-one.com", "alpha-only-two.com"],
    "beta": [SHARED, "beta-only-one.com"],
    "gamma": ["gamma-only-one.com"],
}


def test_a_domain_claimed_by_two_families_is_dropped(monkeypatch):
    """Not awarded to the first claimant - dropped from both."""
    rows, report = _build_with_families(monkeypatch, ["alpha", "beta", "gamma"], CORPORA)

    domains = {domain for domain, _label, _family, _source in rows}
    assert SHARED not in domains, (
        "a domain under two families has no defensible attribution"
    )
    # Everything unambiguous survives - the drop is surgical, not a purge.
    assert domains == {
        "alpha-only-one.com",
        "alpha-only-two.com",
        "beta-only-one.com",
        "gamma-only-one.com",
    }
    assert report["cross_family_dropped"] == 1


@pytest.mark.parametrize(
    "order",
    [
        ["alpha", "beta", "gamma"],
        ["beta", "alpha", "gamma"],
        ["gamma", "beta", "alpha"],
        ["beta", "gamma", "alpha"],
    ],
)
def test_the_corpus_does_not_depend_on_family_order(monkeypatch, order):
    """The load-bearing property: same request, any order, same corpus.

    Under "first family wins" this failed outright - ``alpha`` first put
    ``SHARED`` in ``alpha``, ``beta`` first put it in ``beta``.
    """
    rows, _ = _build_with_families(monkeypatch, order, CORPORA)

    assert {(domain, family) for domain, _label, family, _source in rows} == {
        ("alpha-only-one.com", "alpha"),
        ("alpha-only-two.com", "alpha"),
        ("beta-only-one.com", "beta"),
        ("gamma-only-one.com", "gamma"),
    }


def test_a_domain_claimed_by_every_family_is_dropped_from_all(monkeypatch):
    """The degenerate case: no family has a better claim than any other."""
    corpora = {
        "alpha": [SHARED, "alpha-only.com"],
        "beta": [SHARED],
        "gamma": [SHARED, "gamma-only.com"],
    }
    rows, report = _build_with_families(monkeypatch, ["alpha", "beta", "gamma"], corpora)

    assert {d for d, _l, _f, _s in rows} == {"alpha-only.com", "gamma-only.com"}
    assert report["cross_family_dropped"] == 1
    # `beta` contributed nothing but is still reported, at zero, rather than
    # vanishing from the accounting.
    assert report["per_family_kept"]["beta"] == 0


def test_the_per_family_cap_is_measured_after_ambiguous_rows_are_dropped(monkeypatch):
    """A dropped row must not consume a slot the cap was counting.

    Otherwise an ambiguous domain would still cost the family a row - the
    attribution bug replaced by a quota bug.
    """
    from detection_core.ml.dga.data import build_dataset as bd

    corpora = {
        "alpha": [SHARED, "a1.com", "a2.com", "a3.com"],
        "beta": [SHARED],
    }
    monkeypatch.setattr(bd, "fetch_dga_family", lambda f, **kw: list(corpora[f]))
    monkeypatch.setattr(bd, "fetch_benign", lambda *a, **kw: [])
    monkeypatch.setattr(bd, "fetch_benign_tail", lambda *a, **kw: [])
    monkeypatch.setattr(bd, "fetch_cdn", lambda *a, **kw: ([], {}))

    rows, report = bd.build(
        tranco_n=0,
        families=["alpha", "beta"],
        per_family_cap=3,
        seed=42,
        tranco_id=None,
        timeout=5.0,
        balance=False,
    )

    assert report["per_family_kept"]["alpha"] == 3
    assert {d for d, _l, _f, _s in rows} == {"a1.com", "a2.com", "a3.com"}


def test_a_family_listed_twice_is_fetched_and_counted_once(monkeypatch):
    """``--families alpha,alpha`` is one family, not two."""
    calls: list[str] = []

    from detection_core.ml.dga.data import build_dataset as bd

    def counting_fetch(family, **kwargs):
        calls.append(family)
        return ["a1.com", "a2.com"]

    monkeypatch.setattr(bd, "fetch_dga_family", counting_fetch)
    monkeypatch.setattr(bd, "fetch_benign", lambda *a, **kw: [])
    monkeypatch.setattr(bd, "fetch_benign_tail", lambda *a, **kw: [])
    monkeypatch.setattr(bd, "fetch_cdn", lambda *a, **kw: ([], {}))

    rows, report = bd.build(
        tranco_n=0,
        families=["alpha", "alpha"],
        per_family_cap=100,
        seed=42,
        tranco_id=None,
        timeout=5.0,
        balance=False,
    )

    assert calls == ["alpha"], "a repeated family must not be fetched twice"
    assert report["cross_family_dropped"] == 0
    assert {d for d, _l, _f, _s in rows} == {"a1.com", "a2.com"}


def test_an_unambiguous_corpus_reports_nothing_dropped(monkeypatch):
    """The ordinary case stays quiet - and the counter means what it says."""
    corpora = {"alpha": ["a1.com"], "beta": ["b1.com"]}
    rows, report = _build_with_families(monkeypatch, ["alpha", "beta"], corpora)

    assert report["cross_family_dropped"] == 0
    assert len(rows) == 2
