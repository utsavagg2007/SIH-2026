"""Dataset validation, deduplication and leakage-safe splitting."""

from __future__ import annotations

from pathlib import Path

import pytest

from detection_core.ml.dga.dataset import (
    LABEL_BENIGN,
    LABEL_DGA,
    load_dataset,
    parse_label,
    split_dataset,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "dga_domains.csv"


def write_csv(tmp_path: Path, rows: str, name: str = "domains.csv") -> Path:
    path = tmp_path / name
    path.write_text(rows, encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Labels
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, LABEL_BENIGN),
        (1, LABEL_DGA),
        ("0", LABEL_BENIGN),
        ("1", LABEL_DGA),
        ("benign", LABEL_BENIGN),
        ("DGA", LABEL_DGA),
        (" dga ", LABEL_DGA),
    ],
)
def test_accepted_labels(value, expected):
    assert parse_label(value) == expected


@pytest.mark.parametrize("value", [2, -1, "", "maybe", None, True, 1.5])
def test_invalid_label_rejected(value):
    """15."""
    with pytest.raises(ValueError):
        parse_label(value)


# --------------------------------------------------------------------------
# CSV contract
# --------------------------------------------------------------------------


def test_loads_the_fixture():
    dataset = load_dataset(FIXTURE)
    assert len(dataset) == dataset.stats.deduplicated_rows
    assert dataset.stats.benign_count > 0
    assert dataset.stats.dga_count > 0


@pytest.mark.parametrize(
    "rows",
    ["label\n0\n", "domain\ngoogle.com\n", "host,klass\ngoogle.com,0\n"],
)
def test_missing_required_columns_rejected(tmp_path, rows):
    """14."""
    with pytest.raises(ValueError, match="missing required column"):
        load_dataset(write_csv(tmp_path, rows))


def test_invalid_label_in_csv_reports_the_line(tmp_path):
    path = write_csv(tmp_path, "domain,label\ngoogle.com,0\nbad.com,7\n")
    with pytest.raises(ValueError, match="line 3"):
        load_dataset(path)


def test_empty_domain_in_csv_rejected(tmp_path):
    path = write_csv(tmp_path, "domain,label\ngoogle.com,0\n,1\n")
    with pytest.raises(ValueError, match="line 3"):
        load_dataset(path)


# --------------------------------------------------------------------------
# Deduplication
# --------------------------------------------------------------------------


def test_duplicate_normalized_domains_deduplicated(tmp_path):
    """16, 18. Normalization happens before duplicate detection."""
    path = write_csv(
        tmp_path,
        "domain,label\ngoogle.com,0\nGOOGLE.COM,0\n  google.com.  ,0\nbad.com,1\n",
    )
    dataset = load_dataset(path)

    assert dataset.stats.raw_rows == 4
    assert dataset.stats.deduplicated_rows == 2
    assert dataset.stats.duplicates_removed == 2
    assert sorted(dataset.domains) == ["bad.com", "google.com"]


def test_conflicting_duplicate_labels_rejected(tmp_path):
    """17. Never silently pick one."""
    path = write_csv(tmp_path, "domain,label\ngoogle.com,0\nGOOGLE.COM,1\n")
    with pytest.raises(ValueError, match="conflicting labels"):
        load_dataset(path)


def test_counts_reflect_deduplicated_rows(tmp_path):
    path = write_csv(tmp_path, "domain,label\na.com,0\na.com,0\nb.com,1\n")
    dataset = load_dataset(path)
    assert (dataset.stats.benign_count, dataset.stats.dga_count) == (1, 1)


# --------------------------------------------------------------------------
# Splitting
# --------------------------------------------------------------------------


def test_train_and_test_domains_are_disjoint():
    """19. The leakage rule."""
    split = split_dataset(load_dataset(FIXTURE))
    assert set(split.train_domains).isdisjoint(split.test_domains)


def test_split_is_deterministic():
    """20."""
    dataset = load_dataset(FIXTURE)
    first = split_dataset(dataset, random_state=42)
    second = split_dataset(dataset, random_state=42)

    assert first.train_domains == second.train_domains
    assert first.test_domains == second.test_domains


def test_different_seed_gives_a_different_split():
    dataset = load_dataset(FIXTURE)
    assert (
        split_dataset(dataset, random_state=42).test_domains
        != split_dataset(dataset, random_state=7).test_domains
    )


def test_split_is_stratified_on_the_fixture():
    """21."""
    dataset = load_dataset(FIXTURE)
    split = split_dataset(dataset, test_size=0.25)

    assert split.stratified
    assert set(split.train_labels) == {LABEL_BENIGN, LABEL_DGA}
    assert set(split.test_labels) == {LABEL_BENIGN, LABEL_DGA}


def test_split_sizes_add_up():
    dataset = load_dataset(FIXTURE)
    split = split_dataset(dataset)
    assert split.train_size + split.test_size == len(dataset)


def test_split_falls_back_when_stratification_impossible(tmp_path):
    """A single DGA example cannot be stratified; degrade, do not crash."""
    path = write_csv(tmp_path, "domain,label\na.com,0\nb.com,0\nc.com,0\nd.com,1\n")
    split = split_dataset(load_dataset(path), test_size=0.5)
    assert not split.stratified


def test_split_needs_at_least_two_domains(tmp_path):
    path = write_csv(tmp_path, "domain,label\na.com,0\n")
    with pytest.raises(ValueError, match="at least 2"):
        split_dataset(load_dataset(path))
