"""Dataset loading, validation and leakage-safe splitting.

The CSV contract is two columns, ``domain`` and ``label``:

    domain,label
    google.com,0
    xj3kq9zv.com,1

Canonical labels are ``0 = benign`` and ``1 = DGA``. That mapping is fixed
everywhere in this package - DGA is always the positive class, so
``predict_proba`` column 1 is always the DGA score.

**Leakage rule:** domains are normalized, *then* deduplicated, *then* split.
Because deduplication removes repeats outright, the same normalized domain
can never land in both train and test.
"""

from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from sklearn.model_selection import train_test_split

from .features import normalize_domain

__all__ = [
    "LABEL_BENIGN",
    "LABEL_DGA",
    "LABEL_NAMES",
    "CLASS_MAPPING",
    "DatasetStats",
    "Dataset",
    "SplitDataset",
    "parse_label",
    "load_dataset",
    "split_dataset",
]

LABEL_BENIGN = 0
LABEL_DGA = 1
LABEL_NAMES = {LABEL_BENIGN: "benign", LABEL_DGA: "dga"}
CLASS_MAPPING = {"benign": LABEL_BENIGN, "dga": LABEL_DGA}

#: Textual spellings accepted in the CSV, beyond plain 0 / 1.
_LABEL_ALIASES = {
    "0": LABEL_BENIGN,
    "benign": LABEL_BENIGN,
    "legit": LABEL_BENIGN,
    "1": LABEL_DGA,
    "dga": LABEL_DGA,
    "malicious": LABEL_DGA,
}

REQUIRED_COLUMNS = ("domain", "label")


@dataclass(frozen=True)
class DatasetStats:
    """What the loader saw and what it kept."""

    raw_rows: int
    deduplicated_rows: int
    duplicates_removed: int
    benign_count: int
    dga_count: int


@dataclass(frozen=True)
class Dataset:
    """Normalized, deduplicated domains with their labels."""

    domains: list[str]
    labels: list[int]
    stats: DatasetStats

    def __len__(self) -> int:
        return len(self.domains)


@dataclass(frozen=True)
class SplitDataset:
    """A train/test split guaranteed free of shared domains."""

    train_domains: list[str]
    train_labels: list[int]
    test_domains: list[str]
    test_labels: list[int]
    stratified: bool

    @property
    def train_size(self) -> int:
        return len(self.train_domains)

    @property
    def test_size(self) -> int:
        return len(self.test_domains)


def parse_label(value: object) -> int:
    """Coerce a CSV label cell to 0 or 1, or raise with a clear message."""
    if isinstance(value, bool):
        raise ValueError(f"invalid label {value!r}: use 0 (benign) or 1 (dga)")
    if isinstance(value, int):
        if value in (LABEL_BENIGN, LABEL_DGA):
            return value
        raise ValueError(f"invalid label {value!r}: use 0 (benign) or 1 (dga)")
    if isinstance(value, str):
        alias = _LABEL_ALIASES.get(value.strip().lower())
        if alias is not None:
            return alias
    raise ValueError(
        f"invalid label {value!r}: expected one of "
        f"{sorted(_LABEL_ALIASES)} (0 = benign, 1 = dga)"
    )


def load_dataset(path: str | Path) -> Dataset:
    """Read, validate, normalize and deduplicate a domain CSV.

    Raises on a missing column, an unusable label, an unusable domain, or a
    duplicate normalized domain carrying conflicting labels - guessing which
    label was meant would quietly poison training.
    """
    path = Path(path)
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        missing = [column for column in REQUIRED_COLUMNS if column not in fieldnames]
        if missing:
            raise ValueError(
                f"{path}: missing required column(s) {missing}; "
                f"found {fieldnames}"
            )
        rows = list(reader)

    raw_rows = len(rows)
    by_domain: dict[str, int] = {}
    duplicates_removed = 0

    for line_number, row in enumerate(rows, start=2):  # row 1 is the header
        try:
            domain = normalize_domain(row["domain"] or "")
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{path} line {line_number}: {exc}") from exc
        try:
            label = parse_label(row["label"])
        except ValueError as exc:
            raise ValueError(f"{path} line {line_number}: {exc}") from exc

        existing = by_domain.get(domain)
        if existing is None:
            by_domain[domain] = label
        elif existing != label:
            raise ValueError(
                f"{path} line {line_number}: domain {domain!r} appears with "
                f"conflicting labels ({LABEL_NAMES[existing]} and "
                f"{LABEL_NAMES[label]}); resolve the dataset rather than "
                "letting training pick one"
            )
        else:
            duplicates_removed += 1

    domains = list(by_domain)
    labels = [by_domain[domain] for domain in domains]
    counts = Counter(labels)

    return Dataset(
        domains=domains,
        labels=labels,
        stats=DatasetStats(
            raw_rows=raw_rows,
            deduplicated_rows=len(domains),
            duplicates_removed=duplicates_removed,
            benign_count=counts.get(LABEL_BENIGN, 0),
            dga_count=counts.get(LABEL_DGA, 0),
        ),
    )


def split_dataset(
    dataset: Dataset, *, test_size: float = 0.25, random_state: int = 42
) -> SplitDataset:
    """Split into train/test, stratified by label when the counts allow it.

    Input is already deduplicated, so no normalized domain can appear on both
    sides. Stratification needs at least two members of each class and a test
    fold large enough to hold one of each; when that does not hold we fall
    back to an unstratified split rather than failing the run.
    """
    if len(dataset) < 2:
        raise ValueError("need at least 2 domains to split")

    counts = Counter(dataset.labels)
    n_test = round(test_size * len(dataset))
    can_stratify = (
        len(counts) >= 2
        and min(counts.values()) >= 2
        and n_test >= len(counts)
        and (len(dataset) - n_test) >= len(counts)
    )

    train_domains, test_domains, train_labels, test_labels = train_test_split(
        dataset.domains,
        dataset.labels,
        test_size=test_size,
        random_state=random_state,
        shuffle=True,
        stratify=dataset.labels if can_stratify else None,
    )

    return SplitDataset(
        train_domains=list(train_domains),
        train_labels=list(train_labels),
        test_domains=list(test_domains),
        test_labels=list(test_labels),
        stratified=can_stratify,
    )
