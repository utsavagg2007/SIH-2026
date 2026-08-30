"""Dataset loading, validation and leakage-safe splitting.

The CSV contract is two required columns, ``domain`` and ``label``:

    domain,label
    google.com,0
    xj3kq9zv.com,1

Canonical labels are ``0 = benign`` and ``1 = DGA``. That mapping is fixed
everywhere in this package - DGA is always the positive class, so
``predict_proba`` column 1 is always the DGA score.

**Optional ``family`` column.** When the CSV carries a third column named
``family`` (the malware family for a DGA row, ``"benign"`` for a benign row),
:func:`load_dataset` keeps it and :func:`split_dataset` switches to a
*family-disjoint* split: no family present in the test fold appears in the
training fold. This measures the real task - detecting domains from families
the model was **not** trained on - instead of the easier in-family task a
label-stratified split measures. Without the column, behaviour is exactly as
before: a label-stratified split. The family label is never synthesized from
the domain text; it must come from the data source.

**Leakage rule:** domains are normalized, *then* deduplicated, *then* split.
Because deduplication removes repeats outright, the same normalized domain
can never land in both train and test. With a ``family`` column the split is
disjoint at the family level as well.
"""

from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from sklearn.model_selection import GroupShuffleSplit, train_test_split

from .features import normalize_domain

__all__ = [
    "LABEL_BENIGN",
    "LABEL_DGA",
    "LABEL_NAMES",
    "CLASS_MAPPING",
    "REQUIRED_COLUMNS",
    "FAMILY_COLUMN",
    "BENIGN_FAMILY",
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

#: Optional third column. When present, :func:`split_dataset` becomes
#: family-disjoint. The value is a free-form family name for DGA rows; benign
#: rows conventionally carry :data:`BENIGN_FAMILY` but any value is accepted.
FAMILY_COLUMN = "family"

#: Conventional ``family`` value for a benign row. Not enforced - a benign row
#: may carry any family string - but this is what :mod:`.data.build_dataset`
#: writes, and what documentation refers to.
BENIGN_FAMILY = "benign"


@dataclass(frozen=True)
class DatasetStats:
    """What the loader saw and what it kept."""

    raw_rows: int
    deduplicated_rows: int
    duplicates_removed: int
    benign_count: int
    dga_count: int
    #: Distinct ``family`` values seen (including a benign family, if the
    #: column was present). ``0`` when the CSV had no ``family`` column.
    family_count: int = 0
    #: ``family -> row count``, for reporting. Empty without a ``family``
    #: column. Sorted by descending count then name is the caller's job.
    family_breakdown: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class Dataset:
    """Normalized, deduplicated domains with their labels.

    ``families`` is ``None`` when the source CSV had no ``family`` column, and
    otherwise a list aligned 1:1 with ``domains`` / ``labels``. It is never
    derived from the domain text - a missing column means missing, not
    "infer it".
    """

    domains: list[str]
    labels: list[int]
    stats: DatasetStats
    families: list[str] | None = None

    def __len__(self) -> int:
        return len(self.domains)

    @property
    def has_families(self) -> bool:
        """Whether a genuine ``family`` column was supplied."""
        return self.families is not None


@dataclass(frozen=True)
class SplitDataset:
    """A train/test split guaranteed free of shared domains.

    When ``grouped`` is true the split is also disjoint at the family level:
    no ``family`` in ``test_families`` appears in ``train_families``. In that
    mode ``stratified`` is ``False`` - a family-disjoint split cannot also
    guarantee the label ratio, and pretending otherwise would misdescribe it.
    """

    train_domains: list[str]
    train_labels: list[int]
    test_domains: list[str]
    test_labels: list[int]
    stratified: bool
    #: True when the split was family-disjoint (see class docstring).
    grouped: bool = False
    #: Families aligned with ``train_domains`` / ``test_domains``; ``None``
    #: when the source had no ``family`` column.
    train_families: list[str] | None = None
    test_families: list[str] | None = None

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

    Raises on a missing required column, an unusable label, an unusable
    domain, or a duplicate normalized domain carrying conflicting labels -
    guessing which label was meant would quietly poison training.

    If the optional ``family`` column is present it is validated too: every
    row must supply a non-empty value, and a duplicate domain appearing under
    two different families is a conflict, rejected the same way as a
    conflicting label. Without the column, ``Dataset.families`` is ``None``
    and nothing about the load changes.
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
        has_family = FAMILY_COLUMN in fieldnames
        rows = list(reader)

    raw_rows = len(rows)
    # domain -> label, and (when the column exists) domain -> family.
    by_domain: dict[str, int] = {}
    family_by_domain: dict[str, str] = {}
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

        family: str | None = None
        if has_family:
            family = (row.get(FAMILY_COLUMN) or "").strip()
            if not family:
                raise ValueError(
                    f"{path} line {line_number}: the {FAMILY_COLUMN!r} column is "
                    f"present but row for domain {domain!r} leaves it empty; a "
                    "family label must never be synthesized, so fill it or drop "
                    "the column entirely"
                )

        existing = by_domain.get(domain)
        if existing is None:
            by_domain[domain] = label
            if family is not None:
                family_by_domain[domain] = family
        elif existing != label:
            raise ValueError(
                f"{path} line {line_number}: domain {domain!r} appears with "
                f"conflicting labels ({LABEL_NAMES[existing]} and "
                f"{LABEL_NAMES[label]}); resolve the dataset rather than "
                "letting training pick one"
            )
        elif family is not None and family_by_domain.get(domain) != family:
            raise ValueError(
                f"{path} line {line_number}: domain {domain!r} appears under "
                f"conflicting families ({family_by_domain.get(domain)!r} and "
                f"{family!r}); resolve the dataset rather than guessing"
            )
        else:
            duplicates_removed += 1

    domains = list(by_domain)
    labels = [by_domain[domain] for domain in domains]
    families = [family_by_domain[domain] for domain in domains] if has_family else None
    counts = Counter(labels)
    family_breakdown = dict(Counter(families)) if families is not None else {}

    return Dataset(
        domains=domains,
        labels=labels,
        stats=DatasetStats(
            raw_rows=raw_rows,
            deduplicated_rows=len(domains),
            duplicates_removed=duplicates_removed,
            benign_count=counts.get(LABEL_BENIGN, 0),
            dga_count=counts.get(LABEL_DGA, 0),
            family_count=len(family_breakdown),
            family_breakdown=family_breakdown,
        ),
        families=families,
    )


def split_dataset(
    dataset: Dataset, *, test_size: float = 0.25, random_state: int = 42
) -> SplitDataset:
    """Split into train/test.

    Two modes, chosen by the data:

    * **family-disjoint** (``dataset.has_families`` and the DGA rows span at
      least two distinct families) - the **DGA** rows are split with
      :class:`~sklearn.model_selection.GroupShuffleSplit` on the family
      column, so no DGA family in the test fold appears in training; the
      **benign** rows are split with an ordinary shuffle at the same
      ``test_size`` and concatenated. Benign domains have no meaningful
      "family", and grouping them - benign is one group - would push every
      benign row into a single fold. This mode measures generalization to
      *unseen DGA families* while keeping both classes in both folds.
      ``stratified`` is ``False``: a group split cannot also pin the label
      ratio exactly.
    * **label-stratified** (no ``family`` column, or fewer than two DGA
      families) - the original behaviour, unchanged: ``train_test_split``
      stratified by label when the class counts allow it, otherwise an
      unstratified shuffle.

    Input is already deduplicated, so no normalized domain can appear on both
    sides in either mode.
    """
    if len(dataset) < 2:
        raise ValueError("need at least 2 domains to split")

    if dataset.families is not None:
        dga_idx = [i for i, y in enumerate(dataset.labels) if y == LABEL_DGA]
        dga_families = {dataset.families[i] for i in dga_idx}
        if len(dga_families) >= 2:
            benign_idx = [i for i, y in enumerate(dataset.labels) if y == LABEL_BENIGN]

            splitter = GroupShuffleSplit(
                n_splits=1, test_size=test_size, random_state=random_state
            )
            rel_train, rel_test = next(
                splitter.split(
                    dga_idx,
                    [dataset.labels[i] for i in dga_idx],
                    groups=[dataset.families[i] for i in dga_idx],
                )
            )
            train_pos = [dga_idx[j] for j in rel_train]
            test_pos = [dga_idx[j] for j in rel_test]

            if benign_idx:
                train_neg, test_neg = train_test_split(
                    benign_idx,
                    test_size=test_size,
                    random_state=random_state,
                    shuffle=True,
                )
            else:
                train_neg, test_neg = [], []

            train_idx = sorted(train_pos + list(train_neg))
            test_idx = sorted(test_pos + list(test_neg))
            return SplitDataset(
                train_domains=[dataset.domains[i] for i in train_idx],
                train_labels=[dataset.labels[i] for i in train_idx],
                test_domains=[dataset.domains[i] for i in test_idx],
                test_labels=[dataset.labels[i] for i in test_idx],
                stratified=False,
                grouped=True,
                train_families=[dataset.families[i] for i in train_idx],
                test_families=[dataset.families[i] for i in test_idx],
            )

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
