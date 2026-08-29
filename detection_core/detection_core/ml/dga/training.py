"""Offline DGA training pipeline and CLI.

    CSV -> normalize -> validate -> deduplicate -> split -> fit -> evaluate -> save

Usage::

    python -m detection_core.ml.dga.training \\
        --input domains.csv --output artifacts/dga_model.joblib

Metrics reported here describe *this dataset only*. On a small or synthetic
dataset they say the plumbing works - they are not evidence of production
performance, which depends entirely on having representative benign and DGA
training data.

Evaluation is deliberately split in two, because the two answer different
questions:

* **Decision metrics** - precision, recall, F1, and the confusion counts -
  are computed at an **explicit threshold**, defaulting to
  :data:`DEFAULT_EVAL_THRESHOLD` (0.75), the value the live detector uses.
  Reporting them at scikit-learn's implicit 0.5 argmax would describe a
  classifier nobody runs.
* **Ranking metrics** - ROC-AUC and PR-AUC (average precision) - are computed
  from the **raw model scores**, so they are threshold-free.

The raw score is a RandomForest class-1 vote fraction and is **not a
calibrated probability** anywhere in this module.

**Group-aware splitting is not available**, because the dataset contract
(``domain,label`` - see :mod:`.dataset`) carries no family, campaign or seed
column. Family-aware evaluation needs genuine group metadata from the data
source; deriving "families" from the domain text itself would invent the very
labels the split is supposed to respect, and would report leakage-free
numbers that are nothing of the kind. Until such a column exists, the
supported split is the label-stratified one in :func:`.split_dataset`.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from .dataset import LABEL_BENIGN, LABEL_DGA, Dataset, load_dataset, split_dataset
from .features import extract_feature_matrix
from .model import DGAModel

__all__ = [
    "DEFAULT_EVAL_THRESHOLD",
    "DEFAULT_SWEEP_THRESHOLDS",
    "EvaluationResult",
    "TrainingResult",
    "evaluate",
    "evaluate_baseline",
    "evaluate_scores",
    "sweep_thresholds",
    "train_dga",
    "main",
]

#: Decision threshold the offline evaluator uses unless told otherwise.
#:
#: Deliberately the same number as ``DGAConfig.score_threshold`` so offline
#: numbers describe the classifier that actually runs. It is duplicated
#: rather than imported: this is Phase-1 offline code and must not depend on
#: the live detector package, which imports *this* one. Changing the
#: detector's threshold does not change this constant - and this constant
#: tunes nothing, it only decides what gets measured.
DEFAULT_EVAL_THRESHOLD = 0.75

#: Thresholds :func:`sweep_thresholds` reports on by default. Analysis only:
#: nothing here selects one.
DEFAULT_SWEEP_THRESHOLDS = (0.50, 0.60, 0.70, 0.75, 0.80, 0.90)

#: Baseline settings. Fixed and deterministic so the comparison is stable;
#: ``class_weight`` mirrors the RandomForest's so neither model gets a free
#: advantage on an imbalanced set.
BASELINE_PARAMS: dict[str, Any] = {
    "max_iter": 1000,
    "class_weight": "balanced",
    "random_state": 42,
}


@dataclass
class TrainingResult:
    """Everything a training run produced."""

    model: DGAModel
    metrics: dict[str, Any]
    dataset: Dataset
    model_path: Path | None = None
    feature_importances: list[tuple[str, float]] = field(default_factory=list)
    #: The trained model's own evaluation, structured.
    evaluation: EvaluationResult | None = None
    #: LogisticRegression on the same split, for context. ``None`` when the
    #: training fold held a single class.
    baseline: EvaluationResult | None = None
    #: Decision metrics at several thresholds. Analysis only - see
    #: :func:`sweep_thresholds`.
    threshold_sweep: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "DGA training summary",
            f"  raw rows          : {self.metrics['raw_rows']}",
            f"  after dedupe      : {self.metrics['deduplicated_rows']}"
            f" (removed {self.metrics['duplicates_removed']})",
            f"  benign / dga      : {self.metrics['benign_count']}"
            f" / {self.metrics['dga_count']}",
            f"  train / test      : {self.metrics['train_size']}"
            f" / {self.metrics['test_size']}"
            f" (stratified={self.metrics['stratified']})",
            f"  threshold         : {self.metrics['threshold']}"
            " (decision metrics below are measured at it)",
            f"  accuracy          : {self.metrics['accuracy']:.4f}",
            f"  precision (dga)   : {self.metrics['precision']:.4f}",
            f"  recall (dga)      : {self.metrics['recall']:.4f}",
            f"  f1 (dga)          : {self.metrics['f1']:.4f}",
            f"  roc_auc (raw)     : {self.metrics['roc_auc']}",
            f"  pr_auc  (raw)     : {self.metrics['pr_auc']}",
            f"  tp/fp/tn/fn       : {self.metrics['tp']}/{self.metrics['fp']}"
            f"/{self.metrics['tn']}/{self.metrics['fn']}",
            f"  confusion matrix  : {self.metrics['confusion_matrix']}",
        ]
        if self.metrics.get("note"):
            lines.append(f"  note              : {self.metrics['note']}")

        baseline = self.metrics.get("baseline")
        if baseline is None:
            lines.append("  baseline          : not fitted (single-class train fold)")
        else:
            lines.append(
                f"  baseline (LogReg) : f1={baseline['f1']:.4f}"
                f" precision={baseline['precision']:.4f}"
                f" recall={baseline['recall']:.4f}"
                f" pr_auc={baseline['pr_auc']}"
            )

        if self.threshold_sweep:
            lines.append("  threshold sweep (analysis only, selects nothing):")
            lines.append("    thr    precision  recall     f1         fp    fn")
            for row in self.threshold_sweep:
                lines.append(
                    f"    {row['threshold']:.2f}   {row['precision']:.4f}     "
                    f"{row['recall']:.4f}     {row['f1']:.4f}     "
                    f"{row['fp']:<5} {row['fn']}"
                )

        if self.model_path:
            lines.append(f"  saved to          : {self.model_path}")
        lines.append(
            "  NOTE: metrics describe this dataset only, not production quality."
        )
        lines.append(
            "  NOTE: scores are RandomForest vote fractions, not calibrated "
            "probabilities."
        )
        return "\n".join(lines)


@dataclass(frozen=True)
class EvaluationResult:
    """One model's quality on one evaluation set, at one threshold.

    JSON-serializable via :meth:`to_dict`. Deliberately its own small type -
    ``ThreatAlert`` is the live wire contract and has no business describing
    offline model quality.
    """

    #: Which model produced the scores, e.g. ``"RandomForestClassifier"``.
    model: str
    #: The decision threshold the counts below were computed at.
    threshold: float
    samples: int
    positives: int
    negatives: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    #: Threshold-free, from raw scores. ``None`` when undefined - see ``note``.
    roc_auc: float | None
    pr_auc: float | None
    tp: int
    fp: int
    tn: int
    fn: int
    #: Why a metric is ``None``, when one is. Never a substitute value.
    note: str | None = None

    @property
    def confusion_matrix(self) -> list[list[int]]:
        """``[[tn, fp], [fn, tp]]`` - sklearn's layout for ``labels=[0, 1]``."""
        return [[self.tn, self.fp], [self.fn, self.tp]]

    def to_dict(self) -> dict[str, Any]:
        """Flat, JSON-ready. Keys are stable; new ones may be appended."""
        return {
            "model": self.model,
            "threshold": self.threshold,
            "samples": self.samples,
            "positives": self.positives,
            "negatives": self.negatives,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "roc_auc": self.roc_auc,
            "pr_auc": self.pr_auc,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "confusion_matrix": self.confusion_matrix,
            "note": self.note,
        }


def evaluate_scores(
    labels: list[int],
    scores: list[float],
    *,
    threshold: float = DEFAULT_EVAL_THRESHOLD,
    model: str = "unknown",
) -> EvaluationResult:
    """Metrics for raw scores against true labels, at an explicit threshold.

    The whole point of taking *scores* rather than predictions: the decision
    is made here, at a threshold the caller controls, instead of inheriting
    scikit-learn's implicit 0.5 argmax. A domain qualifies when
    ``score >= threshold``, matching the live detector's comparison.

    Ranking metrics are computed from the same raw scores and ignore the
    threshold entirely. Both are ``None`` on a single-class evaluation set,
    where neither is mathematically defined, and ``note`` says so rather than
    a 0.0 or a 0.5 being invented.
    """
    if len(labels) != len(scores):
        raise ValueError(
            f"labels and scores differ in length: {len(labels)} vs {len(scores)}"
        )
    if not labels:
        raise ValueError("cannot evaluate an empty set")
    if not 0.0 < threshold <= 1.0:
        raise ValueError("threshold must be within (0.0, 1.0]")

    predicted = [LABEL_DGA if score >= threshold else LABEL_BENIGN for score in scores]
    matrix = confusion_matrix(labels, predicted, labels=[LABEL_BENIGN, LABEL_DGA])
    (tn, fp), (fn, tp) = matrix.tolist()

    both_classes = len(set(labels)) > 1
    note = None
    if not both_classes:
        note = (
            "roc_auc and pr_auc are undefined on a single-class evaluation set "
            "and are reported as null rather than substituted"
        )

    return EvaluationResult(
        model=model,
        threshold=float(threshold),
        samples=len(labels),
        positives=sum(1 for label in labels if label == LABEL_DGA),
        negatives=sum(1 for label in labels if label == LABEL_BENIGN),
        accuracy=float(accuracy_score(labels, predicted)),
        precision=float(
            precision_score(labels, predicted, pos_label=LABEL_DGA, zero_division=0)
        ),
        recall=float(
            recall_score(labels, predicted, pos_label=LABEL_DGA, zero_division=0)
        ),
        f1=float(f1_score(labels, predicted, pos_label=LABEL_DGA, zero_division=0)),
        # Raw scores, never the thresholded decisions.
        roc_auc=float(roc_auc_score(labels, scores)) if both_classes else None,
        pr_auc=float(average_precision_score(labels, scores)) if both_classes else None,
        tp=int(tp),
        fp=int(fp),
        tn=int(tn),
        fn=int(fn),
        note=note,
    )


def evaluate(
    model: DGAModel,
    domains: list[str],
    labels: list[int],
    *,
    threshold: float = DEFAULT_EVAL_THRESHOLD,
) -> dict[str, Any]:
    """Score a fitted model on a held-out set, safe on degenerate splits.

    Returns the flat dict form of :class:`EvaluationResult`. Decisions are
    taken at ``threshold``; ROC-AUC and PR-AUC come from the raw scores.
    """
    model_name = type(model.estimator).__name__ if model.estimator is not None else "unknown"
    return evaluate_scores(
        list(labels),
        model.predict_scores(domains),
        threshold=threshold,
        model=model_name,
    ).to_dict()


def sweep_thresholds(
    labels: list[int],
    scores: list[float],
    thresholds: Iterable[float] = DEFAULT_SWEEP_THRESHOLDS,
    *,
    model: str = "unknown",
) -> list[dict[str, Any]]:
    """Decision metrics at several thresholds, for reading - not for choosing.

    **Nothing here selects a threshold**, and the live detector's setting is
    never touched. Picking one off a sweep of the same data it was measured
    on is how a number gets called optimal when it is merely overfitted; that
    decision needs a real validation set and a stated cost trade-off between
    a false positive and a missed domain.
    """
    rows = []
    for threshold in thresholds:
        result = evaluate_scores(labels, scores, threshold=threshold, model=model)
        rows.append(
            {
                "threshold": result.threshold,
                "precision": result.precision,
                "recall": result.recall,
                "f1": result.f1,
                "fp": result.fp,
                "fn": result.fn,
            }
        )
    return rows


def evaluate_baseline(
    train_domains: list[str],
    train_labels: list[int],
    test_domains: list[str],
    test_labels: list[int],
    *,
    threshold: float = DEFAULT_EVAL_THRESHOLD,
    random_state: int = 42,
) -> EvaluationResult | None:
    """A cheap LogisticRegression reference point on the same split.

    Context, not a competitor: a RandomForest score means little until you
    know what a linear model on the *same 19 lexical features* and the *same
    split* achieves. If the two are close, the forest is not earning its
    complexity; if the forest is well ahead, the nonlinearity is doing real
    work.

    **Evaluation only.** This model is never saved, never returned as an
    artifact and never used at detection time - :class:`DGAModel` remains the
    only thing that ships. Features are scaled first, since a linear model
    over columns ranging from 0-1 ratios to 60-character lengths would
    otherwise be reading the scale rather than the signal.

    Returns ``None`` when the training fold holds a single class, where a
    classifier cannot be fitted at all.
    """
    if len(set(train_labels)) < 2:
        return None

    baseline = make_pipeline(
        StandardScaler(),
        LogisticRegression(**{**BASELINE_PARAMS, "random_state": random_state}),
    )
    baseline.fit(extract_feature_matrix(train_domains), train_labels)

    classes = list(baseline.classes_)
    probabilities = baseline.predict_proba(extract_feature_matrix(test_domains))
    if LABEL_DGA not in classes:  # pragma: no cover - guarded by the check above
        scores = [0.0] * len(test_domains)
    else:
        column = classes.index(LABEL_DGA)
        scores = [float(row[column]) for row in probabilities]

    return evaluate_scores(
        list(test_labels),
        scores,
        threshold=threshold,
        model="LogisticRegression",
    )


def train_dga(
    input_csv: str | Path,
    output_path: str | Path | None = None,
    *,
    test_size: float = 0.25,
    random_state: int = 42,
    threshold: float = DEFAULT_EVAL_THRESHOLD,
    include_baseline: bool = True,
    sweep: Iterable[float] | None = DEFAULT_SWEEP_THRESHOLDS,
    **model_params: Any,
) -> TrainingResult:
    """Run the full offline pipeline and optionally persist the model.

    ``threshold`` decides only what is *measured*: it is the cut applied to
    raw scores when computing precision/recall/F1 and the confusion counts.
    It changes nothing the saved artifact does, and it does not tune the live
    detector, which owns its own ``DGAConfig.score_threshold``.

    The split is label-stratified. It is **not** family-aware, because the
    dataset contract has no family column - see this module's docstring.
    """
    dataset = load_dataset(input_csv)
    if dataset.stats.dga_count == 0 or dataset.stats.benign_count == 0:
        raise ValueError(
            "dataset must contain both benign (0) and dga (1) examples; got "
            f"{dataset.stats.benign_count} benign and {dataset.stats.dga_count} dga"
        )

    split = split_dataset(dataset, test_size=test_size, random_state=random_state)

    # Belt and braces: deduplication already guarantees this, but a silent
    # leak would inflate every metric below, so assert it rather than trust it.
    overlap = set(split.train_domains) & set(split.test_domains)
    if overlap:
        raise AssertionError(f"train/test leakage on {len(overlap)} domain(s)")

    model = DGAModel.new(random_state=random_state, **model_params)
    model.fit(split.train_domains, split.train_labels)

    # One set of raw scores, reused by every metric below, so the headline
    # numbers, the baseline comparison and the sweep all describe exactly the
    # same predictions on exactly the same rows.
    test_scores = model.predict_scores(split.test_domains)
    evaluation = evaluate_scores(
        split.test_labels,
        test_scores,
        threshold=threshold,
        model=type(model.estimator).__name__,
    )

    baseline = None
    if include_baseline:
        baseline = evaluate_baseline(
            split.train_domains,
            split.train_labels,
            split.test_domains,
            split.test_labels,
            threshold=threshold,
            random_state=random_state,
        )

    threshold_sweep: list[dict[str, Any]] = []
    if sweep:
        threshold_sweep = sweep_thresholds(
            split.test_labels, test_scores, sweep, model=evaluation.model
        )

    metrics = {
        "raw_rows": dataset.stats.raw_rows,
        "deduplicated_rows": dataset.stats.deduplicated_rows,
        "duplicates_removed": dataset.stats.duplicates_removed,
        "benign_count": dataset.stats.benign_count,
        "dga_count": dataset.stats.dga_count,
        "train_size": split.train_size,
        "test_size": split.test_size,
        "stratified": split.stratified,
        # Stratified by label only; no group/family split is available.
        "split_strategy": "stratified" if split.stratified else "random",
        "group_aware_split": False,
        **evaluation.to_dict(),
        "baseline": baseline.to_dict() if baseline is not None else None,
        "threshold_sweep": threshold_sweep,
    }

    model_path = None
    if output_path is not None:
        model_path = model.save(output_path)

    return TrainingResult(
        model=model,
        metrics=metrics,
        dataset=dataset,
        model_path=model_path,
        feature_importances=model.feature_importances(),
        evaluation=evaluation,
        baseline=baseline,
        threshold_sweep=threshold_sweep,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m detection_core.ml.dga.training",
        description="Train the offline DGA lexical classifier.",
    )
    parser.add_argument("-i", "--input", required=True, help="CSV with domain,label")
    parser.add_argument("-o", "--output", help="Where to write the .joblib bundle")
    parser.add_argument("--test-size", type=float, default=0.25)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_EVAL_THRESHOLD,
        help=(
            "decision threshold the reported precision/recall/F1/confusion "
            f"counts are measured at (default: {DEFAULT_EVAL_THRESHOLD}). "
            "Reporting only - it does not tune the live detector"
        ),
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="skip the LogisticRegression reference point",
    )
    parser.add_argument(
        "--no-sweep",
        action="store_true",
        help="skip the multi-threshold analysis table",
    )
    parser.add_argument(
        "--top-features", type=int, default=10, help="How many importances to print"
    )
    parser.add_argument("--json", action="store_true", help="Print metrics as JSON")
    args = parser.parse_args(argv)

    try:
        result = train_dga(
            args.input,
            args.output,
            test_size=args.test_size,
            random_state=args.random_state,
            threshold=args.threshold,
            include_baseline=not args.no_baseline,
            sweep=None if args.no_sweep else DEFAULT_SWEEP_THRESHOLDS,
            n_estimators=args.n_estimators,
        )
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.metrics, indent=2))
    else:
        print(result.summary())
        if args.top_features > 0:
            print("\nTop features:")
            for name, importance in result.feature_importances[: args.top_features]:
                print(f"  {name:<24} {importance:.4f}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
