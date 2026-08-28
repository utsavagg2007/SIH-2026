"""Offline DGA training pipeline and CLI.

    CSV -> normalize -> validate -> deduplicate -> split -> fit -> evaluate -> save

Usage::

    python -m detection_core.ml.dga.training \\
        --input domains.csv --output artifacts/dga_model.joblib

Metrics reported here describe *this dataset only*. On a small or synthetic
dataset they say the plumbing works - they are not evidence of production
performance, which depends entirely on having representative benign and DGA
training data.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from .dataset import LABEL_BENIGN, LABEL_DGA, Dataset, load_dataset, split_dataset
from .model import DGAModel

__all__ = ["TrainingResult", "evaluate", "train_dga", "main"]


@dataclass
class TrainingResult:
    """Everything a training run produced."""

    model: DGAModel
    metrics: dict[str, Any]
    dataset: Dataset
    model_path: Path | None = None
    feature_importances: list[tuple[str, float]] = field(default_factory=list)

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
            f"  accuracy          : {self.metrics['accuracy']:.4f}",
            f"  precision (dga)   : {self.metrics['precision']:.4f}",
            f"  recall (dga)      : {self.metrics['recall']:.4f}",
            f"  f1 (dga)          : {self.metrics['f1']:.4f}",
            f"  roc_auc           : {self.metrics['roc_auc']}",
            f"  confusion matrix  : {self.metrics['confusion_matrix']}",
        ]
        if self.model_path:
            lines.append(f"  saved to          : {self.model_path}")
        lines.append(
            "  NOTE: metrics describe this dataset only, not production quality."
        )
        return "\n".join(lines)


def evaluate(model: DGAModel, domains: list[str], labels: list[int]) -> dict[str, Any]:
    """Score a fitted model on a held-out set, safe on degenerate splits."""
    predicted = model.predict(domains)
    metrics: dict[str, Any] = {
        "accuracy": float(accuracy_score(labels, predicted)),
        "precision": float(
            precision_score(labels, predicted, pos_label=LABEL_DGA, zero_division=0)
        ),
        "recall": float(
            recall_score(labels, predicted, pos_label=LABEL_DGA, zero_division=0)
        ),
        "f1": float(f1_score(labels, predicted, pos_label=LABEL_DGA, zero_division=0)),
        "confusion_matrix": confusion_matrix(
            labels, predicted, labels=[LABEL_BENIGN, LABEL_DGA]
        ).tolist(),
    }

    # ROC-AUC is undefined unless the test set contains both classes.
    if len(set(labels)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(labels, model.predict_scores(domains)))
    else:
        metrics["roc_auc"] = None
    return metrics


def train_dga(
    input_csv: str | Path,
    output_path: str | Path | None = None,
    *,
    test_size: float = 0.25,
    random_state: int = 42,
    **model_params: Any,
) -> TrainingResult:
    """Run the full offline pipeline and optionally persist the model."""
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

    metrics = {
        "raw_rows": dataset.stats.raw_rows,
        "deduplicated_rows": dataset.stats.deduplicated_rows,
        "duplicates_removed": dataset.stats.duplicates_removed,
        "benign_count": dataset.stats.benign_count,
        "dga_count": dataset.stats.dga_count,
        "train_size": split.train_size,
        "test_size": split.test_size,
        "stratified": split.stratified,
        **evaluate(model, split.test_domains, split.test_labels),
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
