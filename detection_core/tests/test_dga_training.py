"""End-to-end offline DGA training pipeline and CLI."""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from detection_core.ml.dga.features import FEATURE_NAMES
from detection_core.ml.dga.model import DGAModel
from detection_core.ml.dga.training import evaluate, main, train_dga

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "dga_domains.csv"

REQUIRED_METRICS = (
    "raw_rows",
    "deduplicated_rows",
    "duplicates_removed",
    "benign_count",
    "dga_count",
    "train_size",
    "test_size",
    "stratified",
    "accuracy",
    "precision",
    "recall",
    "f1",
    "confusion_matrix",
    "roc_auc",
)


@pytest.fixture(scope="module")
def result():
    return train_dga(FIXTURE, n_estimators=50)


# --------------------------------------------------------------------------
# 33-36. Pipeline
# --------------------------------------------------------------------------


def test_end_to_end_training_succeeds(result):
    """33."""
    assert result.model.is_fitted
    assert len(result.dataset) > 0


def test_training_writes_a_model_file(tmp_path):
    """34."""
    output = tmp_path / "artifacts" / "dga_model.joblib"
    result = train_dga(FIXTURE, output, n_estimators=50)

    assert result.model_path == output
    assert output.exists() and output.stat().st_size > 0
    assert DGAModel.load(output).is_fitted


def test_metrics_contain_every_required_key(result):
    """35."""
    for key in REQUIRED_METRICS:
        assert key in result.metrics


@pytest.mark.parametrize("key", ["accuracy", "precision", "recall", "f1"])
def test_core_metrics_are_finite_and_in_range(result, key):
    value = result.metrics[key]
    assert math.isfinite(value)
    assert 0.0 <= value <= 1.0


def test_confusion_matrix_shape(result):
    """36."""
    matrix = result.metrics["confusion_matrix"]
    assert len(matrix) == 2
    assert all(len(row) == 2 for row in matrix)
    assert sum(sum(row) for row in matrix) == result.metrics["test_size"]


def test_roc_auc_present_when_both_classes_in_test(result):
    assert result.metrics["roc_auc"] is None or 0.0 <= result.metrics["roc_auc"] <= 1.0


def test_counts_are_consistent(result):
    metrics = result.metrics
    assert metrics["benign_count"] + metrics["dga_count"] == metrics["deduplicated_rows"]
    assert metrics["train_size"] + metrics["test_size"] == metrics["deduplicated_rows"]
    assert metrics["deduplicated_rows"] <= metrics["raw_rows"]


def test_training_is_deterministic():
    first = train_dga(FIXTURE, n_estimators=50, random_state=42)
    second = train_dga(FIXTURE, n_estimators=50, random_state=42)
    assert first.metrics == second.metrics


def test_feature_importances_returned(result):
    assert len(result.feature_importances) == len(FEATURE_NAMES)


def test_summary_mentions_the_dataset_caveat(result):
    assert "not production quality" in result.summary()


def test_training_rejects_a_single_class_dataset(tmp_path):
    path = tmp_path / "one_class.csv"
    path.write_text("domain,label\na.com,0\nb.com,0\nc.com,0\n", encoding="utf-8")

    with pytest.raises(ValueError, match="both benign"):
        train_dga(path)


def test_evaluate_is_safe_on_a_single_class_test_set(result):
    """zero_division-safe, and ROC-AUC is skipped rather than crashing."""
    metrics = evaluate(result.model, ["google.com", "github.com"], [0, 0])
    assert metrics["roc_auc"] is None
    assert all(math.isfinite(metrics[k]) for k in ("accuracy", "precision", "recall", "f1"))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def test_cli_trains_and_saves(tmp_path, capsys):
    output = tmp_path / "model.joblib"
    code = main(
        ["--input", str(FIXTURE), "--output", str(output), "--n-estimators", "50"]
    )

    assert code == 0
    assert output.exists()
    assert "DGA training summary" in capsys.readouterr().out


def test_cli_json_output(tmp_path, capsys):
    import json

    code = main(["--input", str(FIXTURE), "--n-estimators", "50", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert set(REQUIRED_METRICS).issubset(payload)


def test_cli_reports_a_bad_dataset_without_traceback(tmp_path, capsys):
    path = tmp_path / "bad.csv"
    path.write_text("host,label\na.com,0\n", encoding="utf-8")

    code = main(["--input", str(path)])
    assert code == 1
    assert "ERROR" in capsys.readouterr().err


# --------------------------------------------------------------------------
# 37. No artifact is expected in source control
# --------------------------------------------------------------------------


def test_model_artifacts_are_gitignored():
    """37. Trained binaries must never be tracked."""
    gitignore = (
        Path(__file__).resolve().parent.parent / ".gitignore"
    ).read_text(encoding="utf-8")

    assert "*.joblib" in gitignore
    assert "artifacts/" in gitignore


def test_no_model_artifact_is_checked_in():
    repo_package = Path(__file__).resolve().parent.parent
    assert not list(repo_package.rglob("*.joblib"))
