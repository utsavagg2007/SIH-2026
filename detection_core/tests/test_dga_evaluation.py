"""Offline DGA evaluation hardening.

What is proved here is that the *reported numbers* are correct and honest:
decisions taken at an explicit threshold, ranking metrics taken from raw
scores, undefined metrics reported as undefined, and a baseline measured on
the same split as the model it contextualizes.

Every case uses hand-built scores or the local synthetic CSV fixture -
nothing is downloaded, and no model artifact is written outside ``tmp_path``.

Live detection is out of scope here and must stay untouched; the guard tests
at the end assert that this offline work did not move the detector's
threshold or its alert semantics.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from detection_core.ml.dga import features as features_module
from detection_core.ml.dga.dataset import REQUIRED_COLUMNS, load_dataset, split_dataset
from detection_core.ml.dga.features import FEATURE_NAMES
from detection_core.ml.dga.model import DGAModel, _load_bundle
from detection_core.ml.dga.training import (
    DEFAULT_EVAL_THRESHOLD,
    DEFAULT_SWEEP_THRESHOLDS,
    EvaluationResult,
    evaluate,
    evaluate_baseline,
    evaluate_scores,
    sweep_thresholds,
    train_dga,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "dga_domains.csv"

#: A deliberately hand-checkable set. At threshold 0.75 the decisions are
#: [1, 1, 0, 0, 0, 0] against truth [1, 1, 1, 0, 0, 0]:
#:   tp = 2 (0.95, 0.80)   fn = 1 (0.60, a DGA scored below the cut)
#:   tn = 3 (0.40, 0.20, 0.05)   fp = 0
LABELS = [1, 1, 1, 0, 0, 0]
SCORES = [0.95, 0.80, 0.60, 0.40, 0.20, 0.05]


@pytest.fixture(scope="module")
def result():
    """One training run, reused - fitting is the slow part."""
    return train_dga(FIXTURE, n_estimators=50)


# --------------------------------------------------------------------------
# 1-2. Metric arithmetic on a deterministic set
# --------------------------------------------------------------------------


def test_confusion_counts_are_exact():
    outcome = evaluate_scores(LABELS, SCORES, threshold=0.75)

    assert (outcome.tp, outcome.fp, outcome.tn, outcome.fn) == (2, 0, 3, 1)
    assert outcome.samples == 6
    assert outcome.positives == 3
    assert outcome.negatives == 3
    # sklearn's layout, [[tn, fp], [fn, tp]], and it accounts for every row.
    assert outcome.confusion_matrix == [[3, 0], [1, 2]]
    assert sum(sum(row) for row in outcome.confusion_matrix) == outcome.samples


def test_precision_recall_f1_match_the_counts():
    outcome = evaluate_scores(LABELS, SCORES, threshold=0.75)

    assert outcome.precision == pytest.approx(2 / 2)          # tp / (tp + fp)
    assert outcome.recall == pytest.approx(2 / 3)             # tp / (tp + fn)
    assert outcome.f1 == pytest.approx(2 * (1.0 * (2 / 3)) / (1.0 + 2 / 3))
    assert outcome.accuracy == pytest.approx(5 / 6)           # (tp + tn) / n


def test_a_boundary_score_counts_as_a_detection():
    """``>=`` at the threshold, matching the live detector's comparison."""
    exact = evaluate_scores([1, 0], [0.75, 0.10], threshold=0.75)

    assert exact.tp == 1 and exact.fn == 0


# --------------------------------------------------------------------------
# 3. Ranking metrics ignore the threshold
# --------------------------------------------------------------------------


def test_ranking_metrics_use_raw_scores_not_thresholded_decisions():
    """ROC-AUC/PR-AUC must not move when only the decision cut moves."""
    low = evaluate_scores(LABELS, SCORES, threshold=0.50)
    high = evaluate_scores(LABELS, SCORES, threshold=0.90)

    assert low.roc_auc == high.roc_auc
    assert low.pr_auc == high.pr_auc
    # This ordering separates the classes perfectly, whatever the cut.
    assert low.roc_auc == pytest.approx(1.0)
    assert low.pr_auc == pytest.approx(1.0)
    # ... while the decisions at those two thresholds genuinely differ.
    assert low.recall > high.recall


def test_ranking_metrics_fall_below_one_when_the_ordering_is_imperfect():
    """A benign domain scoring above a DGA one must cost ranking quality."""
    outcome = evaluate_scores([1, 0, 1, 0], [0.90, 0.80, 0.30, 0.10])

    assert outcome.roc_auc is not None
    assert 0.0 < outcome.roc_auc < 1.0
    assert 0.0 < outcome.pr_auc < 1.0


# --------------------------------------------------------------------------
# 4-5. The threshold is explicit, and defaults to the live 0.75
# --------------------------------------------------------------------------


def test_the_threshold_changes_the_decision_metrics():
    loose = evaluate_scores(LABELS, SCORES, threshold=0.50)
    strict = evaluate_scores(LABELS, SCORES, threshold=0.90)

    # 0.60 now qualifies: the third DGA is caught, nothing benign is hit.
    assert (loose.tp, loose.fn, loose.fp) == (3, 0, 0)
    assert loose.recall == pytest.approx(1.0)
    # Only 0.95 survives a 0.90 cut.
    assert (strict.tp, strict.fn) == (1, 2)
    assert strict.recall == pytest.approx(1 / 3)


def test_the_default_evaluation_threshold_is_the_live_value():
    assert DEFAULT_EVAL_THRESHOLD == 0.75
    assert evaluate_scores(LABELS, SCORES).threshold == 0.75
    # And the default really is applied, not merely stored.
    assert evaluate_scores(LABELS, SCORES).to_dict() == evaluate_scores(
        LABELS, SCORES, threshold=0.75
    ).to_dict()


def test_an_invalid_threshold_is_rejected():
    for bad in (0.0, -0.1, 1.5):
        with pytest.raises(ValueError, match="threshold"):
            evaluate_scores(LABELS, SCORES, threshold=bad)


# --------------------------------------------------------------------------
# 8. Single-class edge case
# --------------------------------------------------------------------------


def test_single_class_ranking_metrics_are_null_not_invented():
    outcome = evaluate_scores([0, 0, 0], [0.1, 0.2, 0.9], threshold=0.75)

    assert outcome.roc_auc is None
    assert outcome.pr_auc is None
    assert outcome.note and "undefined" in outcome.note
    # The threshold-based half is still perfectly well defined.
    assert (outcome.tp, outcome.fp, outcome.tn, outcome.fn) == (0, 1, 2, 0)
    assert all(math.isfinite(v) for v in (outcome.precision, outcome.recall, outcome.f1))


def test_mismatched_or_empty_input_is_rejected():
    with pytest.raises(ValueError, match="differ in length"):
        evaluate_scores([1, 0], [0.5])
    with pytest.raises(ValueError, match="empty"):
        evaluate_scores([], [])


# --------------------------------------------------------------------------
# 9. Serializable result shape
# --------------------------------------------------------------------------


def test_the_result_is_json_serializable_with_the_documented_keys():
    payload = evaluate_scores(LABELS, SCORES, model="RandomForestClassifier").to_dict()

    for key in (
        "model", "threshold", "samples", "positives", "negatives",
        "precision", "recall", "f1", "roc_auc", "pr_auc",
        "tp", "fp", "tn", "fn",
    ):
        assert key in payload, f"missing {key}"
    assert payload["model"] == "RandomForestClassifier"
    # Round-trips through JSON with no custom encoder.
    assert json.loads(json.dumps(payload)) == payload


def test_evaluate_scores_returns_the_structured_type():
    assert isinstance(evaluate_scores(LABELS, SCORES), EvaluationResult)


# --------------------------------------------------------------------------
# 6. Determinism
# --------------------------------------------------------------------------


def test_the_split_and_metrics_are_reproducible_at_random_state_42():
    first = split_dataset(load_dataset(FIXTURE), random_state=42)
    second = split_dataset(load_dataset(FIXTURE), random_state=42)

    assert first.train_domains == second.train_domains
    assert first.test_domains == second.test_domains

    a = train_dga(FIXTURE, n_estimators=50, random_state=42)
    b = train_dga(FIXTURE, n_estimators=50, random_state=42)
    assert a.metrics == b.metrics
    assert a.baseline.to_dict() == b.baseline.to_dict()


# --------------------------------------------------------------------------
# 7. LogisticRegression baseline
# --------------------------------------------------------------------------


def test_the_baseline_is_evaluated_on_the_same_split(result):
    """Same rows, same threshold - otherwise the comparison means nothing."""
    assert result.baseline is not None
    assert result.baseline.model == "LogisticRegression"
    assert result.baseline.samples == result.evaluation.samples
    assert result.baseline.positives == result.evaluation.positives
    assert result.baseline.negatives == result.evaluation.negatives
    assert result.baseline.threshold == result.evaluation.threshold


def test_the_baseline_is_reported_but_never_saved(result, tmp_path):
    """The artifact is still the RandomForest, alone."""
    out = tmp_path / "model.joblib"
    saved = train_dga(FIXTURE, out, n_estimators=50)

    assert saved.model_path == out
    loaded = DGAModel.load(out)
    assert type(loaded.estimator).__name__ == "RandomForestClassifier"
    assert loaded.metadata.model_type == "RandomForestClassifier"
    assert result.metrics["baseline"]["model"] == "LogisticRegression"


def test_the_baseline_can_be_skipped():
    assert train_dga(FIXTURE, n_estimators=50, include_baseline=False).baseline is None


def test_the_baseline_is_none_on_a_single_class_training_fold():
    """It cannot be fitted, and that is reported rather than faked."""
    assert (
        evaluate_baseline(["a.com", "b.com"], [0, 0], ["c.com"], [0]) is None
    )


# --------------------------------------------------------------------------
# 10. Threshold sweep is analysis only
# --------------------------------------------------------------------------


def test_the_sweep_reports_every_configured_threshold():
    rows = sweep_thresholds(LABELS, SCORES)

    assert [row["threshold"] for row in rows] == list(DEFAULT_SWEEP_THRESHOLDS)
    for row in rows:
        assert set(row) == {"threshold", "precision", "recall", "f1", "fp", "fn"}


def test_the_sweep_agrees_with_evaluating_at_each_threshold():
    for row in sweep_thresholds(LABELS, SCORES):
        direct = evaluate_scores(LABELS, SCORES, threshold=row["threshold"])
        assert row["precision"] == direct.precision
        assert row["recall"] == direct.recall
        assert (row["fp"], row["fn"]) == (direct.fp, direct.fn)


def test_the_sweep_selects_nothing(result):
    """No "best"/"recommended" key, and the reported threshold stays 0.75."""
    for row in result.threshold_sweep:
        assert not any(
            k in row for k in ("best", "recommended", "selected", "optimal")
        )
    assert result.metrics["threshold"] == DEFAULT_EVAL_THRESHOLD


# --------------------------------------------------------------------------
# 11. No fabricated family / group information
# --------------------------------------------------------------------------


def test_the_dataset_contract_carries_no_group_labels():
    """The premise of the "no grouped split" decision, pinned.

    If a genuine ``family`` / ``campaign`` / ``seed`` column is ever added to
    the CSV contract, this test fails and a group-aware split becomes both
    possible and required.
    """
    assert REQUIRED_COLUMNS == ("domain", "label")

    dataset = load_dataset(FIXTURE)
    for attribute in ("families", "family", "groups", "group", "campaigns", "seeds"):
        assert not hasattr(dataset, attribute), f"unexpected grouping: {attribute}"


def test_no_grouping_is_synthesized_from_domain_text():
    split = split_dataset(load_dataset(FIXTURE), random_state=42)

    for attribute in ("groups", "train_groups", "test_groups", "family_aware"):
        assert not hasattr(split, attribute), f"fabricated grouping: {attribute}"
    # The split reports honestly what it is: stratified by label, not by family.
    assert split.stratified is True


def test_metrics_state_that_the_split_is_not_group_aware(result):
    assert result.metrics["group_aware_split"] is False
    assert result.metrics["split_strategy"] == "stratified"


# --------------------------------------------------------------------------
# 12. Feature schema and artifact compatibility are untouched
# --------------------------------------------------------------------------


def test_the_feature_schema_is_still_the_same_nineteen():
    assert len(FEATURE_NAMES) == 19
    assert FEATURE_NAMES == features_module.FEATURE_NAMES
    assert FEATURE_NAMES[0] == "length" and FEATURE_NAMES[-1] == "longest_consonant_run"


def test_a_saved_artifact_still_round_trips(tmp_path):
    """Evaluation changes must not touch what goes into the bundle."""
    out = tmp_path / "model.joblib"
    original = train_dga(FIXTURE, out, n_estimators=50).model

    loaded = DGAModel.load(out)
    assert loaded.is_fitted
    assert loaded.metadata.feature_names == FEATURE_NAMES
    assert loaded.metadata.format_version == original.metadata.format_version
    # Same verdicts before and after a save/load cycle.
    domains = ["google.com", "kq3v9x2mzt7wp1.com"]
    assert loaded.predict(domains) == original.predict(domains)
    assert loaded.predict_scores(domains) == original.predict_scores(domains)


def test_the_bundle_gained_no_evaluation_fields(tmp_path):
    """Metadata stays as it was, so an older build can still read it."""
    import joblib

    out = tmp_path / "model.joblib"
    train_dga(FIXTURE, out, n_estimators=50)

    # Read via the project's helper rather than joblib directly: a bare
    # joblib.load re-emits NumPy 2.5's reshape deprecation once per array.
    bundle = _load_bundle(out)
    assert set(bundle) == {"metadata", "estimator"}
    assert set(bundle["metadata"]) == {
        "format_version", "model_type", "feature_names",
        "class_mapping", "training_config", "sklearn_version", "trained_at",
    }


# --------------------------------------------------------------------------
# Live detection is unchanged by this offline work
# --------------------------------------------------------------------------


def test_the_live_detector_threshold_is_untouched():
    from detection_core import DGAConfig

    assert DGAConfig().score_threshold == 0.75
    assert DGAConfig().cooldown_seconds == 300.0


def test_the_offline_module_does_not_import_the_live_detector():
    """Phase 1 must not depend on Phase 2 - the dependency runs the other way."""
    source = Path(
        features_module.__file__
    ).resolve().parent.joinpath("training.py").read_text(encoding="utf-8")

    assert "from ...detectors" not in source
    assert "import detection_core.detectors" not in source
    # The threshold is duplicated deliberately, with the reason stated.
    assert "DEFAULT_EVAL_THRESHOLD = 0.75" in source


def test_evaluate_keeps_its_dict_return_for_existing_callers(result):
    """Backward compatibility: the old keys are all still present."""
    metrics = evaluate(result.model, ["google.com", "kq3v9x2mzt7wp1.com"], [0, 1])

    assert isinstance(metrics, dict)
    for key in ("accuracy", "precision", "recall", "f1", "confusion_matrix", "roc_auc"):
        assert key in metrics
