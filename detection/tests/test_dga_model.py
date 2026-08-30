"""DGA model bundle: fit, predict, persist, explain.

Deliberately avoids asserting exact Random Forest probabilities - only
shape, range, finiteness and save/load stability, which are stable
properties rather than flaky ones.
"""

from __future__ import annotations

import math
from pathlib import Path

import joblib
import pytest

from detection_core.ml.dga.dataset import LABEL_BENIGN, LABEL_DGA, load_dataset
from detection_core.ml.dga.features import FEATURE_NAMES
from detection_core.ml.dga.model import (
    _load_bundle,
    MODEL_FORMAT_VERSION,
    DGAModel,
    DGAPrediction,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "dga_domains.csv"


@pytest.fixture(scope="module")
def dataset():
    return load_dataset(FIXTURE)


@pytest.fixture(scope="module")
def fitted_model(dataset) -> DGAModel:
    return DGAModel.new(n_estimators=50).fit(dataset.domains, dataset.labels)


# --------------------------------------------------------------------------
# Fitting
# --------------------------------------------------------------------------


def test_model_fits_the_fixture(fitted_model, dataset):
    """22. Sanity that fitting works - NOT a quality claim."""
    assert fitted_model.is_fitted
    predicted = fitted_model.predict(dataset.domains)
    correct = sum(p == a for p, a in zip(predicted, dataset.labels))
    assert correct / len(dataset) >= 0.9


def test_unfitted_model_refuses_to_predict():
    with pytest.raises(RuntimeError, match="not fitted"):
        DGAModel.new().predict(["google.com"])


def test_fit_rejects_empty_dataset():
    with pytest.raises(ValueError, match="empty dataset"):
        DGAModel.new().fit([], [])


def test_fit_rejects_mismatched_lengths():
    with pytest.raises(ValueError, match="differ in length"):
        DGAModel.new().fit(["a.com", "b.com"], [0])


# --------------------------------------------------------------------------
# Prediction
# --------------------------------------------------------------------------


def test_predict_one_domain(fitted_model):
    """23."""
    prediction = fitted_model.predict_domain("google.com")
    assert isinstance(prediction, DGAPrediction)
    assert prediction.domain == "google.com"
    assert prediction.normalized_domain == "google.com"


def test_predict_many_domains(fitted_model):
    """24."""
    domains = ["google.com", "kqxvbzmwjrph.com", "github.com"]
    predictions = fitted_model.predict_domains(domains)

    assert len(predictions) == 3
    assert [p.domain for p in predictions] == domains


@pytest.mark.parametrize(
    "domain", ["google.com", "kqxvbzmwjrph.com", "a.io", "MAIL.GOOGLE.COM."]
)
def test_label_is_zero_or_one(fitted_model, domain):
    """25."""
    assert fitted_model.predict_domain(domain).label in (LABEL_BENIGN, LABEL_DGA)


@pytest.mark.parametrize(
    "domain", ["google.com", "kqxvbzmwjrph.com", "a.io", "x-y-z.co.uk"]
)
def test_dga_score_within_range(fitted_model, domain):
    """26, 27."""
    score = fitted_model.predict_domain(domain).dga_score
    assert math.isfinite(score)
    assert 0.0 <= score <= 1.0


def test_prediction_normalizes_the_reported_domain(fitted_model):
    prediction = fitted_model.predict_domain("  GOOGLE.COM.  ")
    assert prediction.normalized_domain == "google.com"


def test_is_dga_matches_the_label(fitted_model):
    for prediction in fitted_model.predict_domains(["google.com", "kqxvbzmwjrph.com"]):
        assert prediction.is_dga == (prediction.label == LABEL_DGA)


def test_empty_input_returns_empty_output(fitted_model):
    assert fitted_model.predict([]) == []
    assert fitted_model.predict_scores([]) == []


def test_scores_align_with_the_dga_class_not_column_index(fitted_model, dataset):
    """Guards against label inversion: DGA must be class 1 everywhere."""
    classes = list(fitted_model.estimator.classes_)
    assert classes == [LABEL_BENIGN, LABEL_DGA]

    scores = fitted_model.predict_scores(dataset.domains)
    labels = fitted_model.predict(dataset.domains)
    for score, label in zip(scores, labels):
        assert (score >= 0.5) == (label == LABEL_DGA)


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


def test_save_and_load_preserves_predictions(fitted_model, tmp_path, dataset):
    """28."""
    path = fitted_model.save(tmp_path / "model.joblib")
    assert path.exists()

    reloaded = DGAModel.load(path)
    probe = dataset.domains[:10] + ["brand-new-domain.com", "zzqkxjvwnbrm.info"]

    assert reloaded.predict(probe) == fitted_model.predict(probe)
    assert reloaded.predict_scores(probe) == fitted_model.predict_scores(probe)


def test_saved_metadata_is_preserved(fitted_model, tmp_path):
    """29."""
    reloaded = DGAModel.load(fitted_model.save(tmp_path / "model.joblib"))

    assert reloaded.metadata.format_version == MODEL_FORMAT_VERSION
    assert reloaded.metadata.model_type == "RandomForestClassifier"
    assert tuple(reloaded.metadata.feature_names) == FEATURE_NAMES
    assert reloaded.metadata.class_mapping == {"benign": 0, "dga": 1}
    assert reloaded.metadata.training_config["n_estimators"] == 50
    assert reloaded.metadata.trained_at is not None
    assert reloaded.metadata.sklearn_version


def test_unfitted_model_cannot_be_saved(tmp_path):
    with pytest.raises(RuntimeError, match="not fitted"):
        DGAModel.new().save(tmp_path / "model.joblib")


def test_incompatible_feature_schema_is_rejected(fitted_model, tmp_path):
    """30. A stale bundle must fail loudly, not predict on the wrong vector."""
    path = fitted_model.save(tmp_path / "model.joblib")
    # Read via the project's helper rather than joblib directly: a bare
    # joblib.load re-emits NumPy 2.5's reshape deprecation once per array.
    bundle = _load_bundle(path)
    bundle["metadata"]["feature_names"] = ("length", "entropy")
    joblib.dump(bundle, path)

    with pytest.raises(ValueError, match="feature schema mismatch"):
        DGAModel.load(path)


def test_incompatible_format_version_is_rejected(fitted_model, tmp_path):
    path = fitted_model.save(tmp_path / "model.joblib")
    # Read via the project's helper rather than joblib directly: a bare
    # joblib.load re-emits NumPy 2.5's reshape deprecation once per array.
    bundle = _load_bundle(path)
    bundle["metadata"]["format_version"] = "0.1"
    joblib.dump(bundle, path)

    with pytest.raises(ValueError, match="does not match"):
        DGAModel.load(path)


def test_non_bundle_file_is_rejected(tmp_path):
    path = tmp_path / "junk.joblib"
    joblib.dump(["not", "a", "bundle"], path)

    with pytest.raises(ValueError, match="not a DGA model bundle"):
        DGAModel.load(path)


# --------------------------------------------------------------------------
# Explanation
# --------------------------------------------------------------------------


def test_feature_importance_names_match_the_extractor(fitted_model):
    """31."""
    importances = fitted_model.feature_importances()
    assert [name for name, _ in importances] and set(
        name for name, _ in importances
    ) == set(FEATURE_NAMES)
    assert len(importances) == len(FEATURE_NAMES)


def test_feature_importances_are_finite_and_sorted(fitted_model):
    """32."""
    importances = fitted_model.feature_importances()
    values = [value for _, value in importances]

    assert all(math.isfinite(value) for value in values)
    assert all(value >= 0.0 for value in values)
    assert values == sorted(values, reverse=True)
    assert sum(values) == pytest.approx(1.0)


def test_feature_importances_are_deterministic(fitted_model):
    assert fitted_model.feature_importances() == fitted_model.feature_importances()


# --------------------------------------------------------------------------
# One forest traversal per verdict, and it must be the same verdict
# --------------------------------------------------------------------------


def test_predict_domains_matches_the_two_call_path_exactly(fitted_model):
    """``predict_domains`` derives the label from the probabilities.

    For a RandomForestClassifier that is what ``predict`` does - sklearn
    defines it as ``classes_.take(argmax(predict_proba))`` - so the derived
    label must equal the one the separate call returns, for every domain.
    If a future estimator breaks that identity, this fails.
    """
    domains = load_dataset(FIXTURE).domains

    predictions = fitted_model.predict_domains(domains)

    assert [p.label for p in predictions] == fitted_model.predict(domains)
    assert [p.dga_score for p in predictions] == fitted_model.predict_scores(domains)


def test_a_single_verdict_matches_the_batch(fitted_model):
    domain = "kq3v9x2mzt7wp1.com"

    single = fitted_model.predict_domain(domain)
    batch = fitted_model.predict_domains([domain])[0]

    assert single == batch


def test_an_empty_batch_returns_nothing(fitted_model):
    assert fitted_model.predict_domains([]) == []


def test_a_benign_only_fit_still_scores_zero():
    """The single-class guard must survive the single-traversal path."""
    model = DGAModel.new(n_estimators=10, random_state=42, n_jobs=1)
    model.fit(["google.com", "wikipedia.org", "github.com"], [0, 0, 0])

    predictions = model.predict_domains(["kq3v9x2mzt7wp1.com", "google.com"])

    assert [p.dga_score for p in predictions] == [0.0, 0.0]
    assert [p.label for p in predictions] == model.predict(
        ["kq3v9x2mzt7wp1.com", "google.com"]
    )
