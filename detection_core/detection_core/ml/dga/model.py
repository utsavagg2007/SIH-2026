"""The DGA model bundle: fit, predict, save, load.

Wraps a scikit-learn estimator together with the metadata needed to stop
silent misuse - above all the exact feature names and order the model was
trained on. Loading a bundle whose schema no longer matches this build of
:mod:`.features` is an error, not a warning.

On score semantics: :meth:`DGAModel.predict_scores` returns the classifier's
class-1 (DGA) probability estimate. A Random Forest's ``predict_proba`` is a
vote fraction, **not** a calibrated probability, so it is deliberately named
``dga_score`` and no ``ThreatAlert.score_type`` is assigned here. Deciding
whether calibration is required belongs to live integration.
"""

from __future__ import annotations

import datetime as _datetime
import warnings
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

import joblib
import sklearn
from sklearn.ensemble import RandomForestClassifier

from .dataset import CLASS_MAPPING, LABEL_DGA
from .features import FEATURE_NAMES, extract_feature_matrix, normalize_domain

__all__ = [
    "MODEL_FORMAT_VERSION",
    "DEFAULT_MODEL_PARAMS",
    "DGAPrediction",
    "DGAModelMetadata",
    "DGAModel",
]

#: Bumped whenever the on-disk bundle layout changes incompatibly.
MODEL_FORMAT_VERSION = "1.0"

#: Conservative baseline. Nonlinear lexical interactions, no scaling needed,
#: feature importances available, and ``class_weight`` to blunt imbalance.
DEFAULT_MODEL_PARAMS: dict[str, Any] = {
    "n_estimators": 200,
    "class_weight": "balanced",
    "random_state": 42,
    "n_jobs": -1,
}


#: joblib's unpickler rebuilds each array with ``array.shape = ...``, which
#: NumPy 2.5 deprecated in favour of ``np.reshape``. That is third-party code
#: on both sides - we neither write the arrays nor reshape them - and it
#: fires once per array in the bundle, so a 200-tree forest buries a terminal
#: in several hundred identical notices.
#:
#: Silenced by exact message, only for the duration of the load call, and
#: nowhere else: see :func:`_load_bundle`. Deliberately not fixed by pinning
#: ``numpy<2.5``, because nothing is broken - a deprecation notice about a
#: line we do not own is not a reason to hold back a working dependency.
_JOBLIB_RESHAPE_DEPRECATION = "Setting the shape on a NumPy array has been deprecated"


def _load_bundle(path: Path) -> object:
    """``joblib.load`` with one known third-party deprecation muted.

    The filter is scoped three ways: to this single call, to
    ``DeprecationWarning``, and to that one message. Every other warning
    raised while reading a bundle - including any other deprecation, any
    ``UserWarning`` about a version mismatch, and every exception - passes
    through untouched, because the point is to remove noise, not to stop
    hearing about a corrupt or incompatible artifact.
    """
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=_JOBLIB_RESHAPE_DEPRECATION,
            category=DeprecationWarning,
        )
        return joblib.load(path)


@dataclass(frozen=True)
class DGAPrediction:
    """One domain's verdict."""

    domain: str
    normalized_domain: str
    label: int
    dga_score: float

    @property
    def is_dga(self) -> bool:
        return self.label == LABEL_DGA


@dataclass
class DGAModelMetadata:
    """Everything needed to verify a loaded bundle is safe to use."""

    format_version: str = MODEL_FORMAT_VERSION
    model_type: str = "RandomForestClassifier"
    feature_names: tuple[str, ...] = FEATURE_NAMES
    class_mapping: dict[str, int] = field(default_factory=lambda: dict(CLASS_MAPPING))
    training_config: dict[str, Any] = field(default_factory=dict)
    sklearn_version: str = sklearn.__version__
    trained_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DGAModel:
    """A fitted (or fittable) DGA classifier plus its provenance."""

    def __init__(
        self,
        estimator: RandomForestClassifier | None = None,
        metadata: DGAModelMetadata | None = None,
    ) -> None:
        self.estimator = estimator
        self.metadata = metadata or DGAModelMetadata()

    # --- construction ---------------------------------------------------

    @classmethod
    def new(cls, **params: Any) -> DGAModel:
        """A fresh, unfitted model with the baseline parameters."""
        config = {**DEFAULT_MODEL_PARAMS, **params}
        return cls(
            estimator=RandomForestClassifier(**config),
            metadata=DGAModelMetadata(training_config=config),
        )

    @property
    def is_fitted(self) -> bool:
        return self.estimator is not None and hasattr(self.estimator, "classes_")

    def _require_fitted(self) -> RandomForestClassifier:
        if not self.is_fitted:
            raise RuntimeError("model is not fitted; call fit() or load() first")
        return self.estimator

    # --- training -------------------------------------------------------

    def fit(self, domains: Iterable[str], labels: Iterable[int]) -> DGAModel:
        """Fit on raw domain strings; features are extracted internally."""
        if self.estimator is None:
            self.estimator = RandomForestClassifier(**DEFAULT_MODEL_PARAMS)

        domains = list(domains)
        labels = list(labels)
        if not domains:
            raise ValueError("cannot fit on an empty dataset")
        if len(domains) != len(labels):
            raise ValueError(
                f"domains and labels differ in length: {len(domains)} vs {len(labels)}"
            )

        self.estimator.fit(extract_feature_matrix(domains), labels)
        self.metadata.feature_names = FEATURE_NAMES
        self.metadata.trained_at = _datetime.datetime.now(
            tz=_datetime.timezone.utc
        ).isoformat()
        return self

    # --- inference ------------------------------------------------------

    def predict(self, domains: Iterable[str]) -> list[int]:
        """Predicted labels (0 benign / 1 DGA) for many domains."""
        estimator = self._require_fitted()
        domains = list(domains)
        if not domains:
            return []
        return [int(label) for label in estimator.predict(extract_feature_matrix(domains))]

    def predict_scores(self, domains: Iterable[str]) -> list[float]:
        """Class-1 (DGA) scores in [0, 1]. Not calibrated probabilities.

        The DGA column is located via ``classes_`` rather than assumed to be
        index 1, so a single-class or reordered fit cannot silently invert
        the score.
        """
        estimator = self._require_fitted()
        domains = list(domains)
        if not domains:
            return []

        classes = list(estimator.classes_)
        probabilities = estimator.predict_proba(extract_feature_matrix(domains))
        if LABEL_DGA not in classes:
            # Trained on benign examples only - nothing can score as DGA.
            return [0.0] * len(domains)
        column = classes.index(LABEL_DGA)
        return [float(row[column]) for row in probabilities]

    def predict_domain(self, domain: str) -> DGAPrediction:
        """Verdict for a single domain."""
        return self.predict_domains([domain])[0]

    def predict_domains(self, domains: Iterable[str]) -> list[DGAPrediction]:
        """Verdicts for many domains, in input order."""
        domains = list(domains)
        labels = self.predict(domains)
        scores = self.predict_scores(domains)
        return [
            DGAPrediction(
                domain=domain,
                normalized_domain=normalize_domain(domain),
                label=label,
                dga_score=score,
            )
            for domain, label, score in zip(domains, labels, scores)
        ]

    # --- explanation ----------------------------------------------------

    def feature_importances(self) -> list[tuple[str, float]]:
        """(name, importance) pairs, sorted most important first.

        Ties break on feature name so the order is fully deterministic.
        """
        estimator = self._require_fitted()
        pairs = [
            (name, float(value))
            for name, value in zip(
                self.metadata.feature_names, estimator.feature_importances_
            )
        ]
        return sorted(pairs, key=lambda item: (-item[1], item[0]))

    # --- persistence ----------------------------------------------------

    def save(self, path: str | Path) -> Path:
        """Write the bundle (estimator + metadata) to disk."""
        self._require_fitted()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"metadata": self.metadata.to_dict(), "estimator": self.estimator}, path
        )
        return path

    @classmethod
    def load(cls, path: str | Path) -> DGAModel:
        """Load a bundle, refusing one whose feature schema no longer matches."""
        path = Path(path)
        bundle = _load_bundle(path)
        if not isinstance(bundle, dict) or "estimator" not in bundle:
            raise ValueError(f"{path}: not a DGA model bundle")

        raw_metadata = dict(bundle.get("metadata") or {})
        stored_version = raw_metadata.get("format_version")
        if stored_version != MODEL_FORMAT_VERSION:
            raise ValueError(
                f"{path}: model format {stored_version!r} does not match this "
                f"build's {MODEL_FORMAT_VERSION!r}; retrain the model"
            )

        stored_features = tuple(raw_metadata.get("feature_names") or ())
        if stored_features != FEATURE_NAMES:
            raise ValueError(
                f"{path}: feature schema mismatch - the model was trained on "
                f"{len(stored_features)} features and this build extracts "
                f"{len(FEATURE_NAMES)}. Retrain rather than predicting with a "
                "mismatched vector."
            )

        raw_metadata["feature_names"] = stored_features
        return cls(estimator=bundle["estimator"], metadata=DGAModelMetadata(**raw_metadata))
