"""Offline DGA (domain generation algorithm) classification.

    CSV -> normalize -> lexical features -> RandomForest -> dga_score

This package is the **offline half**: 19 lexical features, a dataset loader
with a leakage-safe split, the model bundle, and a training CLI whose
evaluation reports precision/recall/F1 and the confusion counts at an
explicit threshold alongside threshold-free ROC-AUC and PR-AUC, a
LogisticRegression baseline on the same split, and a multi-threshold sweep
that reports but never selects.

The **online half** is :class:`~detection_core.detectors.DGADetector`, which
is wired into the detector factory and correlates findings per source. It
needs two things this package cannot supply: a trained model artifact, and a
raw ``dns.query`` on the flow. Detector-v2 supplies the latter while legacy-m1d
does not; reconstructing a domain from an entropy value would be inventing data.

Requires the ``ml`` extra::

    pip install -e ".[ml]"

The training CLI runs as::

    python -m detection_core.ml.dga.training --input domains.csv
"""

from __future__ import annotations

from .dataset import (
    CLASS_MAPPING,
    LABEL_BENIGN,
    LABEL_DGA,
    Dataset,
    DatasetStats,
    SplitDataset,
    load_dataset,
    parse_label,
    split_dataset,
)
from .features import (
    FEATURE_NAMES,
    extract_feature_matrix,
    extract_features,
    extract_features_dict,
    normalize_domain,
    shannon_entropy,
)
from .model import (
    DEFAULT_MODEL_PARAMS,
    MODEL_FORMAT_VERSION,
    DGAModel,
    DGAModelMetadata,
    DGAPrediction,
)
#: Names that live in :mod:`.training` and are re-exported here. They are
#: fetched on first use rather than imported eagerly - see ``__getattr__``.
_TRAINING_EXPORTS = frozenset(
    {
        "DEFAULT_EVAL_THRESHOLD",
        "DEFAULT_SWEEP_THRESHOLDS",
        "EvaluationResult",
        "TrainingResult",
        "evaluate",
        "evaluate_baseline",
        "evaluate_scores",
        "sweep_thresholds",
        "train_dga",
    }
)


def __getattr__(name: str):
    """Resolve the training re-exports on first access (PEP 562).

    ``from detection_core.ml.dga import train_dga`` still works exactly as
    before; what changed is that importing this package no longer imports
    ``training`` as a side effect.

    That side effect made ``python -m detection_core.ml.dga.training`` -
    the command this package's own docstring documents - emit::

        RuntimeWarning: 'detection_core.ml.dga.training' found in
        sys.modules after import of package 'detection_core.ml.dga', but
        prior to execution of ...; this may result in unpredictable
        behaviour

    runpy is right to complain: the module ends up in ``sys.modules`` twice,
    once as ``detection_core.ml.dga.training`` and once as ``__main__``, and
    module-level state would exist in two copies. Deferring the import
    removes the cause rather than silencing the symptom.
    """
    if name in _TRAINING_EXPORTS:
        from . import training

        return getattr(training, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | _TRAINING_EXPORTS)

__all__ = [
    "CLASS_MAPPING",
    "DEFAULT_EVAL_THRESHOLD",
    "DEFAULT_MODEL_PARAMS",
    "DEFAULT_SWEEP_THRESHOLDS",
    "DGAModel",
    "DGAModelMetadata",
    "DGAPrediction",
    "Dataset",
    "DatasetStats",
    "EvaluationResult",
    "FEATURE_NAMES",
    "LABEL_BENIGN",
    "LABEL_DGA",
    "MODEL_FORMAT_VERSION",
    "SplitDataset",
    "TrainingResult",
    "evaluate",
    "evaluate_baseline",
    "evaluate_scores",
    "extract_feature_matrix",
    "extract_features",
    "extract_features_dict",
    "load_dataset",
    "normalize_domain",
    "parse_label",
    "shannon_entropy",
    "split_dataset",
    "sweep_thresholds",
    "train_dga",
]
