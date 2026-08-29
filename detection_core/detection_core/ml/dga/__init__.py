"""Offline DGA (domain generation algorithm) classification.

    CSV -> normalize -> lexical features -> RandomForest -> dga_score

**This is offline infrastructure only.** There is no live ``DGADetector``
yet, because ingestion's ``features.jsonl`` does not expose the raw
``dns.query`` string a classifier needs - only derived entropy and length
values (see SCHEMA.md "Integration TODOs"). Reconstructing a domain from
those would be inventing data, so the live wiring waits for the raw field.

Requires the ``ml`` extra::

    pip install -e ".[ml]"
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
from .training import (
    DEFAULT_EVAL_THRESHOLD,
    DEFAULT_SWEEP_THRESHOLDS,
    EvaluationResult,
    TrainingResult,
    evaluate,
    evaluate_baseline,
    evaluate_scores,
    sweep_thresholds,
    train_dga,
)

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
