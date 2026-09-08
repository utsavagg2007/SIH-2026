"""ML models and feature pipelines.

Implemented:
    dga - lexical DGA classifier: features, dataset, RandomForest bundle,
          training/evaluation CLI. The live half,
          :class:`~detection_core.detectors.DGADetector`, is wired into the
          detector factory and reports per source; it needs a trained model
          (``--dga-model``) and a raw ``dns.query``. Detector-v2 supplies the
          query; legacy-m1d does not, so legacy input remains correctly silent.

A model that emits alerts wraps into the same ``Detector`` interface as
everything else, so the engine cannot tell a model from a rule. Note that a
Random Forest's ``predict_proba`` is a vote fraction, not a calibrated
probability - ``score_type=calibrated_model`` should only be claimed once
calibration is actually done, and the live detector publishes
``rule_score`` for exactly that reason.

Dependencies (numpy, scikit-learn, joblib) live behind the ``ml`` extra:

    pip install -e ".[ml]"

The ``dga`` subpackage is not imported here, so ``import detection_core``
keeps working without the ML extra installed.
"""

from __future__ import annotations

__all__: list[str] = []
