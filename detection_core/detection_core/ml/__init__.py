"""ML models and feature pipelines.

Implemented:
    dga - offline lexical DGA classifier (training, model bundle, CLI).
          Offline only: ingestion does not yet expose raw ``dns.query``,
          so there is no live detector wired to the engine.

A model that eventually emits alerts wraps into the same ``Detector``
interface as everything else, so the engine cannot tell a model from a rule.
Note that a Random Forest's ``predict_proba`` is a vote fraction, not a
calibrated probability - ``score_type=calibrated_model`` should only be
claimed once calibration is actually done.

Dependencies (numpy, scikit-learn, joblib) live behind the ``ml`` extra:

    pip install -e ".[ml]"

The ``dga`` subpackage is not imported here, so ``import detection_core``
keeps working without the ML extra installed.
"""

from __future__ import annotations

__all__: list[str] = []
