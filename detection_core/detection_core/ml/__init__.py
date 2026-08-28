"""ML models and feature pipelines. RESERVED - nothing implemented yet.

Models wrap into the same ``Detector`` interface as everything else, so the
engine cannot tell a model from a rule. A model that emits a probability
must map it onto the 0.0-1.0 ``score`` field with
``score_type=calibrated_model``.

Dependencies (numpy, scikit-learn) live behind the ``ml`` optional extra:

    pip install -e ".[ml]"
"""

from __future__ import annotations

__all__: list[str] = []
