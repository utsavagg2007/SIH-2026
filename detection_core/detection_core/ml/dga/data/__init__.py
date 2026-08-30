"""Dataset-building tooling for the offline DGA classifier.

:mod:`.build_dataset` fetches public benign and family-labeled DGA domains and
writes a ``domain,label,family`` CSV that :mod:`detection_core.ml.dga.training`
can train on with a family-disjoint split.

Nothing here is imported by the detection layer or by training - it is an
offline data step, run by hand. See ``PROVENANCE.md`` in this directory for
the sources, their licences, and the exact build command.
"""

from __future__ import annotations

__all__: list[str] = []
