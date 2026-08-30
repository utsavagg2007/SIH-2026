"""Adapters translate an external format into ``FlowEvent``.

Everything that knows about ingestion's ``features.jsonl`` lives here and
nowhere else. Detectors depend on FlowEvent, never on an ingestion file.
"""

from __future__ import annotations

from .base import FlowSource
from .ingestion_jsonl import (
    SOURCE_NAME,
    AdapterStats,
    IngestionJsonlAdapter,
    record_to_flow_event,
)

__all__ = [
    "AdapterStats",
    "FlowSource",
    "IngestionJsonlAdapter",
    "SOURCE_NAME",
    "record_to_flow_event",
]
