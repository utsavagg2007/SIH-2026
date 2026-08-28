"""Detector interface and the engine that drives detectors."""

from __future__ import annotations

from .detector import Detector
from .engine import DetectionEngine, EngineStats

__all__ = ["DetectionEngine", "Detector", "EngineStats"]
