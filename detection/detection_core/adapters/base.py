"""The FlowSource abstraction.

Anything that yields ``FlowEvent`` objects is a valid input to the
DetectionEngine: today's JSONL file, a live Zeek tail or a queue tomorrow,
or a plain list in a test. The engine never learns which one it got.
"""

from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable

from ..schemas import FlowEvent

__all__ = ["FlowSource"]


@runtime_checkable
class FlowSource(Protocol):
    """Iterable of normalized flows."""

    def __iter__(self) -> Iterator[FlowEvent]:  # pragma: no cover - protocol
        ...
