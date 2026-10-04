"""Missing-aware canonical input, without relaxing the legacy FlowEvent contract."""

from __future__ import annotations

import math
from typing import Any

from pydantic import Field, field_validator

from .flow_event import FlowEvent


class CanonicalFlowEvent(FlowEvent):
    """A flow whose unmeasured counters/duration remain None.

    ``orig`` means canonical src_to_dst, not an inferred initiator role.
    Only audited consumers may receive this subtype (see compatibility.py).
    The strict, required legacy fields on FlowEvent itself are unchanged.
    """

    duration: float | None = Field(default=None, ge=0)
    orig_bytes: int | None = Field(default=None, ge=0)
    resp_bytes: int | None = Field(default=None, ge=0)
    orig_pkts: int | None = Field(default=None, ge=0)
    resp_pkts: int | None = Field(default=None, ge=0)
    canonical: dict[str, Any]

    @field_validator("timestamp", "duration")
    @classmethod
    def _finite(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("must be a finite number")
        return value

    @property
    def total_bytes(self) -> int | None:
        if self.orig_bytes is None or self.resp_bytes is None:
            return None
        return self.orig_bytes + self.resp_bytes

    @property
    def total_pkts(self) -> int | None:
        if self.orig_pkts is None or self.resp_pkts is None:
            return None
        return self.orig_pkts + self.resp_pkts
