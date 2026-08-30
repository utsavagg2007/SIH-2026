"""Profile the bus hot path in-process, with no HTTP or event loop in the way.

Isolates fusion + projection + serialisation cost from transport cost, so a
throughput shortfall can be attributed to the right stage.
"""

from __future__ import annotations

import asyncio
import cProfile
import json
import pstats
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings  # noqa: E402
from app.core.bus import AlertBus  # noqa: E402
from app.core.hub import ConnectionHub  # noqa: E402
from app.core.metrics import MetricsRegistry  # noqa: E402
from app.schemas.alert_v11 import ThreatAlertV11  # noqa: E402
from app.storage.memory import MemoryRepository  # noqa: E402

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def load(n: int) -> list[ThreatAlertV11]:
    raw = [
        json.loads(line)
        for line in (FIXTURES / "flood.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    now = datetime.now(timezone.utc)
    out = []
    for i in range(n):
        a = dict(raw[i % len(raw)])
        t = now - timedelta(seconds=1)
        a["event_start"] = t.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        a["event_end"] = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        a["detected_at"] = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        a["alert_id"] = str(uuid.uuid4())
        out.append(ThreatAlertV11.model_validate(a))
    return out


async def main(n: int = 5000) -> None:
    settings = Settings(storage_backend="memory")
    bus = AlertBus(
        settings=settings,
        hub=ConnectionHub(),
        metrics=MetricsRegistry(),
        repository=MemoryRepository(),
    )
    alerts = load(n)
    print(f"profiling {n} publishes (no HTTP, no websocket clients)")

    t0 = time.perf_counter()
    for a in alerts:
        bus.publish(a)
    elapsed = time.perf_counter() - t0
    print(f"  baseline: {n / elapsed:,.0f} publishes/sec ({elapsed:.2f}s)\n")

    bus2 = AlertBus(
        settings=settings,
        hub=ConnectionHub(),
        metrics=MetricsRegistry(),
        repository=MemoryRepository(),
    )
    alerts2 = load(n)
    prof = cProfile.Profile()
    prof.enable()
    for a in alerts2:
        bus2.publish(a)
    prof.disable()

    s = StringIO()
    pstats.Stats(prof, stream=s).sort_stats("cumulative").print_stats(22)
    print(s.getvalue())


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 5000))
