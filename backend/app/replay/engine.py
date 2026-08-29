"""Replay: feed recorded v1.1 alerts through the live path.

Two jobs, both from the specs:

* **Demo control** (Frontend spec 6.4).  Load a capture, set a speed multiplier,
  start and stop.  Alerts are replayed through the *same* bus the real detectors
  post to, so nothing about the dashboard's behaviour differs between replay and
  live - the fusion layer, the projection and the fan-out are all identical.
* **The flood test** (Frontend spec 8.2).  "Have the mock server replay a
  synthetic flood at several hundred alerts per second and confirm the interface
  holds sixty frames.  Do this in week one, not the night before."

Timestamps are rewritten to the replay wall clock.  A capture recorded yesterday
would otherwise produce alerts whose ``event_end`` is hours in the past, and
every latency measurement on the System view would read in the millions of
milliseconds.  The offset is applied uniformly so relative timing - which is the
whole point of a beacon replay - is preserved exactly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ..core.bus import AlertBus
from ..schemas.alert_v11 import ThreatAlertV11

log = logging.getLogger(__name__)


@dataclass(slots=True)
class ReplayStatus:
    running: bool = False
    capture: str | None = None
    speed: float = 1.0
    position: int = 0
    total: int = 0
    started_at: float | None = None
    elapsed_s: float = 0.0
    emitted: int = 0
    rejected: int = 0
    loop: bool = False
    #: Attack classes the loaded capture is known to contain, read from the
    #: scenario manifest. Frontend spec 6.4: being able to say "this capture
    #: contains a beacon at minute seven, and here it is at minute seven" is a
    #: strong demo moment.
    scenario: dict[str, Any] = field(default_factory=dict)


class ReplayEngine:
    """Replays a JSONL file of v1.1 alerts into the bus."""

    def __init__(self, bus: AlertBus, fixtures_dir: Path) -> None:
        self._bus = bus
        self._dir = fixtures_dir
        self._task: asyncio.Task | None = None
        self._status = ReplayStatus()
        self._stop = asyncio.Event()

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def status(self) -> ReplayStatus:
        if self._status.running and self._status.started_at:
            self._status.elapsed_s = round(time.time() - self._status.started_at, 2)
        return self._status

    def available_captures(self) -> list[dict[str, Any]]:
        """Fixture files that can be replayed, with their scenario manifests."""
        if not self._dir.exists():
            return []
        out: list[dict[str, Any]] = []
        for path in sorted(self._dir.glob("*.jsonl")):
            manifest = self._load_manifest(path)
            try:
                count = sum(1 for line in path.open(encoding="utf-8") if line.strip())
            except OSError:
                count = 0
            out.append(
                {
                    "capture": path.name,
                    "alerts": count,
                    "size_bytes": path.stat().st_size,
                    "scenario": manifest,
                }
            )
        return out

    def _load_manifest(self, capture: Path) -> dict[str, Any]:
        """Ground-truth manifest sitting beside the capture, if present.

        Build Plan 3.3: label by construction, keep the manifest in version
        control.  When a judge asks how you validated, you open the scenario
        file.
        """
        manifest = capture.with_suffix(".manifest.json")
        if not manifest.exists():
            return {}
        try:
            return json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            log.warning("could not read manifest %s", manifest)
            return {}

    # ------------------------------------------------------------------

    async def start(
        self,
        capture: str,
        speed: float = 1.0,
        loop: bool = False,
        max_rate: float | None = None,
    ) -> ReplayStatus:
        """Begin replaying. Stops any replay already in progress."""
        if self.is_running:
            await self.stop()

        # Reject anything that escapes the fixtures directory. The filename
        # arrives over HTTP, and this route reads from disk.
        path = (self._dir / capture).resolve()
        if not path.is_file() or self._dir.resolve() not in path.parents:
            raise FileNotFoundError(
                f"capture {capture!r} not found in {self._dir}"
            )

        alerts = self._load(path)
        if not alerts:
            raise ValueError(f"capture {capture!r} contains no valid v1.1 alerts")

        self._stop.clear()
        self._status = ReplayStatus(
            running=True,
            capture=capture,
            speed=speed,
            total=len(alerts),
            started_at=time.time(),
            loop=loop,
            scenario=self._load_manifest(path),
        )
        self._task = asyncio.create_task(self._run(alerts, speed, loop, max_rate))
        return self._status

    async def stop(self) -> ReplayStatus:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None
        self._status.running = False
        return self._status

    def _load(self, path: Path) -> list[dict[str, Any]]:
        """Read the capture, keeping raw dicts so timestamps can be rewritten."""
        out: list[dict[str, Any]] = []
        with path.open(encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    log.warning("%s:%d is not valid JSON; skipping", path.name, lineno)
                    continue
                if isinstance(obj, dict):
                    out.append(obj)
        # Order by detection time so the replay reproduces the original
        # sequence even if the file is not sorted.
        out.sort(key=lambda a: str(a.get("detected_at", "")))
        return out

    async def _run(
        self,
        alerts: list[dict[str, Any]],
        speed: float,
        loop: bool,
        max_rate: float | None,
    ) -> None:
        try:
            while True:
                await self._pass(alerts, speed, max_rate)
                if not loop or self._stop.is_set():
                    break
                self._status.position = 0
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("replay failed")
        finally:
            self._status.running = False

    async def _pass(
        self, alerts: list[dict[str, Any]], speed: float, max_rate: float | None
    ) -> None:
        base_detected = _parse_ts(alerts[0].get("detected_at"))
        wall_start = time.time()
        # Shift every timestamp forward by the same amount, so the capture's
        # internal timing survives intact while landing on the current clock.
        shift = (
            timedelta(seconds=wall_start) - timedelta(seconds=base_detected.timestamp())
            if base_detected
            else timedelta(0)
        )
        min_gap = 1.0 / max_rate if max_rate else 0.0
        last_emit = 0.0

        for i, raw in enumerate(alerts):
            if self._stop.is_set():
                return

            detected = _parse_ts(raw.get("detected_at"))
            if detected is not None and base_detected is not None:
                offset = (detected - base_detected).total_seconds() / max(speed, 1e-9)
                wait = (wall_start + offset) - time.time()
                if wait > 0:
                    try:
                        await asyncio.wait_for(self._stop.wait(), timeout=wait)
                        return
                    except asyncio.TimeoutError:
                        pass

            if min_gap:
                gap = min_gap - (time.time() - last_emit)
                if gap > 0:
                    await asyncio.sleep(gap)
                last_emit = time.time()

            self._emit(raw, shift)
            self._status.position = i + 1

            # Yield periodically even when the replay is running flat out, so
            # the metrics loop and the WebSocket writers still get scheduled.
            if i % 50 == 0:
                await asyncio.sleep(0)

    def _emit(self, raw: dict[str, Any], shift: timedelta) -> None:
        payload = dict(raw)
        for field_name in ("event_start", "event_end", "detected_at"):
            parsed = _parse_ts(payload.get(field_name))
            if parsed is not None:
                payload[field_name] = (
                    (parsed + shift).isoformat().replace("+00:00", "Z")
                )

        # Evidence carries absolute epoch series too - the beacon comb's
        # connection timestamps, the start of a rate series. Shifting the
        # top-level fields without shifting these leaves the evidence describing
        # a different hour than the alert around it, and the comb renders as an
        # empty axis because its ticks fall outside the window. Same offset,
        # so relative timing inside each series is untouched.
        payload["evidence"] = _shift_evidence(payload.get("evidence"), shift)
        # A fresh id per emission, so replaying the same capture twice does not
        # collide in the alert store. Dedup still folds genuine repeats, because
        # dedup keys on the entity rather than on the alert id.
        payload["alert_id"] = str(uuid.uuid4())
        # Correlation is the backend's job; a stale incident id from the capture
        # would pin replayed alerts to an incident that no longer exists.
        payload["incident_id"] = None

        try:
            alert = ThreatAlertV11.model_validate(payload)
        except Exception as exc:  # noqa: BLE001
            self._status.rejected += 1
            if self._status.rejected <= 5:
                log.warning("replay: skipping invalid alert: %s", exc)
            return

        self._bus.publish(alert)
        self._status.emitted += 1


#: Evidence keys holding absolute epoch seconds, which must move with the alert
#: when a capture is replayed onto the current clock. Relative series (interval
#: lengths, byte counts, entropy samples) are deliberately absent: they carry no
#: absolute time and shifting them would corrupt them.
_EPOCH_SERIES_KEYS = frozenset({"timestamps", "connection_timestamps"})
_EPOCH_SCALAR_KEYS = frozenset({"series_start", "first_seen", "baseline_start"})


def _shift_evidence(evidence: Any, shift: timedelta) -> Any:
    """Move absolute-time values inside an evidence bag by ``shift``."""
    if not isinstance(evidence, dict) or not shift:
        return evidence
    delta = shift.total_seconds()
    out = dict(evidence)
    for key, value in evidence.items():
        if key in _EPOCH_SERIES_KEYS and isinstance(value, list):
            out[key] = [
                v + delta
                if isinstance(v, (int, float)) and not isinstance(v, bool)
                else v
                for v in value
            ]
        elif key in _EPOCH_SCALAR_KEYS and isinstance(value, (int, float)):
            if not isinstance(value, bool):
                out[key] = value + delta
    return out


def _parse_ts(value: Any) -> datetime | None:
    """Accept ISO-8601 (with Z) or epoch seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None
