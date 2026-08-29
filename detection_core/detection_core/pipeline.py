"""Wiring: detectors, alert sinks, and the streaming run loop.

This is the assembly layer. It owns no detection logic of its own - it picks
which detectors to register, decides where finished alerts go, and pumps
flows through the engine one at a time.

    FlowSource -> DetectionEngine -> [detectors] -> ThreatAlert -> AlertSink

Everything here streams. The adapter is a generator, ``DetectionEngine.run``
is a generator, and each alert is written and flushed as it appears, so a
capture larger than memory replays fine and a live source produces output
immediately rather than at end of stream.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterable, Iterator, Protocol, runtime_checkable

from .detectors import (
    C2BeaconingDetector,
    DataExfiltrationDetector,
    DDoSDetector,
    DGADetector,
    DnsTunnellingDetector,
    EncryptedMalwareDetector,
    PortScanDetector,
)
from .engine import DetectionEngine, Detector
from .schemas import FlowEvent, ThreatAlert

__all__ = [
    "DEFAULT_API_TIMEOUT",
    "AlertDeliveryError",
    "AlertSink",
    "HttpAlertSink",
    "JsonlAlertSink",
    "MultiSink",
    "RunStats",
    "build_default_detectors",
    "run_detection",
]

logger = logging.getLogger(__name__)

#: Seconds to wait on a backend POST before giving up.
DEFAULT_API_TIMEOUT = 10.0


# --------------------------------------------------------------------------
# Detector factory
# --------------------------------------------------------------------------


def build_default_detectors(
    *,
    dga_model_path: str | Path | None = None,
    dga_model: object | None = None,
) -> list[Detector]:
    """Every detector that can run, with its own shipped defaults.

    The six rule/heuristic detectors need nothing but their configs, so they
    are always included. **DGA is the exception**: it cannot run without a
    trained model, and this project deliberately ships none.

    So DGA is opt-in. Supply ``dga_model_path`` or ``dga_model`` and it joins
    the line-up; supply neither and the other six run exactly as normal. A
    missing artifact must not take the whole subsystem offline, and there is
    no stand-in model - one that scores everything 0.0 would look healthy on
    a dashboard while detecting nothing.

    An *invalid* path is a different matter and is not swallowed:
    :class:`~detection_core.detectors.DGADetector` raises, because the user
    asked for DGA explicitly and silently dropping it would be worse.
    """
    detectors: list[Detector] = [
        PortScanDetector(),
        DDoSDetector(),
        C2BeaconingDetector(),
        DnsTunnellingDetector(),
        DataExfiltrationDetector(),
        EncryptedMalwareDetector(),
    ]

    if dga_model is not None or dga_model_path is not None:
        detectors.append(
            DGADetector(model=dga_model, model_path=dga_model_path)
            if dga_model is not None
            else DGADetector(model_path=dga_model_path)
        )
    return detectors


# --------------------------------------------------------------------------
# Alert sinks
# --------------------------------------------------------------------------


class AlertDeliveryError(RuntimeError):
    """An alert could not be delivered. Never raised optimistically."""


@runtime_checkable
class AlertSink(Protocol):
    """Somewhere finished alerts go."""

    def emit(self, alert: ThreatAlert) -> None:  # pragma: no cover - protocol
        ...

    def close(self) -> None:  # pragma: no cover - protocol
        ...


class JsonlAlertSink:
    """One ThreatAlert JSON object per line.

    The payload comes from :meth:`ThreatAlert.to_wire`, which is the model's
    own serialization - the schema is never re-described here, so it cannot
    drift from the contract the full-stack team validates against.

    Each line is flushed immediately: a pipeline that is tailing a live
    source should produce output as it goes, not when the process ends.
    """

    def __init__(self, stream: IO[str], *, close_stream: bool = False) -> None:
        self.stream = stream
        self._close_stream = close_stream
        self.count = 0

    def emit(self, alert: ThreatAlert) -> None:
        json.dump(alert.to_wire(), self.stream)
        self.stream.write("\n")
        self.stream.flush()
        self.count += 1

    def close(self) -> None:
        if self._close_stream:
            self.stream.close()


class HttpAlertSink:
    """POSTs one ThreatAlert at a time to the backend.

    The agreed integration contract: a single alert per request, as JSON, to
    ``/api/v1/alerts``. Nothing is batched, no authentication is assumed, and
    there is no retry queue - a failure raises :class:`AlertDeliveryError`
    immediately rather than being absorbed. An undelivered alert that looks
    delivered is worse than a loud failure.

    Uses ``urllib`` from the standard library, so the detection package gains
    no new dependency for this.
    """

    def __init__(self, url: str, *, timeout: float = DEFAULT_API_TIMEOUT) -> None:
        if not url:
            raise ValueError("api url must not be empty")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.url = url
        self.timeout = timeout
        self.count = 0

    def emit(self, alert: ThreatAlert) -> None:
        payload = json.dumps(alert.to_wire()).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = getattr(response, "status", None) or response.getcode()
        except urllib.error.HTTPError as exc:
            # The backend answered, and rejected it. Quote it back.
            body = _read_error_body(exc)
            raise AlertDeliveryError(
                f"{self.url} rejected alert {alert.alert_id}: "
                f"HTTP {exc.code} {exc.reason}{body}"
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise AlertDeliveryError(
                f"could not reach {self.url} to deliver alert "
                f"{alert.alert_id}: {exc}"
            ) from exc

        if not 200 <= int(status) < 300:
            raise AlertDeliveryError(
                f"{self.url} returned HTTP {status} for alert {alert.alert_id}"
            )
        self.count += 1

    def close(self) -> None:
        """Nothing to close - each POST is its own connection."""


class MultiSink:
    """Fan one alert out to several sinks, in order.

    Used when alerts are both written locally and posted to the backend. A
    sink that raises stops the fan-out: partial delivery is reported rather
    than hidden.
    """

    def __init__(self, sinks: Iterable[AlertSink]) -> None:
        self.sinks = list(sinks)

    def emit(self, alert: ThreatAlert) -> None:
        for sink in self.sinks:
            sink.emit(alert)

    def close(self) -> None:
        for sink in self.sinks:
            sink.close()


def _read_error_body(exc: urllib.error.HTTPError, limit: int = 200) -> str:
    """A short quote of the backend's complaint, if it sent one."""
    try:
        body = exc.read().decode("utf-8", "replace").strip()
    except Exception:  # pragma: no cover - body already consumed / unreadable
        return ""
    return f" - {body[:limit]}" if body else ""


# --------------------------------------------------------------------------
# Run loop
# --------------------------------------------------------------------------


@dataclass
class RunStats:
    """What one run did."""

    flows: int = 0
    alerts: int = 0
    detector_errors: int = 0


def run_detection(
    source: Iterable[FlowEvent],
    sink: AlertSink,
    detectors: list[Detector],
    *,
    log: logging.Logger | None = None,
) -> RunStats:
    """Stream every flow through the detectors, emitting alerts as they appear.

    ``source`` is consumed lazily and alerts are handed to ``sink`` one at a
    time, so nothing accumulates: neither the flows nor the alerts are ever
    held as a list.

    Detector exceptions stay contained by ``DetectionEngine`` exactly as they
    do everywhere else - one misbehaving detector must not end the run - and
    are counted in the returned stats.
    """
    log = log or logger
    engine = DetectionEngine(detectors)
    stats = RunStats()

    for alert in engine.run(_counting(source, stats)):
        sink.emit(alert)
        stats.alerts += 1

    stats.detector_errors = engine.stats.detector_errors
    if stats.detector_errors:
        log.warning(
            "%d detector error(s) during the run; see the log above",
            stats.detector_errors,
        )
    return stats


def _counting(source: Iterable[FlowEvent], stats: RunStats) -> Iterator[FlowEvent]:
    """Pass flows through, counting them, without materializing the stream."""
    for flow in source:
        stats.flows += 1
        yield flow
