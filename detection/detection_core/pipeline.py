"""Wiring: detectors, alert sinks, and the streaming run loop.

This is the assembly layer. It owns no detection logic of its own - it picks
which detectors to register, decides where finished alerts go, and pumps
flows through the engine one at a time.

    FlowSource -> DetectionEngine -> [detectors] -> ThreatAlert -> AlertSink

Everything here streams. The adapter is a generator, ``DetectionEngine.run``
is a generator, and each alert is written and flushed as it appears, so a
capture larger than memory replays fine and a live source produces output
immediately rather than at end of stream.

**Network delivery is off the detection thread.** Writing a line of JSONL is
microseconds; a round trip to a backend is milliseconds at best and a socket
timeout at worst, and until recently the detection loop waited for it. See
:class:`QueuedAlertSink` for the measurements and the reasoning - the short
version is that a streaming sensor whose pace is set by a dashboard is not a
streaming sensor.
"""

from __future__ import annotations

import http.client
import json
import logging
import queue
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Iterable, Iterator, NamedTuple, Protocol, runtime_checkable

from .config import DetectorSettings
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
    "DEFAULT_BULK_MAX_AGE",
    "DEFAULT_BULK_SIZE",
    "DEFAULT_QUEUE_SIZE",
    "DEFAULT_TELEMETRY_INTERVAL",
    "MAX_BULK_SIZE",
    "AlertDeliveryError",
    "AlertSink",
    "BulkHttpAlertSink",
    "HttpAlertSink",
    "JsonlAlertSink",
    "MultiSink",
    "QueuedAlertSink",
    "RunStats",
    "TelemetryReporter",
    "TelemetrySample",
    "build_default_detectors",
    "run_detection",
]

logger = logging.getLogger(__name__)

#: Seconds to wait on a backend POST before giving up.
#:
#: This used to be 10s, chosen when a failed POST merely delayed the run. It
#: is now the outer bound on how long the *delivery worker* can be stuck on
#: one alert while the queue behind it fills, so a generous value costs
#: dropped alerts rather than patience. A backend on the same network that
#: has not answered in three seconds is not about to; the alert is counted
#: as undelivered and the next one is tried.
DEFAULT_API_TIMEOUT = 3.0

#: How many alerts may wait for delivery before the oldest is dropped.
#:
#: Sized for the gap this queue exists to absorb: a backend restart or a GC
#: pause of a few seconds at a realistic alert rate, not a backend that has
#: been down for an hour. Beyond that the alerts in the queue describe
#: traffic nobody is looking at any more, and the local JSONL sink - which
#: is never behind this queue - still has every one of them.
DEFAULT_QUEUE_SIZE = 1000

#: Alerts per request for :class:`BulkHttpAlertSink`.
DEFAULT_BULK_SIZE = 100

#: The backend's own per-request cap on ``POST /api/v1/alerts/bulk``
#: (``BulkAlerts.alerts`` is declared ``max_length=5000``). A larger batch is
#: rejected wholesale with a 422, so the sink refuses to be configured past
#: it rather than discovering it one full batch at a time.
MAX_BULK_SIZE = 5000

#: Seconds a partial batch may sit unsent before it is flushed anyway.
DEFAULT_BULK_MAX_AGE = 2.0

#: How often :func:`run_detection` reports flows/sec when given a reporter.
DEFAULT_TELEMETRY_INTERVAL = 1.0

#: How long a settle/close waits for the delivery backlog before giving up
#: and saying so. Bounded on purpose: a run must end even when the backend
#: has stopped answering entirely.
DEFAULT_SETTLE_TIMEOUT = 30.0


# --------------------------------------------------------------------------
# Detector factory
# --------------------------------------------------------------------------


def build_default_detectors(
    *,
    dga_model_path: str | Path | None = None,
    dga_model: object | None = None,
    settings: "DetectorSettings | None" = None,
) -> list[Detector]:
    """Every detector that can run, with its own shipped defaults.

    The six rule/heuristic detectors need nothing but their configs, so they
    are always included. **DGA is the exception**: it cannot run without a
    trained model, and no model is importable from this package - a model is
    a build product, not source, and lives outside it (see
    ``runner.DEFAULT_DGA_MODEL_PATH``).

    So DGA is opt-in *here*. Supply ``dga_model_path`` or ``dga_model`` and
    it joins the line-up; supply neither and the other six run exactly as
    normal. A missing artifact must not take the whole subsystem offline,
    and there is no stand-in model - one that scores everything 0.0 would
    look healthy on a dashboard while detecting nothing.

    An *invalid* path is a different matter and is not swallowed:
    :class:`~detection_core.detectors.DGADetector` raises, because the
    caller named a model explicitly and silently dropping it would be worse.

    ``settings`` supplies per-detector configuration, normally read from a
    TOML file by :func:`~detection_core.config.load_detector_settings`.
    Omitting it - which every existing caller does - builds each detector
    with its own shipped defaults, exactly as before: ``DetectorSettings()``
    *is* those defaults, so the two paths cannot diverge.
    """
    if settings is None:
        settings = DetectorSettings()

    detectors: list[Detector] = [
        PortScanDetector(settings.port_scan),
        DDoSDetector(settings.ddos),
        C2BeaconingDetector(settings.c2_beaconing),
        DnsTunnellingDetector(settings.dns_tunnelling),
        DataExfiltrationDetector(settings.data_exfiltration),
        EncryptedMalwareDetector(settings.encrypted_malware),
    ]

    # DGA still needs a model. Configuration can shape it but never conjure
    # one: a [dga] section on a run with no artifact configures nothing,
    # because there is nothing to configure.
    if dga_model is not None or dga_model_path is not None:
        detectors.append(
            DGADetector(model=dga_model, config=settings.dga_domain)
            if dga_model is not None
            else DGADetector(model_path=dga_model_path, config=settings.dga_domain)
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


class _HttpResponse(NamedTuple):
    """What the backend said. ``body`` is raw and may be empty."""

    status: int
    reason: str
    body: bytes


class _KeepAliveConnection:
    """One HTTP connection to one endpoint, reused across POSTs.

    ``urllib.request.urlopen`` opens a socket, completes a TCP handshake
    (and a TLS one for https), sends, reads, and closes it again - for every
    single call. At one alert per request that setup is most of the cost,
    and it is most of why the per-alert sink managed 82 alerts/s against a
    loopback backend that answers instantly. Holding the connection open
    removes it from all but the first POST.

    A kept-alive socket can be closed by the peer, or by anything between,
    at any time, and the client only finds out by trying to use it. That
    failure looks exactly like a request the server never saw, so a POST on
    a **reused** connection is retried once on a fresh one. A POST on a
    connection we just opened is never retried - there the failure is real
    and retrying would only double the time spent discovering it. In the one
    case where the retry does duplicate (the server took the request and
    died before answering) the backend deduplicates by ``alert_id``, so the
    cost is an occurrence count, not a second alert.

    Not thread-safe by design: it is owned by exactly one sink, and that
    sink is driven by exactly one delivery thread.
    """

    def __init__(self, url: str, *, timeout: float) -> None:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError(
                f"unsupported URL scheme {parts.scheme or ''!r} in {url!r}; "
                "expected http or https"
            )
        if not parts.hostname:
            raise ValueError(f"{url!r} names no host")
        self.url = url
        self.timeout = timeout
        self._parts = parts
        self._target = urllib.parse.urlunsplit(
            ("", "", parts.path or "/", parts.query, "")
        )
        self._connection: http.client.HTTPConnection | None = None

    def post(self, body: bytes) -> _HttpResponse:
        """POST ``body`` as JSON. Raises OSError / HTTPException on transport failure."""
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Connection": "keep-alive",
        }
        for _ in range(2):
            connection, reused = self._open()
            try:
                connection.request("POST", self._target, body=body, headers=headers)
                response = connection.getresponse()
                payload = response.read()
                if response.will_close:
                    # The server declined to keep it; do not reuse a socket
                    # it has already decided to close.
                    self.close()
                return _HttpResponse(response.status, response.reason or "", payload)
            except (http.client.HTTPException, OSError):
                self.close()
                if not reused:
                    raise
        raise AssertionError("unreachable")  # pragma: no cover

    def _open(self) -> tuple[http.client.HTTPConnection, bool]:
        """The live connection and whether it was already open."""
        if self._connection is not None:
            return self._connection, True
        factory = (
            http.client.HTTPSConnection
            if self._parts.scheme == "https"
            else http.client.HTTPConnection
        )
        self._connection = factory(
            self._parts.hostname, self._parts.port, timeout=self.timeout
        )
        return self._connection, False

    def close(self) -> None:
        connection, self._connection = self._connection, None
        if connection is not None:
            try:
                connection.close()
            except Exception:  # pragma: no cover - already broken; nothing to do
                pass


class HttpAlertSink:
    """POSTs one ThreatAlert at a time to the backend.

    The agreed integration contract: a single alert per request, as JSON, to
    ``/api/v1/alerts``. Nothing is batched, no authentication is assumed, and
    there is no retry queue - a failure raises :class:`AlertDeliveryError`
    immediately rather than being absorbed. An undelivered alert that looks
    delivered is worse than a loud failure.

    The connection is reused across posts (see
    :class:`_KeepAliveConnection`); the wire format and the failure contract
    are unchanged. Still standard library only, so the detection package
    gains no new dependency for this.

    This sink blocks for the length of a round trip. That is fine where it
    now runs - inside :class:`QueuedAlertSink`, on its own thread - and is
    the reason it must not go back to running inside the detection loop.
    """

    def __init__(self, url: str, *, timeout: float = DEFAULT_API_TIMEOUT) -> None:
        if not url:
            raise ValueError("api url must not be empty")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.url = url
        self.timeout = timeout
        self.count = 0
        self._connection = _KeepAliveConnection(url, timeout=timeout)

    def emit(self, alert: ThreatAlert) -> None:
        payload = json.dumps(alert.to_wire()).encode("utf-8")
        try:
            response = self._connection.post(payload)
        except (http.client.HTTPException, OSError) as exc:
            raise AlertDeliveryError(
                f"could not reach {self.url} to deliver alert "
                f"{alert.alert_id}: {exc}"
            ) from exc

        if not 200 <= response.status < 300:
            # The backend answered, and rejected it. Quote it back.
            raise AlertDeliveryError(
                f"{self.url} rejected alert {alert.alert_id}: "
                f"HTTP {response.status} {response.reason}"
                f"{_quote_body(response.body)}"
            )
        self.count += 1

    def close(self) -> None:
        self._connection.close()


class BulkHttpAlertSink:
    """Buffers alerts and POSTs them to ``/api/v1/alerts/bulk`` in batches.

    The backend has always had this route and nothing called it. One request
    per alert spends a full round trip on every alert; during a scan or a
    DDoS, which is exactly when alert volume peaks, that is the wrong shape.
    A batch of a hundred pays one round trip for a hundred alerts.

    A batch goes out when it reaches ``batch_size`` **or** when the oldest
    alert in it has waited ``max_age`` seconds, whichever comes first. The
    age rule is not decoration: without it the last few alerts of a quiet
    minute would sit in memory indefinitely, which on a live sensor means
    the dashboard is silent while the sensor is not. ``close`` flushes what
    is left. The age is enforced on every ``emit`` and on :meth:`tick`,
    which :class:`QueuedAlertSink` calls while the queue is idle - a sink
    with no external clock cannot notice time passing on its own.

    ``batch_size`` is capped at :data:`MAX_BULK_SIZE`, the backend's own
    declared limit, because a batch above it is rejected in one piece.

    **This sink counts rather than raises.** ``emit`` has already returned
    "accepted" by the time the batch is posted, so there is no caller left
    to raise at; and the route answers ``202 Accepted`` even when it
    rejected alerts inside the batch, reporting them in ``rejected`` and
    ``errors``. A schema regression would otherwise look like a clean run
    forever. So the response is parsed, ``rejected`` is added to
    ``delivery_failures``, and the first few validation errors are logged
    with the field and reason the backend gave.
    """

    def __init__(
        self,
        url: str,
        *,
        batch_size: int = DEFAULT_BULK_SIZE,
        max_age: float = DEFAULT_BULK_MAX_AGE,
        timeout: float = DEFAULT_API_TIMEOUT,
        log: logging.Logger | None = None,
    ) -> None:
        if not url:
            raise ValueError("api url must not be empty")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if not 1 <= batch_size <= MAX_BULK_SIZE:
            raise ValueError(
                f"batch size must be between 1 and {MAX_BULK_SIZE} "
                f"(the backend's own per-request cap), got {batch_size}"
            )
        if max_age <= 0:
            raise ValueError("max_age must be positive")
        self.url = url
        self.batch_size = batch_size
        self.max_age = max_age
        self.timeout = timeout
        self.log = log or logger
        #: Alerts the backend accepted (created or deduplicated).
        self.count = 0
        #: Alerts the backend never accepted: a batch that failed in
        #: transit, plus every alert it answered with ``rejected``.
        self.delivery_failures = 0
        #: Never drops anything itself; present so every deferred sink
        #: reports the same two counters.
        self.alerts_dropped = 0
        self.batches_sent = 0
        self._buffer: list[dict[str, Any]] = []
        self._oldest: float | None = None
        self._connection = _KeepAliveConnection(url, timeout=timeout)

    def emit(self, alert: ThreatAlert) -> None:
        if not self._buffer:
            self._oldest = time.monotonic()
        self._buffer.append(alert.to_wire())
        if len(self._buffer) >= self.batch_size:
            self._flush()
        else:
            self.tick()

    def tick(self) -> None:
        """Flush a partial batch that has waited longer than ``max_age``."""
        if not self._buffer or self._oldest is None:
            return
        if time.monotonic() - self._oldest >= self.max_age:
            self._flush()

    def settle(self) -> None:
        """Send whatever is buffered. Safe to call more than once."""
        self._flush()

    def close(self) -> None:
        self._flush()
        self._connection.close()

    # --- internals --------------------------------------------------------

    def _flush(self) -> None:
        if not self._buffer:
            return
        batch, self._buffer, self._oldest = self._buffer, [], None
        payload = json.dumps({"alerts": batch}).encode("utf-8")
        try:
            response = self._connection.post(payload)
        except (http.client.HTTPException, OSError) as exc:
            self.delivery_failures += len(batch)
            self.log.error(
                "alert delivery failed, continuing: could not reach %s to "
                "deliver a batch of %d alert(s): %s",
                self.url,
                len(batch),
                exc,
            )
            return

        self.batches_sent += 1
        if not 200 <= response.status < 300:
            self.delivery_failures += len(batch)
            self.log.error(
                "alert delivery failed, continuing: %s rejected a batch of "
                "%d alert(s): HTTP %d %s%s",
                self.url,
                len(batch),
                response.status,
                response.reason,
                _quote_body(response.body),
            )
            return
        self._account(batch, response.body)

    def _account(self, batch: list[dict[str, Any]], body: bytes) -> None:
        """Read the per-alert outcome out of a 2xx body.

        A ``202`` means the request was understood, not that every alert in
        it was. The summary carries ``rejected`` and an ``errors`` array of
        ``{index, alert_id, errors: [{field, msg}]}``; ignoring them is how a
        schema regression stays invisible for a week.
        """
        summary: object = None
        try:
            summary = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            summary = None

        if not isinstance(summary, dict) or "rejected" not in summary:
            # A 2xx with a shape we do not recognize. HTTP says accepted, so
            # they are counted accepted - but say plainly that the per-alert
            # outcome could not be read, rather than implying it was clean.
            self.count += len(batch)
            self.log.warning(
                "%s accepted a batch of %d alert(s) but returned no "
                "recognizable summary; per-alert rejections cannot be seen",
                self.url,
                len(batch),
            )
            return

        try:
            rejected = int(summary.get("rejected") or 0)
        except (TypeError, ValueError):
            rejected = 0
        rejected = max(0, min(rejected, len(batch)))
        self.count += len(batch) - rejected
        if not rejected:
            return

        self.delivery_failures += rejected
        errors = summary.get("errors")
        self.log.error(
            "alert delivery failed, continuing: %s rejected %d of %d alert(s) "
            "in a batch%s",
            self.url,
            rejected,
            len(batch),
            _describe_bulk_errors(errors),
        )


def _describe_bulk_errors(errors: object, limit: int = 3) -> str:
    """The backend's own field-level complaints, on one line.

    The route caps its ``errors`` array at 25 entries; this quotes the first
    few of those. Enough to name the field that broke - which is the whole
    point of reading the body - without a log line nobody finishes.
    """
    if not isinstance(errors, list) or not errors:
        return ""
    parts: list[str] = []
    for entry in errors[:limit]:
        if not isinstance(entry, dict):
            continue
        fields = entry.get("errors")
        detail = ""
        if isinstance(fields, list) and fields:
            first = fields[0]
            if isinstance(first, dict):
                detail = f" {first.get('field', '?')}: {first.get('msg', 'invalid')}"
        parts.append(f"[{entry.get('index', '?')}]{detail}")
    if not parts:
        return ""
    remaining = len(errors) - len(parts)
    tail = f" (+{remaining} more)" if remaining > 0 else ""
    return f" - {'; '.join(parts)}{tail}"


class QueuedAlertSink:
    """Hands an alert to a background thread and returns immediately.

    Delivery used to happen inline in the detection loop: ``run_detection``
    called ``HttpAlertSink.emit`` and did not read the next flow until the
    backend had answered. Measured against a loopback backend that answers
    with no work at all, that path delivered **82 alerts/s** while the
    detectors themselves processed **13,012 flows/s** - so a backend two
    orders of magnitude slower than detection was setting the pace of
    detection. A backend that is merely slow, or unreachable and burning the
    socket timeout on every alert, stalled the sensor outright.

    For a streaming sensor that is a correctness problem before it is a
    performance one. The flows arriving during a stall are not delayed, they
    are *unexamined*: nothing upstream is holding them for us.

    So delivery moves off the detection thread. ``emit`` is a bounded,
    non-blocking enqueue; one worker thread drains the queue into the
    wrapped sink and absorbs its failures the way the run loop used to.

    **The queue is bounded, and drops the oldest alert when full.**
    Unbounded would trade a stall for unbounded memory - the same outage,
    later and less legibly. Blocking on a full queue would reintroduce
    exactly the stall this exists to remove. Dropping the *oldest* keeps the
    freshest picture of the network, which is what an operator watching a
    live dashboard needs. Every drop is counted in ``alerts_dropped`` and
    surfaced in :class:`RunStats` next to ``delivery_failures``, because an
    alert the backend never received must never be silently forgotten - and
    the local JSONL sink, which is deliberately *not* behind this queue,
    still holds every one of them.

    The worker never dies. An exception from the wrapped sink - of any type,
    not only :class:`AlertDeliveryError` - is counted and logged, because a
    dead delivery thread would leave ``emit`` quietly filling a queue nobody
    is draining. That is a deliberate difference from a sink on the
    detection thread, where a non-delivery exception still stops the run.
    """

    def __init__(
        self,
        sink: AlertSink,
        *,
        maxsize: int = DEFAULT_QUEUE_SIZE,
        poll_interval: float = 0.25,
        log: logging.Logger | None = None,
    ) -> None:
        if maxsize < 1:
            raise ValueError("maxsize must be at least 1")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        self.sink = sink
        self.maxsize = maxsize
        self.poll_interval = poll_interval
        self.log = log or logger
        self._queue: queue.Queue[ThreatAlert] = queue.Queue(maxsize=maxsize)
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._closed = False
        self._pending = 0
        self._own_failures = 0
        self._own_dropped = 0
        self._worker = threading.Thread(
            target=self._drain, name="alert-delivery", daemon=True
        )
        self._worker.start()

    # --- counters ---------------------------------------------------------
    #
    # Both include the wrapped sink's own tally, so a caller summing over
    # sinks sees each failure exactly once whether it was detected here (an
    # exception) or there (a bulk batch the backend rejected).

    @property
    def delivery_failures(self) -> int:
        with self._lock:
            own = self._own_failures
        return own + int(getattr(self.sink, "delivery_failures", 0) or 0)

    @property
    def alerts_dropped(self) -> int:
        with self._lock:
            own = self._own_dropped
        return own + int(getattr(self.sink, "alerts_dropped", 0) or 0)

    # --- sink protocol ----------------------------------------------------

    def emit(self, alert: ThreatAlert) -> None:
        """Enqueue. Never blocks, never raises AlertDeliveryError."""
        with self._lock:
            while True:
                try:
                    self._queue.put_nowait(alert)
                    self._pending += 1
                    return
                except queue.Full:
                    try:
                        self._queue.get_nowait()
                    except queue.Empty:  # the worker drained it first; retry
                        continue
                    self._pending -= 1
                    self._own_dropped += 1

    def settle(self, timeout: float = DEFAULT_SETTLE_TIMEOUT) -> bool:
        """Wait for the backlog to be delivered. Returns whether it drained.

        Called at the end of a run so the reported counts describe what the
        backend actually received, rather than what was handed to the queue.
        Bounded, because a run has to be able to end while a backend is
        wedged; the caller is told when it timed out.
        """
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                if self._pending == 0:
                    break
                outstanding = self._pending
            if time.monotonic() >= deadline:
                self.log.warning(
                    "%d alert(s) were still awaiting delivery after %.0fs; "
                    "reported counts may understate what the backend missed",
                    outstanding,
                    timeout,
                )
                return False
            time.sleep(0.005)

        settle = getattr(self.sink, "settle", None)
        if callable(settle):
            settle()
        return True

    def close(self) -> None:
        """Stop the worker once the backlog is delivered, then close the sink."""
        if self._closed:
            return
        self._closed = True
        self.settle()
        self._stopping.set()
        self._worker.join(timeout=DEFAULT_SETTLE_TIMEOUT)
        if self._worker.is_alive():  # pragma: no cover - a wedged backend
            self.log.warning(
                "the delivery worker did not stop within %.0fs; %d alert(s) "
                "were abandoned",
                DEFAULT_SETTLE_TIMEOUT,
                self._queue.qsize(),
            )
        self.sink.close()

    # --- internals --------------------------------------------------------

    def _drain(self) -> None:
        while True:
            try:
                alert = self._queue.get(timeout=self.poll_interval)
            except queue.Empty:
                if self._stopping.is_set():
                    return
                # Idle: give a batching sink the clock tick it cannot
                # generate for itself.
                self._guard(getattr(self.sink, "tick", None))
                continue
            try:
                self._deliver(alert)
            finally:
                with self._lock:
                    self._pending -= 1

    def _deliver(self, alert: ThreatAlert) -> None:
        try:
            self.sink.emit(alert)
        except AlertDeliveryError as exc:
            with self._lock:
                self._own_failures += 1
            self.log.error("alert delivery failed, continuing: %s", exc)
        except Exception as exc:  # the worker must outlive any single alert
            with self._lock:
                self._own_failures += 1
            self.log.error(
                "alert delivery raised %s, continuing: %s", type(exc).__name__, exc
            )

    def _guard(self, hook: object) -> None:
        if not callable(hook):
            return
        try:
            hook()
        except Exception as exc:  # pragma: no cover - defensive
            self.log.error("alert delivery tick raised %s: %s", type(exc).__name__, exc)


class MultiSink:
    """Fan one alert out to several sinks, in order.

    Used when alerts are both written locally and posted to the backend.

    A *delivery* failure in one sink must not cost the others their copy of
    the alert: the backend being down is no reason for the local JSONL
    record to lose a line, and the fan-out order should not decide which
    sinks get served. So :class:`AlertDeliveryError` is held back until
    every sink has been offered the alert, then re-raised - the failure is
    reported, never hidden.

    Any other exception (a local file-write failing, say) still stops the
    fan-out immediately, exactly as before. That is not a delivery problem
    and absorbing it would hide a broken output.
    """

    def __init__(self, sinks: Iterable[AlertSink]) -> None:
        self.sinks = list(sinks)

    def emit(self, alert: ThreatAlert) -> None:
        failures: list[AlertDeliveryError] = []
        for sink in self.sinks:
            try:
                sink.emit(alert)
            except AlertDeliveryError as exc:
                failures.append(exc)
        if failures:
            # The first failure carries the backend's own words. Raised only
            # once the remaining sinks have their copy.
            raise failures[0]

    def close(self) -> None:
        for sink in self.sinks:
            sink.close()


def _quote_body(body: bytes, limit: int = 200) -> str:
    """A short quote of the backend's complaint, if it sent one."""
    try:
        text = body.decode("utf-8", "replace").strip()
    except Exception:  # pragma: no cover - unreadable body
        return ""
    return f" - {text[:limit]}" if text else ""


# --------------------------------------------------------------------------
# Telemetry
# --------------------------------------------------------------------------


class TelemetrySample(NamedTuple):
    """One reading for the backend's throughput panel."""

    flows_per_sec: float
    packets_per_sec: float
    mbps: float
    detectors_online: int
    detectors_total: int


class TelemetryReporter:
    """POSTs processing rates to the backend's ``/api/v1/telemetry`` route.

    The backend only ever sees alerts, so it cannot tell a quiet network
    from a dead sensor: both produce nothing. The dashboard's throughput
    panel and the "how many flows per second does this handle" requirement
    are both unanswerable without a number from the side that can count -
    which is this side. The route has existed and had no caller.

    The figures are **processing rates on a monotonic wall clock**: flows,
    packets and bytes actually pushed through the detectors per real second.
    On a live capture that is also the rate of the link. On a replay it is
    not - it is how fast the file is being consumed - which is exactly why
    the report carries ``source``, and why the runner sets it to
    ``"replay"`` for a file and ``"live_capture"`` for a stream. The panel
    can then say which of the two it is showing instead of implying a link
    rate that was never measured.

    Reporting must never cost detection anything, so this owns a worker
    thread and a **single-slot** mailbox: :meth:`report` overwrites whatever
    has not been sent yet and returns. A telemetry reading is a gauge, not a
    record - when the backend is slow the right thing to lose is the stale
    reading, not the next second of detection. Dropped readings are counted
    in ``samples_dropped`` so the loss is visible rather than assumed.
    """

    #: Values the backend's ``TelemetryReport.source`` accepts.
    SOURCES = ("live_capture", "replay", "flow_collector", "benchmark")

    def __init__(
        self,
        url: str,
        *,
        source: str = "replay",
        timeout: float = DEFAULT_API_TIMEOUT,
        log: logging.Logger | None = None,
    ) -> None:
        if not url:
            raise ValueError("telemetry url must not be empty")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if source not in self.SOURCES:
            raise ValueError(
                f"source must be one of {self.SOURCES}, got {source!r}; the "
                "backend rejects anything else with a 422"
            )
        self.url = url
        self.source = source
        self.timeout = timeout
        self.log = log or logger
        self.sent = 0
        self.failures = 0
        self.samples_dropped = 0
        self._connection = _KeepAliveConnection(url, timeout=timeout)
        self._ready = threading.Condition()
        self._pending: TelemetrySample | None = None
        self._stopping = False
        self._failing = False
        self._closed = False
        self._worker = threading.Thread(
            target=self._drain, name="telemetry", daemon=True
        )
        self._worker.start()

    def report(self, sample: TelemetrySample) -> None:
        """Queue a reading, replacing any that has not been sent yet."""
        with self._ready:
            if self._pending is not None:
                self.samples_dropped += 1
            self._pending = sample
            self._ready.notify()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with self._ready:
            self._stopping = True
            self._ready.notify()
        self._worker.join(timeout=self.timeout + 1.0)
        self._connection.close()

    # --- internals --------------------------------------------------------

    def _drain(self) -> None:
        while True:
            with self._ready:
                while self._pending is None and not self._stopping:
                    self._ready.wait()
                sample, self._pending = self._pending, None
                stopping = self._stopping
            if sample is not None:
                self._post(sample)
            elif stopping:
                return

    def _post(self, sample: TelemetrySample) -> None:
        payload = json.dumps(
            {
                "flows_per_sec": round(sample.flows_per_sec, 3),
                "packets_per_sec": round(sample.packets_per_sec, 3),
                "mbps": round(sample.mbps, 4),
                "detectors_online": sample.detectors_online,
                "detectors_total": sample.detectors_total,
                "source": self.source,
            }
        ).encode("utf-8")
        try:
            response = self._connection.post(payload)
        except (http.client.HTTPException, OSError) as exc:
            self._failed(f"could not reach {self.url}: {exc}")
            return
        if not 200 <= response.status < 300:
            self._failed(
                f"{self.url} returned HTTP {response.status} {response.reason}"
                f"{_quote_body(response.body)}"
            )
            return
        self.sent += 1
        if self._failing:
            self._failing = False
            self.log.info("telemetry reporting to %s recovered", self.url)

    def _failed(self, message: str) -> None:
        """Count every failure; log the first of a run of them.

        A reading a second against a backend that is down would otherwise
        put sixty identical lines a minute on stderr, which is how the one
        line that mattered gets missed. Telemetry is also the least
        important thing here: losing it degrades a panel, not detection.
        """
        self.failures += 1
        if not self._failing:
            self._failing = True
            self.log.warning("telemetry report failed (further ones muted): %s", message)


# --------------------------------------------------------------------------
# Run loop
# --------------------------------------------------------------------------


@dataclass
class RunStats:
    """What one run did."""

    flows: int = 0
    alerts: int = 0
    detector_errors: int = 0
    #: Alerts at least one sink could not deliver. With the CLI's single
    #: HTTP sink this is exactly the number of alerts the backend never
    #: received - they were produced, and any local sink still has them.
    delivery_failures: int = 0
    #: Alerts discarded by a bounded delivery queue to keep the detection
    #: loop moving - see :class:`QueuedAlertSink`. Counted separately from
    #: ``delivery_failures`` because the cause and the fix differ: a failure
    #: means the backend refused or could not be reached, a drop means it
    #: could not keep up. Both mean the backend does not have the alert, and
    #: any local sink does.
    alerts_dropped: int = 0


class _RateWindow:
    """Flows, packets and bytes seen since the last telemetry report."""

    __slots__ = ("flows", "packets", "octets")

    def __init__(self) -> None:
        self.flows = 0
        self.packets = 0
        self.octets = 0

    def add(self, flow: FlowEvent) -> None:
        self.flows += 1
        self.packets += (flow.orig_pkts or 0) + (flow.resp_pkts or 0)
        self.octets += (flow.orig_bytes or 0) + (flow.resp_bytes or 0)

    def reset(self) -> None:
        self.flows = self.packets = self.octets = 0

    def sample(
        self, elapsed: float, *, online: int, total: int
    ) -> TelemetrySample:
        seconds = max(elapsed, 1e-9)
        return TelemetrySample(
            flows_per_sec=self.flows / seconds,
            packets_per_sec=self.packets / seconds,
            # Mb/s, decimal megabits, as the panel labels it.
            mbps=(self.octets * 8.0) / seconds / 1_000_000.0,
            detectors_online=online,
            detectors_total=total,
        )


def run_detection(
    source: Iterable[FlowEvent],
    sink: AlertSink,
    detectors: list[Detector],
    *,
    log: logging.Logger | None = None,
    telemetry: TelemetryReporter | None = None,
    telemetry_interval: float = DEFAULT_TELEMETRY_INTERVAL,
) -> RunStats:
    """Stream every flow through the detectors, emitting alerts as they appear.

    ``source`` is consumed lazily and alerts are handed to ``sink`` one at a
    time, so nothing accumulates: neither the flows nor the alerts are ever
    held as a list.

    Detector exceptions stay contained by ``DetectionEngine`` exactly as they
    do everywhere else - one misbehaving detector must not end the run - and
    are counted in the returned stats.

    :class:`AlertDeliveryError` is contained the same way, and for the same
    reason: a sensor that stops detecting because a dashboard is down has
    turned a delivery problem into a detection outage, and every flow after
    the first bad POST would go unexamined. The alert is never treated as
    delivered - each failure is logged as an error and counted in
    ``delivery_failures`` - so a degraded run is loud rather than silent.
    Nothing is queued or retried here; the run simply continues.

    Other sink exceptions are deliberately NOT caught. A local JSONL write
    failing is a broken output, not a network hiccup, and must still stop
    the run.

    Some sinks cannot know at ``emit`` time whether delivery succeeded -
    :class:`QueuedAlertSink` has only enqueued it, :class:`BulkHttpAlertSink`
    has only buffered it. Those expose a ``settle()`` hook; every sink in
    the tree that has one is settled before this returns, and its counters
    folded into the result. Without that step the run would report zero
    failures for a backend that received nothing.

    ``telemetry``, when given, receives a reading roughly every
    ``telemetry_interval`` seconds and one final reading for the last
    partial interval. Readings are driven by flows arriving, so a stream
    that goes idle stops reporting rather than reporting a stale rate - the
    backend already marks unreported figures stale, which is the honest
    answer to "nothing is arriving".
    """
    log = log or logger
    engine = DetectionEngine(detectors)
    stats = RunStats()
    total_detectors = len(detectors)

    window = _RateWindow()
    last_report = time.monotonic()

    def tick(flow: FlowEvent) -> None:
        nonlocal last_report
        if telemetry is None:
            return
        window.add(flow)
        now = time.monotonic()
        elapsed = now - last_report
        if elapsed < telemetry_interval:
            return
        last_report = now
        telemetry.report(
            window.sample(
                elapsed,
                online=total_detectors - len(engine.stats.errored_detectors),
                total=total_detectors,
            )
        )
        window.reset()

    for alert in engine.run(_counting(source, stats, tick)):
        stats.alerts += 1
        try:
            sink.emit(alert)
        except AlertDeliveryError as exc:
            stats.delivery_failures += 1
            log.error("alert delivery failed, continuing: %s", exc)

    if telemetry is not None:
        # One last reading so the panel's final value covers the tail of the
        # run rather than freezing on the previous whole second.
        telemetry.report(
            window.sample(
                max(time.monotonic() - last_report, 1e-9),
                online=total_detectors - len(engine.stats.errored_detectors),
                total=total_detectors,
            )
        )

    _settle_deferred(sink, stats)

    stats.detector_errors = engine.stats.detector_errors
    if stats.detector_errors:
        log.warning(
            "%d detector error(s) during the run; see the log above",
            stats.detector_errors,
        )
    if stats.delivery_failures:
        log.error(
            "%d of %d alert(s) were not delivered; the backend is missing them",
            stats.delivery_failures,
            stats.alerts,
        )
    if stats.alerts_dropped:
        log.error(
            "%d of %d alert(s) were dropped from the delivery queue; the "
            "backend is missing them",
            stats.alerts_dropped,
            stats.alerts,
        )
    return stats


def _counting(
    source: Iterable[FlowEvent], stats: RunStats, tick: Any = None
) -> Iterator[FlowEvent]:
    """Pass flows through, counting them, without materializing the stream.

    ``tick`` is called once per flow. It lives here rather than in the alert
    loop because the alert loop only runs when a detector fires: a quiet
    minute produces no alerts, and telemetry driven from there would report
    nothing at exactly the times an operator most wants to know the sensor
    is alive.
    """
    for flow in source:
        stats.flows += 1
        if tick is not None:
            tick(flow)
        yield flow


def _settle_deferred(sink: object, stats: RunStats) -> None:
    """Finish deferred delivery and fold its counters into ``stats``."""
    for candidate in _iter_sinks(sink):
        settle = getattr(candidate, "settle", None)
        if not callable(settle):
            continue
        settle()
        stats.delivery_failures += int(getattr(candidate, "delivery_failures", 0) or 0)
        stats.alerts_dropped += int(getattr(candidate, "alerts_dropped", 0) or 0)


def _iter_sinks(sink: object) -> Iterator[object]:
    """A sink and, for a fan-out, everything it fans out to.

    Deliberately does not descend into a *wrapper*'s single inner sink:
    :class:`QueuedAlertSink` already reports its wrapped sink's counters as
    part of its own, and walking into it as well would count every failure
    twice.
    """
    yield sink
    for inner in getattr(sink, "sinks", ()) or ():
        yield from _iter_sinks(inner)
