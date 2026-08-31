"""Regression tests for streaming input, deferred delivery and telemetry.

These cover the five things that made the detection layer a batch tool rather
than a sensor: delivery that blocked the detection loop, an entry point that
could only read a finished file, no throughput reporting at all, no caller for
the backend's bulk route, and no DGA artifact on a default run.

The theme running through most of them is **the detection loop must not be
pausable from outside**. Several tests therefore assert on *ordering and
counts* rather than on wall-clock speed - a timing assertion on a shared CI
box measures the box, not the code. Where elapsed time is genuinely the thing
under test the margin is left enormous (a hundredfold), so the test only fails
if the blocking behaviour is actually back.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from detection_core import runner
from detection_core.engine import Detector
from detection_core.pipeline import (
    DEFAULT_API_TIMEOUT,
    MAX_BULK_SIZE,
    AlertDeliveryError,
    BulkHttpAlertSink,
    HttpAlertSink,
    JsonlAlertSink,
    MultiSink,
    QueuedAlertSink,
    TelemetryReporter,
    TelemetrySample,
    build_default_detectors,
    run_detection,
)

from .conftest import DummyDetector, make_alert, make_flow

# How long a test may wait for the delivery thread to do something before
# declaring it wedged. Generous: this is a failure timeout, not a delay.
WAIT = 5.0


# --------------------------------------------------------------------------
# Test doubles
# --------------------------------------------------------------------------


class _BlockingSink:
    """Stops inside ``emit`` until released, so the queue can be filled."""

    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.delivered: list[str] = []
        self.closed = False

    def emit(self, alert) -> None:
        self.entered.set()
        self.release.wait(timeout=WAIT)
        self.delivered.append(alert.detector)

    def close(self) -> None:
        self.closed = True


class _SlowSink:
    """Takes ``delay`` seconds per alert, the way a real backend does."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.delivered: list[str] = []

    def emit(self, alert) -> None:
        time.sleep(self.delay)
        self.delivered.append(alert.detector)

    def close(self) -> None:
        pass


class _RecordingTelemetry:
    """Captures samples instead of posting them."""

    def __init__(self) -> None:
        self.samples: list[TelemetrySample] = []

    def report(self, sample: TelemetrySample) -> None:
        self.samples.append(sample)

    def close(self) -> None:
        pass


class _DeferredStub:
    """A sink that reports counters it could only know after ``settle``."""

    def __init__(self, *, failures: int = 0, dropped: int = 0) -> None:
        self.delivery_failures = failures
        self.alerts_dropped = dropped
        self.settled = False
        self.closed = False

    def emit(self, alert) -> None:
        pass

    def settle(self) -> None:
        self.settled = True

    def close(self) -> None:
        self.closed = True


class _ExplodingDetector(Detector):
    """Raises on every flow, so ``detectors_online`` has something to exclude."""

    name = "exploding"
    version = "1.0.0"

    def process(self, flow):
        raise RuntimeError("boom")

    def reset(self) -> None:
        pass


# --------------------------------------------------------------------------
# A backend that speaks keep-alive, bulk and telemetry
# --------------------------------------------------------------------------


class _Backend(BaseHTTPRequestHandler):
    """Stands in for the three routes this layer talks to.

    ``protocol_version`` is HTTP/1.1 and every response carries a
    ``Content-Length`` on purpose: without both, the server closes the socket
    after each response and the connection-reuse test would pass for the wrong
    reason - the client would be opening a new connection each time and the
    server would never say so.
    """

    protocol_version = "HTTP/1.1"

    alerts: list[dict] = []
    batches: list[list[dict]] = []
    telemetry: list[dict] = []
    paths: list[str] = []
    connections = 0
    status = 202
    #: How many alerts of the next bulk batch to report as rejected.
    reject = 0
    #: Seconds to stall before answering, standing in for a slow backend.
    delay = 0.0

    def setup(self):  # noqa: D102 - counts TCP connections, not requests
        type(self).connections += 1
        super().setup()

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", 0))
        payload = json.loads(self.rfile.read(length)) if length else {}
        cls = type(self)
        cls.paths.append(self.path)
        if cls.delay:
            time.sleep(cls.delay)

        if self.path.endswith("/telemetry"):
            cls.telemetry.append(payload)
            return self._respond(204, None)
        if self.path.endswith("/bulk"):
            batch = payload.get("alerts", [])
            cls.batches.append(batch)
            rejected = min(cls.reject, len(batch))
            cls.alerts.extend(batch[rejected:])
            return self._respond(
                cls.status,
                {
                    "accepted": len(batch) - rejected,
                    "rejected": rejected,
                    "errors": [
                        {
                            "index": i,
                            "alert_id": batch[i].get("alert_id"),
                            "errors": [{"field": "score", "msg": "not a probability"}],
                        }
                        for i in range(rejected)
                    ],
                },
            )
        # Only what the backend actually accepted is recorded. A rejected
        # POST really did not land, and counting it here would let a test
        # "prove" delivery that never happened.
        if 200 <= cls.status < 300:
            cls.alerts.append(payload)
        return self._respond(cls.status, {"ok": True})

    def _respond(self, status: int, body: dict | None) -> None:
        raw = b"" if body is None else json.dumps(body).encode("utf-8")
        self.send_response(status)
        if status != 204:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if raw:
            self.wfile.write(raw)

    def log_message(self, *args):  # keep the test output quiet
        pass


@pytest.fixture
def backend():
    """A throwaway backend; yields (base_url_for_alerts, telemetry_url)."""
    _Backend.alerts = []
    _Backend.batches = []
    _Backend.telemetry = []
    _Backend.paths = []
    _Backend.connections = 0
    _Backend.status = 202
    _Backend.reject = 0
    _Backend.delay = 0.0
    # Threading, not the plain HTTPServer, because these sinks hold a
    # keep-alive connection open: a single-threaded server would sit inside
    # one handler waiting for the next request on that socket, and teardown
    # would block behind it. daemon_threads lets an idle kept-alive
    # connection be abandoned at shutdown rather than joined.
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Backend)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    root = f"http://127.0.0.1:{server.server_port}/api/v1"
    yield f"{root}/alerts", f"{root}/telemetry"
    server.shutdown()
    server.server_close()


def _alerts(count: int) -> list:
    """Alerts distinguishable by ``detector``, which survives the wire."""
    return [make_alert(detector=f"a{i}") for i in range(count)]


@pytest.fixture
def dga_model_path(tmp_path_factory):
    """A tiny model fitted in-process, saved only under tmp. Never committed.

    Deliberately local to this module and imported lazily: everything else in
    this file is about delivery and streaming and must keep running on a
    core-only install, so the ML extra is only touched by the tests that are
    actually about DGA.
    """
    ml = pytest.importorskip("detection_core.ml.dga")
    benign = [
        "google.com", "facebook.com", "youtube.com", "wikipedia.org",
        "amazon.com", "github.com", "stackoverflow.com", "microsoft.com",
    ]
    dga = [
        "kq3v9x2mzt7wp1.com", "xjfkdlspqoweirut.net", "zzqxwvbnmlkjhg.org",
        "vbnmqwertyuiopas.com", "plmoknijbuhvygc.net", "qazwsxedcrfvtgb.com",
        "mnbvcxzlkjhgfds.org", "poiuytrewqasdfgh.net",
    ]
    model = ml.DGAModel.new(n_estimators=60, random_state=42, n_jobs=1)
    model.fit(
        benign + dga,
        [ml.LABEL_BENIGN] * len(benign) + [ml.LABEL_DGA] * len(dga),
    )
    return model.save(tmp_path_factory.mktemp("dga") / "model.joblib")


# ==========================================================================
# 1. Delivery must not block the detection loop
# ==========================================================================


def test_emit_returns_without_waiting_for_the_backend():
    """The whole point: enqueueing is not delivery.

    Ten alerts against a sink that takes 50ms each is half a second of
    delivery. If ``emit`` still waited for it, the loop below would take that
    long; it must instead return almost immediately, leaving the work to the
    delivery thread.
    """
    inner = _SlowSink(delay=0.05)
    sink = QueuedAlertSink(inner, maxsize=100)

    started = time.monotonic()
    for alert in _alerts(10):
        sink.emit(alert)
    elapsed = time.monotonic() - started

    assert elapsed < 0.05, (
        f"emit blocked for {elapsed:.3f}s; delivery is back on the caller's thread"
    )
    sink.close()
    assert len(inner.delivered) == 10, "close() must not lose the backlog"


def test_a_full_queue_drops_the_oldest_and_counts_every_drop():
    """Bounded, drop-oldest, and never silent about it."""
    inner = _BlockingSink()
    sink = QueuedAlertSink(inner, maxsize=2)
    a0, a1, a2, a3, a4 = _alerts(5)

    sink.emit(a0)
    # Wait until the worker has actually taken a0 and stalled, so the queue
    # state below is decided by the code and not by thread scheduling.
    assert inner.entered.wait(timeout=WAIT)

    sink.emit(a1)
    sink.emit(a2)  # queue now holds two: a1, a2
    sink.emit(a3)  # full -> drops a1
    sink.emit(a4)  # full -> drops a2

    assert sink.alerts_dropped == 2
    inner.release.set()
    sink.close()

    assert inner.delivered == ["a0", "a3", "a4"], (
        "the freshest alerts must survive, not the stalest"
    )


def test_run_stats_surfaces_drops_next_to_delivery_failures():
    """Both counters reach RunStats, and mean different things.

    A drop and a failure have the same consequence - the backend does not have
    the alert - but different causes, so they are counted apart.
    """
    stub = _DeferredStub(failures=3, dropped=2)

    stats = run_detection([make_flow()], MultiSink([stub]), [DummyDetector()])

    assert stub.settled, "a deferred sink must be settled before counts are read"
    assert stats.delivery_failures == 3
    assert stats.alerts_dropped == 2


def test_a_queued_sink_never_raises_delivery_errors_at_the_caller():
    """The worker absorbs failures; the detection loop never sees them."""

    class _Failing:
        def emit(self, alert):
            raise AlertDeliveryError("backend is down")

        def close(self):
            pass

    sink = QueuedAlertSink(_Failing())
    for alert in _alerts(3):
        sink.emit(alert)  # must not raise
    sink.settle()

    assert sink.delivery_failures == 3
    sink.close()


def test_the_worker_outlives_a_sink_that_raises_something_unexpected():
    """A dead delivery thread would leave emit filling a queue nobody drains."""

    class _Erratic:
        def __init__(self):
            self.seen = 0

        def emit(self, alert):
            self.seen += 1
            if self.seen == 1:
                raise ValueError("not a delivery error at all")

        def close(self):
            pass

    inner = _Erratic()
    sink = QueuedAlertSink(inner)
    for alert in _alerts(3):
        sink.emit(alert)
    sink.settle()

    assert inner.seen == 3, "the worker stopped after the first exception"
    assert sink.delivery_failures == 1
    sink.close()


def test_one_connection_is_reused_across_many_posts(backend):
    """82 alerts/s was mostly TCP setup. One connection, many alerts."""
    url, _ = backend
    sink = HttpAlertSink(url, timeout=WAIT)

    for alert in _alerts(5):
        sink.emit(alert)
    sink.close()

    assert len(_Backend.alerts) == 5
    assert _Backend.connections == 1, (
        f"opened {_Backend.connections} connections for 5 alerts; "
        "keep-alive is not being used"
    )


def test_a_slow_backend_does_not_set_the_pace_of_detection(backend):
    """The measurement that motivated the change, in miniature.

    Twenty flows against a backend that takes 100ms per alert is two seconds
    of delivery. What must not happen is the *reading of flows* taking two
    seconds - that is the regression, because the flows arriving during such a
    stall on a live sensor are not delayed, they are unexamined.

    So the clock is stopped when the source is exhausted, not when the run
    returns: ``run_detection`` deliberately settles the delivery backlog
    before returning, and timing that would measure the backend rather than
    the loop.
    """
    url, _ = backend
    _Backend.delay = 0.1
    sink = QueuedAlertSink(HttpAlertSink(url, timeout=WAIT), maxsize=1000)
    finished_reading: list[float] = []

    def flows():
        for _ in range(20):
            yield make_flow()
        finished_reading.append(time.monotonic())

    started = time.monotonic()
    stats = run_detection(flows(), sink, [DummyDetector()])
    total = time.monotonic() - started
    reading = finished_reading[0] - started

    assert stats.alerts == 20
    assert reading < 0.2, (
        f"reading 20 flows took {reading:.2f}s against a slow backend; "
        "detection is serialized behind delivery again"
    )
    # And the delivery really was slow, so the margin above means something
    # rather than the backend having been fast all along.
    assert total > 0.5, f"the backend was not actually slow (total {total:.2f}s)"
    sink.close()


def test_the_default_timeout_is_far_below_the_old_ten_seconds():
    """A wedged backend must not hold one alert for ten seconds."""
    assert DEFAULT_API_TIMEOUT <= 5.0


def test_the_local_record_is_never_behind_the_delivery_queue(tmp_path, backend):
    """The JSONL copy must be complete even when the backend misses alerts.

    That promise is what the DEGRADED message points at, and it only holds if
    the local sink stays on the detection thread.
    """
    url, _ = backend
    _Backend.status = 500
    path = tmp_path / "flows.jsonl"
    path.write_text(
        "\n".join(
            json.dumps(
                {
                    "flow_id": f"10.0.0.5:10.0.0.9:{1000 + i}:tcp:{1000.0 + i * 0.1}",
                    "timestamp": 1000.0 + i * 0.1,
                    "src_ip": "10.0.0.5",
                    "dst_ip": "10.0.0.9",
                    "dst_port": 1000 + i,
                    "proto": "tcp",
                    "duration": 0.01,
                    "orig_bytes": 60,
                    "resp_bytes": 0,
                    "orig_pkts": 1,
                    "resp_pkts": 0,
                }
            )
            for i in range(40)
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "alerts.jsonl"

    code = runner.main(
        [str(path), "--output", str(out), "--api-url", url, "--quiet"]
    )

    assert code == runner.EXIT_DELIVERY_DEGRADED
    written = [json.loads(line) for line in out.read_text().splitlines() if line]
    assert written, "the run produced no alerts at all"
    assert _Backend.alerts == [], "the backend was supposed to reject everything"
    # Every alert the run produced is on disk, which is what the DEGRADED
    # message promises the operator.
    assert all(a["threat_class"] == "port_scan" for a in written)


# ==========================================================================
# 2. Streaming input: stdin and --follow
# ==========================================================================


def _flow_line(i: int, port: int) -> str:
    return json.dumps(
        {
            "flow_id": f"10.0.0.5:10.0.0.9:{port}:tcp:{1000.0 + i * 0.1}",
            "timestamp": 1000.0 + i * 0.1,
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.9",
            "dst_port": port,
            "proto": "tcp",
            "duration": 0.01,
            "orig_bytes": 60,
            "resp_bytes": 0,
            "orig_pkts": 1,
            "resp_pkts": 0,
        }
    )


def test_a_dash_reads_flows_from_stdin(tmp_path, monkeypatch, capsys):
    """``ingestion ... -o - | detection -`` is the whole point of this mode."""
    import io

    lines = "\n".join(_flow_line(i, 1000 + i) for i in range(40)) + "\n"
    monkeypatch.setattr("sys.stdin", io.StringIO(lines))
    out = tmp_path / "alerts.jsonl"

    code = runner.main(["-", "--output", str(out), "--quiet"])

    assert code == runner.EXIT_OK
    alerts = [json.loads(line) for line in out.read_text().splitlines() if line]
    assert alerts, "a port scan on stdin produced no alerts"
    assert alerts[0]["threat_class"] == "port_scan"


def test_stdin_skips_the_is_file_check(monkeypatch, capsys):
    """``-`` names no file, so 'input file not found' must not fire."""
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO(""))

    code = runner.main(["-", "--quiet"])

    assert code == runner.EXIT_OK
    assert "input file not found" not in capsys.readouterr().err


def test_stdin_still_protects_the_other_inputs_from_output(tmp_path, capsys):
    """Only the *input* half of the collision check is waived.

    ``--output`` aimed at the model bundle destroys it whatever the input
    mode, so skipping the whole check in stdin mode would be a regression
    dressed up as a feature.
    """
    model = tmp_path / "dga_model.joblib"
    model.write_bytes(b"not really a model")

    code = runner.main(
        ["-", "--output", str(model), "--dga-model", str(model), "--quiet"]
    )

    assert code == runner.EXIT_ERROR
    assert "would destroy it" in capsys.readouterr().err


def test_follow_reads_records_appended_after_eof(tmp_path):
    """--follow is tail -f: EOF is not the end of the stream."""
    path = tmp_path / "live.jsonl"
    path.write_text(_flow_line(0, 1000) + "\n", encoding="utf-8")
    stop = threading.Event()
    seen: list[str] = []

    def consume():
        for line in runner._follow_lines(path, stop=stop, poll_interval=0.01):
            seen.append(line)

    reader = threading.Thread(target=consume, daemon=True)
    reader.start()

    deadline = time.monotonic() + WAIT
    while len(seen) < 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(seen) == 1, "the line already in the file was not read"

    with open(path, "a", encoding="utf-8") as handle:
        handle.write(_flow_line(1, 1001) + "\n")
        handle.flush()

    deadline = time.monotonic() + WAIT
    while len(seen) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.set()
    reader.join(timeout=WAIT)

    assert len(seen) == 2, "a record appended after EOF was never read"


def test_follow_waits_for_a_half_written_line_to_finish(tmp_path):
    """A fragment must never reach the adapter as though it were a record.

    A producer flushing mid-record leaves the file ending without a newline.
    Handing that on would cost two parse errors for one perfectly good flow.
    """
    path = tmp_path / "partial.jsonl"
    full = _flow_line(0, 1000)
    path.write_text(full[:20], encoding="utf-8")  # deliberately truncated
    stop = threading.Event()
    seen: list[str] = []

    def consume():
        for line in runner._follow_lines(path, stop=stop, poll_interval=0.01):
            seen.append(line)

    reader = threading.Thread(target=consume, daemon=True)
    reader.start()
    time.sleep(0.1)
    assert seen == [], "a partial line was emitted before its newline arrived"

    with open(path, "a", encoding="utf-8") as handle:
        handle.write(full[20:] + "\n")
        handle.flush()

    deadline = time.monotonic() + WAIT
    while not seen and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.set()
    reader.join(timeout=WAIT)

    assert seen == [full + "\n"], "the completed line was not reassembled"


def test_follow_with_stdin_is_refused(capsys):
    """Following a closed stdin would spin on EOF forever."""
    code = runner.main(["-", "--follow", "--quiet"])

    assert code == runner.EXIT_ERROR
    assert "--follow cannot be combined with '-'" in capsys.readouterr().err


def test_a_missing_input_file_is_still_an_error(tmp_path, capsys):
    """The stdin path must not have loosened the check for real paths."""
    code = runner.main([str(tmp_path / "nope.jsonl"), "--quiet"])

    assert code == runner.EXIT_ERROR
    assert "input file not found" in capsys.readouterr().err


# ==========================================================================
# 3. Telemetry
# ==========================================================================


def test_telemetry_posts_exactly_the_fields_the_backend_declares(backend):
    """The shape is ``TelemetryReport`` in backend/app/api/alerts.py.

    Asserted as an exact key set rather than a subset: an extra key is a 422
    from a model that does not accept unknown fields, and a missing one is a
    panel that silently reads zero.
    """
    _, telemetry_url = backend
    reporter = TelemetryReporter(telemetry_url, source="replay", timeout=WAIT)

    reporter.report(
        TelemetrySample(
            flows_per_sec=1234.5,
            packets_per_sec=9876.5,
            mbps=42.25,
            detectors_online=6,
            detectors_total=7,
        )
    )
    reporter.close()

    assert len(_Backend.telemetry) == 1
    report = _Backend.telemetry[0]
    assert set(report) == {
        "flows_per_sec",
        "packets_per_sec",
        "mbps",
        "detectors_online",
        "detectors_total",
        "source",
    }
    assert report["flows_per_sec"] == pytest.approx(1234.5)
    assert report["detectors_online"] == 6
    assert report["detectors_total"] == 7
    assert report["source"] == "replay"


def test_a_source_the_backend_would_reject_fails_at_construction():
    """A 422 an hour into a run is worse than a refusal at startup."""
    with pytest.raises(ValueError, match="source must be one of"):
        TelemetryReporter("http://127.0.0.1:1/x", source="guesswork")


def test_telemetry_measures_flows_per_second_on_a_real_clock():
    """flows/sec is flows divided by elapsed seconds, not a guess."""
    recorder = _RecordingTelemetry()

    run_detection(
        [make_flow() for _ in range(10)],
        JsonlAlertSink(open_devnull()),
        [DummyDetector()],
        telemetry=recorder,
        telemetry_interval=0.0,  # report on every flow
    )

    assert recorder.samples, "no telemetry was reported at all"
    # Every reading but the last covers an interval a flow arrived in. The
    # final one is the tail after the last flow, which genuinely saw none -
    # reporting 0 there is honest, not a bug, so it is excluded rather than
    # asserted over.
    assert all(s.flows_per_sec > 0 for s in recorder.samples[:-1])
    assert all(s.detectors_total == 1 for s in recorder.samples)
    assert all(s.detectors_online == 1 for s in recorder.samples)


def test_detectors_online_excludes_one_that_errored():
    """A detector that is throwing is not online, and the panel should say so."""
    recorder = _RecordingTelemetry()

    stats = run_detection(
        [make_flow() for _ in range(5)],
        JsonlAlertSink(open_devnull()),
        [DummyDetector(), _ExplodingDetector()],
        telemetry=recorder,
        telemetry_interval=0.0,
    )

    assert stats.detector_errors > 0
    last = recorder.samples[-1]
    assert last.detectors_total == 2
    assert last.detectors_online == 1, "the failing detector was still counted online"


def test_telemetry_drops_stale_readings_rather_than_delaying_detection():
    """A reading is a gauge. The right thing to lose is the old one."""
    reporter = TelemetryReporter.__new__(TelemetryReporter)
    # Constructed by hand so nothing is posted and no thread runs: this is
    # about the mailbox's replace-don't-queue rule, not about HTTP.
    reporter._ready = threading.Condition()
    reporter._pending = None
    reporter.samples_dropped = 0

    sample = TelemetrySample(1.0, 2.0, 3.0, 4, 5)
    TelemetryReporter.report(reporter, sample)
    TelemetryReporter.report(reporter, sample)
    TelemetryReporter.report(reporter, sample)

    assert reporter.samples_dropped == 2
    assert reporter._pending is sample


def test_the_runner_reports_replay_for_a_file(tmp_path, backend):
    """A file's flows/sec is a read rate, and must be labelled as one."""
    _, telemetry_url = backend
    path = tmp_path / "flows.jsonl"
    path.write_text(
        "\n".join(_flow_line(i, 1000 + i) for i in range(40)) + "\n", encoding="utf-8"
    )

    code = runner.main(
        [str(path), "--output", str(tmp_path / "a.jsonl"),
         "--telemetry-url", telemetry_url, "--quiet"]
    )

    assert code == runner.EXIT_OK
    assert _Backend.telemetry, "the runner posted no telemetry"
    assert all(r["source"] == "replay" for r in _Backend.telemetry)
    assert _Backend.telemetry[-1]["detectors_total"] >= 6


def test_the_runner_reports_live_capture_for_a_stream(tmp_path, backend, monkeypatch):
    """A stream is the case where flows/sec really is the link's rate."""
    import io

    _, telemetry_url = backend
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO("\n".join(_flow_line(i, 1000 + i) for i in range(40)) + "\n"),
    )

    code = runner.main(
        ["-", "--output", str(tmp_path / "a.jsonl"),
         "--telemetry-url", telemetry_url, "--quiet"]
    )

    assert code == runner.EXIT_OK
    assert _Backend.telemetry
    assert all(r["source"] == "live_capture" for r in _Backend.telemetry)


def test_a_broken_telemetry_endpoint_does_not_fail_the_run(tmp_path):
    """Losing telemetry degrades a panel. It must not degrade detection."""
    path = tmp_path / "flows.jsonl"
    path.write_text(
        "\n".join(_flow_line(i, 1000 + i) for i in range(40)) + "\n", encoding="utf-8"
    )

    code = runner.main(
        [str(path), "--output", str(tmp_path / "a.jsonl"),
         "--telemetry-url", "http://127.0.0.1:9/api/v1/telemetry", "--quiet"]
    )

    assert code == runner.EXIT_OK


def open_devnull():
    import io

    return io.StringIO()


# ==========================================================================
# 4. The bulk route
# ==========================================================================


def test_a_batch_goes_out_when_it_reaches_the_size(backend):
    url, _ = backend
    sink = BulkHttpAlertSink(f"{url}/bulk", batch_size=3, timeout=WAIT)

    for alert in _alerts(7):
        sink.emit(alert)

    assert [len(b) for b in _Backend.batches] == [3, 3], (
        "the seventh alert should still be buffered"
    )
    sink.close()
    assert [len(b) for b in _Backend.batches] == [3, 3, 1], "close() lost the remainder"
    assert sink.count == 7


def test_a_partial_batch_is_flushed_once_it_has_waited(backend):
    """Without the age rule a quiet minute leaves the dashboard silent."""
    url, _ = backend
    sink = BulkHttpAlertSink(
        f"{url}/bulk", batch_size=100, max_age=0.05, timeout=WAIT
    )

    sink.emit(make_alert(detector="lonely"))
    assert _Backend.batches == [], "sent a batch of one immediately"

    time.sleep(0.1)
    sink.tick()

    assert [len(b) for b in _Backend.batches] == [1]
    sink.close()


def test_a_rejected_count_becomes_a_counted_failure(backend, caplog):
    """A 202 that rejected alerts inside is not a clean run."""
    url, _ = backend
    _Backend.reject = 2
    sink = BulkHttpAlertSink(f"{url}/bulk", batch_size=5, timeout=WAIT)

    with caplog.at_level(logging.ERROR):
        for alert in _alerts(5):
            sink.emit(alert)

    assert sink.delivery_failures == 2, "a schema regression stayed silent"
    assert sink.count == 3
    assert "rejected 2 of 5" in caplog.text
    assert "score" in caplog.text, "the backend named the field; the log dropped it"
    sink.close()


def test_a_batch_above_the_backends_cap_is_refused_at_construction():
    """Discovered once, at startup - not one full batch at a time."""
    with pytest.raises(ValueError, match="between 1 and"):
        BulkHttpAlertSink("http://127.0.0.1:1/x", batch_size=MAX_BULK_SIZE + 1)


def test_an_unreadable_success_body_is_counted_but_reported(backend, caplog):
    """HTTP said accepted, so they are - but say the outcome is unverified."""
    url, _ = backend
    sink = BulkHttpAlertSink(f"{url}/bulk", batch_size=2, timeout=WAIT)
    # The plain /alerts route answers {"ok": true}, which carries no
    # "rejected" key - exactly the unrecognized shape this is about.
    sink._connection.url = url
    sink._connection._target = "/api/v1/alerts"

    with caplog.at_level(logging.WARNING):
        for alert in _alerts(2):
            sink.emit(alert)

    assert sink.count == 2
    assert sink.delivery_failures == 0
    assert "no recognizable summary" in caplog.text
    sink.close()


def test_api_batch_sends_alerts_to_the_bulk_route(tmp_path, backend):
    """The route that had no caller now has one."""
    url, _ = backend
    path = tmp_path / "flows.jsonl"
    path.write_text(
        "\n".join(_flow_line(i, 1000 + i) for i in range(40)) + "\n", encoding="utf-8"
    )
    out = tmp_path / "alerts.jsonl"

    code = runner.main(
        [str(path), "--output", str(out), "--api-url", url,
         "--api-batch", "2", "--quiet"]
    )

    assert code == runner.EXIT_OK
    assert _Backend.batches, "nothing reached the bulk route"
    assert all(p.endswith("/alerts/bulk") for p in _Backend.paths)
    written = [json.loads(line) for line in out.read_text().splitlines() if line]
    assert len(_Backend.alerts) == len(written)


def test_the_per_alert_sink_stays_the_default(tmp_path, backend):
    """--api-batch is opt-in; omitting it must change nothing."""
    url, _ = backend
    path = tmp_path / "flows.jsonl"
    path.write_text(
        "\n".join(_flow_line(i, 1000 + i) for i in range(40)) + "\n", encoding="utf-8"
    )

    code = runner.main(
        [str(path), "--output", str(tmp_path / "a.jsonl"), "--api-url", url, "--quiet"]
    )

    assert code == runner.EXIT_OK
    assert _Backend.batches == [], "batching happened without being asked for"
    assert all(p.endswith("/alerts") for p in _Backend.paths)


def test_api_batch_out_of_range_is_rejected_at_startup(tmp_path, capsys):
    path = tmp_path / "flows.jsonl"
    path.write_text(_flow_line(0, 1000) + "\n", encoding="utf-8")

    code = runner.main(
        [str(path), "--api-url", "http://127.0.0.1:1/x",
         "--api-batch", str(MAX_BULK_SIZE + 1), "--quiet"]
    )

    assert code == runner.EXIT_ERROR
    assert "between 1 and" in capsys.readouterr().err


def test_api_batch_without_an_api_url_is_rejected(tmp_path, capsys):
    path = tmp_path / "flows.jsonl"
    path.write_text(_flow_line(0, 1000) + "\n", encoding="utf-8")

    code = runner.main([str(path), "--api-batch", "10", "--quiet"])

    assert code == runner.EXIT_ERROR
    assert "--api-batch only means something with --api-url" in capsys.readouterr().err


# ==========================================================================
# 5. The DGA artifact
# ==========================================================================


def test_a_discovered_model_registers_dga(tmp_path, monkeypatch, capsys, dga_model_path):
    """A built artifact should join the line-up without being named."""
    monkeypatch.setattr(runner, "DEFAULT_DGA_MODEL_PATH", dga_model_path)
    path = tmp_path / "flows.jsonl"
    path.write_text(_flow_line(0, 1000) + "\n", encoding="utf-8")

    code = runner.main([str(path), "--output", str(tmp_path / "a.jsonl")])

    assert code == runner.EXIT_OK
    err = capsys.readouterr().err
    assert "dga_domain" in err
    assert "using the model found at" in err


def test_no_artifact_leaves_the_other_six_running(tmp_path, monkeypatch, capsys):
    """A missing build product must never take the subsystem offline."""
    monkeypatch.setattr(
        runner, "DEFAULT_DGA_MODEL_PATH", tmp_path / "nothing" / "dga_model.joblib"
    )
    path = tmp_path / "flows.jsonl"
    path.write_text(
        "\n".join(_flow_line(i, 1000 + i) for i in range(40)) + "\n", encoding="utf-8"
    )
    out = tmp_path / "alerts.jsonl"

    code = runner.main([str(path), "--output", str(out)])

    assert code == runner.EXIT_OK
    err = capsys.readouterr().err
    assert "dga_domain not registered" in err
    assert "port_scan" in err
    assert out.read_text().strip(), "the rule detectors stopped working too"


def test_a_corrupt_discovered_model_is_a_warning_not_an_outage(
    tmp_path, monkeypatch, capsys
):
    """A half-written artifact must not stop the six rule detectors.

    The distinction is explicit versus discovered: nobody asked for this
    model by name, so losing it costs a warning, not the run.
    """
    broken = tmp_path / "dga_model.joblib"
    broken.write_bytes(b"this is not a joblib bundle")
    monkeypatch.setattr(runner, "DEFAULT_DGA_MODEL_PATH", broken)
    path = tmp_path / "flows.jsonl"
    path.write_text(
        "\n".join(_flow_line(i, 1000 + i) for i in range(40)) + "\n", encoding="utf-8"
    )
    out = tmp_path / "alerts.jsonl"

    code = runner.main([str(path), "--output", str(out)])

    assert code == runner.EXIT_OK
    err = capsys.readouterr().err
    assert "could not be loaded" in err
    assert out.read_text().strip(), "a broken model took the rule detectors down"


def test_an_explicitly_named_broken_model_is_still_an_error(tmp_path, capsys):
    """Naming a model and silently not running it is the worse failure."""
    broken = tmp_path / "named.joblib"
    broken.write_bytes(b"this is not a joblib bundle")
    path = tmp_path / "flows.jsonl"
    path.write_text(_flow_line(0, 1000) + "\n", encoding="utf-8")

    code = runner.main([str(path), "--dga-model", str(broken), "--quiet"])

    assert code == runner.EXIT_ERROR


def test_an_explicit_model_still_beats_a_discovered_one(
    tmp_path, monkeypatch, dga_model_path
):
    """--dga-model must win over whatever happens to be in artifacts/."""
    monkeypatch.setattr(
        runner, "DEFAULT_DGA_MODEL_PATH", tmp_path / "never" / "dga_model.joblib"
    )
    path = tmp_path / "flows.jsonl"
    path.write_text(_flow_line(0, 1000) + "\n", encoding="utf-8")

    detectors_seen = []
    original = runner.build_default_detectors

    def spy(**kwargs):
        detectors_seen.append(kwargs.get("dga_model_path"))
        return original(**kwargs)

    monkeypatch.setattr(runner, "build_default_detectors", spy)
    code = runner.main(
        [str(path), "--dga-model", str(dga_model_path), "--quiet"]
    )

    assert code == runner.EXIT_OK
    assert detectors_seen == [dga_model_path]


@pytest.mark.skipif(
    not runner.DEFAULT_DGA_MODEL_PATH.is_file(),
    reason=(
        "no built DGA artifact; artifacts/ is gitignored, so this only runs "
        "where the training step has been run"
    ),
)
def test_the_built_artifact_loads_and_separates_the_two_classes():
    """The shipped bundle is a real model, not a placeholder.

    Deliberately not an accuracy assertion - the measured precision/recall
    belong to the training report, not to a unit test that would then have to
    be edited every time the model is retrained. What is checked here is the
    property that must hold for the artifact to be worth shipping at all:
    it loads, and it ranks obvious DGA above obvious benign.
    """
    from detection_core.ml.dga import DGAModel

    model = DGAModel.load(runner.DEFAULT_DGA_MODEL_PATH)

    assert model.is_fitted
    benign = model.predict_scores(["google.com", "wikipedia.org", "github.com"])
    dga = model.predict_scores(
        ["kq3v9x2mzt7wp1.com", "xjfkdlspqoweirut.net", "zzqxwvbnmlkjhg.org"]
    )
    assert max(benign) < min(dga), (
        f"the model does not separate the classes: benign={benign} dga={dga}"
    )


def test_the_factory_still_omits_dga_without_any_model():
    """The library layer stays model-agnostic; discovery is the CLI's job."""
    names = [d.name for d in build_default_detectors()]

    assert "dga_domain" not in names
    assert len(names) == 6
