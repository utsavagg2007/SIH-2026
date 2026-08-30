"""Integration tests for the detector factory, alert sinks and CLI runner.

These cover the *wiring*, not the detectors - each detector already has its
own unit suite, and nothing here re-tests their thresholds. What is proved
here is that a JSONL file on disk reaches a ThreatAlert on stdout, a file or
an HTTP endpoint, with the schema intact.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from detection_core import (
    AlertDeliveryError,
    DetectionEngine,
    HttpAlertSink,
    JsonlAlertSink,
    MultiSink,
    ThreatClass,
    build_default_detectors,
    run_detection,
    runner,
)
from detection_core.ml.dga import LABEL_BENIGN, LABEL_DGA, DGAModel

from .conftest import DummyDetector, make_alert, make_flow

EXIT_OK_CODE = 0

RULE_DETECTOR_NAMES = [
    "port_scan",
    "ddos",
    "c2_beaconing",
    "dns_tunnelling",
    "data_exfiltration",
    "encrypted_malware",
]

MIB = 1024 * 1024
BENIGN_DOMAINS = [
    "google.com", "facebook.com", "youtube.com", "wikipedia.org", "amazon.com",
    "github.com", "stackoverflow.com", "microsoft.com", "apple.com", "netflix.com",
]
DGA_DOMAINS = [
    "kq3v9x2mzt7wp1.com", "xjfkdlspqoweirut.net", "zzqxwvbnmlkjhg.org",
    "vbnmqwertyuiopas.com", "plmoknijbuhvygc.net", "qazwsxedcrfvtgb.com",
    "mnbvcxzlkjhgfds.org", "poiuytrewqasdfgh.net", "lkjhgfdsamnbvcxz.com",
    "trewqasdfgzxcvbn.org",
]


# --------------------------------------------------------------------------
# Synthetic ingestion-format records
# --------------------------------------------------------------------------


def record(ts, src, dst, **over):
    """One ingestion-style JSONL record, in the real top-level shape."""
    base = {
        "flow_id": f"{src}:{dst}:{over.get('dst_port', 443)}:{over.get('proto', 'tcp')}:{ts}",
        "src_ip": src, "dst_ip": dst, "dst_port": 443, "proto": "tcp",
        "duration": 0.5, "orig_bytes": 500, "resp_bytes": 800, "byte_ratio": 1.6,
        "orig_pkts": 4, "resp_pkts": 5, "pkt_ratio": 0.8, "conn_state_encoded": 4,
    }
    base.update(over)
    return json.dumps(base)


def scan_records():
    """One source sweeping many ports on one host."""
    return [
        record(1000.0 + i * 0.1, "10.0.0.5", "10.0.0.9", dst_port=1000 + i,
               orig_bytes=60, resp_bytes=0)
        for i in range(40)
    ]


def ddos_records():
    """Many sources converging on one destination."""
    return [
        record(2000.0 + i * 0.001, f"198.51.{i // 256}.{i % 256}", "10.0.0.80",
               dst_port=80, orig_bytes=200, orig_pkts=5)
        for i in range(300)
    ]


def c2_records():
    """One relationship on a fixed 30s timer."""
    return [
        record(3000.0 + i * 30.0, "10.0.0.50", "203.0.113.10", orig_bytes=512)
        for i in range(12)
    ]


def dns_tunnel_records():
    """Long, high-entropy, deeply-labelled, TXT-heavy DNS to one resolver."""
    return [
        record(
            4000.0 + i, "192.168.1.42", "192.168.1.1", dst_port=53, proto="udp",
            orig_bytes=74, resp_bytes=190,
            dns={"uid": f"Ctun{i}", "query_length": 110, "query_entropy": 4.9,
                 "subdomain_entropy": 4.7, "is_txt": True, "label_count": 9},
        )
        for i in range(25)
    ]


def exfil_records():
    """Bulk outbound bytes concentrated on one destination."""
    return [
        record(5000.0 + i, "10.0.0.30", "203.0.113.77", orig_bytes=8 * MIB,
               resp_bytes=512, orig_pkts=6000)
        for i in range(12)
    ]


def tls_metadata_records():
    """FUTURE-style TLS: raw server_name, which ingestion does not emit yet."""
    return [
        record(
            6000.0 + i, "10.0.0.60", "203.0.113.44",
            tls={"uid": f"Ctls{i}", "has_ja3": True, "has_ja3s": True,
                 "ssl_version_encoded": 4, "cipher_encoded": 7,
                 "server_name": "x7k2m9p4q1w8e3r6t5y0u2i4o6a8s1d3.example.com"},
        )
        for i in range(8)
    ]


def dga_records():
    """FUTURE-style DNS: raw query, which ingestion does not emit yet."""
    return [
        record(
            7000.0 + i, "10.0.0.20", "10.0.0.53", dst_port=53, proto="udp",
            orig_bytes=74, resp_bytes=190,
            dns={"uid": f"Cdga{i}", "query": DGA_DOMAINS[i % len(DGA_DOMAINS)],
                 "qtype": "A", "rcode": "NOERROR", "query_length": 18,
                 "query_entropy": 3.9, "label_count": 2, "is_txt": False},
        )
        for i in range(10)
    ]


#: Irregular gaps. Real browsing is bursty, not metronomic - a perfectly
#: even cadence is exactly what C2BeaconingDetector exists to catch, so a
#: fixture meant to be benign must not accidentally beacon.
BENIGN_GAPS = [2.0, 11.0, 3.5, 47.0, 6.0, 19.0, 4.5, 88.0, 7.5, 23.0, 5.0, 61.0]


def benign_records():
    """Ordinary browsing - nothing any detector should fire on.

    Deliberately shaped to avoid tripping a rule by accident: only four
    destinations (twenty hosts on one port inside a 60s window IS a
    horizontal scan, correctly), irregular gaps (an even cadence IS a
    beacon, correctly), small uploads against large downloads, and no
    DNS or TLS metadata blocks.
    """
    records, timestamp = [], 8000.0
    for index in range(30):
        timestamp += BENIGN_GAPS[index % len(BENIGN_GAPS)]
        records.append(
            record(timestamp, "192.168.1.8", f"192.0.78.{100 + (index % 4)}",
                   dst_port=443, orig_bytes=480, resp_bytes=9000,
                   orig_pkts=6, resp_pkts=9)
        )
    return records


@pytest.fixture(scope="module")
def dga_model_path(tmp_path_factory):
    """A tiny model fitted in-process, saved only under tmp. Never committed."""
    model = DGAModel.new(n_estimators=60, random_state=42, n_jobs=1)
    model.fit(
        BENIGN_DOMAINS + DGA_DOMAINS,
        [LABEL_BENIGN] * len(BENIGN_DOMAINS) + [LABEL_DGA] * len(DGA_DOMAINS),
    )
    return model.save(tmp_path_factory.mktemp("dga") / "model.joblib")


def write(tmp_path, name, lines):
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def read_alerts(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# --------------------------------------------------------------------------
# 1-4. Detector factory
# --------------------------------------------------------------------------


def test_factory_includes_every_non_dga_detector():
    detectors = build_default_detectors()
    assert [d.name for d in detectors] == RULE_DETECTOR_NAMES


def test_factory_omits_dga_without_a_model():
    """A missing artifact must not take the whole subsystem offline."""
    assert "dga_domain" not in [d.name for d in build_default_detectors()]


def test_factory_includes_dga_when_a_model_path_is_given(dga_model_path):
    detectors = build_default_detectors(dga_model_path=dga_model_path)
    assert [d.name for d in detectors] == RULE_DETECTOR_NAMES + ["dga_domain"]


def test_factory_includes_dga_when_a_model_object_is_given(dga_model_path):
    model = DGAModel.load(dga_model_path)
    detectors = build_default_detectors(dga_model=model)
    assert detectors[-1].name == "dga_domain"


def test_invalid_dga_path_fails_clearly(tmp_path):
    """The user asked for DGA explicitly; dropping it silently would be worse."""
    with pytest.raises(FileNotFoundError, match="DGA model not found"):
        build_default_detectors(dga_model_path=tmp_path / "nope.joblib")


def test_every_registered_detector_is_accepted_by_the_engine():
    """Guards against a detector being added to the factory but not usable."""
    engine = DetectionEngine(build_default_detectors())
    assert len(engine.detectors) == len(RULE_DETECTOR_NAMES)


# --------------------------------------------------------------------------
# 5-6. Streaming
# --------------------------------------------------------------------------


def test_run_is_incremental_and_does_not_buffer_the_stream():
    """Alerts must appear while the source is still being consumed."""
    consumed: list[int] = []
    emitted_at: list[int] = []
    flows = scan_records()

    def lazy_source():
        from detection_core.adapters import record_to_flow_event

        for index, line in enumerate(flows):
            consumed.append(index)
            yield record_to_flow_event(json.loads(line))

    class RecordingSink:
        def emit(self, alert):
            emitted_at.append(len(consumed))

        def close(self):
            pass

    run_detection(lazy_source(), RecordingSink(), build_default_detectors())

    assert emitted_at, "expected at least one alert"
    # The first alert landed before the source was exhausted.
    assert emitted_at[0] < len(flows)


def test_benign_traffic_produces_no_alerts(tmp_path):
    path = write(tmp_path, "benign.jsonl", benign_records())
    out = tmp_path / "alerts.jsonl"

    assert runner.main([str(path), "--output", str(out), "--quiet"]) == 0
    assert read_alerts(out) == []


# --------------------------------------------------------------------------
# 7-14. Each threat class reaches the wire
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "records,expected",
    [
        (scan_records(), ThreatClass.PORT_SCAN),
        (ddos_records(), ThreatClass.DDOS),
        (c2_records(), ThreatClass.C2_BEACONING),
        (dns_tunnel_records(), ThreatClass.DNS_TUNNELLING),
        (exfil_records(), ThreatClass.DATA_EXFILTRATION),
        (tls_metadata_records(), ThreatClass.ENCRYPTED_MALWARE),
    ],
    ids=["port_scan", "ddos", "c2", "dns_tunnel", "exfil", "encrypted_malware"],
)
def test_each_threat_class_reaches_the_output(tmp_path, records, expected):
    """One synthetic pattern per detector, through the real adapter and CLI."""
    path = write(tmp_path, f"{expected.value}.jsonl", records)
    out = tmp_path / "alerts.jsonl"

    assert runner.main([str(path), "--output", str(out), "--quiet"]) == 0
    classes = {a["threat_class"] for a in read_alerts(out)}
    assert expected.value in classes


def test_dga_reaches_the_output_with_a_model(tmp_path, dga_model_path):
    """Future-style dns.query plus a temp model produces dga_domain."""
    path = write(tmp_path, "dga.jsonl", dga_records())
    out = tmp_path / "alerts.jsonl"

    code = runner.main(
        [str(path), "--output", str(out), "--dga-model", str(dga_model_path), "--quiet"]
    )
    assert code == 0
    assert "dga_domain" in {a["threat_class"] for a in read_alerts(out)}


def test_the_same_run_can_raise_several_threat_classes(tmp_path, dga_model_path):
    """END TO END: one mixed capture, every detector registered."""
    records = (
        benign_records() + scan_records() + ddos_records() + c2_records()
        + dns_tunnel_records() + exfil_records() + tls_metadata_records()
        + dga_records()
    )
    path = write(tmp_path, "mixed.jsonl", records)
    out = tmp_path / "alerts.jsonl"

    code = runner.main(
        [str(path), "--output", str(out), "--dga-model", str(dga_model_path), "--quiet"]
    )
    assert code == 0

    classes = {a["threat_class"] for a in read_alerts(out)}
    assert {
        "port_scan", "ddos", "c2_beaconing", "dns_tunnelling",
        "data_exfiltration", "encrypted_malware", "dga_domain",
    } <= classes


# --------------------------------------------------------------------------
# 15-17. Serialization
# --------------------------------------------------------------------------


def test_alert_json_carries_the_whole_v11_contract(tmp_path):
    path = write(tmp_path, "scan.jsonl", scan_records())
    out = tmp_path / "alerts.jsonl"
    runner.main([str(path), "--output", str(out), "--quiet"])

    alert = read_alerts(out)[0]
    for field in (
        "schema_version", "alert_id", "event_start", "event_end", "detected_at",
        "event_scope", "flow_id", "src_ip", "dst_ip", "dst_port", "protocol",
        "threat_class", "severity", "score", "score_type", "evidence",
        "detector", "detector_version", "mitre_techniques", "incident_id",
    ):
        assert field in alert, f"missing {field}"
    assert alert["schema_version"] == "1.1"
    assert alert["event_start"].endswith("Z")
    assert alert["detected_at"].endswith("Z")


def test_enums_serialize_to_their_frozen_string_values(tmp_path):
    path = write(tmp_path, "scan.jsonl", scan_records())
    out = tmp_path / "alerts.jsonl"
    runner.main([str(path), "--output", str(out), "--quiet"])

    alert = read_alerts(out)[0]
    assert alert["threat_class"] == "port_scan"
    assert alert["event_scope"] == "source_host"
    assert alert["score_type"] == "rule_score"
    assert alert["severity"] in {"low", "medium", "high", "critical"}
    # Strings on the wire, never "ThreatClass.PORT_SCAN".
    assert all(
        isinstance(alert[k], str)
        for k in ("threat_class", "event_scope", "score_type", "severity")
    )


def test_intentional_nulls_survive_as_null(tmp_path):
    """An aggregate alert reports flow_id: null rather than inventing one."""
    path = write(tmp_path, "exfil.jsonl", exfil_records())
    out = tmp_path / "alerts.jsonl"
    runner.main([str(path), "--output", str(out), "--quiet"])

    alert = read_alerts(out)[0]
    assert alert["flow_id"] is None
    assert alert["incident_id"] is None


def test_sink_uses_the_models_own_serialization():
    """The schema is never re-described by the sink."""
    import io

    alert = make_alert()
    stream = io.StringIO()
    JsonlAlertSink(stream).emit(alert)

    assert json.loads(stream.getvalue()) == alert.to_wire()


# --------------------------------------------------------------------------
# 18-19. Output destinations
# --------------------------------------------------------------------------


def test_stdout_carries_only_alert_jsonl(tmp_path, capsys):
    """No log line may pollute stdout - it must stay pipeable."""
    path = write(tmp_path, "scan.jsonl", scan_records())

    assert runner.main([str(path)]) == 0

    captured = capsys.readouterr()
    lines = [line for line in captured.out.splitlines() if line]
    assert lines, "expected alerts on stdout"
    for line in lines:
        json.loads(line)  # every stdout line is a complete JSON object
    # The informational logging went somewhere else.
    assert "detectors:" in captured.err


def test_output_file_gets_one_alert_per_line(tmp_path):
    path = write(tmp_path, "scan.jsonl", scan_records())
    out = tmp_path / "alerts.jsonl"

    assert runner.main([str(path), "--output", str(out), "--quiet"]) == 0

    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines and all(json.loads(line)["schema_version"] == "1.1" for line in lines)


def test_unopenable_output_path_fails_clearly(tmp_path, capsys):
    path = write(tmp_path, "scan.jsonl", scan_records())
    unwritable = tmp_path / "no_such_dir" / "alerts.jsonl"

    assert runner.main([str(path), "--output", str(unwritable)]) == 1
    assert "could not open alert output" in capsys.readouterr().err


def test_missing_input_file_fails_clearly(tmp_path, capsys):
    assert runner.main([str(tmp_path / "nope.jsonl")]) == 1
    assert "input file not found" in capsys.readouterr().err


# --------------------------------------------------------------------------
# 20-21. HTTP sink
# --------------------------------------------------------------------------


class _Collector(BaseHTTPRequestHandler):
    received: list[dict] = []
    headers_seen: list[str] = []
    status = 202
    #: Reject this many of the next POSTs with 503, then behave normally.
    #: A rejected POST is deliberately NOT recorded in ``received``: the
    #: backend really did not accept that alert.
    fail_next = 0

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        if type(self).fail_next > 0:
            type(self).fail_next -= 1
            self.send_response(503)
            self.end_headers()
            return
        type(self).received.append(json.loads(body))
        type(self).headers_seen.append(self.headers.get("Content-Type", ""))
        self.send_response(type(self).status)
        self.end_headers()

    def log_message(self, *args):  # keep the test output quiet
        pass


@pytest.fixture
def backend():
    """A throwaway HTTP endpoint standing in for /api/v1/alerts."""
    _Collector.received = []
    _Collector.headers_seen = []
    _Collector.status = 202
    _Collector.fail_next = 0
    server = HTTPServer(("127.0.0.1", 0), _Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, f"http://127.0.0.1:{server.server_port}/api/v1/alerts"
    server.shutdown()
    server.server_close()


def test_http_sink_posts_the_exact_threat_alert_json(backend):
    _, url = backend
    alert = make_alert()

    HttpAlertSink(url, timeout=5.0).emit(alert)

    assert _Collector.received == [alert.to_wire()]
    assert _Collector.headers_seen == ["application/json"]


def test_runner_posts_alerts_to_the_api(tmp_path, backend):
    _, url = backend
    path = write(tmp_path, "scan.jsonl", scan_records())
    out = tmp_path / "alerts.jsonl"

    code = runner.main(
        [str(path), "--output", str(out), "--api-url", url, "--quiet"]
    )
    assert code == 0
    # Both destinations saw the same alerts.
    assert _Collector.received == read_alerts(out)


def test_backend_rejection_is_surfaced(backend):
    _, url = backend
    _Collector.status = 500

    with pytest.raises(AlertDeliveryError, match="rejected alert"):
        HttpAlertSink(url, timeout=5.0).emit(make_alert())


def test_unreachable_backend_is_surfaced():
    """A closed port must raise, never look like a successful delivery."""
    sink = HttpAlertSink("http://127.0.0.1:9/api/v1/alerts", timeout=1.0)

    with pytest.raises(AlertDeliveryError, match="could not reach"):
        sink.emit(make_alert())


def test_runner_reports_delivery_failure_without_ending_the_run(tmp_path, capsys):
    """A dead backend degrades the run; it must not abort it.

    This used to exit 1 on the first failed POST, leaving the rest of the
    capture unexamined - a delivery problem turned into a detection outage.
    """
    path = write(tmp_path, "scan.jsonl", scan_records())

    code = runner.main(
        [str(path), "--api-url", "http://127.0.0.1:9/api/v1/alerts",
         "--api-timeout", "1"]
    )

    captured = capsys.readouterr()
    assert code == runner.EXIT_DELIVERY_DEGRADED
    assert code != 0, "a run the backend never received must not look clean"
    assert "alert delivery failed, continuing" in captured.err
    assert "DEGRADED" in captured.err
    # The alert JSONL on stdout is still complete.
    assert [json.loads(line) for line in captured.out.splitlines() if line]


def test_multisink_fans_out(tmp_path, backend):
    import io

    _, url = backend
    stream = io.StringIO()
    alert = make_alert()

    MultiSink([JsonlAlertSink(stream), HttpAlertSink(url, timeout=5.0)]).emit(alert)

    assert json.loads(stream.getvalue()) == alert.to_wire()
    assert _Collector.received == [alert.to_wire()]


# --------------------------------------------------------------------------
# 22. Malformed input
# --------------------------------------------------------------------------


def test_malformed_records_are_skipped_without_losing_valid_ones(tmp_path, capsys):
    """A bad line must not corrupt the records around it."""
    lines = scan_records()
    corrupted = (
        lines[:10]
        + ["{not json at all", '{"src_ip": "10.0.0.1"}', "[]", ""]
        + lines[10:]
    )
    path = write(tmp_path, "mixed.jsonl", corrupted)
    out = tmp_path / "alerts.jsonl"

    assert runner.main([str(path), "--output", str(out)]) == 0
    # The scan still fires: the surviving records were processed normally.
    assert "port_scan" in {a["threat_class"] for a in read_alerts(out)}
    assert "skipped" in capsys.readouterr().err


def test_a_raising_detector_does_not_end_the_run(tmp_path):
    """Engine isolation still holds through the pipeline."""
    from .conftest import ExplodingDetector

    class Source:
        def __iter__(self):
            return iter([make_flow(timestamp=1000.0 + i) for i in range(5)])

    class NullSink:
        def emit(self, alert):
            pass

        def close(self):
            pass

    stats = run_detection(Source(), NullSink(), [ExplodingDetector()])

    assert stats.flows == 5
    assert stats.detector_errors > 0


def test_factory_covers_every_threat_class(dga_model_path):
    """Catches a detector added to the package but forgotten in the factory.

    Every detector's ``name`` matches its ThreatClass value, so with DGA
    supplied the factory should account for the whole frozen enum. If a new
    threat class or detector appears and is not wired in here, this fails.
    """
    names = {d.name for d in build_default_detectors(dga_model_path=dga_model_path)}
    assert names == {threat.value for threat in ThreatClass}



# --------------------------------------------------------------------------
# 23-30. Delivery resilience: a failing backend degrades, never aborts
# --------------------------------------------------------------------------


def flows(count: int) -> list:
    """``count`` flows, one canned alert each via DummyDetector."""
    return [make_flow(timestamp=1000.0 + i) for i in range(count)]


def test_a_rejected_delivery_is_counted_and_the_run_continues(backend):
    """HTTP 500 on every POST: all five flows are still processed."""
    _, url = backend
    _Collector.status = 500
    sink = HttpAlertSink(url, timeout=5.0)

    stats = run_detection(iter(flows(5)), sink, [DummyDetector()])

    assert stats.flows == 5, "the run stopped at the first rejection"
    assert stats.alerts == 5
    assert stats.delivery_failures == 5
    # Nothing is pretended delivered: the sink counts 2xx only.
    assert sink.count == 0


def test_an_unreachable_backend_is_counted_and_the_run_continues():
    """A closed port is the same story: counted, logged, run completes."""
    sink = HttpAlertSink("http://127.0.0.1:9/api/v1/alerts", timeout=1.0)

    stats = run_detection(iter(flows(2)), sink, [DummyDetector()])

    assert stats.flows == 2
    assert stats.alerts == 2
    assert stats.delivery_failures == 2


def test_a_later_alert_still_reaches_a_recovered_backend(backend):
    """Recovery needs no intervention - the next alert is simply POSTed."""
    _, url = backend
    _Collector.fail_next = 1

    stats = run_detection(
        iter(flows(3)), HttpAlertSink(url, timeout=5.0), [DummyDetector()]
    )

    assert stats.alerts == 3
    assert stats.delivery_failures == 1
    # The two after the failure genuinely arrived.
    assert len(_Collector.received) == 2


def test_a_failed_post_does_not_cost_the_local_record(backend):
    """JSONL keeps every alert even when the backend rejects all of them."""
    import io

    _, url = backend
    _Collector.status = 503
    stream = io.StringIO()
    jsonl = JsonlAlertSink(stream)
    sink = MultiSink([jsonl, HttpAlertSink(url, timeout=5.0)])

    stats = run_detection(iter(flows(3)), sink, [DummyDetector()])

    assert stats.delivery_failures == 3
    assert jsonl.count == 3
    assert len(stream.getvalue().strip().splitlines()) == 3


def test_sink_order_does_not_decide_which_sinks_are_served(backend):
    """HTTP first, JSONL second: the local sink must still get the alert.

    Fan-out used to stop at the first raising sink, so the local record
    silently depended on being listed before the network.
    """
    import io

    _, url = backend
    _Collector.status = 503
    stream = io.StringIO()
    jsonl = JsonlAlertSink(stream)
    sink = MultiSink([HttpAlertSink(url, timeout=5.0), jsonl])

    stats = run_detection(iter(flows(2)), sink, [DummyDetector()])

    assert stats.delivery_failures == 2
    assert jsonl.count == 2, "a failing HTTP sink starved the local sink"


def test_a_local_write_failure_still_stops_the_run():
    """Only *delivery* failures are absorbed. A broken output is not."""

    class BrokenSink:
        def emit(self, alert):
            raise OSError("disk full")

        def close(self):
            pass

    with pytest.raises(OSError, match="disk full"):
        run_detection(iter(flows(3)), BrokenSink(), [DummyDetector()])


def test_cli_processes_the_whole_capture_despite_delivery_failures(
    tmp_path, capsys, backend
):
    """END TO END: every record read, every alert local, exit degraded."""
    _, url = backend
    _Collector.status = 500
    path = write(tmp_path, "scan.jsonl", scan_records())
    out = tmp_path / "alerts.jsonl"

    code = runner.main([str(path), "--output", str(out), "--api-url", url])

    err = capsys.readouterr().err
    assert code == runner.EXIT_DELIVERY_DEGRADED
    # The whole input was consumed, not just up to the first bad POST.
    assert f"read {len(scan_records())} record(s)" in err
    assert "DEGRADED" in err

    # And the local file holds exactly what a run with no backend produces.
    plain = tmp_path / "plain.jsonl"
    assert runner.main([str(path), "--output", str(plain), "--quiet"]) == EXIT_OK_CODE
    degraded_classes = [a["threat_class"] for a in read_alerts(out)]
    assert degraded_classes, "expected alerts in the local record"
    assert degraded_classes == [a["threat_class"] for a in read_alerts(plain)]


def test_a_healthy_backend_still_exits_clean(tmp_path, backend):
    """No failures, no degradation: the normal path is untouched."""
    _, url = backend
    path = write(tmp_path, "scan.jsonl", scan_records())
    out = tmp_path / "alerts.jsonl"

    code = runner.main(
        [str(path), "--output", str(out), "--api-url", url, "--quiet"]
    )

    assert code == EXIT_OK_CODE
    assert _Collector.received == read_alerts(out)
