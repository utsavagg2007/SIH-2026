"""End-to-end API tests against the real app, with the in-memory store.

These exercise the paths that matter for the graded requirements:
ingest -> fusion -> live WebSocket -> durable store -> history API.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app

# Anchored just behind the real clock rather than at a fixed calendar date, so
# pipeline latency (event_end -> backend receipt) comes out positive the way it
# does with a live detector. A fixed date makes every latency assertion depend
# on what day the suite happens to run.
T0 = datetime.now(timezone.utc) - timedelta(seconds=30)


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def payload(
    *,
    alert_id: str = "aaaaaaaa-1111-4111-8111-111111111111",
    offset: float = 0.0,
    threat_class: str = "port_scan",
    scope: str = "source_host",
    src: str | None = "10.4.2.77",
    dst: str | None = None,
    port: int | None = None,
    severity: str = "high",
    score: float = 0.9,
    detector: str = "portscan_detector",
    evidence: dict | None = None,
    flow_id: str | None = None,
) -> dict:
    start = T0 + timedelta(seconds=offset)
    return {
        "alert_id": alert_id,
        "schema_version": "1.1",
        "event_start": iso(start),
        "event_end": iso(start + timedelta(seconds=2)),
        "detected_at": iso(start + timedelta(seconds=2.2)),
        "event_scope": scope,
        "flow_id": flow_id,
        "src_ip": src,
        "dst_ip": dst,
        "dst_port": port,
        "protocol": "tcp",
        "threat_class": threat_class,
        "severity": severity,
        "score": score,
        "score_type": "rule_score",
        "evidence": evidence
        or {"unique_dst_ports": 1024, "unique_dst_ips": 254, "syn_no_ack_ratio": 0.99},
        "detector": detector,
        "detector_version": "1.0.0",
        "mitre_techniques": ["T1046"],
        "incident_id": None,
    }


@pytest.fixture
def client():
    """A client with lifespan run, so bus/repo/hub exist."""
    with TestClient(app) as c:
        yield c


class TestIngest:
    def test_accepts_valid_alert(self, client):
        r = client.post("/api/v1/alerts", json=payload())
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "accepted"
        assert body["deduplicated"] is False
        assert body["occurrences"] == 1
        assert body["incident_id"].startswith("INC-")

    def test_rejects_invalid_schema_with_422(self, client):
        """Alert spec section 9: invalid schema -> 422."""
        r = client.post("/api/v1/alerts", json=payload(score=1.5))
        assert r.status_code == 422
        body = r.json()
        assert body["status"] == "rejected"
        assert body["schema_version"] == "1.1"
        assert any("score" in e["field"] for e in body["errors"])

    def test_rejects_unknown_top_level_field(self, client):
        bad = payload()
        bad["confidence"] = 0.9
        assert client.post("/api/v1/alerts", json=bad).status_code == 422

    def test_deduplicates_repeat_findings(self, client):
        for i in range(5):
            r = client.post(
                "/api/v1/alerts",
                json=payload(alert_id=f"dedup-{i}", offset=i * 10),
            )
        assert r.json()["deduplicated"] is True
        assert r.json()["occurrences"] == 5

    def test_bulk_ingest_is_partial(self, client):
        """One bad alert must not discard the good ones."""
        r = client.post(
            "/api/v1/alerts/bulk",
            json={
                "alerts": [
                    payload(alert_id="bulk-1", src="10.9.0.1"),
                    payload(alert_id="bulk-2", src="10.9.0.2", score=99),  # bad
                    payload(alert_id="bulk-3", src="10.9.0.3"),
                ]
            },
        )
        assert r.status_code == 202
        body = r.json()
        assert body["created"] == 2
        assert body["rejected"] == 1
        assert body["errors"][0]["index"] == 1
        assert body["errors"][0]["alert_id"] == "bulk-2"


class TestProjection:
    def test_view_carries_both_score_names(self, client):
        client.post("/api/v1/alerts", json=payload(alert_id="proj-1", src="10.20.0.1"))
        _wait_for_write(client, "proj-1")
        a = client.get("/api/v1/alerts/proj-1").json()
        assert a["score"] == a["confidence"] == 0.9
        assert a["score_type"] == "rule_score"

    def test_view_has_evidence_bars_and_raw_evidence(self, client):
        client.post("/api/v1/alerts", json=payload(alert_id="proj-2", src="10.20.0.2"))
        _wait_for_write(client, "proj-2")
        a = client.get("/api/v1/alerts/proj-2").json()
        bars = {e["feature"]: e for e in a["evidence"]}
        assert bars["unique_dst_ports"]["threshold"] == 100
        assert bars["unique_dst_ports"]["exceeded"] is True
        assert a["evidence_raw"]["unique_dst_ports"] == 1024

    def test_view_preserves_the_raw_v11_alert(self, client):
        sent = payload(alert_id="proj-3", src="10.20.0.3")
        client.post("/api/v1/alerts", json=sent)
        _wait_for_write(client, "proj-3")
        a = client.get("/api/v1/alerts/proj-3").json()
        assert a["raw"]["threat_class"] == sent["threat_class"]
        assert a["raw"]["severity"] == sent["severity"]

    def test_severity_is_passed_through_untouched(self, client):
        """Alert spec 4: the backend must not calculate severity."""
        client.post(
            "/api/v1/alerts",
            json=payload(alert_id="proj-4", src="10.20.0.4", severity="low", score=0.99),
        )
        _wait_for_write(client, "proj-4")
        assert client.get("/api/v1/alerts/proj-4").json()["severity"] == "low"

    def test_latency_fields_are_populated(self, client):
        client.post("/api/v1/alerts", json=payload(alert_id="proj-5", src="10.20.0.5"))
        _wait_for_write(client, "proj-5")
        a = client.get("/api/v1/alerts/proj-5").json()
        assert a["detector_latency_ms"] == pytest.approx(200.0, abs=1)
        assert a["pipeline_latency_ms"] > 0


class TestHistory:
    def test_filters(self, client):
        client.post("/api/v1/alerts", json=payload(alert_id="h-1", src="10.30.0.1"))
        client.post(
            "/api/v1/alerts",
            json=payload(
                alert_id="h-2",
                src=None,
                dst="10.30.9.9",
                port=80,
                scope="destination_host",
                threat_class="ddos",
                severity="critical",
                detector="ddos_detector",
                evidence={"flows_per_sec": 8400.0, "unique_sources": 5200},
            ),
        )
        _wait_for_write(client, "h-2")

        assert client.get("/api/v1/alerts?threat_class=ddos").json()["total"] >= 1
        assert client.get("/api/v1/alerts?severity=critical").json()["total"] >= 1
        assert client.get("/api/v1/alerts?src_ip=10.30.0.1").json()["total"] == 1
        # host matches either direction
        assert client.get("/api/v1/alerts?host=10.30.9.9").json()["total"] == 1

    def test_404_explains_the_async_write(self, client):
        r = client.get("/api/v1/alerts/does-not-exist")
        assert r.status_code == 404
        assert "asynchronously" in r.json()["detail"]


class TestIncidents:
    def test_kill_chain_incident(self, client):
        host = "10.40.0.19"
        client.post(
            "/api/v1/alerts",
            json=payload(alert_id="k-1", src=host, threat_class="port_scan"),
        )
        client.post(
            "/api/v1/alerts",
            json=payload(
                alert_id="k-2",
                offset=300,
                src=host,
                dst="185.62.11.4",
                port=443,
                scope="host_pair",
                threat_class="c2_beaconing",
                detector="beacon_periodicity",
                evidence={"interval_cv": 0.04, "connection_count": 42},
            ),
        )
        r = client.post(
            "/api/v1/alerts",
            json=payload(
                alert_id="k-3",
                offset=900,
                src=host,
                dst="198.51.100.14",
                port=443,
                scope="host_pair",
                threat_class="data_exfiltration",
                detector="exfil_anomaly",
                evidence={"outbound_bytes": 512000000, "out_in_byte_ratio": 47.3},
            ),
        )
        incident_id = r.json()["incident_id"]

        detail = client.get(f"/api/v1/incidents/{incident_id}").json()
        inc = detail["incident"]
        assert inc["pivot_host"] == host
        assert inc["alert_count"] == 3
        assert inc["stages"] == ["recon", "c2", "exfil"]
        assert inc["escalated"] is True
        assert inc["severity"] == "critical"  # high, escalated on stage count
        assert "port scanning" in inc["narrative"]

    def test_incident_list(self, client):
        client.post("/api/v1/alerts", json=payload(alert_id="il-1", src="10.41.0.1"))
        assert client.get("/api/v1/incidents").json()["total"] >= 1


class TestHosts:
    def test_host_view(self, client):
        host = "10.50.0.5"
        client.post("/api/v1/alerts", json=payload(alert_id="hv-1", src=host))
        _wait_for_write(client, "hv-1")
        h = client.get(f"/api/v1/hosts/{host}").json()
        assert h["ip"] == host
        assert h["alert_count"] >= 1
        assert h["severity_counts"]["high"] >= 1
        assert h["threat_class_counts"]["port_scan"] >= 1

    def test_unknown_host_404s(self, client):
        assert client.get("/api/v1/hosts/192.0.2.99").status_code == 404


class TestSystem:
    def test_health(self, client):
        h = client.get("/api/v1/system/health").json()
        assert h["schema_version"] == "1.1"
        assert h["storage_backend"] in {"memory", "postgres"}

    def test_detector_status_tracks_ingest(self, client):
        client.post("/api/v1/alerts", json=payload(alert_id="ds-1", src="10.60.0.1"))
        d = client.get("/api/v1/system/detectors").json()
        names = {x["detector"] for x in d["items"]}
        assert "portscan_detector" in names
        assert all(x["state"] in {"online", "degraded", "unseen"} for x in d["items"])

    def test_constraint_proof(self, client):
        c = client.get("/api/v1/system/constraints").json()
        assert c["ingest_direction"] == "inbound_only"
        assert c["payload_decryption"] == "never"
        assert c["egress_blocked"] is True
        assert c["outbound_attempts"] == 0
        assert c["write_routes_toward_network"] == 0
        assert len(c["notes"]) >= 3

    def test_throughput_separates_measured_from_reported(self, client):
        t = client.get("/api/v1/system/throughput").json()
        # No telemetry posted yet, so traffic figures must read as not live
        # rather than as a confident zero.
        assert t["traffic_telemetry_live"] is False
        assert "event_end" in t["latency_definition"]

    def test_telemetry_feeds_the_throughput_panel(self, client):
        client.post(
            "/api/v1/telemetry",
            json={
                "flows_per_sec": 3412,
                "packets_per_sec": 41200,
                "mbps": 284.1,
                "detectors_online": 8,
                "detectors_total": 8,
                "source": "replay",
            },
        )
        t = client.get("/api/v1/system/throughput").json()
        assert t["traffic_telemetry_live"] is True
        assert t["traffic_flows_per_sec"] == 3412
        assert t["traffic_source"] == "replay"


class TestLiveFeed:
    def test_websocket_receives_snapshot_then_alerts(self, client):
        with client.websocket_connect("/ws/alerts") as ws:
            first = ws.receive_json()
            assert first["type"] == "snapshot"
            assert first["data"]["schema_version"] == "1.1"

            status = ws.receive_json()
            assert status["type"] == "system.status"

            client.post(
                "/api/v1/alerts", json=payload(alert_id="ws-1", src="10.70.0.1")
            )

            frames = [ws.receive_json() for _ in range(2)]
            kinds = {f["type"] for f in frames}
            assert "alert.created" in kinds
            assert "incident.created" in kinds

            alert_frame = next(f for f in frames if f["type"] == "alert.created")
            data = alert_frame["data"]
            assert data["alert_id"] == "ws-1"
            assert data["threat_code"] == "PS"
            assert data["kill_chain_stage"] == "recon"
            assert isinstance(data["evidence"], list)

    def test_repeat_arrives_as_alert_updated(self, client):
        with client.websocket_connect("/ws/alerts") as ws:
            ws.receive_json()  # snapshot
            ws.receive_json()  # system.status

            client.post(
                "/api/v1/alerts", json=payload(alert_id="wu-1", src="10.71.0.1")
            )
            client.post(
                "/api/v1/alerts",
                json=payload(alert_id="wu-2", src="10.71.0.1", offset=30),
            )

            types = []
            for _ in range(4):
                types.append(ws.receive_json()["type"])
            assert "alert.updated" in types

    def test_frames_are_strict_json(self, client):
        """No NaN/Infinity tokens: JSON.parse would reject the whole frame."""
        with client.websocket_connect("/ws/alerts") as ws:
            ws.receive_json()
            ws.receive_json()
            client.post(
                "/api/v1/alerts",
                json=payload(
                    alert_id="nan-1",
                    src="10.72.0.1",
                    dst="198.51.100.14",
                    port=443,
                    scope="host_pair",
                    threat_class="data_exfiltration",
                    detector="exfil_anomaly",
                    evidence={"outbound_bytes": 5120000, "inbound_bytes": 0},
                ),
            )
            raw = ws.receive_text()
            assert "NaN" not in raw and "Infinity" not in raw
            json.loads(raw)  # must parse strictly


class TestReplay:
    def test_lists_captures_with_manifests(self, client):
        items = client.get("/api/v1/replay/captures").json()["items"]
        names = {i["capture"] for i in items}
        assert "demo_scenario.jsonl" in names
        demo = next(i for i in items if i["capture"] == "demo_scenario.jsonl")
        assert demo["scenario"]["ground_truth"]

    def test_rejects_path_traversal(self, client):
        r = client.post(
            "/api/v1/replay/start",
            json={"capture": "../app/main.py", "speed": 1.0},
        )
        assert r.status_code == 404

    def test_start_and_stop(self, client):
        r = client.post(
            "/api/v1/replay/start",
            json={"capture": "demo_scenario.jsonl", "speed": 500.0},
        )
        assert r.status_code == 200
        assert r.json()["running"] is True
        assert r.json()["total"] == 12
        client.post("/api/v1/replay/stop")
        assert client.get("/api/v1/replay/status").json()["running"] is False


def _wait_for_write(client, alert_id: str, timeout_s: float = 5.0) -> None:
    """Wait for the write-behind batch to land.

    The durable path is deliberately asynchronous - that is the requirement, not
    a defect - so history assertions have to wait for it.  The bus flushes on a
    timer (``db_batch_interval_s``, 0.5s by default), and TestClient runs the
    app's event loop on its own thread, so a real sleep here is what lets that
    timer fire.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if client.get(f"/api/v1/alerts/{alert_id}").status_code == 200:
            return
        time.sleep(0.05)
    raise AssertionError(
        f"{alert_id} never reached storage within {timeout_s}s"
    )
