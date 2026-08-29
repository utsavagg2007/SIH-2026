"""End-to-end smoke test against a running server.

Walks the whole path a demo takes: replay a capture, watch alerts arrive on the
WebSocket, confirm deduplication and correlation happened, and read back every
REST surface the dashboard uses.

Run the server first, then::

    python tools/smoke.py
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections import Counter
from typing import Any

import httpx
import websockets

PASS = "  [ok]  "
FAIL = "  [XX]  "


class Checks:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def check(self, ok: bool, label: str, detail: str = "") -> bool:
        if ok:
            self.passed += 1
            print(f"{PASS}{label}{(' - ' + detail) if detail else ''}")
        else:
            self.failed += 1
            print(f"{FAIL}{label}{(' - ' + detail) if detail else ''}")
        return ok


async def collect_ws(url: str, seconds: float, sink: list[dict[str, Any]]) -> None:
    try:
        async with websockets.connect(url, max_size=8 * 1024 * 1024) as ws:
            try:
                await asyncio.wait_for(_drain(ws, sink), timeout=seconds)
            except asyncio.TimeoutError:
                pass
    except Exception as exc:  # noqa: BLE001
        print(f"{FAIL}websocket connect failed: {exc}")


async def _drain(ws, sink: list[dict[str, Any]]) -> None:
    async for raw in ws:
        # Strict parse: a NaN or Infinity token anywhere would raise here, which
        # is exactly the failure the dashboard would hit.
        sink.append(json.loads(raw))


async def main(base: str) -> int:
    c = Checks()
    ws_url = base.replace("http://", "ws://").replace("https://", "wss://") + "/ws/alerts"

    async with httpx.AsyncClient(base_url=base, timeout=30.0) as http:
        print("\n=== service ===")
        root = (await http.get("/")).json()
        c.check(root["alert_schema_version"] == "1.1", "alert schema is v1.1")

        print("\n=== read-only constraint proof ===")
        con = (await http.get("/api/v1/system/constraints")).json()
        c.check(con["ingest_direction"] == "inbound_only", "ingest is inbound only")
        c.check(con["payload_decryption"] == "never", "no payload decryption")
        c.check(con["egress_blocked"] is True, "no egress toward monitored network")
        c.check(
            con["outbound_attempts"] == 0,
            "zero outbound attempts",
            f"{con['outbound_attempts']} recorded",
        )

        print("\n=== schema enforcement ===")
        bad = (
            await http.post("/api/v1/alerts", json={"alert_id": "x", "score": 5})
        )
        c.check(bad.status_code == 422, "malformed alert rejected with 422")
        c.check(
            bad.json().get("schema_version") == "1.1",
            "422 body names the schema version",
        )

        print("\n=== replay -> live feed ===")
        await http.post("/api/v1/replay/stop")
        frames: list[dict[str, Any]] = []
        listener = asyncio.create_task(collect_ws(ws_url, 14.0, frames))
        await asyncio.sleep(1.0)

        start = await http.post(
            "/api/v1/replay/start",
            json={"capture": "demo_scenario.jsonl", "speed": 90.0},
        )
        c.check(start.status_code == 200, "replay started", start.text[:120])
        await listener
        await http.post("/api/v1/replay/stop")

        kinds = Counter(f["type"] for f in frames)
        print(f"         frames: {dict(kinds)}")
        c.check(kinds["snapshot"] >= 1, "snapshot frame on connect")
        # Count created and updated together. On a repeat run against a
        # long-lived server the dedup window from the previous run is still
        # open, so the same capture legitimately arrives as alert.updated - that
        # is the fusion layer working, not a missing alert.
        streamed = kinds["alert.created"] + kinds["alert.updated"]
        c.check(streamed >= 10, "alerts streamed live",
                f"{kinds['alert.created']} created, {kinds['alert.updated']} updated")
        c.check(
            kinds["incident.created"] + kinds["incident.updated"] >= 1,
            "incidents correlated live",
        )
        c.check(kinds["metrics"] >= 3, "metrics frame at ~1Hz",
                f"{kinds['metrics']} frames")

        alerts = [
            f["data"]
            for f in frames
            if f["type"] in ("alert.created", "alert.updated")
        ]
        classes = {a["threat_class"] for a in alerts}
        print(f"         classes: {sorted(classes)}")
        c.check(len(classes) >= 6, "multiple threat classes seen",
                f"{len(classes)} of 7")

        print("\n=== projection ===")
        if alerts:
            a = alerts[0]
            c.check(isinstance(a["evidence"], list), "evidence projected to bars")
            c.check(isinstance(a["evidence_raw"], dict), "raw evidence preserved")
            c.check(bool(a["raw"]), "original v1.1 alert preserved")
            c.check(len(a["threat_code"]) == 2, "two-letter threat code present")
            c.check("pipeline_latency_ms" in a, "packet-to-alert latency stamped")
            barred = [e for e in a["evidence"] if e.get("threshold") is not None]
            c.check(bool(barred), "at least one thresholded evidence bar")

        with_visual = [a for a in alerts if a.get("visual")]
        vkinds = {a["visual"]["kind"] for a in with_visual}
        print(f"         visuals: {sorted(vkinds)}")
        c.check(len(vkinds) >= 4, "class-specific visuals built",
                f"{len(vkinds)} kinds")
        observed = [
            a for a in with_visual if a["visual"].get("source") == "observed"
        ]
        c.check(
            bool(observed),
            "some visuals built from observed series (not reconstructed)",
            f"{len(observed)}/{len(with_visual)}",
        )

        print("\n=== fusion ===")
        inc = (await http.get("/api/v1/incidents")).json()
        c.check(inc["total"] >= 1, "incidents available over REST",
                f"{inc['total']} open")
        multi = [i for i in inc["items"] if len(i["stages"]) >= 2]
        if c.check(bool(multi), "an incident spans multiple kill-chain stages"):
            target = max(multi, key=lambda i: len(i["stages"]))
            print(f"         {target['narrative']}")
            c.check(target["escalated"] is True, "multi-stage incident escalated")
            detail = (await http.get(f"/api/v1/incidents/{target['incident_id']}")).json()
            c.check(
                len(detail["alerts"]) >= 1,
                "incident detail carries member alerts",
                f"{len(detail['alerts'])} alerts",
            )

        print("\n=== dedup (beacon_hour: 60 check-ins) ===")
        before = (await http.get("/api/v1/system/health")).json()
        # 3600s of content at 1000x (the API's speed ceiling) replays in ~3.6s.
        started = await http.post(
            "/api/v1/replay/start",
            json={"capture": "beacon_hour.jsonl", "speed": 1000.0},
        )
        # Check the start explicitly: a rejected replay would otherwise show up
        # below as a confusing "0 of 0 deduplicated" rather than as its own
        # failure.
        c.check(started.status_code == 200, "beacon replay started",
                started.text[:160])
        for _ in range(30):
            await asyncio.sleep(0.5)
            if not (await http.get("/api/v1/replay/status")).json()["running"]:
                break
        await http.post("/api/v1/replay/stop")
        # Let the last publishes settle before reading the counters.
        await asyncio.sleep(0.5)
        after = (await http.get("/api/v1/system/health")).json()
        deduped = after["alerts_deduplicated"] - before["alerts_deduplicated"]
        total = after["alerts_total"] - before["alerts_total"]
        c.check(
            total >= 55,
            "all 60 beacon check-ins ingested",
            f"{total} publishes",
        )
        c.check(
            total > 0 and deduped >= total * 0.9,
            "repeat beacons folded into one alert",
            f"{deduped} of {total} deduplicated",
        )

        print("\n=== history API ===")
        page = (await http.get("/api/v1/alerts?limit=5")).json()
        c.check(page["total"] > 0, "alerts queryable", f"{page['total']} stored")
        c.check(len(page["items"]) <= 5, "limit respected")
        filt = (await http.get("/api/v1/alerts?threat_class=c2_beaconing")).json()
        c.check(filt["total"] > 0, "threat_class filter works")
        if page["items"]:
            one = page["items"][0]
            got = await http.get(f"/api/v1/alerts/{one['alert_id']}")
            c.check(got.status_code == 200, "single alert lookup")

        hosts = (await http.get("/api/v1/hosts")).json()
        c.check(hosts["total"] > 0, "hosts enumerated", f"{hosts['total']} hosts")
        if hosts["items"]:
            hv = (await http.get(f"/api/v1/hosts/{hosts['items'][0]}")).json()
            c.check(hv["alert_count"] > 0, "host view populated",
                    f"{hosts['items'][0]}: {hv['alert_count']} alerts")

        print("\n=== throughput / requirement (d) ===")
        tp = (await http.get("/api/v1/system/throughput")).json()
        c.check(tp["alerts_total"] > 0, "alerts counted",
                f"{tp['alerts_total']} total")
        c.check(
            tp["traffic_telemetry_live"] is False,
            "traffic figures reported as not-live without telemetry",
        )
        await http.post(
            "/api/v1/telemetry",
            json={"flows_per_sec": 3412, "packets_per_sec": 41200, "mbps": 284.1,
                  "detectors_online": 8, "detectors_total": 8, "source": "replay"},
        )
        tp2 = (await http.get("/api/v1/system/throughput")).json()
        c.check(tp2["traffic_telemetry_live"] is True, "telemetry accepted")
        c.check(tp2["traffic_flows_per_sec"] == 3412, "flows/sec reported")

        det = (await http.get("/api/v1/system/detectors")).json()
        c.check(det["total"] >= 5, "detector status tracked",
                f"{det['total']} detectors seen")

        health = (await http.get("/api/v1/system/health")).json()
        print(
            f"         storage={health['storage_backend']} "
            f"queue={health['storage_queue_depth']} "
            f"shed={health['storage_writes_shed']} "
            f"errors={health['storage_write_errors']}"
        )
        c.check(health["storage_write_errors"] == 0, "no storage write errors")

    print("\n" + "=" * 64)
    print(f"  {c.passed} passed, {c.failed} failed")
    print("=" * 64)
    return 1 if c.failed else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    raise SystemExit(asyncio.run(main(ap.parse_args().url)))
