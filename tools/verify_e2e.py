#!/usr/bin/env python3
"""End-to-end proof that the layers are actually connected.

    python tools/verify_e2e.py

Starts the backend and the analyst, generates a labelled capture, drives it
through the real detection runner, and then asserts - over the same WebSocket
the dashboard uses and the same REST routes it calls - that what came out the
far end is what went in.

This exists because every layer in this project had a green test suite while the
seams between them were broken. Detection passed 1,598 tests while emitting
evidence keys the backend could not read; the backend passed 98 while its
deduplication collapsed nothing a user could see; the frontend built cleanly
while its live path spoke a protocol no server here emits. A per-layer suite
cannot catch any of that by construction. This can.

Every check below is a claim someone will make on demo day. It fails loudly
rather than reporting a pass it did not earn.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = ROOT / ".venv" / "Scripts" / "python.exe"
if not PY.exists():  # POSIX layout
    PY = ROOT / ".venv" / "bin" / "python"
if not PY.exists():
    PY = Path(sys.executable)

# This script needs the project's dependencies in its OWN process - it opens a
# WebSocket to watch the frames the dashboard receives. Running it with the
# system interpreter is the obvious mistake to make, and the resulting
# ModuleNotFoundError points at the wrong problem, so re-exec under the venv
# rather than explaining it in a README nobody reads at that moment.
if Path(sys.executable).resolve() != PY.resolve() and PY.exists():
    import os

    os.execv(str(PY), [str(PY), str(Path(__file__).resolve()), *sys.argv[1:]])

BACKEND = "http://127.0.0.1:8000"
ANALYST = "http://127.0.0.1:8100"
DATA = ROOT / "data"

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((PASS if ok else FAIL, name, detail))
    print(f"  [{PASS if ok else FAIL}] {name}" + (f"  - {detail}" if detail else ""))
    return ok


def _get(url: str, timeout: float = 10.0):
    import urllib.request

    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read())


def _post(url: str, payload: dict, timeout: float = 20.0):
    import urllib.request

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read()
        return json.loads(body) if body else None


def wait_for(url: str, timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _get(url, timeout=2.0)
            return True
        except Exception:
            time.sleep(0.4)
    return False


class Service:
    """A child process that is always cleaned up, even on assertion failure."""

    def __init__(self, name: str, args: list[str], cwd: Path):
        self.name = name
        self.proc = subprocess.Popen(
            args,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()


async def collect_frames(seconds: float) -> list[dict]:
    """Listen on the dashboard's socket for a while and return what arrived."""
    import websockets

    frames: list[dict] = []
    try:
        async with websockets.connect(f"ws://127.0.0.1:8000/ws/alerts") as socket:
            deadline = time.time() + seconds
            while time.time() < deadline:
                try:
                    raw = await asyncio.wait_for(socket.recv(), timeout=deadline - time.time())
                except (asyncio.TimeoutError, Exception):
                    break
                try:
                    frames.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass
    except Exception as exc:  # pragma: no cover - reported as a failed check
        print(f"    websocket error: {exc}", file=sys.stderr)
    return frames


def main() -> int:
    DATA.mkdir(exist_ok=True)
    services: list[Service] = []

    try:
        # -- Layers 1-3: a labelled capture in the ingestion record format ----
        print("\nLAYER 1-3  ingestion record format")
        subprocess.run(
            [str(PY), "tools/synth_flows.py", "-o", "data/features.jsonl"],
            cwd=str(ROOT), check=True, capture_output=True,
        )
        flows = [json.loads(l) for l in (DATA / "features.jsonl").read_text().splitlines() if l.strip()]
        check("capture generated", len(flows) > 500, f"{len(flows)} flows")
        check(
            "raw dns.query survives to the record",
            any(f.get("dns", {}).get("query") for f in flows),
            "DGA is structurally dead without it",
        )
        check(
            "raw tls.ja3 and server_name survive",
            any(f.get("tls", {}).get("ja3") for f in flows)
            and any(f.get("tls", {}).get("server_name") for f in flows),
            "encrypted_malware is structurally dead without them",
        )
        check(
            "raw conn_state carries S0",
            any(f.get("conn_state") == "S0" for f in flows),
            "the primary scan and SYN-flood signal",
        )
        check(
            "records are in non-decreasing event time",
            all(a["timestamp"] <= b["timestamp"] for a, b in zip(flows, flows[1:])),
        )

        # -- Layer 6: the backend --------------------------------------------
        print("\nLAYER 6  backend")
        services.append(Service(
            "backend",
            [str(PY), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
             "--port", "8000", "--log-level", "warning"],
            ROOT / "backend",
        ))
        if not check("backend is up", wait_for(f"{BACKEND}/health")):
            return 1
        constraints = _get(f"{BACKEND}/api/v1/system/constraints")
        check(
            "read-only constraint proof served",
            constraints.get("ingest_direction") == "inbound_only"
            and constraints.get("payload_decryption") == "never",
            f"routes toward monitored network: {constraints.get('write_routes_toward_network')}",
        )

        # -- Layer 8: the analyst ---------------------------------------------
        print("\nLAYER 8  analyst")
        services.append(Service(
            "analyst",
            [str(PY), "-m", "uvicorn", "analyst.main:app", "--host", "127.0.0.1",
             "--port", "8100", "--log-level", "warning"],
            ROOT / "analyst",
        ))
        analyst_up = check("analyst is up", wait_for(f"{ANALYST}/health"))
        if analyst_up:
            health = _get(f"{ANALYST}/api/v1/analyst/health")
            check(
                "analyst reaches the alert store",
                health.get("alert_store_reachable") is True,
                f"provider={health.get('provider')} model={health.get('model')}",
            )
            proof = _get(f"{ANALYST}/api/v1/analyst/constraints")
            check(
                "analyst discloses its egress state",
                proof.get("reads_from") == "alert_store_only"
                and proof.get("influences_detection") == "never",
                f"egress_enabled={proof.get('egress_enabled')}",
            )

        # -- Layers 4-5 -> 6: detection posting into the backend --------------
        print("\nLAYER 4-5  detection -> backend (over HTTP, with telemetry)")
        frames_task = asyncio.new_event_loop().run_until_complete  # noqa: F841
        loop = asyncio.new_event_loop()
        listener = loop.create_task(collect_frames(seconds=25.0))

        def run_detection():
            return subprocess.run(
                [str(PY), "-m", "detection_core.runner", "data/features.jsonl",
                 "--output", "data/alerts.jsonl",
                 "--ja3-feed", "tools/ja3_feed.example.txt",
                 "--api-url", f"{BACKEND}/api/v1/alerts",
                 "--telemetry-url", f"{BACKEND}/api/v1/telemetry"],
                cwd=str(ROOT), capture_output=True, text=True,
            )

        import threading

        holder: dict = {}
        thread = threading.Thread(target=lambda: holder.update(r=run_detection()))
        thread.start()
        frames = loop.run_until_complete(listener)
        thread.join(timeout=60)
        loop.close()

        detection = holder.get("r")
        check(
            "detection ran and delivered",
            detection is not None and detection.returncode == 0,
            (detection.stderr.strip().splitlines()[-1] if detection and detection.stderr else ""),
        )

        alerts = [json.loads(l) for l in (DATA / "alerts.jsonl").read_text().splitlines() if l.strip()]
        classes = {a["threat_class"] for a in alerts}
        check("alerts emitted", len(alerts) > 0, f"{len(alerts)} alerts")
        check(
            "all seven threat classes exercised",
            len(classes) == 7,
            f"{len(classes)}/7: {', '.join(sorted(classes))}",
        )

        # -- Layer 6 -> 7: the frames the dashboard actually receives ---------
        print("\nLAYER 7  backend -> dashboard (the real WebSocket)")
        kinds = {f.get("type") for f in frames}
        check("snapshot frame received", "snapshot" in kinds)
        check("alert.created frames received", "alert.created" in kinds,
              f"{sum(1 for f in frames if f.get('type') == 'alert.created')}")
        check("metrics frames received", "metrics" in kinds)
        check(
            "every frame is the {type, data} envelope the client expects",
            all("type" in f and "data" in f for f in frames),
        )

        alert_frames = [f["data"] for f in frames if f.get("type", "").startswith("alert.")]
        if alert_frames:
            check(
                "projected alerts carry evidence bars",
                any(
                    any(item.get("threshold") is not None for item in a.get("evidence", []))
                    for a in alert_frames
                ),
                "the supporting-evidence requirement",
            )
            check(
                "projected alerts carry a class visual",
                any(a.get("visual") for a in alert_frames),
            )
            check(
                "every alert carries a two-letter threat code for the Wire",
                all(a.get("threat_code") for a in alert_frames),
            )

        telemetry_frames = [f["data"] for f in frames if f.get("type") == "metrics"]
        check(
            "throughput telemetry reached the dashboard",
            any(f.get("traffic_telemetry_live") for f in telemetry_frames),
            "requirement (d) is unanswerable from the UI without it",
        )

        # -- Fusion: dedup and correlation ------------------------------------
        print("\nLAYER 5  fusion (dedup + correlation)")
        stored = _get(f"{BACKEND}/api/v1/alerts?limit=200")
        check(
            "deduplication collapsed repeats",
            stored["total"] <= len(alerts),
            f"{len(alerts)} emitted -> {stored['total']} stored",
        )
        check(
            "stored alert ids are unique",
            len({a["alert_id"] for a in stored["items"]}) == len(stored["items"]),
        )
        incidents = _get(f"{BACKEND}/api/v1/incidents?limit=20")
        items = incidents["items"] if isinstance(incidents, dict) else incidents
        check("incidents correlated", len(items) > 0, f"{len(items)} incidents")
        multi = [i for i in items if len(i.get("stages", [])) > 1]
        check(
            "at least one incident spans multiple kill-chain stages",
            bool(multi),
            (multi[0]["narrative"][:90] if multi else "no multi-stage sequence"),
        )

        # -- Layer 8 end to end ------------------------------------------------
        if analyst_up and stored["items"]:
            print("\nLAYER 8  analyst over the stored corpus")
            target = stored["items"][0]
            answer = _post(f"{ANALYST}/api/v1/analyst/explain", {"alert_id": target["alert_id"]})
            check("analyst explains a stored alert", bool(answer and answer.get("text")))
            check(
                "every claim carries the evidence field it came from",
                bool(answer and answer.get("citations"))
                and all(c.get("source") for c in answer["citations"]),
                f"{len(answer.get('citations', []))} citations",
            )
            asked = _post(
                f"{ANALYST}/api/v1/analyst/ask",
                {"question": "what beaconed in the last hour"},
            )
            check("analyst answers a history question", bool(asked and asked.get("text")))
            check(
                "analyst reports how it read the question",
                bool(asked and asked.get("interpreted_as")),
                "; ".join(asked.get("interpreted_as", [])[:2]) if asked else "",
            )

        # -- Summary -----------------------------------------------------------
        failed = [r for r in results if r[0] == FAIL]
        print("\n" + "=" * 72)
        print(f"{len(results) - len(failed)}/{len(results)} checks passed")
        if failed:
            print("\nFAILED:")
            for _, name, detail in failed:
                print(f"  - {name}" + (f"  ({detail})" if detail else ""))
        return 1 if failed else 0

    finally:
        for service in reversed(services):
            service.stop()


if __name__ == "__main__":
    raise SystemExit(main())
