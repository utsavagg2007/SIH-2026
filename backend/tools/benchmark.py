"""Throughput and latency harness.

Requirement (d) asks for a stated, *demonstrated* traffic rate.  Build Plan
layer 9 is blunt about what that means: "the throughput figure is a number you
measured rather than one you estimated."

This measures the **backend** stage of the pipeline: how many v1.1 alerts per
second it can ingest, fuse, fan out and queue for durable storage, and the
latency distribution from the alert's ``event_end`` to it leaving on the
WebSocket.  It does not measure Zeek, feature extraction, or model inference -
those live upstream and have their own harness.  Reporting the backend number as
if it were the whole pipeline's would be dishonest, so the output labels it.

Usage::

    # terminal 1
    uvicorn app.main:app

    # terminal 2
    python tools/benchmark.py --rate 500 --duration 30
    python tools/benchmark.py --ramp            # find the saturation point
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def load_templates(capture: str = "flood.jsonl") -> list[dict[str, Any]]:
    path = FIXTURES / capture
    if not path.exists():
        raise SystemExit(
            f"{path} not found. Run: python tools/make_fixtures.py"
        )
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def stamp(template: dict[str, Any], now: datetime) -> dict[str, Any]:
    """Rewrite a template onto the current clock with a fresh id."""
    alert = dict(template)
    start = now - timedelta(seconds=1.0)
    alert["event_start"] = start.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    alert["event_end"] = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    alert["detected_at"] = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    alert["alert_id"] = str(uuid.uuid4())
    alert["incident_id"] = None
    return alert


async def run_phase(
    client: httpx.AsyncClient,
    base_url: str,
    templates: list[dict[str, Any]],
    rate: float,
    duration: float,
    batch_size: int,
    concurrency: int,
) -> dict[str, Any]:
    """Drive one constant-rate phase and measure what came back."""
    sent = accepted = rejected = failed = 0
    rtts: list[float] = []
    sem = asyncio.Semaphore(concurrency)
    start = time.perf_counter()
    deadline = start + duration
    idx = 0
    inflight: list[asyncio.Task] = []

    async def post(batch: list[dict[str, Any]]) -> None:
        nonlocal accepted, rejected, failed
        async with sem:
            t0 = time.perf_counter()
            try:
                r = await client.post(
                    f"{base_url}/api/v1/alerts/bulk", json={"alerts": batch}
                )
                rtts.append((time.perf_counter() - t0) * 1000.0)
                if r.status_code == 202:
                    body = r.json()
                    accepted += body["accepted"]
                    rejected += body["rejected"]
                else:
                    failed += len(batch)
            except (httpx.HTTPError, asyncio.TimeoutError):
                failed += len(batch)

    interval = batch_size / rate if rate > 0 else 0.0
    next_send = start

    while time.perf_counter() < deadline:
        now_wall = datetime.now(timezone.utc)
        batch = [
            stamp(templates[(idx + i) % len(templates)], now_wall)
            for i in range(batch_size)
        ]
        idx += batch_size
        sent += batch_size
        inflight.append(asyncio.create_task(post(batch)))

        # Reap finished tasks so the list does not grow without bound during a
        # long run.
        if len(inflight) > concurrency * 4:
            done = [t for t in inflight if t.done()]
            for t in done:
                inflight.remove(t)

        next_send += interval
        sleep = next_send - time.perf_counter()
        if sleep > 0:
            await asyncio.sleep(sleep)
        else:
            # Cannot keep up with the requested rate: yield and carry on, and
            # the measured rate below will show the shortfall honestly.
            await asyncio.sleep(0)

    await asyncio.gather(*inflight, return_exceptions=True)
    elapsed = time.perf_counter() - start

    # Give the write-behind queue a moment, then read the backend's own view.
    await asyncio.sleep(1.0)
    try:
        # Scope the percentiles to this phase. The server keeps a 60s
        # rolling window; reading it raw after a 12s phase reports the
        # previous phase's saturation, not this one's.
        tp = (
            await client.get(
                f"{base_url}/api/v1/system/throughput",
                params={"window_s": round(elapsed + 2.0, 1)},
            )
        ).json()
        health = (await client.get(f"{base_url}/api/v1/system/health")).json()
    except httpx.HTTPError:
        tp, health = {}, {}

    return {
        "requested_rate": rate,
        "duration_s": round(elapsed, 2),
        "sent": sent,
        "accepted": accepted,
        "rejected": rejected,
        "failed": failed,
        "achieved_rate": round(sent / elapsed, 1) if elapsed else 0.0,
        "accepted_rate": round(accepted / elapsed, 1) if elapsed else 0.0,
        "http_rtt_p50_ms": round(statistics.median(rtts), 2) if rtts else None,
        "http_rtt_p95_ms": (
            round(sorted(rtts)[int(len(rtts) * 0.95)], 2) if len(rtts) > 20 else None
        ),
        "backend_latency_p50_ms": tp.get("latency_p50_ms"),
        "backend_latency_p95_ms": tp.get("latency_p95_ms"),
        "backend_latency_max_ms": tp.get("latency_max_ms"),
        "backend_peak_alerts_per_sec": tp.get("alerts_peak_per_sec"),
        "backend_alerts_total": tp.get("alerts_total"),
        "backend_deduplicated": tp.get("alerts_deduplicated"),
        "storage_queue_depth": health.get("storage_queue_depth"),
        "storage_writes_shed": health.get("storage_writes_shed"),
        "storage_backend": health.get("storage_backend"),
    }


def print_phase(r: dict[str, Any]) -> None:
    shed = r.get("storage_writes_shed") or 0
    flag = "  <-- shedding writes" if shed else ""
    print(
        f"  {r['requested_rate']:>7.0f} req/s | "
        f"achieved {r['achieved_rate']:>8.1f}/s | "
        f"accepted {r['accepted_rate']:>8.1f}/s | "
        f"p50 {str(r['backend_latency_p50_ms']):>7}ms | "
        f"p95 {str(r['backend_latency_p95_ms']):>7}ms | "
        f"failed {r['failed']:>5}{flag}"
    )


async def main_async(args: argparse.Namespace) -> None:
    templates = load_templates(args.capture)
    limits = httpx.Limits(
        max_connections=args.concurrency * 2,
        max_keepalive_connections=args.concurrency * 2,
    )
    async with httpx.AsyncClient(timeout=30.0, limits=limits) as client:
        try:
            root = (await client.get(f"{args.url}/")).json()
        except httpx.HTTPError as exc:
            raise SystemExit(
                f"cannot reach {args.url}: {exc}\nStart it with: uvicorn app.main:app"
            ) from exc
        print(f"target: {root['service']} v{root['version']}")
        print(f"capture: {args.capture} ({len(templates)} templates)\n")

        rates = (
            [args.rate]
            if not args.ramp
            else [100, 250, 500, 1000, 2000, 4000, 8000]
        )
        results = []
        print("phase results")
        for rate in rates:
            r = await run_phase(
                client,
                args.url,
                templates,
                rate=rate,
                duration=args.duration,
                batch_size=args.batch_size,
                concurrency=args.concurrency,
            )
            results.append(r)
            print_phase(r)
            if args.ramp:
                # Saturated: the achieved rate has fallen well short of what we
                # asked for, so higher targets tell us nothing new.
                if r["achieved_rate"] < rate * 0.8:
                    print("  saturated - stopping ramp")
                    break
                await asyncio.sleep(2.0)

        # "Sustained" means the highest rate the backend actually held: it kept
        # up with the offered load AND kept latency bounded. Picking the phase
        # with the largest accepted_rate would report the saturated phase, where
        # the queue is backing up and p95 latency is in seconds - a bigger
        # number that describes a system falling over.
        held = [
            r
            for r in results
            if r["achieved_rate"] >= r["requested_rate"] * 0.95
            and not r["failed"]
            and (r["backend_latency_p95_ms"] or 0) <= args.latency_budget_ms
        ]
        best = (
            max(held, key=lambda r: r["accepted_rate"])
            if held
            else max(results, key=lambda r: r["accepted_rate"])
        )
        saturated = [r for r in results if r not in held]

        print("\n" + "=" * 72)
        print("SUSTAINED THROUGHPUT (backend ingest stage)")
        print("=" * 72)
        if not held:
            print(
                "  WARNING: no phase met the latency budget of "
                f"{args.latency_budget_ms} ms. The figure below is the raw "
                "peak, not a sustainable rate."
            )
        print(
            f"  Sustained: {best['accepted_rate']:.0f} alerts/sec "
            f"with p95 alert latency {best['backend_latency_p95_ms']} ms"
        )
        print(f"  Peak 1s bucket observed: {best['backend_peak_alerts_per_sec']}/s")
        print(f"  Storage backend: {best['storage_backend']}")
        print(
            "  Latency measured from event_end (last packet of the observed "
            "window) to backend receipt."
        )
        print(
            "  Scope: this is the alert-handling stage only. Capture, Zeek "
            "parsing,\n  feature extraction and model inference are upstream "
            "and measured separately."
        )
        if saturated:
            first = min(saturated, key=lambda r: r["requested_rate"])
            print(
                f"  Saturation begins at {first['requested_rate']:.0f} req/s "
                f"(achieved {first['achieved_rate']:.0f}/s, "
                f"p95 {first['backend_latency_p95_ms']} ms)."
            )
        if best["failed"]:
            print(f"  NOTE: {best['failed']} request(s) failed at this rate.")
        if best.get("storage_writes_shed"):
            print(
                f"  NOTE: {best['storage_writes_shed']} durable write(s) shed; "
                "the live path was unaffected."
            )

        if args.out:
            Path(args.out).write_text(
                json.dumps(
                    {
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "capture": args.capture,
                        "phases": results,
                        "headline": {
                            "sustained_alerts_per_sec": best["accepted_rate"],
                            "p95_latency_ms": best["backend_latency_p95_ms"],
                            "latency_budget_ms": args.latency_budget_ms,
                            "stage": "backend ingest / fusion / fan-out",
                            "latency_definition": (
                                "event_end (last packet of the observed window) "
                                "to backend receipt"
                            ),
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            print(f"\n  wrote {args.out}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--rate", type=float, default=500, help="alerts/sec target")
    ap.add_argument("--duration", type=float, default=15.0, help="seconds per phase")
    ap.add_argument("--batch-size", type=int, default=25)
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--capture", default="flood.jsonl")
    ap.add_argument("--ramp", action="store_true", help="ramp until saturation")
    ap.add_argument(
        "--latency-budget-ms",
        type=float,
        default=250.0,
        help="p95 alert latency a phase must stay under to count as sustained",
    )
    ap.add_argument("--out", help="write a JSON report here")
    asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    main()
