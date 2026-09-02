#!/usr/bin/env python3
"""Bring the whole system up with one command.

    python tools/run_demo.py                 # synthetic capture, no Zeek needed
    python tools/run_demo.py --pcap x.pcap   # the real ingestion path
    python tools/run_demo.py --no-analyst    # prove the system without Layer 8

Starts the backend and the analyst, then drives a capture through the real
detection runner into the backend's ingest route, with throughput telemetry
posted alongside so the System view's numbers are real. Ctrl-C stops everything.

Why a script and not a page of README steps
-------------------------------------------
Because until now there was no way to run the three teams' work together at all.
Every layer had its own instructions, all of them Windows-only, and none of them
mentioned the one flag - ``--api-url`` - that actually joins detection to the
backend. A demo path that exists only as prose is a demo path nobody has run.
"""

from __future__ import annotations

import argparse
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

_WIN = ROOT / ".venv" / "Scripts" / "python.exe"
_NIX = ROOT / ".venv" / "bin" / "python"
PY = _WIN if _WIN.exists() else (_NIX if _NIX.exists() else Path(sys.executable))

BACKEND_PORT = 8000
ANALYST_PORT = 8100
VITE_PORT = 5173

children: list[subprocess.Popen] = []


def spawn(name: str, args: list[str], cwd: Path) -> subprocess.Popen:
    print(f"  starting {name} ...")
    proc = subprocess.Popen(args, cwd=str(cwd))
    children.append(proc)
    return proc


def shutdown(*_args) -> None:
    print("\nstopping ...")
    for proc in reversed(children):
        if proc.poll() is None:
            proc.terminate()
    for proc in reversed(children):
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
    print("stopped")


def wait_for(url: str, timeout: float = 45.0) -> bool:
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2.0).read()
            return True
        except Exception:
            time.sleep(0.4)
    return False


def build_capture(args) -> Path:
    """Produce the flow records detection will read."""
    features = DATA / "features.jsonl"
    DATA.mkdir(exist_ok=True)

    if args.features:
        return Path(args.features)

    if args.pcap:
        # The real path. Needs the compiled Rust extension and Zeek (Docker).
        print(f"\nrunning the ingestion pipeline over {args.pcap} ...")
        result = subprocess.run(
            [str(PY), "pipeline.py", args.pcap, "-o", str(features), "--stats"],
            cwd=str(ROOT / "ingestion"),
        )
        if result.returncode != 0:
            sys.exit(
                "ingestion failed. The pipeline needs the compiled ingestion_core "
                "extension (cargo + maturin) and Zeek via Docker. To demo without "
                "either, drop --pcap and a labelled synthetic capture is generated "
                "instead."
            )
        return features

    print("\ngenerating a labelled synthetic capture ...")
    subprocess.run(
        [str(PY), "tools/synth_flows.py", "-o", str(features),
         "--seed", str(args.seed), "--duration", str(args.duration)],
        cwd=str(ROOT), check=True,
    )
    return features


def ensure_dga_model() -> None:
    """Train the DGA model if it is not on disk.

    ``artifacts/`` is gitignored - the bundle is a 12 MB build product and does
    not belong in the repository - so a fresh clone has no model and the
    detection runner registers six detectors instead of seven. It degrades to a
    log line rather than an error, which is the right behaviour and also the
    kind of thing nobody notices until the DGA panel is empty on stage.

    Training from the committed sample dataset takes a few seconds.
    """
    artifact = ROOT / "artifacts" / "dga_model.joblib"
    if artifact.is_file():
        return
    dataset = (
        ROOT / "detection" / "detection_core" / "ml" / "dga" / "data"
        / "dga_dataset.sample.csv"
    )
    if not dataset.is_file():
        print("  no DGA dataset on disk; dga_domain will stay unregistered")
        return

    print("\ntraining the DGA model (first run only) ...")
    artifact.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [str(PY), "-m", "detection_core.ml.dga.training",
         "-i", str(dataset), "-o", str(artifact)],
        cwd=str(ROOT / "detection"),
    )
    if result.returncode != 0 or not artifact.is_file():
        print("  DGA training did not produce an artifact; continuing on six detectors")


def _run() -> int:
    ap = argparse.ArgumentParser(description="Run the whole pipeline end to end")
    ap.add_argument("--pcap", default=None, help="run the real Zeek + Rust ingestion path")
    ap.add_argument("--features", default=None, help="use an existing features.jsonl")
    ap.add_argument("--seed", type=int, default=26145)
    ap.add_argument("--duration", type=float, default=600.0)
    ap.add_argument("--no-analyst", action="store_true",
                    help="prove the system meets every requirement with Layer 8 off")
    ap.add_argument("--ui", action="store_true",
                    help="also start the Vite dev server (otherwise the backend "
                         "serves frontend/dist when it has been built)")
    ap.add_argument("--api-batch", type=int, default=None,
                    help="POST alerts in batches of N to /api/v1/alerts/bulk")
    args = ap.parse_args()

    signal.signal(signal.SIGINT, lambda *a: (shutdown(), sys.exit(0)))

    ensure_dga_model()

    features = build_capture(args)
    if not features.is_file():
        sys.exit(f"no capture at {features}")

    print("\nstarting services ...")
    spawn("backend", [str(PY), "-m", "uvicorn", "app.main:app",
                      "--host", "127.0.0.1", "--port", str(BACKEND_PORT)],
          ROOT / "backend")
    if not wait_for(f"http://127.0.0.1:{BACKEND_PORT}/health"):
        shutdown()
        sys.exit("backend did not start")

    if not args.no_analyst:
        spawn("analyst", [str(PY), "-m", "uvicorn", "analyst.main:app",
                          "--host", "127.0.0.1", "--port", str(ANALYST_PORT)],
              ROOT / "analyst")
        wait_for(f"http://127.0.0.1:{ANALYST_PORT}/health", timeout=25)

    if args.ui:
        # Windows ships npm as npm.cmd, and CreateProcess will not launch it
        # from the bare name "npm" - which() returns the resolved path that it
        # will. shutil.which() was already being called here purely as a
        # boolean, one line above the call that then failed.
        npm = shutil.which("npm")
        if npm:
            spawn("dashboard (vite)", [npm, "run", "dev"], ROOT / "frontend")
        else:
            print("  npm not found; skipping the dev server")

    dist = ROOT / "frontend" / "dist"
    print("\n" + "=" * 66)
    # The Vite dev server binds ::1 and answers to "localhost" but NOT to
    # "127.0.0.1"; uvicorn is bound explicitly to 127.0.0.1. Printing the wrong
    # one sends the operator to a URL that refuses the connection.
    dashboard = (
        f"http://localhost:{VITE_PORT}" if args.ui
        else f"http://127.0.0.1:{BACKEND_PORT}"
    )
    print(f"  dashboard    {dashboard}"
          + ("" if args.ui or dist.is_dir() else "   (run 'npm run build' in frontend/ first)"))
    print(f"  API docs     http://127.0.0.1:{BACKEND_PORT}/docs")
    print(f"  constraints  http://127.0.0.1:{BACKEND_PORT}/api/v1/system/constraints")
    if not args.no_analyst:
        print(f"  analyst      http://127.0.0.1:{ANALYST_PORT}/api/v1/analyst/constraints")
    print("=" * 66)

    ja3_feed = ROOT / "tools" / "ja3_feed.example.txt"
    # The re-derived DGA decision threshold (0.65). DGAConfig ships 0.75, which
    # was chosen for the pre-CDN corpus and is documented there as untuned; the
    # shipped default is frozen detection code and is deliberately not edited,
    # so the demo passes the override the same way an operator would. Without
    # this the demo runs the tuned model at the untuned threshold.
    # See docs/DGA_PRECISION.md and detection/detectors.dga-precision.toml.
    detector_config = ROOT / "detection" / "detectors.dga-precision.toml"

    command = [
        str(PY), "-m", "detection_core.runner", str(features),
        "--output", str(DATA / "alerts.jsonl"),
        "--api-url", f"http://127.0.0.1:{BACKEND_PORT}/api/v1/alerts",
        "--telemetry-url", f"http://127.0.0.1:{BACKEND_PORT}/api/v1/telemetry",
    ]
    if ja3_feed.is_file():
        command += ["--ja3-feed", str(ja3_feed)]
    if detector_config.is_file():
        command += ["--config", str(detector_config)]
    else:
        # Same degradation as a missing JA3 feed: say so rather than silently
        # running at a threshold the report does not describe.
        print(f"  no {detector_config.name}; dga_domain runs at its shipped 0.75 default")
    if args.api_batch:
        command += ["--api-batch", str(args.api_batch)]

    print("\nrunning detection into the backend ...\n")
    detection = subprocess.run(command, cwd=str(ROOT))

    if detection.returncode == 2:
        print("\nDEGRADED: some alerts did not reach the backend (see above).")
    elif detection.returncode != 0:
        print(f"\ndetection exited {detection.returncode}")

    manifest = DATA / "features.manifest.json"
    if manifest.is_file():
        print("\nscoring against ground truth ...\n")
        subprocess.run(
            [str(PY), "tools/evaluate.py", "--alerts", str(DATA / "alerts.jsonl"),
             "--manifest", str(manifest)],
            cwd=str(ROOT),
        )

    print("\nServices are still running. Open the dashboard, then Ctrl-C here to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    return 0


def main() -> int:
    """Whatever happens, do not leave a backend and an analyst running.

    The services start before the wait loop, so any failure between the two -
    npm missing, a port already held, a typo - used to propagate straight out
    and orphan them, and the next run then failed on the port instead of on
    the original cause.
    """
    try:
        return _run()
    finally:
        shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
