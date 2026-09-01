#!/usr/bin/env python3
"""Rebuild the DGA model artifact, then prove it actually wires in.

    python tools/build_dga_model.py                  # build if absent
    python tools/build_dga_model.py --force          # always retrain
    python tools/build_dga_model.py --check-only     # verify an existing bundle

Why this script exists
----------------------
``artifacts/dga_model.joblib`` is a ~12 MB build product and is gitignored on
purpose (root ``.gitignore``: ``artifacts/``; ``detection/.gitignore``:
``*.joblib``). A model binary in git is a binary nobody can review, that grows
the clone for everyone, and that silently goes stale against the code that
loads it. So a fresh clone has **no model**, and
``build_default_detectors()`` returns six detectors instead of seven -
``dga_domain`` never fires and the DGA panel is empty.

The fix is not to commit the artifact. It is to make rebuilding it a single
command that is part of the demo, which is this file. It is deterministic
(``random_state=42``), takes a few seconds, and needs nothing but the
committed sample dataset.

``tools/run_demo.py`` already calls the equivalent of this on startup
(``ensure_dga_model``). This script is the standalone, verbose version: it
runs the same training entry point and then **verifies the result end to end**
rather than assuming a zero exit code means a working detector -

  1. the bundle loads and its feature schema matches this build of
     ``ml/dga/features.py``;
  2. ``build_default_detectors(dga_model_path=...)`` really returns seven
     detectors, with ``dga_domain`` among them;
  3. the detector scores a known-generated name above its 0.75 threshold and a
     plain benign name below it.

Nothing here trains differently from ``detection_core.ml.dga.training``; it
shells out to that module so there is exactly one training implementation.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DETECTION = ROOT / "detection"
DATASET = DETECTION / "detection_core" / "ml" / "dga" / "data" / "dga_dataset.sample.csv"
ARTIFACT = ROOT / "artifacts" / "dga_model.joblib"

#: A venv that has the optional ``[ml]`` extra installed, preferred over
#: whatever interpreter happens to be running this file.
_CANDIDATES = [
    DETECTION / ".venv" / "Scripts" / "python.exe",
    DETECTION / ".venv" / "bin" / "python",
    ROOT / ".venv" / "Scripts" / "python.exe",
    ROOT / ".venv" / "bin" / "python",
]


def pick_python() -> Path:
    for candidate in _CANDIDATES:
        if candidate.is_file():
            return candidate
    return Path(sys.executable)


def train(python: Path, dataset: Path, artifact: Path, extra: list[str]) -> int:
    artifact.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(python), "-m", "detection_core.ml.dga.training",
        "-i", str(dataset), "-o", str(artifact), *extra,
    ]
    print("$ " + " ".join(cmd) + f"    (cwd={DETECTION})\n")
    return subprocess.run(cmd, cwd=str(DETECTION)).returncode


VERIFY_SNIPPET = r'''
import json, sys
from pathlib import Path
sys.path.insert(0, r"{detection}")
from detection_core.ml.dga.features import FEATURE_NAMES
from detection_core.ml.dga.model import DGAModel
from detection_core.pipeline import build_default_detectors

artifact = Path(r"{artifact}")
model = DGAModel.load(artifact)
meta = model.metadata
schema_ok = list(meta.feature_names) == list(FEATURE_NAMES)

detectors = build_default_detectors(dga_model_path=artifact)
names = [d.name for d in detectors]

dga = [d for d in detectors if d.name == "dga_domain"][0]
threshold = dga.config.score_threshold
generated = model.predict_domain("kq7vbzxmwnrlpd.com").dga_score
benign = model.predict_domain("www.google.com").dga_score

print(json.dumps({{
    "artifact_bytes": artifact.stat().st_size,
    "feature_schema_matches": schema_ok,
    "n_features": len(meta.feature_names),
    "model_type": meta.model_type,
    "sklearn_version": meta.sklearn_version,
    "trained_at": str(meta.trained_at),
    "detector_count": len(detectors),
    "detector_names": names,
    "dga_registered": "dga_domain" in names,
    "score_threshold": threshold,
    "score_generated_name": generated,
    "score_benign_name": benign,
    "separates": generated >= threshold > benign,
}}))
'''


def verify(python: Path, artifact: Path) -> dict | None:
    snippet = VERIFY_SNIPPET.format(detection=DETECTION, artifact=artifact)
    result = subprocess.run(
        [str(python), "-c", snippet], capture_output=True, text=True, cwd=str(ROOT)
    )
    if result.returncode != 0:
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return None
    return json.loads(result.stdout.strip().splitlines()[-1])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-i", "--input", default=str(DATASET),
                    help="training CSV (domain,label[,family])")
    ap.add_argument("-o", "--output", default=str(ARTIFACT),
                    help="where the .joblib bundle goes (gitignored)")
    ap.add_argument("--force", action="store_true", help="retrain even if it exists")
    ap.add_argument("--check-only", action="store_true",
                    help="do not train; just verify what is on disk")
    ap.add_argument("--python", default=None,
                    help="interpreter with the [ml] extra installed")
    ap.add_argument("train_args", nargs="*",
                    help="extra flags passed straight to the training CLI "
                         "(e.g. --n-estimators 400 --test-size 0.3)")
    args = ap.parse_args()

    python = Path(args.python) if args.python else pick_python()
    dataset = Path(args.input)
    artifact = Path(args.output)

    print(f"interpreter : {python}")
    print(f"dataset     : {dataset}")
    print(f"artifact    : {artifact}")
    print()

    if not args.check_only:
        if not dataset.is_file():
            print(f"!! no dataset at {dataset}", file=sys.stderr)
            return 1
        if artifact.is_file() and not args.force:
            print(f"[=] {artifact.name} already exists; use --force to retrain.\n")
        else:
            code = train(python, dataset, artifact, list(args.train_args))
            if code != 0:
                print("\n!! training failed. If the error is a missing scikit-learn / "
                      "numpy / joblib, install the optional extra:\n"
                      f"     {python} -m pip install -e detection[ml]\n"
                      "   (or, with uv:  uv pip install --python "
                      f"{python} numpy scikit-learn joblib)", file=sys.stderr)
                return code

    if not artifact.is_file():
        print(f"!! no artifact at {artifact}", file=sys.stderr)
        return 1

    print("verifying the bundle wires in ...")
    info = verify(python, artifact)
    if info is None:
        print("!! the artifact exists but does not load / register", file=sys.stderr)
        return 1

    checks = [
        ("bundle loads", True),
        ("feature schema matches this build", info["feature_schema_matches"]),
        ("build_default_detectors returns 7", info["detector_count"] == 7),
        ("dga_domain registered", info["dga_registered"]),
        ("separates generated from benign name", info["separates"]),
    ]
    print()
    for label, ok in checks:
        print(f"  [{'ok' if ok else 'FAIL'}] {label}")
    print()
    print(f"  size            : {info['artifact_bytes'] / 1e6:.1f} MB")
    print(f"  estimator       : {info['model_type']} (sklearn {info['sklearn_version']})")
    print(f"  features        : {info['n_features']}")
    print(f"  trained at      : {info['trained_at']}")
    print(f"  detectors       : {', '.join(info['detector_names'])}")
    print(f"  threshold       : {info['score_threshold']}")
    print(f"  kq7vbzxmwnrlpd.com -> {info['score_generated_name']:.3f}   "
          f"www.google.com -> {info['score_benign_name']:.3f}")

    failed = [label for label, ok in checks if not ok]
    if failed:
        print(f"\n!! failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("\nall checks passed - the runner will register seven detectors:")
    print(f"  python -m detection_core.runner <capture.jsonl> --dga-model {artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
