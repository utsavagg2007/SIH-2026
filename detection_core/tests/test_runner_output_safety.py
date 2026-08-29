"""The runner's startup guards: output must never destroy an input, and a
DGA run must fail clearly when the ML extra is not installed.

Both are *startup* concerns. ``open(path, "w")`` truncates on open, so an
``--output`` aimed at the input JSONL or at the ``--dga-model`` bundle has
already destroyed that file by the time the sink exists - checking after the
fact is too late. Everything here therefore asserts two things together: the
run is rejected, **and** the file on disk is byte-for-byte what it was.

Scope is the runner only. Detector behaviour and the ThreatAlert contract are
covered by ``test_pipeline_runner.py`` and are not re-tested here.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from detection_core import runner

# The real fixtures - one fitted model, one synthetic capture - rather than
# second copies of them that could drift.
from .test_pipeline_runner import (  # noqa: F401 - dga_model_path is a fixture
    dga_model_path,
    read_alerts,
    scan_records,
    write,
)

RULE_DETECTOR_NAMES = [
    "port_scan",
    "ddos",
    "c2_beaconing",
    "dns_tunnelling",
    "data_exfiltration",
    "encrypted_malware",
]


def digest(path: Path) -> bytes:
    """The file's exact bytes - not its size, not its parsed contents."""
    return path.read_bytes()


# --------------------------------------------------------------------------
# 1-3. --output must not destroy the input JSONL
# --------------------------------------------------------------------------


def test_output_equal_to_input_is_rejected(tmp_path, capsys):
    """The literal case: ``runner input.jsonl --output input.jsonl``."""
    path = write(tmp_path, "input.jsonl", scan_records())
    before = digest(path)

    code = runner.main([str(path), "--output", str(path)])

    assert code == 1
    assert "same file as the input file" in capsys.readouterr().err
    assert digest(path) == before, "input was modified despite the rejection"


def test_relative_alias_of_the_input_is_rejected(tmp_path, monkeypatch, capsys):
    """``./data/test.jsonl`` and ``data/../data/test.jsonl`` are one file."""
    data = tmp_path / "data"
    data.mkdir()
    path = write(data, "test.jsonl", scan_records())
    before = digest(path)

    monkeypatch.chdir(tmp_path)
    code = runner.main(["./data/test.jsonl", "--output", "data/../data/test.jsonl"])

    assert code == 1
    assert "same file as the input file" in capsys.readouterr().err
    assert digest(path) == before


def test_absolute_alias_of_the_input_is_rejected(tmp_path, monkeypatch, capsys):
    """A relative input and an absolute output can still collide."""
    path = write(tmp_path, "input.jsonl", scan_records())
    before = digest(path)

    monkeypatch.chdir(tmp_path)
    code = runner.main(["input.jsonl", "--output", str(path.resolve())])

    assert code == 1
    assert "same file as the input file" in capsys.readouterr().err
    assert digest(path) == before


def test_the_input_is_still_usable_after_a_rejection(tmp_path):
    """Not merely unmodified: the rejected run leaves a working input behind."""
    path = write(tmp_path, "input.jsonl", scan_records())
    before = digest(path)

    assert runner.main([str(path), "--output", str(path), "--quiet"]) == 1

    out = tmp_path / "alerts.jsonl"
    assert runner.main([str(path), "--output", str(out), "--quiet"]) == 0
    assert digest(path) == before
    assert read_alerts(out), "the input survived but produced no alerts"


# --------------------------------------------------------------------------
# 4-5. --output must not destroy the DGA model bundle
# --------------------------------------------------------------------------


def test_output_equal_to_the_dga_model_is_rejected(tmp_path, dga_model_path, capsys):
    path = write(tmp_path, "input.jsonl", scan_records())
    before = digest(dga_model_path)

    code = runner.main(
        [
            str(path),
            "--dga-model",
            str(dga_model_path),
            "--output",
            str(dga_model_path),
        ]
    )

    assert code == 1
    assert "same file as the --dga-model file" in capsys.readouterr().err
    assert digest(dga_model_path) == before, "the model bundle was overwritten"


def test_the_dga_model_survives_an_aliased_output_and_still_loads(
    tmp_path, dga_model_path
):
    """A ``..`` alias of the model is caught, and the bundle still works."""
    path = write(tmp_path, "input.jsonl", scan_records())
    before = digest(dga_model_path)
    alias = dga_model_path.parent / ".." / dga_model_path.parent.name / "model.joblib"

    assert (
        runner.main(
            [
                str(path),
                "--dga-model",
                str(dga_model_path),
                "--output",
                str(alias),
                "--quiet",
            ]
        )
        == 1
    )
    assert digest(dga_model_path) == before

    out = tmp_path / "alerts.jsonl"
    code = runner.main(
        [
            str(path),
            "--dga-model",
            str(dga_model_path),
            "--output",
            str(out),
            "--quiet",
        ]
    )
    assert code == 0, "the model no longer loads after the rejected run"


# --------------------------------------------------------------------------
# 6. A distinct output is untouched by the guard
# --------------------------------------------------------------------------


def test_a_distinct_output_still_works(tmp_path):
    path = write(tmp_path, "input.jsonl", scan_records())
    out = tmp_path / "alerts.jsonl"
    before = digest(path)

    assert runner.main([str(path), "--output", str(out), "--quiet"]) == 0

    assert read_alerts(out), "expected alerts in the output file"
    assert digest(path) == before


def test_a_distinct_output_still_works_with_a_dga_model(tmp_path, dga_model_path):
    """Same run, three different files - all fine."""
    path = write(tmp_path, "input.jsonl", scan_records())
    out = tmp_path / "alerts.jsonl"

    code = runner.main(
        [
            str(path),
            "--dga-model",
            str(dga_model_path),
            "--output",
            str(out),
            "--quiet",
        ]
    )

    assert code == 0
    assert read_alerts(out)


# --------------------------------------------------------------------------
# 7. --dga-model without the ML extra
# --------------------------------------------------------------------------


def test_missing_ml_dependency_fails_at_startup_and_names_the_extra(
    tmp_path, monkeypatch, capsys
):
    """DGA must not be silently dropped, nor raise a bare ImportError."""
    monkeypatch.setattr(runner, "ML_DEPENDENCIES", ("no_such_module_for_tests",))
    path = write(tmp_path, "input.jsonl", scan_records())
    out = tmp_path / "alerts.jsonl"

    code = runner.main(
        [
            str(path),
            "--dga-model",
            str(tmp_path / "model.joblib"),
            "--output",
            str(out),
        ]
    )

    err = capsys.readouterr().err
    assert code == 1
    assert "no_such_module_for_tests is not importable" in err
    assert "pip install -e" in err and "[ml]" in err
    # It failed before opening anything: no half-written alert file.
    assert not out.exists()


def test_a_broken_ml_install_is_reported_not_traced(tmp_path, monkeypatch, capsys):
    """find_spec can succeed where the import still fails; still no traceback."""

    def explode(**kwargs):
        raise ImportError("libgomp.so.1: cannot open shared object file")

    monkeypatch.setattr(runner, "build_default_detectors", explode)
    path = write(tmp_path, "input.jsonl", scan_records())

    code = runner.main([str(path), "--dga-model", str(tmp_path / "model.joblib")])

    err = capsys.readouterr().err
    assert code == 1
    assert "DGA could not be loaded" in err
    assert "libgomp" in err
    assert "Traceback" not in err


def test_the_dependency_probe_agrees_with_this_environment():
    """Sanity: with the ml extra installed, nothing is reported missing."""
    pytest.importorskip("sklearn")
    assert runner._missing_ml_dependencies() == []


def test_the_ml_check_is_skipped_without_dga_model(tmp_path, monkeypatch):
    """A run that never asked for DGA must not be blocked by a missing extra."""
    monkeypatch.setattr(runner, "ML_DEPENDENCIES", ("no_such_module_for_tests",))
    path = write(tmp_path, "input.jsonl", scan_records())
    out = tmp_path / "alerts.jsonl"

    assert runner.main([str(path), "--output", str(out), "--quiet"]) == 0
    assert read_alerts(out)


# --------------------------------------------------------------------------
# 8. The core stays dependency-light
# --------------------------------------------------------------------------


_WITHOUT_ML = '''
import sys

BLOCKED = {"numpy", "sklearn", "scipy", "joblib", "pandas"}


class Blocker:
    """Refuse the ML extra the way a core-only install would."""

    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in BLOCKED:
            raise ImportError("blocked for this test: " + name)
        return None


sys.meta_path.insert(0, Blocker())

import detection_core
from detection_core import runner

names = [d.name for d in detection_core.build_default_detectors()]
assert names == %r, names
assert runner._missing_ml_dependencies(), "the import block was not effective"
print("ok")
''' % (RULE_DETECTOR_NAMES,)


def test_core_import_and_the_six_detectors_need_no_ml_extra():
    """``import detection_core`` must work on a core-only install.

    Run in a subprocess with numpy/scikit-learn/joblib blocked at import
    time: this test process has them installed, so it could not otherwise
    tell whether importing the package pulls them in.
    """
    result = subprocess.run(
        [sys.executable, "-c", _WITHOUT_ML],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("ok")
