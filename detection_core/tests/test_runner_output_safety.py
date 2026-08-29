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

import json
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


# --------------------------------------------------------------------------
# --config / --ja3-feed: startup validation and functional effect
# --------------------------------------------------------------------------


def test_a_missing_config_fails_at_startup_without_touching_the_output(
    tmp_path, capsys
):
    path = write(tmp_path, "input.jsonl", scan_records())
    out = tmp_path / "alerts.jsonl"

    code = runner.main(
        [str(path), "--output", str(out), "--config", str(tmp_path / "absent.toml")]
    )

    assert code == 1
    assert "config file not found" in capsys.readouterr().err
    assert not out.exists(), "the output was opened before configuration was checked"


def test_a_malformed_config_fails_cleanly(tmp_path, capsys):
    path = write(tmp_path, "input.jsonl", scan_records())
    config = tmp_path / "bad.toml"
    config.write_text("[port_scan\nmin_unique_ports = 5\n", encoding="utf-8")

    code = runner.main([str(path), "--config", str(config), "--quiet"])

    err = capsys.readouterr().err
    assert code == 1
    assert "not valid TOML" in err
    assert "Traceback" not in err


def test_an_unknown_config_setting_fails_cleanly(tmp_path, capsys):
    path = write(tmp_path, "input.jsonl", scan_records())
    config = tmp_path / "typo.toml"
    config.write_text("[port_scan]\nmin_unique_prts = 5\n", encoding="utf-8")

    code = runner.main([str(path), "--config", str(config), "--quiet"])

    err = capsys.readouterr().err
    assert code == 1
    assert "min_unique_prts" in err
    assert "Traceback" not in err


def test_a_missing_feed_fails_cleanly(tmp_path, capsys):
    path = write(tmp_path, "input.jsonl", scan_records())

    code = runner.main(
        [str(path), "--ja3-feed", str(tmp_path / "absent.txt"), "--quiet"]
    )

    err = capsys.readouterr().err
    assert code == 1
    assert "fingerprint feed not found" in err
    assert "Traceback" not in err


def test_a_malformed_feed_line_fails_cleanly(tmp_path, capsys):
    path = write(tmp_path, "input.jsonl", scan_records())
    feed = tmp_path / "feed.txt"
    feed.write_text("ja3:not-a-digest\n", encoding="utf-8")

    code = runner.main([str(path), "--ja3-feed", str(feed), "--quiet"])

    err = capsys.readouterr().err
    assert code == 1
    assert "line 1" in err and "MD5" in err
    assert "Traceback" not in err


def test_output_collision_is_still_checked_before_config_is_read(tmp_path, capsys):
    """The Batch-1 safeguard must not be displaced by the new startup work."""
    path = write(tmp_path, "input.jsonl", scan_records())
    before = path.read_bytes()

    code = runner.main(
        [str(path), "--output", str(path), "--config", str(tmp_path / "absent.toml")]
    )

    assert code == 1
    assert "same file as the input file" in capsys.readouterr().err
    assert path.read_bytes() == before


def test_a_config_override_actually_reaches_the_detectors(tmp_path):
    """--config is not decorative: one threshold, one predictable difference.

    Eight distinct ports is under the shipped ``min_unique_ports`` of 15, so
    the default run is silent. Lowering only that one setting - for this test
    only - must make the same input fire.
    """
    records = [
        json.dumps({
            "flow_id": f"10.0.0.5:10.0.0.9:{1000 + i}:tcp:{1000.0 + i * 0.1}",
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "dst_port": 1000 + i,
            "proto": "tcp", "duration": 0.01, "orig_bytes": 60, "resp_bytes": 0,
            "orig_pkts": 1, "resp_pkts": 0,
        })
        for i in range(8)
    ]
    path = write(tmp_path, "eight_ports.jsonl", records)

    plain = tmp_path / "plain.jsonl"
    assert runner.main([str(path), "--output", str(plain), "--quiet"]) == 0
    assert read_alerts(plain) == [], "eight ports must not trip the shipped default"

    config = tmp_path / "lower.toml"
    config.write_text("[port_scan]\nmin_unique_ports = 5\n", encoding="utf-8")
    tuned = tmp_path / "tuned.jsonl"
    assert runner.main(
        [str(path), "--output", str(tuned), "--config", str(config), "--quiet"]
    ) == 0

    alerts = read_alerts(tuned)
    assert alerts, "the configured threshold did not reach the detector"
    assert alerts[0]["threat_class"] == "port_scan"
    assert alerts[0]["evidence"]["min_unique_ports"] == 5


def test_a_dga_section_without_a_model_is_reported_not_silently_ignored(
    tmp_path, capsys
):
    path = write(tmp_path, "input.jsonl", scan_records())
    config = tmp_path / "dga.toml"
    config.write_text("[dga_domain]\nscore_threshold = 0.9\n", encoding="utf-8")

    code = runner.main([str(path), "--config", str(config)])

    err = capsys.readouterr().err
    assert code == 0
    assert "dga_domain" in err and "no --dga-model" in err
    assert "dga_domain not registered" in err


def test_no_new_flags_behaves_exactly_as_before(tmp_path):
    """The default path must be untouched by the configuration layer."""
    path = write(tmp_path, "scan.jsonl", scan_records())
    out = tmp_path / "alerts.jsonl"

    assert runner.main([str(path), "--output", str(out), "--quiet"]) == 0

    classes = [a["threat_class"] for a in read_alerts(out)]
    assert "port_scan" in classes


# --------------------------------------------------------------------------
# DGA artifact failures are configuration errors, not tracebacks
# --------------------------------------------------------------------------


def build_model(tmp_path):
    """A small real bundle, so the valid path is exercised too."""
    from detection_core.ml.dga import LABEL_BENIGN, LABEL_DGA, DGAModel

    model = DGAModel.new(n_estimators=20, random_state=42, n_jobs=1)
    model.fit(
        ["google.com", "wikipedia.org", "github.com",
         "kq3v9x2mzt7wp1.com", "xjfkdlspqoweirut.net", "zzqxwvbnmlkjhg.org"],
        [LABEL_BENIGN] * 3 + [LABEL_DGA] * 3,
    )
    return model.save(tmp_path / "model.joblib")


def test_a_valid_model_still_registers_the_seventh_detector(tmp_path, capsys):
    path = write(tmp_path, "input.jsonl", scan_records())
    model = build_model(tmp_path)
    out = tmp_path / "alerts.jsonl"

    code = runner.main([str(path), "--output", str(out), "--dga-model", str(model)])

    assert code == 0
    assert "dga_domain" in capsys.readouterr().err
    assert read_alerts(out)


def test_a_corrupt_model_fails_cleanly_without_a_traceback(tmp_path, capsys):
    """A truncated or garbage artifact used to surface a raw pickle error.

    ``IndexError: pop from empty list`` from inside ``pickle.load`` tells an
    operator nothing they can act on. It is a configuration problem and now
    reads as one.
    """
    path = write(tmp_path, "input.jsonl", scan_records())
    corrupt = tmp_path / "corrupt.joblib"
    corrupt.write_bytes(b"this is definitely not a joblib bundle")
    out = tmp_path / "alerts.jsonl"

    code = runner.main([str(path), "--output", str(out), "--dga-model", str(corrupt)])

    err = capsys.readouterr().err
    assert code == 1
    assert "could not be read as a joblib model bundle" in err
    assert "Traceback" not in err
    assert "pop from empty list" in err, "the underlying cause should still be named"
    assert err.count("\n") <= 2, f"expected a concise message, got:\n{err}"
    assert not out.exists(), "output was opened before the model was validated"


def test_a_truncated_model_fails_cleanly(tmp_path, capsys):
    path = write(tmp_path, "input.jsonl", scan_records())
    model = build_model(tmp_path)
    truncated = tmp_path / "truncated.joblib"
    truncated.write_bytes(model.read_bytes()[: len(model.read_bytes()) // 3])

    code = runner.main([str(path), "--dga-model", str(truncated)])

    err = capsys.readouterr().err
    assert code == 1
    assert "Traceback" not in err
    assert "could not be read as a joblib model bundle" in err


def test_a_missing_model_still_fails_cleanly(tmp_path, capsys):
    path = write(tmp_path, "input.jsonl", scan_records())

    code = runner.main([str(path), "--dga-model", str(tmp_path / "absent.joblib")])

    err = capsys.readouterr().err
    assert code == 1
    assert "DGA model not found" in err
    assert "Traceback" not in err


def test_a_non_bundle_artifact_still_fails_cleanly(tmp_path, capsys):
    import joblib

    path = write(tmp_path, "input.jsonl", scan_records())
    wrong = tmp_path / "wrong.joblib"
    joblib.dump({"something": "else"}, wrong)

    code = runner.main([str(path), "--dga-model", str(wrong)])

    err = capsys.readouterr().err
    assert code == 1
    assert "not a DGA model bundle" in err
    assert "Traceback" not in err


def test_an_unsupported_format_version_still_fails_cleanly(tmp_path, capsys):
    import joblib

    from detection_core.ml.dga.model import _load_bundle

    path = write(tmp_path, "input.jsonl", scan_records())
    bundle = _load_bundle(build_model(tmp_path))
    bundle["metadata"]["format_version"] = "0.0"
    stale = tmp_path / "stale.joblib"
    joblib.dump(bundle, stale)

    code = runner.main([str(path), "--dga-model", str(stale)])

    err = capsys.readouterr().err
    assert code == 1
    assert "does not match this build" in err
    assert "Traceback" not in err


def test_a_failed_model_load_never_silently_runs_without_dga(tmp_path, capsys):
    """The dangerous failure mode: a scan that looks fine but has no DGA."""
    path = write(tmp_path, "input.jsonl", scan_records())
    corrupt = tmp_path / "corrupt.joblib"
    corrupt.write_bytes(b"garbage")
    out = tmp_path / "alerts.jsonl"

    code = runner.main([str(path), "--output", str(out), "--dga-model", str(corrupt)])

    err = capsys.readouterr().err
    assert code != 0, "a broken model must never degrade into a six-detector run"
    assert not out.exists()
    assert "could not build detectors" in err
    # The run never started: no detector line-up was announced and no
    # records were read.
    assert "detectors: port_scan" not in err
    assert "record(s)" not in err


def test_an_unexpected_error_is_not_swallowed_by_the_model_handling(tmp_path, monkeypatch):
    """The narrow handler must not become a catch-all for our own bugs."""
    path = write(tmp_path, "input.jsonl", scan_records())

    def explode(*args, **kwargs):
        raise MemoryError("a genuinely unexpected failure")

    monkeypatch.setattr(runner, "build_default_detectors", explode)

    with pytest.raises(MemoryError, match="genuinely unexpected"):
        runner.main([str(path), "--quiet"])
