"""Terminal noise that used to bury real output, and the guards against it.

Two warnings fired on ordinary use of this project. Neither indicated a bug,
and neither was ours - but hundreds of lines of third-party deprecation notice
around every model load is how a genuine warning gets missed.

The tests here pin the fixes *and*, more importantly, pin that the fixes are
narrow: an unrelated warning, a warning of another category carrying the same
text, and every error must all still come through. Silence bought by
suppressing everything would be worse than the noise.
"""

from __future__ import annotations

import subprocess
import sys
import warnings
from pathlib import Path

import joblib
import pytest

from detection_core.ml.dga import LABEL_BENIGN, LABEL_DGA, DGAModel

REPO = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "dga_domains.csv"

#: The third-party deprecation this batch silences, by exact text.
JOBLIB_RESHAPE = "Setting the shape on a NumPy array has been deprecated"

BENIGN = ["google.com", "facebook.com", "wikipedia.org", "github.com", "amazon.com"]
GENERATED = [
    "kq3v9x2mzt7wp1.com", "xjfkdlspqoweirut.net", "zzqxwvbnmlkjhg.org",
    "vbnmqwertyuiopas.com", "plmoknijbuhvygc.net",
]


@pytest.fixture(scope="module")
def artifact(tmp_path_factory):
    """A small model saved under tmp. Never committed."""
    model = DGAModel.new(n_estimators=25, random_state=42, n_jobs=1)
    model.fit(BENIGN + GENERATED, [LABEL_BENIGN] * 5 + [LABEL_DGA] * 5)
    return model.save(tmp_path_factory.mktemp("warn") / "model.joblib")


def caught(fn):
    with warnings.catch_warnings(record=True) as records:
        warnings.simplefilter("always")
        fn()
    return records


# --------------------------------------------------------------------------
# 1-3. The model-load deprecation storm
# --------------------------------------------------------------------------


def test_loading_a_model_is_quiet(artifact):
    """joblib reshapes every array it unpickles; a forest has hundreds."""
    records = caught(lambda: DGAModel.load(artifact))

    offending = [r for r in records if JOBLIB_RESHAPE in str(r.message)]
    assert offending == [], f"{len(offending)} reshape deprecation(s) still emitted"


def test_the_filter_is_scoped_to_the_load_call(artifact):
    """No global filter is installed - the rest of the process is unaffected."""
    DGAModel.load(artifact)

    installed = [f for f in warnings.filters if JOBLIB_RESHAPE in str(f[1] or "")]
    assert installed == [], "a process-wide filter was left behind"


def test_unrelated_warnings_still_surface(artifact):
    """The point is less noise, not less information."""

    def load_then_warn():
        DGAModel.load(artifact)
        warnings.warn("something else is deprecated", DeprecationWarning)
        warnings.warn("a user warning", UserWarning)
        warnings.warn("a future change", FutureWarning)

    seen = {r.category for r in caught(load_then_warn)}

    assert DeprecationWarning in seen, "unrelated deprecations must not be hidden"
    assert UserWarning in seen
    assert FutureWarning in seen


def test_the_same_message_in_another_category_still_surfaces(artifact):
    """Both the category and the message must match to be silenced."""

    def load_then_warn():
        DGAModel.load(artifact)
        warnings.warn(JOBLIB_RESHAPE, UserWarning)

    records = caught(load_then_warn)

    assert [r for r in records if r.category is UserWarning], (
        "the filter is matching on message alone"
    )


# --------------------------------------------------------------------------
# 2 (Phase 5). Errors are never hidden
# --------------------------------------------------------------------------


def test_a_corrupt_artifact_still_fails_loudly(tmp_path):
    path = tmp_path / "corrupt.joblib"
    path.write_bytes(b"this is not a pickle")

    with pytest.raises(Exception) as caught_error:
        DGAModel.load(path)

    assert caught_error.type is not Warning


def test_a_non_bundle_still_raises_its_clear_error(tmp_path):
    path = tmp_path / "wrong.joblib"
    joblib.dump({"not": "a bundle"}, path)

    with pytest.raises(ValueError, match="not a DGA model bundle"):
        DGAModel.load(path)


def test_a_stale_format_version_still_raises(tmp_path, artifact):
    # Read through the project's own helper: a bare joblib.load here would
    # re-emit the very deprecation storm this file is about.
    from detection_core.ml.dga.model import _load_bundle

    bundle = _load_bundle(artifact)
    bundle["metadata"]["format_version"] = "0.1"
    path = tmp_path / "stale.joblib"
    joblib.dump(bundle, path)

    with pytest.raises(ValueError, match="does not match this build"):
        DGAModel.load(path)


# --------------------------------------------------------------------------
# 4-5. The `python -m` RuntimeWarning, and public imports
# --------------------------------------------------------------------------


def run_module(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-W", "always", "-m", *args],
        cwd=str(REPO), capture_output=True, text=True,
    )


def test_the_training_cli_no_longer_warns_about_double_import():
    """`python -m detection_core.ml.dga.training` is the documented command."""
    result = run_module(
        "detection_core.ml.dga.training", "--input", str(FIXTURE),
        "--n-estimators", "20",
    )

    assert result.returncode == 0, result.stderr
    assert "found in sys.modules" not in result.stderr
    assert "RuntimeWarning" not in result.stderr
    assert "DGA training summary" in result.stdout


def test_the_training_cli_help_is_clean():
    result = run_module("detection_core.ml.dga.training", "--help")

    assert result.returncode == 0
    assert result.stderr == "", f"--help wrote to stderr: {result.stderr!r}"
    assert "--threshold" in result.stdout


def test_the_runner_help_is_clean_and_documents_the_new_flags():
    result = run_module("detection_core.runner", "--help")

    assert result.returncode == 0
    assert result.stderr == "", f"--help wrote to stderr: {result.stderr!r}"
    for flag in ("--config", "--ja3-feed", "--dga-model", "--output", "--api-url"):
        assert flag in result.stdout


def test_the_public_dga_imports_still_work():
    """Laziness must be invisible to every documented import."""
    from detection_core.ml.dga import (  # noqa: F401
        DEFAULT_EVAL_THRESHOLD,
        DEFAULT_SWEEP_THRESHOLDS,
        DGAModel,
        EvaluationResult,
        TrainingResult,
        evaluate,
        evaluate_baseline,
        evaluate_scores,
        sweep_thresholds,
        train_dga,
    )

    assert DEFAULT_EVAL_THRESHOLD == 0.75
    assert callable(train_dga)
    assert callable(evaluate)


def test_the_package_still_advertises_its_exports():
    import detection_core.ml.dga as dga

    for name in ("train_dga", "evaluate", "TrainingResult", "DGAModel"):
        assert name in dga.__all__
        assert name in dir(dga)
        assert getattr(dga, name) is not None


def test_an_unknown_attribute_still_raises_attribute_error():
    import detection_core.ml.dga as dga

    with pytest.raises(AttributeError, match="has no attribute 'not_a_real_name'"):
        dga.not_a_real_name


def test_importing_the_package_no_longer_pulls_in_training():
    """The cause of the runpy warning, asserted directly."""
    result = subprocess.run(
        [
            sys.executable, "-c",
            "import sys; import detection_core.ml.dga as d; "
            "print('detection_core.ml.dga.training' in sys.modules)",
        ],
        cwd=str(REPO), capture_output=True, text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def test_the_core_package_still_imports_without_the_ml_extra():
    """Laziness must not have moved an ML import onto the core path."""
    script = (
        "import sys\n"
        "class B:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] in {'sklearn','joblib','numpy','scipy'}:\n"
        "            raise ImportError('blocked')\n"
        "        return None\n"
        "sys.meta_path.insert(0, B())\n"
        "import detection_core\n"
        "assert len(detection_core.build_default_detectors()) == 6\n"
        "print('ok')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script], cwd=str(REPO), capture_output=True, text=True
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("ok")
