"""Command-line runner: an ingestion JSONL file in, ThreatAlerts out.

    python -m detection_core.runner features.jsonl
    python -m detection_core.runner features.jsonl --output alerts.jsonl
    python -m detection_core.runner features.jsonl --dga-model artifacts/dga.joblib
    python -m detection_core.runner features.jsonl \\
        --api-url http://localhost:8000/api/v1/alerts

**stdout carries alert JSONL and nothing else.** Every log line, warning and
error goes to stderr, so ``... | jq`` and ``... > alerts.jsonl`` both stay
valid without any extra flags.

Alerts always go to a JSONL stream - stdout by default, a file with
``--output``. ``--api-url`` adds the backend as a *second* destination rather
than replacing the first, so a run that posts alerts still leaves a local
record of what was sent.

``--output`` is never allowed to name one of the run's own inputs: opening it
truncates it, so ``--output`` pointed at the input JSONL or at ``--dga-model``
would destroy the file before it is read. That is checked at startup, before
anything is opened.
"""

from __future__ import annotations

import argparse
import importlib.util
import logging
import os
import sys
from pathlib import Path

from .adapters import IngestionJsonlAdapter
from .config import ConfigError, DetectorSettings, load_detector_settings
from .fingerprints import FingerprintError, load_fingerprint_feed
from .pipeline import (
    DEFAULT_API_TIMEOUT,
    AlertSink,
    HttpAlertSink,
    JsonlAlertSink,
    MultiSink,
    build_default_detectors,
    run_detection,
)

__all__ = ["build_parser", "main"]

logger = logging.getLogger("detection_core.runner")

EXIT_OK = 0
EXIT_ERROR = 1
#: The capture was processed end to end, but some alerts never reached the
#: ``--api-url`` backend. Distinct from EXIT_ERROR so a caller can tell "the
#: run did not happen" from "the run happened and the backend missed some".
EXIT_DELIVERY_DEGRADED = 2

#: Modules the DGA detector needs, all supplied by the ``ml`` extra. Checked
#: by name rather than imported, so the six rule detectors keep running on a
#: core-only install and this module stays cheap to import.
ML_DEPENDENCIES = ("numpy", "sklearn", "joblib")

#: Said the same way wherever a missing ML extra surfaces.
ML_EXTRA_HINT = (
    "DGA requires this project's optional ML dependencies "
    "(numpy, scikit-learn, joblib), which are not part of the core install. "
    'Install them with: pip install -e ".[ml]"'
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m detection_core.runner",
        description=(
            "Run every available detector over an ingestion features.jsonl "
            "file and emit ThreatAlert v1.1 records."
        ),
        epilog=(
            "Alert JSONL goes to stdout unless --output is given; logs always "
            "go to stderr."
        ),
    )
    parser.add_argument(
        "input",
        type=Path,
        help="ingestion-style JSONL file (one flow record per line)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        metavar="PATH",
        help="write alert JSONL here instead of stdout",
    )
    parser.add_argument(
        "--dga-model",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "trained DGA model bundle. Omit to run the other six detectors "
            "without DGA; no model is shipped with this package"
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "TOML file of detector settings (thresholds, windows, cooldowns, "
            "fingerprint lists). Only the values it names are overridden; "
            "everything else keeps its shipped default. Unknown sections, "
            "unknown settings and wrong types are rejected at startup"
        ),
    )
    parser.add_argument(
        "--ja3-feed",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "local file of trusted JA3/JA3S/JA4 fingerprints for the "
            "encrypted_malware signature path, one per line as "
            "'ja3:<hash>' (a bare MD5 is read as ja3). Read from disk only - "
            "nothing is ever downloaded - and unioned with any fingerprints "
            "given in --config"
        ),
    )
    parser.add_argument(
        "--api-url",
        default=None,
        metavar="URL",
        help=(
            "POST each alert to this endpoint as well, one alert per request "
            "(e.g. http://localhost:8000/api/v1/alerts)"
        ),
    )
    parser.add_argument(
        "--api-timeout",
        type=float,
        default=DEFAULT_API_TIMEOUT,
        metavar="SECONDS",
        help=f"timeout for each POST (default: {DEFAULT_API_TIMEOUT})",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="only report errors on stderr",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code rather than calling exit()."""
    args = build_parser().parse_args(argv)

    handler, previous_level = _attach_stderr_logging(quiet=args.quiet)
    try:
        return _run(args)
    finally:
        _detach_logging(handler, previous_level)


def _run(args: argparse.Namespace) -> int:
    if not args.input.is_file():
        logger.error("input file not found: %s", args.input)
        return EXIT_ERROR

    # --- startup: anything misconfigured must fail before any flow is read,
    # and - critically - before the output file is opened, since opening it
    # truncates whatever is already there.
    collision = _output_collision(args)
    if collision is not None:
        logger.error("%s", collision)
        return EXIT_ERROR

    try:
        settings = _detector_settings(args)
    except (ConfigError, FingerprintError) as exc:
        logger.error("%s", exc)
        return EXIT_ERROR

    missing = _missing_ml_dependencies() if args.dga_model is not None else []
    if missing:
        logger.error(
            "--dga-model was supplied but %s not importable. %s",
            _phrase(missing),
            ML_EXTRA_HINT,
        )
        return EXIT_ERROR

    try:
        detectors = build_default_detectors(
            dga_model_path=args.dga_model, settings=settings
        )
    except ImportError as exc:
        # find_spec found the modules but importing one failed - a broken or
        # half-installed extra. Still the user's dependency problem, so it
        # gets the same clear message rather than an internal traceback.
        logger.error("DGA could not be loaded: %s. %s", exc, ML_EXTRA_HINT)
        return EXIT_ERROR
    except (FileNotFoundError, ValueError, RuntimeError, TypeError) as exc:
        logger.error("could not build detectors: %s", exc)
        return EXIT_ERROR

    try:
        sink, jsonl_sink = _build_sink(args)
    except (OSError, ValueError) as exc:
        logger.error("could not open alert output: %s", exc)
        return EXIT_ERROR

    names = ", ".join(d.name for d in detectors)
    logger.info("detectors: %s", names)
    if args.dga_model is None:
        logger.info("dga_domain not registered (no --dga-model supplied)")

    adapter = IngestionJsonlAdapter(path=args.input)
    try:
        # Delivery failures no longer end the run: run_detection logs and
        # counts them, and the whole capture is still processed. They are
        # reported below, and in the exit code.
        stats = run_detection(adapter, sink, detectors, log=logger)
    except OSError as exc:
        logger.error("i/o error during run: %s", exc)
        return EXIT_ERROR
    finally:
        sink.close()

    logger.info(
        "read %d record(s), %d parsed, %d skipped; %d alert(s), %d detector error(s)",
        adapter.stats.total_lines,
        adapter.stats.parsed,
        adapter.stats.skipped,
        stats.alerts,
        stats.detector_errors,
    )
    for warning in adapter.stats.drift_warnings:
        logger.warning("%s", warning)
    if args.output is not None and jsonl_sink is not None:
        logger.info("wrote %d alert(s) to %s", jsonl_sink.count, args.output)

    if stats.delivery_failures:
        # The run finished; the backend's copy did not. Say so plainly and
        # exit non-zero, so a scheduled replay cannot look successful while
        # the backend is missing alerts.
        logger.error(
            "DEGRADED: %d of %d alert(s) failed delivery to %s%s",
            stats.delivery_failures,
            stats.alerts,
            args.api_url,
            (
                f"; all {stats.alerts} alert(s) are in {args.output}"
                if args.output is not None
                else "; alert JSONL on stdout is complete"
            ),
        )
        return EXIT_DELIVERY_DEGRADED

    return EXIT_OK


# --------------------------------------------------------------------------
# Startup validation
# --------------------------------------------------------------------------


def _detector_settings(args: argparse.Namespace) -> DetectorSettings:
    """Detector configuration for this run: defaults, file, and feed.

    Read once, here, before a single flow is parsed - a settings file that is
    wrong should cost nothing but a clear message, and a detector must never
    touch the filesystem while processing.

    With neither flag this returns ``DetectorSettings()``, which is the
    shipped defaults and therefore identical to the behaviour before either
    flag existed.
    """
    settings = (
        load_detector_settings(args.config)
        if args.config is not None
        else DetectorSettings()
    )

    if args.ja3_feed is not None:
        feed = load_fingerprint_feed(args.ja3_feed)
        loaded = sum(len(values) for values in feed.values())
        if loaded:
            logger.info(
                "loaded %d fingerprint(s) from %s (%s)",
                loaded,
                args.ja3_feed,
                ", ".join(
                    f"{kind}={len(values)}" for kind, values in feed.items() if values
                ),
            )
        else:
            logger.warning(
                "%s contained no fingerprints; the signature path stays inert",
                args.ja3_feed,
            )
        settings = settings.with_fingerprints(feed)

    if "dga_domain" in settings.configured_sections and args.dga_model is None:
        # Configured, validated, and inert - DGA needs an artifact, and this
        # says so rather than letting the section look effective.
        logger.info(
            "[dga_domain] settings were read but the detector stays disabled: "
            "no --dga-model was supplied"
        )
    return settings


def _output_collision(args: argparse.Namespace) -> str | None:
    """Reject an ``--output`` that would destroy one of the run's own inputs.

    ``open(path, "w")`` truncates on open, so by the time the sink exists an
    ``--output`` aimed at the input JSONL has already emptied it - the run
    then reads zero flows from a file the user still had. Same for the
    ``--dga-model`` bundle, which is loaded once and cannot be rebuilt from
    the alerts written over it, and same for the settings and fingerprint
    files: both are read at startup and both are hand-maintained, so an
    ``--output`` aimed at one destroys work that no rerun brings back.

    The rule is simply "every file this run reads": any new read-only input
    belongs in the tuple below, and forgetting one is how ``--config`` and
    ``--ja3-feed`` were briefly able to truncate themselves.

    Returns the message to log, or ``None`` when the destinations are
    genuinely distinct. Nothing here opens, creates or modifies a file.
    """
    if args.output is None:  # stdout: nothing on disk to overwrite
        return None

    for label, source in (
        ("input file", args.input),
        ("--dga-model file", args.dga_model),
        ("--config file", args.config),
        ("--ja3-feed file", args.ja3_feed),
    ):
        if source is None:
            continue
        if _same_target(args.output, source):
            return (
                f"--output {args.output} resolves to the same file as the "
                f"{label} {source}; writing alerts there would destroy it. "
                "Choose a different --output path."
            )
    return None


def _same_target(a: Path, b: Path) -> bool:
    """Whether two paths name one file on disk.

    ``os.path.samefile`` is the authority whenever both sides exist: it sees
    through symlinks, hard links and junctions that no amount of string
    comparison would catch. The usual case is an ``--output`` that does not
    exist yet, where there is nothing to stat - there the canonical-path
    comparison decides.
    """
    try:
        if a.exists() and b.exists():
            return os.path.samefile(a, b)
    except OSError:  # pragma: no cover - stat refused; fall back to paths
        pass
    return _canonical(a) == _canonical(b)


def _canonical(path: Path) -> str:
    """A comparable spelling of *path*.

    ``resolve()`` makes it absolute, collapses ``..`` segments and follows
    symlinks, so ``./data/x.jsonl`` and ``data/../data/x.jsonl`` become one
    string. ``normcase`` then folds the case- and separator-insensitivity
    Windows adds. An unresolvable path still normalizes to an absolute one,
    so this never quietly degrades into "these differ".
    """
    try:
        resolved = path.resolve()
    except OSError:  # pragma: no cover - e.g. a nonexistent drive letter
        resolved = Path(os.path.abspath(path))
    return os.path.normcase(str(resolved))


def _missing_ml_dependencies() -> list[str]:
    """Which of :data:`ML_DEPENDENCIES` cannot be imported, in order.

    Uses ``find_spec`` rather than importing: the answer is needed at
    startup, importing scikit-learn is expensive, and a runner that has not
    been asked for DGA must not pay for the ML extra at all.
    """
    missing: list[str] = []
    for module in ML_DEPENDENCIES:
        try:
            found = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            # A broken or shadowed package on the path counts as missing.
            found = False
        if not found:
            missing.append(module)
    return missing


def _phrase(missing: list[str]) -> str:
    """``"sklearn is"`` / ``"sklearn and joblib are"`` - for one log line."""
    names = ", ".join(missing[:-1])
    joined = f"{names} and {missing[-1]}" if names else missing[-1]
    return f"{joined} {'is' if len(missing) == 1 else 'are'}"


def _attach_stderr_logging(*, quiet: bool) -> tuple[logging.Handler, int]:
    """Send this package's logs to stderr, and nowhere else.

    Deliberately not ``logging.basicConfig``: that is a no-op the moment the
    host process has already configured logging, which would silently drop
    this guarantee - and if that ambient configuration happened to write to
    stdout, it would interleave log lines with the alert JSONL and corrupt
    the output. Attaching a handler directly and turning off propagation
    makes "stdout is alerts, stderr is everything else" true regardless of
    what else has configured logging.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))

    package_logger = logging.getLogger("detection_core")
    previous_level = package_logger.level
    package_logger.addHandler(handler)
    package_logger.setLevel(logging.ERROR if quiet else logging.INFO)
    package_logger.propagate = False
    return handler, previous_level


def _detach_logging(handler: logging.Handler, previous_level: int) -> None:
    """Undo :func:`_attach_stderr_logging` so repeat calls do not stack up.

    The level is restored along with the handler and the propagation flag.
    Leaving it raised outlives the run: an embedder that calls ``main()``
    with ``--quiet`` and then uses this package's logging would find its own
    warnings silently filtered out, long after the run they belonged to.
    """
    package_logger = logging.getLogger("detection_core")
    package_logger.removeHandler(handler)
    package_logger.setLevel(previous_level)
    package_logger.propagate = True
    handler.close()


def _build_sink(args: argparse.Namespace) -> tuple[AlertSink, JsonlAlertSink | None]:
    """JSONL always; the backend as an additional destination when asked."""
    if args.output is not None:
        stream = open(args.output, "w", encoding="utf-8")
        jsonl_sink = JsonlAlertSink(stream, close_stream=True)
    else:
        jsonl_sink = JsonlAlertSink(sys.stdout)

    if args.api_url:
        http_sink = HttpAlertSink(args.api_url, timeout=args.api_timeout)
        return MultiSink([jsonl_sink, http_sink]), jsonl_sink
    return jsonl_sink, jsonl_sink


if __name__ == "__main__":  # pragma: no cover - exercised via main()
    sys.exit(main())
