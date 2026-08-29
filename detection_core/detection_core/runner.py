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
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .adapters import IngestionJsonlAdapter
from .pipeline import (
    DEFAULT_API_TIMEOUT,
    AlertDeliveryError,
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

    handler = _attach_stderr_logging(quiet=args.quiet)
    try:
        return _run(args)
    finally:
        _detach_logging(handler)


def _run(args: argparse.Namespace) -> int:
    if not args.input.is_file():
        logger.error("input file not found: %s", args.input)
        return EXIT_ERROR

    # --- startup: anything misconfigured must fail before any flow is read.
    try:
        detectors = build_default_detectors(dga_model_path=args.dga_model)
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
        stats = run_detection(adapter, sink, detectors, log=logger)
    except AlertDeliveryError as exc:
        # Do not pretend the alert reached the backend.
        logger.error("alert delivery failed, aborting: %s", exc)
        return EXIT_ERROR
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

    return EXIT_OK


def _attach_stderr_logging(*, quiet: bool) -> logging.Handler:
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
    package_logger.addHandler(handler)
    package_logger.setLevel(logging.ERROR if quiet else logging.INFO)
    package_logger.propagate = False
    return handler


def _detach_logging(handler: logging.Handler) -> None:
    """Undo :func:`_attach_stderr_logging` so repeat calls do not stack up."""
    package_logger = logging.getLogger("detection_core")
    package_logger.removeHandler(handler)
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
