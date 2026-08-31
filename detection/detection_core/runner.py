"""Command-line runner: ingestion JSONL in, ThreatAlerts out.

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

Three input modes
-----------------

Everything below this layer already streams - the adapter is a generator,
``DetectionEngine.run`` is a generator, and alerts are flushed one at a time -
but this entry point used to accept only a finished file, which made the whole
package file-in/file-out from the outside. It now takes a live stream too:

``features.jsonl``
    A capture on disk, read once, end to end. Telemetry calls this
    ``"replay"``: the rate measured is how fast the file is being consumed,
    not the rate of any link.

``-``
    Read flows from **stdin**, so ingestion can be piped straight in::

        python -m ingestion.pipeline ... -o - \\
            | python -m detection_core.runner - \\
                --api-url http://localhost:8000/api/v1/alerts

    The run ends when the producer closes the pipe. Nothing on disk is named,
    so the ``is_file()`` check and the input half of the ``--output``
    collision check do not apply - the rest of that check still does, because
    ``--output`` can still be aimed at the model or the config.

``--follow``
    Keep reading a file after EOF, like ``tail -f``, for a capture something
    else is still appending to. Only whole lines are handed on: a writer
    caught mid-record would otherwise hand the adapter half a JSON object,
    which it would count as a parse error rather than waiting for the rest.

Both streaming modes report themselves as ``"live_capture"`` and install a
SIGINT handler so Ctrl-C ends the run through the normal path - flushing
sinks, settling deferred delivery and printing the counts - rather than
unwinding through a traceback. A second Ctrl-C aborts immediately, which is
the way out when a wedged backend is holding up the shutdown.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Iterator

from .adapters import IngestionJsonlAdapter
from .config import ConfigError, DetectorSettings, load_detector_settings
from .fingerprints import FingerprintError, load_fingerprint_feed
from .pipeline import (
    DEFAULT_API_TIMEOUT,
    DEFAULT_BULK_SIZE,
    MAX_BULK_SIZE,
    AlertSink,
    BulkHttpAlertSink,
    HttpAlertSink,
    JsonlAlertSink,
    MultiSink,
    QueuedAlertSink,
    TelemetryReporter,
    build_default_detectors,
    run_detection,
)

__all__ = ["DEFAULT_DGA_MODEL_PATH", "build_parser", "main"]

logger = logging.getLogger("detection_core.runner")

EXIT_OK = 0
EXIT_ERROR = 1
#: The capture was processed end to end, but some alerts never reached the
#: ``--api-url`` backend. Distinct from EXIT_ERROR so a caller can tell "the
#: run did not happen" from "the run happened and the backend missed some".
EXIT_DELIVERY_DEGRADED = 2

#: The input spelling that means "read flows from stdin".
#:
#: ``-`` rather than a flag, because it is the convention every other tool in
#: this pipeline already follows (``ingestion/pipeline.py -o -`` writes to
#: stdout), and because it keeps the input a single positional argument in
#: both modes.
STDIN_ARG = "-"

#: Where a built DGA model is expected to sit, and the default for
#: ``--dga-model`` when something is actually there.
#:
#: A model is a build product, not source: it is not importable from the
#: package and nothing in ``detection_core`` may depend on it existing. But
#: the previous arrangement - no default at all - meant every default run
#: silently omitted ``dga_domain``, and the only sign was one INFO line.
#:
#: So the artifact is *discovered*, never required. If the file is there and
#: the ML extra is importable, DGA joins the line-up; if either is missing the
#: other six detectors run exactly as before. The distinction that matters is
#: explicit versus discovered: a ``--dga-model`` the user typed and that
#: cannot be loaded is an error, because they asked for it by name, while a
#: discovered one that cannot be loaded is a log line.
#:
#: ``parents[2]`` walks ``detection_core/runner.py`` -> ``detection`` -> the
#: repository root. Installed anywhere else the path simply will not exist,
#: which lands on the "no artifact" path rather than on an error.
DEFAULT_DGA_MODEL_PATH = (
    Path(__file__).resolve().parents[2] / "artifacts" / "dga_model.joblib"
)

#: Seconds between polls of a followed file that has stopped growing.
#:
#: A compromise, and a cheap one either way: too long adds latency to a live
#: alert, too short spends syscalls on an idle file. Half a second is well
#: inside the time any dashboard takes to redraw.
DEFAULT_FOLLOW_POLL = 0.5

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
        help=(
            "ingestion-style JSONL file (one flow record per line), or '-' to "
            "read flows from stdin as they arrive"
        ),
    )
    parser.add_argument(
        "--follow",
        action="store_true",
        help=(
            "keep reading the input file after EOF, like 'tail -f', for a "
            "capture something else is still appending to. Not valid with '-': "
            "stdin already blocks until the producer closes it"
        ),
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
            "trained DGA model bundle. Defaults to "
            f"{DEFAULT_DGA_MODEL_PATH} when that file exists; when it does "
            "not, the other six detectors run without DGA"
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
        "--api-batch",
        type=int,
        default=None,
        metavar="N",
        help=(
            "post alerts to <api-url>/bulk in batches of N instead of one per "
            f"request (1-{MAX_BULK_SIZE}; {DEFAULT_BULK_SIZE} is a sensible "
            "choice). A partial batch is still sent within a couple of "
            "seconds, so a quiet link does not hold alerts back"
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
        "--telemetry-url",
        default=None,
        metavar="URL",
        help=(
            "POST processing rates (flows/sec, packets/sec, Mb/s, detectors "
            "online) here about once a second, for the dashboard's throughput "
            "panel (e.g. http://localhost:8000/api/v1/telemetry). Without "
            "this the backend cannot tell a quiet network from a dead sensor"
        ),
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
    streaming = _is_stdin(args.input) or args.follow

    # --- startup: anything misconfigured must fail before any flow is read,
    # and - critically - before the output file is opened, since opening it
    # truncates whatever is already there.
    problem = _argument_problem(args)
    if problem is not None:
        logger.error("%s", problem)
        return EXIT_ERROR

    # Resolved before the collision check on purpose: a *discovered* model
    # bundle has to be protected from --output exactly like a named one, and
    # the check can only protect a path it has been told about.
    explicit_dga = args.dga_model is not None
    if not explicit_dga and DEFAULT_DGA_MODEL_PATH.is_file():
        args.dga_model = DEFAULT_DGA_MODEL_PATH

    collision = _output_collision(args)
    if collision is not None:
        logger.error("%s", collision)
        return EXIT_ERROR

    try:
        settings = _detector_settings(args)
    except (ConfigError, FingerprintError) as exc:
        logger.error("%s", exc)
        return EXIT_ERROR

    try:
        detectors = _build_detectors(args, settings, explicit=explicit_dga)
    except _StartupError as exc:
        logger.error("%s", exc)
        return EXIT_ERROR

    try:
        sink, jsonl_sink = _build_sink(args)
    except (OSError, ValueError) as exc:
        logger.error("could not open alert output: %s", exc)
        return EXIT_ERROR

    telemetry = None
    if args.telemetry_url:
        try:
            telemetry = TelemetryReporter(
                args.telemetry_url,
                # A replay's flows/sec is the rate the *file* is being read
                # at, which is not a link rate and must not be shown as one.
                # The backend's panel labels the reading from this field.
                source="live_capture" if streaming else "replay",
                timeout=args.api_timeout,
                log=logger,
            )
        except ValueError as exc:
            logger.error("could not start telemetry reporting: %s", exc)
            sink.close()
            return EXIT_ERROR

    names = ", ".join(d.name for d in detectors)
    logger.info("detectors: %s", names)
    if args.dga_model is None:
        logger.info(
            "dga_domain not registered (no --dga-model, and no model at %s)",
            DEFAULT_DGA_MODEL_PATH,
        )
    elif not explicit_dga:
        logger.info("dga_domain using the model found at %s", args.dga_model)
    logger.info("reading %s", _describe_input(args))

    adapter = IngestionJsonlAdapter(path=None if streaming else args.input)
    stop = threading.Event()
    try:
        # Ctrl-C is only intercepted for a run that would not otherwise end on
        # its own. A file replay keeps the default handler, so nothing about
        # the existing behaviour changes.
        with _interrupt_stops(stop, enabled=streaming):
            # Delivery failures no longer end the run: run_detection logs and
            # counts them, and the whole capture is still processed. They are
            # reported below, and in the exit code.
            stats = run_detection(
                _build_source(args, adapter, stop),
                sink,
                detectors,
                log=logger,
                telemetry=telemetry,
            )
    except OSError as exc:
        logger.error("i/o error during run: %s", exc)
        return EXIT_ERROR
    finally:
        sink.close()
        if telemetry is not None:
            telemetry.close()

    if stop.is_set():
        logger.info("interrupted; stopped reading and flushed what was pending")

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
    if telemetry is not None:
        logger.info(
            "telemetry: %d report(s) sent to %s, %d failed, %d superseded "
            "before sending",
            telemetry.sent,
            args.telemetry_url,
            telemetry.failures,
            telemetry.samples_dropped,
        )

    # A dropped alert and a failed one differ in cause but not in
    # consequence: either way the backend does not have it. Both make the run
    # degraded, or a queue overflow would exit clean.
    missed = stats.delivery_failures + stats.alerts_dropped
    if missed:
        # The run finished; the backend's copy did not. Say so plainly and
        # exit non-zero, so a scheduled replay cannot look successful while
        # the backend is missing alerts.
        logger.error(
            "DEGRADED: %d of %d alert(s) did not reach %s (%d failed delivery, "
            "%d dropped from the delivery queue)%s",
            missed,
            stats.alerts,
            args.api_url,
            stats.delivery_failures,
            stats.alerts_dropped,
            (
                f"; all {stats.alerts} alert(s) are in {args.output}"
                if args.output is not None
                else "; alert JSONL on stdout is complete"
            ),
        )
        return EXIT_DELIVERY_DEGRADED

    return EXIT_OK


# --------------------------------------------------------------------------
# Input modes
# --------------------------------------------------------------------------


def _is_stdin(path: Path) -> bool:
    """Whether the input argument is the ``-`` that means stdin."""
    return str(path) == STDIN_ARG


def _describe_input(args: argparse.Namespace) -> str:
    """One phrase naming the mode, for the startup log line."""
    if _is_stdin(args.input):
        return "flows from stdin (live stream; ends when the producer closes it)"
    if args.follow:
        return f"{args.input}, following it past EOF"
    return f"{args.input} (replay)"


def _build_source(
    args: argparse.Namespace, adapter: IngestionJsonlAdapter, stop: threading.Event
):
    """The flow stream for this run's input mode.

    All three modes end at ``from_lines``, which is where parsing, drift
    warnings and per-line error accounting live - so a streamed record is
    validated exactly as a replayed one is, and ``adapter.stats`` means the
    same thing afterwards whichever mode ran.
    """
    if _is_stdin(args.input):
        # sys.stdin iterates line by line and yields each as the producer
        # flushes it. Nothing is read ahead, so an alert can be emitted for a
        # flow while the producer is still writing the next one.
        return adapter.from_lines(sys.stdin)
    if args.follow:
        return adapter.from_lines(_follow_lines(args.input, stop=stop))
    return adapter.from_path(args.input)


def _follow_lines(
    path: Path,
    *,
    stop: threading.Event,
    poll_interval: float = DEFAULT_FOLLOW_POLL,
) -> Iterator[str]:
    """Yield lines from *path*, waiting for more instead of stopping at EOF.

    **Only whole lines are yielded.** A writer that has flushed half a record
    leaves the file ending mid-line, and ``readline`` hands that fragment back
    immediately; passing it on would make the adapter count a parse error for
    a record that is merely incomplete, and then count a second one for the
    remainder. So a fragment is held until its newline arrives.

    Ends when *stop* is set - which is what the SIGINT handler does - and only
    at a poll boundary, so a partially written trailing line is never emitted
    as though it were complete. The file is opened once and read forward;
    truncation or rotation underneath is not handled, because the appending
    producer this exists for does neither.
    """
    with open(path, "r", encoding="utf-8") as handle:
        pending = ""
        while True:
            chunk = handle.readline()
            if chunk:
                pending += chunk
                if pending.endswith("\n"):
                    yield pending
                    pending = ""
                continue
            if stop.is_set():
                return
            time.sleep(poll_interval)


@contextlib.contextmanager
def _interrupt_stops(stop: threading.Event, *, enabled: bool):
    """Turn the first Ctrl-C into "stop reading" rather than a traceback.

    A followed file and a live stdin pipe have no natural end, so Ctrl-C is
    the normal way to stop them - and the default handler makes that an
    exception thrown through the middle of the run, which skips settling the
    delivery queue and printing the counts. Setting an event instead lets the
    source generator return, so the run finishes through exactly the same path
    a replay does.

    The previous handler is restored on the way out, and the default one is
    put back as soon as the first signal arrives: a second Ctrl-C then aborts
    immediately, which is the only way out if a wedged backend is holding up
    the shutdown. ``signal.signal`` only works on the main thread, so an
    embedder calling ``main()`` from a worker keeps the default behaviour
    rather than crashing.
    """
    if not enabled:
        yield
        return

    def handle(signum, frame):  # pragma: no cover - exercised by signalling
        stop.set()
        signal.signal(signal.SIGINT, previous)

    try:
        previous = signal.signal(signal.SIGINT, handle)
    except (ValueError, OSError):  # pragma: no cover - not the main thread
        yield
        return
    try:
        yield
    finally:
        with contextlib.suppress(ValueError, OSError):
            signal.signal(signal.SIGINT, previous)


# --------------------------------------------------------------------------
# Startup validation
# --------------------------------------------------------------------------


class _StartupError(Exception):
    """A misconfiguration that must stop the run before any flow is read."""


def _argument_problem(args: argparse.Namespace) -> str | None:
    """The first reason these arguments cannot produce a run, or ``None``.

    Everything here is decided from the arguments alone plus one ``is_file``
    stat. Nothing is opened, so a rejected run leaves the filesystem exactly
    as it found it - which is the whole point of validating before the output
    sink truncates its target.
    """
    if _is_stdin(args.input):
        if args.follow:
            return (
                "--follow cannot be combined with '-': stdin already delivers "
                "lines as the producer writes them and ends only when the "
                "producer closes it, so there is no EOF to re-read - "
                "following one would spin on it. Drop --follow."
            )
    elif not args.input.is_file():
        return f"input file not found: {args.input}"

    if args.api_batch is not None:
        if not args.api_url:
            return "--api-batch only means something with --api-url; add one or drop the other"
        if not 1 <= args.api_batch <= MAX_BULK_SIZE:
            return (
                f"--api-batch must be between 1 and {MAX_BULK_SIZE} (the "
                f"backend's own per-request cap), got {args.api_batch}"
            )
    return None


def _build_detectors(
    args: argparse.Namespace, settings: DetectorSettings, *, explicit: bool
) -> list:
    """Every detector for this run, with DGA attached when it can be.

    ``explicit`` says whether ``--dga-model`` was typed. It decides what a
    model that cannot be loaded costs: a named one is an error, because the
    user asked for that model by name and running six detectors while they
    believe seven are running is worse than refusing to start. A *discovered*
    one is a warning and the run continues without it - a stale or half-built
    artifact in ``artifacts/`` must not be able to take the six rule
    detectors offline.

    Mutates ``args.dga_model`` back to ``None`` when a discovered model is
    dropped, so every later line - the log, the collision check's record of
    what was read - describes the run that actually happened.
    """
    missing = _missing_ml_dependencies() if args.dga_model is not None else []
    if missing:
        if explicit:
            raise _StartupError(
                f"--dga-model was supplied but {_phrase(missing)} not "
                f"importable. {ML_EXTRA_HINT}"
            )
        logger.info(
            "a DGA model is present at %s but %s not importable, so "
            "dga_domain stays disabled. %s",
            args.dga_model,
            _phrase(missing),
            ML_EXTRA_HINT,
        )
        args.dga_model = None

    try:
        return build_default_detectors(
            dga_model_path=args.dga_model, settings=settings
        )
    except ImportError as exc:
        # find_spec found the modules but importing one failed - a broken or
        # half-installed extra. Still the user's dependency problem, so it
        # gets the same clear message rather than an internal traceback.
        if explicit or args.dga_model is None:
            raise _StartupError(f"DGA could not be loaded: {exc}. {ML_EXTRA_HINT}") from exc
        reason = f"{exc}. {ML_EXTRA_HINT}"
    except (FileNotFoundError, ValueError, RuntimeError, TypeError) as exc:
        if explicit or args.dga_model is None:
            raise _StartupError(f"could not build detectors: {exc}") from exc
        reason = str(exc)

    logger.warning(
        "the DGA model found at %s could not be loaded, so dga_domain stays "
        "disabled and the other detectors run as normal: %s",
        args.dga_model,
        reason,
    )
    args.dga_model = None
    try:
        return build_default_detectors(dga_model_path=None, settings=settings)
    except (ImportError, FileNotFoundError, ValueError, RuntimeError, TypeError) as exc:
        raise _StartupError(f"could not build detectors: {exc}") from exc


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

    The one input this cannot be about is ``-``, which names no file: there is
    nothing on disk for ``--output`` to collide with, and comparing against it
    would reject a perfectly good ``--output ./-``. Every *other* entry still
    applies in stdin mode, because ``--output`` aimed at the model bundle or
    the settings file destroys them whatever the input mode is.

    Returns the message to log, or ``None`` when the destinations are
    genuinely distinct. Nothing here opens, creates or modifies a file.
    """
    if args.output is None:  # stdout: nothing on disk to overwrite
        return None

    for label, source in (
        ("input file", None if _is_stdin(args.input) else args.input),
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
    """JSONL always; the backend as an additional destination when asked.

    The local JSONL sink stays **on the detection thread**, and the backend
    sink is the only one moved off it. That asymmetry is deliberate. Writing a
    line to an open file is microseconds and cannot be slowed by anything on
    the network, so putting it behind a queue would buy nothing and cost the
    guarantee that matters most here: the local record is the copy that is
    always complete, the one the DEGRADED message points at when the backend
    has missed alerts. It can only keep that promise if it is never the sink
    that drops.

    The backend sink is wrapped in :class:`QueuedAlertSink`, so ``emit``
    returns as soon as the alert is queued and a slow or unreachable backend
    can no longer set the pace of detection.

    ``--api-batch`` swaps one-alert-per-request for the bulk route. It goes
    *inside* the queue rather than replacing it: batching cuts the number of
    round trips, it does not make any one of them non-blocking, and it is the
    blocking that stalled detection.
    """
    if args.output is not None:
        stream = open(args.output, "w", encoding="utf-8")
        jsonl_sink = JsonlAlertSink(stream, close_stream=True)
    else:
        jsonl_sink = JsonlAlertSink(sys.stdout)

    if args.api_url:
        backend: AlertSink
        if args.api_batch:
            backend = BulkHttpAlertSink(
                _bulk_url(args.api_url),
                batch_size=args.api_batch,
                timeout=args.api_timeout,
                log=logger,
            )
        else:
            backend = HttpAlertSink(args.api_url, timeout=args.api_timeout)
        return MultiSink([jsonl_sink, QueuedAlertSink(backend, log=logger)]), jsonl_sink
    return jsonl_sink, jsonl_sink


def _bulk_url(api_url: str) -> str:
    """``.../api/v1/alerts`` -> ``.../api/v1/alerts/bulk``.

    Derived rather than asked for separately: the two routes are the same
    resource and a second URL flag would only create a way to point them at
    different backends. A URL that already ends in ``/bulk`` is left alone, so
    naming the bulk route outright also works.
    """
    trimmed = api_url.rstrip("/")
    return trimmed if trimmed.endswith("/bulk") else f"{trimmed}/bulk"


if __name__ == "__main__":  # pragma: no cover - exercised via main()
    sys.exit(main())
