"""Dataset-only deterministic Zeek selection without global-default drift."""

from pathlib import Path
from unittest import mock

import pipeline


def test_deterministic_wrapper_mode_keeps_required_zeek_flags():
    script = (
        Path(__file__).parents[1] / "scripts" / "run_zeek.sh"
    ).read_text(encoding="utf-8")
    assert "--canonical|--deterministic" in script
    assert "ZEEK_ARGS=(-D -C -r)" in script
    assert pipeline.run_zeek.__defaults__ == (False, False, False)


def test_explicit_deterministic_mode_selects_wrapper_mode(tmp_path: Path):
    pcap = tmp_path / "fixture.pcap"
    pcap.write_bytes(b"pcap")
    output = tmp_path / "features.jsonl"
    logs = tmp_path / "logs"

    with mock.patch.object(pipeline, "run_zeek") as run_zeek:
        with mock.patch.object(pipeline, "_write_feature_output", return_value=[]):
            pipeline.run_pipeline(
                str(pcap),
                str(logs),
                str(output),
                feature_profile="detector-v2",
                deterministic_zeek=True,
            )

    run_zeek.assert_called_once_with(
        str(pcap), str(logs), False, deterministic_mode=True
    )


def test_global_default_does_not_request_deterministic_mode(tmp_path: Path):
    pcap = tmp_path / "fixture.pcap"
    pcap.write_bytes(b"pcap")
    output = tmp_path / "features.jsonl"
    logs = tmp_path / "logs"

    with mock.patch.object(pipeline, "run_zeek") as run_zeek:
        with mock.patch.object(pipeline, "_write_feature_output", return_value=[]):
            pipeline.run_pipeline(str(pcap), str(logs), str(output))

    run_zeek.assert_called_once_with(str(pcap), str(logs), False)


def test_windows_git_bash_initializes_bundled_posix_tools():
    with mock.patch.object(pipeline.os, "name", "nt"):
        with mock.patch.object(pipeline.Path, "is_file", return_value=True):
            with mock.patch.object(pipeline.subprocess, "run") as run:
                pipeline.run_zeek("capture.pcap", "logs", deterministic_mode=True)

    command = run.call_args.args[0]
    assert command[1:] == [
        "--login",
        str(Path(pipeline.__file__).parent / "scripts" / "run_zeek.sh"),
        "capture.pcap",
        "logs",
        "--deterministic",
    ]
    run.assert_called_once_with(command, check=True)
