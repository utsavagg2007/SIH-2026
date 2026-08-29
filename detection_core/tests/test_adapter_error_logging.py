"""What the adapter says when it skips a malformed record.

Skipping is not the interesting part - that already worked and is covered by
``test_ingestion_adapter.py``. What this file pins is that the warning left
behind is *usable*: the failing field and the reason, on one line, rather
than a multi-line Pydantic dump whose most prominent content is a
documentation URL.

Nothing here touches which records are accepted. Every test asserts the
skip/parse behaviour is unchanged alongside the message it checks.
"""

from __future__ import annotations

import json
import logging

import pytest

from detection_core.adapters import IngestionJsonlAdapter
from detection_core.adapters.ingestion_jsonl import (
    describe_record_error,
    record_to_flow_event,
)

VALID = {
    "flow_id": "10.0.0.1:10.0.0.2:443:tcp:1747147700.500",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "dst_port": 443,
    "proto": "tcp",
    "duration": 1.25,
    "orig_bytes": 100,
    "resp_bytes": 200,
    "orig_pkts": 2,
    "resp_pkts": 3,
}


def record(**overrides):
    payload = dict(VALID)
    payload.update(overrides)
    return payload


def write(tmp_path, *records):
    path = tmp_path / "features.jsonl"
    path.write_text(
        "\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8"
    )
    return path


def validation_error(**overrides):
    """A real ValidationError from the real model."""
    with pytest.raises(Exception) as caught:
        record_to_flow_event(record(**overrides))
    return caught.value


# --------------------------------------------------------------------------
# The formatting itself
# --------------------------------------------------------------------------


def test_the_failing_field_and_reason_are_both_present():
    message = describe_record_error(validation_error(src_ip=""))

    assert "src_ip" in message
    assert "must be a non-empty string" in message


def test_the_message_does_not_lean_on_the_pydantic_url():
    """The URL is what str(ValidationError) leads with; the field is not."""
    message = describe_record_error(validation_error(dst_port=99999))

    assert "errors.pydantic.dev" not in message
    assert "dst_port" in message
    assert "less than or equal to 65535" in message


def test_the_summary_is_a_single_line():
    """One record, one log line - the shape every other adapter warning has."""
    message = describe_record_error(
        validation_error(src_ip="", dst_port=99999, duration=-1.0)
    )

    assert "\n" not in message


def test_every_failing_field_is_named():
    message = describe_record_error(
        validation_error(src_ip="", dst_port=99999, duration=-1.0)
    )

    for field in ("src_ip", "dst_port", "duration"):
        assert field in message


def test_a_nested_block_field_is_named():
    """Blocks are validated on their own, so the loc is the block's field.

    ``_build_dns`` constructs ``DnsInfo`` separately before ``FlowEvent``, so
    Pydantic reports ``query_length`` rather than ``dns.query_length``. The
    field is still named and the reason still readable, which is what the
    warning needs; prefixing it would mean changing where the adapter
    catches block errors, which is out of scope here.
    """
    message = describe_record_error(validation_error(dns={"query_length": -5}))

    assert "query_length" in message
    assert "greater than or equal to 0" in message
    assert "errors.pydantic.dev" not in message


def test_many_errors_are_capped_but_counted():
    """A record failing everything must not produce an unreadable line."""
    from detection_core.adapters.ingestion_jsonl import _MAX_REPORTED_ERRORS

    message = describe_record_error(
        validation_error(
            src_ip="", dst_ip="", proto="", dst_port=99999,
            duration=-1.0, orig_bytes=-1, resp_bytes=-1, orig_pkts=-1,
        )
    )

    assert message.count(";") <= _MAX_REPORTED_ERRORS
    assert "more field error(s)" in message


def test_a_plain_value_error_is_passed_through_unchanged():
    """The adapter's own messages are already single-line and specific."""
    with pytest.raises(ValueError) as caught:
        record_to_flow_event({**VALID, "flow_id": "no-epoch-here", "timestamp": None})

    assert describe_record_error(caught.value) == str(caught.value)


# --------------------------------------------------------------------------
# Behaviour around the message must be unchanged
# --------------------------------------------------------------------------


def test_a_malformed_record_is_still_skipped_and_counted(tmp_path, caplog):
    path = write(tmp_path, record(src_ip=""), VALID)
    adapter = IngestionJsonlAdapter(path=path)

    with caplog.at_level(logging.WARNING):
        events = list(adapter)

    # Skipped, counted, and the next valid record still parsed.
    assert adapter.stats.total_lines == 2
    assert adapter.stats.validation_errors == 1
    assert adapter.stats.skipped == 1
    assert adapter.stats.parsed == 1
    assert len(events) == 1
    assert events[0].src_ip == "10.0.0.1"


def test_the_emitted_warning_names_the_field(tmp_path, caplog):
    path = write(tmp_path, record(src_ip=""), VALID)

    with caplog.at_level(logging.WARNING):
        list(IngestionJsonlAdapter(path=path))

    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    text = warnings[0]
    assert "line 1" in text
    assert "src_ip" in text
    assert "must be a non-empty string" in text
    assert "errors.pydantic.dev" not in text
    assert "\n" not in text
    # The existing wording is preserved, only its detail is now readable.
    assert "could not build FlowEvent, skipping" in text


def test_valid_input_still_logs_nothing(tmp_path, caplog):
    path = write(tmp_path, VALID, VALID)

    with caplog.at_level(logging.WARNING):
        events = list(IngestionJsonlAdapter(path=path))

    assert len(events) == 2
    assert adapter_warnings(caplog) == []
    assert IngestionJsonlAdapter(path=path).stats.validation_errors == 0


def adapter_warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


def test_invalid_json_handling_is_untouched(tmp_path, caplog):
    """The other skip path still reports the way it always did."""
    path = tmp_path / "broken.jsonl"
    path.write_text("{not json\n" + json.dumps(VALID) + "\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        events = list(IngestionJsonlAdapter(path=path))

    assert len(events) == 1
    assert any("invalid JSON, skipping" in text for text in adapter_warnings(caplog))


def test_strict_mode_still_raises_the_original_exception(tmp_path):
    """Formatting is for the log only - a caller still sees the real error."""
    from pydantic import ValidationError

    path = write(tmp_path, record(src_ip=""), VALID)

    with pytest.raises(ValidationError):
        list(IngestionJsonlAdapter(path=path, strict=True))
