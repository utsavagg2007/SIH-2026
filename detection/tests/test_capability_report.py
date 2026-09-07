"""A run that could not have seen a threat class must say so.

These pin the difference between "looked and found nothing" and "could not
have looked", which are the same silence from outside the process. The cases
below are the ones ordinary use produces: ingestion left on its default
``legacy-m1d`` profile, and Zeek run without the qualified TLS-fingerprint
runtime.
"""

from __future__ import annotations

import json

import pytest

from detection_core.adapters.capability import ObservableCapability
from detection_core.adapters.ingestion_jsonl import IngestionJsonlAdapter
from detection_core.schemas import FlowEvent


def _events(records: list[dict]) -> list[FlowEvent]:
    lines = [json.dumps(record) for record in records]
    return list(IngestionJsonlAdapter().from_lines(lines))


def _base(**overrides) -> dict:
    record = {
        "flow_id": "10.0.0.1:10.0.0.2:443:tcp:1700000000.0",
        "timestamp": 1700000000.0,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "proto": "tcp",
        "duration": 1.0,
        "orig_bytes": 100,
        "resp_bytes": 200,
        "orig_pkts": 2,
        "resp_pkts": 2,
    }
    record.update(overrides)
    return record


def _report(records: list[dict]) -> ObservableCapability:
    capability = ObservableCapability()
    for event in capability.watch(_events(records)):
        assert isinstance(event, FlowEvent)
    return capability


# --- the fully-equipped case stays silent ------------------------------


def test_a_capture_carrying_everything_reports_nothing():
    """A detector-v2 capture with a fingerprinting Zeek run has no limits."""
    report = _report(
        [
            _base(
                conn_state="SF",
                dns={"query": "example.test", "qtype": "A"},
                tls={
                    "ja3": "3207ef9f2e951242b53b44f07d8439d0",
                    "ja3s": "cce84e7a8b742462e40afb585a3e3ccc",
                    "ja4": "t13d020200_c1929292aa6b_b9a491fefe05",
                    "server_name": "tls.example.test",
                },
            )
        ]
    )
    assert report.notes() == []
    assert report.flows == 1


def test_an_empty_run_reports_nothing():
    """No flows means no evidence either way, so no claim is made."""
    assert ObservableCapability().notes() == []


# --- conn_state -------------------------------------------------------


def test_a_flow_without_conn_state_names_the_detectors_it_degrades():
    report = _report([_base()])
    (note,) = report.notes()
    assert "1 of 1 flow(s) carried no conn_state" in note
    assert "port_scan" in note and "ddos" in note
    assert "S0" in note
    assert "detector-v2" in note


def test_conn_state_decoded_from_the_legacy_encoding_still_counts_as_present():
    """Only a genuinely absent state is reported - a decoded one is real."""
    report = _report([_base(conn_state_encoded=4)])
    assert report.without_conn_state == 0
    assert report.notes() == []


def test_the_conn_state_note_counts_only_the_flows_that_lacked_it():
    report = _report([_base(conn_state="SF"), _base(), _base()])
    (note,) = report.notes()
    assert "2 of 3 flow(s)" in note


# --- dns --------------------------------------------------------------


def test_dns_without_a_raw_query_reports_dga_could_not_fire():
    report = _report(
        [_base(conn_state="SF", dns={"query_length": 11, "label_count": 2})]
    )
    (note,) = report.notes()
    assert "dga_domain" in note
    assert "dns_tunnelling" in note
    assert "1 DNS flow(s)" in note


def test_one_raw_query_is_enough_to_withdraw_the_dns_claim():
    """The note says *no* query arrived; one that did makes it untrue."""
    report = _report(
        [
            _base(conn_state="SF", dns={"query_length": 11}),
            _base(conn_state="SF", dns={"query": "example.test"}),
        ]
    )
    assert report.notes() == []
    assert report.dns_with_query == 1


def test_a_capture_with_no_dns_at_all_makes_no_dns_claim():
    report = _report([_base(conn_state="SF")])
    assert report.dns_flows == 0
    assert report.notes() == []


# --- tls --------------------------------------------------------------


def test_tls_without_fingerprints_reports_the_signature_path_dark():
    report = _report(
        [_base(conn_state="SF", tls={"server_name": "tls.example.test"})]
    )
    (note,) = report.notes()
    assert "encrypted_malware" in note
    assert "ja3" in note
    # Both causes named: the Zeek runtime and the ingestion profile.
    assert "TLS-fingerprint runtime" in note
    assert "detector-v2" in note
    # The metadata path still works here, and the note must not imply otherwise.
    assert "SNI-metadata path is unaffected" in note


def test_tls_without_a_server_name_reports_the_metadata_path_dark():
    report = _report(
        [_base(conn_state="SF", tls={"ja3": "3207ef9f2e951242b53b44f07d8439d0"})]
    )
    (note,) = report.notes()
    assert "server_name" in note
    assert "SNI-metadata path" in note


@pytest.mark.parametrize("field", ["ja3", "ja3s", "ja4"])
def test_any_one_fingerprint_counts_as_a_fingerprint(field):
    report = _report([_base(conn_state="SF", tls={field: "x", "server_name": "a.test"})])
    assert report.tls_with_fingerprint == 1
    assert report.notes() == []


def test_a_bare_legacy_capture_reports_every_gap_at_once():
    """What ``pipeline.py`` produces on its default profile, end to end."""
    report = _report(
        [
            _base(conn_state_encoded=0, dns={"query_length": 11}),
            _base(conn_state_encoded=0, tls={"has_ja3": False, "ssl_version_encoded": 3}),
        ]
    )
    notes = " | ".join(report.notes())
    assert "conn_state" in notes
    assert "dga_domain" in notes
    assert "encrypted_malware" in notes
    assert len(report.notes()) == 4


# --- streaming --------------------------------------------------------


def test_watch_streams_rather_than_buffering():
    """It sits in a streaming pipeline, so it must not collect the capture."""
    consumed = 0

    def source():
        nonlocal consumed
        for _ in range(3):
            consumed += 1
            yield _events([_base(conn_state="SF")])[0]

    report = ObservableCapability()
    stream = report.watch(source())
    next(stream)
    assert consumed == 1, "watch() pulled more than the one event requested"
    assert report.flows == 1


# --- the runner wiring ------------------------------------------------
#
# Everything above tests the counter in isolation. These test the only thing
# that makes it matter: that a real ``runner.main()`` run actually prints the
# notes. Without them, ``capability.watch(...)`` could be dropped from the
# source chain in a refactor and every other test in this file would still
# pass while real runs went back to reporting a blind capture as a clean one -
# which is the exact failure this feature exists to prevent.


def _write(tmp_path, name, records):
    path = tmp_path / name
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8"
    )
    return path


def _degraded(capsys):
    """The ``degraded:`` lines a real run puts in front of the operator.

    Read from stderr rather than through ``caplog``: the runner deliberately
    sets ``propagate = False`` on the package logger so that stdout carries
    alert JSONL and nothing else, which puts these records permanently out of
    reach of a root-level capture. Stderr is where they are contracted to
    appear, so stderr is what this asserts on.
    """
    return [
        line
        for line in capsys.readouterr().err.splitlines()
        if "degraded: " in line
    ]


def _legacy_records():
    """What ``pipeline.py`` emits on its default ``legacy-m1d`` profile.

    No raw ``conn_state`` (Zeek's ``S0`` encodes to 0, which decodes back to
    None), no raw ``dns.query``, no ``ja3``/``ja3s``/``ja4``, no
    ``server_name`` - only the derived numbers.
    """
    return [
        _base(
            conn_state_encoded=0,
            dst_port=1000 + index,
            dns={"uid": f"Cdns{index}", "query_length": 24, "label_count": 3},
            tls={"uid": f"Ctls{index}", "has_ja3": False, "ssl_version_encoded": 3},
        )
        for index in range(5)
    ]


def _detector_v2_records():
    """The same flows under ``--feature-profile detector-v2``, fingerprinted."""
    return [
        _base(
            conn_state="S0",
            dst_port=1000 + index,
            dns={"uid": f"Cdns{index}", "query": f"host{index}.example.test",
                 "qtype": "A", "rcode": "NOERROR"},
            tls={"uid": f"Ctls{index}",
                 "ja3": "3207ef9f2e951242b53b44f07d8439d0",
                 "ja3s": "cce84e7a8b742462e40afb585a3e3ccc",
                 "ja4": "t13d020200_c1929292aa6b_b9a491fefe05",
                 "server_name": "tls.example.test"},
        )
        for index in range(5)
    ]


def test_the_runner_reports_a_legacy_capture_as_degraded(tmp_path, capsys):
    from detection_core import runner

    path = _write(tmp_path, "legacy.jsonl", _legacy_records())
    assert runner.main([str(path), "--output", str(tmp_path / "a.jsonl")]) == 0

    notes = " | ".join(_degraded(capsys))
    assert notes, "a capture with no raw observables reported no limitation"
    # Each blinded detector is named, so the operator knows what the silence
    # in the alert stream does and does not mean.
    assert "conn_state" in notes and "port_scan" in notes and "ddos" in notes
    assert "dga_domain" in notes
    assert "encrypted_malware" in notes


def test_the_runner_stays_silent_on_a_detector_v2_capture(tmp_path, capsys):
    """A capture that carried everything must make no claim at all."""
    from detection_core import runner

    path = _write(tmp_path, "v2.jsonl", _detector_v2_records())
    assert runner.main([str(path), "--output", str(tmp_path / "a.jsonl")]) == 0

    assert _degraded(capsys) == []


def test_the_notes_reach_the_operator_at_warning_level(tmp_path, capsys):
    """WARNING, not INFO: the runner logs at INFO by default, so an INFO note
    would be indistinguishable from ordinary progress chatter."""
    from detection_core import runner

    path = _write(tmp_path, "legacy.jsonl", _legacy_records())
    runner.main([str(path), "--output", str(tmp_path / "a.jsonl")])

    notes = _degraded(capsys)
    assert notes
    assert all(line.startswith("WARNING detection_core.runner: ") for line in notes)


def test_a_quiet_run_suppresses_the_notes_like_every_other_warning(tmp_path, capsys):
    """``--quiet`` means "errors only"; these are not errors, so they go.

    Pinned so the behaviour is a decision rather than an accident: a run that
    asked for silence gets it, and the notes are not special-cased past it.
    """
    from detection_core import runner

    path = _write(tmp_path, "legacy.jsonl", _legacy_records())
    runner.main([str(path), "--output", str(tmp_path / "a.jsonl"), "--quiet"])

    assert _degraded(capsys) == []
