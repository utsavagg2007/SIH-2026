"""Question parsing. Deterministic by design, so the tests are exhaustive
about the vocabulary rather than sampling it.
"""

from __future__ import annotations

from analyst.queryplan import plan

NOW = 1_800_000_000.0


def test_relative_window_with_count():
    q = plan("what happened in the last 3 hours", now=NOW)
    assert q.from_ts == NOW - 3 * 3600
    assert q.to_ts == NOW
    assert q.window_label == "in the last 3 hours"


def test_relative_window_without_count_defaults_to_one():
    q = plan("show me every host that beaconed in the last hour", now=NOW)
    assert q.from_ts == NOW - 3600
    assert q.window_label == "in the last 1 hour"
    assert q.threat_class == "c2_beaconing"


def test_today_maps_to_24_hours():
    q = plan("anything critical today", now=NOW)
    assert q.from_ts == NOW - 86400
    assert q.severity == "critical"


def test_longest_phrase_wins_for_threat_class():
    # "tunnel" alone must not shadow the more specific "dns tunnel".
    assert plan("any dns tunnelling?", now=NOW).threat_class == "dns_tunnelling"


def test_synonyms_map_to_the_frozen_enum():
    assert plan("who is scanning us", now=NOW).threat_class == "port_scan"
    assert plan("any callback traffic", now=NOW).threat_class == "c2_beaconing"
    assert plan("show syn flood activity", now=NOW).threat_class == "ddos"
    assert plan("unusual ja3 fingerprints", now=NOW).threat_class == "encrypted_malware"
    assert plan("data exfiltration attempts", now=NOW).threat_class == "data_exfiltration"
    assert plan("domain generation algorithm hits", now=NOW).threat_class == "dga_domain"


def test_ipv4_is_extracted_as_the_host_filter():
    assert plan("what did 10.4.2.19 do", now=NOW).host == "10.4.2.19"


def test_unrecognised_question_says_so_rather_than_guessing():
    q = plan("is everything fine", now=NOW)
    assert q.is_unfiltered
    assert q.understood == ["no filter recognised; searching the most recent alerts"]
