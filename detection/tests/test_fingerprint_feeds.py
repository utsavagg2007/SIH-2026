"""Loading local JA3/JA3S/JA4 fingerprints, and matching on them end to end.

Every fingerprint in this file is invented. They are hex strings of the right
shape and nothing more - no real indicator is committed to this repository,
and none is downloaded at test time or at run time.

The tests cover three layers: the feed parser on its own, the parsed sets
reaching ``EncryptedMalwareDetector`` through configuration, and the whole
path from a JSONL file through the runner to a ThreatAlert on disk.
"""

from __future__ import annotations

import json

import pytest

from detection_core import (
    EncryptedMalwareConfig,
    EncryptedMalwareDetector,
    ScoreType,
    ThreatClass,
    TlsInfo,
    build_default_detectors,
    runner,
)
from detection_core.config import DetectorSettings, load_detector_settings
from detection_core.fingerprints import (
    FINGERPRINT_TYPES,
    FingerprintError,
    load_fingerprint_feed,
    normalize_fingerprint,
)

from .conftest import make_flow

# Synthetic. Not indicators of anything.
JA3 = "0123456789abcdef0123456789abcdef"
JA3S = "fedcba9876543210fedcba9876543210"
JA4 = "t13d1516h2_8daaf6152771_02713d6af862"
OTHER_JA3 = "00112233445566778899aabbccddeeff"

SRC = "10.0.0.60"
DST = "203.0.113.44"


def write_feed(tmp_path, text: str, name: str = "feed.txt"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def tls_flow(timestamp: float = 1000.0, **tls):
    return make_flow(
        src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp", timestamp=timestamp,
        tls=TlsInfo(uid="Ctls", server_name="www.example.com", version="TLSv13",
                    has_ja3=True, has_ja3s=True, **tls),
    )


# --------------------------------------------------------------------------
# 7-9, 14. Feed syntax
# --------------------------------------------------------------------------


def test_typed_entries_load_into_their_own_sets(tmp_path):
    path = write_feed(tmp_path, f"ja3:{JA3}\nja3s:{JA3S}\nja4:{JA4}\n")

    feed = load_fingerprint_feed(path)

    assert feed["ja3"] == frozenset({JA3})
    assert feed["ja3s"] == frozenset({JA3S})
    assert feed["ja4"] == frozenset({JA4})
    assert set(feed) == set(FINGERPRINT_TYPES)


def test_comments_and_blank_lines_are_ignored(tmp_path):
    path = write_feed(
        tmp_path,
        f"# handover list\n\n   \nja3:{JA3}\n\n# trailing note\n",
    )

    assert load_fingerprint_feed(path)["ja3"] == frozenset({JA3})


def test_a_bare_md5_is_read_as_ja3(tmp_path):
    """The shape of most public JA3 lists."""
    path = write_feed(tmp_path, f"{OTHER_JA3}\n")

    feed = load_fingerprint_feed(path)

    assert feed["ja3"] == frozenset({OTHER_JA3})
    assert feed["ja3s"] == frozenset(), "a bare digest must never become ja3s"


def test_case_and_whitespace_are_normalized(tmp_path):
    path = write_feed(tmp_path, f"  JA3:  {JA3.upper()}  \n")

    assert load_fingerprint_feed(path)["ja3"] == frozenset({JA3})


def test_duplicates_collapse_and_are_not_an_error(tmp_path):
    path = write_feed(tmp_path, f"ja3:{JA3}\nja3:{JA3.upper()}\n{JA3}\n")

    assert load_fingerprint_feed(path)["ja3"] == frozenset({JA3})


def test_an_empty_feed_is_valid_and_loads_nothing(tmp_path):
    feed = load_fingerprint_feed(write_feed(tmp_path, "# nothing yet\n"))

    assert all(values == frozenset() for values in feed.values())


# --------------------------------------------------------------------------
# 9-13, 15-16. Malformed input is refused, never skipped
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line,expected",
    [
        ("ja3:nope", "32-character hex MD5"),
        ("ja3:0123456789abcdef", "32-character hex MD5"),
        (f"ja3:{JA3}ff", "32-character hex MD5"),
        ("ja3s:zzzzcba9876543210fedcba9876543210", "32-character hex MD5"),
        ("ja4:", "has no fingerprint"),
        ("ja3:", "has no fingerprint"),
        ("ja5:0123456789abcdef0123456789abcdef", "unknown fingerprint type"),
        ("not-a-fingerprint", "neither a"),
        ("ja4:has spaces in it", "plausible JA4 token"),
    ],
)
def test_a_malformed_line_names_the_file_line_and_reason(tmp_path, line, expected):
    path = write_feed(tmp_path, f"ja3:{JA3}\n{line}\n")

    with pytest.raises(FingerprintError) as caught:
        load_fingerprint_feed(path)

    message = str(caught.value)
    assert "line 2" in message, message
    assert str(path) in message
    assert expected in message


def test_a_missing_feed_is_a_clean_error(tmp_path):
    with pytest.raises(FingerprintError, match="fingerprint feed not found"):
        load_fingerprint_feed(tmp_path / "absent.txt")


def test_a_directory_is_a_clean_error(tmp_path):
    with pytest.raises(FingerprintError, match="is a directory"):
        load_fingerprint_feed(tmp_path)


def test_a_non_utf8_file_is_a_clean_error(tmp_path):
    path = tmp_path / "binary.txt"
    path.write_bytes(b"\xff\xfe\x00\x01 not text")

    with pytest.raises(FingerprintError, match="not valid UTF-8"):
        load_fingerprint_feed(path)


def test_normalize_rejects_an_unknown_kind():
    with pytest.raises(FingerprintError, match="unknown fingerprint type"):
        normalize_fingerprint("ja9", JA3)


# --------------------------------------------------------------------------
# 1-5, 18-19. Matching through the detector
# --------------------------------------------------------------------------


def detector_with(**sets) -> EncryptedMalwareDetector:
    return EncryptedMalwareDetector(EncryptedMalwareConfig(**sets))


def test_a_configured_ja3_matches_exactly():
    det = detector_with(malicious_ja3={JA3})

    alerts = det.process(tls_flow(ja3=JA3))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.threat_class is ThreatClass.ENCRYPTED_MALWARE
    assert alert.score_type is ScoreType.SIGNATURE_MATCH
    assert alert.evidence["fingerprint"] == JA3
    assert alert.evidence["fingerprint_type"] == "ja3"


def test_a_configured_ja3s_matches_exactly():
    det = detector_with(malicious_ja3s={JA3S})

    alerts = det.process(tls_flow(ja3s=JA3S))

    assert len(alerts) == 1
    assert alerts[0].evidence["fingerprint_type"] == "ja3s"
    assert alerts[0].score_type is ScoreType.SIGNATURE_MATCH


def test_a_configured_ja4_matches_exactly():
    det = detector_with(malicious_ja4={JA4})

    alerts = det.process(tls_flow(ja4=JA4))

    assert len(alerts) == 1
    assert alerts[0].evidence["fingerprint_type"] == "ja4"


def test_an_uppercase_fingerprint_on_the_flow_still_matches():
    det = detector_with(malicious_ja3={JA3})

    assert det.process(tls_flow(ja3=JA3.upper()))


def test_a_different_fingerprint_does_not_match():
    det = detector_with(malicious_ja3={JA3})

    assert det.process(tls_flow(ja3=OTHER_JA3)) == []


def test_a_flow_without_fingerprints_cannot_false_positive():
    """Today's ingestion emits no JA3, and must not trip the signature path."""
    det = detector_with(malicious_ja3={JA3}, malicious_ja3s={JA3S}, malicious_ja4={JA4})

    assert det.process(tls_flow()) == []


def test_empty_default_sets_are_inert():
    det = EncryptedMalwareDetector()

    assert det.config.has_signatures is False
    assert det.process(tls_flow(ja3=JA3, ja3s=JA3S, ja4=JA4)) == []


def test_the_heuristic_path_is_unaffected_by_signatures():
    """Loading fingerprints must not change the SNI metadata verdict."""
    generated = "x7k2m9p4q1w8e3r6t5y0u2i4o6a8s1d3.example.com"
    plain = EncryptedMalwareDetector()
    signed = detector_with(malicious_ja3={JA3})

    flows = [
        make_flow(src_ip=SRC, dst_ip=DST, dst_port=443, proto="tcp",
                  timestamp=2000.0 + i,
                  tls=TlsInfo(uid=f"C{i}", server_name=generated, version="TLSv13"))
        for i in range(8)
    ]
    plain_alerts = [a for f in flows for a in plain.process(f)]
    signed_alerts = [a for f in flows for a in signed.process(f)]

    assert len(plain_alerts) == len(signed_alerts) == 1
    assert plain_alerts[0].score == signed_alerts[0].score
    assert plain_alerts[0].severity is signed_alerts[0].severity
    assert plain_alerts[0].evidence == signed_alerts[0].evidence


# --------------------------------------------------------------------------
# 17. Config and feed union
# --------------------------------------------------------------------------


def test_config_and_feed_fingerprints_are_unioned(tmp_path):
    config = tmp_path / "detectors.toml"
    config.write_text(
        f'[encrypted_malware]\nja3_fingerprints = ["{OTHER_JA3}"]\n', encoding="utf-8"
    )
    feed = write_feed(tmp_path, f"ja3:{JA3}\nja4:{JA4}\n")

    settings = load_detector_settings(config).with_fingerprints(
        load_fingerprint_feed(feed)
    )

    tls = settings.encrypted_malware
    assert tls.malicious_ja3 == frozenset({JA3, OTHER_JA3}), "a feed must not replace config"
    assert tls.malicious_ja4 == frozenset({JA4})


def test_a_feed_alone_arms_the_detector(tmp_path):
    feed = write_feed(tmp_path, f"ja3:{JA3}\n")

    settings = DetectorSettings().with_fingerprints(load_fingerprint_feed(feed))
    detectors = build_default_detectors(settings=settings)

    encrypted = [d for d in detectors if d.name == "encrypted_malware"][0]
    assert encrypted.config.malicious_ja3 == frozenset({JA3})
    assert encrypted.process(tls_flow(ja3=JA3))


def test_the_union_leaves_other_settings_alone(tmp_path):
    feed = write_feed(tmp_path, f"ja3:{JA3}\n")

    merged = DetectorSettings().with_fingerprints(load_fingerprint_feed(feed))

    default = EncryptedMalwareConfig()
    assert merged.encrypted_malware.min_tls_observations == default.min_tls_observations
    assert merged.encrypted_malware.suspicious_sni_entropy == default.suspicious_sni_entropy
    assert merged.port_scan == DetectorSettings().port_scan


# --------------------------------------------------------------------------
# 18 (Phase). End to end through the runner
# --------------------------------------------------------------------------


def test_the_runner_matches_a_fingerprint_from_a_local_feed(tmp_path):
    """JSONL -> adapter -> detector -> ThreatAlert v1.1 on disk."""
    record = {
        "flow_id": f"{SRC}:{DST}:443:tcp:1747147700.500",
        "src_ip": SRC, "dst_ip": DST, "dst_port": 443, "proto": "tcp",
        "duration": 0.5, "orig_bytes": 800, "resp_bytes": 1200,
        "orig_pkts": 6, "resp_pkts": 8,
        "tls": {"uid": "Ctls1", "ja3": JA3.upper(), "ja3s": JA3S, "ja4": JA4,
                "server_name": "www.example.com", "has_ja3": True},
    }
    source = tmp_path / "features.jsonl"
    source.write_text(json.dumps(record) + "\n", encoding="utf-8")
    feed = write_feed(tmp_path, f"# synthetic\nja3:{JA3}\n")
    out = tmp_path / "alerts.jsonl"

    code = runner.main(
        [str(source), "--output", str(out), "--ja3-feed", str(feed), "--quiet"]
    )

    assert code == 0
    alerts = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["schema_version"] == "1.1"
    assert alert["threat_class"] == "encrypted_malware"
    assert alert["score_type"] == "signature_match"
    assert alert["evidence"]["fingerprint"] == JA3
    assert alert["evidence"]["fingerprint_type"] == "ja3"
    assert alert["src_ip"] == SRC and alert["dst_ip"] == DST


def test_the_same_input_without_a_feed_produces_nothing(tmp_path):
    """Proof the feed is what armed it - not something else in the flow."""
    record = {
        "flow_id": f"{SRC}:{DST}:443:tcp:1747147700.500",
        "src_ip": SRC, "dst_ip": DST, "dst_port": 443, "proto": "tcp",
        "duration": 0.5, "orig_bytes": 800, "resp_bytes": 1200,
        "orig_pkts": 6, "resp_pkts": 8,
        "tls": {"uid": "Ctls1", "ja3": JA3, "server_name": "www.example.com"},
    }
    source = tmp_path / "features.jsonl"
    source.write_text(json.dumps(record) + "\n", encoding="utf-8")
    out = tmp_path / "alerts.jsonl"

    assert runner.main([str(source), "--output", str(out), "--quiet"]) == 0
    assert out.read_text(encoding="utf-8").strip() == ""
