"""Strict TOML detector configuration, and the defaults it must not disturb.

Two properties matter more than anything else here.

**Defaults are untouched.** Adding a configuration layer must not move a
single shipped threshold, so the first tests pin every default field of every
detector and assert that building with no settings is the same as building the
way every existing caller does.

**Typos fail.** A settings file that looks applied but silently is not is
worse than no settings file at all, so an unknown section, an unknown key or a
wrong type is an error naming exactly where.
"""

from __future__ import annotations

import dataclasses as dc

import pytest

from detection_core import (
    C2BeaconingConfig,
    DDoSConfig,
    DataExfiltrationConfig,
    DGAConfig,
    DnsTunnellingConfig,
    EncryptedMalwareConfig,
    PortScanConfig,
    build_default_detectors,
)
from detection_core.config import (
    DETECTOR_SECTIONS,
    ConfigError,
    DetectorSettings,
    load_detector_settings,
)

RULE_DETECTORS = [
    "port_scan",
    "ddos",
    "c2_beaconing",
    "dns_tunnelling",
    "data_exfiltration",
    "encrypted_malware",
]


def write(tmp_path, text: str, name: str = "detectors.toml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# 1-2, 19-20. Defaults, and old callers
# --------------------------------------------------------------------------


def test_the_shipped_defaults_are_exactly_what_they_were():
    """Every documented threshold, pinned by value.

    If a configuration change ever moves one of these, that is a detector
    tuning decision and belongs in its own reviewed change - not in a commit
    about reading a settings file.
    """
    assert dc.asdict(PortScanConfig()) == {
        "window_seconds": 60.0, "min_unique_ports": 15, "min_unique_hosts": 20,
        "cooldown_seconds": 300.0, "saturation_multiple": 4.0,
        "combined_bonus": 0.1,
        # 0.3.0: the two credibility checks derived from real captures. See
        # docs/REAL_DATA_EVAL.md for where each number came from.
        "max_service_port": 49151, "min_service_ports": 3,
        "established_resp_bytes": 100, "max_established_fraction": 0.20,
        "min_incomplete_fraction": 0.05, "min_conn_state_coverage": 0.50,
    }
    assert dc.asdict(DDoSConfig()) == {
        "window_seconds": 10.0, "min_unique_sources": 50, "min_flows": 200,
        "min_packets": 1000, "cooldown_seconds": 60.0, "saturation_multiple": 4.0,
    }
    c2 = C2BeaconingConfig()
    assert (c2.window_seconds, c2.min_observations, c2.max_interval_cv) == (900.0, 6, 0.20)
    assert (c2.min_mean_interval_seconds, c2.max_mean_interval_seconds) == (2.0, 120.0)
    assert c2.cooldown_seconds == 300.0
    dns = DnsTunnellingConfig()
    assert (dns.min_dns_observations, dns.min_suspicious_ratio) == (20, 0.5)
    assert (dns.suspicious_query_length, dns.suspicious_entropy) == (50, 4.0)
    exfil = DataExfiltrationConfig()
    assert (exfil.min_flows, exfil.min_total_orig_bytes) == (10, 50 * 1024 * 1024)
    assert exfil.min_destination_concentration == 0.6
    tls = EncryptedMalwareConfig()
    assert (tls.min_tls_observations, tls.suspicious_sni_length) == (6, 38)
    assert tls.suspicious_sni_entropy == 4.2
    assert DGAConfig().score_threshold == 0.75
    assert DGAConfig().cooldown_seconds == 300.0


def test_empty_settings_are_the_shipped_configs():
    settings = DetectorSettings()

    assert settings.port_scan == PortScanConfig()
    assert settings.ddos == DDoSConfig()
    assert settings.c2_beaconing == C2BeaconingConfig()
    assert settings.dns_tunnelling == DnsTunnellingConfig()
    assert settings.data_exfiltration == DataExfiltrationConfig()
    assert settings.encrypted_malware == EncryptedMalwareConfig()
    assert settings.dga_domain == DGAConfig()
    assert settings.configured_sections == frozenset()


def test_the_old_factory_call_still_works_and_is_unchanged():
    """Every existing caller passes no settings; nothing may change for them."""
    old_way = build_default_detectors()
    explicit = build_default_detectors(settings=DetectorSettings())

    assert [d.name for d in old_way] == RULE_DETECTORS
    for previous, current in zip(old_way, explicit):
        assert previous.config == current.config
        assert previous.name == current.name
        assert previous.version == current.version


def test_no_config_file_means_no_change_to_any_detector(tmp_path):
    empty = write(tmp_path, "")

    from_file = build_default_detectors(settings=load_detector_settings(empty))
    default = build_default_detectors()

    for a, b in zip(from_file, default):
        assert a.config == b.config


# --------------------------------------------------------------------------
# 3-5. Overrides reach the detectors, and only where asked
# --------------------------------------------------------------------------


def test_one_override_leaves_every_other_field_alone(tmp_path):
    path = write(tmp_path, "[port_scan]\ncooldown_seconds = 120.0\n")

    settings = load_detector_settings(path)

    assert settings.port_scan.cooldown_seconds == 120.0
    # Everything else is still the shipped default.
    default = PortScanConfig()
    for f in dc.fields(PortScanConfig):
        if f.name != "cooldown_seconds":
            assert getattr(settings.port_scan, f.name) == getattr(default, f.name)


def test_several_fields_and_several_sections(tmp_path):
    path = write(
        tmp_path,
        """
        [port_scan]
        min_unique_ports = 8
        min_unique_hosts = 9

        [ddos]
        min_unique_sources = 25

        [c2_beaconing]
        max_interval_cv = 0.35
        """,
    )

    settings = load_detector_settings(path)

    assert (settings.port_scan.min_unique_ports, settings.port_scan.min_unique_hosts) == (8, 9)
    assert settings.ddos.min_unique_sources == 25
    assert settings.c2_beaconing.max_interval_cv == 0.35
    # Untouched sections keep their whole default config.
    assert settings.dns_tunnelling == DnsTunnellingConfig()
    assert settings.data_exfiltration == DataExfiltrationConfig()


def test_an_integer_is_accepted_for_a_float_setting(tmp_path):
    """TOML `120` for a float field is a number, not a type error."""
    path = write(tmp_path, "[port_scan]\ncooldown_seconds = 120\n")

    settings = load_detector_settings(path)

    assert settings.port_scan.cooldown_seconds == 120.0
    assert isinstance(settings.port_scan.cooldown_seconds, float)


# --------------------------------------------------------------------------
# 6-11. Strictness
# --------------------------------------------------------------------------


def test_an_unknown_section_is_rejected(tmp_path):
    path = write(tmp_path, "[port_scanner]\nwindow_seconds = 60.0\n")

    with pytest.raises(ConfigError, match=r"unknown section \[port_scanner\]"):
        load_detector_settings(path)


def test_a_typo_in_a_field_name_is_rejected(tmp_path):
    """The case this strictness exists for."""
    path = write(tmp_path, "[port_scan]\nmin_unique_prts = 15\n")

    with pytest.raises(ConfigError) as caught:
        load_detector_settings(path)

    message = str(caught.value)
    assert "port_scan" in message and "min_unique_prts" in message
    assert "min_unique_ports" in message, "the error should list what is valid"


def test_malformed_toml_is_rejected(tmp_path):
    path = write(tmp_path, "[port_scan\nmin_unique_ports = 15\n")

    with pytest.raises(ConfigError, match="not valid TOML"):
        load_detector_settings(path)


def test_a_string_where_a_number_belongs_is_rejected(tmp_path):
    path = write(tmp_path, '[port_scan]\nmin_unique_ports = "15"\n')

    with pytest.raises(ConfigError) as caught:
        load_detector_settings(path)

    assert "must be an integer" in str(caught.value)
    assert "min_unique_ports" in str(caught.value)


def test_a_boolean_is_never_accepted_as_a_number(tmp_path):
    """bool subclasses int in Python, so `true` would otherwise arrive as 1."""
    path = write(tmp_path, "[port_scan]\nmin_unique_ports = true\n")

    with pytest.raises(ConfigError, match="got a boolean"):
        load_detector_settings(path)


def test_a_float_where_an_integer_belongs_is_rejected(tmp_path):
    path = write(tmp_path, "[port_scan]\nmin_unique_ports = 15.5\n")

    with pytest.raises(ConfigError, match="must be an integer"):
        load_detector_settings(path)


def test_a_value_the_dataclass_rejects_still_fails(tmp_path):
    """The config's own validation is not bypassed by coming from a file."""
    path = write(tmp_path, "[port_scan]\nwindow_seconds = 0.0\n")

    with pytest.raises(ConfigError) as caught:
        load_detector_settings(path)

    assert "window_seconds must be positive" in str(caught.value)
    assert "[port_scan]" in str(caught.value)


def test_a_weight_set_that_does_not_sum_is_rejected(tmp_path):
    path = write(tmp_path, "[dns_tunnelling]\nratio_weight = 0.9\n")

    with pytest.raises(ConfigError, match="must sum to 1.0"):
        load_detector_settings(path)


def test_a_missing_or_directory_path_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="config file not found"):
        load_detector_settings(tmp_path / "nope.toml")
    with pytest.raises(ConfigError, match="is a directory"):
        load_detector_settings(tmp_path)


def test_a_section_that_is_not_a_table_is_rejected(tmp_path):
    path = write(tmp_path, 'port_scan = "everything"\n')

    with pytest.raises(ConfigError, match="must be a table"):
        load_detector_settings(path)


# --------------------------------------------------------------------------
# 12-14. DGA
# --------------------------------------------------------------------------


def test_the_dga_default_threshold_is_still_075(tmp_path):
    assert load_detector_settings(write(tmp_path, "")).dga_domain.score_threshold == 0.75


def test_dga_threshold_can_be_overridden_explicitly(tmp_path):
    path = write(tmp_path, "[dga_domain]\nscore_threshold = 0.9\n")

    settings = load_detector_settings(path)

    assert settings.dga_domain.score_threshold == 0.9
    assert settings.dga_domain.cooldown_seconds == 300.0  # untouched


def test_a_dga_section_does_not_enable_dga_without_a_model(tmp_path):
    """Configuration can shape DGA; it cannot conjure a model."""
    settings = load_detector_settings(write(tmp_path, "[dga_domain]\nscore_threshold = 0.9\n"))

    detectors = build_default_detectors(settings=settings)

    assert [d.name for d in detectors] == RULE_DETECTORS
    assert "dga_domain" not in [d.name for d in detectors]
    # The section is recorded, so the runner can say so.
    assert "dga_domain" in settings.configured_sections


def test_dga_settings_reach_the_detector_when_a_model_is_present(tmp_path):
    from tests.test_dga_source_aggregation import ScriptedModel

    settings = load_detector_settings(write(tmp_path, "[dga_domain]\nscore_threshold = 0.9\n"))
    detectors = build_default_detectors(dga_model=ScriptedModel(), settings=settings)

    dga = [d for d in detectors if d.name == "dga_domain"][0]
    assert dga.config.score_threshold == 0.9


# --------------------------------------------------------------------------
# 15-17. Fingerprint arrays in TOML
# --------------------------------------------------------------------------


def test_fingerprint_arrays_are_loaded_and_normalized(tmp_path):
    path = write(
        tmp_path,
        """
        [encrypted_malware]
        ja3_fingerprints = ["0123456789ABCDEF0123456789abcdef"]
        ja3s_fingerprints = ["fedcba9876543210fedcba9876543210"]
        ja4_fingerprints = ["t13d1516h2_8daaf6152771_02713d6af862"]
        """,
    )

    tls = load_detector_settings(path).encrypted_malware

    assert tls.malicious_ja3 == frozenset({"0123456789abcdef0123456789abcdef"})
    assert tls.malicious_ja3s == frozenset({"fedcba9876543210fedcba9876543210"})
    assert tls.malicious_ja4 == frozenset({"t13d1516h2_8daaf6152771_02713d6af862"})
    assert tls.has_signatures is True


def test_duplicate_fingerprints_collapse(tmp_path):
    path = write(
        tmp_path,
        """
        [encrypted_malware]
        ja3_fingerprints = [
          "0123456789abcdef0123456789abcdef",
          "0123456789ABCDEF0123456789ABCDEF",
        ]
        """,
    )

    assert len(load_detector_settings(path).encrypted_malware.malicious_ja3) == 1


def test_a_malformed_fingerprint_in_config_is_rejected(tmp_path):
    path = write(tmp_path, '[encrypted_malware]\nja3_fingerprints = ["nope"]\n')

    with pytest.raises(ConfigError) as caught:
        load_detector_settings(path)

    message = str(caught.value)
    assert "ja3_fingerprints[0]" in message
    assert "32-character hex MD5" in message


def test_the_internal_attribute_name_is_not_accepted(tmp_path):
    """Operators write ja3_fingerprints, not the Python attribute."""
    path = write(tmp_path, '[encrypted_malware]\nmalicious_ja3 = ["x"]\n')

    with pytest.raises(ConfigError, match="no setting 'malicious_ja3'"):
        load_detector_settings(path)


def test_a_fingerprint_array_must_be_an_array(tmp_path):
    path = write(tmp_path, '[encrypted_malware]\nja3_fingerprints = "abc"\n')

    with pytest.raises(ConfigError, match="must be an array"):
        load_detector_settings(path)


def test_a_switch_takes_a_boolean(tmp_path):
    """One setting is a switch rather than a threshold, and must be reachable.

    ``ignore_multicast_destinations`` is documented as configurable, so a
    config file has to be able to turn it off - the blanket "no setting here
    takes a boolean" rule that predates it would have made the knob
    unreachable and said so with the wrong message.
    """
    path = write(
        tmp_path, "[c2_beaconing]\nignore_multicast_destinations = false\n"
    )

    beaconing = load_detector_settings(path).c2_beaconing

    assert beaconing.ignore_multicast_destinations is False
    assert beaconing.ignored_dst_ports == C2BeaconingConfig().ignored_dst_ports


def test_a_switch_rejects_a_number(tmp_path):
    """`1` in a switch is a reader guessing; the guess is refused."""
    path = write(tmp_path, "[c2_beaconing]\nignore_multicast_destinations = 1\n")

    with pytest.raises(ConfigError, match="must be true or false"):
        load_detector_settings(path)


def test_the_periodic_service_list_takes_an_array_of_ports(tmp_path):
    """Which services are periodic-by-design is a property of the network.

    A site with no directory server, or one that runs something unusual on a
    timer, has to be able to say so without editing frozen detector code.
    """
    path = write(tmp_path, "[c2_beaconing]\nignored_dst_ports = [123, 5353]\n")

    beaconing = load_detector_settings(path).c2_beaconing

    assert beaconing.ignored_dst_ports == frozenset({123, 5353})


def test_the_periodic_service_list_rejects_strings(tmp_path):
    path = write(tmp_path, '[c2_beaconing]\nignored_dst_ports = ["123"]\n')

    with pytest.raises(ConfigError, match="must be an array of port numbers"):
        load_detector_settings(path)


def test_the_periodic_service_list_rejects_an_impossible_port(tmp_path):
    """The dataclass's own range check, reported with the file that caused it."""
    path = write(tmp_path, "[c2_beaconing]\nignored_dst_ports = [70000]\n")

    with pytest.raises(ConfigError, match=r"\[0, 65535\]"):
        load_detector_settings(path)


def test_a_set_valued_field_takes_an_array_of_strings(tmp_path):
    path = write(
        tmp_path,
        '[encrypted_malware]\nobsolete_tls_versions = ["SSLv3", "TLSv10"]\n',
    )

    tls = load_detector_settings(path).encrypted_malware

    assert tls.obsolete_tls_versions == frozenset({"SSLv3", "TLSv10"})


# --------------------------------------------------------------------------
# Section vocabulary
# --------------------------------------------------------------------------


def test_every_detector_has_a_section_named_after_it():
    """One vocabulary: section names are detector names are threat classes."""
    from detection_core import ThreatClass

    assert set(DETECTOR_SECTIONS) == {threat.value for threat in ThreatClass}


# --------------------------------------------------------------------------
# Non-finite numbers are not settings
# --------------------------------------------------------------------------


def numeric_float_fields():
    """Every float-valued setting across every detector section."""
    for section, config_class in DETECTOR_SECTIONS.items():
        for field in dc.fields(config_class):
            if type(field.default) is float:
                yield section, field.name


@pytest.mark.parametrize("literal", ["nan", "inf", "-inf", "+inf"])
def test_non_finite_values_are_rejected(tmp_path, literal):
    """NaN loses every comparison and inf is a bound nothing crosses.

    Either would leave a detector looking configured while never expiring a
    window or never qualifying a ratio.
    """
    path = write(tmp_path, f"[port_scan]\nwindow_seconds = {literal}\n")

    with pytest.raises(ConfigError) as caught:
        load_detector_settings(path)

    message = str(caught.value)
    assert "must be a finite number" in message
    assert "window_seconds" in message and "port_scan" in message


@pytest.mark.parametrize(
    "section,field", list(numeric_float_fields()),
    ids=lambda v: v if isinstance(v, str) else str(v),
)
def test_every_float_setting_rejects_nan(tmp_path, section, field):
    """Parameterized over all of them, so a new float field is covered too."""
    path = write(tmp_path, f"[{section}]\n{field} = nan\n")

    with pytest.raises(ConfigError, match="must be a finite number"):
        load_detector_settings(path)


def test_a_finite_value_is_still_accepted(tmp_path):
    path = write(tmp_path, "[port_scan]\nwindow_seconds = 45.5\n")

    assert load_detector_settings(path).port_scan.window_seconds == 45.5


def test_an_integer_is_still_accepted_for_a_float_setting(tmp_path):
    path = write(tmp_path, "[port_scan]\nwindow_seconds = 45\n")

    assert load_detector_settings(path).port_scan.window_seconds == 45.0


def test_a_boolean_is_still_rejected_before_the_finite_check(tmp_path):
    path = write(tmp_path, "[port_scan]\nwindow_seconds = true\n")

    with pytest.raises(ConfigError, match="got a boolean"):
        load_detector_settings(path)


def test_partial_override_behaviour_is_unchanged_by_the_finite_check(tmp_path):
    path = write(tmp_path, "[port_scan]\nwindow_seconds = 45.0\n")

    settings = load_detector_settings(path)

    assert settings.port_scan.window_seconds == 45.0
    assert settings.port_scan.min_unique_ports == PortScanConfig().min_unique_ports
    assert settings.ddos == DDoSConfig()
