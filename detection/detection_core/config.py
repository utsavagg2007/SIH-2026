"""Detector settings from a TOML file, or the code defaults when there is none.

Thresholds live in the detector ``Config`` dataclasses and always have. This
module lets an operator override them for a run without editing source, and
does nothing else: it is deliberately not an application-configuration
framework. The API URL, the output path, timeouts and logging stay CLI
options, because they are not detector behaviour.

TOML because Python ships ``tomllib``; adding PyYAML to read a settings file
would be a runtime dependency bought for nothing.

    [port_scan]
    cooldown_seconds = 120.0

    [encrypted_malware]
    ja3_fingerprints = ["0123456789abcdef0123456789abcdef"]

Two rules make this safe to hand to someone at 3am:

**Partial.** Only the fields present are overridden; everything else keeps the
code default, because the override is applied by *constructing the real
dataclass* with just those fields. There is no second copy of the defaults
here to drift from the ones the detectors use.

**Strict.** An unknown section, an unknown field, or a value of the wrong type
is an error naming exactly what and where. ``min_unique_prts = 15`` must fail
loudly - a typo that silently leaves a threshold at its default is a
configuration that lies about what it is doing.
"""

from __future__ import annotations

import math
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .detectors import (
    C2BeaconingConfig,
    DDoSConfig,
    DGAConfig,
    DataExfiltrationConfig,
    DnsTunnellingConfig,
    EncryptedMalwareConfig,
    PortScanConfig,
)
from .fingerprints import FingerprintError, normalize_fingerprint

__all__ = [
    "DETECTOR_SECTIONS",
    "ConfigError",
    "DetectorSettings",
    "load_detector_settings",
]

#: TOML section name -> the config class it fills. Every section is named
#: for its detector - which is also its ThreatClass value - so there is one
#: vocabulary to remember rather than three. That includes ``dga_domain``,
#: spelled in full rather than shortened to "dga": one detector being the
#: exception is exactly the kind of thing a config file gets wrong at 3am.
DETECTOR_SECTIONS: dict[str, type] = {
    "port_scan": PortScanConfig,
    "ddos": DDoSConfig,
    "c2_beaconing": C2BeaconingConfig,
    "dns_tunnelling": DnsTunnellingConfig,
    "data_exfiltration": DataExfiltrationConfig,
    "encrypted_malware": EncryptedMalwareConfig,
    "dga_domain": DGAConfig,
}

#: TOML arrays of fingerprints, mapped to the config fields they fill and the
#: kind each is validated as. Named for what an operator would call them
#: rather than for the internal attribute.
_FINGERPRINT_FIELDS: dict[str, tuple[str, str]] = {
    "ja3_fingerprints": ("malicious_ja3", "ja3"),
    "ja3s_fingerprints": ("malicious_ja3s", "ja3s"),
    "ja4_fingerprints": ("malicious_ja4", "ja4"),
}


class ConfigError(ValueError):
    """A configuration file could not be read, or says something invalid."""


@dataclass(frozen=True)
class DetectorSettings:
    """One config per detector. Every field defaults to the shipped config.

    Constructed with no arguments this is exactly what the detectors build
    themselves, which is what keeps "no ``--config``" byte-for-byte identical
    to the behaviour before this module existed.
    """

    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    ddos: DDoSConfig = field(default_factory=DDoSConfig)
    c2_beaconing: C2BeaconingConfig = field(default_factory=C2BeaconingConfig)
    dns_tunnelling: DnsTunnellingConfig = field(default_factory=DnsTunnellingConfig)
    data_exfiltration: DataExfiltrationConfig = field(
        default_factory=DataExfiltrationConfig
    )
    encrypted_malware: EncryptedMalwareConfig = field(
        default_factory=EncryptedMalwareConfig
    )
    dga_domain: DGAConfig = field(default_factory=DGAConfig)
    #: Sections the file actually contained, so the runner can say something
    #: useful about a ``[dga_domain]`` block on a run with no model.
    configured_sections: frozenset[str] = frozenset()

    def with_fingerprints(self, feed: dict[str, frozenset[str]]) -> DetectorSettings:
        """Return settings whose fingerprint sets also contain ``feed``.

        A **union**, deliberately. A feed supplements the indicators an
        operator wrote into their config rather than replacing them; the
        alternative would let adding ``--ja3-feed`` silently disarm the
        signatures already configured, which is the wrong way for a mistake
        to fail.
        """
        merged = EncryptedMalwareConfig(
            **{
                **{
                    f.name: getattr(self.encrypted_malware, f.name)
                    for f in fields(EncryptedMalwareConfig)
                },
                "malicious_ja3": self.encrypted_malware.malicious_ja3
                | feed.get("ja3", frozenset()),
                "malicious_ja3s": self.encrypted_malware.malicious_ja3s
                | feed.get("ja3s", frozenset()),
                "malicious_ja4": self.encrypted_malware.malicious_ja4
                | feed.get("ja4", frozenset()),
            }
        )
        return DetectorSettings(
            port_scan=self.port_scan,
            ddos=self.ddos,
            c2_beaconing=self.c2_beaconing,
            dns_tunnelling=self.dns_tunnelling,
            data_exfiltration=self.data_exfiltration,
            encrypted_malware=merged,
            dga_domain=self.dga_domain,
            configured_sections=self.configured_sections,
        )


def load_detector_settings(path: str | Path) -> DetectorSettings:
    """Read a TOML file into :class:`DetectorSettings`.

    An empty file is valid and means "the defaults", as does a file naming
    only some detectors.
    """
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    if path.is_dir():
        raise ConfigError(f"config path is a directory, not a file: {path}")

    try:
        with open(path, "rb") as handle:
            document = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"could not read config file {path}: {exc}") from exc

    known = ", ".join(sorted(DETECTOR_SECTIONS))
    built: dict[str, Any] = {}

    for section, values in document.items():
        if section not in DETECTOR_SECTIONS:
            raise ConfigError(
                f"{path}: unknown section [{section}]; expected one of {known}"
            )
        if not isinstance(values, dict):
            raise ConfigError(
                f"{path}: [{section}] must be a table of settings, got "
                f"{type(values).__name__}"
            )
        built[section] = _build_section(path, section, values)

    return DetectorSettings(**built, configured_sections=frozenset(document))


def _build_section(path: Path, section: str, values: dict[str, Any]):
    """Construct one detector config from its overrides, strictly."""
    config_class = DETECTOR_SECTIONS[section]
    defaults = {f.name: f for f in fields(config_class)}
    accepted = set(defaults)
    if section == "encrypted_malware":
        # The fingerprint arrays are spelled for operators, not for Python.
        accepted |= set(_FINGERPRINT_FIELDS)
        accepted -= {"malicious_ja3", "malicious_ja3s", "malicious_ja4"}

    overrides: dict[str, Any] = {}
    for key, value in values.items():
        if key not in accepted:
            raise ConfigError(
                f"{path}: [{section}] has no setting {key!r}; expected one of "
                f"{', '.join(sorted(accepted))}"
            )
        if key in _FINGERPRINT_FIELDS and section == "encrypted_malware":
            attribute, kind = _FINGERPRINT_FIELDS[key]
            overrides[attribute] = _coerce_fingerprints(path, section, key, kind, value)
            continue
        overrides[key] = _coerce_scalar(path, section, key, defaults[key], value)

    try:
        return config_class(**overrides)
    except (ValueError, TypeError) as exc:
        # The dataclass's own __post_init__ rejected it - the same rule that
        # protects a hand-written config, reported with its source.
        raise ConfigError(f"{path}: [{section}] {exc}") from exc


def _coerce_scalar(path: Path, section: str, key: str, spec, value: Any) -> Any:
    """Type-check one scalar against the field's default.

    The default is the source of truth for the expected type; the annotations
    are strings under ``from __future__ import annotations`` and parsing them
    would be a second, less reliable definition of the same thing.
    """
    expected = type(spec.default)

    # bool is a subclass of int in Python, so `true` would otherwise sail
    # into an integer threshold as 1. Nothing here takes a boolean.
    if isinstance(value, bool):
        raise ConfigError(
            f"{path}: [{section}] {key} must be {expected.__name__}, got a boolean"
        )

    if expected is float:
        if isinstance(value, (int, float)):
            number = float(value)
            if not math.isfinite(number):
                # TOML spells these `nan` and `inf`, and every setting here is
                # a threshold, a weight or a duration. NaN loses every
                # comparison, so a window would never expire and a ratio
                # would never qualify; inf is a bound nothing can cross.
                # Both would disable a detector while looking configured.
                raise ConfigError(
                    f"{path}: [{section}] {key} must be a finite number, got "
                    f"{value!r}"
                )
            return number
        raise ConfigError(
            f"{path}: [{section}] {key} must be a number, got "
            f"{type(value).__name__} ({value!r})"
        )
    if expected is int:
        if isinstance(value, int):
            return value
        raise ConfigError(
            f"{path}: [{section}] {key} must be an integer, got "
            f"{type(value).__name__} ({value!r})"
        )
    if expected is frozenset:
        # obsolete_tls_versions and anything else set-shaped.
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(
                f"{path}: [{section}] {key} must be an array of strings"
            )
        cleaned = frozenset(item.strip() for item in value if item.strip())
        return cleaned
    if expected is str:
        if isinstance(value, str):
            return value
        raise ConfigError(
            f"{path}: [{section}] {key} must be a string, got {type(value).__name__}"
        )

    raise ConfigError(  # pragma: no cover - a new field type would land here
        f"{path}: [{section}] {key} has unsupported type {expected.__name__}"
    )


def _coerce_fingerprints(
    path: Path, section: str, key: str, kind: str, value: Any
) -> frozenset[str]:
    """Validate a TOML array of fingerprints, exactly as a feed file is."""
    if not isinstance(value, list):
        raise ConfigError(
            f"{path}: [{section}] {key} must be an array of fingerprint strings, "
            f"got {type(value).__name__}"
        )
    loaded = set()
    for index, item in enumerate(value):
        try:
            loaded.add(normalize_fingerprint(kind, item))
        except FingerprintError as exc:
            raise ConfigError(f"{path}: [{section}] {key}[{index}]: {exc}") from exc
    return frozenset(loaded)
