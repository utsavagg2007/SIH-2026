#!/usr/bin/env python3
"""Reproducible, integrity-bound PCAP-to-feature dataset ingestion.

Replay identity is intentionally stable at ``sha256 + label`` for compatibility.
Reuse is allowed only when the complete production configuration, immutable
runtime identity, per-replay metadata, and feature artifact digest all agree.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import copy
from dataclasses import dataclass
import datetime
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tempfile
import uuid
from collections.abc import Iterator, Mapping


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET_ROOT = REPO_ROOT / "pcap_dataset"
INGESTION_ROOT = REPO_ROOT / "ingestion"

DATASET_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "sih2026:pcap_dataset:v1")

ALLOWED_LABELS = {
    "benign",
    "port_scan",
    "ddos",
    "dns_tunnelling",
    "encrypted_malware",
    "data_exfiltration",
    "c2_beaconing",
    "dga_domain",
}

DATASET_FEATURE_PROFILE = "detector-v2"
FEATURE_PROFILES = ("legacy-m1d", "detector-v2")
FEATURE_PROFILE_REVISIONS = {"legacy-m1d": 1, "detector-v2": 2}
TLS_FINGERPRINT_MODES = ("none", "ja4", "ja3-ja3s-ja4")
DATASET_SENSOR_ID = "sensor/pcap-dataset"
STANDARD_ZEEK_IMAGE = (
    "zeek/zeek:8.0.10@sha256:"
    "73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"
)
JA4_RUNTIME_LOCK = INGESTION_ROOT / "runtime" / "ja4-runtime.lock"
TLS_FINGERPRINT_RUNTIME_LOCK = (
    INGESTION_ROOT / "runtime" / "tls-fingerprint-runtime.lock"
)

METADATA_VERSION = 2
REPLAY_CONFIG_VERSION = 2
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_DIGEST_RE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")


class ReplayIntegrityError(RuntimeError):
    """Stored replay state is incomplete, contradictory, or corrupted."""


@dataclass(frozen=True)
class ReplayConfig:
    """Every stable input that can materially affect a dataset feature artifact."""

    config_version: int
    feature_profile: str
    feature_profile_revision: int
    tls_fingerprint_mode: str
    runtime_mode: str
    zeek_image: str
    runtime_lock_sha256: str | None
    runtime_config_digest: str | None
    deterministic_zeek: bool
    window_secs: float
    sensor_id: str

    @property
    def use_ja4(self) -> bool:
        """Compatibility mirror for the historical JA4-only CLI flag."""
        return self.tls_fingerprint_mode == "ja4"

    def as_dict(self) -> dict[str, object]:
        common = {
            "config_version": self.config_version,
            "deterministic_zeek": self.deterministic_zeek,
            "feature_profile": self.feature_profile,
            "runtime_config_digest": self.runtime_config_digest,
            "runtime_lock_sha256": self.runtime_lock_sha256,
            "runtime_mode": self.runtime_mode,
            "sensor_id": self.sensor_id,
            "window_secs": self.window_secs,
            "zeek_image": self.zeek_image,
        }
        if self.config_version == 1:
            common["use_ja4"] = self.use_ja4
        else:
            common["feature_profile_revision"] = self.feature_profile_revision
            common["tls_fingerprint_mode"] = self.tls_fingerprint_mode
        return common

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical_json_bytes(self.as_dict())).hexdigest()

    @classmethod
    def from_mapping(cls, value: object, context: str) -> "ReplayConfig":
        if not isinstance(value, Mapping):
            raise ReplayIntegrityError(f"{context} config must be an object")
        config_version = value.get("config_version")
        if config_version == 1:
            expected = {
                "config_version",
                "feature_profile",
                "use_ja4",
                "runtime_mode",
                "zeek_image",
                "runtime_lock_sha256",
                "runtime_config_digest",
                "deterministic_zeek",
                "window_secs",
                "sensor_id",
            }
        elif config_version == REPLAY_CONFIG_VERSION:
            expected = {
                "config_version",
                "feature_profile",
                "feature_profile_revision",
                "tls_fingerprint_mode",
                "runtime_mode",
                "zeek_image",
                "runtime_lock_sha256",
                "runtime_config_digest",
                "deterministic_zeek",
                "window_secs",
                "sensor_id",
            }
        else:
            raise ReplayIntegrityError(f"{context} has unsupported config_version")
        actual = set(value)
        if actual != expected:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            raise ReplayIntegrityError(
                f"{context} config fields differ (missing={missing}, extra={extra})"
            )

        profile = value["feature_profile"]
        if config_version == 1:
            use_ja4 = value["use_ja4"]
            if not isinstance(use_ja4, bool):
                raise ReplayIntegrityError(f"{context} has invalid use_ja4")
            tls_fingerprint_mode = "ja4" if use_ja4 else "none"
            feature_profile_revision = 1
        else:
            tls_fingerprint_mode = value["tls_fingerprint_mode"]
            feature_profile_revision = value["feature_profile_revision"]
        runtime_mode = value["runtime_mode"]
        image = value["zeek_image"]
        lock_sha = value["runtime_lock_sha256"]
        runtime_config_digest = value["runtime_config_digest"]
        deterministic = value["deterministic_zeek"]
        window_secs = value["window_secs"]
        sensor_id = value["sensor_id"]

        if profile not in FEATURE_PROFILES:
            raise ReplayIntegrityError(f"{context} has invalid feature_profile")
        if config_version != 1 and (
            isinstance(feature_profile_revision, bool)
            or feature_profile_revision != FEATURE_PROFILE_REVISIONS[profile]
        ):
            raise ReplayIntegrityError(
                f"{context} has invalid feature_profile_revision for {profile}"
            )
        if tls_fingerprint_mode not in TLS_FINGERPRINT_MODES:
            raise ReplayIntegrityError(f"{context} has invalid tls_fingerprint_mode")
        expected_mode = {
            "none": "standard",
            "ja4": "ja4",
            "ja3-ja3s-ja4": "tls-fingerprints",
        }[tls_fingerprint_mode]
        if runtime_mode != expected_mode:
            raise ReplayIntegrityError(
                f"{context} runtime_mode does not agree with tls_fingerprint_mode"
            )
        if not isinstance(image, str) or _IMAGE_DIGEST_RE.fullmatch(image) is None:
            raise ReplayIntegrityError(
                f"{context} zeek_image must be an immutable image digest"
            )
        if tls_fingerprint_mode != "none":
            if not isinstance(lock_sha, str) or _SHA256_RE.fullmatch(lock_sha) is None:
                raise ReplayIntegrityError(
                    f"{context} has invalid fingerprint runtime_lock_sha256"
                )
            if (
                not isinstance(runtime_config_digest, str)
                or _DIGEST_ID_RE.fullmatch(runtime_config_digest) is None
            ):
                raise ReplayIntegrityError(
                    f"{context} has invalid fingerprint runtime_config_digest"
                )
        elif lock_sha is not None or runtime_config_digest is not None:
            raise ReplayIntegrityError(
                f"{context} standard runtime must not claim a fingerprint lock identity"
            )
        if deterministic is not True:
            raise ReplayIntegrityError(
                f"{context} is not a deterministic dataset replay configuration"
            )
        if (
            isinstance(window_secs, bool)
            or not isinstance(window_secs, (int, float))
            or not math.isfinite(float(window_secs))
            or float(window_secs) <= 0.0
        ):
            raise ReplayIntegrityError(f"{context} has invalid window_secs")
        if not isinstance(sensor_id, str) or not sensor_id:
            raise ReplayIntegrityError(f"{context} has invalid sensor_id")

        return cls(
            config_version=config_version,
            feature_profile=profile,
            feature_profile_revision=feature_profile_revision,
            tls_fingerprint_mode=tls_fingerprint_mode,
            runtime_mode=runtime_mode,
            zeek_image=image,
            runtime_lock_sha256=lock_sha,
            runtime_config_digest=runtime_config_digest,
            deterministic_zeek=True,
            window_secs=float(window_secs),
            sensor_id=sensor_id,
        )


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_ja4_runtime_identity() -> tuple[str, str, str]:
    try:
        lock_bytes = JA4_RUNTIME_LOCK.read_bytes()
    except OSError as exc:
        raise ReplayIntegrityError(
            f"qualified JA4 runtime lock is unavailable: {JA4_RUNTIME_LOCK}: {exc}"
        ) from exc

    values: dict[str, str] = {}
    try:
        for line in lock_bytes.decode("utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            name, separator, value = line.partition("=")
            if not separator or not name or not value:
                raise ValueError(f"invalid line {line!r}")
            values[name] = value
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReplayIntegrityError(
            f"qualified JA4 runtime lock is malformed: {JA4_RUNTIME_LOCK}: {exc}"
        ) from exc

    image = values.get("JA4_IMAGE_DIGEST")
    config_digest = values.get("JA4_CONFIG_DIGEST")
    if not isinstance(image, str) or _IMAGE_DIGEST_RE.fullmatch(image) is None:
        raise ReplayIntegrityError("JA4 runtime lock has no immutable JA4_IMAGE_DIGEST")
    if (
        not isinstance(config_digest, str)
        or _DIGEST_ID_RE.fullmatch(config_digest) is None
    ):
        raise ReplayIntegrityError("JA4 runtime lock has no valid JA4_CONFIG_DIGEST")
    return image, hashlib.sha256(lock_bytes).hexdigest(), config_digest


def _read_tls_fingerprint_runtime_identity() -> tuple[str, str, str]:
    try:
        lock_bytes = TLS_FINGERPRINT_RUNTIME_LOCK.read_bytes()
    except OSError as exc:
        raise ReplayIntegrityError(
            "qualified TLS fingerprint runtime lock is unavailable: "
            f"{TLS_FINGERPRINT_RUNTIME_LOCK}: {exc}"
        ) from exc

    values: dict[str, str] = {}
    try:
        for line in lock_bytes.decode("utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            name, separator, value = line.partition("=")
            if not separator or not name or not value:
                raise ValueError(f"invalid line {line!r}")
            values[name] = value
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReplayIntegrityError(
            "qualified TLS fingerprint runtime lock is malformed: "
            f"{TLS_FINGERPRINT_RUNTIME_LOCK}: {exc}"
        ) from exc

    image = values.get("TLS_FP_IMAGE_DIGEST")
    config_digest = values.get("TLS_FP_CONFIG_DIGEST")
    if not isinstance(image, str) or _IMAGE_DIGEST_RE.fullmatch(image) is None:
        raise ReplayIntegrityError(
            "TLS fingerprint runtime lock has no immutable TLS_FP_IMAGE_DIGEST"
        )
    if (
        not isinstance(config_digest, str)
        or _DIGEST_ID_RE.fullmatch(config_digest) is None
    ):
        raise ReplayIntegrityError(
            "TLS fingerprint runtime lock has no valid TLS_FP_CONFIG_DIGEST"
        )
    return image, hashlib.sha256(lock_bytes).hexdigest(), config_digest


def _requested_config(
    feature_profile: str,
    use_ja4: bool,
    window_secs: float,
    use_tls_fingerprints: bool = False,
) -> ReplayConfig:
    if feature_profile not in FEATURE_PROFILES:
        raise ReplayIntegrityError(
            f"unsupported feature profile {feature_profile!r}; "
            f"expected one of {', '.join(FEATURE_PROFILES)}"
        )
    if (
        isinstance(window_secs, bool)
        or not isinstance(window_secs, (int, float))
        or not math.isfinite(float(window_secs))
        or float(window_secs) <= 0.0
    ):
        raise ReplayIntegrityError("window_secs must be a finite positive number")

    if use_ja4 and use_tls_fingerprints:
        raise ReplayIntegrityError("--ja4 and --tls-fingerprints are mutually exclusive")

    if use_tls_fingerprints:
        image, lock_sha, runtime_config_digest = (
            _read_tls_fingerprint_runtime_identity()
        )
        runtime_mode = "tls-fingerprints"
        tls_fingerprint_mode = "ja3-ja3s-ja4"
    elif use_ja4:
        image, lock_sha, runtime_config_digest = _read_ja4_runtime_identity()
        runtime_mode = "ja4"
        tls_fingerprint_mode = "ja4"
    else:
        image = STANDARD_ZEEK_IMAGE
        lock_sha = None
        runtime_config_digest = None
        runtime_mode = "standard"
        tls_fingerprint_mode = "none"

    return ReplayConfig(
        config_version=REPLAY_CONFIG_VERSION,
        feature_profile=feature_profile,
        feature_profile_revision=FEATURE_PROFILE_REVISIONS[feature_profile],
        tls_fingerprint_mode=tls_fingerprint_mode,
        runtime_mode=runtime_mode,
        zeek_image=image,
        runtime_lock_sha256=lock_sha,
        runtime_config_digest=runtime_config_digest,
        deterministic_zeek=True,
        window_secs=float(window_secs),
        sensor_id=DATASET_SENSOR_ID,
    )


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def replay_id_for(sha256: str, label: str) -> str:
    """Return the frozen UUIDv5 identity derived from PCAP SHA-256 and label."""

    return str(uuid.uuid5(DATASET_NS, f"{sha256}:{label}"))


def _expected_features_relative(replay_id: str) -> str:
    return PurePosixPath("output", replay_id, "features.jsonl").as_posix()


def _resolve_features_path(
    dataset_root: Path, replay_id: str, serialized: object, context: str
) -> Path:
    if not isinstance(serialized, str) or not serialized or "\\" in serialized:
        raise ReplayIntegrityError(
            f"{context} features_path must be a POSIX-style relative path"
        )
    relative = PurePosixPath(serialized)
    expected = PurePosixPath(_expected_features_relative(replay_id))
    if relative.is_absolute() or ".." in relative.parts or relative != expected:
        raise ReplayIntegrityError(
            f"{context} features_path must be exactly {expected.as_posix()}"
        )
    return dataset_root.joinpath(*relative.parts)


def _portable_pcap_source(pcap_path: Path, dataset_root: Path) -> str:
    resolved = pcap_path.resolve()
    for root, prefix in (
        (dataset_root.resolve(), None),
        (REPO_ROOT.resolve(), "repository"),
    ):
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError:
            continue
        return relative if prefix is None else f"{prefix}/{relative}"
    return PurePosixPath("external", resolved.name).as_posix()


def _is_portable_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts


def _validate_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ReplayIntegrityError(f"{context} must be a lowercase SHA-256")
    return value


def _validate_central_entry(
    dataset_root: Path, replay_id: str, entry: object
) -> None:
    context = f"central replay {replay_id!r}"
    if not isinstance(entry, dict):
        raise ReplayIntegrityError(f"{context} must be an object")
    sha256 = _validate_sha256(entry.get("sha256"), f"{context} sha256")
    label = entry.get("label")
    if label not in ALLOWED_LABELS:
        raise ReplayIntegrityError(f"{context} has invalid label")
    if entry.get("replay_id") != replay_id or replay_id_for(sha256, label) != replay_id:
        raise ReplayIntegrityError(
            f"{context} identity does not match replay_id/sha256/label"
        )
    _resolve_features_path(
        dataset_root, replay_id, entry.get("features_path"), context
    )
    if not isinstance(entry.get("pcap_source"), str) or not entry["pcap_source"]:
        raise ReplayIntegrityError(f"{context} has invalid pcap_source")
    if not isinstance(entry.get("created_at"), str) or not entry["created_at"]:
        raise ReplayIntegrityError(f"{context} has invalid created_at")

    modern = ("config", "config_sha256", "features_sha256")
    present = [name in entry for name in modern]
    if any(present) and not all(present):
        raise ReplayIntegrityError(
            f"{context} has a partial modern integrity binding"
        )
    if not all(present):
        return

    if not _is_portable_relative_path(entry["pcap_source"]):
        raise ReplayIntegrityError(
            f"{context} modern pcap_source must be portable and relative"
        )
    config = ReplayConfig.from_mapping(entry["config"], context)
    config_sha = _validate_sha256(
        entry["config_sha256"], f"{context} config_sha256"
    )
    if config_sha != config.sha256:
        raise ReplayIntegrityError(f"{context} config fingerprint does not match config")
    _validate_sha256(entry["features_sha256"], f"{context} features_sha256")
    mirrors = [
        ("feature_profile", config.feature_profile),
        ("use_ja4", config.use_ja4),
        ("zeek_image", config.zeek_image),
    ]
    if config.config_version != 1:
        mirrors.extend(
            [
                ("feature_profile_revision", config.feature_profile_revision),
                ("tls_fingerprint_mode", config.tls_fingerprint_mode),
                ("runtime_mode", config.runtime_mode),
            ]
        )
    for mirror, expected in mirrors:
        if entry.get(mirror) != expected:
            raise ReplayIntegrityError(
                f"{context} {mirror} does not agree with authoritative config"
            )


def _load_metadata(dataset_root: Path) -> dict:
    meta_path = dataset_root / "metadata.json"
    if not meta_path.exists():
        return {"metadata_version": METADATA_VERSION, "replays": {}}
    if meta_path.is_symlink() or not meta_path.is_file():
        sys.exit(f"ERROR: invalid dataset metadata {meta_path}: not a regular file")
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"ERROR: invalid dataset metadata {meta_path}: {exc}")
    if not isinstance(data, dict):
        sys.exit(f"ERROR: invalid dataset metadata {meta_path}: root must be an object")
    version = data.get("metadata_version")
    if version is not None and version not in (1, METADATA_VERSION):
        sys.exit(
            f"ERROR: invalid dataset metadata {meta_path}: unsupported metadata_version"
        )
    if "replays" not in data:
        data["replays"] = {}
    if not isinstance(data["replays"], dict):
        sys.exit(
            f"ERROR: invalid dataset metadata {meta_path}: replays must be an object"
        )
    try:
        for replay_id, entry in data["replays"].items():
            _validate_central_entry(dataset_root, replay_id, entry)
    except ReplayIntegrityError as exc:
        raise SystemExit(f"ERROR: invalid dataset metadata {meta_path}: {exc}") from exc
    return data


def _atomic_replace_file(source: Path, destination: Path) -> None:
    os.replace(source, destination)


def _replace_directory(source: Path, destination: Path) -> None:
    os.replace(source, destination)


def _write_json_atomic(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        payload = _canonical_json_bytes(value) + b"\n"
        with open(temporary, "xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _atomic_replace_file(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _save_metadata_atomic(dataset_root: Path, data: dict) -> None:
    data = copy.deepcopy(data)
    data["metadata_version"] = METADATA_VERSION
    _write_json_atomic(dataset_root / "metadata.json", data)


@contextmanager
def _metadata_lock(dataset_root: Path) -> Iterator[None]:
    lock_path = dataset_root / "metadata.json.lock"
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise SystemExit(
            f"ERROR: dataset metadata lock already exists: {lock_path}; "
            "another ingestion may be active or operator recovery is required"
        ) from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(f"pid={os.getpid()}\n".encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        yield
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _central_config(entry: dict) -> ReplayConfig | None:
    if "config" not in entry:
        return None
    return ReplayConfig.from_mapping(entry["config"], "central replay")


def _load_and_validate_per_meta(
    meta_path: Path,
    features_path: Path,
    replay_id: str,
    sha256: str,
    label: str,
) -> tuple[dict, ReplayConfig, str]:
    if meta_path.is_symlink() or not meta_path.is_file():
        raise ReplayIntegrityError("per-replay meta.json is missing or not a regular file")
    if features_path.is_symlink() or not features_path.is_file():
        raise ReplayIntegrityError(
            "features.jsonl is missing, is a symlink, or is not a regular file"
        )
    try:
        per_meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReplayIntegrityError(f"per-replay meta.json is malformed: {exc}") from exc
    if not isinstance(per_meta, dict):
        raise ReplayIntegrityError("per-replay meta.json root must be an object")
    if per_meta.get("metadata_version") != METADATA_VERSION:
        raise ReplayIntegrityError(
            "per-replay metadata is ambiguous/legacy and cannot be reused; "
            "use --force to rebuild it under an explicit configuration"
        )
    if per_meta.get("replay_id") != replay_id:
        raise ReplayIntegrityError("per-replay replay_id disagrees with expected identity")
    if per_meta.get("sha256") != sha256:
        raise ReplayIntegrityError("per-replay PCAP SHA-256 disagrees with requested bytes")
    if per_meta.get("label") != label:
        raise ReplayIntegrityError("per-replay label disagrees with requested label")
    if not _is_portable_relative_path(per_meta.get("pcap_source")):
        raise ReplayIntegrityError("per-replay pcap_source is not portable and relative")
    if not isinstance(per_meta.get("created_at"), str) or not per_meta["created_at"]:
        raise ReplayIntegrityError("per-replay created_at is invalid")

    config = ReplayConfig.from_mapping(
        per_meta.get("config"), "per-replay metadata"
    )
    stored_config_sha = _validate_sha256(
        per_meta.get("config_sha256"), "per-replay config_sha256"
    )
    if stored_config_sha != config.sha256:
        raise ReplayIntegrityError(
            "per-replay config fingerprint does not match its configuration"
        )

    artifacts = per_meta.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ReplayIntegrityError("per-replay artifacts must be an object")
    if artifacts.get("features") != "features.jsonl" or artifacts.get("meta") != "meta.json":
        raise ReplayIntegrityError("per-replay artifact paths are not the expected local names")

    stored_features_sha = _validate_sha256(
        per_meta.get("features_sha256"), "per-replay features_sha256"
    )
    actual_features_sha = _sha256_file(features_path)
    if actual_features_sha != stored_features_sha:
        raise ReplayIntegrityError(
            "features.jsonl SHA-256 does not match per-replay metadata"
        )
    return per_meta, config, actual_features_sha


def _entry_from_artifact(
    per_meta: dict,
    config: ReplayConfig,
    features_sha256: str,
    replay_id: str,
) -> dict:
    entry = {
        "replay_id": replay_id,
        "pcap_source": per_meta["pcap_source"],
        "sha256": per_meta["sha256"],
        "label": per_meta["label"],
        "created_at": per_meta["created_at"],
        "features_path": _expected_features_relative(replay_id),
        "features_sha256": features_sha256,
        "feature_profile": config.feature_profile,
        "use_ja4": config.use_ja4,
        "zeek_image": config.zeek_image,
        "config_sha256": config.sha256,
        "config": config.as_dict(),
    }
    if config.config_version != 1:
        entry["feature_profile_revision"] = config.feature_profile_revision
        entry["tls_fingerprint_mode"] = config.tls_fingerprint_mode
        entry["runtime_mode"] = config.runtime_mode
    return entry


def _validate_central_per_meta_agreement(
    central: dict, recovered: dict, replay_id: str
) -> None:
    for field in (
        "replay_id",
        "pcap_source",
        "sha256",
        "label",
        "created_at",
        "features_path",
        "features_sha256",
        "feature_profile",
        "feature_profile_revision",
        "tls_fingerprint_mode",
        "runtime_mode",
        "use_ja4",
        "zeek_image",
        "config_sha256",
        "config",
    ):
        if central.get(field) != recovered.get(field):
            raise ReplayIntegrityError(
                f"central/per-replay metadata disagree on {field} for replay {replay_id}"
            )


def _validate_legacy_central_hints(
    central: dict, recovered: dict, replay_id: str
) -> None:
    for field in (
        "replay_id",
        "pcap_source",
        "sha256",
        "label",
        "created_at",
        "features_path",
        "feature_profile",
        "use_ja4",
        "zeek_image",
    ):
        if field in central and central[field] != recovered.get(field):
            raise ReplayIntegrityError(
                f"incomplete central metadata disagrees with the validated artifact on "
                f"{field} for replay {replay_id}"
            )


def _assert_no_orphan_publication_state(output_root: Path, replay_id: str) -> None:
    prefixes = (f".tmp-{replay_id}-", f".backup-{replay_id}-")
    leftovers = sorted(
        child.name
        for child in output_root.iterdir()
        if any(child.name.startswith(prefix) for prefix in prefixes)
    )
    central_temps = sorted(
        path.name for path in output_root.parent.glob(".metadata.json.*.tmp")
    )
    if leftovers or central_temps:
        raise ReplayIntegrityError(
            "orphan replay publication state requires operator recovery: "
            f"output={leftovers}, registry={central_temps}"
        )


def _reuse_existing(
    dataset_root: Path,
    output_root: Path,
    meta: dict,
    replay_id: str,
    sha256: str,
    label: str,
    expected_config: ReplayConfig,
) -> dict | None:
    replay_dir = output_root / replay_id
    features_path = replay_dir / "features.jsonl"
    meta_path = replay_dir / "meta.json"
    central = meta["replays"].get(replay_id)

    if replay_dir.is_symlink() or (replay_dir.exists() and not replay_dir.is_dir()):
        raise ReplayIntegrityError("replay output path is not a regular directory")
    features_exists = features_path.exists() or features_path.is_symlink()
    per_meta_exists = meta_path.exists() or meta_path.is_symlink()

    if not features_exists and not per_meta_exists:
        if central is not None:
            print(
                f"[recover] Replay {replay_id} is registered but has no local "
                "artifact; rebuilding under the requested configuration."
            )
        elif replay_dir.exists() and any(replay_dir.iterdir()):
            raise ReplayIntegrityError("unregistered replay directory is not empty")
        return None
    if features_exists != per_meta_exists:
        raise ReplayIntegrityError(
            "replay is incomplete: features.jsonl and meta.json must both exist"
        )

    per_meta, stored_config, features_sha = _load_and_validate_per_meta(
        meta_path, features_path, replay_id, sha256, label
    )
    recovered = _entry_from_artifact(
        per_meta, stored_config, features_sha, replay_id
    )

    if central is None:
        needs_recovery = True
    else:
        central_config = _central_config(central)
        if central_config is None:
            _validate_legacy_central_hints(central, recovered, replay_id)
            needs_recovery = True
        else:
            _validate_central_per_meta_agreement(central, recovered, replay_id)
            needs_recovery = False

    if stored_config != expected_config:
        raise ReplayIntegrityError(
            f"replay {replay_id} configuration mismatch: "
            f"stored={stored_config.sha256} requested={expected_config.sha256}; "
            "use --force to explicitly rebuild"
        )

    if needs_recovery:
        updated = copy.deepcopy(meta)
        updated["metadata_version"] = METADATA_VERSION
        updated["replays"][replay_id] = recovered
        _save_metadata_atomic(dataset_root, updated)
        meta.clear()
        meta.update(updated)
        print(
            f"[recover] Rebuilt authoritative central binding for replay {replay_id} "
            "from validated per-replay metadata."
        )
    return recovered


def _warn_same_sha_label(
    meta: dict, sha256: str, label: str, replay_id: str, action: str
) -> None:
    conflict = next(
        (
            (existing_id, entry)
            for existing_id, entry in meta["replays"].items()
            if entry.get("sha256") == sha256
            and entry.get("label") != label
            and existing_id != replay_id
        ),
        None,
    )
    if conflict is None:
        return
    existing_id, entry = conflict
    if action == "create":
        detail = "this request will create another conflicting-label replay"
    elif action == "rebuild":
        detail = "this request will rebuild the replay for the requested label"
    else:
        detail = "this request reuses an existing replay; no new replay will be created"
    print(
        f"[warn] identical PCAP bytes are already registered as "
        f"{entry.get('label')} ({existing_id[:8]}...); requested label={label}; "
        f"{detail}.",
        file=sys.stderr,
    )


def _hash_pcap(pcap_path: Path) -> str:
    try:
        sys.path.insert(0, str(INGESTION_ROOT))
        import ingestion_core  # type: ignore

        if not hasattr(ingestion_core, "sha256_input_file"):
            raise ImportError(
                "ingestion_core wheel is stale; rebuild it with maturin develop "
                "--manifest-path ingestion/Cargo.toml"
            )
        return ingestion_core.sha256_input_file(str(pcap_path))
    except Exception as exc:
        sys.exit(f"ERROR: failed to hash PCAP {pcap_path}: {exc}")
    finally:
        if str(INGESTION_ROOT) in sys.path:
            sys.path.remove(str(INGESTION_ROOT))


def _fsync_file(path: Path) -> None:
    # Windows' CRT rejects fsync on a read-only descriptor, so request write
    # access without modifying the already-complete artifact.
    with open(path, "r+b") as stream:
        os.fsync(stream.fileno())


def _normalize_feature_artifact(path: Path) -> None:
    """Normalize dataset-only JSONL to UTF-8/LF and durably stage it."""

    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.normalize.tmp")
    try:
        with open(path, "r", encoding="utf-8", newline=None) as source:
            with open(temporary, "x", encoding="utf-8", newline="\n") as target:
                shutil.copyfileobj(source, target)
                target.flush()
                os.fsync(target.fileno())
        _atomic_replace_file(temporary, path)
        _fsync_file(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_per_replay_meta(path: Path, value: dict) -> None:
    _write_json_atomic(path, value)


def _safe_remove_tree(path: Path, allowed_parent: Path, allowed_names: set[str]) -> None:
    parent = path.parent.resolve()
    if parent != allowed_parent.resolve() or path.name not in allowed_names:
        raise ReplayIntegrityError(f"refusing to remove unexpected path {path}")
    if path.is_symlink():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def _require_local_dataset_directory(path: Path, dataset_root: Path) -> None:
    """Reject redirected dataset subdirectories before creating or deleting data."""

    if path.is_symlink() or not path.is_dir():
        raise ReplayIntegrityError(
            f"dataset {path.name} path must be a regular local directory"
        )
    try:
        path.resolve().relative_to(dataset_root.resolve())
    except ValueError as exc:
        raise ReplayIntegrityError(
            f"dataset {path.name} path resolves outside the dataset root"
        ) from exc


def _generate_candidate(
    pcap_path: Path,
    pcap_source: str,
    dataset_root: Path,
    output_root: Path,
    replay_id: str,
    sha256: str,
    label: str,
    config: ReplayConfig,
) -> tuple[Path, dict]:
    candidate_dir = Path(
        tempfile.mkdtemp(prefix=f".tmp-{replay_id}-", dir=str(output_root))
    )
    candidate_features = candidate_dir / "features.jsonl"
    candidate_meta = candidate_dir / "meta.json"
    zeek_work = Path(
        tempfile.mkdtemp(prefix="pcap_dataset_zeek_", dir=str(dataset_root))
    )
    try:
        sys.path.insert(0, str(INGESTION_ROOT))
        import pipeline  # type: ignore

        pipeline.run_pipeline(
            str(pcap_path),
            str(zeek_work),
            str(candidate_features),
            window_secs=config.window_secs,
            use_ja4=config.use_ja4,
            use_tls_fingerprints=(
                config.tls_fingerprint_mode == "ja3-ja3s-ja4"
            ),
            skip_zeek=False,
            feature_profile=config.feature_profile,
            deterministic_zeek=config.deterministic_zeek,
        )
        if candidate_features.is_symlink() or not candidate_features.is_file():
            raise ReplayIntegrityError(
                "ingestion pipeline did not produce a regular features.jsonl"
            )
        _normalize_feature_artifact(candidate_features)
        features_sha = _sha256_file(candidate_features)
        created_at = _utc_now_iso()
        per_meta = {
            "metadata_version": METADATA_VERSION,
            "replay_id": replay_id,
            "pcap_source": pcap_source,
            "sha256": sha256,
            "label": label,
            "created_at": created_at,
            "config": config.as_dict(),
            "config_sha256": config.sha256,
            "features_sha256": features_sha,
            "artifacts": {
                "features": "features.jsonl",
                "meta": "meta.json",
            },
        }
        _write_per_replay_meta(candidate_meta, per_meta)
        validated_meta, validated_config, validated_features_sha = (
            _load_and_validate_per_meta(
                candidate_meta, candidate_features, replay_id, sha256, label
            )
        )
        if validated_config != config or validated_features_sha != features_sha:
            raise ReplayIntegrityError("candidate replay validation changed its binding")
        entry = _entry_from_artifact(
            validated_meta, validated_config, validated_features_sha, replay_id
        )
        return candidate_dir, entry
    except BaseException:
        if candidate_dir.exists():
            _safe_remove_tree(candidate_dir, output_root, {candidate_dir.name})
        raise
    finally:
        if str(INGESTION_ROOT) in sys.path:
            sys.path.remove(str(INGESTION_ROOT))
        if zeek_work.exists():
            _safe_remove_tree(zeek_work, dataset_root, {zeek_work.name})


def _publish_candidate(
    dataset_root: Path,
    output_root: Path,
    replay_id: str,
    candidate_dir: Path,
    entry: dict,
    starting_metadata: dict,
) -> dict:
    replay_dir = output_root / replay_id
    backup_dir = output_root / f".backup-{replay_id}-{uuid.uuid4().hex}"
    previous_exists = replay_dir.exists() or replay_dir.is_symlink()
    moved_previous = False
    published_candidate = False
    current_metadata = _load_metadata(dataset_root)
    if current_metadata != starting_metadata:
        raise ReplayIntegrityError(
            "central metadata changed while replay generation was in progress"
        )
    updated = copy.deepcopy(current_metadata)
    updated["metadata_version"] = METADATA_VERSION
    updated["replays"][replay_id] = entry

    try:
        if previous_exists:
            if replay_dir.is_symlink() or not replay_dir.is_dir():
                raise ReplayIntegrityError(
                    "existing replay path is not a regular directory"
                )
            _replace_directory(replay_dir, backup_dir)
            moved_previous = True
        _replace_directory(candidate_dir, replay_dir)
        published_candidate = True
        _save_metadata_atomic(dataset_root, updated)
    except BaseException as exc:
        rollback_errors: list[str] = []
        try:
            if published_candidate and replay_dir.exists():
                _safe_remove_tree(replay_dir, output_root, {replay_id})
        except Exception as rollback_exc:
            rollback_errors.append(f"new artifact cleanup failed: {rollback_exc}")
        try:
            if moved_previous and backup_dir.exists():
                _replace_directory(backup_dir, replay_dir)
        except Exception as rollback_exc:
            rollback_errors.append(f"old artifact restore failed: {rollback_exc}")
        try:
            if candidate_dir.exists():
                _safe_remove_tree(candidate_dir, output_root, {candidate_dir.name})
        except Exception as rollback_exc:
            rollback_errors.append(f"candidate cleanup failed: {rollback_exc}")
        if rollback_errors:
            raise ReplayIntegrityError(
                "publication failed and automatic rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        raise

    if backup_dir.exists():
        try:
            _safe_remove_tree(backup_dir, output_root, {backup_dir.name})
        except Exception as exc:
            print(
                f"[warn] published replay is valid but old backup cleanup failed: "
                f"{backup_dir}: {exc}",
                file=sys.stderr,
            )
    return entry


def ingest_one(
    pcap_path: Path,
    label: str,
    dataset_root: Path,
    window_secs: float = 60.0,
    force: bool = False,
    feature_profile: str = DATASET_FEATURE_PROFILE,
    use_ja4: bool = False,
    use_tls_fingerprints: bool = False,
) -> dict:
    if label not in ALLOWED_LABELS:
        sys.exit(f"ERROR: label must be one of {sorted(ALLOWED_LABELS)} (got {label!r})")
    try:
        config = _requested_config(
            feature_profile, use_ja4, window_secs, use_tls_fingerprints
        )
    except ReplayIntegrityError as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
    if not pcap_path.is_file():
        sys.exit(f"ERROR: PCAP not found: {pcap_path}")

    dataset_root = dataset_root.resolve()
    raw_root = dataset_root / "raw"
    output_root = dataset_root / "output"
    raw_root.mkdir(parents=True, exist_ok=True)
    output_root.mkdir(parents=True, exist_ok=True)
    try:
        _require_local_dataset_directory(raw_root, dataset_root)
        _require_local_dataset_directory(output_root, dataset_root)
    except ReplayIntegrityError as exc:
        raise SystemExit(f"ERROR: replay integrity check failed: {exc}") from exc
    sha256 = _hash_pcap(pcap_path)
    replay_id = replay_id_for(sha256, label)
    pcap_source = _portable_pcap_source(pcap_path, dataset_root)

    with _metadata_lock(dataset_root):
        try:
            _assert_no_orphan_publication_state(output_root, replay_id)
            meta = _load_metadata(dataset_root)
            if not force:
                existing = _reuse_existing(
                    dataset_root,
                    output_root,
                    meta,
                    replay_id,
                    sha256,
                    label,
                    config,
                )
                if existing is not None:
                    _warn_same_sha_label(
                        meta, sha256, label, replay_id, action="reuse"
                    )
                    print(
                        f"[=] Replay {replay_id} already exists for {pcap_path.name} "
                        f"label={label}; integrity verified, idempotent reuse. "
                        "Use --force to regenerate."
                    )
                    return existing

            action = (
                "rebuild"
                if force
                or replay_id in meta["replays"]
                or (output_root / replay_id).exists()
                else "create"
            )
            _warn_same_sha_label(meta, sha256, label, replay_id, action=action)
            candidate_dir, entry = _generate_candidate(
                pcap_path,
                pcap_source,
                dataset_root,
                output_root,
                replay_id,
                sha256,
                label,
                config,
            )
            entry = _publish_candidate(
                dataset_root,
                output_root,
                replay_id,
                candidate_dir,
                entry,
                meta,
            )
        except SystemExit:
            raise
        except ReplayIntegrityError as exc:
            raise SystemExit(f"ERROR: replay integrity check failed: {exc}") from exc
        except Exception as exc:
            raise SystemExit(f"ERROR: replay generation/publication failed: {exc}") from exc

    print(
        f"[+] Replay {replay_id} label={label} sha256={sha256[:8]}... "
        f"config={config.sha256[:12]}... features={entry['features_sha256'][:12]}... "
        f"-> {output_root / replay_id / 'features.jsonl'}"
    )
    return entry


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dataset manager: PCAP -> reproducible, integrity-bound features"
    )
    parser.add_argument("--pcap", help="Path to one .pcap or .pcapng file")
    parser.add_argument(
        "--label",
        choices=sorted(ALLOWED_LABELS),
        help="Threat class label (seven detection classes plus benign)",
    )
    parser.add_argument(
        "--batch", help="Directory of PCAP files to ingest with the same --label"
    )
    parser.add_argument(
        "--dataset-root",
        default=str(DEFAULT_DATASET_ROOT),
        help="Dataset root (default: repository pcap_dataset directory)",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=60.0,
        help="Sliding window size in seconds (default: 60)",
    )
    parser.add_argument(
        "--feature-profile",
        choices=FEATURE_PROFILES,
        default=DATASET_FEATURE_PROFILE,
        help=(
            "Feature contract: detector-v2 (default, retains detector telemetry) "
            "or frozen legacy-m1d"
        ),
    )
    fingerprint_group = parser.add_mutually_exclusive_group()
    fingerprint_group.add_argument(
        "--ja4",
        action="store_true",
        help=(
            "Use the pinned, locally qualified JA4-only runtime"
        ),
    )
    fingerprint_group.add_argument(
        "--tls-fingerprints",
        action="store_true",
        help="Use the pinned, locally qualified JA3/JA3S/JA4 runtime",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate through staged validation while preserving old output on failure",
    )
    args = parser.parse_args()

    dataset_root = Path(args.dataset_root).resolve()
    dataset_root.mkdir(parents=True, exist_ok=True)
    (dataset_root / "raw").mkdir(exist_ok=True)
    (dataset_root / "output").mkdir(exist_ok=True)

    if args.batch and args.pcap:
        parser.error("--batch and --pcap are mutually exclusive")
    if args.batch:
        if not args.label:
            parser.error("--batch requires --label")
        batch_dir = Path(args.batch)
        if not batch_dir.is_dir():
            sys.exit(f"ERROR: --batch directory not found: {batch_dir}")
        pcaps = sorted(batch_dir.glob("*.pcap")) + sorted(batch_dir.glob("*.pcapng"))
        if not pcaps:
            sys.exit(f"ERROR: no .pcap or .pcapng files in {batch_dir}")
        for path in pcaps:
            ingest_one(
                path,
                args.label,
                dataset_root,
                window_secs=args.window,
                force=args.force,
                feature_profile=args.feature_profile,
                use_ja4=args.ja4,
                use_tls_fingerprints=args.tls_fingerprints,
            )
        print(f"[+] Batch done: {len(pcaps)} files -> {dataset_root / 'output'}")
        return
    if args.pcap:
        if not args.label:
            parser.error("--pcap requires --label")
        ingest_one(
            Path(args.pcap),
            args.label,
            dataset_root,
            window_secs=args.window,
            force=args.force,
            feature_profile=args.feature_profile,
            use_ja4=args.ja4,
            use_tls_fingerprints=args.tls_fingerprints,
        )
        return
    parser.error("provide --pcap or --batch")


if __name__ == "__main__":
    main()
