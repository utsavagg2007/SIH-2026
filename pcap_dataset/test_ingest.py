"""Replay identity, integrity binding, recovery, and publication tests."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import types

import pytest

from pcap_dataset import ingest


FIXTURE = (
    Path(__file__).parents[1]
    / "ingestion"
    / "tests"
    / "fixtures"
    / "pcap"
    / "m1d_synthetic.pcap"
)
FIXTURE_SHA = "87082cf96b12f7c90ca6b25fccc99650e9967daa409d85f132a5783068673bd9"


@pytest.fixture(autouse=True)
def _stable_fixture_hash(monkeypatch):
    monkeypatch.setattr(ingest, "_hash_pcap", lambda _path: FIXTURE_SHA)


@pytest.fixture
def dataset_root(tmp_path: Path) -> Path:
    root = tmp_path / "dataset"
    root.mkdir()
    (root / "metadata.json").write_text('{"replays": {}}\n', encoding="utf-8")
    return root


def _fake_pipeline(monkeypatch, payload: bytes = b'{"flow_id":"fixture"}\n'):
    state: dict[str, object] = {"payload": payload, "failure": None}
    calls: list[tuple[tuple, dict]] = []

    def run_pipeline(*args, **kwargs):
        calls.append((args, kwargs))
        failure = state["failure"]
        if failure is not None:
            raise failure
        Path(args[2]).write_bytes(state["payload"])
        return []

    module = types.SimpleNamespace(run_pipeline=run_pipeline)
    monkeypatch.setitem(sys.modules, "pipeline", module)
    return calls, state


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _paths(root: Path, entry: dict) -> tuple[Path, Path, Path]:
    features = root.joinpath(*entry["features_path"].split("/"))
    return features, features.parent / "meta.json", root / "metadata.json"


def _fresh(root: Path, monkeypatch, **kwargs):
    calls, state = _fake_pipeline(monkeypatch)
    entry = ingest.ingest_one(FIXTURE, "benign", root, **kwargs)
    return entry, calls, state


def _rehash_per_meta(per_meta: dict) -> None:
    config = ingest.ReplayConfig.from_mapping(per_meta["config"], "test")
    per_meta["config_sha256"] = config.sha256


def _snapshot(root: Path, entry: dict) -> tuple[bytes, bytes, bytes]:
    features, per_meta, central = _paths(root, entry)
    return features.read_bytes(), per_meta.read_bytes(), central.read_bytes()


def test_ingestion_root_uses_integrated_directory():
    assert ingest.INGESTION_ROOT == Path(__file__).parents[1] / "ingestion"
    assert (ingest.INGESTION_ROOT / "Cargo.toml").is_file()


def test_replay_id_has_fixed_sha_and_label_vectors():
    assert (
        ingest.replay_id_for(FIXTURE_SHA, "benign")
        == "92838b0f-1d70-550c-a566-c33f0ba26aba"
    )
    assert (
        ingest.replay_id_for(FIXTURE_SHA, "ddos")
        == "694071ae-3ca4-5248-82c9-c11d77274ead"
    )


def test_configuration_fingerprint_is_canonical_and_runtime_bound():
    standard = ingest._requested_config("detector-v2", False, 60)
    reordered = dict(reversed(list(standard.as_dict().items())))
    assert ingest.ReplayConfig.from_mapping(reordered, "test") == standard
    assert (
        standard.sha256
        == "c2c93bba62492734c7b16e015de82c11977e11158d56dae1d9ae4563139d5fd8"
    )
    assert standard.deterministic_zeek is True
    assert standard.zeek_image == ingest.STANDARD_ZEEK_IMAGE
    ja4 = ingest._requested_config("detector-v2", True, 60)
    assert ja4.sha256 != standard.sha256
    assert ja4.runtime_lock_sha256
    assert ja4.runtime_config_digest
    assert "@sha256:" in ja4.zeek_image
    full = ingest._requested_config("detector-v2", False, 60, True)
    assert full.sha256 == "7f2dac4bcbea1e7925095d99786e1901b6b29e7be3da735e6694fcab979e593b"
    assert full.tls_fingerprint_mode == "ja3-ja3s-ja4"
    assert full.runtime_mode == "tls-fingerprints"
    assert full.runtime_lock_sha256 and full.runtime_config_digest
    assert len({standard.sha256, ja4.sha256, full.sha256}) == 3


def test_pre_transaction_array_config_remains_readable_but_not_equivalent():
    old = {
        "config_version": 1,
        "deterministic_zeek": True,
        "feature_profile": "detector-v2",
        "runtime_config_digest": None,
        "runtime_lock_sha256": None,
        "runtime_mode": "standard",
        "sensor_id": ingest.DATASET_SENSOR_ID,
        "use_ja4": False,
        "window_secs": 60.0,
        "zeek_image": ingest.STANDARD_ZEEK_IMAGE,
    }
    parsed = ingest.ReplayConfig.from_mapping(old, "old replay")
    current = ingest._requested_config("detector-v2", False, 60)
    assert parsed.as_dict() == old
    assert parsed.sha256 == "56651f9eca44fe619332c838ba0d8a27f7d443b689a58b2eb8861de6614861cd"
    assert parsed != current
    assert parsed.feature_profile_revision == 1
    assert current.feature_profile_revision == 2


def test_pre_transaction_array_replay_requires_explicit_rebuild(
    dataset_root: Path, monkeypatch
):
    entry, calls, _state = _fresh(dataset_root, monkeypatch)
    _features, per_meta_path, central_path = _paths(dataset_root, entry)
    old_config = {
        "config_version": 1,
        "deterministic_zeek": True,
        "feature_profile": "detector-v2",
        "runtime_config_digest": None,
        "runtime_lock_sha256": None,
        "runtime_mode": "standard",
        "sensor_id": ingest.DATASET_SENSOR_ID,
        "use_ja4": False,
        "window_secs": 60.0,
        "zeek_image": ingest.STANDARD_ZEEK_IMAGE,
    }
    old_sha = ingest.ReplayConfig.from_mapping(old_config, "old replay").sha256
    per_meta = _read_json(per_meta_path)
    per_meta["config"] = old_config
    per_meta["config_sha256"] = old_sha
    _write_json(per_meta_path, per_meta)
    central = _read_json(central_path)
    central_entry = central["replays"][entry["replay_id"]]
    central_entry["config"] = old_config
    central_entry["config_sha256"] = old_sha
    for field in ("feature_profile_revision", "tls_fingerprint_mode", "runtime_mode"):
        central_entry.pop(field, None)
    _write_json(central_path, central)

    with pytest.raises(SystemExit, match="configuration mismatch"):
        ingest.ingest_one(FIXTURE, "benign", dataset_root)
    assert len(calls) == 1


@pytest.mark.parametrize(
    "bad_path",
    [
        "../escape.jsonl",
        "/absolute/features.jsonl",
        r"output\92838b0f-1d70-550c-a566-c33f0ba26aba\features.jsonl",
        "output/not-the-replay/features.jsonl",
    ],
)
def test_invalid_registry_identity_and_paths_fail_closed(
    tmp_path: Path, bad_path: str
):
    replay_id = ingest.replay_id_for(FIXTURE_SHA, "benign")
    bad = {
        "replays": {
            replay_id: {
                "replay_id": replay_id,
                "sha256": FIXTURE_SHA,
                "label": "benign",
                "pcap_source": "raw/fixture.pcap",
                "created_at": "2026-01-01T00:00:00Z",
                "features_path": bad_path,
            }
        }
    }
    (tmp_path / "metadata.json").write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(SystemExit, match="features_path"):
        ingest._load_metadata(tmp_path)


def test_ingest_writes_complete_binding_and_reuses_only_after_validation(
    dataset_root: Path, monkeypatch
):
    entry, calls, _state = _fresh(dataset_root, monkeypatch)
    second = ingest.ingest_one(FIXTURE, "benign", dataset_root)

    assert entry == second
    assert len(calls) == 1
    assert calls[0][1]["feature_profile"] == "detector-v2"
    assert calls[0][1]["use_ja4"] is False
    assert calls[0][1]["deterministic_zeek"] is True
    assert "\\" not in entry["features_path"]
    assert entry["features_path"].startswith("output/")
    features, per_meta_path, _central_path = _paths(dataset_root, entry)
    per_meta = _read_json(per_meta_path)
    assert entry["features_sha256"] == hashlib.sha256(features.read_bytes()).hexdigest()
    assert per_meta["features_sha256"] == entry["features_sha256"]
    assert per_meta["config"] == entry["config"]
    assert per_meta["config_sha256"] == entry["config_sha256"]
    assert per_meta["metadata_version"] == ingest.METADATA_VERSION
    assert not Path(per_meta["pcap_source"]).is_absolute()
    assert "\\" not in per_meta["pcap_source"]


def test_invalid_label_and_profile_are_rejected_before_processing(
    dataset_root: Path
):
    with pytest.raises(SystemExit, match="label must be one of"):
        ingest.ingest_one(FIXTURE, "not-a-threat-class", dataset_root)
    with pytest.raises(SystemExit, match="unsupported feature profile"):
        ingest.ingest_one(
            FIXTURE, "benign", dataset_root, feature_profile="legacy"
        )


def test_legacy_m1d_profile_reaches_deterministic_pipeline(
    dataset_root: Path, monkeypatch
):
    entry, calls, _state = _fresh(
        dataset_root, monkeypatch, feature_profile="legacy-m1d"
    )
    assert calls[0][1]["feature_profile"] == "legacy-m1d"
    assert calls[0][1]["deterministic_zeek"] is True
    assert entry["config"]["feature_profile"] == "legacy-m1d"


@pytest.mark.parametrize(
    "override",
    [
        {"feature_profile": "legacy-m1d"},
        {"use_ja4": True},
        {"window_secs": 30.0},
    ],
    ids=["profile", "ja4", "window"],
)
def test_configuration_mismatch_never_reuses(
    dataset_root: Path, monkeypatch, override: dict
):
    _entry, calls, _state = _fresh(dataset_root, monkeypatch)
    with pytest.raises(SystemExit, match="configuration mismatch"):
        ingest.ingest_one(FIXTURE, "benign", dataset_root, **override)
    assert len(calls) == 1


def test_previous_pr_detector_artifact_is_never_guessed_as_legacy(
    dataset_root: Path, monkeypatch
):
    entry, calls, _state = _fresh(dataset_root, monkeypatch)
    _features, per_meta_path, central_path = _paths(dataset_root, entry)
    modern_per_meta = _read_json(per_meta_path)
    previous_per_meta = {
        "replay_id": modern_per_meta["replay_id"],
        "pcap_source": modern_per_meta["pcap_source"],
        "sha256": modern_per_meta["sha256"],
        "label": modern_per_meta["label"],
        "created_at": modern_per_meta["created_at"],
        "pipeline": {
            "window_secs": 60.0,
            "sensor_id": ingest.DATASET_SENSOR_ID,
            "zeek_image": ingest.STANDARD_ZEEK_IMAGE,
            "feature_profile": "detector-v2",
            "use_ja4": False,
        },
        "artifacts": {"features": "features.jsonl", "meta": "meta.json"},
    }
    _write_json(per_meta_path, previous_per_meta)
    central = _read_json(central_path)
    previous_entry = central["replays"][entry["replay_id"]]
    for field in (
        "config",
        "config_sha256",
        "features_sha256",
        "feature_profile",
        "use_ja4",
        "zeek_image",
    ):
        previous_entry.pop(field, None)
    _write_json(central_path, central)

    with pytest.raises(SystemExit, match="ambiguous/legacy"):
        ingest.ingest_one(
            FIXTURE,
            "benign",
            dataset_root,
            feature_profile="legacy-m1d",
        )
    with pytest.raises(SystemExit, match="ambiguous/legacy"):
        ingest.ingest_one(FIXTURE, "benign", dataset_root)
    assert len(calls) == 1


def test_valid_per_meta_only_artifact_recovers_central_registry(
    dataset_root: Path, monkeypatch
):
    entry, calls, _state = _fresh(dataset_root, monkeypatch)
    central_path = dataset_root / "metadata.json"
    central = _read_json(central_path)
    del central["replays"][entry["replay_id"]]
    _write_json(central_path, central)

    recovered = ingest.ingest_one(FIXTURE, "benign", dataset_root)
    assert recovered == entry
    assert len(calls) == 1
    assert _read_json(central_path)["replays"][entry["replay_id"]] == entry


def test_incomplete_central_entry_recovers_from_complete_per_meta(
    dataset_root: Path, monkeypatch
):
    entry, calls, _state = _fresh(dataset_root, monkeypatch)
    central_path = dataset_root / "metadata.json"
    central = _read_json(central_path)
    incomplete = central["replays"][entry["replay_id"]]
    for field in ("config", "config_sha256", "features_sha256"):
        incomplete.pop(field)
    _write_json(central_path, central)

    recovered = ingest.ingest_one(FIXTURE, "benign", dataset_root)
    assert recovered == entry
    assert len(calls) == 1
    assert _read_json(central_path)["replays"][entry["replay_id"]] == entry


@pytest.mark.parametrize(
    "corruption",
    [
        "missing_meta",
        "malformed_meta",
        "wrong_replay_id",
        "wrong_sha",
        "wrong_label",
        "wrong_pcap_source",
        "wrong_profile",
        "wrong_use_ja4",
        "wrong_runtime",
        "wrong_config_fingerprint",
        "wrong_central_config_fingerprint",
        "partial_modern_central",
        "wrong_per_meta_features_sha",
        "wrong_central_features_sha",
        "modified_features",
        "central_per_meta_disagreement",
        "missing_features",
    ],
)
def test_corruption_matrix_fails_closed(
    dataset_root: Path, monkeypatch, corruption: str
):
    entry, calls, _state = _fresh(dataset_root, monkeypatch)
    features, per_meta_path, central_path = _paths(dataset_root, entry)
    per_meta = _read_json(per_meta_path)
    central = _read_json(central_path)
    replay_id = entry["replay_id"]

    if corruption == "missing_meta":
        per_meta_path.unlink()
    elif corruption == "malformed_meta":
        per_meta_path.write_text("{", encoding="utf-8")
    elif corruption == "wrong_replay_id":
        per_meta["replay_id"] = str(uuid_for_test("wrong-replay"))
        _write_json(per_meta_path, per_meta)
    elif corruption == "wrong_sha":
        per_meta["sha256"] = "0" * 64
        _write_json(per_meta_path, per_meta)
    elif corruption == "wrong_label":
        per_meta["label"] = "ddos"
        _write_json(per_meta_path, per_meta)
    elif corruption == "wrong_pcap_source":
        per_meta["pcap_source"] = "external/other.pcap"
        _write_json(per_meta_path, per_meta)
    elif corruption == "wrong_profile":
        per_meta["config"] = ingest._requested_config(
            "legacy-m1d", False, 60
        ).as_dict()
        _rehash_per_meta(per_meta)
        _write_json(per_meta_path, per_meta)
    elif corruption == "wrong_use_ja4":
        per_meta["config"] = ingest._requested_config(
            "detector-v2", True, 60
        ).as_dict()
        _rehash_per_meta(per_meta)
        _write_json(per_meta_path, per_meta)
    elif corruption == "wrong_runtime":
        per_meta["config"]["zeek_image"] = "example.invalid/zeek@sha256:" + "a" * 64
        _rehash_per_meta(per_meta)
        _write_json(per_meta_path, per_meta)
    elif corruption == "wrong_config_fingerprint":
        per_meta["config_sha256"] = "0" * 64
        _write_json(per_meta_path, per_meta)
    elif corruption == "wrong_central_config_fingerprint":
        central["replays"][replay_id]["config_sha256"] = "0" * 64
        _write_json(central_path, central)
    elif corruption == "partial_modern_central":
        del central["replays"][replay_id]["config"]
        _write_json(central_path, central)
    elif corruption == "wrong_per_meta_features_sha":
        per_meta["features_sha256"] = "0" * 64
        _write_json(per_meta_path, per_meta)
    elif corruption == "wrong_central_features_sha":
        central["replays"][replay_id]["features_sha256"] = "0" * 64
        _write_json(central_path, central)
    elif corruption == "modified_features":
        features.write_bytes(features.read_bytes() + b"tampered\n")
    elif corruption == "central_per_meta_disagreement":
        central["replays"][replay_id]["created_at"] = "2020-01-01T00:00:00Z"
        _write_json(central_path, central)
    elif corruption == "missing_features":
        features.unlink()

    with pytest.raises(SystemExit, match="integrity|invalid dataset"):
        ingest.ingest_one(FIXTURE, "benign", dataset_root)
    assert len(calls) == 1


def test_malformed_central_registry_fails_before_artifact_write(
    dataset_root: Path, monkeypatch
):
    calls, _state = _fake_pipeline(monkeypatch)
    (dataset_root / "metadata.json").write_text("{", encoding="utf-8")
    with pytest.raises(SystemExit, match="invalid dataset metadata"):
        ingest.ingest_one(FIXTURE, "benign", dataset_root)
    assert calls == []
    assert not list((dataset_root / "output").iterdir())


def uuid_for_test(name: str):
    import uuid

    return uuid.uuid5(uuid.NAMESPACE_DNS, name)


def test_central_only_old_entry_with_no_artifact_is_rebuilt(
    dataset_root: Path, monkeypatch
):
    replay_id = ingest.replay_id_for(FIXTURE_SHA, "benign")
    central = {
        "replays": {
            replay_id: {
                "replay_id": replay_id,
                "pcap_source": "raw/old.pcap",
                "sha256": FIXTURE_SHA,
                "label": "benign",
                "created_at": "2026-01-01T00:00:00Z",
                "features_path": f"output/{replay_id}/features.jsonl",
            }
        }
    }
    _write_json(dataset_root / "metadata.json", central)
    calls, _state = _fake_pipeline(monkeypatch)
    entry = ingest.ingest_one(FIXTURE, "benign", dataset_root)
    assert len(calls) == 1
    assert entry["config"]["feature_profile"] == "detector-v2"
    assert entry["features_sha256"]


def test_orphan_temporary_publication_state_is_diagnosed(
    dataset_root: Path, monkeypatch
):
    _fake_pipeline(monkeypatch)
    replay_id = ingest.replay_id_for(FIXTURE_SHA, "benign")
    orphan = dataset_root / "output" / f".tmp-{replay_id}-orphan"
    orphan.mkdir(parents=True)
    with pytest.raises(SystemExit, match="orphan replay publication state"):
        ingest.ingest_one(FIXTURE, "benign", dataset_root)


def test_partial_central_temporary_file_is_diagnosed(
    dataset_root: Path, monkeypatch
):
    _fake_pipeline(monkeypatch)
    orphan = dataset_root / ".metadata.json.interrupted.tmp"
    orphan.write_text("partial", encoding="ascii")
    with pytest.raises(SystemExit, match="orphan replay publication state"):
        ingest.ingest_one(FIXTURE, "benign", dataset_root)


def test_metadata_lock_fails_closed_and_is_not_removed(
    dataset_root: Path, monkeypatch
):
    _fake_pipeline(monkeypatch)
    lock = dataset_root / "metadata.json.lock"
    lock.write_text("operator-owned\n", encoding="ascii")
    with pytest.raises(SystemExit, match="metadata lock already exists"):
        ingest.ingest_one(FIXTURE, "benign", dataset_root)
    assert lock.read_text(encoding="ascii") == "operator-owned\n"


def test_paths_are_portable_and_windows_separators_are_rejected(
    dataset_root: Path, monkeypatch
):
    entry, _calls, _state = _fresh(dataset_root, monkeypatch)
    assert "\\" not in entry["features_path"]
    assert "\\" not in entry["pcap_source"]
    central = _read_json(dataset_root / "metadata.json")
    central["replays"][entry["replay_id"]]["features_path"] = entry[
        "features_path"
    ].replace("/", "\\")
    _write_json(dataset_root / "metadata.json", central)
    with pytest.raises(SystemExit, match="POSIX-style"):
        ingest._load_metadata(dataset_root)


def test_redirected_output_directory_is_rejected_before_generation(
    dataset_root: Path, monkeypatch
):
    calls, _state = _fake_pipeline(monkeypatch)
    original_is_symlink = Path.is_symlink

    def mark_output_as_symlink(path: Path) -> bool:
        return path == dataset_root / "output" or original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", mark_output_as_symlink)
    with pytest.raises(SystemExit, match="output path must be a regular local directory"):
        ingest.ingest_one(FIXTURE, "benign", dataset_root)
    assert calls == []


def test_same_sha_warning_describes_create_and_existing_reuse(
    dataset_root: Path, monkeypatch, capsys
):
    calls, _state = _fake_pipeline(monkeypatch)
    ingest.ingest_one(FIXTURE, "benign", dataset_root)
    capsys.readouterr()
    ingest.ingest_one(FIXTURE, "ddos", dataset_root)
    first = capsys.readouterr()
    assert "will create another conflicting-label replay" in first.err
    assert "identical PCAP bytes" in first.err

    ingest.ingest_one(FIXTURE, "ddos", dataset_root)
    second = capsys.readouterr()
    assert "no new replay will be created" in second.err
    assert "will create another" not in second.err
    assert len(calls) == 2


def test_same_label_reuse_without_conflict_has_no_warning(
    dataset_root: Path, monkeypatch, capsys
):
    _fake_pipeline(monkeypatch)
    ingest.ingest_one(FIXTURE, "benign", dataset_root)
    capsys.readouterr()
    ingest.ingest_one(FIXTURE, "benign", dataset_root)
    assert "[warn]" not in capsys.readouterr().err


def test_different_sha_and_label_has_no_warning(
    dataset_root: Path, monkeypatch, capsys
):
    _fake_pipeline(monkeypatch)
    hashes = iter((FIXTURE_SHA, "1" * 64))
    monkeypatch.setattr(ingest, "_hash_pcap", lambda _path: next(hashes))
    ingest.ingest_one(FIXTURE, "benign", dataset_root)
    capsys.readouterr()
    ingest.ingest_one(FIXTURE, "ddos", dataset_root)
    assert "[warn]" not in capsys.readouterr().err


def test_cli_help_is_cp1252_safe():
    environment = os.environ.copy()
    environment["PYTHONIOENCODING"] = "cp1252"
    result = subprocess.run(
        [sys.executable, str(Path(ingest.__file__)), "--help"],
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )
    assert result.returncode == 0
    assert "detector-v2" in result.stdout
    assert "legacy-m1d" in result.stdout
    assert "--ja4" in result.stdout
    assert "--force" in result.stdout


@pytest.mark.parametrize(
    "failure_point",
    [
        "pipeline",
        "feature_write",
        "feature_fsync",
        "per_meta_write",
        "per_meta_publish",
        "feature_publish",
        "central_serialize",
        "central_publish",
    ],
)
def test_force_failure_preserves_last_known_good_replay(
    dataset_root: Path, monkeypatch, failure_point: str
):
    entry, _calls, state = _fresh(dataset_root, monkeypatch)
    before = _snapshot(dataset_root, entry)
    state["payload"] = b'{"flow_id":"replacement"}\n'

    if failure_point == "pipeline":
        state["failure"] = RuntimeError("injected pipeline failure")
    elif failure_point == "feature_write":
        monkeypatch.setattr(
            ingest,
            "_normalize_feature_artifact",
            lambda _path: (_ for _ in ()).throw(RuntimeError("feature write")),
        )
    elif failure_point == "feature_fsync":
        monkeypatch.setattr(
            ingest,
            "_fsync_file",
            lambda _path: (_ for _ in ()).throw(OSError("feature fsync")),
        )
    elif failure_point == "per_meta_write":
        monkeypatch.setattr(
            ingest,
            "_write_per_replay_meta",
            lambda _path, _value: (_ for _ in ()).throw(OSError("meta write")),
        )
    elif failure_point == "per_meta_publish":
        original = ingest._atomic_replace_file

        def fail_per_meta_publish(source: Path, destination: Path):
            if destination.name == "meta.json":
                raise OSError("per-meta publish")
            return original(source, destination)

        monkeypatch.setattr(ingest, "_atomic_replace_file", fail_per_meta_publish)
    elif failure_point == "feature_publish":
        original = ingest._replace_directory

        def fail_candidate_publish(source: Path, destination: Path):
            if source.name.startswith(".tmp-"):
                raise OSError("feature publish")
            return original(source, destination)

        monkeypatch.setattr(ingest, "_replace_directory", fail_candidate_publish)
    elif failure_point == "central_serialize":
        monkeypatch.setattr(
            ingest,
            "_save_metadata_atomic",
            lambda _root, _data: (_ for _ in ()).throw(TypeError("serialize")),
        )
    elif failure_point == "central_publish":
        original = ingest._atomic_replace_file

        def fail_central_publish(source: Path, destination: Path):
            if destination.name == "metadata.json":
                raise OSError("central publish")
            return original(source, destination)

        monkeypatch.setattr(ingest, "_atomic_replace_file", fail_central_publish)

    with pytest.raises(SystemExit):
        ingest.ingest_one(FIXTURE, "benign", dataset_root, force=True)

    assert _snapshot(dataset_root, entry) == before
    output = dataset_root / "output"
    assert not list(output.glob(".tmp-*"))
    assert not list(output.glob(".backup-*"))
    assert not (dataset_root / "metadata.json.lock").exists()
    assert not list(dataset_root.glob(".metadata.json.*.tmp"))


def test_successful_force_atomically_replaces_complete_binding(
    dataset_root: Path, monkeypatch
):
    entry, calls, state = _fresh(dataset_root, monkeypatch)
    before = _snapshot(dataset_root, entry)
    state["payload"] = b'{"flow_id":"replacement"}\n'
    replacement = ingest.ingest_one(FIXTURE, "benign", dataset_root, force=True)
    after = _snapshot(dataset_root, replacement)
    assert len(calls) == 2
    assert after != before
    assert replacement["features_sha256"] == hashlib.sha256(after[0]).hexdigest()
    assert _read_json(_paths(dataset_root, replacement)[1])["features_sha256"] == replacement[
        "features_sha256"
    ]
    assert not list((dataset_root / "output").glob(".backup-*"))


def test_feature_profile_runtime_matrix_has_no_silent_collision(
    tmp_path: Path, monkeypatch
):
    calls, _state = _fake_pipeline(monkeypatch)
    configurations = [
        ("detector-v2", False, False),
        ("detector-v2", True, False),
        ("detector-v2", False, True),
        ("legacy-m1d", False, False),
        ("legacy-m1d", True, False),
        ("legacy-m1d", False, True),
    ]
    for index, (profile, use_ja4, use_tls_fingerprints) in enumerate(configurations):
        root = tmp_path / f"matrix-{index}"
        entry = ingest.ingest_one(
            FIXTURE,
            "benign",
            root,
            feature_profile=profile,
            use_ja4=use_ja4,
            use_tls_fingerprints=use_tls_fingerprints,
        )
        reused = ingest.ingest_one(
            FIXTURE,
            "benign",
            root,
            feature_profile=profile,
            use_ja4=use_ja4,
            use_tls_fingerprints=use_tls_fingerprints,
        )
        assert reused == entry
        for other_profile, other_ja4, other_tls in configurations:
            if (other_profile, other_ja4, other_tls) == (
                profile,
                use_ja4,
                use_tls_fingerprints,
            ):
                continue
            with pytest.raises(SystemExit, match="configuration mismatch"):
                ingest.ingest_one(
                    FIXTURE,
                    "benign",
                    root,
                    feature_profile=other_profile,
                    use_ja4=other_ja4,
                    use_tls_fingerprints=other_tls,
                )
    assert len(calls) == len(configurations)


def test_ja4_runtime_lock_change_invalidates_reuse(
    dataset_root: Path, monkeypatch, tmp_path: Path
):
    _entry, calls, _state = _fresh(dataset_root, monkeypatch, use_ja4=True)
    changed_lock = tmp_path / "ja4-runtime.lock"
    changed_lock.write_bytes(ingest.JA4_RUNTIME_LOCK.read_bytes() + b"# changed\n")
    monkeypatch.setattr(ingest, "JA4_RUNTIME_LOCK", changed_lock)
    with pytest.raises(SystemExit, match="configuration mismatch"):
        ingest.ingest_one(FIXTURE, "benign", dataset_root, use_ja4=True)
    assert len(calls) == 1
