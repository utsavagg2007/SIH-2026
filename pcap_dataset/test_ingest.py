"""PCAP dataset path, identity, metadata, and idempotency checks."""

from __future__ import annotations

import json
from pathlib import Path
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


def test_ingestion_root_uses_integrated_directory():
    assert ingest.INGESTION_ROOT == Path(__file__).parents[1] / "ingestion"
    assert (ingest.INGESTION_ROOT / "Cargo.toml").is_file()


def test_replay_id_has_fixed_sha_and_label_vectors():
    assert ingest.replay_id_for(FIXTURE_SHA, "benign") == "92838b0f-1d70-550c-a566-c33f0ba26aba"
    assert ingest.replay_id_for(FIXTURE_SHA, "ddos") == "694071ae-3ca4-5248-82c9-c11d77274ead"


def test_invalid_registry_identity_and_path_fail_closed(tmp_path):
    replay_id = ingest.replay_id_for(FIXTURE_SHA, "benign")
    bad = {
        "replays": {
            replay_id: {
                "replay_id": replay_id,
                "sha256": FIXTURE_SHA,
                "label": "benign",
                "features_path": "../escape.jsonl",
            }
        }
    }
    (tmp_path / "metadata.json").write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(SystemExit, match="must stay under output"):
        ingest._load_metadata(tmp_path)


def test_ingest_is_idempotent_and_writes_valid_bindings(tmp_path, monkeypatch):
    # `pipeline` is faked below, but the SHA-256 provenance hash still comes
    # from the compiled crate. Without it this failed with a SystemExit that
    # named the hash rather than the missing toolchain.
    pytest.importorskip(
        "ingestion_core",
        reason="ingestion_core (PyO3) is not built - run `maturin develop "
        "--manifest-path ingestion/Cargo.toml` (needs a Rust toolchain; "
        "see README, 'Ingestion needs a Rust toolchain')",
    )
    dataset_root = tmp_path / "dataset"
    dataset_root.mkdir()
    (dataset_root / "metadata.json").write_text('{"replays": {}}\n', encoding="utf-8")
    calls = []

    def fake_run_pipeline(*args, **kwargs):
        calls.append((args, kwargs))
        Path(args[2]).write_text('{"flow_id":"fixture"}\n', encoding="utf-8")
        return []

    fake_pipeline = types.SimpleNamespace(run_pipeline=fake_run_pipeline)
    monkeypatch.setitem(sys.modules, "pipeline", fake_pipeline)

    first = ingest.ingest_one(FIXTURE, "benign", dataset_root)
    second = ingest.ingest_one(FIXTURE, "benign", dataset_root)

    assert first == second
    assert len(calls) == 1
    assert calls[0][1]["skip_zeek"] is False
    assert calls[0][1]["feature_profile"] == "detector-v2"
    assert calls[0][1]["use_ja4"] is False
    replay_dir = dataset_root / first["features_path"]
    assert replay_dir.is_file()
    per_meta = json.loads((replay_dir.parent / "meta.json").read_text(encoding="utf-8"))
    assert per_meta["sha256"] == FIXTURE_SHA
    assert per_meta["label"] == "benign"
    assert per_meta["replay_id"] == first["replay_id"]
    assert per_meta["pipeline"]["feature_profile"] == "detector-v2"
    assert ingest._load_metadata(dataset_root)["replays"][first["replay_id"]] == first


def test_invalid_label_is_rejected_before_processing(tmp_path):
    with pytest.raises(SystemExit, match="label must be one of"):
        ingest.ingest_one(FIXTURE, "not-a-threat-class", tmp_path)


def test_unknown_feature_profile_rejected_before_processing(tmp_path):
    with pytest.raises(SystemExit, match="unsupported feature profile"):
        ingest.ingest_one(FIXTURE, "benign", tmp_path, feature_profile="legacy")


def _fake_pipeline(monkeypatch):
    calls = []

    def fake_run_pipeline(*args, **kwargs):
        calls.append((args, kwargs))
        Path(args[2]).write_text('{"flow_id":"fixture"}\n', encoding="utf-8")
        return []

    monkeypatch.setitem(
        sys.modules, "pipeline", types.SimpleNamespace(run_pipeline=fake_run_pipeline)
    )
    return calls


def test_legacy_m1d_profile_reaches_pipeline(tmp_path, monkeypatch):
    dataset_root = tmp_path / "dataset"
    dataset_root.mkdir()
    (dataset_root / "metadata.json").write_text('{"replays": {}}\n', encoding="utf-8")
    calls = _fake_pipeline(monkeypatch)

    entry = ingest.ingest_one(
        FIXTURE, "benign", dataset_root, feature_profile="legacy-m1d"
    )
    assert calls[0][1]["feature_profile"] == "legacy-m1d"
    assert entry["feature_profile"] == "legacy-m1d"
    assert entry["use_ja4"] is False


def test_replay_reuse_is_configuration_aware(tmp_path, monkeypatch):
    dataset_root = tmp_path / "dataset"
    dataset_root.mkdir()
    (dataset_root / "metadata.json").write_text('{"replays": {}}\n', encoding="utf-8")
    calls = _fake_pipeline(monkeypatch)

    first = ingest.ingest_one(FIXTURE, "benign", dataset_root)
    assert first["feature_profile"] == "detector-v2"

    with pytest.raises(SystemExit, match="already exists with"):
        ingest.ingest_one(
            FIXTURE, "benign", dataset_root, feature_profile="legacy-m1d"
        )
    with pytest.raises(SystemExit, match="already exists with"):
        ingest.ingest_one(FIXTURE, "benign", dataset_root, use_ja4=True)
    assert len(calls) == 1  # rejected requests never reached the pipeline

    forced = ingest.ingest_one(
        FIXTURE, "benign", dataset_root, feature_profile="legacy-m1d", force=True
    )
    assert len(calls) == 2
    assert forced["feature_profile"] == "legacy-m1d"
    stored = ingest._load_metadata(dataset_root)["replays"][first["replay_id"]]
    assert stored["feature_profile"] == "legacy-m1d"
    assert stored["use_ja4"] is False
