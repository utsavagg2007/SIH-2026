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
    assert "feature_profile" not in calls[0][1]  # dataset keeps frozen M1D default
    replay_dir = dataset_root / first["features_path"]
    assert replay_dir.is_file()
    per_meta = json.loads((replay_dir.parent / "meta.json").read_text(encoding="utf-8"))
    assert per_meta["sha256"] == FIXTURE_SHA
    assert per_meta["label"] == "benign"
    assert per_meta["replay_id"] == first["replay_id"]
    assert ingest._load_metadata(dataset_root)["replays"][first["replay_id"]] == first


def test_invalid_label_is_rejected_before_processing(tmp_path):
    with pytest.raises(SystemExit, match="label must be one of"):
        ingest.ingest_one(FIXTURE, "not-a-threat-class", tmp_path)
