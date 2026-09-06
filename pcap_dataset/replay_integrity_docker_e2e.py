#!/usr/bin/env python3
"""Real Docker qualification for deterministic, integrity-bound dataset replay."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))
sys.path.insert(0, str(REPOSITORY_ROOT / "detection"))

from detection_core.adapters import IngestionJsonlAdapter  # noqa: E402
from pcap_dataset import ingest  # noqa: E402


STANDARD_FIXTURE = (
    REPOSITORY_ROOT
    / "ingestion"
    / "tests"
    / "fixtures"
    / "pcap"
    / "m1d_synthetic.pcap"
)
JA4_FIXTURE = STANDARD_FIXTURE.with_name("ja4_synthetic.pcap")
EXPECTED_JA4 = [
    "t13d020200_c1929292aa6b_b9a491fefe05",
    "t13i030100_34b97de2cef7_b9a491fefe05",
]
EXPECTED_JA3 = [
    "3207ef9f2e951242b53b44f07d8439d0",
    "7b21866302b81455e328a912c6a3020a",
]
EXPECTED_JA3S = [
    "cce84e7a8b742462e40afb585a3e3ccc",
    "13b064e3d43575147f6ca25c24556a31",
]
ASSERTIONS = 0


def require(condition: bool, message: str) -> None:
    global ASSERTIONS
    ASSERTIONS += 1
    if not condition:
        raise AssertionError(message)


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def feature_path(root: Path, entry: dict) -> Path:
    return root.joinpath(*entry["features_path"].split("/"))


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def run_fresh(
    parent: Path,
    name: str,
    pcap: Path,
    *,
    feature_profile: str = "detector-v2",
    use_ja4: bool = False,
    use_tls_fingerprints: bool = False,
) -> tuple[Path, dict, Path]:
    root = parent / name
    entry = ingest.ingest_one(
        pcap,
        "benign",
        root,
        feature_profile=feature_profile,
        use_ja4=use_ja4,
        use_tls_fingerprints=use_tls_fingerprints,
    )
    feature = feature_path(root, entry)
    per_meta = read_json(feature.parent / "meta.json")
    central = read_json(root / "metadata.json")["replays"][entry["replay_id"]]
    actual_sha = hashlib.sha256(feature.read_bytes()).hexdigest()
    require(actual_sha == entry["features_sha256"], f"{name}: entry feature hash mismatch")
    require(actual_sha == per_meta["features_sha256"], f"{name}: per-meta feature hash mismatch")
    require(actual_sha == central["features_sha256"], f"{name}: central feature hash mismatch")
    require(per_meta["config"] == central["config"], f"{name}: config disagreement")
    require(
        per_meta["config_sha256"] == central["config_sha256"],
        f"{name}: config fingerprint disagreement",
    )
    require("\\" not in entry["features_path"], f"{name}: non-portable feature path")
    require(not Path(per_meta["pcap_source"]).is_absolute(), f"{name}: absolute PCAP source")
    return root, entry, feature


def assert_real_detector_fields(feature: Path) -> None:
    records = rows(feature)
    require(len(records) == 4, "standard fixture did not emit four detector records")
    require(all(row.get("conn_state") == "SF" for row in records), "conn_state missing")
    require(all(row.get("src_port") is not None for row in records), "src_port missing")
    require(any(row.get("service") for row in records), "service missing")

    dns = [row["dns"] for row in records if row.get("dns")]
    require(len(dns) >= 1, "DNS enrichment missing")
    require(any(item.get("query") for item in dns), "DNS query missing")
    require(any(item.get("qtype") == "A" for item in dns), "DNS qtype missing")
    require(any(item.get("rcode") == "NOERROR" for item in dns), "DNS rcode missing")
    require(
        sum(len(row.get("dns_transactions", [])) for row in records) == 2,
        "standard DNS transaction arrays missing",
    )

    tls = [row["tls"] for row in records if row.get("tls")]
    require(len(tls) == 1, "TLS enrichment missing")
    require(tls[0].get("server_name") == "tls.example.test", "SNI changed")
    require(tls[0].get("version") == "TLSv13", "TLS version changed")
    require(
        tls[0].get("cipher") == "TLS_AES_128_GCM_SHA256", "TLS cipher changed"
    )
    require(tls[0].get("ja3") is None, "real standard runtime unexpectedly emitted JA3")
    require(tls[0].get("ja3s") is None, "real standard runtime unexpectedly emitted JA3S")
    require(tls[0].get("ja4") is None, "standard runtime unexpectedly emitted JA4")

    http = [row["http"] for row in records if row.get("http")]
    require(len(http) == 1, "HTTP enrichment missing")
    require(http[0].get("host") == "http.example.test", "HTTP host changed")
    require(http[0].get("uri") == "/one", "HTTP URI changed")
    require(http[0].get("method") == "GET", "HTTP method changed")
    require(http[0].get("user_agent") == "SIH-M1D", "HTTP user-agent changed")
    require(http[0].get("status_code") == 200, "HTTP status changed")
    require(http[0].get("transaction_count") == 2, "HTTP row count changed")
    require(
        [item["uri"] for row in records for item in row.get("http_transactions", [])]
        == ["/one", "/two"],
        "standard HTTP transaction array changed",
    )

    adapter = IngestionJsonlAdapter(path=feature, strict=True)
    events = list(adapter)
    require(adapter.stats.errors == 0, "Detection adapter reported standard errors")
    require(len(events) == 4, "Detection adapter rejected standard records")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sih-replay-integrity-e2e-") as temporary:
        root = Path(temporary)

        standard_runs = [
            run_fresh(root, f"standard-{index}", STANDARD_FIXTURE)
            for index in range(10)
        ]
        standard_hashes = {entry["features_sha256"] for _, entry, _ in standard_runs}
        standard_configs = {entry["config_sha256"] for _, entry, _ in standard_runs}
        require(len(standard_hashes) == 1, "ten standard feature hashes differ")
        require(len(standard_configs) == 1, "ten standard config hashes differ")
        standard_bytes = {feature.read_bytes() for _, _, feature in standard_runs}
        require(len(standard_bytes) == 1, "ten standard artifacts are not byte-identical")
        standard_uids = {
            tuple(row.get("uid") for row in rows(feature))
            for _, _, feature in standard_runs
        }
        require(len(standard_uids) == 1, "ten standard UID sequences differ")
        assert_real_detector_fields(standard_runs[0][2])

        renamed_dir = root / "renamed-input"
        renamed_dir.mkdir()
        renamed = renamed_dir / "same-bytes-renamed.pcap"
        shutil.copy2(STANDARD_FIXTURE, renamed)
        require(
            hashlib.sha256(renamed.read_bytes()).digest()
            == hashlib.sha256(STANDARD_FIXTURE.read_bytes()).digest(),
            "renamed PCAP bytes changed",
        )
        _, renamed_entry, renamed_feature = run_fresh(root, "renamed-run", renamed)
        require(
            renamed_entry["features_sha256"] == next(iter(standard_hashes)),
            "renamed-path feature hash changed",
        )
        require(
            renamed_entry["config_sha256"] == next(iter(standard_configs)),
            "renamed-path config hash changed",
        )
        require(
            renamed_feature.read_bytes() == standard_runs[0][2].read_bytes(),
            "renamed-path feature bytes changed",
        )

        legacy_runs = [
            run_fresh(
                root,
                f"legacy-{index}",
                STANDARD_FIXTURE,
                feature_profile="legacy-m1d",
            )
            for index in range(3)
        ]
        legacy_hashes = {entry["features_sha256"] for _, entry, _ in legacy_runs}
        require(len(legacy_hashes) == 1, "legacy dataset feature hashes differ")
        require(
            len({feature.read_bytes() for _, _, feature in legacy_runs}) == 1,
            "legacy dataset feature bytes differ",
        )

        ja4_runs = [
            run_fresh(root, f"ja4-{index}", JA4_FIXTURE, use_ja4=True)
            for index in range(10)
        ]
        ja4_hashes = {entry["features_sha256"] for _, entry, _ in ja4_runs}
        ja4_configs = {entry["config_sha256"] for _, entry, _ in ja4_runs}
        require(len(ja4_hashes) == 1, "ten JA4 feature hashes differ")
        require(len(ja4_configs) == 1, "ten JA4 config hashes differ")
        require(
            len({feature.read_bytes() for _, _, feature in ja4_runs}) == 1,
            "ten JA4 artifacts are not byte-identical",
        )
        ja4_records = rows(ja4_runs[0][2])
        actual_ja4 = [
            row["tls"]["ja4"] for row in ja4_records if row.get("tls")
        ]
        require(actual_ja4 == EXPECTED_JA4, "real JA4 values changed")
        require(
            all(row["tls"].get("ja3") is None for row in ja4_records if row.get("tls")),
            "JA4 runtime unexpectedly emitted JA3",
        )
        require(
            all(row["tls"].get("ja3s") is None for row in ja4_records if row.get("tls")),
            "JA4 runtime unexpectedly emitted JA3S",
        )
        adapter = IngestionJsonlAdapter(path=ja4_runs[0][2], strict=True)
        events = list(adapter)
        require(adapter.stats.errors == 0, "Detection adapter reported JA4 errors")
        require(
            [event.tls.ja4 for event in events if event.tls] == EXPECTED_JA4,
            "Detection TlsInfo altered JA4",
        )

        full_runs = [
            run_fresh(
                root,
                f"tls-fingerprints-{index}",
                JA4_FIXTURE,
                use_tls_fingerprints=True,
            )
            for index in range(10)
        ]
        full_hashes = {entry["features_sha256"] for _, entry, _ in full_runs}
        full_configs = {entry["config_sha256"] for _, entry, _ in full_runs}
        require(len(full_hashes) == 1, "ten full-fingerprint feature hashes differ")
        require(len(full_configs) == 1, "ten full-fingerprint config hashes differ")
        require(
            len({feature.read_bytes() for _, _, feature in full_runs}) == 1,
            "ten full-fingerprint artifacts are not byte-identical",
        )
        full_records = rows(full_runs[0][2])
        full_tls = [row["tls"] for row in full_records if row.get("tls")]
        require([item["ja3"] for item in full_tls] == EXPECTED_JA3, "real JA3 values changed")
        require([item["ja3s"] for item in full_tls] == EXPECTED_JA3S, "real JA3S values changed")
        require([item["ja4"] for item in full_tls] == EXPECTED_JA4, "full-mode JA4 values changed")
        full_adapter = IngestionJsonlAdapter(path=full_runs[0][2], strict=True)
        full_events = list(full_adapter)
        require(full_adapter.stats.errors == 0, "Detection adapter reported full-mode errors")
        require(
            [event.tls.ja3 for event in full_events if event.tls] == EXPECTED_JA3,
            "Detection TlsInfo altered JA3",
        )
        require(
            [event.tls.ja3s for event in full_events if event.tls] == EXPECTED_JA3S,
            "Detection TlsInfo altered JA3S",
        )
        require(
            len({next(iter(standard_configs)), next(iter(ja4_configs)), next(iter(full_configs))})
            == 3,
            "runtime modes did not produce three distinct replay configurations",
        )
        require(
            len({next(iter(standard_hashes)), next(iter(ja4_hashes)), next(iter(full_hashes))})
            == 3,
            "runtime modes did not produce isolated feature artifacts",
        )

        reuse_root, reuse_entry, reuse_feature = standard_runs[0]
        before_mtime = reuse_feature.stat().st_mtime_ns
        reused = ingest.ingest_one(STANDARD_FIXTURE, "benign", reuse_root)
        require(reused == reuse_entry, "same-config replay did not reuse its binding")
        require(reuse_feature.stat().st_mtime_ns == before_mtime, "reuse rewrote features")

        mismatch_meta_path = ja4_runs[0][2].parent / "meta.json"
        mismatch_meta = read_json(mismatch_meta_path)
        mismatch_meta["config"]["zeek_image"] = (
            "example.invalid/zeek@sha256:" + "a" * 64
        )
        mismatch_config = ingest.ReplayConfig.from_mapping(
            mismatch_meta["config"], "qualification mismatch"
        )
        mismatch_meta["config_sha256"] = mismatch_config.sha256
        write_json(mismatch_meta_path, mismatch_meta)
        try:
            ingest.ingest_one(JA4_FIXTURE, "benign", ja4_runs[0][0], use_ja4=True)
        except SystemExit:
            pass
        else:
            raise AssertionError("runtime identity mismatch was silently reused")

        print("Replay integrity Docker E2E: PASS")
        print(f"assertions={ASSERTIONS}")
        print(f"standard_runs={len(standard_runs)}")
        print(f"standard_features_sha256={next(iter(standard_hashes))}")
        print(f"standard_config_sha256={next(iter(standard_configs))}")
        print(f"legacy_features_sha256={next(iter(legacy_hashes))}")
        print(f"ja4_runs={len(ja4_runs)}")
        print(f"ja4_features_sha256={next(iter(ja4_hashes))}")
        print(f"ja4_config_sha256={next(iter(ja4_configs))}")
        print("ja4_values=" + ",".join(EXPECTED_JA4))
        print(f"tls_fingerprint_runs={len(full_runs)}")
        print(f"tls_fingerprint_features_sha256={next(iter(full_hashes))}")
        print(f"tls_fingerprint_config_sha256={next(iter(full_configs))}")
        print("ja3_values=" + ",".join(EXPECTED_JA3))
        print("ja3s_values=" + ",".join(EXPECTED_JA3S))
        print("adapter_errors=0")
        print("renamed_path=byte-identical")


if __name__ == "__main__":
    main()
