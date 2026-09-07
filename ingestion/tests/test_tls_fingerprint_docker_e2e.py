#!/usr/bin/env python3
"""Docker qualification for full JA3/JA3S/JA4 and transaction telemetry."""

from __future__ import annotations

__test__ = False  # Standalone qualification executable, not a pytest module.

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


SCRIPT_ROOT = Path(__file__).resolve().parent
INGESTION_ROOT = SCRIPT_ROOT.parent
REPOSITORY_ROOT = INGESTION_ROOT.parent
FIXTURE_ROOT = SCRIPT_ROOT / "fixtures" / "pcap"
TLS_FIXTURE = FIXTURE_ROOT / "ja4_synthetic.pcap"
M1D_FIXTURE = FIXTURE_ROOT / "m1d_synthetic.pcap"
TRANSACTION_FIXTURE = FIXTURE_ROOT / "transaction_synthetic.pcap"
EMPTY_FIXTURE = FIXTURE_ROOT / "m1d_empty.pcap"
HEADER_EVIDENCE = (
    SCRIPT_ROOT
    / "fixtures"
    / "runtime_headers"
    / "zeek_8.0.10_tls_fingerprint_fields.txt"
)
LOCK_FILE = INGESTION_ROOT / "runtime" / "tls-fingerprint-runtime.lock"
OBSERVED_AT = "2026-01-02T03:04:05.678901Z"
SENSOR_ID = "tls-fingerprint-e2e-sensor"
EXPECTED_JA3 = [
    "3207ef9f2e951242b53b44f07d8439d0",
    "7b21866302b81455e328a912c6a3020a",
]
EXPECTED_JA3S = [
    "cce84e7a8b742462e40afb585a3e3ccc",
    "13b064e3d43575147f6ca25c24556a31",
]
EXPECTED_JA4 = [
    "t13d020200_c1929292aa6b_b9a491fefe05",
    "t13i030100_34b97de2cef7_b9a491fefe05",
]
EXPECTED_TRANSACTION_SHA256 = (
    "01e9ed4582078321b554c08a3a9f264ce74c4c7cd23466add10837aaa823703e"
)
EXPECTED_CONTRACT_SHA256 = (
    "311a22470f79fd0d339d3fd97512d3fa107d30768e58d428a92dabcbe0416f57"
)
FORBIDDEN_JA4_FIELDS = {
    "ja4s",
    "ja4h",
    "ja4l",
    "ja4ls",
    "ja4t",
    "ja4ts",
    "ja4ssh",
    "ja4x",
    "ja4d",
}
ASSERTION_COUNT = 0


def require(condition: bool, message: str) -> None:
    global ASSERTION_COUNT
    ASSERTION_COUNT += 1
    if not condition:
        raise AssertionError(message)


def run(
    arguments: list[str], *, cwd: Path = REPOSITORY_ROOT
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )
    if result.returncode:
        raise AssertionError(
            f"command failed ({result.returncode}): {arguments!r}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def read_lock(path: Path = LOCK_FILE) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        require(bool(separator and name and value), f"invalid lock line: {line!r}")
        values[name] = value
    return values


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_manifest(root: Path, manifest_name: str = "SOURCE-MANIFEST.sha256") -> None:
    manifest = root / manifest_name
    listed: set[Path] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        expected, name = line.split("  ", 1)
        path = root / name
        listed.add(path)
        require(path.is_file(), f"manifest source is missing: {name}")
        require(sha256(path) == expected, f"manifest hash mismatch: {name}")
    require(not any(path.name == ".git" for path in root.rglob(".git")), "vendored .git found")
    require(len(listed) >= 3, "source manifest is unexpectedly incomplete")


def verify_source_integrity(lock: dict[str, str]) -> None:
    require(
        sha256(INGESTION_ROOT / "docker" / "tls-fingerprints" / "Dockerfile")
        == lock["TLS_FP_DOCKERFILE_SHA256"],
        "TLS fingerprint Dockerfile differs from lock",
    )
    require(
        sha256(INGESTION_ROOT / "runtime" / "tls-fingerprints.zeek")
        == lock["TLS_FP_LOADER_SHA256"],
        "TLS fingerprint loader differs from lock",
    )
    ja3_vendor = INGESTION_ROOT / "vendor" / "ja3-zeek"
    ja4_vendor = INGESTION_ROOT / "vendor" / "ja4-zeek"
    require(
        sha256(ja3_vendor / "SOURCE-MANIFEST.sha256")
        == lock["JA3_SOURCE_MANIFEST_SHA256"],
        "JA3 manifest differs from lock",
    )
    require(
        sha256(ja4_vendor / "SOURCE-MANIFEST.sha256")
        == lock["JA4_SOURCE_MANIFEST_SHA256"],
        "JA4 manifest differs from lock",
    )
    verify_manifest(ja3_vendor)
    verify_manifest(ja4_vendor)
    license_text = (ja3_vendor / "LICENSE.txt").read_text(encoding="utf-8")
    require("Redistribution and use in source and binary forms" in license_text, "JA3 BSD license missing")


def build_locked_image(lock: dict[str, str], root: Path) -> None:
    iid_file = root / "tls-fingerprint-image.iid"
    run(
        [
            "docker",
            "build",
            "--platform",
            lock["TLS_FP_BUILD_PLATFORM"],
            "--network",
            "none",
            "--no-cache",
            "--provenance=false",
            "--build-arg",
            f"SOURCE_DATE_EPOCH={lock['TLS_FP_BUILD_EPOCH']}",
            "--iidfile",
            str(iid_file),
            "--tag",
            lock["TLS_FP_IMAGE_TAG"],
            "--file",
            str(INGESTION_ROOT / "docker" / "tls-fingerprints" / "Dockerfile"),
            str(INGESTION_ROOT),
        ]
    )
    require(
        iid_file.read_text(encoding="ascii").strip() == lock["TLS_FP_CONFIG_DIGEST"],
        "rebuilt full-fingerprint config digest differs from lock",
    )
    image_id = run(
        ["docker", "image", "inspect", lock["TLS_FP_IMAGE_TAG"], "--format", "{{.Id}}"]
    ).stdout.strip()
    require(image_id == lock["TLS_FP_IMAGE_ID"], "rebuilt full-fingerprint image ID differs")
    labels = json.loads(
        run(
            [
                "docker",
                "image",
                "inspect",
                lock["TLS_FP_IMAGE_ID"],
                "--format",
                "{{json .Config.Labels}}",
            ]
        ).stdout
    )
    expected_labels = {
        "io.sih.zeek.base-digest": lock["TLS_FP_BASE_IMAGE"].split("@", 1)[1],
        "io.sih.ja3.upstream-repository": lock["JA3_UPSTREAM_REPOSITORY"],
        "io.sih.ja3.upstream-commit": lock["JA3_UPSTREAM_COMMIT"],
        "io.sih.ja3.upstream-tree": lock["JA3_UPSTREAM_TREE"],
        "io.sih.ja3.upstream-archive-sha256": lock["JA3_UPSTREAM_ARCHIVE_SHA256"],
        "io.sih.ja3.source-manifest-sha256": lock["JA3_SOURCE_MANIFEST_SHA256"],
        "io.sih.ja4.upstream-commit": lock["JA4_UPSTREAM_COMMIT"],
        "io.sih.ja4.upstream-tree": lock["JA4_UPSTREAM_TREE"],
        "io.sih.ja4.upstream-archive-sha256": lock["JA4_UPSTREAM_ARCHIVE_SHA256"],
        "io.sih.ja4.source-manifest-sha256": lock["JA4_SOURCE_MANIFEST_SHA256"],
        "io.sih.fingerprints.loader-sha256": lock["TLS_FP_LOADER_SHA256"],
    }
    for name, expected in expected_labels.items():
        require(labels.get(name) == expected, f"image label failed: {name}")


def bash_executable() -> str:
    if os.name != "nt":
        return "bash"
    candidates = [
        Path(os.environ.get("ProgramFiles", "")) / "Git" / "bin" / "bash.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Git" / "bin" / "bash.exe",
    ]
    match = next((path for path in candidates if path.is_file()), None)
    require(match is not None, "Git Bash is required on Windows")
    return str(match)


def invoke_wrapper(
    pcap: Path,
    output: Path,
    mode: str,
    script: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            bash_executable(),
            "-l",
            str(script or (INGESTION_ROOT / "scripts" / "run_zeek.sh")),
            str(pcap),
            str(output),
            mode,
        ],
        cwd=REPOSITORY_ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )


def invoke_validator(logs: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            bash_executable(),
            "-l",
            str(INGESTION_ROOT / "scripts" / "validate_tls_fingerprint_logs.sh"),
            str(logs),
        ],
        cwd=REPOSITORY_ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )


def read_zeek(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    fields: list[str] | None = None
    rows: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#fields\t"):
            fields = line.split("\t")[1:]
        elif line and not line.startswith("#"):
            require(fields is not None, f"{path.name} data precedes #fields")
            columns = line.split("\t")
            rows.append(dict(zip(fields, columns, strict=True)))
    require(fields is not None, f"{path.name} has no #fields header")
    return fields, rows


def assert_headers(logs: Path) -> None:
    evidence = HEADER_EVIDENCE.read_text(encoding="utf-8").replace("\r\n", "\n")
    for name in ("conn.log", "ssl.log"):
        fields, _ = read_zeek(logs / name)
        field_line = "#fields\t" + "\t".join(fields)
        require(f"{name}\n{field_line}" in evidence, f"{name} full-runtime header drift")


def compare_shared_log_data(left: Path, right: Path, names: tuple[str, ...]) -> None:
    for name in names:
        if not (left / name).is_file() or not (right / name).is_file():
            continue
        left_fields, left_rows = read_zeek(left / name)
        right_fields, right_rows = read_zeek(right / name)
        shared = [field for field in left_fields if field in right_fields]
        require(
            [{field: row[field] for field in shared} for row in left_rows]
            == [{field: row[field] for field in shared} for row in right_rows],
            f"{name} pre-existing source facts changed",
        )


def canonicalize(logs: Path, output: Path, input_sha256: str) -> list[dict]:
    import ingestion_core

    summary = json.loads(
        ingestion_core.write_canonical_observations_from_zeek_logs(
            str(logs), str(output), SENSOR_ID, input_sha256, OBSERVED_AT, False
        )
    )
    require(summary["rows_skipped"] == 0, "canonicalization skipped a source row")
    return [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines() if line]


def profile(logs: Path, output: Path) -> tuple[object, list[dict]]:
    import pipeline

    stats = pipeline.run_pipeline(
        None,
        str(logs),
        str(output),
        skip_zeek=True,
        feature_profile=pipeline.DETECTOR_FEATURE_PROFILE,
    )
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines() if line]
    return stats, rows


def test_validator(root: Path) -> None:
    missing = root / "validator-missing"
    missing.mkdir()
    (missing / "ssl.log").write_text(
        "#fields\tts\tuid\tja3\tja4\n1.0\tC1\ta\tc\n",
        encoding="utf-8",
        newline="\n",
    )
    result = invoke_validator(missing)
    require(result.returncode != 0 and "without required ja3, ja3s, and ja4" in result.stderr, "missing ja3s did not fail closed")

    unavailable = root / "validator-unavailable"
    unavailable.mkdir()
    (unavailable / "ssl.log").write_text(
        "#fields\tts\tuid\tja3\tja3s\tja4\n1.0\tC1\t-\t-\t-\n",
        encoding="utf-8",
        newline="\n",
    )
    result = invoke_validator(unavailable)
    require(result.returncode == 0 and "unavailable values remain null" in result.stderr, "unavailable source state diagnostic failed")

    forbidden = root / "validator-forbidden"
    forbidden.mkdir()
    (forbidden / "ssl.log").write_text(
        "#fields\tts\tuid\tja3\tja3s\tja4\tja4h\n1.0\tC1\ta\tb\tc\td\n",
        encoding="utf-8",
        newline="\n",
    )
    result = invoke_validator(forbidden)
    require(result.returncode != 0 and "forbidden field ja4h" in result.stderr, "forbidden JA4+ field did not fail closed")


def test_fail_closed_copies(root: Path, pcap: Path, lock: dict[str, str]) -> None:
    def make_copy(name: str) -> Path:
        target = root / name
        (target / "scripts").mkdir(parents=True)
        shutil.copy2(INGESTION_ROOT / "scripts" / "run_zeek.sh", target / "scripts")
        shutil.copy2(
            INGESTION_ROOT / "scripts" / "validate_tls_fingerprint_logs.sh",
            target / "scripts",
        )
        shutil.copytree(INGESTION_ROOT / "runtime", target / "runtime")
        shutil.copytree(INGESTION_ROOT / "docker", target / "docker")
        shutil.copytree(INGESTION_ROOT / "vendor", target / "vendor")
        return target

    missing_image = make_copy("failure-missing-image")
    path = missing_image / "runtime" / "tls-fingerprint-runtime.lock"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            lock["TLS_FP_IMAGE_TAG"], "sih-zeek-tls-fingerprints:definitely-missing"
        ),
        encoding="utf-8",
        newline="\n",
    )
    result = invoke_wrapper(pcap, root / "missing-image-output", "--tls-fingerprints", missing_image / "scripts" / "run_zeek.sh")
    require(result.returncode != 0 and "unavailable locally" in result.stderr, "missing image did not fail closed")

    missing_loader = make_copy("failure-missing-loader")
    (missing_loader / "runtime" / "tls-fingerprints.zeek").unlink()
    result = invoke_wrapper(pcap, root / "missing-loader-output", "--tls-fingerprints", missing_loader / "scripts" / "run_zeek.sh")
    require(result.returncode != 0 and "required TLS fingerprint runtime input is missing" in result.stderr, "missing loader did not fail closed")

    corrupt_source = make_copy("failure-corrupt-source")
    with (corrupt_source / "vendor" / "ja3-zeek" / "zeek" / "ja3.zeek").open(
        "a", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write("# corruption probe\n")
    result = invoke_wrapper(pcap, root / "corrupt-source-output", "--tls-fingerprints", corrupt_source / "scripts" / "run_zeek.sh")
    require(result.returncode != 0 and "source integrity" in result.stderr, "corrupt source did not fail closed")

    wrong_label = make_copy("failure-wrong-label")
    path = wrong_label / "runtime" / "tls-fingerprint-runtime.lock"
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            lock["JA3_UPSTREAM_COMMIT"], "0" * 40
        ),
        encoding="utf-8",
        newline="\n",
    )
    result = invoke_wrapper(pcap, root / "wrong-label-output", "--tls-fingerprints", wrong_label / "scripts" / "run_zeek.sh")
    require(result.returncode != 0 and "image label" in result.stderr, "mismatched provenance label did not fail closed")


def main() -> None:
    sys.path.insert(0, str(INGESTION_ROOT))
    sys.path.insert(0, str(REPOSITORY_ROOT / "detection"))
    from detection_core.adapters import IngestionJsonlAdapter
    from detection_core.detectors import EncryptedMalwareConfig, EncryptedMalwareDetector
    from detection_core.engine import DetectionEngine
    from scripts.generate_synthetic_pcap import (
        build_fixture,
        build_ja4_fixture,
        build_transaction_fixture,
    )

    lock = read_lock()
    verify_source_integrity(lock)
    require(TLS_FIXTURE.read_bytes() == build_ja4_fixture(), "TLS fixture is not reproducible")
    require(M1D_FIXTURE.read_bytes() == build_fixture(), "M1D fixture is not reproducible")
    require(TRANSACTION_FIXTURE.read_bytes() == build_transaction_fixture(), "transaction fixture is not reproducible")
    require(sha256(TRANSACTION_FIXTURE) == EXPECTED_TRANSACTION_SHA256, "transaction fixture SHA drift")

    with tempfile.TemporaryDirectory(prefix="sih-tls-fingerprint-e2e-") as temp:
        root = Path(temp)
        test_validator(root)
        build_locked_image(lock, root)

        empty = root / "empty"
        result = invoke_wrapper(EMPTY_FIXTURE, empty, "--tls-fingerprints")
        require(result.returncode == 0, "no-TLS full-fingerprint run failed")
        require("no ssl.log was emitted" in result.stderr, "no-TLS diagnostic missing")

        standard = root / "standard"
        ja4 = root / "ja4"
        full = root / "full-0"
        for mode, output in (("--canonical", standard), ("--ja4", ja4), ("--tls-fingerprints", full)):
            result = invoke_wrapper(TLS_FIXTURE, output, mode)
            require(result.returncode == 0, f"runtime mode failed: {mode}\n{result.stderr}")
        assert_headers(full)
        compare_shared_log_data(standard, ja4, ("conn.log", "ssl.log"))
        compare_shared_log_data(standard, full, ("conn.log", "ssl.log"))
        standard_fields, _ = read_zeek(standard / "ssl.log")
        ja4_fields, _ = read_zeek(ja4 / "ssl.log")
        full_fields, full_ssl_rows = read_zeek(full / "ssl.log")
        require(ja4_fields == standard_fields + ["ja4"], "JA4 mode field isolation failed")
        require(full_fields == standard_fields + ["ja3", "ja3s", "ja4"], "full mode field isolation failed")
        require(not (FORBIDDEN_JA4_FIELDS & set(full_fields)), "full mode leaked a forbidden JA4+ field")
        require([row["ja3"] for row in full_ssl_rows] == EXPECTED_JA3, "real JA3 vector changed")
        require([row["ja3s"] for row in full_ssl_rows] == EXPECTED_JA3S, "real JA3S vector changed")
        require([row["ja4"] for row in full_ssl_rows] == EXPECTED_JA4, "real JA4 vector changed")

        renamed_dir = root / "renamed"
        renamed_dir.mkdir()
        renamed = renamed_dir / "identical-bytes-renamed.pcap"
        shutil.copy2(TLS_FIXTURE, renamed)
        require(sha256(renamed) == sha256(TLS_FIXTURE), "renamed PCAP differs")
        full_runs = [full]
        for index in range(1, 9):
            candidate = root / f"full-{index}"
            result = invoke_wrapper(TLS_FIXTURE, candidate, "--tls-fingerprints")
            require(result.returncode == 0, f"full replay {index} failed")
            full_runs.append(candidate)
        renamed_run = root / "full-renamed"
        result = invoke_wrapper(renamed, renamed_run, "--tls-fingerprints")
        require(result.returncode == 0, "renamed full replay failed")
        full_runs.append(renamed_run)
        for candidate in full_runs[1:]:
            compare_shared_log_data(full_runs[0], candidate, ("conn.log", "ssl.log"))

        pcap_sha = sha256(TLS_FIXTURE)
        canonical_paths = [root / f"full-canonical-{index}.jsonl" for index in range(10)]
        canonical_runs = [
            canonicalize(logs, output, pcap_sha)
            for logs, output in zip(full_runs, canonical_paths, strict=True)
        ]
        for output in canonical_paths[1:]:
            require(output.read_bytes() == canonical_paths[0].read_bytes(), "ten-run canonical replay is not byte-identical")
        canonical_tls = [row for row in canonical_runs[0] if row["observation_type"] == "tls"]
        require([row["data"]["ja3"] for row in canonical_tls] == EXPECTED_JA3, "canonical JA3 changed")
        require([row["data"]["ja3s"] for row in canonical_tls] == EXPECTED_JA3S, "canonical JA3S changed")
        require([row["data"]["ja4"] for row in canonical_tls] == EXPECTED_JA4, "canonical JA4 changed")

        standard_path = root / "standard-canonical.jsonl"
        standard_canonical = canonicalize(standard, standard_path, pcap_sha)
        require(
            [row["record_id"] for row in standard_canonical]
            == [row["record_id"] for row in canonical_runs[0]],
            "fingerprint mode changed canonical record IDs",
        )
        scrubbed = json.loads(json.dumps(canonical_runs[0]))
        for row in scrubbed:
            if row["observation_type"] == "tls":
                for field in ("ja3", "ja3s", "ja4"):
                    row["data"].pop(field, None)
        require(scrubbed == standard_canonical, "full mode changed a pre-existing canonical fact")

        detector_path = root / "tls-detector-v2.jsonl"
        stats, detector_rows = profile(full, detector_path)
        require((stats.with_ja3, stats.with_ja3s, stats.with_ja4) == (2, 2, 2), "fingerprint availability counts failed")
        require(len(detector_rows) == 2, "TLS detector row count failed")
        require(all(len(row["tls_transactions"]) == 1 for row in detector_rows), "TLS transaction arrays failed")
        require([row["tls_transactions"][0]["ja3"] for row in detector_rows] == EXPECTED_JA3, "detector JA3 changed")
        require([row["tls_transactions"][0]["ja3s"] for row in detector_rows] == EXPECTED_JA3S, "detector JA3S changed")
        require([row["tls_transactions"][0]["ja4"] for row in detector_rows] == EXPECTED_JA4, "detector JA4 changed")
        adapter = IngestionJsonlAdapter(path=detector_path, strict=True)
        events = list(adapter)
        require(adapter.stats.errors == 0 and len(events) == 2, "Detection adapter rejected full fingerprints")
        for fingerprint_type, values in (("ja3", EXPECTED_JA3), ("ja3s", EXPECTED_JA3S), ("ja4", EXPECTED_JA4)):
            config = EncryptedMalwareConfig(**{f"malicious_{fingerprint_type}": {values[0]}})
            alerts = list(DetectionEngine([EncryptedMalwareDetector(config)], raise_on_detector_error=True).run(events))
            matching = [alert for alert in alerts if alert.evidence.get("fingerprint_type") == fingerprint_type]
            require(len(matching) == 1 and matching[0].evidence["fingerprint"] == values[0], f"real {fingerprint_type} detector match failed")

        m1d_logs = root / "m1d-full"
        result = invoke_wrapper(M1D_FIXTURE, m1d_logs, "--tls-fingerprints")
        require(result.returncode == 0, "M1D full runtime failed")
        _, m1d_rows = profile(m1d_logs, root / "m1d-detector-v2.jsonl")
        http_row = next(row for row in m1d_rows if row.get("http_transactions"))
        require(http_row["http"]["uri"] == "/one", "HTTP scalar compatibility projection changed")
        require(http_row["http"]["transaction_count"] == 2, "HTTP transaction_count failed")
        require([item["uri"] for item in http_row["http_transactions"]] == ["/one", "/two"], "real-PCAP HTTP transaction order/loss failed")
        m1d_adapter = IngestionJsonlAdapter(path=root / "m1d-detector-v2.jsonl", strict=True)
        m1d_events = list(m1d_adapter)
        http_event = next(event for event in m1d_events if event.http_transactions)
        require([item.uri for item in http_event.http_transactions] == ["/one", "/two"], "Detection lost an HTTP transaction")

        transaction_logs = root / "transaction-full"
        result = invoke_wrapper(TRANSACTION_FIXTURE, transaction_logs, "--tls-fingerprints")
        require(result.returncode == 0, "five-transaction runtime failed")
        _, source_dns = read_zeek(transaction_logs / "dns.log")
        require(len(source_dns) == 5 and len({row["uid"] for row in source_dns}) == 1, "real PCAP did not yield five DNS rows on one UID")
        _, transaction_rows = profile(transaction_logs, root / "transaction-detector-v2.jsonl")
        require(len(transaction_rows) == 1, "five DNS source rows did not correlate to one flow")
        dns_row = transaction_rows[0]
        expected_queries = [f"txn-{index}.example.test" for index in range(1, 6)]
        require(dns_row["dns"]["query"] == expected_queries[0], "DNS scalar compatibility projection changed")
        require(dns_row["dns"]["transaction_count"] == 5, "DNS transaction_count failed")
        require([item["query"] for item in dns_row["dns_transactions"]] == expected_queries, "real-PCAP DNS transaction order/loss failed")
        require([item["source_ordinal"] for item in dns_row["dns_transactions"]] == list(range(5)), "DNS source ordinals failed")
        transaction_adapter = IngestionJsonlAdapter(path=root / "transaction-detector-v2.jsonl", strict=True)
        transaction_events = list(transaction_adapter)
        require(transaction_adapter.stats.errors == 0 and len(transaction_events) == 1, "Detection rejected DNS transactions")
        require([item.query for item in transaction_events[0].dns_transactions] == expected_queries, "Detection lost a DNS transaction")

        serialized = detector_path.read_text(encoding="utf-8").lower()
        serialized += (root / "m1d-detector-v2.jsonl").read_text(encoding="utf-8").lower()
        for forbidden in FORBIDDEN_JA4_FIELDS | {
            "cert_chain_fps",
            "client_cert_chain_fps",
            "answers",
            "ttls",
            "password",
            "cookie",
            "authorization",
        }:
            require(f'"{forbidden}"' not in serialized, f"detector output leaked {forbidden}")

        test_fail_closed_copies(root, TLS_FIXTURE, lock)

    require(sha256(REPOSITORY_ROOT / "contracts" / "canonical_observation_v1.schema.json") == EXPECTED_CONTRACT_SHA256, "CanonicalObservation contract hash changed")
    if (REPOSITORY_ROOT / ".git").exists():
        require(
            not run(
                [
                    "git",
                    "-c",
                    f"safe.directory={REPOSITORY_ROOT.as_posix()}",
                    "diff",
                    "--",
                    "contracts",
                ]
            ).stdout,
            "contracts changed",
        )

    print("TLS fingerprint + transaction Docker E2E: PASS")
    print(f"assertions={ASSERTION_COUNT}")
    print(f"image_id={lock['TLS_FP_IMAGE_ID']}")
    print(f"config_digest={lock['TLS_FP_CONFIG_DIGEST']}")
    print(f"ja3_commit={lock['JA3_UPSTREAM_COMMIT']}")
    print("ja3_values=" + ",".join(EXPECTED_JA3))
    print("ja3s_values=" + ",".join(EXPECTED_JA3S))
    print("ja4_values=" + ",".join(EXPECTED_JA4))
    print("replay=10/10 byte-identical canonical outputs including renamed PCAP")
    print("transactions=real-PCAP DNS 5/5 and HTTP 2/2 reach Detection; TLS multi-row covered by log fixture tests")
    print("seam=PCAP->Zeek->canonical/detector-v2->Detection->JA3/JA3S/JA4 signature alerts")
    print("failure_modes=missing-image,missing-loader,corrupt-source,wrong-label fail closed")


if __name__ == "__main__":
    main()
