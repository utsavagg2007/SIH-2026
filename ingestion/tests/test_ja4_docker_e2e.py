#!/usr/bin/env python3
"""Independent Docker qualification for the pinned JA4 ingestion profile."""

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
JA4_FIXTURE = FIXTURE_ROOT / "ja4_synthetic.pcap"
M1D_FIXTURE = FIXTURE_ROOT / "m1d_synthetic.pcap"
EMPTY_FIXTURE = FIXTURE_ROOT / "m1d_empty.pcap"
STANDARD_HEADER_EVIDENCE = (
    SCRIPT_ROOT / "fixtures" / "runtime_headers" / "zeek_8.0.10_m1d_fields.txt"
)
JA4_HEADER_EVIDENCE = (
    SCRIPT_ROOT / "fixtures" / "runtime_headers" / "zeek_8.0.10_ja4_fields.txt"
)
LOCK_FILE = INGESTION_ROOT / "runtime" / "ja4-runtime.lock"
OBSERVED_AT = "2026-01-02T03:04:05.678901Z"
SENSOR_ID = "ja4-e2e-sensor"
EXPECTED_JA4 = [
    "t13d020200_c1929292aa6b_b9a491fefe05",
    "t13i030100_34b97de2cef7_b9a491fefe05",
]
EXPECTED_CONTRACT_SHA256 = (
    "311a22470f79fd0d339d3fd97512d3fa107d30768e58d428a92dabcbe0416f57"
)
EXPECTED_DETECTOR_SOURCE_SHA256 = (
    "39f27db71cd14c2e63a676554458146006b3e22926426a39623a00781e2cbc1f"
)
FORBIDDEN_FIELDS = {
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


def run(arguments: list[str], *, cwd: Path = REPOSITORY_ROOT) -> subprocess.CompletedProcess[str]:
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
        require(bool(separator and name and value), f"invalid runtime lock line: {line!r}")
        values[name] = value
    return values


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
        if "__pycache__" in path.parts:
            continue
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def verify_source_integrity(lock: dict[str, str]) -> None:
    require(
        sha256(INGESTION_ROOT / "docker" / "ja4" / "Dockerfile")
        == lock["JA4_DOCKERFILE_SHA256"],
        "Dockerfile hash differs from runtime lock",
    )
    require(
        sha256(INGESTION_ROOT / "runtime" / "ja4-only.zeek")
        == lock["JA4_LOADER_SHA256"],
        "loader hash differs from runtime lock",
    )
    vendor = INGESTION_ROOT / "vendor" / "ja4-zeek"
    manifest = vendor / "SOURCE-MANIFEST.sha256"
    require(
        sha256(manifest) == lock["JA4_SOURCE_MANIFEST_SHA256"],
        "source-manifest hash differs from runtime lock",
    )
    for line in manifest.read_text(encoding="utf-8").splitlines():
        expected, name = line.split("  ", 1)
        require(sha256(vendor / name) == expected, f"vendored source hash failed: {name}")


def build_locked_image(lock: dict[str, str], root: Path) -> None:
    iid_file = root / "ja4-image.iid"
    run(
        [
            "docker",
            "build",
            "--platform",
            lock["JA4_BUILD_PLATFORM"],
            "--no-cache",
            "--provenance=false",
            "--build-arg",
            f"SOURCE_DATE_EPOCH={lock['JA4_BUILD_EPOCH']}",
            "--iidfile",
            str(iid_file),
            "--tag",
            lock["JA4_IMAGE_TAG"],
            "--file",
            str(INGESTION_ROOT / "docker" / "ja4" / "Dockerfile"),
            str(INGESTION_ROOT),
        ]
    )
    require(
        iid_file.read_text(encoding="ascii").strip() == lock["JA4_CONFIG_DIGEST"],
        "rebuilt image config digest differs from runtime lock",
    )
    image_id = run(
        ["docker", "image", "inspect", lock["JA4_IMAGE_TAG"], "--format", "{{.Id}}"]
    ).stdout.strip()
    require(image_id == lock["JA4_IMAGE_ID"], "rebuilt image ID differs from runtime lock")

    labels = json.loads(
        run(
            [
                "docker",
                "image",
                "inspect",
                lock["JA4_IMAGE_ID"],
                "--format",
                "{{json .Config.Labels}}",
            ]
        ).stdout
    )
    expected_labels = {
        "io.sih.zeek.base-digest": lock["JA4_BASE_IMAGE"].split("@", 1)[1],
        "io.sih.ja4.upstream-commit": lock["JA4_UPSTREAM_COMMIT"],
        "io.sih.ja4.upstream-tree": lock["JA4_UPSTREAM_TREE"],
        "io.sih.ja4.upstream-archive-sha256": lock["JA4_UPSTREAM_ARCHIVE_SHA256"],
        "io.sih.ja4.source-manifest-sha256": lock["JA4_SOURCE_MANIFEST_SHA256"],
        "io.sih.ja4.loader-sha256": lock["JA4_LOADER_SHA256"],
    }
    for name, expected in expected_labels.items():
        require(labels.get(name) == expected, f"image label {name} failed qualification")


def invoke_zeek(
    image: str,
    pcap: Path,
    output: Path,
    *,
    ja4: bool,
) -> None:
    output.mkdir()
    arguments = [
        "docker",
        "run",
        "--rm",
        "--platform",
        "linux/amd64",
        "-v",
        f"{pcap.parent}:/pcaps:ro",
        "-v",
        f"{output}:/logs",
        "-w",
        "/logs",
        image,
        "zeek",
        "-D",
        "-C",
        "-r",
        f"/pcaps/{pcap.name}",
        "local",
    ]
    if ja4:
        arguments.append("/usr/local/zeek/share/zeek/site/ja4-only.zeek")
    run(arguments)


def bash_executable() -> str:
    if os.name != "nt":
        return "bash"
    candidates = [
        Path(os.environ.get("ProgramFiles", "")) / "Git" / "bin" / "bash.exe",
        Path(os.environ.get("LOCALAPPDATA", ""))
        / "Programs"
        / "Git"
        / "bin"
        / "bash.exe",
    ]
    match = next((path for path in candidates if path.is_file()), None)
    require(match is not None, "Git Bash is required for the Windows wrapper test")
    return str(match)


def invoke_wrapper(pcap: Path, output: Path, script: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            bash_executable(),
            "-l",
            str(script or (INGESTION_ROOT / "scripts" / "run_zeek.sh")),
            str(pcap),
            str(output),
            "--ja4",
        ],
        cwd=REPOSITORY_ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )


def invoke_log_validator(logs: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            bash_executable(),
            "-l",
            str(INGESTION_ROOT / "scripts" / "validate_ja4_logs.sh"),
            str(logs),
        ],
        cwd=REPOSITORY_ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )


def test_log_validator(root: Path) -> None:
    missing_header = root / "validator-missing-header"
    missing_header.mkdir()
    (missing_header / "ssl.log").write_text(
        "#fields\tts\tuid\n1.0\tC1\n", encoding="utf-8", newline="\n"
    )
    result = invoke_log_validator(missing_header)
    require(
        result.returncode != 0 and "without the required ja4 field" in result.stderr,
        "ssl.log without a JA4 header did not fail closed",
    )

    empty_value = root / "validator-empty-value"
    empty_value.mkdir()
    (empty_value / "ssl.log").write_text(
        "#fields\tts\tuid\tja4\n1.0\tC1\t-\n", encoding="utf-8", newline="\n"
    )
    result = invoke_log_validator(empty_value)
    require(
        result.returncode == 0 and "no source JA4 value was available" in result.stderr,
        "empty JA4 source state did not succeed with an explicit diagnostic",
    )

    arbitrary_value = root / "validator-arbitrary-value"
    arbitrary_value.mkdir()
    (arbitrary_value / "ssl.log").write_text(
        "#fields\tts\tuid\tja4\n1.0\tC1\tnot-a-validated-shape\n",
        encoding="utf-8",
        newline="\n",
    )
    result = invoke_log_validator(arbitrary_value)
    require(
        result.returncode == 0 and "no source JA4 value was available" not in result.stderr,
        "non-empty arbitrary source JA4 was rejected or treated as unavailable",
    )

    forbidden_field = root / "validator-forbidden-field"
    forbidden_field.mkdir()
    shutil.copy2(arbitrary_value / "ssl.log", forbidden_field / "ssl.log")
    (forbidden_field / "http.log").write_text(
        "#fields\tts\tja4h\n1.0\tforbidden\n", encoding="utf-8", newline="\n"
    )
    result = invoke_log_validator(forbidden_field)
    require(
        result.returncode != 0 and "forbidden JA4+ field" in result.stderr,
        "forbidden JA4+ log field did not fail closed",
    )


def read_zeek(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    fields: list[str] | None = None
    rows: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#fields\t"):
            fields = line.split("\t")[1:]
        elif line and not line.startswith("#"):
            require(fields is not None, f"{path.name} data preceded #fields")
            columns = line.split("\t")
            rows.append(dict(zip(fields, columns, strict=True)))
    require(fields is not None, f"{path.name} has no #fields header")
    return fields, rows


def assert_headers(logs: Path, evidence: Path) -> None:
    text = evidence.read_text(encoding="utf-8").replace("\r\n", "\n")
    for name in ("conn.log", "dns.log", "ssl.log", "http.log"):
        fields, _ = read_zeek(logs / name)
        field_line = "#fields\t" + "\t".join(fields)
        require(f"{name}\n{field_line}" in text, f"{name} runtime header drift")


def canonicalize(logs: Path, output: Path, input_sha256: str) -> list[dict]:
    import ingestion_core

    summary = json.loads(
        ingestion_core.write_canonical_observations_from_zeek_logs(
            str(logs),
            str(output),
            SENSOR_ID,
            input_sha256,
            OBSERVED_AT,
            False,
        )
    )
    require(summary["rows_skipped"] == 0, "canonicalization skipped a JA4 row")
    return [
        json.loads(line)
        for line in output.read_text(encoding="utf-8").splitlines()
        if line
    ]


def compare_log_data(left: Path, right: Path, names: tuple[str, ...]) -> None:
    for name in names:
        left_fields, left_rows = read_zeek(left / name)
        right_fields, right_rows = read_zeek(right / name)
        shared = [field for field in left_fields if field in right_fields]
        left_projection = [{field: row[field] for field in shared} for row in left_rows]
        right_projection = [{field: row[field] for field in shared} for row in right_rows]
        require(left_projection == right_projection, f"{name} existing source facts changed")


def test_fail_closed_copies(root: Path, pcap: Path, lock: dict[str, str]) -> None:
    def make_copy(name: str) -> Path:
        target = root / name
        (target / "scripts").mkdir(parents=True)
        shutil.copy2(INGESTION_ROOT / "scripts" / "run_zeek.sh", target / "scripts")
        shutil.copytree(INGESTION_ROOT / "runtime", target / "runtime")
        shutil.copytree(INGESTION_ROOT / "docker", target / "docker")
        shutil.copytree(INGESTION_ROOT / "vendor", target / "vendor")
        return target

    missing = make_copy("failure-missing-image")
    missing_lock = missing / "runtime" / "ja4-runtime.lock"
    content = missing_lock.read_text(encoding="utf-8").replace(
        lock["JA4_IMAGE_TAG"], "sih-zeek-ja4:definitely-missing"
    )
    missing_lock.write_text(content, encoding="utf-8", newline="\n")
    result = invoke_wrapper(pcap, root / "missing-image-output", missing / "scripts" / "run_zeek.sh")
    require(result.returncode != 0 and "unavailable locally" in result.stderr, "missing image did not fail closed")

    missing_loader = make_copy("failure-missing-loader")
    (missing_loader / "runtime" / "ja4-only.zeek").unlink()
    result = invoke_wrapper(
        pcap,
        root / "missing-loader-output",
        missing_loader / "scripts" / "run_zeek.sh",
    )
    require(
        result.returncode != 0 and "required JA4 runtime input is missing" in result.stderr,
        "missing loader did not fail closed",
    )

    loader = make_copy("failure-corrupt-loader")
    with (loader / "runtime" / "ja4-only.zeek").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write("# corruption probe\n")
    result = invoke_wrapper(pcap, root / "corrupt-loader-output", loader / "scripts" / "run_zeek.sh")
    require(result.returncode != 0 and "integrity failure" in result.stderr, "corrupt loader did not fail closed")

    source = make_copy("failure-corrupt-source")
    with (source / "vendor" / "ja4-zeek" / "zeek" / "ja4" / "main.zeek").open(
        "a", encoding="utf-8", newline="\n"
    ) as handle:
        handle.write("# corruption probe\n")
    result = invoke_wrapper(pcap, root / "corrupt-source-output", source / "scripts" / "run_zeek.sh")
    require(result.returncode != 0 and "source integrity" in result.stderr, "corrupt package did not fail closed")


def main() -> None:
    sys.path.insert(0, str(INGESTION_ROOT))
    sys.path.insert(0, str(REPOSITORY_ROOT / "detection"))
    import pipeline
    from detection_core.adapters import IngestionJsonlAdapter
    from detection_core.detectors import EncryptedMalwareConfig, EncryptedMalwareDetector
    from detection_core.engine import DetectionEngine
    from scripts.generate_synthetic_pcap import build_fixture, build_ja4_fixture

    lock = read_lock()
    verify_source_integrity(lock)
    require(M1D_FIXTURE.read_bytes() == build_fixture(), "frozen M1D fixture changed")
    require(JA4_FIXTURE.read_bytes() == build_ja4_fixture(), "JA4 fixture is not reproducible")
    require(sha256(JA4_FIXTURE) == "8f9389585d4a35691c5b499d593b4bd6a69a891a8f9b32259a7557e72adfe5ba", "JA4 fixture SHA drift")

    with tempfile.TemporaryDirectory(prefix="sih-ja4-docker-e2e-") as temp:
        root = Path(temp)
        test_log_validator(root)
        build_locked_image(lock, root)

        empty_output = root / "empty-ja4"
        empty_result = invoke_wrapper(EMPTY_FIXTURE, empty_output)
        require(empty_result.returncode == 0, "no-TLS JA4 run did not succeed")
        require(
            "no ssl.log was emitted; the PCAP contained no recognized TLS source rows"
            in empty_result.stderr,
            "no-TLS JA4 run did not emit the required explicit diagnostic",
        )

        standard_m1d = root / "standard-m1d"
        ja4_m1d = root / "ja4-m1d"
        invoke_zeek(lock["JA4_BASE_IMAGE"], M1D_FIXTURE, standard_m1d, ja4=False)
        invoke_zeek(lock["JA4_IMAGE_ID"], M1D_FIXTURE, ja4_m1d, ja4=True)
        assert_headers(standard_m1d, STANDARD_HEADER_EVIDENCE)
        assert_headers(ja4_m1d, JA4_HEADER_EVIDENCE)
        compare_log_data(standard_m1d, ja4_m1d, ("conn.log", "dns.log", "ssl.log", "http.log"))
        for name in ("conn.log", "dns.log", "ssl.log", "http.log"):
            fields, _ = read_zeek(ja4_m1d / name)
            require(not (FORBIDDEN_FIELDS & set(fields)), f"{name} contains a JA4+ field")
        standard_ssl_fields, _ = read_zeek(standard_m1d / "ssl.log")
        ja4_ssl_fields, _ = read_zeek(ja4_m1d / "ssl.log")
        require(
            ja4_ssl_fields == standard_ssl_fields + ["ja4"],
            "qualified ssl.log header is not exactly standard fields plus ja4",
        )

        sha_m1d = sha256(M1D_FIXTURE)
        standard_canonical_path = root / "standard-m1d-canonical.jsonl"
        ja4_canonical_path = root / "ja4-m1d-canonical.jsonl"
        standard_canonical = canonicalize(standard_m1d, standard_canonical_path, sha_m1d)
        ja4_canonical = canonicalize(ja4_m1d, ja4_canonical_path, sha_m1d)
        require(
            [row["record_id"] for row in standard_canonical]
            == [row["record_id"] for row in ja4_canonical],
            "JA4 changed canonical record identity",
        )
        scrubbed = json.loads(json.dumps(ja4_canonical))
        for row in scrubbed:
            if row["observation_type"] == "tls":
                row["data"].pop("ja4", None)
        require(scrubbed == standard_canonical, "JA4 changed a pre-existing canonical fact")

        legacy_standard = root / "legacy-standard.jsonl"
        legacy_ja4 = root / "legacy-ja4.jsonl"
        pipeline.run_pipeline(None, str(standard_m1d), str(legacy_standard), skip_zeek=True)
        pipeline.run_pipeline(None, str(ja4_m1d), str(legacy_ja4), skip_zeek=True)
        require(legacy_standard.read_bytes() == legacy_ja4.read_bytes(), "legacy-m1d bytes changed with JA4 logs")

        runs = [root / f"run-{letter}" for letter in "abcd"]
        wrapper = invoke_wrapper(JA4_FIXTURE, runs[0])
        require(wrapper.returncode == 0, f"qualified wrapper failed:\n{wrapper.stdout}\n{wrapper.stderr}")
        invoke_zeek(lock["JA4_IMAGE_ID"], JA4_FIXTURE, runs[1], ja4=True)
        invoke_zeek(lock["JA4_IMAGE_ID"], JA4_FIXTURE, runs[2], ja4=True)
        renamed_dir = root / "renamed"
        renamed_dir.mkdir()
        renamed = renamed_dir / "identical-bytes-renamed.pcap"
        shutil.copy2(JA4_FIXTURE, renamed)
        require(sha256(renamed) == sha256(JA4_FIXTURE), "renamed PCAP SHA changed")
        invoke_zeek(lock["JA4_IMAGE_ID"], renamed, runs[3], ja4=True)

        for candidate in runs[1:]:
            compare_log_data(runs[0], candidate, ("conn.log", "ssl.log"))
        _, ssl_rows = read_zeek(runs[0] / "ssl.log")
        actual_ja4 = [row["ja4"] for row in ssl_rows]
        require(actual_ja4 == EXPECTED_JA4, "actual PCAP-derived JA4 values changed")
        require(len({row["uid"] for row in ssl_rows}) == 2, "JA4 fixture UIDs are not distinct")

        sha_ja4 = sha256(JA4_FIXTURE)
        canonical_paths = [root / f"canonical-{letter}.jsonl" for letter in "abcd"]
        canonical_runs = [
            canonicalize(logs, output, sha_ja4)
            for logs, output in zip(runs, canonical_paths, strict=True)
        ]
        for output in canonical_paths[1:]:
            require(
                output.read_bytes() == canonical_paths[0].read_bytes(),
                "fixed-clock A/B/C/D canonical bytes differ",
            )
        canonical_tls = [
            row["data"]["ja4"]
            for row in canonical_runs[0]
            if row["observation_type"] == "tls"
        ]
        require(canonical_tls == EXPECTED_JA4, "canonical TLS did not preserve exact JA4")

        detector_output = root / "detector-v2.jsonl"
        stats = pipeline.run_pipeline(
            None,
            str(runs[0]),
            str(detector_output),
            skip_zeek=True,
            feature_profile=pipeline.DETECTOR_FEATURE_PROFILE,
        )
        require(stats.with_ja4 == 2, "detector-v2 JA4 availability count is wrong")
        detector_rows = [
            json.loads(line)
            for line in detector_output.read_text(encoding="utf-8").splitlines()
        ]
        detector_ja4 = [row["tls"]["ja4"] for row in detector_rows]
        require(detector_ja4 == EXPECTED_JA4, "detector-v2 altered JA4")

        adapter = IngestionJsonlAdapter(path=detector_output, strict=True)
        events = list(adapter)
        require(adapter.stats.errors == 0 and len(events) == 2, "adapter rejected JA4 detector rows")
        require([event.tls.ja4 for event in events] == EXPECTED_JA4, "TlsInfo altered JA4")
        detector = EncryptedMalwareDetector(
            EncryptedMalwareConfig(malicious_ja4={EXPECTED_JA4[0]})
        )
        alerts = list(DetectionEngine([detector], raise_on_detector_error=True).run(events))
        matches = [
            alert
            for alert in alerts
            if alert.evidence.get("fingerprint_type") == "ja4"
            and alert.evidence.get("fingerprint") == EXPECTED_JA4[0]
        ]
        require(len(matches) == 1, "real transported JA4 did not trigger the configured detector")

        canonical_text = canonical_paths[0].read_text(encoding="utf-8").lower()
        for forbidden in FORBIDDEN_FIELDS | {
            "cert_chain_fps",
            "client_cert_chain_fps",
            "cookie",
            "authorization",
            "answers",
        }:
            require(f'"{forbidden}"' not in canonical_text, f"canonical leaked {forbidden}")

        test_fail_closed_copies(root, JA4_FIXTURE, lock)

    contract = REPOSITORY_ROOT / "contracts" / "canonical_observation_v1.schema.json"
    require(sha256(contract) == EXPECTED_CONTRACT_SHA256, "canonical contract hash changed")
    detector_root = REPOSITORY_ROOT / "detection" / "detection_core" / "detectors"
    require(
        source_tree_sha256(detector_root) == EXPECTED_DETECTOR_SOURCE_SHA256,
        "detector algorithm source hash changed",
    )
    if (REPOSITORY_ROOT / ".git").exists():
        safe_git = ["git", "-c", f"safe.directory={REPOSITORY_ROOT.as_posix()}"]
        contract_diff = run([*safe_git, "diff", "--", "contracts"]).stdout
        require(not contract_diff, "CanonicalObservation contract changed")

    print("JA4 Docker E2E: PASS")
    print(f"assertions={ASSERTION_COUNT}")
    print(f"image_id={lock['JA4_IMAGE_ID']}")
    print(f"config_digest={lock['JA4_CONFIG_DIGEST']}")
    print(f"fixture_sha256={sha256(JA4_FIXTURE)}")
    print("ja4_values=" + ",".join(EXPECTED_JA4))
    print("replay=A/B/C/D byte-identical canonical output")
    print("seam=PCAP->Zeek->detector-v2->TlsInfo->encrypted-malware match")
    print("scope=canonical-contract and detector-source hashes verified")
    print(
        "failure_modes=no-TLS/empty-source diagnostics; missing-header,forbidden-field,"
        "missing-image,missing/corrupt-loader,corrupt-source fail closed; arbitrary source preserved"
    )


if __name__ == "__main__":
    main()
