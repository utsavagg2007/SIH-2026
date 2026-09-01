import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import ingestion_core
import pipeline
from scripts.generate_synthetic_pcap import build_fixture


FIXTURES = Path(__file__).parent / "fixtures"
LOG_FIXTURE = FIXTURES / "zeek" / "legacy_regression"
LEGACY_GOLDEN = FIXTURES / "golden" / "legacy_regression_features.jsonl"
FIXED_OBSERVED_AT = "2026-01-02T03:04:05.678901Z"
SHA_A = "01" * 32
SHA_B = "02" * 32
SYNTHETIC_PCAP = FIXTURES / "pcap" / "m1d_synthetic.pcap"
SYNTHETIC_SHA = "87082cf96b12f7c90ca6b25fccc99650e9967daa409d85f132a5783068673bd9"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class M1DPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sih-m1d-python-test-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_skip(
        self,
        *,
        logs: Path = LOG_FIXTURE,
        output_name: str = "features.jsonl",
        canonical_name: str = "canonical.jsonl",
        sensor_id: str = "Sensor/Alpha",
        input_sha256: str | None = SHA_A,
        pcap: Path | None = None,
        observed_at: str = FIXED_OBSERVED_AT,
    ) -> tuple[Path, Path, list[dict]]:
        legacy = self.root / output_name
        canonical = self.root / canonical_name
        vectors = pipeline.run_pipeline(
            str(pcap) if pcap is not None else None,
            str(logs),
            str(legacy),
            skip_zeek=True,
            canonical_output_path=str(canonical),
            sensor_id=sensor_id,
            input_sha256=input_sha256,
            observed_at=observed_at,
        )
        return legacy, canonical, vectors

    def test_synthetic_fixture_matches_generator_and_frozen_sha(self) -> None:
        import hashlib

        checked_in = SYNTHETIC_PCAP.read_bytes()
        self.assertEqual(checked_in, build_fixture())
        self.assertEqual(hashlib.sha256(checked_in).hexdigest(), SYNTHETIC_SHA)
        self.assertEqual(
            (SYNTHETIC_PCAP.with_suffix(".pcap.sha256")).read_text(encoding="ascii"),
            f"{SYNTHETIC_SHA}  m1d_synthetic.pcap\n",
        )

    def test_runtime_files_use_exact_pin_and_canonical_determinism(self) -> None:
        expected = (
            "zeek/zeek:8.0.10@sha256:"
            "73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"
        )
        script = (Path(__file__).parents[1] / "scripts" / "run_zeek.sh").read_text(
            encoding="utf-8"
        )
        compose = (Path(__file__).parents[1] / "docker-compose.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(expected, script)
        self.assertIn("ZEEK_ARGS=(-D -C -r)", script)
        self.assertIn("--platform linux/amd64", script)
        self.assertNotIn("zeek/zeek:latest", script)
        self.assertIn(expected, compose)
        self.assertIn("platform: linux/amd64", compose)
        self.assertNotIn("zeek/zeek:latest", compose)
        self.assertNotIn(
            b"\r", (Path(__file__).parents[1] / "scripts" / "run_zeek.sh").read_bytes()
        )
        self.assertIn(
            "*.sh text eol=lf",
            (Path(__file__).parents[1] / ".gitattributes").read_text(
                encoding="utf-8"
            ),
        )

    def test_legacy_output_matches_frozen_baseline_and_last_row_wins(self) -> None:
        output = self.root / "legacy.jsonl"
        vectors = pipeline.run_pipeline(
            None, str(LOG_FIXTURE), str(output), skip_zeek=True
        )
        expected = LEGACY_GOLDEN.read_bytes().replace(b"\n", os.linesep.encode())
        self.assertEqual(output.read_bytes(), expected)
        self.assertEqual(len(vectors), 2)
        self.assertEqual(vectors[0]["http"]["method_encoded"], 2)
        self.assertEqual(vectors[1]["dns"]["query_length"], len("ghi.jkl"))

    def test_dual_output_does_not_change_legacy_bytes(self) -> None:
        legacy_only = self.root / "legacy-only.jsonl"
        pipeline.run_pipeline(None, str(LOG_FIXTURE), str(legacy_only), skip_zeek=True)
        dual, canonical, _ = self.run_skip(output_name="dual.jsonl")
        self.assertEqual(dual.read_bytes(), legacy_only.read_bytes())
        self.assertEqual(len(read_jsonl(canonical)), 7)

    def test_canonical_order_counts_one_to_many_and_fixed_run_context(self) -> None:
        _, canonical, _ = self.run_skip()
        rows = read_jsonl(canonical)
        self.assertEqual(
            [row["observation_type"] for row in rows],
            ["flow", "flow", "dns", "dns", "tls", "http", "http"],
        )
        self.assertEqual({row["observed_at"] for row in rows}, {FIXED_OBSERVED_AT})
        self.assertEqual({row["sensor_id"] for row in rows}, {"Sensor/Alpha"})
        self.assertEqual({row["provenance"]["input_sha256"] for row in rows}, {SHA_A})
        http_rows = [row for row in rows if row["observation_type"] == "http"]
        self.assertEqual(len(http_rows), 2)
        self.assertNotEqual(http_rows[0]["record_id"], http_rows[1]["record_id"])
        self.assertEqual(
            {row["data"]["flow_record_id"] for row in http_rows},
            {rows[0]["record_id"]},
        )

    def test_observed_at_does_not_change_record_ids(self) -> None:
        _, first, _ = self.run_skip(canonical_name="first.jsonl")
        _, second, _ = self.run_skip(
            output_name="second-features.jsonl",
            canonical_name="second.jsonl",
            observed_at="2030-12-31T23:59:59Z",
        )
        self.assertEqual(
            [row["record_id"] for row in read_jsonl(first)],
            [row["record_id"] for row in read_jsonl(second)],
        )

    def test_skip_identity_pcap_authoritative_uppercase_and_mismatch(self) -> None:
        pcap = self.root / "input.pcap"
        pcap.write_bytes(b"deterministic-pcap-bytes")
        expected = ingestion_core.sha256_input_file(str(pcap))
        _, canonical, _ = self.run_skip(pcap=pcap, input_sha256=expected.upper())
        self.assertEqual(
            {row["provenance"]["input_sha256"] for row in read_jsonl(canonical)},
            {expected},
        )
        with self.assertRaisesRegex(SystemExit, "does not match"):
            self.run_skip(
                output_name="mismatch-features.jsonl",
                canonical_name="mismatch.jsonl",
                pcap=pcap,
                input_sha256=SHA_B,
            )

    def test_skip_asserted_identity_validation(self) -> None:
        _, canonical, _ = self.run_skip(input_sha256=SHA_A.upper())
        self.assertEqual(
            {row["provenance"]["input_sha256"] for row in read_jsonl(canonical)},
            {SHA_A},
        )
        for invalid in ("", "a" * 63, "g" * 64):
            with self.subTest(invalid=invalid), self.assertRaises(SystemExit):
                self.run_skip(
                    output_name=f"bad-{len(invalid)}.jsonl",
                    canonical_name=f"bad-canonical-{len(invalid)}.jsonl",
                    input_sha256=invalid,
                )
        with self.assertRaisesRegex(SystemExit, "requires either"):
            pipeline.run_pipeline(
                None,
                str(LOG_FIXTURE),
                str(self.root / "missing-id-features.jsonl"),
                skip_zeek=True,
                canonical_output_path=str(self.root / "missing-id.jsonl"),
                sensor_id="sensor",
            )

    def test_sensor_identity_and_changed_pcap_identity(self) -> None:
        _, first, _ = self.run_skip(canonical_name="sensor-a.jsonl")
        _, second, _ = self.run_skip(
            output_name="sensor-b-features.jsonl",
            canonical_name="sensor-b.jsonl",
            sensor_id="Sensor/Beta",
        )
        first_rows = read_jsonl(first)
        second_rows = read_jsonl(second)
        self.assertNotEqual(
            [row["record_id"] for row in first_rows],
            [row["record_id"] for row in second_rows],
        )
        for left, right in zip(first_rows, second_rows):
            left.pop("record_id")
            right.pop("record_id")
            left.pop("sensor_id")
            right.pop("sensor_id")
            if "flow_record_id" in left["data"]:
                left["data"].pop("flow_record_id")
                right["data"].pop("flow_record_id")
            self.assertEqual(left, right)

        pcap_a = self.root / "identity-a.pcap"
        pcap_b = self.root / "identity-b.pcap"
        pcap_a.write_bytes(b"identity fixture bytes A")
        pcap_b.write_bytes(b"identity fixture bytes B")
        _, pcap_first, _ = self.run_skip(
            output_name="pcap-a-features.jsonl",
            canonical_name="pcap-a.jsonl",
            pcap=pcap_a,
            input_sha256=None,
        )
        _, changed, _ = self.run_skip(
            output_name="changed-features.jsonl",
            canonical_name="changed.jsonl",
            pcap=pcap_b,
            input_sha256=None,
        )
        self.assertNotEqual(
            read_jsonl(pcap_first)[0]["provenance"]["input_sha256"],
            read_jsonl(changed)[0]["provenance"]["input_sha256"],
        )
        self.assertNotEqual(
            [row["record_id"] for row in read_jsonl(pcap_first)],
            [row["record_id"] for row in read_jsonl(changed)],
        )

    def test_sensor_preservation_matrix_and_utf8_identity(self) -> None:
        sensors = ["   ", "Sénsor/東京", "MiXeD-Case", " leading and trailing "]
        observed: dict[str, list[str]] = {}
        for index, sensor in enumerate(sensors):
            _, canonical, _ = self.run_skip(
                output_name=f"sensor-{index}-features.jsonl",
                canonical_name=f"sensor-{index}.jsonl",
                sensor_id=sensor,
            )
            rows = read_jsonl(canonical)
            self.assertEqual({row["sensor_id"] for row in rows}, {sensor})
            observed[sensor] = [row["record_id"] for row in rows]

        with self.assertRaisesRegex(SystemExit, "nonempty"):
            self.run_skip(
                output_name="empty-sensor-features.jsonl",
                canonical_name="empty-sensor.jsonl",
                sensor_id="",
            )

        _, changed, _ = self.run_skip(
            output_name="utf8-changed-features.jsonl",
            canonical_name="utf8-changed.jsonl",
            sensor_id="Sênsor/東京",
        )
        self.assertNotEqual(
            observed["Sénsor/東京"],
            [row["record_id"] for row in read_jsonl(changed)],
        )

    def test_identical_pcap_bytes_at_different_paths_are_path_independent(self) -> None:
        first_pcap = self.root / "one" / "capture.pcap"
        second_pcap = self.root / "two" / "renamed.pcap"
        first_pcap.parent.mkdir()
        second_pcap.parent.mkdir()
        first_pcap.write_bytes(b"same exact bytes")
        second_pcap.write_bytes(first_pcap.read_bytes())
        expected = ingestion_core.sha256_input_file(str(first_pcap))
        _, first, _ = self.run_skip(
            canonical_name="path-a.jsonl", pcap=first_pcap, input_sha256=expected
        )
        _, second, _ = self.run_skip(
            output_name="path-b-features.jsonl",
            canonical_name="path-b.jsonl",
            pcap=second_pcap,
            input_sha256=expected,
        )
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_request_and_target_validation(self) -> None:
        with self.assertRaisesRegex(SystemExit, "sensor-id"):
            pipeline.run_pipeline(
                None,
                str(LOG_FIXTURE),
                str(self.root / "no-sensor-features.jsonl"),
                skip_zeek=True,
                canonical_output_path=str(self.root / "no-sensor.jsonl"),
                input_sha256=SHA_A,
            )
        with self.assertRaisesRegex(SystemExit, "nonempty"):
            self.run_skip(sensor_id="")
        same = self.root / "same.jsonl"
        with self.assertRaisesRegex(SystemExit, "different files"):
            pipeline.run_pipeline(
                None,
                str(LOG_FIXTURE),
                str(same),
                skip_zeek=True,
                canonical_output_path=str(self.root / "." / "same.jsonl"),
                sensor_id="sensor",
                input_sha256=SHA_A,
            )
        existing = self.root / "existing.jsonl"
        existing.write_bytes(b"prior evidence")
        with self.assertRaisesRegex(SystemExit, "already exists"):
            self.run_skip(canonical_name="existing.jsonl")
        self.assertEqual(existing.read_bytes(), b"prior evidence")
        with self.assertRaisesRegex(SystemExit, "parent directory"):
            self.run_skip(canonical_name="missing/child.jsonl")
        directory_target = self.root / "directory-target"
        directory_target.mkdir()
        with self.assertRaisesRegex(SystemExit, "already exists"):
            self.run_skip(canonical_name="directory-target")

    def test_absolute_relative_dot_and_dotdot_output_aliases_are_rejected(self) -> None:
        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        legacy = real_parent / "same.jsonl"

        old_cwd = Path.cwd()
        try:
            os.chdir(self.root)
            with self.assertRaisesRegex(SystemExit, "different files"):
                pipeline.run_pipeline(
                    None,
                    str(LOG_FIXTURE),
                    str(Path("real-parent") / "same.jsonl"),
                    skip_zeek=True,
                    canonical_output_path=str(
                        self.root / "real-parent" / "child" / ".." / "same.jsonl"
                    ),
                    sensor_id="sensor",
                    input_sha256=SHA_A,
                )
        finally:
            os.chdir(old_cwd)

    def test_symlinked_parent_output_alias_is_rejected(self) -> None:
        real_parent = self.root / "real-parent"
        real_parent.mkdir()
        legacy = real_parent / "same.jsonl"
        alias_parent = self.root / "alias-parent"
        try:
            alias_parent.symlink_to(real_parent, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"directory symlinks unavailable on this host: {exc}")
        with self.assertRaisesRegex(SystemExit, "different files"):
            pipeline.run_pipeline(
                None,
                str(LOG_FIXTURE),
                str(legacy),
                skip_zeek=True,
                canonical_output_path=str(alias_parent / "same.jsonl"),
                sensor_id="sensor",
                input_sha256=SHA_A,
            )

    def test_direct_output_file_symlink_alias_is_rejected(self) -> None:
        legacy = self.root / "direct-target.jsonl"
        direct_alias = self.root / "direct-output-link.jsonl"
        try:
            direct_alias.symlink_to(legacy)
        except OSError as exc:
            self.skipTest(f"output-file symlinks unavailable on this host: {exc}")
        with self.assertRaisesRegex(SystemExit, "different files"):
            pipeline.run_pipeline(
                None,
                str(LOG_FIXTURE),
                str(legacy),
                skip_zeek=True,
                canonical_output_path=str(direct_alias),
                sensor_id="sensor",
                input_sha256=SHA_A,
            )

    def test_output_alias_case_handling_matches_host_filesystem(self) -> None:
        legacy = self.root / "Case-Sensitive-Output.jsonl"
        canonical = self.root / "case-sensitive-output.jsonl"
        if os.path.normcase(str(legacy)) == os.path.normcase(str(canonical)):
            with self.assertRaisesRegex(SystemExit, "different files"):
                pipeline.run_pipeline(
                    None,
                    str(LOG_FIXTURE),
                    str(legacy),
                    skip_zeek=True,
                    canonical_output_path=str(canonical),
                    sensor_id="sensor",
                    input_sha256=SHA_A,
                )
        else:
            pipeline.run_pipeline(
                None,
                str(LOG_FIXTURE),
                str(legacy),
                skip_zeek=True,
                canonical_output_path=str(canonical),
                sensor_id="sensor",
                input_sha256=SHA_A,
                observed_at=FIXED_OBSERVED_AT,
            )
            self.assertTrue(legacy.is_file())
            self.assertTrue(canonical.is_file())

    def test_canonical_only_flags_and_unqualified_ja4_are_rejected(self) -> None:
        with self.assertRaisesRegex(SystemExit, "require --canonical-output"):
            pipeline.run_pipeline(
                None,
                str(LOG_FIXTURE),
                str(self.root / "ignored.jsonl"),
                skip_zeek=True,
                sensor_id="sensor",
            )
        with self.assertRaisesRegex(SystemExit, "not qualified"):
            pipeline.run_pipeline(
                None,
                str(LOG_FIXTURE),
                str(self.root / "ja4-features.jsonl"),
                use_ja4=True,
                skip_zeek=True,
                canonical_output_path=str(self.root / "ja4.jsonl"),
                sensor_id="sensor",
                input_sha256=SHA_A,
            )

    def test_missing_optional_logs_and_incomplete_or_invalid_log_sets(self) -> None:
        conn_only = self.root / "conn-only"
        conn_only.mkdir()
        shutil.copy2(LOG_FIXTURE / "conn.log", conn_only / "conn.log")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            _, canonical, _ = self.run_skip(logs=conn_only)
        self.assertEqual(
            [row["observation_type"] for row in read_jsonl(canonical)],
            ["flow", "flow"],
        )
        self.assertIn("missing_optional_logs=dns.log,ssl.log,http.log", stderr.getvalue())

        incomplete = self.root / "incomplete"
        incomplete.mkdir()
        shutil.copy2(LOG_FIXTURE / "dns.log", incomplete / "dns.log")
        config_error = None
        try:
            ingestion_core.write_canonical_observations_from_zeek_logs(
                str(incomplete),
                str(self.root / "incomplete.jsonl"),
                "sensor",
                SHA_A,
                FIXED_OBSERVED_AT,
                False,
            )
        except ValueError as exc:
            config_error = str(exc)
        self.assertIn("incomplete", config_error or "")
        self.assertFalse((self.root / "incomplete.jsonl").exists())

        invalid = self.root / "invalid"
        invalid.mkdir()
        (invalid / "conn.log").write_text("not a Zeek header\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "parse"):
            ingestion_core.write_canonical_observations_from_zeek_logs(
                str(invalid),
                str(self.root / "invalid.jsonl"),
                "sensor",
                SHA_A,
                FIXED_OBSERVED_AT,
                False,
            )

    def test_normal_mode_uses_fresh_logs_and_preserves_requested_logs(self) -> None:
        pcap = self.root / "normal.pcap"
        pcap.write_bytes(b"normal-mode-fixture")
        requested_logs = self.root / "kept-logs"
        requested_logs.mkdir()
        shutil.copy2(LOG_FIXTURE / "dns.log", requested_logs / "dns.log")
        seen: dict[str, object] = {}

        def fake_run_zeek(
            pcap_path: str,
            out_dir: str,
            use_ja4: bool = False,
            canonical_mode: bool = False,
        ) -> None:
            seen["out_dir"] = out_dir
            seen["canonical_mode"] = canonical_mode
            shutil.copy2(LOG_FIXTURE / "conn.log", Path(out_dir) / "conn.log")

        legacy = self.root / "normal-features.jsonl"
        canonical = self.root / "normal-canonical.jsonl"
        with mock.patch.object(pipeline, "run_zeek", side_effect=fake_run_zeek):
            pipeline.run_pipeline(
                str(pcap),
                str(requested_logs),
                str(legacy),
                canonical_output_path=str(canonical),
                sensor_id="sensor",
                observed_at=FIXED_OBSERVED_AT,
            )
        self.assertTrue(seen["canonical_mode"])
        self.assertNotEqual(Path(str(seen["out_dir"])), requested_logs)
        self.assertTrue((requested_logs / "conn.log").is_file())
        self.assertEqual(
            [row["observation_type"] for row in read_jsonl(canonical)],
            ["flow", "flow"],
        )

    def test_normal_empty_run_publishes_zero_byte_outputs(self) -> None:
        pcap = self.root / "empty.pcap"
        pcap.write_bytes(b"pcap header placeholder")
        legacy = self.root / "empty-features.jsonl"
        canonical = self.root / "empty-canonical.jsonl"
        with mock.patch.object(pipeline, "run_zeek", return_value=None):
            pipeline.run_pipeline(
                str(pcap),
                str(self.root / "empty-logs"),
                str(legacy),
                canonical_output_path=str(canonical),
                sensor_id="sensor",
                observed_at=FIXED_OBSERVED_AT,
            )
        self.assertEqual(legacy.read_bytes(), b"")
        self.assertEqual(canonical.read_bytes(), b"")

    def test_pre_post_pcap_sha_mutation_stops_before_all_publication(self) -> None:
        pcap = self.root / "mutable.pcap"
        pcap.write_bytes(b"original immutable evidence")
        legacy = self.root / "mutation-features.jsonl"
        canonical = self.root / "mutation-canonical.jsonl"
        kept = self.root / "mutation-kept"

        def mutate_after_zeek(
            pcap_path: str,
            out_dir: str,
            use_ja4: bool = False,
            canonical_mode: bool = False,
        ) -> None:
            del use_ja4, canonical_mode
            (Path(out_dir) / "conn.log").write_bytes(
                (LOG_FIXTURE / "conn.log").read_bytes()
            )
            Path(pcap_path).write_bytes(b"mutated while Zeek ran")

        stderr = io.StringIO()
        with mock.patch.object(
            pipeline, "run_zeek", side_effect=mutate_after_zeek
        ), mock.patch.object(
            pipeline, "_write_canonical_output"
        ) as canonical_writer, contextlib.redirect_stderr(
            stderr
        ), self.assertRaisesRegex(
            SystemExit, "changed while Zeek"
        ):
            pipeline.run_pipeline(
                str(pcap),
                str(kept),
                str(legacy),
                canonical_output_path=str(canonical),
                sensor_id="sensor",
            )
        canonical_writer.assert_not_called()
        self.assertNotIn("[canonical] flow_emitted=", stderr.getvalue())
        self.assertFalse(legacy.exists())
        self.assertFalse(canonical.exists())
        self.assertFalse(kept.exists())

    def test_final_synthetic_one_byte_change_changes_sha_and_record_ids(self) -> None:
        import hashlib

        original = bytearray(SYNTHETIC_PCAP.read_bytes())
        changed = bytearray(original)
        changed[-1] ^= 0x01
        changed_sha = hashlib.sha256(changed).hexdigest()
        self.assertNotEqual(SYNTHETIC_SHA, changed_sha)

        _, original_ids, _ = self.run_skip(
            output_name="synthetic-original-features.jsonl",
            canonical_name="synthetic-original.jsonl",
            input_sha256=SYNTHETIC_SHA,
        )
        _, changed_ids, _ = self.run_skip(
            output_name="synthetic-changed-features.jsonl",
            canonical_name="synthetic-changed.jsonl",
            input_sha256=changed_sha,
        )
        self.assertNotEqual(
            [row["record_id"] for row in read_jsonl(original_ids)],
            [row["record_id"] for row in read_jsonl(changed_ids)],
        )

    def test_stale_http_in_keep_destination_is_never_consumed(self) -> None:
        pcap = self.root / "stale-http.pcap"
        pcap.write_bytes(b"fresh conn-only run")
        kept = self.root / "stale-http-kept"
        kept.mkdir()
        stale_http = kept / "http.log"
        stale_http.write_bytes((LOG_FIXTURE / "http.log").read_bytes())
        stale_bytes = stale_http.read_bytes()

        def conn_only(
            _pcap_path: str,
            out_dir: str,
            use_ja4: bool = False,
            canonical_mode: bool = False,
        ) -> None:
            del use_ja4, canonical_mode
            (Path(out_dir) / "conn.log").write_bytes(
                (LOG_FIXTURE / "conn.log").read_bytes()
            )

        legacy = self.root / "stale-http-features.jsonl"
        canonical = self.root / "stale-http-canonical.jsonl"
        with mock.patch.object(pipeline, "run_zeek", side_effect=conn_only):
            pipeline.run_pipeline(
                str(pcap),
                str(kept),
                str(legacy),
                canonical_output_path=str(canonical),
                sensor_id="sensor",
                observed_at=FIXED_OBSERVED_AT,
            )
        self.assertEqual(stale_http.read_bytes(), stale_bytes)
        self.assertTrue(all("http" not in row for row in read_jsonl(legacy)))
        self.assertNotIn(
            "http", [row["observation_type"] for row in read_jsonl(canonical)]
        )

    def test_keep_log_copy_failure_is_explicit_and_prepublication(self) -> None:
        pcap = self.root / "copy-failure.pcap"
        pcap.write_bytes(b"copy failure input")
        kept = self.root / "copy-failure-kept"
        kept.mkdir()
        unrelated = kept / "operator-notes.txt"
        unrelated.write_bytes(b"do not delete")

        fresh_workspace: Path | None = None

        def two_logs(
            _pcap_path: str,
            out_dir: str,
            use_ja4: bool = False,
            canonical_mode: bool = False,
        ) -> None:
            nonlocal fresh_workspace
            del use_ja4, canonical_mode
            fresh_workspace = Path(out_dir)
            (Path(out_dir) / "conn.log").write_bytes(
                (LOG_FIXTURE / "conn.log").read_bytes()
            )
            (Path(out_dir) / "dns.log").write_bytes(
                (LOG_FIXTURE / "dns.log").read_bytes()
            )

        actual_copy = shutil.copy2
        calls = 0

        def fail_second_copy(source: Path, destination: Path):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected destination failure")
            return actual_copy(source, destination)

        legacy = self.root / "copy-failure-features.jsonl"
        canonical = self.root / "copy-failure-canonical.jsonl"
        with mock.patch.object(
            pipeline, "run_zeek", side_effect=two_logs
        ), mock.patch.object(
            pipeline.shutil, "copy2", side_effect=fail_second_copy
        ), self.assertRaisesRegex(SystemExit, "partial set of current-run copies"):
            pipeline.run_pipeline(
                str(pcap),
                str(kept),
                str(legacy),
                canonical_output_path=str(canonical),
                sensor_id="sensor",
            )
        self.assertFalse(legacy.exists())
        self.assertFalse(canonical.exists())
        self.assertEqual(unrelated.read_bytes(), b"do not delete")
        copied_current_logs = [
            name for name in ("conn.log", "dns.log") if (kept / name).exists()
        ]
        self.assertEqual(len(copied_current_logs), 1)
        self.assertIsNotNone(fresh_workspace)
        self.assertFalse(fresh_workspace.exists())

    def test_diagnostic_bounding_notice_and_safe_stderr(self) -> None:
        canonical = self.root / "diagnostic-output.jsonl"
        diagnostics = [
            {
                "log_type": "http",
                "source_record_id": "C-safe",
                "row_ordinal": index,
                "field": "status_code",
                "kind": "InvalidOptionalField",
                "message": "invalid optional numeric field",
            }
            for index in range(100)
        ]
        summary = {
            "flow_emitted": 0,
            "dns_emitted": 0,
            "tls_emitted": 0,
            "http_emitted": 0,
            "rows_skipped": 0,
            "diagnostics_count": 137,
            "diagnostics_truncated": True,
            "missing_optional_logs": [],
            "diagnostics": diagnostics,
        }

        def fake_canonical(*_args):
            canonical.write_bytes(b"")
            return json.dumps(summary)

        stderr = io.StringIO()
        with mock.patch.object(
            pipeline,
            "write_canonical_observations_from_zeek_logs",
            side_effect=fake_canonical,
        ), contextlib.redirect_stderr(stderr):
            returned = pipeline._write_canonical_output(
                str(LOG_FIXTURE),
                str(canonical),
                "sensor",
                SHA_A,
                FIXED_OBSERVED_AT,
                False,
            )
        self.assertEqual(returned["diagnostics_count"], 137)
        self.assertEqual(len(returned["diagnostics"]), 100)
        self.assertIn("additional diagnostics omitted", stderr.getvalue())
        self.assertIn("diagnostics=137", stderr.getvalue())
        for marker in ("secret-uri", "secret-agent", "secret-password"):
            self.assertNotIn(marker, stderr.getvalue())

    def test_zeek_and_canonical_failures_publish_no_partial_canonical(self) -> None:
        pcap = self.root / "failure.pcap"
        pcap.write_bytes(b"failure input")
        legacy = self.root / "failure-features.jsonl"
        canonical = self.root / "failure-canonical.jsonl"
        with mock.patch.object(
            pipeline, "run_zeek", side_effect=SystemExit("injected Zeek failure")
        ), self.assertRaisesRegex(SystemExit, "Zeek failure"):
            pipeline.run_pipeline(
                str(pcap),
                str(self.root / "failure-logs"),
                str(legacy),
                canonical_output_path=str(canonical),
                sensor_id="sensor",
            )
        self.assertFalse(legacy.exists())
        self.assertFalse(canonical.exists())

        dual_legacy = self.root / "preserved-features.jsonl"
        dual_canonical = self.root / "not-published.jsonl"
        with mock.patch.object(
            pipeline,
            "write_canonical_observations_from_zeek_logs",
            side_effect=OSError("injected publication failure"),
        ), self.assertRaisesRegex(SystemExit, "publication failure"):
            pipeline.run_pipeline(
                None,
                str(LOG_FIXTURE),
                str(dual_legacy),
                skip_zeek=True,
                canonical_output_path=str(dual_canonical),
                sensor_id="sensor",
                input_sha256=SHA_A,
            )
        self.assertTrue(dual_legacy.is_file())
        self.assertFalse(dual_canonical.exists())


if __name__ == "__main__":
    unittest.main()
