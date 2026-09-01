import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
PIPELINE = ROOT / "pipeline.py"
LOG_FIXTURE = ROOT / "tests" / "fixtures" / "zeek" / "legacy_regression"
SHA = "01" * 32


class M1DCliSubprocessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sih-m1d-cli-test-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(PIPELINE), *arguments],
            cwd=ROOT,
            env=os.environ.copy(),
            text=True,
            capture_output=True,
            check=False,
        )

    def paths(self) -> tuple[Path, Path]:
        return self.root / "features.jsonl", self.root / "canonical.jsonl"

    def assert_failure_without_summary(
        self, result: subprocess.CompletedProcess[str]
    ) -> None:
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("[canonical] flow_emitted=", result.stderr)
        self.assertNotIn("[+] Processed", result.stdout)

    def test_canonical_output_without_sensor_id_fails(self) -> None:
        legacy, canonical = self.paths()
        result = self.run_cli(
            "--skip-zeek",
            "--keep-logs",
            str(LOG_FIXTURE),
            "--output",
            str(legacy),
            "--canonical-output",
            str(canonical),
            "--input-sha256",
            SHA,
        )
        self.assert_failure_without_summary(result)
        self.assertIn("--sensor-id is required", result.stderr)
        self.assertFalse(legacy.exists())
        self.assertFalse(canonical.exists())

    def test_sensor_id_without_canonical_output_fails(self) -> None:
        legacy, _ = self.paths()
        result = self.run_cli(
            "--skip-zeek",
            "--keep-logs",
            str(LOG_FIXTURE),
            "--output",
            str(legacy),
            "--sensor-id",
            "sensor",
        )
        self.assert_failure_without_summary(result)
        self.assertIn("require --canonical-output", result.stderr)
        self.assertFalse(legacy.exists())

    def test_input_sha_without_canonical_output_fails(self) -> None:
        legacy, _ = self.paths()
        result = self.run_cli(
            "--skip-zeek",
            "--keep-logs",
            str(LOG_FIXTURE),
            "--output",
            str(legacy),
            "--input-sha256",
            SHA,
        )
        self.assert_failure_without_summary(result)
        self.assertIn("require --canonical-output", result.stderr)
        self.assertFalse(legacy.exists())

    def test_canonical_with_ja4_fails(self) -> None:
        legacy, canonical = self.paths()
        result = self.run_cli(
            "--skip-zeek",
            "--keep-logs",
            str(LOG_FIXTURE),
            "--output",
            str(legacy),
            "--canonical-output",
            str(canonical),
            "--sensor-id",
            "sensor",
            "--input-sha256",
            SHA,
            "--ja4",
        )
        self.assert_failure_without_summary(result)
        self.assertIn("not qualified", result.stderr)
        self.assertFalse(legacy.exists())
        self.assertFalse(canonical.exists())

    def test_normal_mode_missing_pcap_fails(self) -> None:
        legacy, _ = self.paths()
        result = self.run_cli("--output", str(legacy))
        self.assert_failure_without_summary(result)
        self.assertIn("PCAP argument is required", result.stderr)
        self.assertFalse(legacy.exists())

    def test_canonical_skip_without_pcap_or_sha_fails(self) -> None:
        legacy, canonical = self.paths()
        result = self.run_cli(
            "--skip-zeek",
            "--keep-logs",
            str(LOG_FIXTURE),
            "--output",
            str(legacy),
            "--canonical-output",
            str(canonical),
            "--sensor-id",
            "sensor",
        )
        self.assert_failure_without_summary(result)
        self.assertIn("requires either a readable PCAP", result.stderr)
        self.assertFalse(legacy.exists())
        self.assertFalse(canonical.exists())

    def test_malformed_sha_fails(self) -> None:
        legacy, canonical = self.paths()
        result = self.run_cli(
            "--skip-zeek",
            "--keep-logs",
            str(LOG_FIXTURE),
            "--output",
            str(legacy),
            "--canonical-output",
            str(canonical),
            "--sensor-id",
            "sensor",
            "--input-sha256",
            "not-a-sha",
        )
        self.assert_failure_without_summary(result)
        self.assertIn("64 hexadecimal", result.stderr)
        self.assertFalse(legacy.exists())
        self.assertFalse(canonical.exists())

    def test_same_legacy_and_canonical_path_fails(self) -> None:
        shared = self.root / "same.jsonl"
        result = self.run_cli(
            "--skip-zeek",
            "--keep-logs",
            str(LOG_FIXTURE),
            "--output",
            str(shared),
            "--canonical-output",
            str(self.root / "." / "same.jsonl"),
            "--sensor-id",
            "sensor",
            "--input-sha256",
            SHA,
        )
        self.assert_failure_without_summary(result)
        self.assertIn("different files", result.stderr)
        self.assertFalse(shared.exists())

    def test_existing_canonical_target_fails_unchanged(self) -> None:
        legacy, canonical = self.paths()
        canonical.write_bytes(b"existing evidence")
        result = self.run_cli(
            "--skip-zeek",
            "--keep-logs",
            str(LOG_FIXTURE),
            "--output",
            str(legacy),
            "--canonical-output",
            str(canonical),
            "--sensor-id",
            "sensor",
            "--input-sha256",
            SHA,
        )
        self.assert_failure_without_summary(result)
        self.assertIn("will not be overwritten", result.stderr)
        self.assertEqual(canonical.read_bytes(), b"existing evidence")
        self.assertFalse(legacy.exists())

    def test_successful_legacy_only_invocation_uses_stdout(self) -> None:
        legacy, _ = self.paths()
        result = self.run_cli(
            "--skip-zeek",
            "--keep-logs",
            str(LOG_FIXTURE),
            "--output",
            str(legacy),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"[+] Processed 2 flows -> {legacy}\n")
        self.assertEqual(result.stderr, "")
        self.assertTrue(legacy.is_file())

    def test_successful_canonical_skip_invocation_splits_streams(self) -> None:
        legacy, canonical = self.paths()
        result = self.run_cli(
            "--skip-zeek",
            "--keep-logs",
            str(LOG_FIXTURE),
            "--output",
            str(legacy),
            "--canonical-output",
            str(canonical),
            "--sensor-id",
            " CLI Sensor ",
            "--input-sha256",
            SHA.upper(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"[+] Processed 2 flows -> {legacy}\n")
        self.assertIn("[canonical] flow_emitted=2", result.stderr)
        self.assertIn("dns_emitted=2", result.stderr)
        self.assertIn("tls_emitted=1", result.stderr)
        self.assertIn("http_emitted=2", result.stderr)
        self.assertTrue(legacy.is_file())
        self.assertTrue(canonical.is_file())
        self.assertEqual(canonical.read_bytes().count(b"\n"), 7)

    def test_real_cli_bounds_more_than_one_hundred_diagnostics(self) -> None:
        logs = self.root / "diagnostic-logs"
        shutil.copytree(LOG_FIXTURE, logs)
        http_path = logs / "http.log"
        content = http_path.read_text(encoding="utf-8")
        close_index = content.index("#close")
        rows = "".join(
            "1000.{index:06}\tC1\t192.0.2.10\t50000\t198.51.100.20\t80\t"
            "tcp\t6\t{depth}\tGET\texample.test\t/private-marker-uri\t"
            "private-marker-agent\tprivate-marker-status\t0\t10\n".format(
                index=index, depth=index + 3
            )
            for index in range(137)
        )
        http_path.write_text(
            content[:close_index] + rows + content[close_index:],
            encoding="utf-8",
            newline="\n",
        )

        legacy, canonical = self.paths()
        result = self.run_cli(
            "--skip-zeek",
            "--keep-logs",
            str(logs),
            "--output",
            str(legacy),
            "--canonical-output",
            str(canonical),
            "--sensor-id",
            "sensor",
            "--input-sha256",
            SHA,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr.count("[canonical] diagnostic "), 100)
        self.assertIn("additional diagnostics omitted", result.stderr)
        self.assertIn("diagnostics=137", result.stderr)
        self.assertNotIn("private-marker-uri", result.stderr)
        self.assertNotIn("private-marker-agent", result.stderr)
        self.assertNotIn("private-marker-status", result.stderr)
        self.assertIn("[+] Processed 2 flows", result.stdout)
        self.assertTrue(legacy.is_file())
        self.assertTrue(canonical.is_file())


if __name__ == "__main__":
    unittest.main()
