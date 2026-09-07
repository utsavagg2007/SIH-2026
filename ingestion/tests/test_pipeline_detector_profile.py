"""Integration tests for the opt-in detector-v2 feature interface."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import detector_profile
import pipeline


FIXTURES = Path(__file__).parent / "fixtures"
LOG_FIXTURE = FIXTURES / "zeek" / "legacy_regression"
LEGACY_GOLDEN = FIXTURES / "golden" / "legacy_regression_features.jsonl"
FIXED_OBSERVED_AT = "2026-01-02T03:04:05.678901Z"
SHA256 = "01" * 32


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class DetectorProfileIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sih-detector-profile-test-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_default_remains_frozen_legacy_projection(self) -> None:
        output = self.root / "legacy.jsonl"
        result = pipeline.run_pipeline(
            None,
            str(LOG_FIXTURE),
            str(output),
            skip_zeek=True,
        )
        self.assertIsInstance(result, list)
        expected_lines = LEGACY_GOLDEN.read_text(encoding="utf-8").splitlines()
        self.assertEqual(output.read_text(encoding="utf-8").splitlines(), expected_lines)

    def test_detector_v2_preserves_raw_fields_order_and_multiplicity(self) -> None:
        output = self.root / "detector.jsonl"
        result = pipeline.run_pipeline(
            None,
            str(LOG_FIXTURE),
            str(output),
            skip_zeek=True,
            feature_profile=pipeline.DETECTOR_FEATURE_PROFILE,
        )
        self.assertIsInstance(result, detector_profile.PipelineStats)
        rows = _read_jsonl(output)
        self.assertEqual([row["uid"] for row in rows], ["C1", "C2"])
        self.assertEqual([row["timestamp"] for row in rows], [1000.0, 1001.0])
        self.assertEqual(rows[0]["tls"]["ja3"], "client-ja3")
        self.assertIsNone(rows[0]["tls"]["ja4"])
        self.assertEqual(rows[0]["tls"]["server_name"], "example.test")
        self.assertEqual(rows[0]["tls"]["transaction_count"], 1)
        self.assertEqual(
            [item["ja3"] for item in rows[0]["tls_transactions"]],
            ["client-ja3"],
        )
        self.assertEqual(rows[0]["http"]["uri"], "/first")
        self.assertEqual(rows[0]["http"]["transaction_count"], 2)
        self.assertEqual(
            [item["uri"] for item in rows[0]["http_transactions"]],
            ["/first", "/second"],
        )
        self.assertEqual(
            [item["source_ordinal"] for item in rows[0]["http_transactions"]],
            [0, 1],
        )
        self.assertEqual(rows[1]["dns"]["query"], "abc.def")
        self.assertEqual(rows[1]["dns"]["qtype"], "A")
        self.assertEqual(rows[1]["dns"]["rcode"], "NOERROR")
        self.assertEqual(rows[1]["dns"]["transaction_count"], 2)
        self.assertEqual(
            [item["query"] for item in rows[1]["dns_transactions"]],
            ["abc.def", "ghi.jkl"],
        )
        self.assertEqual(rows[1]["dns_transactions"][0]["answer_count"], 1)
        self.assertIsNone(rows[1]["dns_transactions"][1]["answer_count"])
        self.assertEqual(result.multi_row_uids, {"dns": 1, "http": 1})
        self.assertTrue(all("flow_rate" not in row for row in rows))

    def test_detector_v2_uses_exact_ja4_from_its_earliest_selected_tls_row(self) -> None:
        logs = self.root / "ja4-logs"
        shutil.copytree(LOG_FIXTURE, logs)
        ssl_path = logs / "ssl.log"
        content = ssl_path.read_text(encoding="utf-8")
        content = content.replace(
            "client-ja3\tserver-ja3\t-\n",
            "client-ja3\tserver-ja3\tlater-source-ja4\n",
        )
        earlier = (
            "999.900000\tC1\t192.0.2.10\t50000\t198.51.100.20\t80\t"
            "tcp\t6\tTLSv12\tTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\t"
            "earliest.example\tother-ja3\tother-ja3s\t"
            "t13d020200_exact-source-token\n"
        )
        content = content.replace("#close", earlier + "#close")
        ssl_path.write_text(content, encoding="utf-8", newline="\n")

        output = self.root / "ja4-detector.jsonl"
        result = pipeline.run_pipeline(
            None,
            str(logs),
            str(output),
            skip_zeek=True,
            feature_profile=pipeline.DETECTOR_FEATURE_PROFILE,
        )
        rows = _read_jsonl(output)
        tls = rows[0]["tls"]
        self.assertEqual(tls["ja4"], "t13d020200_exact-source-token")
        self.assertEqual(tls["transaction_count"], 2)
        self.assertEqual(
            [item["ja4"] for item in rows[0]["tls_transactions"]],
            ["later-source-ja4", "t13d020200_exact-source-token"],
        )
        self.assertEqual(
            [item["event_time"] for item in rows[0]["tls_transactions"]],
            [1000.1, 999.9],
        )
        self.assertEqual(
            [item["source_ordinal"] for item in rows[0]["tls_transactions"]],
            [0, 1],
        )
        self.assertEqual(result.with_ja4, 1)
        self.assertEqual(result.multi_row_uids.get("tls"), 1)

    def test_detector_profile_never_changes_canonical_bytes(self) -> None:
        legacy = self.root / "legacy.jsonl"
        detector = self.root / "detector.jsonl"
        canonical_a = self.root / "canonical-a.jsonl"
        canonical_b = self.root / "canonical-b.jsonl"

        pipeline.run_pipeline(
            None,
            str(LOG_FIXTURE),
            str(legacy),
            skip_zeek=True,
            canonical_output_path=str(canonical_a),
            sensor_id="sensor/profile-test",
            input_sha256=SHA256,
            observed_at=FIXED_OBSERVED_AT,
        )
        pipeline.run_pipeline(
            None,
            str(LOG_FIXTURE),
            str(detector),
            skip_zeek=True,
            canonical_output_path=str(canonical_b),
            sensor_id="sensor/profile-test",
            input_sha256=SHA256,
            observed_at=FIXED_OBSERVED_AT,
            feature_profile=pipeline.DETECTOR_FEATURE_PROFILE,
        )

        self.assertEqual(canonical_a.read_bytes(), canonical_b.read_bytes())
        self.assertNotEqual(legacy.read_bytes(), detector.read_bytes())

    def test_five_transactions_survive_without_special_case_loss(self) -> None:
        parsed = pipeline.parse_logs(
            str(LOG_FIXTURE), feature_profile=pipeline.DETECTOR_FEATURE_PROFILE
        )
        template = parsed["dns"][0]
        parsed["dns"] = []
        for index in range(5):
            transaction = dict(template)
            transaction["query"] = f"query-{index}.example"
            transaction["timestamp"] = 1001.5
            transaction["event_time"] = 1001.5
            transaction["source_ordinal"] = index
            parsed["dns"].append(transaction)

        rows = list(
            detector_profile.build_records(detector_profile.join_by_uid(parsed), parsed)
        )
        dns_row = next(row for row in rows if row["uid"] == "C2")
        self.assertEqual(dns_row["dns"]["transaction_count"], 5)
        self.assertEqual(len(dns_row["dns_transactions"]), 5)
        self.assertEqual(
            [item["query"] for item in dns_row["dns_transactions"]],
            [f"query-{index}.example" for index in range(5)],
        )
        self.assertEqual(
            [item["source_ordinal"] for item in dns_row["dns_transactions"]],
            list(range(5)),
        )

    def test_detector_stdout_is_jsonl_and_window_block_is_explicit(self) -> None:
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            result = pipeline.run_pipeline(
                None,
                str(LOG_FIXTURE),
                "-",
                skip_zeek=True,
                feature_profile=pipeline.DETECTOR_FEATURE_PROFILE,
                emit_window=True,
            )
        rows = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual(len(rows), result.emitted)
        self.assertTrue(all("flow_rate" in row for row in rows))

    def test_window_and_unknown_profile_fail_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "requires --feature-profile detector-v2"):
            pipeline.run_pipeline(
                None,
                str(LOG_FIXTURE),
                str(self.root / "forbidden.jsonl"),
                skip_zeek=True,
                emit_window=True,
            )
        with self.assertRaisesRegex(SystemExit, "unsupported feature profile"):
            pipeline.run_pipeline(
                None,
                str(LOG_FIXTURE),
                str(self.root / "unknown.jsonl"),
                skip_zeek=True,
                feature_profile="unknown",
            )


if __name__ == "__main__":
    unittest.main()
