"""The offline evaluation, benchmark and profiling harness.

These tests check *arithmetic and structure*, never performance. A minimum
flows/second assertion would fail on a loaded CI box and tell nobody anything
useful, so nothing here asserts a speed - only that a measurement was taken,
that its derived values follow from its counts, and that measuring changed
no detector.

Workloads are generated locally and deterministically. Nothing is downloaded
and no dataset is written outside ``tmp_path``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from detection_core import DGAConfig, ThreatClass, build_default_detectors
from detection_core.evaluation import (
    REAL,
    SYNTHETIC,
    benchmark_detectors,
    benchmark_jsonl,
    benign_flows,
    environment,
    evaluate_benign,
    evaluate_benign_jsonl,
    mixed_flows,
    percentile,
    profile_detectors,
    sample_latency,
    write_jsonl,
)
from detection_core.evaluation.workloads import stress_flows

# The fitted-in-tmp model, reused rather than re-derived.
from .test_pipeline_runner import dga_model_path  # noqa: F401 - fixture

RULE_DETECTORS = [
    "port_scan",
    "ddos",
    "c2_beaconing",
    "dns_tunnelling",
    "data_exfiltration",
    "encrypted_malware",
]


@pytest.fixture(scope="module")
def benign():
    """A small benign workload, generated once."""
    return benign_flows(600)


# --------------------------------------------------------------------------
# A. Benign evaluation
# --------------------------------------------------------------------------


def test_the_benign_workload_produces_no_alerts(benign):
    """The premise of every benign number: the fixture really is quiet.

    If a detector ever fires here, this fixture stopped being benign and the
    numbers derived from it stop meaning anything - so it is asserted, not
    assumed.
    """
    evaluation = evaluate_benign(benign, input_label="benign(600)")

    assert evaluation.total_alerts == 0
    assert evaluation.total_flows == 600
    assert evaluation.by_threat_class == {}
    assert evaluation.detector_errors == 0


def test_alert_counts_are_attributed_to_the_right_detector():
    """A workload with a known scan must charge those alerts to port_scan."""
    evaluation = evaluate_benign(
        mixed_flows(2000),
        input_label="mixed(2000)",
        notes=["not a benign workload - contains deliberate scan bursts"],
    )

    assert evaluation.total_alerts > 0
    assert evaluation.by_detector["port_scan"].alerts_emitted > 0
    # Every alert is accounted for exactly once.
    assert (
        sum(stats.alerts_emitted for stats in evaluation.by_detector.values())
        == evaluation.total_alerts
    )


def test_threat_class_counts_match_the_detector_counts():
    evaluation = evaluate_benign(mixed_flows(2000), input_label="mixed(2000)")

    assert sum(evaluation.by_threat_class.values()) == evaluation.total_alerts
    assert evaluation.by_threat_class[ThreatClass.PORT_SCAN.value] == (
        evaluation.by_detector["port_scan"].alerts_emitted
    )
    for name in evaluation.by_threat_class:
        assert name in {threat.value for threat in ThreatClass}


def test_alerts_per_1000_flows_is_arithmetically_correct():
    evaluation = evaluate_benign(mixed_flows(2000), input_label="mixed(2000)")

    assert evaluation.alerts_per_1000_flows == (
        evaluation.total_alerts / evaluation.total_flows * 1000
    )
    for stats in evaluation.by_detector.values():
        assert stats.alerts_per_1000_flows == (
            stats.alerts_emitted / stats.flows_processed * 1000
        )


def test_six_detectors_evaluate_without_any_dga_dependency(benign):
    """A core-only install must be able to run this."""
    evaluation = evaluate_benign(benign, input_label="benign(600)")

    assert evaluation.detectors == RULE_DETECTORS
    assert "dga_domain" not in evaluation.by_detector


def test_dga_joins_only_when_a_model_is_explicitly_supplied(benign, dga_model_path):
    with_dga = evaluate_benign(
        benign, input_label="benign(600)", dga_model_path=dga_model_path
    )

    assert with_dga.detectors == RULE_DETECTORS + ["dga_domain"]
    assert with_dga.by_detector["dga_domain"].threat_class == "dga_domain"
    # No model, no stand-in: the detector is simply absent.
    assert "dga_domain" not in evaluate_benign(benign, input_label="x").by_detector


def test_synthetic_input_is_labelled_synthetic(benign):
    evaluation = evaluate_benign(benign, input_label="benign(600)")

    assert evaluation.data_source_type == SYNTHETIC
    assert evaluation.to_dict()["data_source_type"] == "synthetic"


def test_jsonl_input_is_labelled_by_the_caller(tmp_path, benign):
    path = tmp_path / "capture.jsonl"
    write_jsonl(benign, path)

    real = evaluate_benign_jsonl(path)
    assert real.data_source_type == REAL
    assert real.input_label == str(path)

    relabelled = evaluate_benign_jsonl(path, data_source_type=SYNTHETIC)
    assert relabelled.data_source_type == SYNTHETIC


def test_an_unknown_data_source_label_is_rejected(benign):
    with pytest.raises(ValueError, match="data_source_type"):
        evaluate_benign(benign, input_label="x", data_source_type="probably_benign")


def test_empty_input_is_handled_without_dividing_by_zero():
    evaluation = evaluate_benign([], input_label="empty")

    assert evaluation.total_flows == 0
    assert evaluation.total_alerts == 0
    assert evaluation.alerts_per_1000_flows == 0.0
    for stats in evaluation.by_detector.values():
        assert stats.alerts_per_1000_flows == 0.0


def test_the_benign_report_is_json_serializable(benign):
    payload = evaluate_benign(benign, input_label="benign(600)").to_dict()

    assert json.loads(json.dumps(payload)) == payload
    for key in (
        "input_label", "data_source_type", "total_flows", "total_alerts",
        "alerts_per_1000_flows", "by_detector", "by_threat_class",
    ):
        assert key in payload


def test_false_positive_alerts_is_only_an_alias(benign):
    """It names an assumption about the input, not a measurement."""
    evaluation = evaluate_benign(benign, input_label="benign(600)")

    assert evaluation.false_positive_alerts == evaluation.total_alerts


# --------------------------------------------------------------------------
# B. Throughput and latency
# --------------------------------------------------------------------------


def test_throughput_counts_every_generated_flow(benign):
    result = benchmark_detectors(benign)

    assert result.flows_processed == len(benign)
    assert result.mode == "detectors_only"
    assert result.detectors == RULE_DETECTORS


def test_alerts_emitted_matches_an_independent_count():
    flows = mixed_flows(2000)
    result = benchmark_detectors(flows, workload="mixed")

    assert result.alerts_emitted == evaluate_benign(
        flows, input_label="mixed(2000)"
    ).total_alerts


def test_elapsed_time_is_positive_and_derived_values_follow(benign):
    result = benchmark_detectors(benign)

    assert result.elapsed_seconds > 0
    assert result.flows_per_second == result.flows_processed / result.elapsed_seconds
    assert result.mean_seconds_per_flow == result.elapsed_seconds / result.flows_processed
    assert result.to_dict()["mean_microseconds_per_flow"] == pytest.approx(
        result.mean_seconds_per_flow * 1e6
    )


def test_derived_values_are_zero_rather_than_undefined():
    result = benchmark_detectors([], workload="empty")

    assert result.flows_processed == 0
    assert result.flows_per_second == 0.0
    assert result.mean_seconds_per_flow == 0.0


def test_a_lazy_source_is_refused(benign):
    """A generator would be built inside the timer and measured as detection."""
    with pytest.raises(TypeError, match="materialized list"):
        benchmark_detectors(flow for flow in benign)


def test_latency_percentiles_are_ordered(benign):
    latency = sample_latency(benign)

    assert latency.samples == len(benign)
    assert latency.p50_ns <= latency.p95_ns <= latency.p99_ns <= latency.max_ns
    assert latency.mean_ns > 0
    assert latency.mode == "latency_sampling"


def test_the_percentile_helper_uses_nearest_rank():
    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]

    assert percentile(values, 0.50) == 5.0
    assert percentile(values, 0.95) == 10.0
    assert percentile(values, 1.0) == 10.0
    # Every reported value is a measurement that really happened.
    assert percentile(values, 0.51) in values
    with pytest.raises(ValueError):
        percentile([], 0.5)


def test_latency_is_a_separate_run_from_throughput(benign):
    """Both must say so, so the two numbers are never quoted as one."""
    throughput = benchmark_detectors(benign)
    latency = sample_latency(benign)

    assert any("no i/o" in note for note in throughput.notes)
    assert any("separate run" in note for note in latency.notes)


def test_detector_only_mode_touches_no_filesystem(tmp_path, monkeypatch, benign):
    """MODE 1 is in-memory: nothing may be read or written while it runs."""
    monkeypatch.chdir(tmp_path)

    benchmark_detectors(benign)

    assert list(tmp_path.iterdir()) == []


def test_the_jsonl_benchmark_reads_only_temporary_data(tmp_path, benign):
    path = tmp_path / "workload.jsonl"
    written = write_jsonl(benign, path)

    result = benchmark_jsonl(path)

    assert written == len(benign)
    assert result.mode == "jsonl_pipeline"
    assert result.flows_processed == len(benign)
    assert path.parent == tmp_path


def test_the_generator_is_deterministic():
    first, second = benign_flows(300), benign_flows(300)

    assert [flow.flow_id for flow in first] == [flow.flow_id for flow in second]
    assert [flow.timestamp for flow in first] == [flow.timestamp for flow in second]
    # A prefix of a longer run is the same run.
    assert [f.flow_id for f in benign_flows(50)] == [f.flow_id for f in first[:50]]


def test_event_time_never_goes_backwards():
    """Rolling windows assume approximately non-decreasing event time."""
    for flows in (benign_flows(400), mixed_flows(1500)):
        timestamps = [flow.timestamp for flow in flows]
        assert timestamps == sorted(timestamps)


def test_the_environment_is_recorded_without_network_access():
    report = environment()

    for key in ("python", "platform", "machine", "cpu_count"):
        assert key in report
    assert json.loads(json.dumps(report)) == report


# --------------------------------------------------------------------------
# C. Profiling
# --------------------------------------------------------------------------


def test_profiling_completes_and_ranks_functions(benign):
    report = profile_detectors(benign, top=8)

    assert report.flows_processed == len(benign)
    assert report.profiled_seconds > 0
    assert len(report.by_cumulative) == 8
    assert len(report.by_total) == 8


def test_profile_entries_are_ordered_and_serializable(benign):
    report = profile_detectors(benign, top=6)

    cumulative = [entry.cumulative_seconds for entry in report.by_cumulative]
    assert cumulative == sorted(cumulative, reverse=True)
    total = [entry.total_seconds for entry in report.by_total]
    assert total == sorted(total, reverse=True)
    payload = report.to_dict()
    assert json.loads(json.dumps(payload)) == payload


def test_profiling_does_not_mutate_detector_configuration(benign):
    """Measuring must leave the detectors exactly as they ship."""
    before = {d.name: d.config for d in build_default_detectors()}

    profile_detectors(benign, top=5)

    after = {d.name: d.config for d in build_default_detectors()}
    assert before == after


def test_the_stress_shapes_are_generated_and_non_alerting():
    """They measure bookkeeping cost, so they must not build alerts."""
    for shape in ("hot_key", "many_keys"):
        flows = stress_flows(200, shape=shape)
        assert len(flows) == 200
        assert evaluate_benign(flows, input_label=shape).total_alerts == 0

    with pytest.raises(ValueError, match="shape"):
        stress_flows(10, shape="not_a_shape")


# --------------------------------------------------------------------------
# Preservation: measuring changed nothing
# --------------------------------------------------------------------------


def test_detector_configs_are_untouched():
    from detection_core import (
        C2BeaconingConfig,
        DDoSConfig,
        DataExfiltrationConfig,
        DnsTunnellingConfig,
        EncryptedMalwareConfig,
        PortScanConfig,
    )

    assert PortScanConfig().min_unique_ports == 15
    assert PortScanConfig().min_unique_hosts == 20
    assert DDoSConfig().min_unique_sources == 50
    assert DDoSConfig().min_flows == 200
    assert C2BeaconingConfig().min_observations == 6
    assert C2BeaconingConfig().max_interval_cv == 0.20
    assert DnsTunnellingConfig().min_dns_observations == 20
    assert DataExfiltrationConfig().min_flows == 10
    assert EncryptedMalwareConfig().min_tls_observations == 6


def test_the_dga_threshold_is_still_075():
    assert DGAConfig().score_threshold == 0.75


def test_the_threat_alert_contract_is_untouched():
    from detection_core.schemas import ThreatAlert

    from .conftest import make_alert

    wire = make_alert().to_wire()
    assert wire["schema_version"] == "1.1"
    assert len(wire) == 20
    assert ThreatAlert.model_fields["schema_version"].default == "1.1"


def test_evaluation_does_not_import_the_ml_extra():
    """Importing the harness must stay as cheap as importing the core."""
    import subprocess
    import sys

    script = (
        "import sys\n"
        "class B:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] in {'sklearn', 'joblib', 'numpy', 'scipy'}:\n"
        "            raise ImportError('blocked: ' + name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, B())\n"
        "from detection_core.evaluation import evaluate_benign, benign_flows\n"
        "e = evaluate_benign(benign_flows(50), input_label='t')\n"
        "assert e.total_flows == 50 and len(e.detectors) == 6, e.detectors\n"
        "print('ok')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("ok")
