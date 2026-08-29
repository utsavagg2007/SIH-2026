"""Differential tests for the three windows made incremental in this pass.

The DNS tunnelling window, the encrypted-malware SNI window and the DGA
source correlation all used to rebuild their aggregates from every resident
observation on every event — O(n) per event, so a busy pair or a chatty
infected host cost O(n²) overall. Each now maintains its state incrementally.

That is only safe if the fast answer is the answer a full rescan would give,
so each section keeps a deliberately slow reference implementing the old
logic and compares after **every** add and expiry. The references live here,
in test code: a second implementation inside the package would be dead weight
that drifts, whereas here its only job is to disagree loudly.

Sequences are deterministic and deliberately include what breaks naive
bookkeeping: repeated values, absent optional fields, mixed ports and
protocols, duplicate timestamps, out-of-order arrival, exact window edges,
complete drain and refill.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

import pytest

from detection_core import (
    DGAConfig,
    DGADetector,
    DnsInfo,
    DnsTunnellingConfig,
    EncryptedMalwareConfig,
    EncryptedMalwareDetector,
    TlsInfo,
)
from detection_core.detectors.dns_tunnelling import (
    DnsObservation,
    DnsTunnellingDetector,
    _DnsWindow,
)
from detection_core.detectors.encrypted_malware import (
    TlsObservation,
    _TlsWindow,
    sni_entropy,
)

from .conftest import make_flow

SEED = 20260830


# ==========================================================================
# DNS tunnelling window
# ==========================================================================


def dns_reference(observations, signals, threshold):
    """The pre-change ``_aggregate`` body, over a plain list."""
    total = len(observations)
    if not total:
        return None
    suspicious = [s for s in signals if s >= threshold]
    txt_flags = [o.is_txt for o in observations if o.is_txt is not None]
    lengths = [o.query_length for o in observations if o.query_length is not None]
    entropies = [o.query_entropy for o in observations if o.query_entropy is not None]
    subs = [o.subdomain_entropy for o in observations if o.subdomain_entropy is not None]
    labels = [o.label_count for o in observations if o.label_count is not None]
    stamps = [o.timestamp for o in observations]
    txt_count = sum(1 for flag in txt_flags if flag)
    mean = lambda values: (sum(values) / len(values)) if values else None  # noqa: E731
    known_ports = {o.dst_port for o in observations if o.dst_port is not None}
    known_protos = {o.proto for o in observations if o.proto is not None}
    return {
        "observation_count": total,
        "suspicious_count": len(suspicious),
        "suspicious_ratio": len(suspicious) / total,
        "mean_signals": mean(suspicious),
        "txt_count": txt_count,
        "txt_ratio": (txt_count / len(txt_flags)) if txt_flags else None,
        "mean_query_length": mean(lengths),
        "max_query_length": max(lengths) if lengths else None,
        "mean_query_entropy": mean(entropies),
        "max_query_entropy": max(entropies) if entropies else None,
        "mean_subdomain_entropy": mean(subs),
        "mean_label_count": mean(labels),
        "max_label_count": max(labels) if labels else None,
        "total_orig_bytes": sum(o.orig_bytes for o in observations),
        "time_span": (min(stamps), max(stamps)),
        "dst_port": next(iter(known_ports)) if len(known_ports) == 1 else None,
        "protocol": next(iter(known_protos)) if len(known_protos) == 1 else None,
        "raw_query_count": sum(1 for o in observations if o.has_raw_query),
    }


def dns_fast(window):
    return {
        "observation_count": len(window),
        "suspicious_count": window.suspicious_count,
        "suspicious_ratio": window.suspicious_count / len(window) if len(window) else None,
        "mean_signals": window.mean_signals(),
        "txt_count": window.txt_count,
        "txt_ratio": window.txt_ratio(),
        "mean_query_length": window.mean_query_length(),
        "max_query_length": window.max_query_length(),
        # The alert publishes the exact mean; the incremental one exists
        # only for the O(1) decision path, which never reads it.
        "mean_query_entropy": window.exact_mean_query_entropy(),
        "max_query_entropy": window.max_query_entropy(),
        "mean_subdomain_entropy": window.exact_mean_subdomain_entropy(),
        "mean_label_count": window.mean_label_count(),
        "max_label_count": window.max_label_count(),
        "total_orig_bytes": window.total_orig_bytes,
        "time_span": window.time_span(),
        "dst_port": window.unanimous_dst_port(),
        "protocol": window.unanimous_proto(),
        "raw_query_count": window.raw_query_count,
    }


def dns_observation(timestamp, **over):
    payload = dict(
        query_length=60, query_entropy=4.5, subdomain_entropy=3.9,
        label_count=6, is_txt=True, orig_bytes=100, dst_port=53, proto="udp",
        has_raw_query=False,
    )
    payload.update(over)
    return DnsObservation(timestamp=timestamp, **payload)


def drive_dns(steps, window_seconds=300.0, threshold=2, max_observations=5000):
    """Feed observations into both, comparing after every one."""
    window = _DnsWindow(window_seconds, max_observations)
    resident: list[DnsObservation] = []
    signals: list[int] = []

    for index, (observation, signal) in enumerate(steps):
        window.observe(observation, signal, threshold)
        resident.append(observation)
        signals.append(signal)
        # The reference expiry loop, verbatim.
        cutoff = observation.timestamp - window_seconds
        while resident and resident[0].timestamp <= cutoff:
            resident.pop(0)
            signals.pop(0)
        while len(resident) > max_observations:
            resident.pop(0)
            signals.pop(0)

        assert dns_fast(window) == dns_reference(resident, signals, threshold), (
            f"DNS mismatch at step {index}"
        )
    return window, resident


@pytest.mark.parametrize("window_seconds", [1.0, 30.0, 300.0])
@pytest.mark.parametrize("run", range(3))
def test_dns_window_matches_a_full_rescan(window_seconds, run):
    rng = random.Random(SEED + run * 7 + int(window_seconds))
    steps = []
    timestamp = 1000.0
    for _ in range(300):
        timestamp += rng.choice([0.0, 0.0, 0.5, 2.0, 20.0])
        steps.append(
            (
                dns_observation(
                    timestamp,
                    query_length=rng.choice([None, 20, 60, 110]),
                    query_entropy=rng.choice([None, 2.5, 4.5, 4.9]),
                    subdomain_entropy=rng.choice([None, 0.0, 3.9]),
                    label_count=rng.choice([None, 2, 6, 9]),
                    is_txt=rng.choice([None, True, False]),
                    orig_bytes=rng.choice([0, 74, 500]),
                    dst_port=rng.choice([None, 53, 5353]),
                    proto=rng.choice([None, "udp", "tcp"]),
                    has_raw_query=rng.choice([True, False]),
                ),
                rng.randint(0, 5),
            )
        )
    drive_dns(steps, window_seconds=window_seconds)


def test_dns_window_handles_the_named_edge_cases():
    # duplicate timestamps, absent fields, mixed ports, mixed protocols
    steps = [
        (dns_observation(1000.0), 3),
        (dns_observation(1000.0, dst_port=5353), 3),
        (dns_observation(1000.0, proto="tcp", query_length=None), 1),
        (dns_observation(1001.0, is_txt=None, label_count=None), 0),
        (dns_observation(1002.0, has_raw_query=True), 5),
    ]
    window, resident = drive_dns(steps, window_seconds=10.0)

    assert window.unanimous_dst_port() is None  # 53 and 5353 both live
    assert window.unanimous_proto() is None
    assert window.raw_query_count == 1


def test_dns_window_expiry_boundary_and_drain():
    steps = [(dns_observation(1000.0 + i), 3) for i in range(5)]
    window, _ = drive_dns(steps, window_seconds=2.0)

    assert len(window) == 2  # half-open: exactly window_seconds old has gone

    window.expire(1_000_000.0)
    assert window.is_empty()
    assert window.time_span() is None
    assert window.max_query_length() is None
    assert window.txt_ratio() is None
    assert window.mean_signals() is None
    assert window.total_orig_bytes == 0


def test_dns_window_refills_after_a_drain():
    window = _DnsWindow(10.0, 5000)
    window.observe(dns_observation(1000.0), 3, 2)
    window.expire(1_000_000.0)
    window.observe(dns_observation(2_000_000.0, query_length=42), 4, 2)

    assert len(window) == 1
    assert window.max_query_length() == 42
    assert window.suspicious_count == 1


def test_dns_window_out_of_order_arrival_matches_the_reference():
    steps = [
        (dns_observation(1000.0), 3),
        (dns_observation(1050.0), 3),
        (dns_observation(1020.0), 3),  # late
    ]
    drive_dns(steps, window_seconds=600.0)


def test_dns_window_respects_the_observation_cap_exactly():
    """The cap must evict through the bookkeeping, not silently."""
    steps = [(dns_observation(1000.0 + i * 0.001, orig_bytes=i), 3) for i in range(30)]
    window, resident = drive_dns(steps, window_seconds=300.0, max_observations=10)

    assert len(window) == 10
    assert window.total_orig_bytes == sum(o.orig_bytes for o in resident)


def test_dns_window_state_drains_completely():
    window = _DnsWindow(1.0, 5000)
    for index in range(500):
        window.observe(
            dns_observation(1000.0 + index * 2.0, query_length=index, dst_port=index),
            3, 2,
        )
        assert len(window) == 1

    window.expire(9_999_999.0)

    for name in ("_dst_port_counts", "_proto_counts"):
        assert getattr(window, name) == {}, f"{name} retained entries"
    for name in ("_max_length", "_max_entropy", "_max_label",
                 "_min_timestamp", "_max_timestamp"):
        assert len(getattr(window, name)) == 0, f"{name} retained candidates"
    assert window._suspicious_count == 0
    assert window._orig_bytes_total == 0
    assert window._raw_query_count == 0


# ==========================================================================
# Encrypted-malware SNI window
# ==========================================================================


def tls_reference(observations, obsolete_versions):
    total = len(observations)
    if not total:
        return None
    lengths = [o.sni_length for o in observations if o.sni_length is not None]
    entropies = [o.sni_entropy for o in observations if o.sni_entropy is not None]
    versions = [o.version for o in observations if o.version is not None]
    obsolete = [v for v in versions if v in obsolete_versions]
    stamps = [o.timestamp for o in observations]
    mean = lambda values: (sum(values) / len(values)) if values else None  # noqa: E731
    return {
        "observation_count": total,
        "sni_available_count": sum(
            1 for o in observations
            if o.sni_length is not None and o.sni_entropy is not None
        ),
        "mean_sni_length": mean(lengths),
        "max_sni_length": max(lengths) if lengths else None,
        "mean_sni_entropy": mean(entropies),
        "max_sni_entropy": max(entropies) if entropies else None,
        "obsolete_version_count": len(obsolete),
        "obsolete_version_ratio": (len(obsolete) / len(versions)) if versions else None,
        "time_span": (min(stamps), max(stamps)),
    }


def tls_fast(window):
    versions = window.version_count
    obsolete = window.obsolete_version_count
    return {
        "observation_count": len(window),
        "sni_available_count": window.sni_available_count,
        "mean_sni_length": window.mean_sni_length(),
        "max_sni_length": window.max_sni_length(),
        "mean_sni_entropy": window.exact_mean_sni_entropy(),
        "max_sni_entropy": window.max_sni_entropy(),
        "obsolete_version_count": obsolete,
        "obsolete_version_ratio": (obsolete / versions) if versions else None,
        "time_span": window.time_span(),
    }


OBSOLETE = frozenset({"TLSv10", "TLSv11", "SSLv3"})


def tls_observation(timestamp, **over):
    payload = dict(sni_length=44, sni_entropy=4.7, server_name_available=True,
                   version="TLSv13", dst_port=443, proto="tcp")
    payload.update(over)
    return TlsObservation(timestamp=timestamp, **payload)


def drive_tls(steps, window_seconds=300.0, max_observations=5000):
    window = _TlsWindow(window_seconds, max_observations, OBSOLETE)
    resident: list[TlsObservation] = []

    for index, observation in enumerate(steps):
        suspicious = (
            observation.sni_length is not None
            and observation.sni_entropy is not None
            and observation.sni_length >= 38
            and observation.sni_entropy >= 4.2
        )
        window.observe(observation, suspicious, observation.version in OBSOLETE)
        resident.append(observation)
        cutoff = observation.timestamp - window_seconds
        while resident and resident[0].timestamp <= cutoff:
            resident.pop(0)
        while len(resident) > max_observations:
            resident.pop(0)

        assert tls_fast(window) == tls_reference(resident, OBSOLETE), (
            f"TLS mismatch at step {index}"
        )
        expected_suspicious = sum(
            1 for o in resident
            if o.sni_length is not None and o.sni_entropy is not None
            and o.sni_length >= 38 and o.sni_entropy >= 4.2
        )
        assert window.suspicious_count == expected_suspicious, f"step {index}"
    return window, resident


@pytest.mark.parametrize("window_seconds", [1.0, 30.0, 300.0])
@pytest.mark.parametrize("run", range(3))
def test_tls_window_matches_a_full_rescan(window_seconds, run):
    rng = random.Random(SEED + run * 11 + int(window_seconds))
    steps = []
    timestamp = 1000.0
    for _ in range(300):
        timestamp += rng.choice([0.0, 0.0, 0.5, 2.0, 20.0])
        steps.append(
            tls_observation(
                timestamp,
                sni_length=rng.choice([None, 12, 38, 44, 60]),
                sni_entropy=rng.choice([None, 3.0, 4.2, 4.7]),
                version=rng.choice([None, "TLSv13", "TLSv12", "TLSv10", "SSLv3"]),
            )
        )
    drive_tls(steps, window_seconds=window_seconds)


def test_tls_window_edge_cases_and_drain():
    steps = [
        tls_observation(1000.0),
        tls_observation(1000.0, sni_length=None, sni_entropy=None),
        tls_observation(1000.5, version=None),
        tls_observation(1001.0, version="SSLv3"),
    ]
    window, _ = drive_tls(steps, window_seconds=10.0)

    assert window.sni_available_count == 3
    assert window.obsolete_version_count == 1

    window.expire(1_000_000.0)
    assert window.is_empty()
    assert window.time_span() is None
    assert window.max_sni_length() is None
    assert window.max_sni_entropy() is None


def test_tls_window_out_of_order_and_cap():
    drive_tls(
        [tls_observation(1000.0), tls_observation(1050.0), tls_observation(1020.0)],
        window_seconds=600.0,
    )
    window, resident = drive_tls(
        [tls_observation(2000.0 + i * 0.001, sni_length=20 + i) for i in range(30)],
        window_seconds=300.0, max_observations=10,
    )
    assert len(window) == 10
    assert window.max_sni_length() == max(o.sni_length for o in resident)


def test_tls_window_state_drains_completely():
    window = _TlsWindow(1.0, 5000, OBSOLETE)
    for index in range(500):
        window.observe(
            tls_observation(1000.0 + index * 2.0, sni_length=index, sni_entropy=index / 10),
            True, False,
        )
        assert len(window) == 1

    window.expire(9_999_999.0)

    for name in ("_max_length", "_max_entropy",
                 "_min_timestamp", "_max_timestamp"):
        assert len(getattr(window, name)) == 0, f"{name} retained candidates"
    assert window._suspicious_count == 0
    assert window._version_count == 0
    assert window._obsolete_count == 0


# ==========================================================================
# DGA source correlation
# ==========================================================================


@dataclass(frozen=True)
class StubPrediction:
    domain: str
    normalized_domain: str
    label: int
    dga_score: float


class AlwaysPositive:
    is_fitted = True

    def predict_domain(self, domain):
        return StubPrediction(domain, domain, 1, 0.95)


def dga_flow(timestamp, query, src="10.0.0.7"):
    return make_flow(
        src_ip=src, dst_ip="10.0.0.53", dst_port=53, proto="udp",
        timestamp=timestamp, dns=DnsInfo(uid=f"C{timestamp}", query=query),
    )


def reference_expire(findings: dict, cutoff: float) -> dict:
    """The pre-change expiry: walk everything, drop what is old."""
    return {
        name: finding
        for name, finding in findings.items()
        if finding.timestamp > cutoff
    }


def test_dga_correlation_expiry_matches_a_full_scan():
    """The heap must leave exactly what a full scan would have left.

    Driven directly against the correlation structure, with a small domain
    pool so re-recording a live domain - the case that leaves a stale heap
    entry behind - happens constantly.
    """
    from detection_core.detectors.dga import _DomainFinding, _SourceCorrelation

    rng = random.Random(SEED + 3)
    correlation = _SourceCorrelation()
    mirror: dict = {}
    window = 100.0
    timestamp = 1000.0

    for step in range(500):
        # Occasionally step backwards: event time is only ever assumed to be
        # *approximately* ordered, and the heap must not care.
        timestamp += rng.choice([0.0, 0.5, 5.0, 40.0, -3.0])
        domain = f"kq3v9x2mzt7wp{rng.randint(0, 25):03d}.com"
        finding = _DomainFinding(
            timestamp=timestamp, domain=domain, normalized=domain,
            model_score=0.95, score=0.9, dst_ip="10.0.0.53",
            dst_port=53, proto="udp",
        )
        correlation.record(finding)
        mirror[domain] = finding

        cutoff = timestamp - window
        correlation.expire(cutoff)
        mirror = {n: f for n, f in mirror.items() if f.timestamp > cutoff}

        assert set(correlation.findings) == set(mirror), f"step {step}"
        assert {n: f.timestamp for n, f in correlation.findings.items()} == {
            n: f.timestamp for n, f in mirror.items()
        }, f"step {step}"

    # The heap must not accumulate stale entries without bound.
    assert len(correlation._expiry) <= 2 * len(correlation.findings) + 2


def test_dga_correlation_expires_an_out_of_order_arrival():
    """A deque would strand it; the heap does not.

    ``ccc`` arrives after ``bbb`` but is older than it. When the cutoff
    passes both, popping in *arrival* order would stop at ``bbb`` and leave
    ``ccc`` resident - silently inflating the distinct-domain count.
    """
    from detection_core.detectors.dga import _DomainFinding, _SourceCorrelation

    def finding(timestamp, name):
        return _DomainFinding(
            timestamp=timestamp, domain=name, normalized=name, model_score=0.95,
            score=0.9, dst_ip="10.0.0.53", dst_port=53, proto="udp",
        )

    correlation = _SourceCorrelation()
    correlation.record(finding(1000.0, "aaa.com"))
    correlation.record(finding(1010.0, "bbb.com"))
    correlation.record(finding(1005.0, "ccc.com"))  # late, and older than bbb
    assert set(correlation.findings) == {"aaa.com", "bbb.com", "ccc.com"}

    correlation.expire(1006.0)  # past aaa and ccc, not past bbb

    assert set(correlation.findings) == {"bbb.com"}, (
        "an out-of-order arrival was stranded behind a newer one"
    )


def test_dga_a_requeried_domain_keeps_its_newer_timestamp():
    """Re-recording supersedes; the stale heap entry must not evict it."""
    config = DGAConfig(cooldown_seconds=100.0)
    detector = DGADetector(model=AlwaysPositive(), config=config)

    detector.process(dga_flow(1000.0, "aaa.com"))
    # Past the per-domain cooldown, so it contributes again.
    detector.process(dga_flow(1150.0, "aaa.com"))
    correlation = detector._sources["10.0.0.7"]
    assert correlation.findings["aaa.com"].timestamp == 1150.0

    # The stale 1000.0 heap entry passes the cutoff here; the domain stays.
    detector.process(dga_flow(1200.0, "bbb.com"))

    assert "aaa.com" in correlation.findings
    assert correlation.findings["aaa.com"].timestamp == 1150.0


def test_dga_correlation_state_drains():
    detector = DGADetector(model=AlwaysPositive(), config=DGAConfig())
    for index in range(200):
        detector.process(dga_flow(1000.0 + index, f"gen{index:04d}.com"))

    correlation = detector._sources["10.0.0.7"]
    detector.process(dga_flow(1_000_000.0, "final.com"))

    assert set(correlation.findings) == {"final.com"}
    assert len(correlation._expiry) <= 2, "the expiry heap kept stale entries"

    detector.reset()
    assert detector._sources == {}
