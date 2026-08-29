"""Generate replayable v1.1 alert captures and their ground-truth manifests.

Build Plan layer 0: "A fixture file of a few hundred synthetic flow records and
a few dozen synthetic alerts exists in the repository.  The dashboard developer
can build a full UI against those fixtures without any other layer existing."

Three captures are produced:

``demo_scenario.jsonl``
    A ten-minute narrative on a small network.  One host is scanned, then
    beacons, then exfiltrates - which is what makes the incident ribbon show a
    three-stage kill chain rather than three unrelated alerts.  Every threat
    class appears at least once.

``beacon_hour.jsonl``
    Sixty beacon check-ins from one tuple.  Exists to demonstrate the
    deduplication requirement literally: the Build Plan's completion test for
    layer 5 is "a one-hour replay containing a persistent beacon produces one
    incident with an occurrence count, not sixty alerts."

``flood.jsonl``
    Two thousand DDoS and port-scan alerts across many sources, for the
    interface stress test the frontend spec asks for in week one.

Everything here is *synthetic alert output*, not synthetic traffic.  It stands
in for the detection layer while it is being built and is replaced by real
detector output with no change anywhere downstream.

Run::

    python tools/make_fixtures.py
"""

from __future__ import annotations

import argparse
import json
import math
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

RNG = random.Random(20260829)  # fixed seed: replays must be reproducible

BASE = datetime(2026, 8, 28, 23, 30, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def alert(
    *,
    offset_s: float,
    duration_s: float,
    detect_delay_s: float,
    scope: str,
    threat_class: str,
    severity: str,
    score: float,
    score_type: str,
    detector: str,
    evidence: dict[str, Any],
    mitre: list[str],
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    protocol: str | None = None,
    flow_id: str | None = None,
    detector_version: str = "1.0.0",
) -> dict[str, Any]:
    start = BASE + timedelta(seconds=offset_s)
    end = start + timedelta(seconds=duration_s)
    detected = end + timedelta(seconds=detect_delay_s)
    return {
        "alert_id": str(uuid.UUID(int=RNG.getrandbits(128), version=4)),
        "schema_version": "1.1",
        "event_start": iso(start),
        "event_end": iso(end),
        "detected_at": iso(detected),
        "event_scope": scope,
        "flow_id": flow_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "threat_class": threat_class,
        "severity": severity,
        "score": round(score, 4),
        "score_type": score_type,
        "evidence": evidence,
        "detector": detector,
        "detector_version": detector_version,
        "mitre_techniques": mitre,
        "incident_id": None,
    }


def flow_id(src: str, dst: str, port: int, proto: str, offset: float) -> str:
    """Zeek-style flow id, matching the ingestion core's features.jsonl format."""
    return f"{src}:{dst}:{port}:{proto}:{(BASE.timestamp() + offset):.3f}"


# ---------------------------------------------------------------------------
# The demo narrative
# ---------------------------------------------------------------------------

VICTIM = "10.4.2.19"
SCANNER = "10.4.2.77"
EXFIL_HOST = "10.4.2.22"
DNS_HOST = "10.4.2.31"
C2 = "185.62.11.4"
DNS_AUTH = "203.0.113.9"
EXFIL_DST = "198.51.100.14"
WEB_TARGET = "10.4.0.80"


def _beacon_evidence(count: int, interval: float, jitter_pct: float) -> dict:
    """Beacon evidence including the observed timestamp series.

    Shipping ``timestamps`` is what lets the backend draw the comb from real
    observations rather than reconstructing it from summary statistics - see
    the provenance discussion in app/projection/visuals.py.  Real detectors
    should do the same.
    """
    ts0 = BASE.timestamp() + 120
    stamps, t = [], ts0
    for _ in range(count):
        stamps.append(round(t, 3))
        t += interval * (1 + RNG.uniform(-jitter_pct, jitter_pct) / 100.0)
    intervals = [b - a for a, b in zip(stamps, stamps[1:])]
    mean = sum(intervals) / len(intervals)
    var = sum((i - mean) ** 2 for i in intervals) / len(intervals)
    sd = math.sqrt(var)
    return {
        "connection_count": count,
        "observed_periods": count,
        "mean_interval_sec": round(mean, 3),
        "interval_stddev_sec": round(sd, 3),
        "interval_cv": round(sd / mean, 4),
        "jitter_pct": round(jitter_pct, 2),
        "periodicity_score": round(max(0.0, 1.0 - (sd / mean) * 4), 4),
        "autocorrelation_peak": round(RNG.uniform(0.82, 0.96), 3),
        "payload_size_cv": round(RNG.uniform(0.01, 0.06), 4),
        "destination_repetition": 1.0,
        "timestamps": stamps,
    }


def _scan_evidence(ports: int, hosts: int, duration: float) -> dict:
    port_list = sorted(RNG.sample(range(1, 9000), min(ports, 400)))
    return {
        "unique_dst_ports": ports,
        "unique_dst_ips": hosts,
        "connection_attempts": ports * hosts // 4,
        "rejected_connections": int(ports * hosts * 0.24),
        "syn_no_ack_ratio": 0.99,
        "window_seconds": duration,
        "port_series": port_list,
    }


def _ddos_evidence(window: int) -> dict:
    # Rate climbing while source entropy jumps out of band: the spoofed-flood
    # signature the frontend's entropy-against-rate visual is built to show.
    rate = [round(300 * math.exp(i / 6.0) + RNG.uniform(-40, 40), 1) for i in range(window)]
    entropy = [round(3.1 + (i / window) * 6.4 + RNG.uniform(-0.2, 0.2), 3) for i in range(window)]
    return {
        "flows_per_sec": round(max(rate), 1),
        "bytes_per_sec": 124_000_000.0,
        "packets_per_sec": 412_000.0,
        "source_ip_entropy": entropy[-1],
        "unique_sources": 5200,
        "syn_no_ack_ratio": 0.98,
        "window_seconds": window,
        "series_start": BASE.timestamp() + 400,
        "series_step_sec": 1.0,
        "rate_series": rate,
        "entropy_series": entropy,
        "baseline_band": [3.0, 4.2],
    }


def _dga_evidence(domain: str) -> dict:
    return {
        "query": domain,
        "query_entropy": 3.91,
        "query_length": len(domain),
        "subdomain_entropy": 3.88,
        "ngram_score": 0.021,
        "digit_ratio": round(sum(c.isdigit() for c in domain) / len(domain), 3),
        "consonant_run": 4,
        "label_count": domain.count(".") + 1,
        "nxdomain_count": 47,
        "nxdomain_rate": 0.83,
        "nxdomain_series": [0, 1, 3, 9, 14, 22, 31, 47],
    }


def _tunnel_evidence() -> dict:
    subs = [
        "".join(RNG.choice("abcdef0123456789") for _ in range(RNG.randint(40, 62)))
        for _ in range(120)
    ]
    return {
        "parent_domain": "sync-cdn-edge.net",
        "query": f"{subs[0]}.sync-cdn-edge.net",
        "query_length": 187,
        "query_entropy": 4.62,
        "subdomain_entropy": 4.71,
        "unique_subdomains": 412,
        "queries_per_sec": 42.0,
        "record_type": "TXT",
        "txt_ratio": 0.94,
        "subdomains": subs,
    }


def _tls_evidence() -> dict:
    # Log-scaled baseline JA3 frequency distribution, with this connection far
    # out in the tail (frontend spec 5.2, EC).
    hist = [4210, 3180, 1902, 1140, 702, 431, 264, 162, 99, 61, 37, 23, 14, 8, 5, 3, 2, 1]
    return {
        "ja3": "e7d705a3286e19ea42f587b344ee6865",
        "ja3s": "f4febc55ea12b31ae17cfb7e614afda8",
        "ja3_frequency": 2,
        "ja3_rarity": 0.994,
        "ja3_novel_for_host": True,
        "ja3_histogram": hist,
        "ja3_host_history": [
            "cd08e31494f9531f560d64c695473da9",
            "cd08e31494f9531f560d64c695473da9",
            "e7d705a3286e19ea42f587b344ee6865",
        ],
        "matched_family": "Cobalt Strike",
        "ssl_version": "TLSv13",
        "sni": "cdn-update-service.net",
        "sni_entropy": 3.42,
        "self_signed": True,
        "cert_validity_days": 7,
        "mean_pkt_size_orig": 412,
        "mean_pkt_size_resp": 1180,
    }


def _exfil_evidence() -> dict:
    baseline = [round(RNG.uniform(1.2e6, 4.8e6), 0) for _ in range(46)]
    spike = [8.9e7, 2.4e8, 5.12e8]
    return {
        "outbound_bytes": 512_000_000,
        "inbound_bytes": 10_800_000,
        "out_in_byte_ratio": 47.4,
        "baseline_ratio": 1.2,
        "baseline_outbound_bytes": 3_100_000,
        "robust_z_score": 11.8,
        "anomaly_score": 0.91,
        "destination_rarity": 0.97,
        "destination_novel": True,
        "time_of_day_deviation": 0.88,
        "transfer_duration_sec": 150.0,
        "outbound_series": baseline + spike,
        "baseline_band": [1.2e6, 4.8e6],
    }


def demo_scenario() -> tuple[list[dict], dict]:
    """Ten minutes on a small network, with one host telling a full story."""
    out: list[dict] = []

    # t+0:30  reconnaissance - the scanner sweeps the /16
    out.append(
        alert(
            offset_s=30,
            duration_s=12.4,
            detect_delay_s=0.31,
            scope="source_host",
            threat_class="port_scan",
            severity="high",
            score=0.90,
            score_type="rule_score",
            detector="portscan_detector",
            src_ip=SCANNER,
            protocol="tcp",
            evidence=_scan_evidence(1024, 254, 12.4),
            mitre=["T1046"],
        )
    )
    # The same scanner also touches the eventual victim, which is what ties it
    # into that host's incident.
    out.append(
        alert(
            offset_s=44,
            duration_s=8.1,
            detect_delay_s=0.22,
            scope="source_host",
            threat_class="port_scan",
            severity="medium",
            score=0.71,
            score_type="rule_score",
            detector="portscan_detector",
            src_ip=VICTIM,
            protocol="tcp",
            evidence=_scan_evidence(312, 18, 8.1),
            mitre=["T1046"],
        )
    )

    # t+2:00  DGA lookups from a third host
    for i, domain in enumerate(
        ["x7k2p9qz3v1m.com", "vn4rjq8bkt2w.net", "zqm3xp7fdh9c.org"]
    ):
        out.append(
            alert(
                offset_s=120 + i * 9,
                duration_s=0.0,
                detect_delay_s=0.11,
                scope="flow",
                threat_class="dga_domain",
                severity="high",
                score=0.94 - i * 0.03,
                score_type="calibrated_model",
                detector="dga_classifier",
                src_ip=DNS_HOST,
                dst_ip="8.8.8.8",
                dst_port=53,
                protocol="udp",
                flow_id=flow_id(DNS_HOST, "8.8.8.8", 53, "udp", 120 + i * 9),
                evidence=_dga_evidence(domain),
                mitre=["T1568.002"],
                detector_version="1.2.0",
            )
        )

    # t+2:30  C2 beaconing from the victim - the middle of the kill chain
    out.append(
        alert(
            offset_s=150,
            duration_s=600,
            detect_delay_s=0.25,
            scope="host_pair",
            threat_class="c2_beaconing",
            severity="high",
            score=0.91,
            score_type="rule_score",
            detector="beacon_periodicity",
            src_ip=VICTIM,
            dst_ip=C2,
            dst_port=443,
            protocol="tcp",
            evidence=_beacon_evidence(count=42, interval=60.0, jitter_pct=4.1),
            mitre=["T1071"],
            detector_version="0.3.1",
        )
    )

    # t+3:20  the same session, seen by the TLS metadata model
    out.append(
        alert(
            offset_s=200,
            duration_s=4.2,
            detect_delay_s=0.09,
            scope="flow",
            threat_class="encrypted_malware",
            severity="critical",
            score=0.97,
            score_type="signature_match",
            detector="ja3_matcher",
            src_ip=VICTIM,
            dst_ip=C2,
            dst_port=443,
            protocol="tcp",
            flow_id=flow_id(VICTIM, C2, 443, "tcp", 200),
            evidence=_tls_evidence(),
            mitre=["T1071.001"],
        )
    )

    # t+4:30  DNS tunnelling from another host
    out.append(
        alert(
            offset_s=270,
            duration_s=13.0,
            detect_delay_s=0.18,
            scope="host_pair",
            threat_class="dns_tunnelling",
            severity="high",
            score=0.88,
            score_type="rule_score",
            detector="dns_tunnel_detector",
            src_ip=DNS_HOST,
            dst_ip=DNS_AUTH,
            dst_port=53,
            protocol="udp",
            evidence=_tunnel_evidence(),
            mitre=["T1071.004"],
        )
    )

    # t+6:40  volumetric flood against the web tier
    out.append(
        alert(
            offset_s=400,
            duration_s=5.0,
            detect_delay_s=0.25,
            scope="destination_host",
            threat_class="ddos",
            severity="critical",
            score=0.92,
            score_type="rule_score",
            detector="ddos_detector",
            dst_ip=WEB_TARGET,
            dst_port=80,
            protocol="tcp",
            evidence=_ddos_evidence(18),
            mitre=["T1498"],
        )
    )

    # t+7:30  UDP amplification, folded into the ddos class per the frozen enum
    out.append(
        alert(
            offset_s=450,
            duration_s=6.0,
            detect_delay_s=0.2,
            scope="destination_host",
            threat_class="ddos",
            severity="high",
            score=0.86,
            score_type="rule_score",
            detector="amplification_detector",
            dst_ip=WEB_TARGET,
            dst_port=53,
            protocol="udp",
            evidence={
                "flows_per_sec": 2100.0,
                "bytes_per_sec": 88_000_000.0,
                "amplification_factor": 54.2,
                "reflector_port": 53,
                "unique_sources": 180,
                "source_ip_entropy": 2.1,
                "window_seconds": 6,
            },
            mitre=["T1498.002"],
        )
    )

    # t+8:30  exfiltration from the victim - the end of the kill chain
    out.append(
        alert(
            offset_s=510,
            duration_s=150,
            detect_delay_s=0.2,
            scope="host_pair",
            threat_class="data_exfiltration",
            severity="high",
            score=0.91,
            score_type="anomaly_score",
            detector="exfil_anomaly",
            src_ip=VICTIM,
            dst_ip=EXFIL_DST,
            dst_port=443,
            protocol="tcp",
            evidence=_exfil_evidence(),
            mitre=["T1048"],
            detector_version="0.9.2",
        )
    )

    # A second, unrelated exfiltration so the Incidents view has more than one
    # story on it.
    out.append(
        alert(
            offset_s=540,
            duration_s=95,
            detect_delay_s=0.24,
            scope="host_pair",
            threat_class="data_exfiltration",
            severity="medium",
            score=0.68,
            score_type="anomaly_score",
            detector="exfil_anomaly",
            src_ip=EXFIL_HOST,
            dst_ip=EXFIL_DST,
            dst_port=443,
            protocol="tcp",
            evidence={
                "outbound_bytes": 61_000_000,
                "inbound_bytes": 9_400_000,
                "out_in_byte_ratio": 6.5,
                "baseline_ratio": 1.4,
                "robust_z_score": 3.9,
                "anomaly_score": 0.68,
                "destination_rarity": 0.42,
                "destination_novel": False,
                "transfer_duration_sec": 95.0,
            },
            mitre=["T1048"],
            detector_version="0.9.2",
        )
    )

    manifest = {
        "capture": "demo_scenario.jsonl",
        "description": (
            "Ten-minute narrative. 10.4.2.19 is scanned, beacons to 185.62.11.4 "
            "over TLS, then exfiltrates to 198.51.100.14 - one host, three "
            "kill-chain stages, one incident."
        ),
        "generated_by": "tools/make_fixtures.py",
        "seed": 20260829,
        "duration_s": 700,
        "ground_truth": [
            {"at_s": 30, "threat_class": "port_scan", "src": SCANNER},
            {"at_s": 44, "threat_class": "port_scan", "src": VICTIM},
            {"at_s": 120, "threat_class": "dga_domain", "src": DNS_HOST},
            {"at_s": 150, "threat_class": "c2_beaconing", "src": VICTIM, "dst": C2},
            {"at_s": 200, "threat_class": "encrypted_malware", "src": VICTIM},
            {"at_s": 270, "threat_class": "dns_tunnelling", "src": DNS_HOST},
            {"at_s": 400, "threat_class": "ddos", "dst": WEB_TARGET},
            {"at_s": 450, "threat_class": "ddos", "dst": WEB_TARGET, "note": "amplification"},
            {"at_s": 510, "threat_class": "data_exfiltration", "src": VICTIM},
            {"at_s": 540, "threat_class": "data_exfiltration", "src": EXFIL_HOST},
        ],
        "expected_incidents": [
            {
                "pivot_host": VICTIM,
                "stages": ["recon", "c2", "exfil"],
                "note": "should escalate on stage count",
            }
        ],
    }
    return out, manifest


def beacon_hour() -> tuple[list[dict], dict]:
    """Sixty check-ins from one tuple, one minute apart.

    The completion test for Build Plan layer 5: this must produce one alert with
    an occurrence count of 60, not sixty rows.
    """
    out = []
    for i in range(60):
        out.append(
            alert(
                offset_s=i * 60,
                duration_s=1.2,
                detect_delay_s=0.2,
                scope="host_pair",
                threat_class="c2_beaconing",
                severity="high",
                score=0.87 + RNG.uniform(-0.03, 0.05),
                score_type="rule_score",
                detector="beacon_periodicity",
                src_ip=VICTIM,
                dst_ip=C2,
                dst_port=443,
                protocol="tcp",
                evidence=_beacon_evidence(
                    count=min(i + 2, 60), interval=60.0, jitter_pct=3.8
                ),
                mitre=["T1071"],
                detector_version="0.3.1",
            )
        )
    manifest = {
        "capture": "beacon_hour.jsonl",
        "description": (
            "Sixty beacon check-ins from one (src, dst, dport) tuple. Tests the "
            "deduplication requirement: expect ONE alert with occurrences=60."
        ),
        "generated_by": "tools/make_fixtures.py",
        "duration_s": 3600,
        "expected_result": {
            "alerts_created": 1,
            "alerts_deduplicated": 59,
            "occurrences": 60,
        },
    }
    return out, manifest


def flood(count: int = 2000) -> tuple[list[dict], dict]:
    """A dense burst, for the interface stress test (frontend spec 8.2)."""
    out = []
    targets = [f"10.4.0.{i}" for i in range(10, 40)]
    for i in range(count):
        t = i * 0.05
        if i % 3 == 0:
            src = f"{RNG.randint(11,223)}.{RNG.randint(0,255)}.{RNG.randint(0,255)}.{RNG.randint(1,254)}"
            out.append(
                alert(
                    offset_s=t,
                    duration_s=1.0,
                    detect_delay_s=RNG.uniform(0.05, 0.4),
                    scope="source_host",
                    threat_class="port_scan",
                    severity=RNG.choice(["medium", "high", "high", "critical"]),
                    score=RNG.uniform(0.62, 0.98),
                    score_type="rule_score",
                    detector="portscan_detector",
                    src_ip=src,
                    protocol="tcp",
                    evidence=_scan_evidence(
                        RNG.randint(80, 1400), RNG.randint(4, 200), 1.0
                    ),
                    mitre=["T1046"],
                )
            )
        else:
            out.append(
                alert(
                    offset_s=t,
                    duration_s=1.0,
                    detect_delay_s=RNG.uniform(0.05, 0.4),
                    scope="destination_host",
                    threat_class="ddos",
                    severity=RNG.choice(["high", "critical", "critical"]),
                    score=RNG.uniform(0.7, 0.99),
                    score_type="rule_score",
                    detector="ddos_detector",
                    dst_ip=RNG.choice(targets),
                    dst_port=RNG.choice([80, 443, 53, 123]),
                    protocol=RNG.choice(["tcp", "udp"]),
                    evidence={
                        "flows_per_sec": RNG.uniform(2000, 12000),
                        "bytes_per_sec": RNG.uniform(4e7, 2.4e8),
                        "source_ip_entropy": RNG.uniform(5.5, 11.2),
                        "unique_sources": RNG.randint(400, 9000),
                        "syn_no_ack_ratio": RNG.uniform(0.85, 0.995),
                        "window_seconds": 1,
                    },
                    mitre=["T1498"],
                )
            )
    manifest = {
        "capture": "flood.jsonl",
        "description": (
            f"{count} alerts across many sources and targets. Replay with "
            "max_rate=500 to confirm the dashboard holds 60fps under flood "
            "(frontend spec 8.2)."
        ),
        "generated_by": "tools/make_fixtures.py",
        "duration_s": count * 0.05,
        "suggested_replay": {"speed": 1.0, "max_rate": 500},
    }
    return out, manifest


def write(path: Path, alerts: list[dict], manifest: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(json.dumps(a, separators=(",", ":")) + "\n")
    manifest_path = path.with_suffix(".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"  {path.name:24s} {len(alerts):5d} alerts  + {manifest_path.name}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-o", "--out", default="fixtures", help="output directory")
    ap.add_argument("--flood-size", type=int, default=2000)
    args = ap.parse_args()

    out = Path(args.out)
    print(f"writing fixtures to {out.resolve()}")

    demo, demo_manifest = demo_scenario()
    write(out / "demo_scenario.jsonl", demo, demo_manifest)

    beacon, beacon_manifest = beacon_hour()
    write(out / "beacon_hour.jsonl", beacon, beacon_manifest)

    fl, fl_manifest = flood(args.flood_size)
    write(out / "flood.jsonl", fl, fl_manifest)

    # One pretty-printed sample per threat class, for anyone reading the
    # contract rather than replaying it.
    samples = {}
    for a in demo:
        samples.setdefault(a["threat_class"], a)
    (out / "sample_by_class.json").write_text(
        json.dumps(samples, indent=2), encoding="utf-8"
    )
    print(f"  sample_by_class.json     {len(samples)} classes")


if __name__ == "__main__":
    main()
