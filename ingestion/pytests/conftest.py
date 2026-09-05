"""A stand-in for the compiled Rust module.

The defects these tests cover are in the Python projection, not in the Rust
mathematics. The imported detector-profile module is therefore patched within
each test with a faithful transcription of the five feature extractors. The
patch is fixture-scoped so it cannot contaminate M1D integration tests collected
in the same pytest process.

The fake is deliberately a transcription rather than a reimplementation: each
function returns exactly the field set the corresponding Rust struct serialises,
in the same shape, so a test that passes here would pass against the real crate.
The one thing it reproduces on purpose is the misbehaviour under test -
``extract_window_features`` sorts its input by timestamp internally, exactly as
``temporal::sliding_window_features`` does, which is what made the old
merge-by-index wrong.
"""

from __future__ import annotations

import json
import math
import sys
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in Counter(text).values())


def _encode_conn_state(state: str) -> int:
    return {
        "S1": 1, "S2": 2, "S3": 3, "SF": 4, "REJ": 5, "RSTO": 6, "RSTOS0": 7,
        "RSTR": 8, "RSTRH": 9, "SH": 10, "SHR": 11, "OTH": 12,
    }.get(state, 0)  # note: no S0 arm, exactly as the crate has none


def _encode_ssl_version(version: str) -> int:
    return {"TLSv10": 1, "TLSv11": 2, "TLSv12": 3, "TLSv13": 4, "SSLv3": 5}.get(version, 0)


def _flow_features(conn_json: str) -> str:
    out = []
    for r in json.loads(conn_json):
        orig_bytes = r.get("orig_bytes", 0)
        resp_bytes = r.get("resp_bytes", 0)
        orig_pkts = r.get("orig_pkts", 0)
        resp_pkts = r.get("resp_pkts", 0)
        out.append(
            {
                "flow_id": (
                    f"{r['src_ip']}:{r['dst_ip']}:{r['dst_port']}:"
                    f"{r['proto']}:{r['timestamp']:.3f}"
                ),
                "src_ip": r["src_ip"],
                "dst_ip": r["dst_ip"],
                "dst_port": r["dst_port"],
                "proto": r["proto"],
                "duration": r.get("duration", 0.0),
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "byte_ratio": resp_bytes / (orig_bytes + 1.0),
                "orig_pkts": orig_pkts,
                "resp_pkts": resp_pkts,
                "pkt_ratio": resp_pkts / (orig_pkts + 1.0),
                "conn_state_encoded": _encode_conn_state(r.get("conn_state", "")),
            }
        )
    return json.dumps(out)


def _window_features(conn_json: str, window_secs: float) -> str:
    """Sorted by timestamp internally - the behaviour that broke the join."""
    records = sorted(json.loads(conn_json), key=lambda r: r["timestamp"])
    out = []
    window: list[dict] = []
    for record in records:
        window.append(record)
        window = [w for w in window if record["timestamp"] - w["timestamp"] <= window_secs]
        span = window[-1]["timestamp"] - window[0]["timestamp"]
        total = sum(w.get("orig_bytes", 0) + w.get("resp_bytes", 0) for w in window)
        stamps = [w["timestamp"] for w in window]
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        mean = sum(gaps) / len(gaps) if gaps else 0.0
        out.append(
            {
                # n / (span + 1e-6): 1e6 on a single-flow window, as shipped.
                "flow_rate": len(window) / (span + 1e-6),
                "byte_rate": total / (span + 1e-6),
                "inter_arrival_mean": mean,
                "inter_arrival_stddev": 0.0,
                "unique_dst_ports": len({w["dst_port"] for w in window}),
                "unique_dst_ips": len({w["dst_ip"] for w in window}),
                "src_ip_entropy": _entropy("".join(w["src_ip"] for w in window)),
                # Not a real field - a marker so a test can prove which input
                # record this row was computed from.
                "_window_owner_uid": record["uid"],
            }
        )
    return json.dumps(out)


def _dns_features(dns_json: str) -> str:
    out = []
    for r in json.loads(dns_json):
        query = r.get("query", "")
        out.append(
            {
                "uid": r["uid"],
                "query_length": len(query),
                "query_entropy": _entropy(query),
                "subdomain_entropy": _entropy(query.split(".")[0] if query else ""),
                # Compares the NUMERIC qtype against "TXT" - always False.
                "is_txt": str(r.get("qtype", "")).upper() == "TXT",
                "label_count": len(query.rstrip(".").split(".")) if query else 0,
            }
        )
    return json.dumps(out)


def _tls_features(ssl_json: str) -> str:
    out = []
    for r in json.loads(ssl_json):
        cipher = r.get("cipher") or ""
        out.append(
            {
                "uid": r["uid"],
                "has_ja3": bool(r.get("ja3")),
                "has_ja3s": bool(r.get("ja3s")),
                "ssl_version_encoded": _encode_ssl_version(r.get("version", "")),
                "cipher_encoded": 0 if not cipher else (len(cipher) % 16) + 1,
            }
        )
    return json.dumps(out)


def _http_features(http_json: str) -> str:
    out = []
    for r in json.loads(http_json):
        uri = r.get("uri") or ""
        agent = r.get("user_agent") or ""
        out.append(
            {
                "uid": r["uid"],
                "method_encoded": 1,
                "host_length": len(r.get("host") or ""),
                "uri_length": len(uri),
                "uri_entropy": _entropy(uri),
                "has_user_agent": bool(agent),
                "user_agent_length": len(agent),
                "request_body_len": r.get("request_body_len", 0),
                "response_body_len": r.get("response_body_len", 0),
                "status_code": r.get("status_code", 0),
            }
        )
    return json.dumps(out)


@pytest.fixture
def pipeline(monkeypatch):
    # `detector_profile` imports the five extractors from the compiled crate
    # at module scope, so this fixture cannot substitute the doubles until
    # that import has already succeeded. Without the crate the suite reported
    # 17 ERRORs with a bare ModuleNotFoundError, which reads as a broken merge
    # rather than as an unbuilt toolchain. Skip with the build command instead.
    pytest.importorskip(
        "ingestion_core",
        reason="ingestion_core (PyO3) is not built - run `maturin develop "
        "--manifest-path ingestion/Cargo.toml` (needs a Rust toolchain; "
        "see README, 'Ingestion needs a Rust toolchain')",
    )
    import detector_profile as module

    monkeypatch.setattr(module, "extract_flow_features", _flow_features)
    monkeypatch.setattr(module, "extract_window_features", _window_features)
    monkeypatch.setattr(module, "extract_dns_features", _dns_features)
    monkeypatch.setattr(module, "extract_tls_features", _tls_features)
    monkeypatch.setattr(module, "extract_http_features", _http_features)
    return module
