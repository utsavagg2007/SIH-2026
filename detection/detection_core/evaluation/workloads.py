"""Deterministic synthetic FlowEvent workloads for evaluation and benchmarking.

**Everything here is synthetic.** It is generated arithmetic, not captured
traffic, and results measured on it must be labelled
:data:`SYNTHETIC` wherever they are reported. A synthetic benign workload can
show that a detector does not fire on traffic *shaped* like ordinary browsing;
it cannot establish a real-world false-positive rate, because it contains only
the variation this file was written to contain.

Determinism is by construction: every value is drawn from a
``random.Random`` seeded with a fixed constant, never from the wall clock or
the OS entropy pool. The same ``count`` always yields byte-identical flows,
so a benchmark re-run measures the code rather than a new dataset.

The draws are pseudo-random rather than index-arithmetic on purpose. A first
version of this generator used fixed cycles, and the cycles beat against each
other into a perfectly regular DNS cadence - which C2BeaconingDetector
correctly flagged, 412 times. That was the fixture being wrong, not the
detector; a seeded stream has no such hidden period.

The benign generator is deliberately shaped to stay clear of every detector's
qualification, and ``tests/test_evaluation.py`` asserts it produces zero
alerts. That is the point of a benign workload - but note the direction of
the claim: it is evidence the *generator* is benign, not evidence the
*detectors* are quiet on real traffic.
"""

from __future__ import annotations

import random

from ..schemas import DnsInfo, FlowEvent, TlsInfo

__all__ = [
    "REAL",
    "SYNTHETIC",
    "STRESS_SHAPES",
    "benign_flows",
    "mixed_flows",
    "stress_flows",
    "write_jsonl",
]

#: Data-source labels. Every evaluation result carries one, and they are
#: never mixed in a single report.
REAL = "real"
SYNTHETIC = "synthetic"

#: Seed for every draw below. Fixed, so the workload is reproducible.
_SEED = 42

#: Inter-flow gap bounds, in seconds of event time. Real browsing is bursty,
#: not metronomic - and a perfectly even cadence is exactly what
#: C2BeaconingDetector exists to catch, so gaps are drawn, never stepped.
_GAP_MIN = 0.15
_GAP_MAX = 9.0

#: Roughly how often a flow carries a DNS or TLS block, so both metadata
#: detectors are genuinely exercised rather than skipped.
_DNS_SHARE = 0.125
_TLS_SHARE = 0.09

#: Client hosts. Enough that no single source accumulates many distinct
#: ports or destinations inside PortScanDetector's 60s window.
_SOURCES = tuple(f"192.168.10.{index}" for index in range(11, 43))

#: Servers, spread over several /24s so no single destination collects the
#: 50 distinct sources DDoSDetector requires inside its 10s window.
_DESTINATIONS = tuple(
    f"93.184.{block}.{host}" for block in range(4) for host in range(10, 26)
)

#: Ordinary client-server ports. Far fewer than min_unique_ports (15).
_PORTS = (443, 443, 443, 80, 443, 8443, 443, 80)

#: A resolver and some unremarkable lookups. Short names, ordinary entropy,
#: two labels, not TXT - zero tunnelling signals each.
_RESOLVER = "192.168.10.1"
_DNS_PROFILE = (
    (18, 3.10, 0.0, 2, False),
    (24, 3.45, 0.0, 3, False),
    (15, 2.80, 0.0, 2, False),
    (29, 3.60, 0.0, 3, False),
)

#: Real, human-registered names: well under the 38-character / 4.2-bit SNI
#: thresholds EncryptedMalwareDetector treats as suspicious.
_SERVER_NAMES = (
    "outlook.office365.com",
    "www.wikipedia.org",
    "cdn.example.net",
    "api.github.com",
)


def benign_flows(count: int, *, start: float = 1_700_000_000.0) -> list[FlowEvent]:
    """``count`` deterministic flows shaped like ordinary internal traffic.

    Shaped specifically to clear every detector's bar, and the reasons are
    worth stating because they are the reasons a fixture like this usually
    fails:

    * **Port scan** - each source touches at most a handful of ports and
      hosts inside any 60s window, against thresholds of 15 and 20.
    * **DDoS** - the timeline advances on every flow, so a 10s window holds
      only a few flows, nowhere near 50 distinct sources.
    * **C2 beaconing** - gaps are drawn, not stepped, so no relationship
      recurs on a fixed timer.
    * **Data exfiltration** - uploads are hundreds of bytes; the 50 MiB
      window bar is never approached.
    * **DNS tunnelling** - lookups are short, low-entropy, shallow and not
      TXT: zero signals each, so the suspicious ratio stays at 0.
    * **Encrypted malware** - real server names, no JA3/JA3S/JA4, and no
      fingerprint list is configured by default.

    About one flow in eight carries a DNS block and one in eleven a TLS
    block, so those two detectors are genuinely exercised rather than
    skipped.
    """
    if count < 0:
        raise ValueError("count must not be negative")

    rng = random.Random(_SEED)
    flows: list[FlowEvent] = []
    timestamp = start
    for index in range(count):
        timestamp += round(rng.uniform(_GAP_MIN, _GAP_MAX), 3)
        src = rng.choice(_SOURCES)
        dst = rng.choice(_DESTINATIONS)
        port = rng.choice(_PORTS)

        dns = None
        tls = None
        draw = rng.random()
        if draw < _DNS_SHARE:
            length, entropy, sub_entropy, labels, is_txt = rng.choice(_DNS_PROFILE)
            dns = DnsInfo(
                uid=f"Cdns{index}",
                query_length=length,
                query_entropy=entropy,
                subdomain_entropy=sub_entropy,
                label_count=labels,
                is_txt=is_txt,
            )
            dst, port = _RESOLVER, 53
        elif draw < _DNS_SHARE + _TLS_SHARE:
            tls = TlsInfo(
                uid=f"Ctls{index}",
                server_name=rng.choice(_SERVER_NAMES),
                version="TLSv13",
                has_ja3=False,
                has_ja3s=False,
            )

        proto = "udp" if dns is not None else "tcp"
        flows.append(
            FlowEvent(
                flow_id=f"{src}:{dst}:{port}:{proto}:{timestamp:.3f}",
                timestamp=timestamp,
                src_ip=src,
                dst_ip=dst,
                dst_port=port,
                proto=proto,
                duration=0.12 + (index % 7) * 0.03,
                # Small request, larger response: a download, never an upload.
                orig_bytes=180 + (index % 23) * 11,
                resp_bytes=2_400 + (index % 37) * 130,
                orig_pkts=4 + (index % 5),
                resp_pkts=7 + (index % 9),
                dns=dns,
                tls=tls,
                source="detection_core.evaluation.workloads:benign",
            )
        )
    return flows


def mixed_flows(count: int, *, start: float = 1_700_000_000.0) -> list[FlowEvent]:
    """Benign traffic with a periodic port-scan burst folded in.

    For benchmarking the alerting path, where a run that never emits would
    not measure alert construction at all. **Not a benign workload** - never
    report false-positive numbers from this.

    The burst is a vertical scan: one source sweeping many ports on one host
    inside a few seconds, which is the cheapest honest way to make
    PortScanDetector fire without touching its configuration.
    """
    if count < 0:
        raise ValueError("count must not be negative")

    flows = benign_flows(count, start=start)
    if not flows:
        return flows

    scanner = "192.168.10.250"
    victim = "93.184.9.9"
    # Roughly one burst per 1000 flows, each on its own timeline slice.
    for burst, position in enumerate(range(500, count, 1000)):
        base = flows[position].timestamp
        for step in range(20):
            timestamp = base + step * 0.05
            flows.append(
                FlowEvent(
                    flow_id=f"{scanner}:{victim}:{9000 + step}:tcp:{timestamp:.3f}",
                    timestamp=timestamp,
                    src_ip=scanner,
                    dst_ip=victim,
                    dst_port=9000 + burst * 100 + step,
                    proto="tcp",
                    duration=0.01,
                    orig_bytes=60,
                    resp_bytes=0,
                    orig_pkts=1,
                    resp_pkts=0,
                    source="detection_core.evaluation.workloads:scan_burst",
                )
            )
    # Event time must not go backwards: the engine and every rolling window
    # assume approximately non-decreasing timestamps.
    flows.sort(key=lambda flow: flow.timestamp)
    return flows


#: Shapes :func:`stress_flows` can generate. Each isolates one cost the
#: rolling-window structures could plausibly have.
#:
#: The first two are synthetic probes of the bookkeeping. The last three are
#: the shapes the detectors actually exist to catch, and they are the ones
#: where a per-flow cost that grows with *distinct values* hurts: a scan or a
#: flood is, by definition, a stream of values nobody has seen before.
STRESS_SHAPES = (
    "hot_key",
    "many_keys",
    "vertical_scan",
    "horizontal_scan",
    "distinct_source_flood",
)


def stress_flows(
    count: int,
    *,
    shape: str = "hot_key",
    start: float = 1_700_000_000.0,
    step: float = 0.0005,
) -> list[FlowEvent]:
    """Workloads that isolate rolling-window cost, for diagnosis only.

    Two variables drive rolling-window cost: how many observations are
    *resident* in one window, and how many windows the index holds. These
    shapes pull them apart, so a per-flow cost that grows with either one
    shows up here as a rising curve rather than a flat line.

    * ``hot_key`` - one ``(src, dst, port, proto)`` relationship, timestamps
      1ms apart. Nothing expires inside a 300s window, so occupancy climbs
      to ``count`` and one key carries all of it. This is the shape that
      would expose a per-call rescan of a window's contents as O(N^2)
      overall - the defect ``ActivityWindow`` was rewritten to remove, and
      the reason this shape is still measured after every change to it.
    * ``many_keys`` - a distinct source *and* destination per flow, so every
      window index grows to ``count`` entries while every individual window
      holds one observation. This isolates index growth from scan length.
      Both endpoints must vary: holding the destination constant would make
      the DDoS window a hot key and quietly measure scan length again.
    * ``vertical_scan`` - one source sweeping one host, **a new destination
      port on every flow**. This is what PortScanDetector's vertical rule
      counts, and the port must genuinely change: a fixed port would leave
      the distinct-port count at 1 and measure nothing.
    * ``horizontal_scan`` - one source, one port, a new destination host on
      every flow: the per-port host fanout the horizontal rule reads.
    * ``distinct_source_flood`` - one destination, a new source on every
      flow, which is DDoSDetector's unique-source count.

    The three attack shapes pack their timestamps tightly enough that
    nothing expires inside the relevant window, so resident distinct values
    climb to ``count`` and the cost of counting them is what gets measured.

    ``hot_key`` and ``many_keys`` are deliberately non-alerting: a sub-ms
    cadence is far below
    C2's ``min_mean_interval_seconds``, one port cannot be a scan, one source
    cannot be a flood, and the byte counts never approach the exfiltration
    bar. What is being measured is the cost of *bookkeeping*, not of
    building alerts.
    """
    if count < 0:
        raise ValueError("count must not be negative")
    if shape not in STRESS_SHAPES:
        raise ValueError(f"shape must be one of {STRESS_SHAPES}")

    flows: list[FlowEvent] = []
    for index in range(count):
        timestamp = start + index * step
        port = 443
        if shape == "hot_key":
            src, dst = "10.20.30.40", "10.20.30.99"
        elif shape == "many_keys":
            src = f"10.{index // 65536 % 256}.{index // 256 % 256}.{index % 256}"
            dst = f"172.{index // 65536 % 256}.{index // 256 % 256}.{index % 256}"
        elif shape == "vertical_scan":
            # One source, one victim, a port nobody has tried yet.
            src, dst = "10.0.0.1", "10.0.0.50"
            port = 1 + index
        elif shape == "horizontal_scan":
            # One source sweeping one port across the estate.
            src, port = "10.0.0.1", 22
            dst = f"10.{index // 65536 % 256}.{index // 256 % 256}.{index % 256}"
        else:  # distinct_source_flood
            src = f"198.{index // 65536 % 256}.{index // 256 % 256}.{index % 256}"
            dst = "10.0.0.80"
        flows.append(
            FlowEvent(
                flow_id=f"{src}:{dst}:{port}:tcp:{timestamp:.3f}",
                timestamp=timestamp,
                src_ip=src,
                dst_ip=dst,
                dst_port=port,
                proto="tcp",
                duration=0.05,
                orig_bytes=200,
                resp_bytes=1_200,
                orig_pkts=3,
                resp_pkts=5,
                source=f"detection_core.evaluation.workloads:stress:{shape}",
            )
        )
    return flows


def write_jsonl(flows: list[FlowEvent], path) -> int:
    """Write flows as ingestion-style JSONL. Returns the line count.

    Only the fields the adapter reads are emitted, in the top-level shape
    ``features.jsonl`` uses, so the JSONL benchmark exercises the real
    adapter rather than a shortcut around it.
    """
    import json
    from pathlib import Path

    path = Path(path)
    with open(path, "w", encoding="utf-8") as handle:
        for flow in flows:
            record = {
                "flow_id": flow.flow_id,
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port,
                "proto": flow.proto,
                "duration": flow.duration,
                "orig_bytes": flow.orig_bytes,
                "resp_bytes": flow.resp_bytes,
                "orig_pkts": flow.orig_pkts,
                "resp_pkts": flow.resp_pkts,
            }
            if flow.dns is not None:
                record["dns"] = flow.dns.model_dump(exclude_none=True)
            if flow.tls is not None:
                record["tls"] = flow.tls.model_dump(exclude_none=True)
            handle.write(json.dumps(record))
            handle.write("\n")
    return len(flows)
