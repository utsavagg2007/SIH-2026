#!/usr/bin/env python3
"""Generate a labelled flow capture in the ingestion output format.

    python tools/synth_flows.py -o data/features.jsonl -m data/manifest.json

Why this exists
---------------
The ingestion layer needs Zeek, Docker and a compiled Rust extension before it
produces a single record. That is the right architecture and the wrong
dependency chain to stand between a reviewer and a working demo - and it is not
where the interesting failures are anyway. This writes the same record shape
``ingestion/pipeline.py`` writes, so everything downstream of Layer 3 - the
seven detectors, fusion, the alert bus, the dashboard, the analyst - runs end to
end with nothing installed but Python.

It is also the labelling half of the problem the Layered Build Plan calls a
workstream in its own right (section 3): traffic generated here is labelled *by
construction*, because we know exactly which flow was written for which threat,
and the manifest is written as the traffic is emitted rather than inferred
afterwards.

The confounders are the point
-----------------------------
Build Plan 3.2 is blunt about the trap: if benign traffic comes from one
generator and malicious traffic from another, a model learns to tell two
generators apart and reports near-perfect scores that mean nothing. So the
benign half here deliberately contains the four things that look exactly like
the threats:

    NTP heartbeat every 64 seconds     looks exactly like a beacon
    nightly cloud backup               looks exactly like exfiltration
    CDN hostnames, long and random     look exactly like DGA domains
    authorised inventory scan          looks exactly like hostile recon

A detector that fires on those is wrong, and a report that does not contain
them is not worth reading. Each is labelled ``benign_confounder`` in the
manifest with the threat class it mimics, so the evaluation harness can score
precision against them specifically.

Known limitation, stated rather than discovered
-----------------------------------------------
This is synthetic. Inter-arrival times are cleaner than real traffic, byte
counts are drawn from tidy distributions, and there is no packet loss or
retransmission. It exercises the pipeline and the detector logic honestly; it
does not substitute for a real capture when reporting accuracy. Use it to prove
the system works, and a real labelled capture to say how well.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import string
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

# --------------------------------------------------------------------------
# Topology
# --------------------------------------------------------------------------

INTERNAL = "10.4.2."
RESOLVER = "10.4.0.53"
GATEWAY = "10.4.0.1"

#: Reserved for attacker-controlled behaviour, so anything from this range
#: inside a manifest window is unambiguous (Build Plan 3.3).
COMPROMISED_HOST = "10.4.2.19"
SCANNER_HOST = "10.4.2.77"
EXFIL_HOST = "10.4.2.31"
TUNNEL_HOST = "10.4.2.44"

C2_SERVER = "185.62.11.4"
EXFIL_SERVER = "91.219.236.18"
FLOOD_TARGET = "10.4.1.10"

#: A browser's JA3 and a scripting library's JA3. The difference between them is
#: the actual signal the encrypted-session detector reads, and it is a real
#: property of the TLS handshake rather than anything decrypted.
JA3_BROWSER = "579ccef312d18482fc42e2b822ca2430"
JA3_CURL = "a0e9f5d64349fb13191bc781f81f42e1"
JA3_MALWARE = "51c64c77e60f3980eea90869b68c58a8"
JA3S_COMMON = "f4febc55ea12b31ae17cfb7e614afda8"

BENIGN_DOMAINS = [
    "www.example.test", "api.example.test", "updates.example.test",
    "mail.example.test", "docs.example.test", "login.example.test",
]

#: Legitimate content-delivery hostnames: long, high-entropy, and entirely
#: innocent. These are the DGA confounder.
CDN_DOMAINS = [
    "d3f7k2mq9xz1lp.cloudfront.test",
    "a7b2c9d4e1f6g8.akamai-edge.test",
    "x9k2mq7z4lp1nv.fastly-cdn.test",
    "storage-eu-west-2-b7f9c1.objectstore.test",
]


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------


@dataclass
class Interval:
    """One labelled span of traffic, written as it is generated."""

    label: str  # a threat_class, or "benign_confounder", or "benign"
    src_ip: str | None
    dst_ip: str | None
    start: float
    end: float
    flows: int = 0
    note: str = ""
    #: For confounders: the threat class this innocent traffic resembles.
    mimics: str | None = None
    #: Every source and destination that participated. ``src_ip``/``dst_ip``
    #: above name the principal actor for display; these are what the evaluator
    #: matches an alert against, because a confounder like the time daemon runs
    #: on several hosts and an alert naming any of them is the same finding.
    src_ips: list[str] = field(default_factory=list)
    dst_ips: list[str] = field(default_factory=list)


def _endpoints(records: list[dict]) -> tuple[list[str], list[str]]:
    return (
        sorted({r["src_ip"] for r in records}),
        sorted({r["dst_ip"] for r in records}),
    )


@dataclass
class Scenario:
    seed: int
    generated_at: float
    base_time: float
    duration_seconds: float
    intervals: list[Interval] = field(default_factory=list)
    total_flows: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": "sih26.scenario_manifest.v1",
            "seed": self.seed,
            "generated_at": self.generated_at,
            "base_time": self.base_time,
            "duration_seconds": self.duration_seconds,
            "total_flows": self.total_flows,
            "intervals": [asdict(i) for i in self.intervals],
        }


# --------------------------------------------------------------------------
# Record construction
# --------------------------------------------------------------------------


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    from collections import Counter

    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in Counter(text).values())


_uid_counter = 0


def _uid() -> str:
    global _uid_counter
    _uid_counter += 1
    return f"Csynth{_uid_counter:08d}"


def flow(
    ts: float,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    proto: str = "tcp",
    *,
    src_port: int | None = None,
    service: str | None = None,
    duration: float = 0.05,
    orig_bytes: int = 0,
    resp_bytes: int = 0,
    orig_pkts: int = 0,
    resp_pkts: int = 0,
    conn_state: str = "SF",
    rng: random.Random,
) -> dict[str, Any]:
    """One flow record, shaped exactly like ingestion/pipeline.py emits.

    The field set is not a convention invented here - it is what
    ``detection_core.adapters.record_to_flow_event`` reads, and every name is
    checked against that adapter by the tests in tools/tests.
    """
    sp = src_port if src_port is not None else rng.randint(32768, 60999)
    return {
        "flow_id": f"{src_ip}:{dst_ip}:{dst_port}:{proto}:{ts:.3f}",
        "uid": _uid(),
        "timestamp": round(ts, 6),
        "src_ip": src_ip,
        "src_port": sp,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "proto": proto,
        "service": service,
        "duration": round(duration, 6),
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "orig_ip_bytes": orig_bytes + 40 * max(orig_pkts, 1),
        "resp_ip_bytes": resp_bytes + 40 * max(resp_pkts, 1),
        "conn_state": conn_state,
        "byte_ratio": resp_bytes / (orig_bytes + 1.0),
        "pkt_ratio": resp_pkts / (orig_pkts + 1.0),
        "conn_state_encoded": {
            "S1": 1, "S2": 2, "S3": 3, "SF": 4, "REJ": 5, "RSTO": 6,
            "RSTOS0": 7, "RSTR": 8, "RSTRH": 9, "SH": 10, "SHR": 11, "OTH": 12,
        }.get(conn_state, 0),
    }


def with_dns(
    record: dict[str, Any], query: str, qtype: str = "A", rcode: str = "NOERROR"
) -> dict[str, Any]:
    labels = query.rstrip(".").split(".")
    record["dns"] = {
        "uid": record["uid"],
        "query": query,
        "qtype": qtype,
        "qtype_num": {"A": "1", "TXT": "16", "AAAA": "28", "NULL": "10"}.get(qtype, "1"),
        "rcode": rcode,
        "rcode_num": {"NOERROR": "0", "NXDOMAIN": "3", "SERVFAIL": "2"}.get(rcode, "0"),
        "query_length": len(query),
        "query_entropy": round(_entropy(query), 6),
        "subdomain_entropy": round(_entropy(labels[0]), 6),
        "is_txt": qtype == "TXT",
        "label_count": len(labels),
    }
    return record


def with_tls(
    record: dict[str, Any],
    server_name: str | None,
    ja3: str,
    *,
    version: str = "TLSv13",
    ja3s: str = JA3S_COMMON,
    cipher: str = "TLS_AES_128_GCM_SHA256",
) -> dict[str, Any]:
    block: dict[str, Any] = {
        "uid": record["uid"],
        "ja3": ja3,
        "ja3s": ja3s,
        "ja4": None,
        "server_name": server_name,
        "version": version,
        "cipher": cipher,
        "has_ja3": True,
        "has_ja3s": True,
        "ssl_version_encoded": {"TLSv10": 1, "TLSv11": 2, "TLSv12": 3, "TLSv13": 4}.get(version, 0),
    }
    if server_name:
        block["sni_length"] = len(server_name)
        block["sni_entropy"] = round(_entropy(server_name), 6)
    record["tls"] = block
    return record


# --------------------------------------------------------------------------
# Benign background and confounders
# --------------------------------------------------------------------------


def benign_web(base: float, duration: float, rng: random.Random) -> Iterator[dict]:
    """Ordinary browsing: irregular, bidirectional, mostly inbound bytes."""
    for host_id in range(3, 16):
        src = f"{INTERNAL}{host_id}"
        t = base + rng.uniform(0, 30)
        while t < base + duration:
            domain = rng.choice(BENIGN_DOMAINS)
            yield with_dns(
                flow(t, src, RESOLVER, 53, "udp", service="dns",
                     duration=0.01, orig_bytes=70, resp_bytes=180,
                     orig_pkts=1, resp_pkts=1, rng=rng),
                domain,
            )
            yield with_tls(
                flow(t + 0.05, src, f"93.184.216.{rng.randint(2, 60)}", 443,
                     service="ssl", duration=rng.uniform(0.3, 4.0),
                     orig_bytes=rng.randint(400, 2000),
                     resp_bytes=rng.randint(8000, 120000),
                     orig_pkts=rng.randint(6, 30), resp_pkts=rng.randint(20, 120),
                     rng=rng),
                domain, JA3_BROWSER,
            )
            t += rng.expovariate(1 / 12.0)


def confounder_ntp(base: float, duration: float, rng: random.Random) -> Iterator[dict]:
    """A time daemon. Perfectly periodic, perfectly innocent.

    This is the single most important record in the file. A beacon detector
    that cannot separate this from a real beacon has not been tested.
    """
    for host_id in (4, 9):
        src = f"{INTERNAL}{host_id}"
        t = base + rng.uniform(0, 20)
        while t < base + duration:
            yield flow(t, src, GATEWAY, 123, "udp", service="ntp",
                       duration=0.004, orig_bytes=48, resp_bytes=48,
                       orig_pkts=1, resp_pkts=1, rng=rng)
            t += 64.0 + rng.uniform(-0.4, 0.4)


def confounder_backup(base: float, duration: float, rng: random.Random) -> Iterator[dict]:
    """Cloud backup: enormous outbound volume to a destination seen every night."""
    src = f"{INTERNAL}7"
    t = base + 30
    while t < base + duration:
        payload = rng.randint(4_000_000, 9_000_000)
        yield with_tls(
            flow(t, src, "203.0.113.77", 443, service="ssl",
                 duration=rng.uniform(20, 45), orig_bytes=payload,
                 resp_bytes=rng.randint(2000, 9000),
                 orig_pkts=payload // 1400, resp_pkts=rng.randint(30, 90), rng=rng),
            "backup.vendor.test", JA3_BROWSER,
        )
        t += rng.uniform(45, 70)


def confounder_cdn(base: float, duration: float, rng: random.Random) -> Iterator[dict]:
    """Long, high-entropy, entirely legitimate hostnames."""
    for host_id in (5, 11):
        src = f"{INTERNAL}{host_id}"
        t = base + rng.uniform(0, 40)
        while t < base + duration:
            yield with_dns(
                flow(t, src, RESOLVER, 53, "udp", service="dns", duration=0.01,
                     orig_bytes=80, resp_bytes=210, orig_pkts=1, resp_pkts=1, rng=rng),
                rng.choice(CDN_DOMAINS),
            )
            t += rng.expovariate(1 / 25.0)


def confounder_authorised_scan(
    base: float, duration: float, rng: random.Random
) -> Iterator[dict]:
    """An asset-inventory sweep. Structurally identical to hostile recon.

    Deliberately kept below the detector's threshold in breadth but obvious in
    character, so it tests the boundary rather than trivially passing.
    """
    src = f"{INTERNAL}250"
    t = base + duration * 0.55
    for port in (22, 80, 443, 445, 3389, 8080):
        for host_id in range(3, 12):
            yield flow(t, src, f"{INTERNAL}{host_id}", port, service=None,
                       duration=0.002, orig_bytes=0, resp_bytes=0,
                       orig_pkts=1, resp_pkts=1, conn_state="REJ", rng=rng)
            t += 0.08


# --------------------------------------------------------------------------
# Attacks
# --------------------------------------------------------------------------


def attack_port_scan(base: float, rng: random.Random) -> tuple[list[dict], Interval]:
    """Vertical scan: one source, many ports, no completed handshakes.

    conn_state S0 throughout - a SYN with no reply - which is the signal the
    Rust encoder had no arm for and the raw string now carries.
    """
    start = base + 60
    records = []
    t = start
    for port in range(20, 20 + 40):
        records.append(
            flow(t, SCANNER_HOST, "10.4.1.5", port, service=None, duration=0.001,
                 orig_bytes=0, resp_bytes=0, orig_pkts=1, resp_pkts=0,
                 conn_state="S0", rng=rng)
        )
        t += 0.25
    srcs, dsts = _endpoints(records)
    return records, Interval(
        "port_scan", SCANNER_HOST, "10.4.1.5", start, t, len(records),
        "vertical scan, 40 ports, all S0",
        src_ips=srcs,
        dst_ips=dsts,
    )


def attack_intrusion_recon(base: float, rng: random.Random) -> tuple[list[dict], Interval]:
    """The compromised host's own scan, so one host walks the kill chain.

    Without this, every finding on 10.4.2.19 sits at the same kill-chain stage -
    DGA, beaconing and encrypted-session malware are all command-and-control -
    and the incident ribbon has nothing to order. The correlation layer is the
    highest-value component in the build relative to its cost, and the screen
    that shows it needs a host that went reconnaissance, then command and
    control, then exfiltration.

    That is also the example the frontend specification uses by name
    (section 6.1: ``HOST 10.4.2.19 ... PS -> BC -> EX``), and it is what an
    actual intrusion looks like: the same machine does all three.
    """
    start = base + 5
    records = []
    t = start
    for port in (22, 23, 80, 135, 139, 443, 445, 1433, 3306, 3389,
                 5432, 5900, 8080, 8443, 9200, 27017, 6379, 11211):
        for host_id in (12, 13, 14):
            records.append(
                flow(t, COMPROMISED_HOST, f"10.4.1.{host_id}", port, service=None,
                     duration=0.001, orig_bytes=0, resp_bytes=0, orig_pkts=1,
                     resp_pkts=0, conn_state="S0", rng=rng)
            )
            t += 0.12
    srcs, dsts = _endpoints(records)
    return records, Interval(
        "port_scan", COMPROMISED_HOST, None, start, t, len(records),
        "the compromised host's own recon: 18 ports across 3 hosts, all S0 - "
        "stage one of the kill chain this host then walks",
        src_ips=srcs,
        dst_ips=dsts,
    )


def attack_ddos(base: float, rng: random.Random) -> tuple[list[dict], Interval]:
    """Spoofed-source SYN flood: high source entropy, no completed handshakes."""
    start = base + 200
    records = []
    t = start
    for i in range(320):
        spoofed = f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        records.append(
            flow(t, spoofed, FLOOD_TARGET, 80, service=None, duration=0.0,
                 orig_bytes=0, resp_bytes=0, orig_pkts=rng.randint(3, 8),
                 resp_pkts=0, conn_state="S0", rng=rng)
        )
        t += 0.02
    srcs, dsts = _endpoints(records)
    return records, Interval(
        "ddos", None, FLOOD_TARGET, start, t, len(records),
        "spoofed SYN flood, 320 flows from 320 distinct sources in ~6s",
        src_ips=srcs,
        dst_ips=dsts,
    )


def attack_beacon(base: float, duration: float, rng: random.Random) -> tuple[list[dict], Interval]:
    """C2 check-in every 45s with 6% jitter, near-identical payload each time.

    Jitter is a parameter on purpose. Sweeping it is how you characterise the
    detector rather than merely running it - "holds to 40% jitter, degrades
    beyond" is a far stronger claim than "we detected the beacon".
    """
    start = base + 20
    records = []
    t = start
    while t < base + duration:
        records.append(
            with_tls(
                flow(t, COMPROMISED_HOST, C2_SERVER, 443, service="ssl",
                     duration=0.4, orig_bytes=rng.randint(870, 890),
                     resp_bytes=rng.randint(240, 260), orig_pkts=6, resp_pkts=5,
                     rng=rng),
                None, JA3_CURL,
            )
        )
        t += 45.0 * (1.0 + rng.uniform(-0.06, 0.06))
    srcs, dsts = _endpoints(records)
    return records, Interval(
        "c2_beaconing", COMPROMISED_HOST, C2_SERVER, start, t, len(records),
        "45s interval, 6% jitter, no SNI, scripting-library JA3",
        src_ips=srcs,
        dst_ips=dsts,
    )


def attack_dga(base: float, rng: random.Random) -> tuple[list[dict], Interval]:
    """Algorithmically generated domains, mostly failing to resolve.

    The NXDOMAIN burst is half the detection and is often the stronger half.
    """
    start = base + 90
    records = []
    t = start
    for i in range(30):
        name = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(15))
        resolved = i % 10 == 0
        records.append(
            with_dns(
                flow(t, COMPROMISED_HOST, RESOLVER, 53, "udp", service="dns",
                     duration=0.01, orig_bytes=78, resp_bytes=120 if resolved else 90,
                     orig_pkts=1, resp_pkts=1, rng=rng),
                f"{name}.com", "A", "NOERROR" if resolved else "NXDOMAIN",
            )
        )
        t += rng.uniform(0.8, 2.2)
    srcs, dsts = _endpoints(records)
    return records, Interval(
        "dga_domain", COMPROMISED_HOST, RESOLVER, start, t, len(records),
        "30 generated domains, 90% NXDOMAIN",
        src_ips=srcs,
        dst_ips=dsts,
    )


def attack_dns_tunnel(base: float, rng: random.Random) -> tuple[list[dict], Interval]:
    """Data carried in DNS: many long unique subdomains under one parent."""
    start = base + 150
    records = []
    t = start
    parent = "t.exfil-channel.test"
    for _ in range(60):
        payload = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(48))
        records.append(
            with_dns(
                flow(t, TUNNEL_HOST, RESOLVER, 53, "udp", service="dns",
                     duration=0.02, orig_bytes=110, resp_bytes=340,
                     orig_pkts=1, resp_pkts=1, rng=rng),
                f"{payload}.{parent}", "TXT", "NOERROR",
            )
        )
        t += rng.uniform(0.3, 0.9)
    srcs, dsts = _endpoints(records)
    return records, Interval(
        "dns_tunnelling", TUNNEL_HOST, RESOLVER, start, t, len(records),
        f"60 unique 48-char subdomains under {parent}, all TXT",
        src_ips=srcs,
        dst_ips=dsts,
    )


def attack_encrypted_malware(base: float, rng: random.Random) -> tuple[list[dict], Interval]:
    """TLS sessions the encrypted-session detector can actually qualify.

    No payload is involved at any point - this is handshake metadata only.

    Both of the detector's paths are exercised on purpose, because they answer
    different questions and a demo that only shows one is misleading:

    * **Signature** - a JA3 that matches a locally configured fingerprint list.
      This is how a *known* implant is caught, and it needs
      ``--ja3-feed tools/ja3_feed.example.txt`` or the path stays inert by
      design (the detector never downloads a feed).
    * **Heuristic** - a long, high-entropy server name over an obsolete TLS
      version. This is how an *unknown* one is caught.

    An earlier version of this generator emitted sessions with no SNI at all
    and TLSv12, and the detector correctly stayed silent: absence of SNI is not
    evidence (ECH and ordinary TLS both hide the name) and TLSv12 is not
    obsolete. The traffic was wrong, not the detector - worth recording, because
    the tempting fix was to loosen the detector until the demo lit up.
    """
    start = base + 240
    records = []
    t = start

    # Heuristic path: one host pair, long random SNI, obsolete negotiated
    # version. The detector needs at least six observations on the pair and a
    # suspicious majority, so ten of eleven here are suspicious.
    for index in range(11):
        label = "".join(
            rng.choice(string.ascii_lowercase + string.digits) for _ in range(46)
        )
        sni = f"{label}.cdn-node.test" if index < 10 else "ordinary.example.test"
        records.append(
            with_tls(
                flow(t, COMPROMISED_HOST, "45.134.26.9", 443, service="ssl",
                     duration=rng.uniform(1.0, 3.0), orig_bytes=rng.randint(600, 1400),
                     resp_bytes=rng.randint(700, 2200), orig_pkts=9, resp_pkts=11,
                     rng=rng),
                sni, JA3_MALWARE, version="TLSv10",
            )
        )
        t += rng.uniform(4, 9)

    # Signature path: a fingerprint on the configured list. One flow is enough -
    # an exact IOC match is not a statistical argument.
    for _ in range(3):
        records.append(
            with_tls(
                flow(t, COMPROMISED_HOST, "45.134.26.10", 443, service="ssl",
                     duration=rng.uniform(0.5, 2.0), orig_bytes=rng.randint(400, 900),
                     resp_bytes=rng.randint(500, 1500), orig_pkts=7, resp_pkts=8,
                     rng=rng),
                None, JA3_MALWARE, version="TLSv12",
            )
        )
        t += rng.uniform(3, 7)

    srcs, dsts = _endpoints(records)
    return records, Interval(
        "encrypted_malware", COMPROMISED_HOST, "45.134.26.9", start, t, len(records),
        "11 sessions with long high-entropy SNI over obsolete TLS (heuristic "
        "path) plus 3 carrying a listed JA3 (signature path)",
        src_ips=srcs,
        dst_ips=dsts,
    )


def attack_exfiltration(base: float, rng: random.Random) -> tuple[list[dict], Interval]:
    """Bulk outbound to a destination this host has never contacted."""
    start = base + 420
    records = []
    t = start
    for _ in range(16):
        payload = rng.randint(2_500_000, 6_000_000)
        records.append(
            with_tls(
                flow(t, COMPROMISED_HOST, EXFIL_SERVER, 443, service="ssl",
                     duration=rng.uniform(8, 20), orig_bytes=payload,
                     resp_bytes=rng.randint(800, 3000),
                     orig_pkts=payload // 1400, resp_pkts=rng.randint(15, 40), rng=rng),
                "upload.unfamiliar-host.test", JA3_CURL,
            )
        )
        t += rng.uniform(3, 8)
    srcs, dsts = _endpoints(records)
    return records, Interval(
        "data_exfiltration", COMPROMISED_HOST, EXFIL_SERVER, start, t, len(records),
        "16 bulk uploads to a novel destination, ~99% outbound - stage three "
        "of the kill chain, on the same host that scanned and then beaconed",
        src_ips=srcs,
        dst_ips=dsts,
    )


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------


def generate(
    *, seed: int = 26145, duration: float = 600.0, base_time: float | None = None
) -> tuple[list[dict], Scenario]:
    rng = random.Random(seed)
    base = base_time if base_time is not None else time.time() - duration

    scenario = Scenario(
        seed=seed,
        generated_at=time.time(),
        base_time=base,
        duration_seconds=duration,
    )
    records: list[dict] = []

    # Benign background, with the confounders that make the numbers mean
    # something.
    for label, mimics, producer, note in (
        ("benign", None, benign_web, "ordinary browsing"),
        ("benign_confounder", "c2_beaconing", confounder_ntp,
         "time daemon, 64s period - a beacon detector must not fire on this"),
        ("benign_confounder", "data_exfiltration", confounder_backup,
         "cloud backup, ~99% outbound - an exfil detector must not fire on this"),
        ("benign_confounder", "dga_domain", confounder_cdn,
         "CDN hostnames, long and high-entropy but legitimate"),
        ("benign_confounder", "port_scan", confounder_authorised_scan,
         "authorised inventory sweep, structurally identical to hostile recon"),
    ):
        produced = list(producer(base, duration, rng))
        records.extend(produced)
        if produced:
            scenario.intervals.append(
                Interval(
                    label,
                    produced[0]["src_ip"] if label != "benign" else None,
                    None,
                    min(r["timestamp"] for r in produced),
                    max(r["timestamp"] for r in produced),
                    len(produced),
                    note,
                    mimics,
                    src_ips=sorted({r["src_ip"] for r in produced}),
                    dst_ips=sorted({r["dst_ip"] for r in produced}),
                )
            )

    for attack in (
        attack_intrusion_recon(base, rng),
        attack_port_scan(base, rng),
        attack_ddos(base, rng),
        attack_beacon(base, duration, rng),
        attack_dga(base, rng),
        attack_dns_tunnel(base, rng),
        attack_encrypted_malware(base, rng),
        attack_exfiltration(base, rng),
    ):
        produced, interval = attack
        records.extend(produced)
        scenario.intervals.append(interval)

    # Event-time order. detection_core documents that it needs non-decreasing
    # event time, and this is where a generator most easily gets it wrong.
    records.sort(key=lambda r: r["timestamp"])
    scenario.total_flows = len(records)
    return records, scenario


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate a labelled synthetic capture in the ingestion record format"
    )
    ap.add_argument("-o", "--output", default="data/features.jsonl",
                    help="flow records, JSON lines ('-' for stdout)")
    ap.add_argument("-m", "--manifest", default=None,
                    help="ground-truth manifest (default: alongside --output)")
    ap.add_argument("--seed", type=int, default=26145,
                    help="deterministic: the same seed produces the same capture")
    ap.add_argument("--duration", type=float, default=600.0,
                    help="seconds of simulated traffic")
    ap.add_argument("--base-time", type=float, default=None,
                    help="epoch seconds for the first flow (default: now - duration, "
                         "so the capture ends at the present and latency figures stay sane)")
    args = ap.parse_args()

    records, scenario = generate(
        seed=args.seed, duration=args.duration, base_time=args.base_time
    )

    if args.output == "-":
        for record in records:
            sys.stdout.write(json.dumps(record) + "\n")
    else:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")

        manifest = Path(args.manifest) if args.manifest else out.with_suffix(".manifest.json")
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps(scenario.to_json(), indent=2), encoding="utf-8")
        print(f"[+] {len(records)} flows -> {out}", file=sys.stderr)
        print(f"[+] ground truth  -> {manifest}", file=sys.stderr)

    by_label: dict[str, int] = {}
    for interval in scenario.intervals:
        by_label[interval.label] = by_label.get(interval.label, 0) + interval.flows
    for label, count in sorted(by_label.items()):
        print(f"    {label:20} {count:6} flows", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
