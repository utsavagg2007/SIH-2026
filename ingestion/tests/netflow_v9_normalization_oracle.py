#!/usr/bin/env python3
"""Independent F7 stdlib oracle. Default is read-only verification.

Small synthetic wire specifications and canonical expectations are calculated
here without Rust, PyO3, or reading Rust-produced output. --emit-patch prints an
apply_patch document for initial fixture creation; it never writes files itself.
Wire files use ASCII hex for reviewability. Hashes identify DECODED wire bytes.
Canonical goldens are exact compact UTF-8 JSONL, LF after every record, no BOM.
"""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import struct
import uuid

ROOT = Path(__file__).resolve().parent / "fixtures/export/netflow_v9_canonical"
REPO = Path(__file__).resolve().parents[2]
MARKER = "co-netflow-v9-id-v1"
URI = "https://utsavagg2007.github.io/SIH-2026/contracts/" + MARKER
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, URI)
AGE = 86_400_000
MAX_AGE = (1 << 31) - 1
OBSERVED = "2026-10-03T00:00:00Z"
EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
SUPPORTED = {1: None, 2: None, 4: 1, 6: 1, 7: 2, 8: 4, 10: None,
             11: 2, 12: 4, 14: None, 21: 4, 22: 4, 27: 16, 28: 16, 32: 2, 60: 1}


def lp(components):
    return b"".join(struct.pack("!I", len(s.encode())) + s.encode() for s in components)


def binary_uuid(namespace, name):
    digest = bytearray(hashlib.sha1(namespace.bytes + name).digest()[:16])
    digest[6] = (digest[6] & 15) | 80
    digest[8] = (digest[8] & 63) | 128
    return str(uuid.UUID(bytes=bytes(digest)))


def vector():
    parts = [MARKER, "sensor-v9-a", "0123456789abcdef" * 4, "exporter-a",
             "collector-a.udp.epoch-1", "42", "123", "0", "1", "0"]
    name = lp(parts)
    assert str(NAMESPACE) == "5a4b3750-4220-5f0e-b506-8f6080b3828c"
    assert len(name) == 175
    assert hashlib.sha1(NAMESPACE.bytes + name).hexdigest() == "3a5978cadf7802f897f89e47e3af8ddeab54b707"
    assert binary_uuid(NAMESPACE, name) == "3a5978ca-df78-52f8-97f8-9e47e3af8dde"


def number(ie, value, width):
    return ie, value.to_bytes(width, "big")


def base(protocol=17):
    return [(8, ipaddress.ip_address("192.0.2.1").packed),
            (12, ipaddress.ip_address("198.51.100.2").packed),
            number(4, protocol, 1), number(22, 8000, 4), number(21, 9000, 4), number(2, 5, 4)]


def replace(fields, ie, value):
    return [(key, value if key == ie else old) for key, old in fields]


def flowset(ident, payload):
    payload += bytes((-(len(payload) + 4)) % 4)
    return struct.pack("!HH", ident, len(payload) + 4) + payload


def wire(fields, repeat=1, uptime=10000, seconds=1700000100, count=None):
    template = struct.pack("!HH", 256, len(fields))
    template += b"".join(struct.pack("!HH", ie, len(value)) for ie, value in fields)
    data = b"".join(value for _, value in fields) * repeat
    return struct.pack("!HHIIII", 9, repeat + 1 if count is None else count,
                       uptime, seconds, 123, 42) + flowset(0, template) + flowset(256, data)


def cases():
    result = []

    def add(name, fields, **kwargs):
        basis = kwargs.pop("basis", "Unknown")
        age = kwargs.pop("age", AGE)
        result.append((name, wire(fields, **kwargs), basis, age, None))

    add("udp_min", base())
    add("tcp_min", base(6))
    v6 = [f for f in base() if f[0] not in (8, 12)] + [
        (27, ipaddress.ip_address("2001:db8::1").packed),
        (28, ipaddress.ip_address("2001:db8::2").packed), number(60, 6, 1)]
    add("ipv6", v6)
    add("icmpv4", base(1) + [number(32, 0x0800, 2)])
    add("packet_only", base() + [number(1, 250, 4)])
    add("byte_only", [f for f in base() if f[0] != 2] + [number(1, 250, 8)], basis="VerifiedIpLayer")
    add("both_counters", base() + [number(1, 250, 8)], basis="VerifiedIpLayer")
    add("zero_counter", replace(base(), 2, bytes(4)))
    wrapped = replace(replace(base(), 22, (0xFFFFFFE0).to_bytes(4, "big")), 21, (0xFFFFFFF0).to_bytes(4, "big"))
    add("uptime_wrap", wrapped, uptime=16)
    add("repeated", base(), repeat=2)
    add("tcp_details", base(6) + [number(7, 0, 2), number(11, 443, 2), number(6, 0xFF, 1),
                                  number(10, 123456789, 8), number(14, 0, 2)])
    add("ipv6_zero", replace(replace(v6, 27, bytes(16)), 28, bytes(16)))
    add("u64_max", replace(base(), 2, bytes.fromhex("ffffffffffffffff")))
    add("duplicate_equal", base() + [number(2, 5, 8)])
    add("deferred_bad_bytes", base() + [(1, bytes(9)), number(23, 999, 8), number(24, 999, 8),
                                       number(34, 10, 4), number(61, 1, 1), (65000, b"opaque")])
    add("sctp", base(132) + [number(7, 1234, 2), number(11, 4321, 2)])
    add("icmpv6", replace(v6, 4, bytes([58])) + [number(139, 0x8000, 2)])
    add("both_families_selected", base() + [f for f in v6 if f[0] in (27, 28, 60)])
    add("millisecond_time", replace(replace(base(), 22, (8123).to_bytes(4, "big")), 21, (9456).to_bytes(4, "big")))
    add("missing_src", [f for f in base() if f[0] != 8])
    add("missing_dst", [f for f in base() if f[0] != 12])
    add("missing_protocol", [f for f in base() if f[0] != 4])
    add("missing_first", [f for f in base() if f[0] != 22])
    add("missing_last", [f for f in base() if f[0] != 21])
    add("no_counter", [f for f in base() if f[0] != 2])
    add("byte_only_unknown", [f for f in base() if f[0] != 2] + [number(1, 250, 4)])
    add("counter_width9", replace(base(), 2, bytes(9)))
    add("active_byte_width9", base() + [(1, bytes(9))], basis="VerifiedIpLayer")
    add("duplicate_conflict", base() + [number(2, 6, 4)])
    add("optional_wrong_width", base() + [number(7, 1, 1)])
    add("ipv6_no_selector", [f for f in v6 if f[0] != 60])
    add("both_no_selector", base() + [f for f in v6 if f[0] in (27, 28)])
    add("mixed_endpoints", [f for f in base() if f[0] != 12] + [(28, ipaddress.ip_address("2001:db8::2").packed)])
    add("invalid_selector", base() + [number(60, 5, 1)])
    add("future_last", replace(base(), 21, (10001).to_bytes(4, "big")))
    add("age_exceeded", base(), uptime=AGE + 9001)
    add("unix_underflow", base(), seconds=0)
    old = REPO / "ingestion/tests/fixtures/export/netflow_v9/real/softflowd_000.bin"
    result.append(("softflowd_negative", old.read_bytes(), "VerifiedIpLayer", AGE,
                   "ingestion/tests/fixtures/export/netflow_v9/real/softflowd_000.bin"))
    return result


def decode_packet(raw):
    """Independent structural decoder for dedicated complete F7 test packets."""
    version, declared, uptime, seconds, sequence, domain = struct.unpack_from("!HHIIII", raw)
    assert version == 9
    templates = {}
    records = []
    parsed = 0
    at = 20
    ordinal = 0
    while at < len(raw):
        ident, length = struct.unpack_from("!HH", raw, at)
        assert length >= 4 and at + length <= len(raw)
        payload = raw[at + 4:at + length]
        if ident in (0, 1):
            pos = 0
            while len(payload) - pos >= (4 if ident == 0 else 6):
                if ident == 0:
                    tid, count = struct.unpack_from("!HH", payload, pos)
                    scope, start = 0, pos + 4
                else:
                    tid, scope_bytes, option_bytes = struct.unpack_from("!HHH", payload, pos)
                    assert scope_bytes % 4 == option_bytes % 4 == 0
                    scope, count, start = scope_bytes // 4, (scope_bytes + option_bytes) // 4, pos + 6
                assert tid >= 256 and count > 0
                fields = [struct.unpack_from("!HH", payload, start + i * 4) for i in range(count)]
                assert all(width > 0 for _, width in fields)
                pos = start + count * 4
                templates[tid] = (ident == 1, scope, fields)
                parsed += 1
            assert len(payload) - pos <= 3 and not any(payload[pos:])
        else:
            options, scope, fields = templates[ident]
            size = sum(width for _, width in fields)
            count, padding = divmod(len(payload), size)
            assert padding <= 3 and not any(payload[count * size:])
            for record in range(count):
                start = record * size
                values = []
                for ie, width in fields:
                    values.append((ie, payload[start:start + width]))
                    start += width
                records.append((ordinal, record, ident, options, values))
            parsed += count
        at += length
        ordinal += 1
    assert at == len(raw)
    return dict(declared=declared, parsed=parsed, uptime=uptime, seconds=seconds,
                sequence=sequence, domain=domain), records


class Reject(Exception):
    pass


def timestamp(ns):
    if ns < 0:
        raise Reject("TimestampArithmeticFailure")
    seconds, nanos = divmod(ns, 1_000_000_000)
    date = EPOCH + dt.timedelta(seconds=seconds)
    fraction = "" if nanos == 0 else "." + f"{nanos:09d}"[:3]
    return date.strftime("%Y-%m-%dT%H:%M:%S") + fraction + "Z"


def normalize(header, fields, source, coords, basis, age):
    values = {}
    duplicate, deferred = False, False
    for ident, raw in fields:
        if ident == 1 and basis == "Unknown":
            deferred = True
            continue
        if ident not in SUPPORTED:
            continue
        width = len(raw)
        expected = SUPPORTED[ident]
        if expected is not None:
            valid = width == expected
        else:
            valid = (2 if ident in (10, 14) else 1) <= width <= 8
        if not valid:
            raise Reject("UnsupportedFieldWidth")
        value = int.from_bytes(raw, "big")
        if ident in values:
            if values[ident] != value:
                raise Reject("AmbiguousField")
            duplicate = True
        values[ident] = value
    if 4 not in values:
        raise Reject("MissingRequiredField")
    version = values.get(60)
    if version is None:
        if 27 in values or 28 in values:
            raise Reject("AddressFamilyConflict")
        version = 4
    if version not in (4, 6):
        raise Reject("InvalidSemanticValue")
    src, dst = (8, 12) if version == 4 else (27, 28)
    if src not in values or dst not in values or 22 not in values or 21 not in values:
        raise Reject("MissingRequiredField")
    end_age = (header["uptime"] - values[21]) % (1 << 32)
    duration = (values[21] - values[22]) % (1 << 32)
    if ((values[21] > header["uptime"] and end_age > min(age, MAX_AGE)) or
            (values[22] > values[21] and duration > min(age, MAX_AGE)) or
            end_age + duration >= 1 << 32):
        raise Reject("FlowTimeOrderingInvalid")
    if end_age > age or duration > age:
        raise Reject("FlowAgeExceeded")
    end_ns = header["seconds"] * 1_000_000_000 - end_age * 1_000_000
    start_ns = end_ns - duration * 1_000_000
    start, end = timestamp(start_ns), timestamp(end_ns)
    if 2 not in values and 1 not in values:
        raise Reject("MissingRequiredField")
    flow = dict(start_time=start, end_time=end,
                src_ip=str(ipaddress.IPv4Address(values[src]) if version == 4 else ipaddress.IPv6Address(values[src])),
                dst_ip=str(ipaddress.IPv4Address(values[dst]) if version == 4 else ipaddress.IPv6Address(values[dst])))
    protocol = values[4]
    if protocol in (6, 17):
        for ident, label in ((7, "src_port"), (11, "dst_port")):
            if ident in values:
                flow[label] = values[ident]
    if protocol == 1 and 32 in values:
        flow["icmp_type"], flow["icmp_code"] = values[32] >> 8, values[32] & 255
    flow.update(ip_protocol=protocol, direction_mode="unidirectional")
    if protocol == 6 and 6 in values:
        flow["tcp_flags"] = [flag for bit, flag in enumerate(("fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr")) if values[6] & (1 << bit)]
    for ident, label in ((10, "ingress_interface"), (14, "egress_interface")):
        if values.get(ident, 0):
            flow[label] = "ifindex:" + str(values[ident])
    counters = {}
    if 2 in values:
        counters["packets"] = values[2]
    if 1 in values:
        counters["ip_bytes"] = values[1]
    flow["counters"] = {"src_to_dst": counters}
    fs, record, tid = coords
    numeric = [str(header["domain"]), str(header["sequence"]), "0", str(fs), str(record)]
    record_id = binary_uuid(NAMESPACE, lp([MARKER, source["sensor_id"], source["input_sha256"], source["exporter_id"], source["session_id"]] + numeric))
    fingerprint = hashlib.sha256(lp(["co-netflow-v9-session-v1", source["exporter_id"], source["session_id"]])).hexdigest()
    source_id = "/".join(["netflow_v9", source["exporter_id"], fingerprint] + numeric)
    provenance = dict(input_mode="export_file", parser_name="sih-ingestion-core-netflow-v9", parser_version="0.1.0",
                      input_sha256=source["input_sha256"], exporter_id=source["exporter_id"],
                      observation_domain_id=header["domain"], template_id=tid, message_sequence=header["sequence"])
    observation = dict(schema_version="1.0", record_id=record_id, source_record_id=source_id, observation_type="flow",
                       telemetry_source="netflow_v9", sensor_id=source["sensor_id"], observed_at=OBSERVED,
                       quality=dict(fidelity="unknown", truncated=False, loss_detected=False), provenance=provenance, data=flow)
    warnings = (["DuplicateEquivalent"] if duplicate else []) + (["DeferredSemanticsObserved"] if deferred else [])
    return observation, warnings


def expected(name, raw, basis, age, existing):
    header, records = decode_packet(raw)
    source = dict(sensor_id="sensor-v9-a", exporter_id="exporter-a", session_id="collector-a.udp.epoch-1",
                  input_sha256=hashlib.sha256(raw).hexdigest())
    observations, diagnostics, coordinates = [], [], []
    rejected, options = 0, 0
    for fs, ordinal, tid, is_option, fields in records:
        coordinates.append(dict(flowset_ordinal=fs, record_ordinal=ordinal, template_id=tid))
        if is_option:
            options += 1
            continue
        try:
            observation, notices = normalize(header, fields, source, (fs, ordinal, tid), basis, age)
            observations.append(observation)
            diagnostics.extend(notices)
        except Reject as error:
            rejected += 1
            diagnostics.append(str(error))
    count = "Match" if header["declared"] == header["parsed"] else "Mismatch"
    data = "".join(json.dumps(item, separators=(",", ":"), ensure_ascii=False) + "\n" for item in observations)
    metadata = dict(name=name, evidence_kind="synthetic independently specified" if existing is None else "frozen real negative",
                    wire_format="ASCII hex -> decoded datagram bytes" if existing is None else "existing binary",
                    existing_wire=existing, wire_sha256=source["input_sha256"], source_context=source,
                    observed_at=OBSERVED, input_mode="export_file", byte_basis_profile=basis, max_flow_age_ms=age,
                    parser_count=count, declared_count=header["declared"], parsed_count=header["parsed"],
                    parser_completion="Complete" if count == "Match" else "CompleteWithDiagnostics", session_disposition="Continue",
                    records_inspected=len(records), records_emitted=len(observations), records_rejected=rejected,
                    options_records_ignored=options, diagnostics=diagnostics, coordinates=coordinates,
                    normalization_status="Complete" if count == "Match" and not diagnostics else "CompleteWithRejectionsOrWarnings",
                    golden_sha256=hashlib.sha256(data.encode()).hexdigest(), newline_policy="UTF-8 without BOM; LF after every record; zero-output file empty")
    return metadata, data


def fixture_contents():
    content = {}
    for name, raw, basis, age, existing in cases():
        metadata, data = expected(name, raw, basis, age, existing)
        if existing is None:
            content[f"wire/{name}.hex"] = raw.hex() + "\n"
            content[f"wire/{name}.sha256"] = metadata["wire_sha256"] + "\n"
        content[f"golden/{name}.jsonl"] = data
        content[f"golden/{name}.sha256"] = metadata["golden_sha256"] + "\n"
        content[f"metadata/{name}.json"] = json.dumps(metadata, indent=2) + "\n"
    return content


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-patch", action="store_true")
    args = parser.parse_args()
    vector()
    content = fixture_contents()
    if args.emit_patch:
        print("*** Begin Patch")
        for path, value in content.items():
            print("*** Add File: ingestion/tests/fixtures/export/netflow_v9_canonical/" + path)
            for line in value.splitlines():
                print("+" + line)
        print("*** End Patch")
        return
    failures = []
    for path, value in content.items():
        actual = ROOT / path
        if not actual.is_file() or actual.read_bytes() != value.encode():
            failures.append(path)
    expected_paths = set(content)
    actual_paths = {str(p.relative_to(ROOT)).replace("\\", "/") for p in ROOT.rglob("*") if p.is_file()}
    if actual_paths != expected_paths:
        failures.append("unexpected/missing fixture inventory")
    if failures:
        raise SystemExit("F7 ORACLE FAIL: " + ", ".join(failures))
    totals = [expected(*case)[0] for case in cases()]
    positives = sum(m["records_emitted"] > 0 for m in totals)
    records = sum(m["records_emitted"] for m in totals)
    print(f"F7 ORACLE PASS={len(totals)} FAIL=0 positive_fixtures={positives} negative_fixtures={len(totals)-positives} canonical_records={records} files={len(content)} UUID_VECTOR=PASS")


if __name__ == "__main__":
    main()
