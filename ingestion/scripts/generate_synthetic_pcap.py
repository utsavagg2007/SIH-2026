#!/usr/bin/env python3
"""Generate deterministic, non-sensitive M1D and JA4 PCAP fixtures.

The fixture uses only IANA documentation address ranges and Python's standard
library. Packet timestamps, sequence numbers, headers, and payloads are fixed.
The primary fixture contains one UDP DNS transaction, one TCP DNS transaction,
one HTTP/1.1 connection with two requests, and one minimal TLS handshake. A
separate cardinality fixture contains five DNS transactions on one UDP flow.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import socket
import struct


CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
PACKETS: list[tuple[int, int, bytes]] = []
IP_ID = 100


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet(payload: bytes, client_to_server: bool) -> bytes:
    source = CLIENT_MAC if client_to_server else SERVER_MAC
    destination = SERVER_MAC if client_to_server else CLIENT_MAC
    return destination + source + struct.pack("!H", 0x0800) + payload


def ipv4(source: str, destination: str, protocol: int, payload: bytes) -> bytes:
    global IP_ID
    source_bytes = socket.inet_aton(source)
    destination_bytes = socket.inet_aton(destination)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        IP_ID,
        0x4000,
        64,
        protocol,
        0,
        source_bytes,
        destination_bytes,
    )
    IP_ID += 1
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def add_udp(
    second: int,
    microsecond: int,
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
) -> None:
    pseudo = socket.inet_aton(source) + socket.inet_aton(destination)
    length = 8 + len(payload)
    header = struct.pack("!HHHH", source_port, destination_port, length, 0)
    udp_checksum = checksum(pseudo + struct.pack("!BBH", 0, 17, length) + header + payload)
    header = struct.pack("!HHHH", source_port, destination_port, length, udp_checksum)
    frame = ethernet(ipv4(source, destination, 17, header + payload), source_port != 53)
    PACKETS.append((second, microsecond, frame))


def add_tcp(
    second: int,
    microsecond: int,
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgment: int,
    flags: int,
    payload: bytes = b"",
) -> None:
    offset_flags = (5 << 12) | flags
    header = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgment,
        offset_flags,
        65535,
        0,
        0,
    )
    pseudo = socket.inet_aton(source) + socket.inet_aton(destination)
    length = len(header) + len(payload)
    tcp_checksum = checksum(pseudo + struct.pack("!BBH", 0, 6, length) + header + payload)
    header = header[:16] + struct.pack("!H", tcp_checksum) + header[18:]
    client_to_server = destination_port in {53, 80, 443}
    frame = ethernet(ipv4(source, destination, 6, header + payload), client_to_server)
    PACKETS.append((second, microsecond, frame))


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"


def dns_query(transaction: int, name: str) -> bytes:
    return struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def dns_response(transaction: int, name: str, address: str) -> bytes:
    question = dns_name(name) + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    return struct.pack("!HHHHHH", transaction, 0x8180, 1, 1, 0, 0) + question + answer


def tcp_session(
    second: int,
    client: str,
    server: str,
    client_port: int,
    server_port: int,
    exchanges: list[tuple[bytes, bytes]],
    client_sequence: int,
    server_sequence: int,
) -> None:
    tick = 0

    def emit(
        source: str,
        destination: str,
        source_port: int,
        destination_port: int,
        sequence: int,
        acknowledgment: int,
        flags: int,
        payload: bytes = b"",
    ) -> None:
        nonlocal tick
        add_tcp(
            second,
            tick * 10_000,
            source,
            destination,
            source_port,
            destination_port,
            sequence,
            acknowledgment,
            flags,
            payload,
        )
        tick += 1

    emit(client, server, client_port, server_port, client_sequence, 0, 0x02)
    emit(server, client, server_port, client_port, server_sequence, client_sequence + 1, 0x12)
    client_sequence += 1
    server_sequence += 1
    emit(client, server, client_port, server_port, client_sequence, server_sequence, 0x10)

    for request, response in exchanges:
        emit(client, server, client_port, server_port, client_sequence, server_sequence, 0x18, request)
        client_sequence += len(request)
        emit(server, client, server_port, client_port, server_sequence, client_sequence, 0x18, response)
        server_sequence += len(response)
        emit(client, server, client_port, server_port, client_sequence, server_sequence, 0x10)

    emit(client, server, client_port, server_port, client_sequence, server_sequence, 0x11)
    client_sequence += 1
    emit(server, client, server_port, client_port, server_sequence, client_sequence, 0x11)
    server_sequence += 1
    emit(client, server, client_port, server_port, client_sequence, server_sequence, 0x10)


def tls_handshake(
    server_name: str | None = "tls.example.test",
    cipher_suites: bytes = b"\x13\x01\xc0\x2f",
    selected_cipher: bytes = b"\x13\x01",
) -> tuple[bytes, bytes]:
    sni = b""
    if server_name is not None:
        encoded_name = server_name.encode("ascii")
        name_list = (
            struct.pack("!HBH", len(encoded_name) + 3, 0, len(encoded_name))
            + encoded_name
        )
        sni = struct.pack("!HH", 0, len(name_list)) + name_list
    versions = struct.pack("!HHBHH", 0x002B, 5, 4, 0x0304, 0x0303)
    extensions = sni + versions
    client_body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + struct.pack("!H", len(cipher_suites))
        + cipher_suites
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    client_handshake = b"\x01" + len(client_body).to_bytes(3, "big") + client_body
    client_record = b"\x16\x03\x01" + struct.pack("!H", len(client_handshake)) + client_handshake

    selected_version = struct.pack("!HHH", 0x002B, 2, 0x0304)
    server_body = (
        b"\x03\x03"
        + bytes(range(32, 64))
        + b"\x00"
        + selected_cipher
        + b"\x00"
        + struct.pack("!H", len(selected_version))
        + selected_version
    )
    server_handshake = b"\x02" + len(server_body).to_bytes(3, "big") + server_body
    server_record = b"\x16\x03\x03" + struct.pack("!H", len(server_handshake)) + server_handshake
    return client_record, server_record


def build_fixture() -> bytes:
    PACKETS.clear()
    global IP_ID
    IP_ID = 100

    udp_name = "udp.example.test"
    add_udp(1_700_000_000, 0, "192.0.2.10", "198.51.100.53", 53000, 53, dns_query(0x1001, udp_name))
    add_udp(1_700_000_000, 50_000, "198.51.100.53", "192.0.2.10", 53, 53000, dns_response(0x1001, udp_name, "203.0.113.10"))

    tcp_name = "tcp.example.test"
    tcp_query = dns_query(0x1002, tcp_name)
    tcp_response = dns_response(0x1002, tcp_name, "203.0.113.11")
    tcp_session(
        1_700_000_001,
        "192.0.2.11",
        "198.51.100.53",
        53001,
        53,
        [(struct.pack("!H", len(tcp_query)) + tcp_query, struct.pack("!H", len(tcp_response)) + tcp_response)],
        10_000,
        20_000,
    )

    request_one = b"GET /one HTTP/1.1\r\nHost: http.example.test\r\nUser-Agent: SIH-M1D\r\n\r\n"
    response_one = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none"
    request_two = b"POST /two HTTP/1.1\r\nHost: http.example.test\r\nUser-Agent: SIH-M1D\r\nContent-Length: 3\r\n\r\ntwo"
    response_two = b"HTTP/1.1 201 Created\r\nContent-Length: 3\r\n\r\ntwo"
    tcp_session(
        1_700_000_002,
        "192.0.2.20",
        "198.51.100.80",
        40000,
        80,
        [(request_one, response_one), (request_two, response_two)],
        30_000,
        40_000,
    )

    client_hello, server_hello = tls_handshake()
    tcp_session(
        1_700_000_003,
        "192.0.2.30",
        "198.51.100.44",
        41000,
        443,
        [(client_hello, server_hello)],
        50_000,
        60_000,
    )

    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for second, microsecond, frame in PACKETS:
        output.extend(struct.pack("<IIII", second, microsecond, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def build_empty_fixture() -> bytes:
    """A valid Ethernet PCAP containing zero packets."""
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def build_ja4_fixture() -> bytes:
    """Two deterministic TLS flows with distinct real client fingerprints."""
    PACKETS.clear()
    global IP_ID
    IP_ID = 500

    first_client, first_server = tls_handshake()
    tcp_session(
        1_700_000_100,
        "192.0.2.31",
        "198.51.100.44",
        42000,
        443,
        [(first_client, first_server)],
        70_000,
        80_000,
    )

    second_client, second_server = tls_handshake(
        server_name=None,
        cipher_suites=b"\x13\x02\x13\x03\xc0\x2f",
        selected_cipher=b"\x13\x02",
    )
    tcp_session(
        1_700_000_101,
        "192.0.2.32",
        "198.51.100.45",
        42001,
        443,
        [(second_client, second_server)],
        90_000,
        100_000,
    )

    output = bytearray(build_empty_fixture())
    for second, microsecond, frame in PACKETS:
        output.extend(struct.pack("<IIII", second, microsecond, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def build_transaction_fixture() -> bytes:
    """Five DNS transactions on one deterministic UDP connection/UID."""
    PACKETS.clear()
    global IP_ID
    IP_ID = 800

    second = 1_700_000_200
    for index in range(5):
        transaction = 0x2001 + index
        name = f"txn-{index + 1}.example.test"
        request_tick = index * 100_000
        add_udp(
            second,
            request_tick,
            "192.0.2.40",
            "198.51.100.53",
            54000,
            53,
            dns_query(transaction, name),
        )
        add_udp(
            second,
            request_tick + 50_000,
            "198.51.100.53",
            "192.0.2.40",
            53,
            54000,
            dns_response(transaction, name, f"203.0.113.{40 + index}"),
        )

    output = bytearray(build_empty_fixture())
    for packet_second, microsecond, frame in PACKETS:
        output.extend(
            struct.pack("<IIII", packet_second, microsecond, len(frame), len(frame))
        )
        output.extend(frame)
    return bytes(output)


def build_invalid_fixture() -> bytes:
    """A deterministically truncated packet record for Zeek failure testing."""
    output = bytearray(build_empty_fixture())
    output.extend(struct.pack("<IIII", 1_700_000_010, 0, 64, 64))
    output.extend(b"truncated")
    return bytes(output)


def build_unsupported_fixture() -> bytes:
    """One ARP request: stable link telemetry but no supported v1 observation."""
    arp = (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        + CLIENT_MAC
        + socket.inet_aton("192.0.2.1")
        + b"\x00" * 6
        + socket.inet_aton("192.0.2.2")
    )
    frame = b"\xff" * 6 + CLIENT_MAC + struct.pack("!H", 0x0806) + arp
    output = bytearray(build_empty_fixture())
    output.extend(struct.pack("<IIII", 1_700_000_020, 0, len(frame), len(frame)))
    output.extend(frame)
    return bytes(output)


def write_fixture(path: Path, payload: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    path.with_suffix(path.suffix + ".sha256").write_text(
        f"{digest}  {path.name}\n", encoding="ascii", newline="\n"
    )
    return digest


def main() -> None:
    default_output = Path(__file__).parent.parent / "tests" / "fixtures" / "pcap" / "m1d_synthetic.pcap"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=default_output)
    parser.add_argument(
        "--ja4-output",
        type=Path,
        help="also write the two-flow JA4 qualification fixture",
    )
    parser.add_argument(
        "--transaction-output",
        type=Path,
        help="also write the five-row DNS cardinality qualification fixture",
    )
    parser.add_argument(
        "--auxiliary-directory",
        type=Path,
        help="also write deterministic empty, invalid, and unsupported-only fixtures",
    )
    args = parser.parse_args()
    payload = build_fixture()
    digest = write_fixture(args.output, payload)
    packet_count = len(PACKETS)
    if args.ja4_output is not None:
        write_fixture(args.ja4_output, build_ja4_fixture())
    if args.transaction_output is not None:
        write_fixture(args.transaction_output, build_transaction_fixture())
    if args.auxiliary_directory is not None:
        for name, auxiliary in [
            ("m1d_empty.pcap", build_empty_fixture()),
            ("m1d_invalid_truncated.pcap", build_invalid_fixture()),
            ("m1d_unsupported_arp.pcap", build_unsupported_fixture()),
        ]:
            write_fixture(args.auxiliary_directory / name, auxiliary)
    print(f"wrote {packet_count} packets, {len(payload)} bytes, sha256={digest}")


if __name__ == "__main__":
    main()
