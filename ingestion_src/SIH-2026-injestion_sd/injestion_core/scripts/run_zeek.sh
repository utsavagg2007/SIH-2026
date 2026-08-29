#!/usr/bin/env bash
#
# run_zeek.sh — Run Zeek (via Docker) on a PCAP and emit structured logs.
#
# Usage:
#   ./run_zeek.sh <pcap> [output_dir] [--ja4]
#
# Examples:
#   ./run_zeek.sh pcaps/capture.pcap
#   ./run_zeek.sh pcaps/capture.pcap zeek_output
#   ./run_zeek.sh pcaps/capture.pcap zeek_output --ja4
#
# The default image (zeek/zeek:latest) produces conn.log, dns.log,
# http.log, ssl.log, etc. Pass --ja4 to use activecm/zeek which adds
# JA3/JA4 TLS fingerprints needed for encrypted-malware detection.
#
set -euo pipefail

PCAP="${1:?Usage: run_zeek.sh <pcap> [output_dir] [--ja4]}"
OUT_DIR="${2:-zeek_output}"
JA4_FLAG="${3:-}"

IMAGE="zeek/zeek:latest"
if [[ "$JA4_FLAG" == "--ja4" ]]; then
  IMAGE="activecm/zeek:8.0.6"
fi

if [[ ! -f "$PCAP" ]]; then
  echo "Error: PCAP file not found: $PCAP" >&2
  exit 1
fi

PCAP_DIR="$(dirname "$(realpath "$PCAP")")"
PCAP_NAME="$(basename "$PCAP")"

mkdir -p "$OUT_DIR"

docker run --rm \
  -v "$PCAP_DIR":/pcaps:ro \
  -w /output \
  -v "$(realpath "$OUT_DIR")":/output \
  "$IMAGE" \
  zeek -C -r "/pcaps/$PCAP_NAME" local

echo "[+] Logs written to $OUT_DIR"
ls -1 "$OUT_DIR"
