#!/usr/bin/env bash
#
# run_zeek.sh — Run Zeek (via Docker) on a PCAP and emit structured logs.
#
# Usage:
#   ./run_zeek.sh <pcap> [output_dir] [--canonical|--ja4]
#
# Examples:
#   ./run_zeek.sh pcaps/capture.pcap
#   ./run_zeek.sh pcaps/capture.pcap zeek_output
#   ./run_zeek.sh pcaps/capture.pcap zeek_output --canonical
#   ./run_zeek.sh pcaps/capture.pcap zeek_output --ja4
#
# Default and canonical modes use the frozen, digest-pinned M1D runtime.
# Canonical mode additionally enables deterministic Zeek UIDs with -D.
# --ja4 retains the legacy third-party image and is intentionally rejected by
# the canonical producer because that runtime has not been qualified for it.
#
set -euo pipefail

PCAP="${1:?Usage: run_zeek.sh <pcap> [output_dir] [--canonical|--ja4]}"
OUT_DIR="${2:-zeek_output}"
MODE="${3:-}"

FROZEN_IMAGE="zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"
IMAGE="$FROZEN_IMAGE"
PLATFORM_ARGS=()
ZEEK_ARGS=(-C -r)
case "$MODE" in
  "")
    ;;
  --canonical)
    PLATFORM_ARGS=(--platform linux/amd64)
    ZEEK_ARGS=(-D -C -r)
    ;;
  --ja4)
    IMAGE="activecm/zeek:8.0.6"
    ;;
  *)
    echo "Error: unsupported mode '$MODE' (expected --canonical or --ja4)" >&2
    exit 2
    ;;
esac

if [[ ! -f "$PCAP" ]]; then
  echo "Error: PCAP file not found: $PCAP" >&2
  exit 1
fi

PCAP_DIR="$(dirname "$(realpath "$PCAP")")"
PCAP_NAME="$(basename "$PCAP")"

mkdir -p "$OUT_DIR"

docker run --rm "${PLATFORM_ARGS[@]}" \
  -v "$PCAP_DIR":/pcaps:ro \
  -w /output \
  -v "$(realpath "$OUT_DIR")":/output \
  "$IMAGE" \
  zeek "${ZEEK_ARGS[@]}" "/pcaps/$PCAP_NAME" local

echo "[+] Logs written to $OUT_DIR"
ls -1 "$OUT_DIR"
