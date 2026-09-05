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
# --ja4 uses a separately built, integrity-checked, immutable local image and
# also enables deterministic UIDs. It never pulls or installs at runtime.
#
set -euo pipefail

PCAP="${1:?Usage: run_zeek.sh <pcap> [output_dir] [--canonical|--ja4]}"
OUT_DIR="${2:-zeek_output}"
MODE="${3:-}"

FROZEN_IMAGE="zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"
IMAGE="$FROZEN_IMAGE"
PLATFORM_ARGS=()
ZEEK_ARGS=(-C -r)
ZEEK_POLICY=(local)
JA4_PROFILE=false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INGESTION_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

verify_hash() {
  local expected="$1"
  local path="$2"
  if [[ ! -f "$path" ]]; then
    echo "Error: required JA4 runtime input is missing: $path" >&2
    exit 1
  fi
  local actual
  actual="$(hash_file "$path")"
  if [[ "$actual" != "$expected" ]]; then
    echo "Error: JA4 runtime input integrity failure: $path" >&2
    echo "expected=$expected actual=$actual" >&2
    exit 1
  fi
}

verify_image_label() {
  local name="$1"
  local expected="$2"
  local actual
  actual="$(docker image inspect "$JA4_IMAGE_ID" --format "{{ index .Config.Labels \"$name\" }}")"
  if [[ "$actual" != "$expected" ]]; then
    echo "Error: JA4 image label $name failed qualification" >&2
    echo "expected=$expected actual=$actual" >&2
    exit 1
  fi
}

qualify_ja4_runtime() {
  local lock_file="$INGESTION_ROOT/runtime/ja4-runtime.lock"
  if [[ ! -f "$lock_file" ]]; then
    echo "Error: qualified JA4 runtime lock is missing: $lock_file" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  source "$lock_file"

  verify_hash "$JA4_DOCKERFILE_SHA256" "$INGESTION_ROOT/docker/ja4/Dockerfile"
  verify_hash "$JA4_SOURCE_MANIFEST_SHA256" "$INGESTION_ROOT/vendor/ja4-zeek/SOURCE-MANIFEST.sha256"
  verify_hash "$JA4_LOADER_SHA256" "$INGESTION_ROOT/runtime/ja4-only.zeek"
  (
    cd "$INGESTION_ROOT/vendor/ja4-zeek"
    sha256sum --check --strict SOURCE-MANIFEST.sha256 >/dev/null
  ) || {
    echo "Error: vendored JA4 source integrity check failed" >&2
    exit 1
  }

  if ! docker image inspect "$JA4_IMAGE_TAG" >/dev/null 2>&1; then
    echo "Error: qualified JA4 image is unavailable locally: $JA4_IMAGE_TAG" >&2
    echo "Build it explicitly with scripts/build_ja4_runtime.sh; runtime fallback is forbidden." >&2
    exit 1
  fi
  local tag_id
  tag_id="$(docker image inspect "$JA4_IMAGE_TAG" --format '{{.Id}}')"
  if [[ "$tag_id" != "$JA4_IMAGE_ID" ]]; then
    echo "Error: local JA4 image tag does not match the locked image identity" >&2
    echo "expected=$JA4_IMAGE_ID actual=$tag_id" >&2
    exit 1
  fi

  verify_image_label io.sih.zeek.base-digest "${JA4_BASE_IMAGE##*@}"
  verify_image_label io.sih.ja4.upstream-commit "$JA4_UPSTREAM_COMMIT"
  verify_image_label io.sih.ja4.upstream-tree "$JA4_UPSTREAM_TREE"
  verify_image_label io.sih.ja4.upstream-archive-sha256 "$JA4_UPSTREAM_ARCHIVE_SHA256"
  verify_image_label io.sih.ja4.source-manifest-sha256 "$JA4_SOURCE_MANIFEST_SHA256"
  verify_image_label io.sih.ja4.loader-sha256 "$JA4_LOADER_SHA256"

  IMAGE="$JA4_IMAGE_ID"
}
case "$MODE" in
  "")
    ;;
  --canonical)
    PLATFORM_ARGS=(--platform linux/amd64)
    ZEEK_ARGS=(-D -C -r)
    ;;
  --ja4)
    JA4_PROFILE=true
    PLATFORM_ARGS=(--platform linux/amd64)
    ZEEK_ARGS=(-D -C -r)
    ZEEK_POLICY=(local /usr/local/zeek/share/zeek/site/ja4-only.zeek)
    qualify_ja4_runtime
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

docker_host_path() {
  local resolved
  resolved="$(realpath "$1")"
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$resolved"
  else
    printf '%s\n' "$resolved"
  fi
}

PCAP_DIR="$(docker_host_path "$(dirname "$PCAP")")"
PCAP_NAME="$(basename "$PCAP")"

mkdir -p "$OUT_DIR"
OUT_DOCKER_DIR="$(docker_host_path "$OUT_DIR")"

MSYS_NO_PATHCONV=1 docker run --rm "${PLATFORM_ARGS[@]}" \
  -v "$PCAP_DIR":/pcaps:ro \
  -w /output \
  -v "$OUT_DOCKER_DIR":/output \
  "$IMAGE" \
  zeek "${ZEEK_ARGS[@]}" "/pcaps/$PCAP_NAME" "${ZEEK_POLICY[@]}"

if [[ "$JA4_PROFILE" == true ]]; then
  bash "$SCRIPT_DIR/validate_ja4_logs.sh" "$OUT_DIR"
fi

echo "[+] Logs written to $OUT_DIR"
ls -1 "$OUT_DIR"
