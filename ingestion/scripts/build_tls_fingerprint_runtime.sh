#!/usr/bin/env bash
# Rebuild and verify the repository-controlled JA3/JA3S/JA4 runtime.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INGESTION_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCK_FILE="$INGESTION_ROOT/runtime/tls-fingerprint-runtime.lock"

if [[ ! -f "$LOCK_FILE" ]]; then
  echo "Error: TLS fingerprint runtime lock is missing: $LOCK_FILE" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$LOCK_FILE"

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

verify_hash() {
  local expected="$1"
  local path="$2"
  if [[ ! -f "$path" ]]; then
    echo "Error: required TLS fingerprint build input is missing: $path" >&2
    exit 1
  fi
  local actual
  actual="$(hash_file "$path")"
  if [[ "$actual" != "$expected" ]]; then
    echo "Error: TLS fingerprint build input integrity failure: $path" >&2
    echo "expected=$expected actual=$actual" >&2
    exit 1
  fi
}

verify_hash "$TLS_FP_DOCKERFILE_SHA256" "$INGESTION_ROOT/docker/tls-fingerprints/Dockerfile"
verify_hash "$TLS_FP_LOADER_SHA256" "$INGESTION_ROOT/runtime/tls-fingerprints.zeek"
verify_hash "$JA3_SOURCE_MANIFEST_SHA256" "$INGESTION_ROOT/vendor/ja3-zeek/SOURCE-MANIFEST.sha256"
verify_hash "$JA4_SOURCE_MANIFEST_SHA256" "$INGESTION_ROOT/vendor/ja4-zeek/SOURCE-MANIFEST.sha256"
(
  cd "$INGESTION_ROOT/vendor/ja3-zeek"
  sha256sum --check --strict SOURCE-MANIFEST.sha256
)
(
  cd "$INGESTION_ROOT/vendor/ja4-zeek"
  sha256sum --check --strict SOURCE-MANIFEST.sha256
)

iid_file="$(mktemp)"
trap 'rm -f "$iid_file"' EXIT

docker build \
  --platform "$TLS_FP_BUILD_PLATFORM" \
  --network none \
  --no-cache \
  --provenance=false \
  --build-arg "SOURCE_DATE_EPOCH=$TLS_FP_BUILD_EPOCH" \
  --iidfile "$iid_file" \
  --tag "$TLS_FP_IMAGE_TAG" \
  --file "$INGESTION_ROOT/docker/tls-fingerprints/Dockerfile" \
  "$INGESTION_ROOT"

actual_config_digest="$(tr -d '\r\n' < "$iid_file")"
if [[ "$actual_config_digest" != "$TLS_FP_CONFIG_DIGEST" ]]; then
  echo "Error: rebuilt TLS fingerprint config digest differs from the runtime lock" >&2
  echo "expected=$TLS_FP_CONFIG_DIGEST actual=$actual_config_digest" >&2
  exit 1
fi

actual_id="$(docker image inspect "$TLS_FP_IMAGE_TAG" --format '{{.Id}}')"
if [[ "$actual_id" != "$TLS_FP_IMAGE_ID" ]]; then
  echo "Error: rebuilt TLS fingerprint image identity differs from the runtime lock" >&2
  echo "expected=$TLS_FP_IMAGE_ID actual=$actual_id" >&2
  exit 1
fi

echo "[+] Qualified TLS fingerprint runtime rebuilt: $actual_id"
