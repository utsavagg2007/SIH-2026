#!/usr/bin/env bash
# Rebuild the repository-controlled JA4 runtime and verify its locked identity.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INGESTION_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCK_FILE="$INGESTION_ROOT/runtime/ja4-runtime.lock"

if [[ ! -f "$LOCK_FILE" ]]; then
  echo "Error: JA4 runtime lock is missing: $LOCK_FILE" >&2
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
    echo "Error: required JA4 build input is missing: $path" >&2
    exit 1
  fi
  local actual
  actual="$(hash_file "$path")"
  if [[ "$actual" != "$expected" ]]; then
    echo "Error: JA4 build input integrity failure: $path" >&2
    echo "expected=$expected actual=$actual" >&2
    exit 1
  fi
}

verify_hash "$JA4_DOCKERFILE_SHA256" "$INGESTION_ROOT/docker/ja4/Dockerfile"
verify_hash "$JA4_SOURCE_MANIFEST_SHA256" "$INGESTION_ROOT/vendor/ja4-zeek/SOURCE-MANIFEST.sha256"
verify_hash "$JA4_LOADER_SHA256" "$INGESTION_ROOT/runtime/ja4-only.zeek"
(
  cd "$INGESTION_ROOT/vendor/ja4-zeek"
  sha256sum --check --strict SOURCE-MANIFEST.sha256
)

iid_file="$(mktemp)"
trap 'rm -f "$iid_file"' EXIT

docker build \
  --platform "$JA4_BUILD_PLATFORM" \
  --no-cache \
  --provenance=false \
  --build-arg "SOURCE_DATE_EPOCH=$JA4_BUILD_EPOCH" \
  --iidfile "$iid_file" \
  --tag "$JA4_IMAGE_TAG" \
  --file "$INGESTION_ROOT/docker/ja4/Dockerfile" \
  "$INGESTION_ROOT"

actual_config_digest="$(tr -d '\r\n' < "$iid_file")"
if [[ "$actual_config_digest" != "$JA4_CONFIG_DIGEST" ]]; then
  echo "Error: rebuilt JA4 config digest differs from the runtime lock" >&2
  echo "expected=$JA4_CONFIG_DIGEST actual=$actual_config_digest" >&2
  exit 1
fi

actual_id="$(docker image inspect "$JA4_IMAGE_TAG" --format '{{.Id}}')"
if [[ "$actual_id" != "$JA4_IMAGE_ID" ]]; then
  echo "Error: rebuilt JA4 image identity differs from the runtime lock" >&2
  echo "expected=$JA4_IMAGE_ID actual=$actual_id" >&2
  exit 1
fi

echo "[+] Qualified JA4 runtime rebuilt: $actual_id"
