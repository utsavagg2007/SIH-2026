#!/usr/bin/env bash
# Fail closed if full fingerprint mode did not expose exactly its three fields.
set -euo pipefail

OUT_DIR="${1:?Usage: validate_tls_fingerprint_logs.sh <zeek_output_dir>}"
SSL_LOG="$OUT_DIR/ssl.log"

if [[ ! -f "$SSL_LOG" ]]; then
  echo "[tls-fingerprints] diagnostic: no ssl.log was emitted; the PCAP contained no recognized TLS source rows" >&2
  exit 0
fi

read -r ja3_column ja3s_column ja4_column tls_rows ja3_values ja3s_values ja4_values < <(
  awk -F '\t' '
    /^#fields/ {
      for (i = 2; i <= NF; i++) {
        if ($i == "ja3") ja3_column = i - 1
        if ($i == "ja3s") ja3s_column = i - 1
        if ($i == "ja4") ja4_column = i - 1
      }
      next
    }
    !/^#/ && NF > 1 {
      tls_rows++
      if (ja3_column > 0 && $ja3_column != "" && $ja3_column != "-" && $ja3_column != "(empty)") ja3_values++
      if (ja3s_column > 0 && $ja3s_column != "" && $ja3s_column != "-" && $ja3s_column != "(empty)") ja3s_values++
      if (ja4_column > 0 && $ja4_column != "" && $ja4_column != "-" && $ja4_column != "(empty)") ja4_values++
    }
    END { printf "%d %d %d %d %d %d %d\n", ja3_column, ja3s_column, ja4_column, tls_rows, ja3_values, ja3s_values, ja4_values }
  ' "$SSL_LOG"
)

if [[ "$ja3_column" -eq 0 || "$ja3s_column" -eq 0 || "$ja4_column" -eq 0 ]]; then
  echo "Error: qualified TLS fingerprint mode emitted ssl.log without required ja3, ja3s, and ja4 fields" >&2
  exit 1
fi

if [[ "$tls_rows" -gt 0 && ( "$ja3_values" -eq 0 || "$ja3s_values" -eq 0 || "$ja4_values" -eq 0 ) ]]; then
  echo "[tls-fingerprints] diagnostic: some fingerprint types had no source value; unavailable values remain null" >&2
fi

for field in ja4s ja4h ja4l ja4ls ja4t ja4ts ja4ssh ja4x ja4d; do
  if awk -F '\t' -v forbidden="$field" '/^#fields/ { for (i = 2; i <= NF; i++) if ($i == forbidden) exit 0; exit 1 } END { if (NR == 0) exit 1 }' "$SSL_LOG"; then
    echo "Error: qualified TLS fingerprint mode exposed forbidden field $field" >&2
    exit 1
  fi
done

echo "[tls-fingerprints] ssl.log source fields verified: rows=$tls_rows ja3=$ja3_values ja3s=$ja3s_values ja4=$ja4_values" >&2
