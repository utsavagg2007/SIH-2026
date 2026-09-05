#!/usr/bin/env bash
# Validate the post-run contract of the qualified JA4-only Zeek profile.
set -euo pipefail

OUT_DIR="${1:?Usage: validate_ja4_logs.sh <zeek_output_dir>}"

if [[ ! -f "$OUT_DIR/ssl.log" ]]; then
  echo "[ja4] diagnostic: no ssl.log was emitted; the PCAP contained no recognized TLS source rows" >&2
else
  read -r ja4_column tls_rows ja4_values < <(
    awk -F '\t' '
      $1 == "#fields" {
        for (i = 2; i <= NF; i++) if ($i == "ja4") ja4_column = i - 1
        next
      }
      $0 !~ /^#/ && NF > 0 {
        tls_rows++
        if (ja4_column > 0 && $ja4_column != "" && $ja4_column != "-" && $ja4_column != "(empty)") ja4_values++
      }
      END { printf "%d %d %d\n", ja4_column, tls_rows, ja4_values }
    ' "$OUT_DIR/ssl.log"
  )
  if [[ "$ja4_column" -eq 0 ]]; then
    echo "Error: qualified JA4 mode emitted ssl.log without the required ja4 field" >&2
    exit 1
  fi
  if [[ "$tls_rows" -gt 0 && "$ja4_values" -eq 0 ]]; then
    echo "[ja4] diagnostic: ssl.log contains TLS rows but no source JA4 value was available; values remain null" >&2
  fi
fi

for log_path in "$OUT_DIR"/*.log; do
  [[ -f "$log_path" ]] || continue
  if awk -F '\t' '
    $1 == "#fields" {
      for (i = 2; i <= NF; i++)
        if ($i == "ja4s" || $i == "ja4h" || $i == "ja4l" || $i == "ja4ls" ||
            $i == "ja4t" || $i == "ja4ts" || $i == "ja4ssh" || $i == "ja4x" || $i == "ja4d")
          exit 0
      exit 1
    }
    END { if (NR == 0) exit 1 }
  ' "$log_path"; then
    echo "Error: JA4-only runtime emitted a forbidden JA4+ field in $log_path" >&2
    exit 1
  fi
done
