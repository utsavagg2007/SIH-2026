/**
 * Formatters.
 *
 * Copy rule (spec section 9): words in this interface are readouts, not
 * commentary. Factual, present tense, no hedging. A missing value is an em
 * dash, never "N/A" or "unknown".
 */

const DASH = "—";

export const fmt = {
  /** An evidence value with its unit, or a dash when absent. */
  value(v: unknown, unit?: string | null): string {
    if (v === null || v === undefined) return DASH;
    if (typeof v === "boolean") return v ? "yes" : "no";
    if (typeof v === "number") {
      if (!Number.isFinite(v)) return DASH;
      const n = fmt.compact(v);
      return unit ? `${n} ${unit}` : n;
    }
    return String(v);
  },

  compact(v: number): string {
    if (!Number.isFinite(v)) return DASH;
    const a = Math.abs(v);
    if (a >= 1e9) return `${(v / 1e9).toFixed(2)}G`;
    if (a >= 1e6) return `${(v / 1e6).toFixed(2)}M`;
    if (a >= 1e4) return `${(v / 1e3).toFixed(1)}k`;
    if (a >= 100) return v.toFixed(0);
    if (a >= 1) return v.toFixed(2).replace(/\.00$/, "");
    if (a === 0) return "0";
    return v.toPrecision(3);
  },

  bytes(v: unknown): string {
    if (typeof v !== "number" || !Number.isFinite(v)) return DASH;
    const units = ["B", "KB", "MB", "GB", "TB"];
    let n = v;
    let i = 0;
    while (n >= 1024 && i < units.length - 1) {
      n /= 1024;
      i += 1;
    }
    return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  },

  /** Wall-clock time from epoch seconds, to millisecond precision. */
  clock(epoch: number): string {
    if (!Number.isFinite(epoch)) return DASH;
    const d = new Date(epoch * 1000);
    const p = (n: number, w = 2) => String(n).padStart(w, "0");
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(
      d.getMilliseconds(),
      3
    )}`;
  },

  duration(seconds: number): string {
    if (!Number.isFinite(seconds)) return DASH;
    if (seconds < 60) return `${seconds.toFixed(1)}s`;
    if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
    return `${(seconds / 3600).toFixed(1)} h`;
  },

  uptime(seconds: number): string {
    const s = Math.floor(seconds);
    const p = (n: number) => String(n).padStart(2, "0");
    return `${p(Math.floor(s / 3600))}:${p(Math.floor((s % 3600) / 60))}:${p(
      s % 60
    )}`;
  },
};
