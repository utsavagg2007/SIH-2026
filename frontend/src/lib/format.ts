// Section 9: copy is a readout, not commentary — factual, present tense.
export function fmtTime(ts: number): string {
  const d = new Date(ts * 1000);
  const p2 = (n: number) => String(n).padStart(2, "0");
  return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, "0")}`;
}

/**
 * Relative age, e.g. `12s ago`.
 *
 * DESIGN.md §1.3(L): an absolute clock does not tell a viewer the feed is live.
 * "12s ago", ticking, does. The absolute timestamp is still available - it
 * moves to the Wire tooltip and the evidence panel rather than disappearing.
 */
export function fmtAgo(seconds: number): string {
  if (!Number.isFinite(seconds)) return "—";
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 172800) return `${(seconds / 3600).toFixed(1)}h ago`;
  return `${(seconds / 86400).toFixed(1)}d ago`;
}

export function fmtUptime(totalSeconds: number): string {
  const p2 = (n: number) => String(n).padStart(2, "0");
  // The backend reports uptime as a float, so the seconds term has to be
  // floored: `862.1 % 60` is 22.099999999999994, and the instrument bar was
  // rendering it in full. A clock that grows a fifteen-digit tail is the
  // opposite of the fixed-width readout this display is built on.
  const whole = Math.max(0, Math.floor(totalSeconds));
  const h = Math.floor(whole / 3600);
  const m = Math.floor((whole % 3600) / 60);
  const s = whole % 60;
  return `${p2(h)}:${p2(m)}:${p2(s)}`;
}
/**
 * Namespaced formatters for the REST-backed views.
 *
 * Same register as the functions above (spec 9: readouts, not commentary), and
 * deliberately the same implementations - `fmt.clock` is `fmtTime`, so a
 * timestamp reads identically whether it was rendered by the live stream or by
 * a screen that fetched it. Two independently-written clock formatters is how
 * a display ends up showing the same instant two ways.
 */
export const fmt = {
  clock: fmtTime,
  uptime: fmtUptime,
  /**
   * A numeric readout at a width that does not change as the value does.
   *
   * The evidence bars printed `String(value)`, so any float arrived at full
   * double precision - "Destination concentration 0.9996614928833266",
   * "Transfer duration (s) 63.43478298187256", on the panel whose job is to
   * justify the alert. Sixteen significant digits is not a measurement, it is
   * the absence of one, and it is the exact thing DESIGN.md 3.1 asks for
   * fixed decimals to prevent: a figure that resizes the column it sits in.
   *
   * Non-numbers pass through unchanged - evidence values are not all numeric
   * and a JA3 hash must not be rounded.
   */
  metric(value: unknown): string {
    if (typeof value !== "number") return value === null || value === undefined ? "—" : String(value);
    if (!Number.isFinite(value)) return "—";
    if (Number.isInteger(value)) return value.toLocaleString("en-US");
    const abs = Math.abs(value);
    if (abs >= 1000) return Math.round(value).toLocaleString("en-US");
    if (abs >= 1) return value.toFixed(2);
    if (abs >= 0.001) return value.toFixed(4);
    return value.toExponential(2);
  },
  /** Elapsed spans, widening the unit as the magnitude grows so the figure
   *  stays two or three significant digits instead of five. */
  duration(seconds: number): string {
    if (!Number.isFinite(seconds)) return "—";
    if (seconds < 90) return `${Math.round(seconds)}s`;
    if (seconds < 5400) return `${Math.round(seconds / 60)}m`;
    if (seconds < 172800) return `${(seconds / 3600).toFixed(1)}h`;
    return `${(seconds / 86400).toFixed(1)}d`;
  },
};

/**
 * The endpoint pair for an alert row.
 *
 * Not every class has both ends. A port scan has one source and hundreds of
 * destinations, so the backend sends no single `dst_ip`; a DDoS flood has one
 * target and a distributed, unknown source. The row used to interpolate those
 * fields unconditionally and printed the punctuation around the hole -
 * `10.4.2.19 → :` for the scan, `→ 10.4.1.10:80` for the flood - which reads
 * as a rendering fault rather than as an absent field.
 *
 * DESIGN.md §11 rule 2 is explicit about the alternative: an absent value
 * renders as an omission or a *labelled dash*, never as a plausible value. The
 * dash keeps the direction of the arrow readable, which is the part that says
 * which end of the connection the host on screen actually is.
 */
export function fmtEndpoints(a: {
  src_ip?: string;
  dst_ip?: string;
  dst_port?: number;
}): string {
  const src = a.src_ip?.trim();
  const dst = a.dst_ip?.trim();
  if (!src && !dst) return "—";
  const port = dst && a.dst_port ? `:${a.dst_port}` : "";
  return `${src || "—"} → ${dst ? dst + port : "—"}`;
}
