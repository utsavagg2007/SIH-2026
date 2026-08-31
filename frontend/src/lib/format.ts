// Section 9: copy is a readout, not commentary — factual, present tense.
export function fmtTime(ts: number): string {
  const d = new Date(ts * 1000);
  const p2 = (n: number) => String(n).padStart(2, "0");
  return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, "0")}`;
}

export function fmtUptime(totalSeconds: number): string {
  const p2 = (n: number) => String(n).padStart(2, "0");
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
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
