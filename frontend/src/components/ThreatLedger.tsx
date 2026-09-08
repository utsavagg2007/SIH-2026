/**
 * The Threat Ledger (DESIGN.md §4.1).
 *
 * One 44px strip that answers *how bad is it right now* before anyone reads a
 * row. It is the fix for the previous build's largest gap: severity counts,
 * alert rate and the most active class were nowhere on screen, so a viewer had
 * to tally rows to learn how the network was doing.
 *
 * Three rules the implementation depends on:
 *
 *   * The window is rolling, not cumulative. An all-time total only ever goes
 *     up and stops carrying information after a minute; five minutes of history
 *     keeps saying something.
 *
 *   * Counts are the one place a large number is allowed to be coloured, and
 *     that is why the strip works from across a room.
 *
 *   * A zero renders as a dim zero, never as a hidden cell. "0 critical" is
 *     itself the finding.
 *
 * The cells are filter toggles synced with the stream's chips, so the strip is
 * a control surface rather than a second, contradictory readout.
 */
import { useMemo } from "react";
import { T, SEV, SEV_ORDER, CLASS_META, MONO, SANS, microStyle } from "../lib/tokens";
import type { Alert, Severity } from "../lib/types";

/** Matches the trim window in `useFeed`, and §4.1's stated "last 5 min". */
const WINDOW_MS = 300_000;
/** The rate is observed over the last five seconds of arrivals rather than read
 *  from a backend counter, so a stopped feed reads zero at once instead of
 *  holding whatever rate was last reported. */
const RATE_WINDOW_MS = 5_000;

interface Props {
  alerts: Alert[];
  /** Arrival instants on the `performance.now()` clock, newest last. */
  arrivals: number[];
  /** Alerts admitted since the backend started. Measured, not counted here. */
  sessionTotal: number;
  peakPerSec: number;
  connected: boolean;
  sevFilter: Severity | "all";
  onPickSeverity: (s: Severity | "all") => void;
  /** Sampled at 4Hz by the parent so the counts move at a readable cadence. */
  tick: number;
}

export function ThreatLedger({
  alerts, arrivals, sessionTotal, peakPerSec, connected, sevFilter, onPickSeverity, tick,
}: Props) {
  const model = useMemo(() => {
    const now = performance.now();

    // `ts` is wall-clock seconds from the detector; the window is measured
    // against it so alerts already in the snapshot are counted on the same
    // basis as ones that arrived live.
    const tally = (cutoff: number) => {
      const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
      const classCounts: Record<string, number> = {};
      for (const a of alerts) {
        if (a.ts < cutoff) continue;
        if (counts[a.severity] === undefined) continue;
        counts[a.severity] += 1;
        const code = a.threat_code || CLASS_META[a.threat_class]?.code || "??";
        classCounts[code] = (classCounts[code] || 0) + 1;
      }
      return {
        counts,
        classCounts,
        total: SEV_ORDER.reduce((n, k) => n + counts[k], 0),
      };
    };

    // The rolling window is the right answer on live traffic. It is the wrong
    // answer on a replayed capture, on a resumed session, and on any network
    // quiet for five minutes: the strip read four dim zeros and "no detections
    // in window" directly above a stream listing sixty-six alerts, which is
    // the exact contradiction this component exists to prevent. When the
    // window is empty but the buffer is not, count what is actually on screen
    // and relabel - the honest reading, rather than a technically-correct zero
    // that every viewer reads as "nothing detected".
    let scope = tally(Date.now() / 1000 - WINDOW_MS / 1000);
    let windowLabel = "last 5 min";
    if (scope.total === 0 && alerts.length > 0) {
      scope = tally(-Infinity);
      windowLabel = "all loaded";
    }
    const { counts, classCounts, total } = scope;
    const max = Math.max(1, ...SEV_ORDER.map((k) => counts[k]));

    let topCode = "—";
    let topName = alerts.length ? "no classified detections" : "no detections yet";
    let topN = 0;
    for (const [code, n] of Object.entries(classCounts)) {
      if (n > topN) {
        topN = n;
        topCode = code;
      }
    }
    if (topN) {
      const entry = Object.values(CLASS_META).find((c) => c.code === topCode);
      topName = entry ? entry.name.toLowerCase() : topCode;
    }

    const recent = arrivals.filter((t) => t > now - RATE_WINDOW_MS).length;
    return {
      counts,
      total,
      max,
      topCode,
      topName,
      windowLabel,
      rate: connected ? recent / (RATE_WINDOW_MS / 1000) : 0,
    };
    // `tick` is the 4Hz sampler: ages and counts are time-derived, so the
    // memo has to be invalidated by the clock as well as by the data.
  }, [alerts, arrivals, connected, tick]);

  return (
    <div
      style={{ height: 44, flexShrink: 0, background: T.panel, display: "flex", alignItems: "stretch" }}
      aria-label={`Threat ledger, ${model.windowLabel}`}
    >
      <div
        style={{
          width: 96, flexShrink: 0, borderRight: `1px solid ${T.rule}`,
          padding: "8px 0 0 14px", display: "flex", flexDirection: "column", gap: 2,
        }}
      >
        <span style={microStyle}>Window</span>
        <span style={{ fontFamily: MONO, fontSize: 12, color: T.text2 }}>{model.windowLabel}</span>
      </div>

      {SEV_ORDER.map((key) => {
        const meta = SEV[key];
        const n = model.counts[key];
        const active = sevFilter === key;
        return (
          <button
            key={key}
            className="ledger-cell"
            aria-pressed={active}
            title={active ? `Clear the ${key} filter` : `Filter the stream to ${key}`}
            onClick={() => onPickSeverity(active ? "all" : key)}
          >
            <div style={{ display: "flex", alignItems: "baseline", gap: 10, height: 33, overflow: "hidden" }}>
              <span
                style={{
                  fontFamily: SANS, fontSize: 9, fontWeight: 600, letterSpacing: "0.08em",
                  width: 34, color: n ? meta.color : T.text3,
                }}
              >
                {meta.short}
              </span>
              <span
                style={{
                  fontFamily: MONO, fontWeight: 500, fontSize: 32, lineHeight: 1,
                  color: n ? meta.color : T.text3,
                }}
              >
                {n}
              </span>
              <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, marginLeft: "auto", paddingRight: 2 }}>
                {n && model.total ? `${Math.round((n / model.total) * 100)}%` : ""}
              </span>
            </div>
            {/* Proportional bar in the severity wash, so the four cells read as
                one distribution rather than four unrelated numbers. */}
            <div style={{ position: "absolute", left: 16, right: 16, bottom: 1, height: 5, background: T.bg }}>
              <div
                style={{
                  position: "absolute", left: 0, top: 0, bottom: 0, background: meta.wash,
                  width: n ? `${((n / model.max) * 100).toFixed(1)}%` : "0%",
                  transition: "width 240ms cubic-bezier(0.2,0,0,1)",
                }}
              />
            </div>
          </button>
        );
      })}

      <div style={{ width: 344, flexShrink: 0, display: "flex", alignItems: "stretch" }}>
        <div style={{ flex: 1, padding: "6px 0 0 16px", display: "flex", flexDirection: "column", gap: 1 }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
            <span style={{ fontFamily: MONO, fontWeight: 500, fontSize: 18, lineHeight: 1, color: T.text }}>
              {model.rate.toFixed(1)}
            </span>
            <span style={microStyle}>alerts/s</span>
          </div>
          <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3 }}>peak {peakPerSec.toFixed(1)}</span>
        </div>
        <div
          style={{
            flex: 1.1, padding: "6px 0 0 12px", borderLeft: `1px solid ${T.rule}`,
            display: "flex", flexDirection: "column", gap: 2, minWidth: 0,
          }}
        >
          <span style={microStyle}>Most active</span>
          <div style={{ display: "flex", alignItems: "center", gap: 5, minWidth: 0 }}>
            <span
              style={{
                fontFamily: MONO, fontSize: 10, fontWeight: 500, color: T.text2,
                border: `1px solid ${T.ruleBright}`, padding: "1px 3px", flexShrink: 0,
              }}
            >
              {model.topCode}
            </span>
            <span
              style={{
                fontFamily: SANS, fontSize: 11, color: T.text2,
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
              }}
            >
              {model.topName}
            </span>
          </div>
        </div>
        <div
          style={{
            width: 96, padding: "6px 14px 0 12px", borderLeft: `1px solid ${T.rule}`,
            display: "flex", flexDirection: "column", gap: 2, textAlign: "right",
          }}
        >
          <span style={microStyle}>Session</span>
          <span style={{ fontFamily: MONO, fontSize: 13, color: T.text2 }}>
            {sessionTotal.toLocaleString()}
          </span>
        </div>
      </div>
    </div>
  );
}
