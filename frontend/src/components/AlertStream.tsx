/**
 * The alert stream.
 *
 * Two of spec 8.2's performance rules live here, and both of them are aimed at
 * the DDoS demo - the moment the backend emits faster than React can render,
 * and the worst possible moment for the interface to stall.
 *
 *   * Virtualized. Only the rows inside the viewport are in the DOM. The ring
 *     buffer holds 500 alerts and every one of them was previously mounted,
 *     live-updating, on every flush; that is 500 rows of DOM churn per frame
 *     for roughly a dozen visible rows of value.
 *
 *   * The visible counter is sampled at 4Hz. The count itself is exact and
 *     unthrottled - it is `filtered.length`, read directly - but a number
 *     re-rendering at 60Hz is unreadable and reads as noise on a projector.
 *
 * Virtualization is arithmetic here rather than a dependency because the spec
 * fixes row height at 40px (2.4). Fixed pitch means the first visible index is
 * a division, so react-window would buy nothing but a bundle and an API.
 */
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { T, SEV, CLASS_META, MONO, SANS } from "../lib/tokens";
import { fmtTime } from "../lib/format";
import { useThrottledValue } from "../hooks/useThrottledValue";
import { scrollToIndex, windowRange } from "../lib/virtual";
import type { Alert, Severity } from "../lib/types";

/** Spec 2.4: 40px in the alert stream. Rows are border-box, so the 1px rule
 *  sits inside this and the scroll pitch is exactly 40. */
const ROW_H = 40;
/** Rows rendered beyond each edge of the viewport. Enough that a fast scroll
 *  or a j/k step never exposes blank space before the next paint. */
const OVERSCAN = 6;

function AlertRow({ alert, selected, onSelect }: { alert: Alert; selected: boolean; onSelect: (id: string) => void }) {
  const sev = SEV[alert.severity];
  const meta = CLASS_META[alert.threat_class];
  return (
    <div
      onClick={() => onSelect(alert.alert_id)}
      style={{
        display: "flex", alignItems: "center", gap: 8, height: ROW_H, padding: "0 10px",
        borderLeft: `2px solid ${sev.color}`, background: selected ? T.panel2 : "transparent",
        cursor: "pointer", borderBottom: `1px solid ${T.rule}`,
      }}
    >
      <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, width: 92, flexShrink: 0 }}>{fmtTime(alert.ts)}</span>
      <span style={{ fontFamily: MONO, fontSize: 11, color: T.text2, border: `1px solid ${T.rule}`, padding: "1px 4px", flexShrink: 0 }}>
        {alert.threat_code || meta?.code || "??"}
      </span>
      <span style={{ fontFamily: SANS, fontSize: 10, fontWeight: 600, color: sev.color, width: 56, flexShrink: 0 }}>{sev.label}</span>
      <span style={{ fontFamily: MONO, fontSize: 12, color: T.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
        {alert.src_ip} &rarr; {alert.dst_ip}
      </span>
      <span style={{ fontFamily: MONO, fontSize: 11, color: T.text2, flexShrink: 0 }}>{alert.confidence.toFixed(2)}</span>
    </div>
  );
}

interface Props {
  alerts: Alert[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  filterSev: Severity | "all";
  setFilterSev: (s: Severity | "all") => void;
}

export function AlertStream({ alerts, selectedId, onSelect, filterSev, setFilterSev }: Props) {
  const filtered = filterSev === "all" ? alerts : alerts.filter((a) => a.severity === filterSev);

  const scroller = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(0);

  // The panel is a flex child of a resizable shell, so the visible row count is
  // measured rather than assumed.
  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el) return;
    setViewportH(el.clientHeight);
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => setViewportH(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const onScroll = useCallback(() => {
    const el = scroller.current;
    if (el) setScrollTop(el.scrollTop);
  }, []);

  const total = filtered.length;
  const { first, last, padTop, padBottom } = windowRange(scrollTop, viewportH, total, ROW_H, OVERSCAN);
  const rows = filtered.slice(first, last);

  // Keyboard navigation is the spec's stated way to drive this list (8.3), and
  // a virtualized list can move the selection to a row that is not mounted. So
  // the selected row is scrolled back into view whenever it leaves it. Only the
  // minimum distance is scrolled, so j/k walks the list a row at a time instead
  // of recentring on every step.
  const selectedIndex = selectedId ? filtered.findIndex((a) => a.alert_id === selectedId) : -1;
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const next = scrollToIndex(selectedIndex, el.scrollTop, el.clientHeight, ROW_H);
    if (next !== null) el.scrollTop = next;
  }, [selectedIndex]);

  // Exact count in, 4Hz out. `filtered.length` above is untouched: filtering,
  // windowing and keyboard navigation all use it directly on every render.
  const shownCount = useThrottledValue(total);
  const shownTotal = useThrottledValue(alerts.length);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 4, padding: 8, borderBottom: `1px solid ${T.rule}`, flexShrink: 0 }}>
        {(["all", "critical", "high", "medium", "low"] as const).map((s) => (
          <button
            key={s}
            onClick={() => setFilterSev(s)}
            aria-pressed={filterSev === s}
            style={{
              fontFamily: SANS, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em",
              padding: "4px 8px", borderRadius: 2, border: `1px solid ${filterSev === s ? T.ruleBright : T.rule}`,
              background: filterSev === s ? T.panel2 : "transparent",
              color: s === "all" ? T.text2 : SEV[s as Severity].color, cursor: "pointer",
            }}
          >
            {s}
          </button>
        ))}
        <span
          style={{ marginLeft: "auto", fontFamily: MONO, fontSize: 11, color: T.text3, fontVariantNumeric: "tabular-nums", whiteSpace: "nowrap" }}
          title="Shown of alerts held in the ring buffer"
        >
          {shownCount} / {shownTotal}
        </span>
      </div>

      <div ref={scroller} onScroll={onScroll} style={{ overflowY: "auto", flex: 1, minHeight: 0 }}>
        {total === 0 && (
          <div style={{ padding: 16, fontFamily: SANS, fontSize: 13, color: T.text3 }}>Waiting for first detection.</div>
        )}
        {/* Spacers stand in for the rows that are not mounted, so the scrollbar
            reports the true length of the list and the thumb behaves normally. */}
        <div style={{ height: padTop }} />
        {rows.map((a) => (
          <AlertRow key={a.alert_id} alert={a} selected={a.alert_id === selectedId} onSelect={onSelect} />
        ))}
        <div style={{ height: padBottom }} />
      </div>

      <div style={{ padding: "5px 10px", borderTop: `1px solid ${T.rule}`, fontFamily: SANS, fontSize: 10, color: T.text3, flexShrink: 0 }}>
        j / k move &middot; enter open &middot; a analyst &middot; esc clear
      </div>
    </div>
  );
}
