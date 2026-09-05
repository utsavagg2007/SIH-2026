/**
 * The alert stream (DESIGN.md §5).
 *
 * The most-looked-at forty pixels in the product. The previous row put all five
 * fields between 10 and 12px in secondary greys, so a CRITICAL exfiltration and
 * a LOW port scan were separated by a 2px rail and one small coloured word -
 * the severity ramp existed but carried almost no visual weight. This row gives
 * the endpoints the brightest treatment on the line, moves the class, severity
 * and age onto a second line, and adds the two fields the payload always
 * carried and the interface always dropped: the deduplication count and
 * incident membership.
 *
 * INCIDENT GROUPING
 * -----------------
 * The list is grouped by the incident the correlator opened (see `lib/group`).
 * On the demo capture that turns 95 flat rows into seven situations, eighteen
 * of which were one host being scanned, then beaconing, then exfiltrating -
 * a sequence the backend had already worked out and stamped on every member,
 * and which the flat list obliged the reader to reconstruct by eye.
 *
 * The toggle beside the filters restores the flat list, because the two
 * audiences want different things from this panel: grouped answers "what is
 * happening" for someone who has been watching for eight seconds, flat is the
 * firehose an analyst reads during a shift. Neither is a mode the other has to
 * live in.
 *
 * Performance rules that are load-bearing here (§12.2):
 *
 *   * Virtualized. Only rows inside the viewport are mounted. The ring buffer
 *     holds 500 alerts and every one of them used to be mounted and
 *     live-updating on every flush.
 *
 *   * ROW_H is fixed at 40 and grouping does not change that. Group headers are
 *     40px rows in the same flat array as the alerts, so the windowing stays
 *     fixed-pitch arithmetic and `windowRange` / `scrollToIndex` are untouched.
 *     A variable row height means a dependency and a rewrite.
 *
 *   * The visible counter is sampled at 4Hz. The count itself is exact and
 *     unthrottled - a number re-rendering at 60Hz is unreadable and reads as
 *     noise on a projector.
 */
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { T, SEV, SEV_ORDER, CLASS_META, MONO, SANS } from "../lib/tokens";
import { fmtAgo, fmtEndpoints, fmtUptime } from "../lib/format";
import { useThrottledValue } from "../hooks/useThrottledValue";
import { scrollToIndex, windowRange } from "../lib/virtual";
import { groupStream, rowIndexOfAlert, type StreamGroup, type StreamRow } from "../lib/group";
import type { Alert, Incident, Severity } from "../lib/types";

/** §3.2: 40px in the alert stream. Rows are border-box, so the 1px rule sits
 *  inside this and the scroll pitch is exactly 40. Group headers are the same
 *  height for the same reason. */
const ROW_H = 40;
/** Rows rendered beyond each edge of the viewport. Enough that a fast scroll or
 *  a j/k step never exposes blank space before the next paint. */
const OVERSCAN = 6;
/** Recency decay (motion #3). A row's rail sits at full chroma on arrival and
 *  settles to 55% over six seconds, so recency is visible without a badge. */
const DECAY_MS = 6000;
const DECAY_FLOOR = 0.55;
/** Dedup flash (motion #4): the only way a repeat folding into an existing
 *  finding is otherwise visible is a digit quietly changing. */
const FLASH_MS = 390;
/** Indent applied to a member of an expanded group. Enough that containment is
 *  unmistakable at four metres without stealing width from the endpoints. */
const MEMBER_INDENT = 18;

export interface StreamFilters {
  severity: Severity | "all";
  classes: string[];
  host: string;
}

/** Shared by the stream and the app shell, so the ledger, the chips and the
 *  keyboard all filter the same list rather than three similar ones. */
export function applyFilters(alerts: Alert[], f: StreamFilters): Alert[] {
  const host = f.host.trim().toLowerCase();
  if (f.severity === "all" && f.classes.length === 0 && !host) return alerts;
  return alerts.filter((a) => {
    if (f.severity !== "all" && a.severity !== f.severity) return false;
    if (f.classes.length) {
      const code = a.threat_code || CLASS_META[a.threat_class]?.code || "";
      if (!f.classes.includes(code)) return false;
    }
    if (host && !a.src_ip.toLowerCase().includes(host) && !a.dst_ip.toLowerCase().includes(host)) {
      return false;
    }
    return true;
  });
}

/** The two-letter class mark (§2.7). Monochrome: giving each detector a hue
 *  would break the severity discipline the whole palette rests on. */
function ClassCode({ code }: { code: string }) {
  return (
    <span
      style={{
        fontFamily: MONO, fontSize: 9, fontWeight: 500, letterSpacing: "0.04em", color: T.text2,
        border: `1px solid ${T.ruleBright}`, padding: "1px 3px", flexShrink: 0,
      }}
    >
      {code}
    </span>
  );
}

/** Severity always carries a text label as well as its colour, so the display
 *  survives projection and colour-vision differences (§12.3). Critical fills
 *  the chip - its second encoding channel (§2.4). */
function SeverityChip({ severity }: { severity: Severity }) {
  const sev = SEV[severity];
  const critical = severity === "critical";
  return (
    <span
      style={{
        fontFamily: SANS, fontSize: 9, fontWeight: 600, letterSpacing: "0.07em", padding: "1px 3px",
        flexShrink: 0, color: critical ? T.bg : sev.color,
        background: critical ? sev.color : "transparent", border: `1px solid ${sev.color}`,
      }}
    >
      {sev.label}
    </span>
  );
}

/**
 * An incident header.
 *
 * Reads as one sentence: *this host, this sequence of stages, this many
 * findings, this bad, this recently*. The code sequence is the part that does
 * the work - `PS › BC › EC › EX` is "scanned, then beaconed, then ran encrypted
 * C2, then exfiltrated", and it is legible before any row underneath it is.
 */
function GroupRow({
  group, expanded, tick, onToggle,
}: {
  group: StreamGroup;
  expanded: boolean;
  tick: number;
  onToggle: (id: string) => void;
}) {
  const sev = SEV[group.severity];
  const Chevron = expanded ? ChevronDown : ChevronRight;
  const age = Math.max(0, Date.now() / 1000 - group.latest);
  // `shown` is what survived the filter; `total` is the backend's own exact
  // count. Printing one number for both would misreport the incident every
  // time a severity chip is pressed.
  const filtered = group.total !== undefined && group.total > group.shown;

  return (
    <button
      className="group-row"
      aria-expanded={expanded}
      onClick={() => onToggle(group.id)}
      title={`Incident ${group.id} — ${expanded ? "collapse" : "expand"}`}
    >
      <div className="rail" style={{ width: sev.rail, background: sev.color }} />

      <div style={{ display: "flex", alignItems: "center", gap: 6, height: 16 }}>
        <Chevron size={12} color={T.text2} style={{ flexShrink: 0 }} />
        <span
          style={{
            fontFamily: MONO, fontSize: 13, lineHeight: 1.25, color: T.text,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0,
          }}
        >
          {group.label}
        </span>
        {/* The correlator expires incidents long before the client's ring lets
            go of their members, so a header is often named from the address its
            members share rather than from the incident's own `pivot_host`. That
            is an observation about what is on screen, not the correlator's
            finding, and the two must not be allowed to look identical - the id
            is printed beside it whenever the record was not in hand. */}
        {group.labelDerived && (
          <span
            title={`Incident ${group.id}. The correlator's record has expired, so this header is named from the source address its members share rather than from the incident's own pivot host.`}
            style={{ fontFamily: MONO, fontSize: 10, color: T.text3, flexShrink: 0 }}
          >
            {group.id}
          </span>
        )}
        {group.escalated && (
          <span
            title="Spans more than one kill-chain stage. The sequence is why it outranks its highest member severity."
            style={{ ...ESCALATED, flexShrink: 0 }}
          >
            ESCALATED
          </span>
        )}
        <span
          title={
            filtered
              ? `${group.shown} of this incident's ${group.total} member alerts are in the buffer. The rest have scrolled out of it or are hidden by the active filter; ${group.total} is the correlator's own exact count.`
              : `${group.shown} member alerts`
          }
          style={{
            marginLeft: "auto", flexShrink: 0, fontFamily: MONO, fontSize: 11,
            color: filtered ? T.text3 : T.text2,
          }}
        >
          {filtered ? `${group.shown} of ${group.total}` : `${group.shown}`}
        </span>
        <span style={{ ...LABEL_SM, flexShrink: 0 }}>alerts</span>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 4, height: 14, marginTop: 2, paddingLeft: 18 }}>
        {group.codes.map((code, i) => (
          <span key={`${code}-${i}`} style={{ display: "flex", alignItems: "center", gap: 4, minWidth: 0 }}>
            {i > 0 && <span style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>&rsaquo;</span>}
            <ClassCode code={code} />
          </span>
        ))}
        <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 7, flexShrink: 0 }}>
          <SeverityChip severity={group.severity} />
          <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3 }}>{fmtAgo(age)}</span>
        </span>
      </div>
      <span hidden data-tick={tick} />
    </button>
  );
}

const LABEL_SM = {
  fontFamily: SANS, fontSize: 9, fontWeight: 600, letterSpacing: "0.07em",
  textTransform: "uppercase" as const, color: T.text3,
};

const ESCALATED = {
  fontFamily: SANS, fontSize: 9, fontWeight: 600, letterSpacing: "0.07em",
  color: T.text3, border: `1px solid ${T.rule}`, padding: "0 3px",
};

function AlertRow({
  alert, selected, flashing, depth, onSelect,
}: {
  alert: Alert;
  selected: boolean;
  flashing: boolean;
  depth: 0 | 1;
  onSelect: (id: string) => void;
}) {
  const sev = SEV[alert.severity];
  const meta = CLASS_META[alert.threat_class];

  // Age drives both the readable label and the rail's chroma. Both come from
  // the detector's own timestamp - nothing here invents a clock.
  const ageSec = Math.max(0, Date.now() / 1000 - (alert.detected_at ?? alert.ts));
  const railOpacity = selected
    ? 1
    : ageSec * 1000 < DECAY_MS
      ? 1 - (1 - DECAY_FLOOR) * ((ageSec * 1000) / DECAY_MS)
      : DECAY_FLOOR;

  const indent = depth * MEMBER_INDENT;

  return (
    <button
      className="alert-row"
      role="option"
      aria-selected={selected}
      onClick={() => onSelect(alert.alert_id)}
      style={indent ? { paddingLeft: 14 + indent } : undefined}
    >
      {/* Selected rows carry the severity wash across the first 64px. A wash is
          never a full-panel background (§2.3). */}
      {selected && (
        <div
          style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: 64, background: sev.wash, pointerEvents: "none" }}
        />
      )}
      {/* A member's own severity rail sits inboard of the indent, so the group's
          rail stays the outermost mark and containment reads down the column. */}
      <div className="rail" style={{ width: sev.rail, background: sev.color, opacity: railOpacity, left: indent }} />

      <div style={{ position: "relative", display: "flex", alignItems: "center", gap: 8, height: 16 }}>
        <span
          style={{
            fontFamily: MONO, fontSize: 13, lineHeight: 1.25, color: T.text,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, minWidth: 0,
          }}
        >
          {fmtEndpoints(alert)}
        </span>
        {alert.occurrences > 1 && (
          <span
            title={`${alert.occurrences} occurrences folded into this finding`}
            style={{ fontFamily: MONO, fontSize: 11, flexShrink: 0, color: flashing ? T.text : T.text2 }}
          >
            &times;{alert.occurrences}
          </span>
        )}
        {/* Confidence is a neutral bar and a number. It never takes the
            severity colour - they are different quantities (§2.5). */}
        <div style={{ width: 40, height: 3, background: T.rule, position: "relative", flexShrink: 0 }}>
          <div
            style={{ position: "absolute", left: 0, top: 0, bottom: 0, background: T.text2, width: `${alert.confidence * 100}%` }}
          />
        </div>
        <span style={{ fontFamily: MONO, fontSize: 11, color: T.text2, flexShrink: 0, width: 30, textAlign: "right" }}>
          {alert.confidence.toFixed(2)}
        </span>
      </div>

      <div style={{ position: "relative", display: "flex", alignItems: "center", gap: 7, height: 14, marginTop: 2 }}>
        <ClassCode code={alert.threat_code || meta?.code || "??"} />
        <span
          style={{
            fontFamily: SANS, fontSize: 11, color: T.text2, minWidth: 0,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          }}
        >
          {(alert.threat_label || meta?.name || alert.threat_class).toLowerCase()}
        </span>
        <SeverityChip severity={alert.severity} />
        <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, flexShrink: 0 }}>{fmtAgo(ageSec)}</span>
        {/* Inside a group the incident id is the header directly above, so
            repeating it on every member is a column of identical text. */}
        {alert.incident_id && depth === 0 && (
          <span
            title={`Part of incident ${alert.incident_id}`}
            style={{ fontFamily: MONO, fontSize: 11, color: T.text3, marginLeft: "auto", flexShrink: 0 }}
          >
            {/* The backend's ids already carry their own prefix, so a label of
                our own reads as "INC INC-dd51b6…". The id is shown as issued. */}
            {alert.incident_id}
          </span>
        )}
      </div>
    </button>
  );
}

interface Props {
  alerts: Alert[];
  filtered: Alert[];
  incidents: Incident[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  filters: StreamFilters;
  setFilters: (f: StreamFilters) => void;
  connected: boolean;
  /** Seconds since the last arrival, for the feed-stopped line. */
  stoppedFor: number;
  /** 4Hz sampler, so ages and the recency decay advance at a readable cadence
   *  rather than on every animation frame. */
  tick: number;
}

export function AlertStream({
  alerts, filtered, incidents, selectedId, onSelect, filters, setFilters, connected, stoppedFor, tick,
}: Props) {
  const scroller = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(0);
  const [grouped, setGrouped] = useState(true);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(() => new Set());

  const toggleGroup = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (!next.delete(id)) next.add(id);
      return next;
    });
  }, []);

  // Dedup flashes. `occurrences` is the only field the backend revises on an
  // existing alert_id, so a change to it is exactly a repeat folding in.
  const seenOcc = useRef<Map<string, number>>(new Map());
  const flashUntil = useRef<Map<string, number>>(new Map());
  useEffect(() => {
    const now = performance.now();
    for (const a of alerts) {
      const prev = seenOcc.current.get(a.alert_id);
      if (prev !== undefined && a.occurrences > prev) {
        flashUntil.current.set(a.alert_id, now + FLASH_MS);
      }
      seenOcc.current.set(a.alert_id, a.occurrences);
    }
    // The map is bounded by the ring buffer: ids that fell out stop mattering.
    if (seenOcc.current.size > 1200) {
      const live = new Set(alerts.map((a) => a.alert_id));
      for (const id of seenOcc.current.keys()) if (!live.has(id)) seenOcc.current.delete(id);
      for (const id of flashUntil.current.keys()) if (!live.has(id)) flashUntil.current.delete(id);
    }
  }, [alerts]);

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

  // The selected alert's own group is always open. Keyboard navigation walks
  // the flat filtered list (App.tsx owns that), so j/k can step the selection
  // into a collapsed group; without this it would vanish from the panel.
  const selectedIncident = useMemo(
    () => filtered.find((a) => a.alert_id === selectedId)?.incident_id ?? null,
    [filtered, selectedId]
  );

  const rows: StreamRow[] = useMemo(() => {
    if (!grouped) {
      return filtered.map((a) => ({ kind: "alert", key: a.alert_id, alert: a, depth: 0 }));
    }
    const open = selectedIncident ? new Set([...expanded, selectedIncident]) : expanded;
    return groupStream(filtered, incidents, open);
  }, [grouped, filtered, incidents, expanded, selectedIncident]);

  const total = rows.length;
  const { first, last, padTop, padBottom } = windowRange(scrollTop, viewportH, total, ROW_H, OVERSCAN);
  const visible = rows.slice(first, last);

  // Keyboard navigation is the stated way to drive this list, and a virtualized
  // list can move the selection to a row that is not mounted. So the selected
  // row is scrolled back into view whenever it leaves it, by the minimum
  // distance - j/k walks the list a row at a time instead of recentring. The
  // index is the row's position in the flattened list, which after grouping is
  // no longer its index in `filtered`.
  const selectedRow = rowIndexOfAlert(rows, selectedId);
  useEffect(() => {
    const el = scroller.current;
    if (!el) return;
    const next = scrollToIndex(selectedRow, el.scrollTop, el.clientHeight, ROW_H);
    if (next !== null) el.scrollTop = next;
  }, [selectedRow]);

  // Exact count in, 4Hz out. `filtered.length` above is untouched: filtering,
  // windowing and keyboard navigation all use it directly on every render.
  const shownCount = useThrottledValue(filtered.length);
  const shownTotal = useThrottledValue(alerts.length);
  const groupCount = useThrottledValue(rows.reduce((n, r) => n + (r.kind === "group" ? 1 : 0), 0));

  const classChips = useMemo(() => Object.entries(CLASS_META), []);
  const now = performance.now();

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0, background: T.bg }}>
      <div style={{ flexShrink: 0, background: T.panel, borderBottom: `1px solid ${T.rule}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "7px 12px 6px" }}>
          {(["all", ...SEV_ORDER] as const).map((s) => {
            const active = filters.severity === s;
            return (
              <button
                key={s}
                className="chip"
                aria-pressed={active}
                onClick={() => setFilters({ ...filters, severity: s })}
                style={{ color: s === "all" ? (active ? T.text : T.text2) : SEV[s].color }}
              >
                {s === "all" ? "ALL" : SEV[s].short}
              </button>
            );
          })}
          <span
            title="Shown of alerts held in the ring buffer"
            style={{ marginLeft: "auto", fontFamily: MONO, fontSize: 11, color: T.text3, whiteSpace: "nowrap" }}
          >
            {shownCount} / {shownTotal}
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 4, padding: "0 12px 8px" }}>
          {classChips.map(([key, meta]) => {
            const active = filters.classes.includes(meta.code);
            return (
              <button
                key={key}
                className="chip mono"
                aria-pressed={active}
                title={meta.name}
                onClick={() =>
                  setFilters({
                    ...filters,
                    classes: active
                      ? filters.classes.filter((c) => c !== meta.code)
                      : [...filters.classes, meta.code],
                  })
                }
                style={{ color: active ? T.text : T.text2 }}
              >
                {meta.code}
              </button>
            );
          })}
          <input
            className="field"
            value={filters.host}
            onChange={(e) => setFilters({ ...filters, host: e.target.value })}
            placeholder="filter host…"
            aria-label="Filter by host address"
            style={{ marginLeft: "auto", width: 132 }}
          />
        </div>
        {/* Grouped or flat. Grouped answers "what is happening" in seven rows;
            flat is the firehose. Neither audience has to live in the other's
            view (§0). */}
        <div
          style={{
            display: "flex", alignItems: "center", gap: 6, padding: "0 12px 8px",
          }}
        >
          <button
            className="chip"
            aria-pressed={grouped}
            onClick={() => setGrouped(true)}
            title="One row per correlated incident"
          >
            Grouped
          </button>
          <button
            className="chip"
            aria-pressed={!grouped}
            onClick={() => setGrouped(false)}
            title="Every alert as its own row"
          >
            Flat
          </button>
          {grouped && (
            <span style={{ marginLeft: "auto", fontFamily: MONO, fontSize: 11, color: T.text3, whiteSpace: "nowrap" }}>
              {groupCount} {groupCount === 1 ? "incident" : "incidents"}
            </span>
          )}
        </div>
      </div>

      {!connected && (
        <div
          style={{
            flexShrink: 0, padding: "7px 12px", borderBottom: `1px solid ${T.rule}`,
            background: T.panel, fontFamily: SANS, fontSize: 12, color: T.text,
          }}
        >
          Feed stopped.{" "}
          {stoppedFor > 0 && (
            <>
              Last alert <span style={{ fontFamily: MONO, color: T.text2 }}>{fmtUptime(Math.round(stoppedFor))}</span> ago.
            </>
          )}
        </div>
      )}

      <div
        ref={scroller}
        onScroll={onScroll}
        role="listbox"
        aria-label="Alert stream"
        style={{ overflowY: "auto", overflowX: "hidden", flex: 1, minHeight: 0 }}
      >
        {total === 0 && (
          <div style={{ padding: "40px 16px", textAlign: "center", fontFamily: SANS, fontSize: 13, color: T.text3 }}>
            {alerts.length === 0
              ? "Waiting for first detection."
              : "No alerts match the current filter. Press 0 to clear."}
          </div>
        )}
        {/* Spacers stand in for the rows that are not mounted, so the scrollbar
            reports the true length of the list and the thumb behaves normally. */}
        <div style={{ height: padTop }} />
        {visible.map((r) =>
          r.kind === "group" ? (
            <GroupRow key={r.key} group={r.group} expanded={r.expanded} tick={tick} onToggle={toggleGroup} />
          ) : (
            <AlertRow
              key={r.key}
              alert={r.alert}
              depth={r.depth}
              selected={r.alert.alert_id === selectedId}
              flashing={(flashUntil.current.get(r.alert.alert_id) ?? 0) > now}
              onSelect={onSelect}
            />
          )
        )}
        <div style={{ height: padBottom }} />
        {/* `tick` is read so the 4Hz sampler invalidates ages and the recency
            decay; without it the rails would freeze between arrivals. */}
        <span hidden data-tick={tick} />
      </div>

      <div
        style={{
          flexShrink: 0, padding: "6px 12px", borderTop: `1px solid ${T.rule}`, background: T.panel,
          fontFamily: SANS, fontSize: 10, letterSpacing: "0.02em", color: T.text3,
        }}
      >
        j / k move &middot; enter analyst &middot; 1–4 severity &middot; 0 clear &middot; e expand raw &middot; esc clear
      </div>
    </div>
  );
}
