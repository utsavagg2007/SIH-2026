/**
 * The kill-chain ribbon (DESIGN.md §8.1).
 *
 * An incident is several alerts on one host correlated into a sequence. The
 * ribbon is the argument: these findings are one story, and the sequence is
 * itself evidence. This is where the fusion layer's work becomes visible.
 *
 * The change from the previous ribbon is the axis. Nodes used to be laid out
 * with equal `flex: 1` spacing, which erased the thing that makes the sequence
 * evidence — a port scan followed by exfiltration twenty minutes later drew
 * identically to three alerts in the same second. Nodes now sit at their real
 * position in elapsed time.
 *
 * Counts come from the incident itself, never from the drawn nodes: `members`
 * is a trimmed narrative slice, so counting rendered elements would under-report
 * a long incident and quietly contradict the exact figure the backend carried
 * separately.
 */
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { T, SEV, CLASS_META, MONO, SANS, microStyle } from "../lib/tokens";
import { fmtTime, fmt } from "../lib/format";
import { api } from "../lib/api";
import type { Incident } from "../lib/types";

/** Width one node's label block needs before it starts colliding with its
 *  neighbour. Node content is 96px wide plus a little breathing room. */
const NODE_W = 104;

/**
 * Node x-positions in pixels: true time first, then the minimum shift that
 * stops labels overlapping.
 *
 * A real time axis is the whole point of this ribbon, and it is also what makes
 * collisions possible - three alerts inside ten seconds land on the same pixel
 * and their labels print on top of each other. The sweep below pushes each node
 * only as far right as it must go, and the caller draws a tick at the node's
 * true time so the reading is never falsified: the dot may be nudged, the
 * moment it happened is still marked on the axis.
 */
export function layoutNodes(times: number[], width: number, nodeW = NODE_W): number[] {
  const n = times.length;
  if (n === 0) return [];
  const usable = Math.max(width - nodeW, 1);
  const t0 = times[0];
  const span = Math.max(times[n - 1] - t0, 1e-6);
  const degenerate = times[n - 1] - t0 < 1;

  // True position, with the node's own width kept inside the track.
  const raw = times.map((t, i) =>
    degenerate
      ? (n === 1 ? usable / 2 : (i / (n - 1)) * usable)
      : ((t - t0) / span) * usable
  );

  // Forward sweep: never closer than nodeW to the previous node.
  const out = raw.slice();
  for (let i = 1; i < n; i++) out[i] = Math.max(out[i], out[i - 1] + nodeW);

  // If the sweep ran past the right edge, slide the whole run back and repeat
  // the constraint from the right, so the last node lands on the edge rather
  // than outside it.
  const overflow = out[n - 1] - usable;
  if (overflow > 0) {
    for (let i = n - 1; i >= 0; i--) {
      out[i] = Math.min(out[i] - overflow, i === n - 1 ? usable : out[i + 1] - nodeW);
      if (out[i] < 0) out[i] = 0;
    }
    for (let i = 1; i < n; i++) out[i] = Math.max(out[i], out[i - 1] + nodeW);
  }
  return out;
}

function elapsedLabel(seconds: number): string {
  if (seconds < 90) return `${Math.round(seconds)} sec elapsed`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min elapsed`;
  return `${(seconds / 3600).toFixed(1)} h elapsed`;
}

function IncidentRibbon({
  incident, selectedId, focused, onSelectAlert, onOpenHost,
}: {
  incident: Incident;
  selectedId?: string | null;
  focused?: boolean;
  onSelectAlert: (id: string) => void;
  onOpenHost: (ip: string) => void;
}) {
  /**
   * `members` is the backend's trimmed narrative slice. When it says so, the
   * full set is one call away on `GET /incidents/{id}` - so the ribbon offers
   * it rather than leaving "12 of 47 shown" as a dead end.
   */
  const [full, setFull] = useState<Incident["members"] | null>(null);
  const [expanding, setExpanding] = useState(false);
  const [expandError, setExpandError] = useState<string | null>(null);

  async function expand() {
    setExpanding(true);
    setExpandError(null);
    try {
      const r = await api.incident(incident.incident_id);
      // The detail route returns the incident plus its member alerts; the
      // ribbon draws member nodes, so the incident's own list is preferred and
      // the alert array is the fallback when it is absent.
      setFull(
        r.incident?.members?.length
          ? r.incident.members
          : r.alerts.map((a) => ({
              alert_id: a.alert_id,
              ts: a.ts,
              threat_class: a.threat_class,
              threat_code: a.threat_code,
              severity: a.severity,
              confidence: a.confidence,
              stage: a.kill_chain_stage ?? "reconnaissance",
              occurrences: a.occurrences,
            }))
      );
    } catch (e) {
      setExpandError(String((e as Error)?.message ?? e));
    } finally {
      setExpanding(false);
    }
  }

  const members = [...(full ?? incident.members ?? [])].sort((a, b) => a.ts - b.ts);
  const sev = SEV[incident.severity];
  const critical = incident.severity === "critical";

  // The track is measured rather than assumed: node positions are in pixels so
  // the de-overlap sweep can reason about label width, which a percentage
  // cannot.
  const track = useRef<HTMLDivElement | null>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const el = track.current;
    if (!el) return;
    setWidth(el.clientWidth);
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const t0 = members.length ? members[0].ts : 0;
  const span = members.length ? Math.max(members[members.length - 1].ts - t0, 1e-6) : 1;
  const degenerate = members.length < 2 || members[members.length - 1].ts - t0 < 1;
  const xs = layoutNodes(members.map((m) => m.ts), width);
  const usable = Math.max(width - NODE_W, 1);

  return (
    <div
      style={{
        border: `1px solid ${focused ? T.ruleBright : T.rule}`,
        background: T.panel,
        marginBottom: 12,
      }}
    >
      <div
        style={{
          display: "flex", alignItems: "baseline", gap: 10, padding: "10px 16px",
          borderBottom: `1px solid ${T.rule}`, fontFamily: SANS, fontSize: 12, color: T.text2, flexWrap: "wrap",
        }}
      >
        <span style={microStyle}>Host</span>
        <button className="ip" onClick={() => onOpenHost(incident.pivot_host)} style={{ fontSize: 14, color: T.text }}>
          {incident.pivot_host}
        </button>
        <span style={{ color: T.text3, fontFamily: MONO, fontSize: 11 }}>
          opened {fmtTime(incident.opened_at)} · {incident.alert_count} alerts · {incident.incident_id}
        </span>
        <span
          style={{
            fontFamily: SANS, fontSize: 9, fontWeight: 600, letterSpacing: "0.07em", padding: "2px 5px", marginLeft: "auto",
            color: critical ? T.bg : sev.color, background: critical ? sev.color : "transparent", border: `1px solid ${sev.color}`,
          }}
        >
          {sev.label}
        </span>
      </div>

      {incident.escalated && (
        // Not just a badge: the sentence is the argument for outranking the
        // highest member severity, and without it the badge asserts a judgement
        // it does not explain.
        <div style={{ padding: "8px 16px", borderBottom: `1px solid ${T.rule}`, fontFamily: SANS, fontSize: 12, color: T.text2 }}>
          Escalated: this incident spans {incident.stages?.length ?? "multiple"} kill-chain stages on one host. The
          sequence is itself evidence, which is what raises it above its highest member severity.
        </div>
      )}

      {incident.narrative && (
        <div style={{ padding: "10px 16px", borderBottom: `1px solid ${T.rule}`, fontFamily: SANS, fontSize: 13, lineHeight: 1.5, color: T.text2 }}>
          {incident.narrative}
        </div>
      )}

      <div style={{ padding: "20px 16px 12px" }}>
        {members.length === 0 ? (
          <div style={{ fontFamily: SANS, fontSize: 13, color: T.text3 }}>Correlated, member alerts not yet loaded.</div>
        ) : (
          <>
            <div ref={track} style={{ position: "relative", height: 132, margin: "0 20px" }}>
              {/* The dot stays at the instant the alert fired; only the label
                  block is nudged clear of its neighbours, with a leader line
                  back to its dot. That keeps both readings intact - the axis
                  still shows when things happened, and the text is legible
                  even when six alerts land inside ten seconds. */}
              <svg
                width="100%"
                height="34"
                style={{ position: "absolute", left: 0, top: 0, overflow: "visible" }}
                aria-hidden="true"
              >
                <line x1={0} y1={6.5} x2="100%" y2={6.5} stroke={T.ruleBright} strokeWidth="1" />
                {members.map((m, i) => {
                  const trueX = NODE_W / 2 + (degenerate ? (xs[i] ?? 0) : ((m.ts - t0) / span) * usable);
                  const labelX = (xs[i] ?? 0) + NODE_W / 2;
                  return (
                    <g key={`lead-${m.alert_id}`}>
                      <circle cx={trueX} cy={6.5} r={5} fill={T.bg} stroke={SEV[m.severity].color} strokeWidth="2" />
                      {Math.abs(trueX - labelX) > 1 && (
                        <polyline
                          points={`${trueX},12 ${trueX},22 ${labelX},28 ${labelX},34`}
                          fill="none"
                          stroke={T.rule}
                          strokeWidth="1"
                        />
                      )}
                    </g>
                  );
                })}
              </svg>

              {members.map((m, i) => {
                const meta = CLASS_META[m.threat_class];
                const selected = selectedId === m.alert_id;
                return (
                  <button
                    key={m.alert_id}
                    className="pick-row"
                    aria-selected={selected}
                    onClick={() => onSelectAlert(m.alert_id)}
                    title={`${meta?.name ?? m.threat_class} · ${m.stage.replace(/_/g, " ")} · conf ${m.confidence.toFixed(2)} · ${fmtTime(m.ts)}`}
                    style={{
                      position: "absolute", left: xs[i] ?? 0, top: 36,
                      width: NODE_W, textAlign: "center", padding: "2px 2px 4px",
                    }}
                  >
                    <div style={{ fontFamily: MONO, fontSize: 11, color: T.text2, border: `1px solid ${T.ruleBright}`, padding: "1px 4px", display: "inline-block", marginBottom: 3 }}>
                      {m.threat_code || meta?.code || "??"}
                    </div>
                    <div style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>{fmtTime(m.ts)}</div>
                    <div style={{ fontFamily: SANS, fontSize: 10, color: T.text2, marginTop: 2, lineHeight: 1.2, overflowWrap: "anywhere" }}>
                      {(meta?.name ?? m.threat_class).toLowerCase()}
                    </div>
                    <div style={{ fontFamily: SANS, fontSize: 9, color: T.text3, letterSpacing: "0.03em", marginTop: 1, lineHeight: 1.2, overflowWrap: "anywhere" }}>
                      {m.stage.replace(/_/g, " ")}
                    </div>
                    <div style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>conf {m.confidence.toFixed(2)}</div>
                  </button>
                );
              })}
            </div>
            {!degenerate && (
              <div style={{ margin: "0 20px", display: "flex", justifyContent: "space-between", fontFamily: MONO, fontSize: 10, color: T.text3, borderTop: `1px solid ${T.rule}`, paddingTop: 4 }}>
                <span>{fmtTime(t0)}</span>
                <span>{fmt.duration(span)} span</span>
                <span>{fmtTime(members[members.length - 1].ts)}</span>
              </div>
            )}
          </>
        )}
      </div>

      <div
        style={{
          textAlign: "center", padding: "8px 16px", borderTop: `1px solid ${T.rule}`,
          fontFamily: MONO, fontSize: 11, color: T.text3,
        }}
      >
        {elapsedLabel(incident.elapsed_sec)}
        {members.length < incident.alert_count && (
          <>
            <span> &middot; {members.length} of {incident.alert_count} shown</span>
            {!full && (
              <button
                className="ctl"
                onClick={expand}
                disabled={expanding}
                style={{ marginLeft: 10, verticalAlign: "middle" }}
              >
                {expanding ? "loading" : "load all"}
              </button>
            )}
          </>
        )}
        {expandError && (
          <span style={{ color: T.text3 }}> &middot; member list unavailable ({expandError})</span>
        )}
      </div>
    </div>
  );
}

export function IncidentsView({
  incidents, selectedId, focusedIncident, onSelectAlert, onOpenHost,
}: {
  incidents: Incident[];
  selectedId?: string | null;
  /** Opened from an alert's evidence panel: that ribbon sorts first and is
   *  outlined, so the operator lands on it instead of hunting the list. */
  focusedIncident?: string | null;
  onSelectAlert: (id: string) => void;
  onOpenHost: (ip: string) => void;
}) {
  const ordered = useMemo(() => {
    // A still-growing incident stays at the top, unless one was explicitly
    // opened from an alert.
    const byRecency = [...incidents].sort((a, b) => b.updated_at - a.updated_at);
    if (!focusedIncident) return byRecency;
    const i = byRecency.findIndex((x) => x.incident_id === focusedIncident);
    if (i <= 0) return byRecency;
    return [byRecency[i], ...byRecency.slice(0, i), ...byRecency.slice(i + 1)];
  }, [incidents, focusedIncident]);

  const focusRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (focusedIncident) focusRef.current?.scrollTo({ top: 0 });
  }, [focusedIncident]);

  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: T.bg }}>
      <div className="panel-head">
        <span className="panel-title">Incidents</span>
        <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, marginLeft: "auto" }}>
          {ordered.length} correlated
        </span>
      </div>
      <div ref={focusRef} style={{ flex: 1, overflowY: "auto", padding: 16 }}>
        {ordered.length === 0 ? (
          <div style={{ padding: "40px 16px", textAlign: "center", fontFamily: SANS, fontSize: 13, color: T.text3 }}>
            No correlated incidents yet.
          </div>
        ) : (
          ordered.map((inc) => (
            <IncidentRibbon
              key={inc.incident_id}
              incident={inc}
              selectedId={selectedId}
              focused={inc.incident_id === focusedIncident}
              onSelectAlert={onSelectAlert}
              onOpenHost={onOpenHost}
            />
          ))
        )}
      </div>
    </div>
  );
}
