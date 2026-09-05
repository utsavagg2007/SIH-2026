import { memo, useMemo, useState } from "react";
import { T, SEV, CLASS_META, KILL_CHAIN, MONO, SANS, labelStyle, microStyle } from "../lib/tokens";
import { fmtTime, fmt } from "../lib/format";
import type { Alert, EvidenceItem, Severity } from "../lib/types";
import { classVisual } from "./visuals";
import { VisualBoundary } from "./visuals/chrome";

/** Severity to the suffix used by the `--sev-*` custom properties in
 *  styles.css. The token names are abbreviated where the enum is not, so the
 *  mapping is explicit rather than a string slice. */
export function sevKey(s: Severity): string {
  return s === "medium" ? "med" : s === "critical" ? "crit" : s;
}

/** Every IP in the product is a link to its host view. That single interaction
 *  rule is what makes the whole product feel navigable (DESIGN.md §7.1). */
function IpLink({ ip, onOpenHost }: { ip: string; onOpenHost: (ip: string) => void }) {
  return (
    <button className="ip" onClick={(e) => { e.stopPropagation(); onOpenHost(ip); }} title={`Open host view for ${ip}`}>
      {ip}
    </button>
  );
}

function Field({ k, v, title }: { k: string; v: React.ReactNode; title?: string }) {
  return (
    <>
      <span style={{ ...microStyle, whiteSpace: "nowrap" }} title={title}>{k}</span>
      <span
        style={{ fontFamily: MONO, fontSize: 12, color: T.text, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
        title={title ?? (typeof v === "string" ? v : undefined)}
      >
        {v}
      </span>
    </>
  );
}

/**
 * One evidence bar.
 *
 * Two things beyond the track and the marker matter here. The observed marker
 * takes the severity colour ONLY when the value is on the wrong side of the
 * line, and which side that is comes from the backend's `exceeded` flag rather
 * than a comparison recomputed in the browser - recomputing it can disagree
 * with the detector that actually fired. And the readout names the *distance*
 * past the threshold, because "3.7× above 0.15" is the analytical content; the
 * bar alone only says "past".
 */
function EvidenceBar({ item, severityColor }: { item: EvidenceItem; severityColor: string }) {
  const label = (item.label || item.feature) + (item.unit ? ` (${item.unit})` : "");
  const hasThreshold = item.threshold !== undefined && typeof item.value === "number";

  if (!hasThreshold) {
    // Contextual values render as a plain label-value pair. Inventing a scale
    // to make them look uniform would assert a threshold nobody set.
    return (
      <div style={{ padding: "9px 0", borderBottom: `1px solid ${T.rule}` }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12 }}>
          <span style={{ fontFamily: SANS, fontSize: 12, color: T.text2 }}>{label}</span>
          <span style={{ fontFamily: MONO, fontSize: 13, color: T.text }}>{fmt.metric(item.value)}</span>
        </div>
      </div>
    );
  }

  const threshold = item.threshold as number;
  const value = item.value as number;
  const [lo, hi] = item.scale ?? [0, threshold * 2 || 1];
  const pct = (v: number) => Math.max(0, Math.min(100, ((v - lo) / (hi - lo)) * 100));
  const crossed =
    item.exceeded ?? (item.direction === "above" ? value >= threshold : value <= threshold);

  let distance = `threshold ${fmt.metric(threshold)}`;
  if (item.direction === "above" && threshold !== 0) {
    distance = `${(value / threshold).toFixed(1)}× above threshold ${fmt.metric(threshold)}`;
  } else if (item.direction === "below" && value !== 0) {
    distance = `${(threshold / value).toFixed(1)}× below threshold ${fmt.metric(threshold)}`;
  }

  return (
    <div style={{ padding: "9px 0", borderBottom: `1px solid ${T.rule}` }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12, marginBottom: 5 }}>
        <span style={{ fontFamily: SANS, fontSize: 12, color: T.text2 }}>{label}</span>
        <span style={{ fontFamily: MONO, fontSize: 13, color: crossed ? severityColor : T.text }}>{fmt.metric(item.value)}</span>
      </div>
      <div style={{ position: "relative", height: 6, background: T.rule }}>
        <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: `${pct(value)}%`, background: T.text2 }} />
        <div style={{ position: "absolute", top: -4, bottom: -4, left: `${pct(threshold)}%`, width: 1, background: T.ruleBright }} />
        <div
          style={{
            position: "absolute", top: -3, bottom: -3, left: `calc(${pct(value)}% - 1px)`,
            width: 2, background: crossed ? severityColor : T.text,
          }}
        />
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4 }}>
        <span style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>{fmt.metric(lo)}</span>
        <span style={{ fontFamily: MONO, fontSize: 10, color: T.text2 }}>{distance}</span>
        <span style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>{fmt.metric(hi)}</span>
      </div>
    </div>
  );
}

/** Position in the kill chain rather than the stage as a string. Showing where
 *  in the sequence a finding sits is the point of having a stage at all. */
function KillChain({ stage }: { stage?: string }) {
  const idx = stage ? KILL_CHAIN.indexOf(stage as (typeof KILL_CHAIN)[number]) : -1;
  if (idx < 0) return null;
  return (
    <div style={{ borderTop: `1px solid ${T.rule}`, paddingTop: 12 }}>
      <div style={{ ...microStyle, marginBottom: 6 }}>Kill chain</div>
      <div style={{ display: "flex", gap: 2, marginBottom: 5 }}>
        {KILL_CHAIN.map((s, i) => (
          <div
            key={s}
            title={s.replace(/_/g, " ")}
            style={{ flex: 1, height: 6, background: i === idx ? T.text : i < idx ? T.text3 : T.rule }}
          />
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", fontFamily: SANS, fontSize: 9, letterSpacing: "0.04em", color: T.text3 }}>
        <span>recon</span>
        <span style={{ color: T.text }}>{stage!.replace(/_/g, " ")}</span>
        <span>actions</span>
      </div>
    </div>
  );
}

/**
 * The raw flow record.
 *
 * Collapsed by default, and rendered from `evidence_raw` as a sorted key/value
 * grid rather than a JSON blob - a blob is a debugging artifact, not an
 * interface. The full payload is still one click away via copy.
 */
function RawRecord({ alert, open, onToggle }: { alert: Alert; open: boolean; onToggle: () => void }) {
  const [copied, setCopied] = useState(false);
  const rows = useMemo(() => {
    const src: Record<string, unknown> = {
      alert_id: alert.alert_id,
      ts: alert.ts,
      flow_id: alert.flow_id,
      src_ip: alert.src_ip,
      dst_ip: alert.dst_ip,
      dst_port: alert.dst_port,
      threat_class: alert.threat_class,
      threat_code: alert.threat_code,
      severity: alert.severity,
      confidence: alert.confidence,
      score: alert.score,
      score_type: alert.score_type,
      detector: alert.detector,
      detector_version: alert.detector_version,
      occurrences: alert.occurrences,
      first_seen: alert.first_seen,
      last_seen: alert.last_seen,
      kill_chain_stage: alert.kill_chain_stage,
      mitre_technique: alert.mitre_technique,
      pipeline_latency_ms: alert.pipeline_latency_ms,
      incident_id: alert.incident_id,
      visual_kind: alert.visual?.kind,
      // The detector's untouched bag, so a novel key still reaches this table
      // even when the threshold registry has no opinion about it.
      ...(alert.evidence_raw ?? {}),
    };
    return Object.entries(src)
      .filter(([, v]) => v !== undefined && v !== null && v !== "")
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : String(v)] as const);
  }, [alert]);

  const copy = () => {
    try {
      navigator.clipboard?.writeText(JSON.stringify(alert, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard unavailable (insecure origin, denied permission); the table
         above is still readable, so this is not worth an error state */
    }
  };

  return (
    <div style={{ padding: "14px 18px 24px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
        <span className="panel-title">Raw flow record</span>
        <button className="ctl" onClick={onToggle} aria-expanded={open}>
          {open ? "collapse" : "expand"}
        </button>
        <span style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>{rows.length} fields</span>
        <button className="ctl" onClick={copy} style={{ marginLeft: "auto" }}>
          {copied ? "copied" : "copy json"}
        </button>
      </div>
      {open && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 32px" }}>
          {rows.map(([k, v]) => (
            <div
              key={k}
              style={{ display: "flex", justifyContent: "space-between", gap: 16, padding: "5px 0", borderBottom: `1px solid ${T.rule}` }}
            >
              <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3 }}>{k}</span>
              <span
                style={{ fontFamily: MONO, fontSize: 11, color: T.text, textAlign: "right", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                title={v}
              >
                {v}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

interface Props {
  alert: Alert | null;
  onOpenHost: (ip: string) => void;
  onOpenIncident?: (id: string) => void;
  /** Raw-record disclosure is owned by the shell so the `e` shortcut and the
   *  expand control drive the same state. Optional, with the collapsed default,
   *  so the panel still renders standalone. */
  rawOpen?: boolean;
  onToggleRaw?: () => void;
}

function EvidencePanelImpl({ alert, onOpenHost, onOpenIncident, rawOpen = false, onToggleRaw }: Props) {
  if (!alert) {
    return (
      <div style={{ display: "flex", flexDirection: "column", height: "100%", background: T.bg }}>
        <div className="panel-head">
          <span className="panel-title">Evidence</span>
        </div>
        <div
          style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: T.text3, fontFamily: SANS, fontSize: 13 }}
        >
          Waiting for first detection.
        </div>
      </div>
    );
  }

  const meta = CLASS_META[alert.threat_class];
  const sev = SEV[alert.severity];
  const critical = alert.severity === "critical";
  const cv = classVisual(alert);
  const reconstructed =
    (alert.visual as { source?: string } | undefined)?.source === "reconstructed_from_summary_statistics";

  // "Order by contribution, most decisive first." `rank` is the backend's own
  // statement of contribution; thresholded items lead only where it is absent.
  const ordered = [...alert.evidence].sort((a, b) => {
    if (a.rank !== undefined && b.rank !== undefined) return a.rank - b.rank;
    if (a.rank !== undefined) return -1;
    if (b.rank !== undefined) return 1;
    return (b.threshold !== undefined ? 1 : 0) - (a.threshold !== undefined ? 1 : 0);
  });

  const mitre = alert.mitre_techniques?.length
    ? alert.mitre_techniques.join("  ")
    : alert.mitre_technique || undefined;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0, background: T.bg }}>
      <div className="panel-head">
        <span className="panel-title">Evidence</span>
        <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, marginLeft: "auto" }}>{alert.alert_id}</span>
      </div>

      <div style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>
        {/* Identity and the class visual sit side by side, so the most
            convincing image in the product is above the fold rather than
            third in a scrolling column (§1.1E). */}
        <div
          style={{
            display: "grid", gridTemplateColumns: "1fr 1fr", gap: 1,
            background: T.rule, borderBottom: `1px solid ${T.rule}`,
          }}
        >
          <div style={{ background: T.bg, padding: "16px 18px", minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <span style={{ fontFamily: MONO, fontSize: 12, fontWeight: 500, color: T.text2, border: `1px solid ${T.ruleBright}`, padding: "2px 5px" }}>
                {alert.threat_code || meta?.code || "??"}
              </span>
              <span style={{ fontFamily: SANS, fontSize: 15, fontWeight: 600, letterSpacing: "0.02em", color: T.text }}>
                {(alert.threat_label || meta?.name || alert.threat_class).toUpperCase()}
              </span>
              <span
                style={{
                  fontFamily: SANS, fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", padding: "3px 6px", marginLeft: "auto",
                  color: critical ? T.bg : sev.color, background: critical ? sev.color : "transparent", border: `1px solid ${sev.color}`,
                }}
              >
                {sev.label}
              </span>
            </div>

            {/* Not every class has both ends: a port scan has one source and
                hundreds of destinations, a flood one target and a distributed
                source. Interpolating unconditionally printed the punctuation
                around the hole - "10.4.2.19 → :" - which reads as a rendering
                fault rather than as a field the detector did not report. §11
                rule 2: an absent value is a labelled dash, and the dash keeps
                the arrow's direction readable. */}
            <div style={{ fontFamily: MONO, fontSize: 15, color: T.text, marginBottom: 14 }}>
              {alert.src_ip?.trim() ? (
                <IpLink ip={alert.src_ip} onOpenHost={onOpenHost} />
              ) : (
                <span style={{ color: T.text3 }} title="No single source address for this finding">
                  &mdash;
                </span>
              )}
              <span style={{ color: T.text3 }}> &rarr; </span>
              {alert.dst_ip?.trim() ? (
                <>
                  <IpLink ip={alert.dst_ip} onOpenHost={onOpenHost} />
                  {alert.dst_port ? <span style={{ color: T.text2 }}>:{alert.dst_port}</span> : null}
                </>
              ) : (
                <span style={{ color: T.text3 }} title="No single destination address for this finding">
                  &mdash;
                </span>
              )}
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 16, flexWrap: "wrap" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 9, flex: 1, minWidth: 200 }}>
                <span style={microStyle}>Confidence</span>
                <span style={{ fontFamily: MONO, fontWeight: 500, fontSize: 18, lineHeight: 1.1, color: T.text }}>
                  {alert.confidence.toFixed(2)}
                </span>
                {/* Neutral, never severity-tinted: severity and confidence are
                    different quantities and must not share an encoding. */}
                <div style={{ flex: 1, maxWidth: 120, height: 6, background: T.rule, position: "relative" }}>
                  <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, background: T.text2, width: `${alert.confidence * 100}%` }} />
                </div>
              </div>
              {alert.score !== undefined && (
                <div style={{ display: "flex", alignItems: "baseline", gap: 8, borderLeft: `1px solid ${T.rule}`, paddingLeft: 14 }}>
                  <span style={microStyle}>Score</span>
                  <span style={{ fontFamily: MONO, fontSize: 15, color: T.text }}>{alert.score.toFixed(2)}</span>
                  {/* A rule score is not a probability, so it is shown as a
                      value with its provenance, never as a bar or a percent. */}
                  {alert.score_type && (
                    <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3 }}>&middot; {alert.score_type}</span>
                  )}
                </div>
              )}
            </div>

            {/* Any field the backend did not send is omitted entirely. No dash,
                no "unknown" - an absent field is information: the detector did
                not report it. */}
            <div style={{ display: "grid", gridTemplateColumns: "auto 1fr auto 1fr", gap: "11px 14px", alignItems: "baseline", marginBottom: 18 }}>
              <Field k="occurrences" v={`×${alert.occurrences}`} />
              {alert.first_seen !== undefined && <Field k="first seen" v={fmtTime(alert.first_seen)} />}
              {alert.last_seen !== undefined && <Field k="last seen" v={fmtTime(alert.last_seen)} />}
              {alert.detector && (
                <Field k="detector" v={`${alert.detector}${alert.detector_version ? ` ${alert.detector_version}` : ""}`} />
              )}
              {mitre && <Field k="MITRE" v={mitre} />}
              {alert.pipeline_latency_ms !== undefined &&
                // Reported to the millisecond, drawn to one decimal. A negative
                // figure is still shown - the backend computes this against the
                // detector's own event clock, so it is real skew between two
                // hosts and worth seeing, not a value to hide.
                //
                // It is not shown *as a latency*, though. Printing
                // "pipeline latency -618850.7ms" labels ten minutes of clock
                // skew with the name of a quantity that cannot be negative, and
                // every viewer reads that as a broken readout rather than as
                // the finding it is. Same number, named for what it measures,
                // at a magnitude the eye can take in.
                (alert.pipeline_latency_ms < 0 ? (
                  <Field
                    k="clock skew"
                    v={fmt.duration(alert.pipeline_latency_ms / -1000)}
                    title="The detector's event clock is ahead of the backend's receipt clock by this much. Pipeline latency cannot be measured across hosts that disagree."
                  />
                ) : (
                  <Field k="pipeline latency" v={`${alert.pipeline_latency_ms.toFixed(1)}ms`} />
                ))}
              {alert.flow_id && <Field k="flow" v={alert.flow_id} />}
              {alert.incident_id && (
                <>
                  <span style={{ ...microStyle, whiteSpace: "nowrap" }}>incident</span>
                  <button
                    className="ip"
                    onClick={() => onOpenIncident?.(alert.incident_id!)}
                    style={{ fontSize: 12, color: T.text, textAlign: "left" }}
                    title="Open this incident"
                  >
                    {alert.incident_id} &rarr;
                  </button>
                </>
              )}
            </div>

            <KillChain stage={alert.kill_chain_stage} />
          </div>

          <div style={{ background: T.bg, padding: "16px 18px", minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 10 }}>
              <span className="panel-title">{cv?.title ?? "Class visual"}</span>
              {/* A comb reconstructed from summary statistics looks like a
                  perfect beacon BY CONSTRUCTION, so presenting it as observed
                  would fabricate the most convincing image in the product. The
                  badge is what keeps the image an argument, not an assertion. */}
              {reconstructed && (
                <span
                  title="No observed series was reported for this alert. The shape below was derived from summary statistics and is illustrative, not observed."
                  style={{ ...microStyle, color: T.text2, border: `1px solid ${T.ruleBright}`, padding: "3px 5px", marginLeft: "auto" }}
                >
                  reconstructed from summary statistics
                </span>
              )}
            </div>
            {cv ? (
              <VisualBoundary key={alert.alert_id}>{cv.node}</VisualBoundary>
            ) : (
              <div style={{ fontFamily: SANS, fontSize: 12, color: T.text3, padding: "8px 0" }}>
                No class visual reported for this detector. The evidence bars below carry this detection.
              </div>
            )}
          </div>
        </div>

        <div style={{ padding: "16px 18px", borderBottom: `1px solid ${T.rule}` }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 10 }}>
            <span className="panel-title">Why this fired</span>
            <span style={{ fontFamily: SANS, fontSize: 10, color: T.text3 }}>most decisive first</span>
          </div>
          {ordered.length === 0 ? (
            <div style={{ fontFamily: SANS, fontSize: 12, color: T.text3 }}>No evidence fields reported.</div>
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 32px" }}>
              {ordered.map((item, i) => (
                <EvidenceBar key={`${item.feature}-${i}`} item={item} severityColor={sev.color} />
              ))}
            </div>
          )}
        </div>

        <RawRecord alert={alert} open={rawOpen} onToggle={onToggleRaw ?? (() => {})} />
      </div>
    </div>
  );
}

/**
 * Memoized on the alert's identity plus its deduplication state.
 *
 * The parent re-renders once per animation frame while the feed is running, and
 * this subtree is the most expensive one in the product. `occurrences` and
 * `last_seen` are the only fields the backend revises on an existing alert_id,
 * and they are exactly what a repeating alert changes, so including them keeps
 * a live-updating selection honest while still ignoring every update that
 * concerns a different alert.
 */
export const EvidencePanel = memo(EvidencePanelImpl, (prev, next) => {
  if (prev.onOpenHost !== next.onOpenHost) return false;
  if (prev.onOpenIncident !== next.onOpenIncident) return false;
  if (prev.rawOpen !== next.rawOpen) return false;
  if (prev.onToggleRaw !== next.onToggleRaw) return false;
  const a = prev.alert;
  const b = next.alert;
  if (a === b) return true;
  if (!a || !b) return false;
  return (
    a.alert_id === b.alert_id &&
    a.occurrences === b.occurrences &&
    a.last_seen === b.last_seen
  );
});
