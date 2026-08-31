/**
 * The kill-chain ribbon (spec 6.1).
 *
 * An incident is several alerts on one host correlated into a sequence, drawn
 * ordered by stage rather than only by time. The ribbon is the argument: these
 * findings are one story, and the sequence is itself evidence. This is where
 * the fusion layer's work becomes visible.
 *
 * The nodes come from the backend's `members` array, which is the trimmed
 * narrative slice rather than the full alert set - so `alert_count` and
 * `elapsed_sec` are read from the incident itself instead of derived from the
 * nodes on screen. Counting the drawn nodes would under-report a long incident
 * and quietly contradict the exact figure the backend went to the trouble of
 * carrying separately.
 */
import { T, SEV, CLASS_META, MONO, SANS } from "../lib/tokens";
import { fmtTime } from "../lib/format";
import type { Incident } from "../lib/types";

function IpLink({ ip, onOpenHost }: { ip: string; onOpenHost: (ip: string) => void }) {
  return (
    <span onClick={() => onOpenHost(ip)} style={{ fontFamily: MONO, color: T.text, cursor: "pointer", textDecoration: "underline", textDecorationColor: T.rule }}>
      {ip}
    </span>
  );
}

function elapsedLabel(seconds: number): string {
  if (seconds < 90) return `${Math.round(seconds)} sec elapsed`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min elapsed`;
  return `${(seconds / 3600).toFixed(1)} h elapsed`;
}

function IncidentRibbon({ incident, onSelectAlert, onOpenHost }: { incident: Incident; onSelectAlert: (id: string) => void; onOpenHost: (ip: string) => void }) {
  const members = incident.members ?? [];
  const sev = SEV[incident.severity];

  return (
    <div style={{ border: `1px solid ${T.rule}`, background: T.panel, padding: 16, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 14, fontFamily: SANS, fontSize: 13, color: T.text2, flexWrap: "wrap" }}>
        HOST <IpLink ip={incident.pivot_host} onOpenHost={onOpenHost} />
        <span style={{ color: T.text3 }}>incident opened {fmtTime(incident.opened_at)}</span>
        <span style={{ color: T.text3 }}>&middot; {incident.alert_count} alerts</span>
        {incident.escalated && (
          <span style={{ fontFamily: SANS, fontSize: 9, fontWeight: 600, letterSpacing: "0.07em", textTransform: "uppercase", color: T.text2, border: `1px solid ${T.ruleBright}`, padding: "3px 4px" }}>
            escalated
          </span>
        )}
        <span style={{ color: sev.color, fontWeight: 600, marginLeft: "auto" }}>{sev.label}</span>
      </div>

      {members.length === 0 ? (
        <div style={{ fontFamily: SANS, fontSize: 13, color: T.text3 }}>Correlated, member alerts not yet loaded.</div>
      ) : (
        <div style={{ display: "flex", alignItems: "flex-start", position: "relative" }}>
          <div style={{ position: "absolute", top: 6, left: `${100 / members.length / 2}%`, right: `${100 / members.length / 2}%`, height: 1, background: T.ruleBright }} />
          {members.map((m) => {
            const meta = CLASS_META[m.threat_class];
            return (
              <div key={m.alert_id} onClick={() => onSelectAlert(m.alert_id)} style={{ flex: 1, textAlign: "center", cursor: "pointer" }}>
                <div style={{ width: 12, height: 12, borderRadius: "50%", background: T.bg, border: `2px solid ${SEV[m.severity].color}`, margin: "0 auto 8px" }} />
                <div style={{ fontFamily: MONO, fontSize: 12, color: T.text2, border: `1px solid ${T.rule}`, padding: "1px 5px", display: "inline-block", marginBottom: 4 }}>
                  {m.threat_code || meta?.code || "??"}
                </div>
                <div style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>{fmtTime(m.ts)}</div>
                <div style={{ fontFamily: SANS, fontSize: 11, color: T.text2, marginTop: 2 }}>{meta?.name.toLowerCase() ?? m.threat_class}</div>
                <div style={{ fontFamily: MONO, fontSize: 10, color: T.text3, fontVariantNumeric: "tabular-nums" }}>conf {m.confidence.toFixed(2)}</div>
              </div>
            );
          })}
        </div>
      )}

      <div style={{ textAlign: "center", marginTop: 12, paddingTop: 8, borderTop: `1px solid ${T.rule}`, fontFamily: MONO, fontSize: 11, color: T.text3, fontVariantNumeric: "tabular-nums" }}>
        {elapsedLabel(incident.elapsed_sec)}
        {incident.members_truncated && (
          <span> &middot; {members.length} of {incident.alert_count} shown</span>
        )}
      </div>
    </div>
  );
}

export function IncidentsView({ incidents, onSelectAlert, onOpenHost }: { incidents: Incident[]; onSelectAlert: (id: string) => void; onOpenHost: (ip: string) => void }) {
  if (incidents.length === 0) {
    return <div style={{ padding: 24, fontFamily: SANS, fontSize: 13, color: T.text3 }}>No correlated incidents yet.</div>;
  }
  return (
    <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
      {incidents.map((inc) => (
        <IncidentRibbon key={inc.incident_id} incident={inc} onSelectAlert={onSelectAlert} onOpenHost={onOpenHost} />
      ))}
    </div>
  );
}
