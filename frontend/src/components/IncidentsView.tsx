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

function IncidentRibbon({ incident, onSelectAlert, onOpenHost }: { incident: Incident; onSelectAlert: (id: string) => void; onOpenHost: (ip: string) => void }) {
  const stages = incident.stages;
  const elapsedMin = Math.round((stages[stages.length - 1].ts - incident.opened_at) / 60);
  const sev = SEV[incident.severity];

  return (
    <div style={{ border: `1px solid ${T.rule}`, background: T.panel, padding: 16, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 14, fontFamily: SANS, fontSize: 13, color: T.text2 }}>
        HOST <IpLink ip={incident.host} onOpenHost={onOpenHost} />
        <span style={{ color: T.text3 }}>incident opened {fmtTime(incident.opened_at)}</span>
        <span style={{ color: T.text3 }}>&middot; {stages.length} alerts</span>
        <span style={{ color: sev.color, fontWeight: 600, marginLeft: "auto" }}>{sev.label}</span>
      </div>
      <div style={{ display: "flex", alignItems: "flex-start", position: "relative" }}>
        <div style={{ position: "absolute", top: 6, left: `${100 / stages.length / 2}%`, right: `${100 / stages.length / 2}%`, height: 1, background: T.ruleBright }} />
        {stages.map((a) => {
          const m = CLASS_META[a.threat_class];
          return (
            <div key={a.alert_id} onClick={() => onSelectAlert(a.alert_id)} style={{ flex: 1, textAlign: "center", cursor: "pointer" }}>
              <div style={{ width: 12, height: 12, borderRadius: "50%", background: T.bg, border: `2px solid ${SEV[a.severity].color}`, margin: "0 auto 8px" }} />
              <div style={{ fontFamily: MONO, fontSize: 12, color: T.text2, border: `1px solid ${T.rule}`, padding: "1px 5px", display: "inline-block", marginBottom: 4 }}>{m.code}</div>
              <div style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>{fmtTime(a.ts)}</div>
              <div style={{ fontFamily: SANS, fontSize: 11, color: T.text2, marginTop: 2 }}>{m.name.toLowerCase()}</div>
              <div style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>conf {a.confidence.toFixed(2)}</div>
            </div>
          );
        })}
      </div>
      <div style={{ textAlign: "center", marginTop: 12, paddingTop: 8, borderTop: `1px solid ${T.rule}`, fontFamily: MONO, fontSize: 11, color: T.text3 }}>
        {elapsedMin} min elapsed
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