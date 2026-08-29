import { useMemo } from "react";
import { T, SEV, CLASS_META, MONO, SANS, headingStyle } from "../lib/tokens";
import { fmtTime } from "../lib/format";
import type { Alert, Incident } from "../lib/types";

const rand = (a: number, b: number) => a + Math.random() * (b - a);
const oct = () => Math.floor(rand(0, 255));
const externalIp = () => `185.62.${oct()}.${oct()}`;

interface Props {
  host: string | null;
  alerts: Alert[];
  incidents: Incident[];
  onSelectAlert: (id: string) => void;
}

export function HostView({ host, alerts, incidents, onSelectAlert }: Props) {
  const hostAlerts = alerts.filter((a) => a.src_ip === host || a.dst_ip === host);
  const hostIncidents = incidents.filter((i) => i.host === host);

  // In production these three come from GET /hosts/{ip} (section 7). Mocked
  // here so the screen is fully browsable before that endpoint is wired up.
  const baseline = useMemo(() => Array.from({ length: 48 }, (_, i) => 800 + Math.sin(i / 5) * 200 + rand(-50, 50)), [host]);
  const current = useMemo(() => baseline.map((v, i) => (i > 40 ? v * rand(2, 5) : v * rand(0.9, 1.1))), [baseline]);
  const maxV = Math.max(...baseline, ...current);
  const destinations = useMemo(
    () => Array.from({ length: 8 }, () => ({ ip: externalIp(), novel: Math.random() > 0.6, bytes: Math.floor(rand(1e5, 5e8)) })),
    [host]
  );

  if (!host) {
    return <div style={{ padding: 24, fontFamily: SANS, fontSize: 13, color: T.text3 }}>Click any IP address in the interface to open its host view.</div>;
  }

  return (
    <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
      <div style={{ fontFamily: MONO, fontSize: 20, color: T.text, marginBottom: 16 }}>{host}</div>

      <div style={{ border: `1px solid ${T.rule}`, background: T.panel, padding: 16, marginBottom: 12 }}>
        <div style={{ ...headingStyle, marginBottom: 10 }}>Timeline</div>
        {hostAlerts.length === 0 && <div style={{ fontFamily: SANS, fontSize: 13, color: T.text3 }}>No traffic on this interface.</div>}
        {hostAlerts.slice(0, 10).map((a) => {
          const m = CLASS_META[a.threat_class];
          return (
            <div key={a.alert_id} onClick={() => onSelectAlert(a.alert_id)} style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 0", borderBottom: `1px solid ${T.rule}`, cursor: "pointer" }}>
              <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, width: 90 }}>{fmtTime(a.ts)}</span>
              <span style={{ fontFamily: MONO, fontSize: 11, color: T.text2, border: `1px solid ${T.rule}`, padding: "1px 4px" }}>{m.code}</span>
              <span style={{ fontFamily: SANS, fontSize: 12, color: T.text2 }}>{m.name}</span>
              <span style={{ fontFamily: SANS, fontSize: 11, fontWeight: 600, color: SEV[a.severity].color, marginLeft: "auto" }}>{SEV[a.severity].label}</span>
            </div>
          );
        })}
      </div>

      <div style={{ border: `1px solid ${T.rule}`, background: T.panel, padding: 16, marginBottom: 12 }}>
        <div style={{ ...headingStyle, marginBottom: 10 }}>Baseline vs current</div>
        <svg width="100%" viewBox="0 0 460 90" style={{ display: "block" }}>
          <path d={baseline.map((v, i) => `${i === 0 ? "M" : "L"}${((i / 47) * 460).toFixed(1)},${(90 - (v / maxV) * 90).toFixed(1)}`).join(" ")} fill="none" stroke={T.baseline} strokeWidth="1.5" />
          <path d={current.map((v, i) => `${i === 0 ? "M" : "L"}${((i / 47) * 460).toFixed(1)},${(90 - (v / maxV) * 90).toFixed(1)}`).join(" ")} fill="none" stroke={T.text} strokeWidth="1.5" />
        </svg>
        <div style={{ display: "flex", gap: 14, marginTop: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 10, height: 2, background: T.baseline, display: "inline-block" }} />
            <span style={{ fontFamily: SANS, fontSize: 11, color: T.text2 }}>learned baseline</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 10, height: 2, background: T.text, display: "inline-block" }} />
            <span style={{ fontFamily: SANS, fontSize: 11, color: T.text2 }}>current</span>
          </div>
        </div>
      </div>

      <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
        <div style={{ flex: 1, border: `1px solid ${T.rule}`, background: T.panel, padding: 16 }}>
          <div style={{ ...headingStyle, marginBottom: 10 }}>Destinations</div>
          {destinations.map((d, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0", fontFamily: MONO, fontSize: 12, color: T.text2 }}>
              <span>{d.ip}</span>
              {d.novel && <span style={{ fontFamily: SANS, fontSize: 10, color: T.sevHigh, border: `1px solid ${T.sevHigh}`, padding: "0 4px" }}>never seen</span>}
              <span style={{ marginLeft: "auto", color: T.text3 }}>{(d.bytes / 1e6).toFixed(1)} MB</span>
            </div>
          ))}
        </div>
        <div style={{ flex: 1, border: `1px solid ${T.rule}`, background: T.panel, padding: 16 }}>
          <div style={{ ...headingStyle, marginBottom: 10 }}>Incidents involving this host</div>
          {hostIncidents.length === 0 && <div style={{ fontFamily: SANS, fontSize: 13, color: T.text3 }}>None.</div>}
          {hostIncidents.map((inc) => (
            <div key={inc.incident_id} style={{ fontFamily: MONO, fontSize: 12, color: T.text2, padding: "4px 0" }}>
              {inc.stages.map((s) => CLASS_META[s.threat_class].code).join(" \u2192 ")}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}