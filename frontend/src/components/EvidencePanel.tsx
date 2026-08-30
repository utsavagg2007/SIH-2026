import { T, SEV, CLASS_META, MONO, SANS, labelStyle } from "../lib/tokens";
import type { Alert, EvidenceItem } from "../lib/types";
import { classVisual } from "./visuals";

function IpLink({ ip, onOpenHost }: { ip: string; onOpenHost: (ip: string) => void }) {
  return (
    <span
      onClick={(e) => { e.stopPropagation(); onOpenHost(ip); }}
      style={{ fontFamily: MONO, color: T.text, cursor: "pointer", textDecoration: "underline", textDecorationColor: T.rule, textUnderlineOffset: 2 }}
    >
      {ip}
    </span>
  );
}

function EvidenceBar({ item, severityColor }: { item: EvidenceItem; severityColor: string }) {
  const hasThreshold = item.threshold !== undefined;
  if (!hasThreshold) {
    return (
      <div style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: `1px solid ${T.rule}` }}>
        <span style={{ fontFamily: MONO, fontSize: 13, color: T.text2 }}>{item.feature}</span>
        <span style={{ fontFamily: MONO, fontSize: 13, color: T.text, fontVariantNumeric: "tabular-nums" }}>{item.value}</span>
      </div>
    );
  }
  const [lo, hi] = item.scale || [0, (item.threshold as number) * 2 || 1];
  const pct = (v: number) => Math.max(0, Math.min(100, ((v - lo) / (hi - lo)) * 100));
  const value = item.value as number;
  const crossed = item.direction === "above" ? value >= (item.threshold as number) : value <= (item.threshold as number);
  return (
    <div style={{ padding: "8px 0", borderBottom: `1px solid ${T.rule}` }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
        <span style={{ fontFamily: MONO, fontSize: 13, color: T.text2 }}>{item.feature}</span>
        <span style={{ fontFamily: MONO, fontSize: 13, fontVariantNumeric: "tabular-nums", color: crossed ? severityColor : T.text }}>{item.value}</span>
      </div>
      <div style={{ position: "relative", height: 6, background: T.rule }}>
        <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: `${pct(value)}%`, background: T.text2 }} />
        <div style={{ position: "absolute", top: -3, bottom: -3, left: `${pct(item.threshold as number)}%`, width: 1, background: T.ruleBright }} />
        {crossed && <div style={{ position: "absolute", top: -2, bottom: -2, left: `calc(${pct(value)}% - 1px)`, width: 2, background: severityColor }} />}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginTop: 2 }}>
        <span style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>{lo}</span>
        <span style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>threshold {item.threshold}</span>
        <span style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>{hi}</span>
      </div>
    </div>
  );
}

export function EvidencePanel({ alert, onOpenHost }: { alert: Alert | null; onOpenHost: (ip: string) => void }) {
  if (!alert) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: T.text3, fontFamily: SANS, fontSize: 13 }}>
        Waiting for first detection.
      </div>
    );
  }

  const meta = CLASS_META[alert.threat_class];
  const sev = SEV[alert.severity];
  const ordered = [...alert.evidence].sort((a, b) => (b.threshold !== undefined ? 1 : 0) - (a.threshold !== undefined ? 1 : 0));
  const cv = classVisual(alert);

  return (
    <div style={{ height: "100%", overflowY: "auto" }}>
      <div style={{ padding: 16, borderBottom: `1px solid ${T.rule}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
          <span style={{ fontFamily: MONO, fontSize: 11, color: T.text2, border: `1px solid ${T.rule}`, padding: "2px 5px" }}>{meta.code}</span>
          <span style={{ fontFamily: SANS, fontSize: 15, fontWeight: 600, color: T.text }}>{meta.name.toUpperCase()}</span>
          <span style={{ fontFamily: SANS, fontSize: 11, fontWeight: 600, letterSpacing: "0.06em", color: sev.color, marginLeft: "auto" }}>{sev.label}</span>
        </div>
        <div style={{ fontFamily: MONO, fontSize: 13, color: T.text2, marginBottom: 10 }}>
          <IpLink ip={alert.src_ip} onOpenHost={onOpenHost} /> <span style={{ color: T.text3 }}>&rarr;</span>{" "}
          <IpLink ip={alert.dst_ip} onOpenHost={onOpenHost} />:{alert.dst_port}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={labelStyle}>confidence</span>
          <span style={{ fontFamily: MONO, fontSize: 18, color: T.text, fontVariantNumeric: "tabular-nums" }}>{alert.confidence.toFixed(2)}</span>
          <div style={{ flex: 1, height: 6, background: T.rule, position: "relative" }}>
            <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: `${alert.confidence * 100}%`, background: T.text2 }} />
          </div>
        </div>
      </div>

      <div style={{ padding: 16, borderBottom: `1px solid ${T.rule}` }}>
        <div style={{ ...labelStyle, marginBottom: 8 }}>Why this fired</div>
        {ordered.map((item, i) => <EvidenceBar key={i} item={item} severityColor={sev.color} />)}
      </div>

      {cv && (
        <div style={{ padding: 16, borderBottom: `1px solid ${T.rule}` }}>
          <div style={{ ...labelStyle, marginBottom: 8 }}>{cv.title}</div>
          {cv.node}
        </div>
      )}

      <div style={{ padding: 16 }}>
        <div style={{ ...labelStyle, marginBottom: 8 }}>Raw flow record</div>
        <pre style={{ fontFamily: MONO, fontSize: 11, color: T.text2, background: T.panel2, padding: 10, margin: 0, overflowX: "auto" }}>
{JSON.stringify(alert, null, 2)}
        </pre>
      </div>
    </div>
  );
}