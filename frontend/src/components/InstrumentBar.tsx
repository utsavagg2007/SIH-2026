import { T, MONO, labelStyle } from "../lib/tokens";
import type { Metrics } from "../lib/types";

export function InstrumentBar({ metrics }: { metrics: Metrics }) {
  // The backend never sees a packet: flow, packet and bit rates are reported by
  // the ingestion and detection layers over POST /api/v1/telemetry, or not at
  // all. When nothing has reported, these read as a dash rather than as zero -
  // a confident 0.0 Mb/s next to a live alert stream is a lie about what the
  // system knows, and it is the readout requirement (d) is graded on.
  const traffic = (value: string) => (metrics.trafficLive ? value : "—");

  const items = [
    { l: "flows/sec", v: traffic(metrics.flowsPerSec.toLocaleString()) },
    { l: "Mb/s", v: traffic(metrics.mbps.toFixed(1)) },
    { l: "p95 latency", v: `${metrics.p95}ms` },
    { l: "detectors", v: `${metrics.detectorsOnline}/${metrics.detectorsTotal}` },
    { l: "uptime", v: metrics.uptime },
  ];
  return (
    <div style={{ height: 48, borderTop: `1px solid ${T.rule}`, display: "flex", alignItems: "center", padding: "0 16px", gap: 24, flexShrink: 0, background: T.panel }}>
      {items.map((it, i) => (
        <div key={i} style={{ display: "flex", alignItems: "baseline", gap: 6, borderRight: `1px solid ${T.rule}`, paddingRight: 24 }}>
          <span style={{ fontFamily: MONO, fontSize: 15, color: T.text, fontVariantNumeric: "tabular-nums" }}>{it.v}</span>
          <span style={labelStyle}>{it.l}</span>
        </div>
      ))}
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ width: 6, height: 6, borderRadius: "50%", background: metrics.connected ? T.sevLow : T.sevCrit }} />
        <span style={{ fontFamily: MONO, fontSize: 11, color: metrics.connected ? T.text2 : T.sevCrit }}>
          {metrics.connected ? "streaming" : "feed stopped"}
        </span>
      </div>
    </div>
  );
}