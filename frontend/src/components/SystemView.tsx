import { T, CLASS_META, MONO, SANS, headingStyle, labelStyle } from "../lib/tokens";
import type { Alert, Metrics } from "../lib/types";

const rand = (a: number, b: number) => a + Math.random() * (b - a);

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ background: T.panel, display: "flex", flexDirection: "column", minHeight: 0 }}>
      <div style={{ padding: "10px 14px", borderBottom: `1px solid ${T.rule}`, flexShrink: 0 }}>
        <span style={headingStyle}>{title}</span>
      </div>
      <div style={{ padding: 16, flex: 1, minHeight: 0, overflow: "auto" }}>{children}</div>
    </div>
  );
}

function ThroughputPanel({ history }: { history: { t: number; flowsPerSec: number }[] }) {
  const width = 460, height = 90;
  const flows = history.map((h) => h.flowsPerSec);
  const max = Math.max(1, ...flows);
  const sustained = flows.length ? Math.round(flows.reduce((a, b) => a + b, 0) / flows.length) : 0;
  const peak = flows.length ? Math.max(...flows) : 0;
  const path = flows.map((v, i) => `${i === 0 ? "M" : "L"}${((i / Math.max(1, flows.length - 1)) * width).toFixed(1)},${(height - (v / max) * height).toFixed(1)}`).join(" ");
  return (
    <div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 16, marginBottom: 12 }}>
        <div>
          <div style={labelStyle}>sustained</div>
          <div style={{ fontFamily: MONO, fontSize: 28, color: T.text, fontVariantNumeric: "tabular-nums" }}>{sustained.toLocaleString()}</div>
          <div style={{ fontFamily: SANS, fontSize: 10, color: T.text3 }}>flows/sec</div>
        </div>
        <div>
          <div style={labelStyle}>tested peak</div>
          <div style={{ fontFamily: MONO, fontSize: 18, color: T.text2, fontVariantNumeric: "tabular-nums" }}>{peak.toLocaleString()}</div>
        </div>
      </div>
      <svg width="100%" viewBox={`0 0 ${width} ${height}`} style={{ display: "block" }}>
        <line x1="0" y1={height} x2={width} y2={height} stroke={T.rule} strokeWidth="1" />
        <path d={path} fill="none" stroke={T.text2} strokeWidth="1.25" />
      </svg>
    </div>
  );
}

function LatencyPanel({ p50, p95, samples }: { p50: number; p95: number; samples: number[] }) {
  const width = 460, height = 90, bins = 20;
  const maxSample = Math.max(...samples, p95 * 1.5, 1);
  const counts = new Array(bins).fill(0);
  samples.forEach((s) => counts[Math.min(bins - 1, Math.floor((s / maxSample) * bins))]++);
  const maxCount = Math.max(1, ...counts);
  const binW = width / bins;
  const markerX = (v: number) => (v / maxSample) * width;
  return (
    <div>
      <div style={{ display: "flex", gap: 24, marginBottom: 12 }}>
        <div><span style={{ ...labelStyle, marginRight: 6 }}>median</span><span style={{ fontFamily: MONO, fontSize: 15, color: T.text }}>{p50}ms</span></div>
        <div><span style={{ ...labelStyle, marginRight: 6 }}>p95</span><span style={{ fontFamily: MONO, fontSize: 15, color: T.text }}>{p95}ms</span></div>
      </div>
      <svg width="100%" viewBox={`0 0 ${width} ${height + 16}`} style={{ display: "block" }}>
        {counts.map((c, i) => <rect key={i} x={i * binW + 1} y={height - (c / maxCount) * height} width={binW - 2} height={(c / maxCount) * height} fill={T.text2} />)}
        <line x1="0" y1={height} x2={width} y2={height} stroke={T.rule} strokeWidth="1" />
        <line x1={markerX(p50)} y1="0" x2={markerX(p50)} y2={height} stroke={T.ruleBright} strokeWidth="1" />
        <line x1={markerX(p95)} y1="0" x2={markerX(p95)} y2={height} stroke={T.sevMed} strokeWidth="1" />
        <text x={markerX(p50) + 3} y={height + 12} fill={T.text3} fontFamily={MONO} fontSize="10">p50</text>
        <text x={markerX(p95) + 3} y={height + 12} fill={T.sevMed} fontFamily={MONO} fontSize="10">p95</text>
      </svg>
    </div>
  );
}

function DetectorStatusPanel({ alerts }: { alerts: Alert[] }) {
  const rows = Object.entries(CLASS_META).map(([key, meta]) => ({
    key, name: meta.name, code: meta.code,
    state: key === "dns_tunnel" ? "degraded" : "online",
    alertsProduced: alerts.filter((a) => a.threat_class === key).length,
    meanScoringMs: +rand(0.4, 3.2).toFixed(1),
    version: "0.3.1",
  }));
  return (
    <div>
      <div style={{ display: "grid", gridTemplateColumns: "28px 1fr 80px 70px 90px 60px", gap: 8, padding: "0 0 6px", borderBottom: `1px solid ${T.rule}` }}>
        {["", "detector", "state", "alerts", "scoring", "ver"].map((h, i) => <span key={i} style={labelStyle}>{h}</span>)}
      </div>
      {rows.map((r) => (
        <div key={r.key} style={{ display: "grid", gridTemplateColumns: "28px 1fr 80px 70px 90px 60px", gap: 8, padding: "7px 0", borderBottom: `1px solid ${T.rule}`, alignItems: "center" }}>
          <span style={{ fontFamily: MONO, fontSize: 11, color: T.text2, border: `1px solid ${T.rule}`, padding: "1px 4px", width: "fit-content" }}>{r.code}</span>
          <span style={{ fontFamily: SANS, fontSize: 12, color: T.text }}>{r.name}</span>
          <span style={{ fontFamily: MONO, fontSize: 11, color: r.state === "online" ? T.sevLow : T.sevMed }}>{r.state}</span>
          <span style={{ fontFamily: MONO, fontSize: 12, color: T.text2, fontVariantNumeric: "tabular-nums" }}>{r.alertsProduced}</span>
          <span style={{ fontFamily: MONO, fontSize: 12, color: T.text2, fontVariantNumeric: "tabular-nums" }}>{r.meanScoringMs}ms</span>
          <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3 }}>{r.version}</span>
        </div>
      ))}
    </div>
  );
}

function ConstraintPanel() {
  const rows = [
    { l: "egress state", v: "blocked — no path out" },
    { l: "ingest direction", v: "one-way, mirrored copy only" },
    { l: "payload decryption", v: "none performed" },
  ];
  return (
    <div>
      {rows.map((r, i) => (
        <div key={i} style={{ padding: "10px 0", borderBottom: i < rows.length - 1 ? `1px solid ${T.rule}` : "none" }}>
          <div style={{ ...labelStyle, marginBottom: 3 }}>{r.l}</div>
          <div style={{ fontFamily: MONO, fontSize: 14, color: T.text }}>{r.v}</div>
        </div>
      ))}
    </div>
  );
}

interface Props {
  metrics: Metrics;
  throughputHistory: { t: number; flowsPerSec: number }[];
  latencySamples: number[];
  alerts: Alert[];
}

export function SystemView({ metrics, throughputHistory, latencySamples, alerts }: Props) {
  return (
    <div style={{ flex: 1, display: "grid", gridTemplateColumns: "1fr 1fr", gridTemplateRows: "1fr 1fr", gap: 1, background: T.rule, minHeight: 0, overflow: "auto" }}>
      <Panel title="Throughput"><ThroughputPanel history={throughputHistory} /></Panel>
      <Panel title="Latency"><LatencyPanel p50={metrics.p50} p95={metrics.p95} samples={latencySamples} /></Panel>
      <Panel title="Detector status"><DetectorStatusPanel alerts={alerts} /></Panel>
      <Panel title="Constraint panel"><ConstraintPanel /></Panel>
    </div>
  );
}