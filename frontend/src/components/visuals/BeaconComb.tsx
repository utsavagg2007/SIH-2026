import { useMemo } from "react";
import { T, labelStyle } from "../../lib/tokens";
import type { ClassVisual } from "../../lib/types";
import { SourceBadge, type VisualChrome } from "./chrome";

type Props = Extract<ClassVisual, { kind: "beacon_comb" }> & VisualChrome;

const rand = (a: number, b: number) => a + Math.random() * (b - a);

export function BeaconComb({ periods = 42, jitterPct = 4, source, sevColor }: Props) {
  const width = 480;

  const beaconTicks = useMemo(() => {
    const n = Math.min(periods, 34);
    const spacing = width / (n + 1);
    return Array.from({ length: n }, (_, i) => spacing * (i + 1) + rand(-spacing * (jitterPct / 100), spacing * (jitterPct / 100)));
  }, [periods, jitterPct]);

  const humanTicks = useMemo(() => {
    const out: number[] = [];
    for (let c = 0; c < 5; c++) {
      const center = rand(20, width - 20);
      const n = Math.floor(rand(2, 6));
      for (let i = 0; i < n; i++) out.push(center + rand(-15, 15));
    }
    return out.filter((x) => x > 0 && x < width);
  }, []);

  const Row = ({ text, ticks, color }: { text: string; ticks: number[]; color: string }) => (
    <div style={{ marginBottom: 14 }}>
      <div style={{ ...labelStyle, marginBottom: 4 }}>{text}</div>
      <svg width="100%" viewBox={`0 0 ${width} 28`} style={{ display: "block" }}>
        <line x1="0" y1="24" x2={width} y2="24" stroke={T.rule} strokeWidth="1" />
        {ticks.map((x, i) => <line key={i} x1={x} y1="4" x2={x} y2="24" stroke={color} strokeWidth="1.5" />)}
      </svg>
    </div>
  );

  return (
    <div>
      <SourceBadge source={source} />
      <Row text="This flow" ticks={beaconTicks} color={sevColor} />
      <Row text="Typical host" ticks={humanTicks} color={T.text2} />
      <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "monospace", fontSize: 10, color: T.text3, marginTop: -6 }}>
        <span>0</span><span>60 min</span>
      </div>
      <div style={{ marginTop: 12, fontFamily: "monospace", fontSize: 13, color: T.text }}>
        measured jitter <span style={{ color: sevColor }}>{jitterPct}%</span>
      </div>
    </div>
  );
}