import { T, labelStyle } from "../../lib/tokens";
import type { ClassVisual } from "../../lib/types";
import { type VisualChrome } from "./chrome";

type Props = Extract<ClassVisual, { kind: "baseline_departure" }> & VisualChrome;

export function BaselineDeparture({ series, baselineBand, source, sevColor }: Props) {
  const width = 460, height = 100;
  const max = Math.max(...series, baselineBand[1]);
  const pathFor = (s: number[]) =>
    s.map((v, i) => `${i === 0 ? "M" : "L"}${((i / (s.length - 1)) * width).toFixed(1)},${(height - (v / max) * height).toFixed(1)}`).join(" ");
  const bandY1 = height - (baselineBand[1] / max) * height;
  const bandY2 = height - (baselineBand[0] / max) * height;

  return (
    <div>
      <div style={{ ...labelStyle, marginBottom: 6 }}>outbound bytes / hour, last 72h</div>
      <svg width="100%" viewBox={`0 0 ${width} ${height}`} style={{ display: "block" }}>
        <rect x="0" y={bandY1} width={width} height={bandY2 - bandY1} fill={T.baseline} opacity="0.18" />
        <line x1="0" y1={height} x2={width} y2={height} stroke={T.rule} strokeWidth="1" />
        <path d={pathFor(series)} fill="none" stroke={sevColor} strokeWidth="1.5" />
      </svg>
    </div>
  );
}