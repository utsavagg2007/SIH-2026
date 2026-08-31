import { T, labelStyle } from "../../lib/tokens";
import type { ClassVisual } from "../../lib/types";
import { SourceBadge, type VisualChrome } from "./chrome";

type Props = Extract<ClassVisual, { kind: "entropy_rate" }> & VisualChrome;

export function EntropyRateChart({ rateSeries, entropySeries, spoofed, baselineLow, baselineHigh, source, sevColor }: Props) {
  const width = 480, rateH = 70, entH = 70, gapY = 18;
  const n = rateSeries.length || 1;
  const stepX = width / (n - 1 || 1);
  const maxRate = Math.max(1, ...rateSeries);

  const pathFor = (series: number[], h: number, max: number, min = 0) =>
    series.map((v, i) => `${i === 0 ? "M" : "L"}${(i * stepX).toFixed(1)},${(h - ((v - min) / (max - min || 1)) * h).toFixed(1)}`).join(" ");

  const baseY = (v: number) => entH - v * entH;

  return (
    <div>
      <SourceBadge source={source} />
      <div style={{ ...labelStyle, marginBottom: 4 }}>packet rate</div>
      <svg width="100%" viewBox={`0 0 ${width} ${rateH}`} style={{ display: "block", marginBottom: gapY }}>
        <line x1="0" y1={rateH} x2={width} y2={rateH} stroke={T.rule} strokeWidth="1" />
        <path d={pathFor(rateSeries, rateH, maxRate)} fill="none" stroke={T.text} strokeWidth="1.5" />
      </svg>
      <div style={{ ...labelStyle, marginBottom: 4 }}>source-IP entropy</div>
      <svg width="100%" viewBox={`0 0 ${width} ${entH}`} style={{ display: "block" }}>
        <rect x="0" y={baseY(baselineHigh)} width={width} height={baseY(baselineLow) - baseY(baselineHigh)} fill={T.baseline} opacity="0.18" />
        <line x1="0" y1={rateH} x2={width} y2={rateH} stroke={T.rule} strokeWidth="1" />
        <path d={pathFor(entropySeries, entH, 1)} fill="none" stroke={sevColor} strokeWidth="1.5" />
      </svg>
      <div style={{ fontFamily: "monospace", fontSize: 12, color: T.text2, marginTop: 8 }}>
        {spoofed ? "entropy climbing out of the learned band — spoofed sources" : "entropy collapsing out of the learned band — direct flood"}
      </div>
    </div>
  );
}