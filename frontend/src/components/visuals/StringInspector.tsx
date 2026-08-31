/**
 * DG - the string inspector (spec 5.2).
 *
 * The queried domain at readout-lg, with the n-gram heat drawn as a background
 * band behind each character span: darker where the sequence is improbable
 * against the legitimate-domain corpus. Below it, the host's NXDOMAIN
 * sparkline - the behavioural half of the detection, on the same screen as the
 * string half.
 *
 * The heat band takes the alert's severity colour rather than a fixed one. It
 * used to be hardcoded to `--sev-crit`, which meant every DGA alert rendered as
 * critical no matter what the detector actually said - a low-confidence
 * medium-severity domain drew in exactly the same red as a confirmed one. That
 * breaks the single most important rule in the design spec: colour is reserved
 * for severity, so a colour that does not vary with severity is not carrying
 * information, it is decorating. It also inverts the ramp's purpose, since the
 * loudest thing on screen stops correlating with the most urgent thing on
 * screen.
 */
import { T, MONO, labelStyle } from "../../lib/tokens";
import type { ClassVisual } from "../../lib/types";
import { SourceBadge, type VisualChrome } from "./chrome";

type Props = Extract<ClassVisual, { kind: "string_inspector" }> & VisualChrome;

export function StringInspector({ domain, heat, nxdomain, score, source, sevColor }: Props) {
  const width = 460, h = 26;
  const chars = domain.split("");
  const cellW = width / Math.max(chars.length, 1);
  const maxNx = Math.max(1, ...nxdomain);

  return (
    <div>
      <SourceBadge source={source} />
      <div style={{ ...labelStyle, marginBottom: 6 }}>queried domain</div>
      <svg width="100%" viewBox={`0 0 ${width} ${h}`} style={{ display: "block", marginBottom: 8 }}>
        {chars.map((_, i) => (
          <rect key={i} x={i * cellW} y="0" width={cellW} height={h} fill={sevColor} opacity={heat[i] || 0} />
        ))}
        {chars.map((c, i) => (
          <text key={i} x={i * cellW + cellW / 2} y={h / 2 + 6} textAnchor="middle" fontFamily={MONO} fontSize="16" fill={T.text}>{c}</text>
        ))}
      </svg>
      <div style={{ fontFamily: MONO, fontSize: 13, color: T.text, marginBottom: 14, fontVariantNumeric: "tabular-nums" }}>
        model score <span style={{ color: sevColor }}>{score}</span>
        <span style={{ color: T.text3 }}> &middot; darker = more improbable against legitimate-domain corpus</span>
      </div>
      <div style={{ ...labelStyle, marginBottom: 4 }}>NXDOMAIN, last hour</div>
      <svg width="100%" viewBox={`0 0 ${width} 40`} style={{ display: "block" }}>
        {nxdomain.map((v, i) => {
          const bw = width / Math.max(nxdomain.length, 1);
          return <rect key={i} x={i * bw + 1} y={40 - (v / maxNx) * 40} width={Math.max(bw - 2, 0.5)} height={(v / maxNx) * 40} fill={T.text2} />;
        })}
      </svg>
    </div>
  );
}
