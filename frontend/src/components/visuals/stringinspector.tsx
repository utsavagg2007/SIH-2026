import { T, MONO, labelStyle } from "../../lib/tokens";

interface Props { domain: string; heat: number[]; nxdomain: number[]; score: number; }

export function StringInspector({ domain, heat, nxdomain, score }: Props) {
  const width = 460, h = 26;
  const chars = domain.split("");
  const cellW = width / chars.length;
  const maxNx = Math.max(1, ...nxdomain);

  return (
    <div>
      <div style={{ ...labelStyle, marginBottom: 6 }}>queried domain</div>
      <svg width="100%" viewBox={`0 0 ${width} ${h}`} style={{ display: "block", marginBottom: 8 }}>
        {chars.map((_, i) => (
          <rect key={i} x={i * cellW} y="0" width={cellW} height={h} fill={T.sevCrit} opacity={heat[i] || 0} />
        ))}
        {chars.map((c, i) => (
          <text key={i} x={i * cellW + cellW / 2} y={h / 2 + 6} textAnchor="middle" fontFamily={MONO} fontSize="16" fill={T.text}>{c}</text>
        ))}
      </svg>
      <div style={{ fontFamily: MONO, fontSize: 13, color: T.text, marginBottom: 14 }}>
        model score <span style={{ color: T.sevCrit }}>{score}</span>
        <span style={{ color: T.text3 }}> &middot; darker = more improbable against legitimate-domain corpus</span>
      </div>
      <div style={{ ...labelStyle, marginBottom: 4 }}>NXDOMAIN, last hour</div>
      <svg width="100%" viewBox={`0 0 ${width} 40`} style={{ display: "block" }}>
        {nxdomain.map((v, i) => {
          const bw = width / nxdomain.length;
          return <rect key={i} x={i * bw + 1} y={40 - (v / maxNx) * 40} width={bw - 2} height={(v / maxNx) * 40} fill={T.sevMed} />;
        })}
      </svg>
    </div>
  );
}