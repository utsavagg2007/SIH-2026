import { T, MONO, labelStyle } from "../../lib/tokens";

interface Props { parent: string; count: number; subs: string[]; lengths: number[]; }

export function SubdomainFanout({ parent, count, subs, lengths }: Props) {
  const maxLen = Math.max(...lengths, 63);
  const bins = 12;
  const hist = new Array(bins).fill(0);
  lengths.forEach((l) => hist[Math.min(bins - 1, Math.floor((l / maxLen) * bins))]++);
  const maxCount = Math.max(1, ...hist);

  return (
    <div>
      <div style={{ ...labelStyle, marginBottom: 4 }}>parent domain</div>
      <div style={{ fontFamily: MONO, fontSize: 16, color: T.text, marginBottom: 10 }}>{parent}</div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 10 }}>
        <span style={{ fontFamily: MONO, fontSize: 28, color: T.sevHigh, fontVariantNumeric: "tabular-nums" }}>{count}</span>
        <span style={labelStyle}>distinct subdomains, last hour</span>
      </div>
      <div style={{ ...labelStyle, marginBottom: 4 }}>recent queries</div>
      <div style={{ maxHeight: 96, overflowY: "auto", border: `1px solid ${T.rule}`, marginBottom: 12 }}>
        {subs.map((s, i) => (
          <div key={i} style={{ fontFamily: MONO, fontSize: 12, color: T.text2, padding: "4px 8px", borderBottom: i < subs.length - 1 ? `1px solid ${T.rule}` : "none" }}>
            {s}.{parent}
          </div>
        ))}
      </div>
      <div style={{ ...labelStyle, marginBottom: 4 }}>query length distribution</div>
      <svg width="100%" viewBox="0 0 460 36" style={{ display: "block" }}>
        {hist.map((c, i) => {
          const bw = 460 / bins;
          return <rect key={i} x={i * bw + 1} y={36 - (c / maxCount) * 36} width={bw - 2} height={(c / maxCount) * 36} fill={T.text2} />;
        })}
      </svg>
    </div>
  );
}