import { T, MONO, labelStyle } from "../../lib/tokens";

interface Props { bins: number[]; tailIndex: number; history: string[]; }

export function Ja3Rarity({ bins, tailIndex, history }: Props) {
  const width = 460, height = 90;
  const maxLog = Math.log10(Math.max(...bins) + 1);
  const bw = width / bins.length;

  return (
    <div>
      <div style={{ ...labelStyle, marginBottom: 6 }}>baseline JA3 frequency (log)</div>
      <svg width="100%" viewBox={`0 0 ${width} ${height + 14}`} style={{ display: "block" }}>
        {bins.map((v, i) => {
          const h = (Math.log10(v + 1) / maxLog) * height;
          const isThis = i === tailIndex;
          return <rect key={i} x={i * bw + 2} y={height - h} width={bw - 4} height={h} fill={isThis ? T.sevCrit : T.text2} />;
        })}
        <text x={tailIndex * bw + bw / 2} y={height + 12} textAnchor="middle" fontFamily={MONO} fontSize="10" fill={T.sevCrit}>this connection</text>
      </svg>
      <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "sans-serif", fontSize: 11, color: T.text3, marginTop: 2 }}>
        <span>common</span><span>rare</span>
      </div>
      <div style={{ ...labelStyle, margin: "14px 0 6px" }}>fingerprint history, this host</div>
      {history.map((h, i) => (
        <div key={i} style={{ fontFamily: MONO, fontSize: 12, color: i === history.length - 1 ? T.sevCrit : T.text2, padding: "3px 0" }}>{h}</div>
      ))}
    </div>
  );
}