import { useMemo } from "react";
import { T, SANS } from "../../lib/tokens";

const rand = (a: number, b: number) => a + Math.random() * (b - a);

export function FanoutMatrix({ sweep, refusedRatio }: { sweep: "vertical" | "horizontal"; refusedRatio: number }) {
  const cols = 20, rows = 12, cellW = 22, cellH = 16, gap = 2;
  const width = cols * (cellW + gap), height = rows * (cellH + gap);

  const cells = useMemo(() => {
    const out: { r: number; c: number; refused: boolean }[] = [];
    const target = sweep === "vertical" ? Math.floor(rand(4, cols - 4)) : Math.floor(rand(2, rows - 2));
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const near = sweep === "vertical" ? Math.abs(c - target) <= 1 : Math.abs(r - target) <= 1;
        if (near || Math.random() < 0.03) out.push({ r, c, refused: Math.random() < refusedRatio });
      }
    }
    return out;
  }, [sweep, refusedRatio]);

  return (
    <div>
      <svg width="100%" viewBox={`0 0 ${width} ${height}`} style={{ display: "block" }}>
        {cells.map((cell, i) => (
          <rect key={i} x={cell.c * (cellW + gap)} y={cell.r * (cellH + gap)} width={cellW} height={cellH} fill={cell.refused ? T.sevHigh : T.text2} />
        ))}
      </svg>
      <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "monospace", fontSize: 10, color: T.text3, marginTop: 4 }}>
        <span>dest. port &rarr;</span><span>{sweep} sweep</span>
      </div>
      <div style={{ display: "flex", gap: 14, marginTop: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <span style={{ width: 10, height: 10, background: T.text2, display: "inline-block" }} />
          <span style={{ fontFamily: SANS, fontSize: 11, color: T.text2 }}>contact made</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <span style={{ width: 10, height: 10, background: T.sevHigh, display: "inline-block" }} />
          <span style={{ fontFamily: SANS, fontSize: 11, color: T.text2 }}>refused / reset</span>
        </div>
      </div>
    </div>
  );
}