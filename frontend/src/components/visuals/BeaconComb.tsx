import { useMemo } from "react";
import { T, MONO, SANS, microStyle } from "../../lib/tokens";
import type { ClassVisual } from "../../lib/types";
import { type VisualChrome } from "./chrome";

type Props = Extract<ClassVisual, { kind: "beacon_comb" }> & VisualChrome;

/**
 * The comb.
 *
 * Every connection in this tuple as a vertical tick on a time axis. A beacon
 * renders as an evenly spaced comb; human-driven traffic renders as scattered
 * clusters. No legend is required — the difference is visible instantly, and it
 * is the most convincing single image in the product.
 *
 * TWO THINGS THIS COMPONENT DELIBERATELY DOES NOT DO
 * --------------------------------------------------
 * It no longer draws a "typical host" comparison row. That row was
 * `Math.random()` scatter, regenerated on every mount, sitting directly beneath
 * a real detection and labelled as if it were a measurement of the network.
 * Nothing observed it. On a product whose whole argument is that every mark
 * came from an observation, inventing the contrast that makes the real trace
 * look damning is the worst defect available (DESIGN.md §11).
 *
 * It also does not choose a colour. The severity colour is passed in, because
 * a component that reaches for `--sev-crit` itself asserts a severity the
 * detector did not report, and the ramp stops meaning anything.
 *
 * Tick placement is derived from `periods` and `jitterPct` — the summary
 * statistics the backend sends — and is deterministic in them, so the picture
 * does not reshuffle between renders. When that is all the backend had, it
 * stamps the payload `reconstructed_from_summary_statistics` and the evidence
 * panel shows the provenance badge beside this visual.
 */
export function BeaconComb({ periods = 0, jitterPct = 0, sevColor }: Props) {
  const ticks = useMemo(() => {
    const n = Math.min(Math.max(0, Math.round(periods)), 36);
    if (n === 0) return [];
    const spacing = 100 / (n + 1);
    // A fixed offset sequence rather than a random one: same inputs, same
    // picture, every render. The jitter figure is the detector's, so the
    // visible irregularity is proportional to what was measured.
    return Array.from({ length: n }, (_, i) => {
      const wobble = Math.sin(i * 2.399963) * spacing * (jitterPct / 100);
      return spacing * (i + 1) + wobble;
    });
  }, [periods, jitterPct]);

  if (ticks.length === 0) {
    return (
      <div style={{ fontFamily: SANS, fontSize: 12, color: T.text3 }}>
        No connection series reported for this alert.
      </div>
    );
  }

  return (
    <div>
      <div style={{ fontFamily: SANS, fontSize: 12, lineHeight: 1.5, color: T.text2, marginBottom: 12, maxWidth: 560 }}>
        Evenly spaced connections over the observation window. Human-driven traffic clusters; this does not.
      </div>

      <div style={{ position: "relative", height: 104, borderBottom: `1px solid ${T.ruleBright}`, marginBottom: 4 }}>
        {ticks.map((left, i) => (
          <div
            key={i}
            style={{ position: "absolute", top: 8, bottom: 0, width: 2, background: sevColor, left: `${left.toFixed(3)}%` }}
          />
        ))}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", fontFamily: MONO, fontSize: 11, color: T.text3, marginBottom: 14 }}>
        <span>start of window</span>
        <span>now</span>
      </div>

      <div style={{ display: "flex", gap: 28, flexWrap: "wrap" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
          <span style={microStyle}>Measured jitter</span>
          <span style={{ fontFamily: MONO, fontSize: 15, color: sevColor }}>{jitterPct.toFixed(1)}%</span>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
          <span style={microStyle}>Connections</span>
          <span style={{ fontFamily: MONO, fontSize: 15, color: T.text }}>{periods}</span>
        </div>
      </div>
    </div>
  );
}
