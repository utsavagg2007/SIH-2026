/**
 * PS - the fan-out matrix (spec 5.2).
 *
 * Destination port across, time down, a cell where the source made contact.
 * A vertical scan fills a dense vertical band; a horizontal sweep fills across.
 *
 * THE AXIS IS ORDINAL, NOT LINEAR
 *
 * Port numbers are identifiers, not quantities. Plotting them linearly puts the
 * axis on a 0-65535 range, and the scan this panel exists to show - ports 1
 * through 1024, or a handful of service ports - collapses into a sliver at the
 * left edge with 98% of the chart empty. The pattern becomes invisible in the
 * one visual whose entire job is to make it obvious.
 *
 * So the horizontal axis is the rank of each observed port among the distinct
 * ports contacted: the ports actually seen, sorted ascending, evenly spaced.
 * Every column is a port that was really touched, spacing carries ordering
 * without implying distance, and the tick labels name the real port numbers so
 * nothing is hidden by the transform. This is the standard treatment for a
 * categorical axis with a natural order, and it is why "1-1024 swept" and
 * "22, 80, 443 probed" produce visibly different pictures instead of two
 * identical smudges.
 */
import { useMemo } from "react";
import { T, MONO, SANS } from "../../lib/tokens";
import type { ClassVisual } from "../../lib/types";
import { fanoutModel, tickIndices } from "../../lib/fanout";
import { type VisualChrome } from "./chrome";

type Fanout = Extract<ClassVisual, { kind: "fanout_matrix" }>;

/** Time buckets down the vertical axis. */
const ROWS = 14;

export function FanoutMatrix({ sevColor, ...v }: Fanout & VisualChrome) {
  const ports = v.cell_ports ?? [];
  const offsets = v.cell_offsets ?? [];
  const rejected = v.cell_rejected ?? [];

  const model = useMemo(
    () => fanoutModel(ports, offsets, rejected, v.duration_sec ?? 0, ROWS),
    [ports, offsets, rejected, v.duration_sec]
  );

  const { distinct, cells } = model;

  if (distinct.length === 0) {
    return (
      <div style={{ fontFamily: SANS, fontSize: 12, color: T.text3 }}>
        No contacted ports reported. Evidence bars carry this detection.
      </div>
    );
  }

  // Fixed drawing area, scaled to the panel by the viewBox. Column width falls
  // out of the port count, so 8 ports draw wide cells and 120 draw a dense band
  // - which is itself the difference between a probe and a sweep.
  const width = 460;
  const height = 190;
  const gutter = 1;
  const colW = width / distinct.length;
  const rowH = height / ROWS;

  // At most a handful of ticks, always including the first and last observed
  // port, so the reader can see the real numbers behind the ordinal positions.
  const tickIdx = tickIndices(distinct.length);

  const refusedCount = cells.filter((c) => c.refused).length;

  return (
    <div>
      <svg width="100%" viewBox={`0 0 ${width} ${height}`} style={{ display: "block" }} role="img"
        aria-label={`Fan-out matrix: ${distinct.length} distinct destination ports contacted over ${ROWS} time buckets`}>
        <rect x="0" y="0" width={width} height={height} fill="none" stroke={T.rule} strokeWidth="1" />
        {cells.map((c, i) => (
          <rect
            key={i}
            x={c.col * colW}
            y={c.row * rowH}
            width={Math.max(colW - gutter, 0.75)}
            height={Math.max(rowH - gutter, 1)}
            fill={c.refused ? sevColor : T.text2}
          />
        ))}
      </svg>

      {/* Ordinal tick marks. Positioned at column centres, labelled with the
          actual port so the axis is readable as ports, not as ranks. */}
      <svg width="100%" viewBox={`0 0 ${width} 16`} style={{ display: "block" }} aria-hidden="true">
        {tickIdx.map((i) => (
          <g key={i}>
            <line x1={i * colW + colW / 2} y1="0" x2={i * colW + colW / 2} y2="3" stroke={T.ruleBright} strokeWidth="1" />
            <text
              x={Math.min(width - 12, Math.max(12, i * colW + colW / 2))}
              y="13"
              textAnchor="middle"
              fontFamily={MONO}
              fontSize="10"
              fill={T.text3}
            >
              {distinct[i]}
            </text>
          </g>
        ))}
      </svg>

      <div style={{ display: "flex", justifyContent: "space-between", fontFamily: SANS, fontSize: 10, color: T.text3, marginTop: 4 }}>
        <span>destination port, by rank among those contacted &rarr;</span>
        <span>time &darr; {(v.duration_sec ?? 0).toFixed(0)}s</span>
      </div>

      <div style={{ display: "flex", gap: 16, marginTop: 10, flexWrap: "wrap", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <span style={{ width: 10, height: 10, background: T.text2, display: "inline-block" }} />
          <span style={{ fontFamily: SANS, fontSize: 11, color: T.text2 }}>contact made</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <span style={{ width: 10, height: 10, background: sevColor, display: "inline-block" }} />
          <span style={{ fontFamily: SANS, fontSize: 11, color: T.text2 }}>refused / reset ({refusedCount})</span>
        </div>
      </div>

      <div style={{ marginTop: 8, fontFamily: MONO, fontSize: 11, color: T.text2, fontVariantNumeric: "tabular-nums" }}>
        {v.unique_dst_ports ?? distinct.length} unique ports
        {v.unique_dst_ips != null && <> &middot; {v.unique_dst_ips} hosts</>}
        {v.pattern && v.pattern !== "unknown" && <> &middot; {v.pattern.replace(/_/g, " ")}</>}
        {/* The grid is sampled; the true count travels as a scalar beside it. */}
        {v.cells_total != null && v.cells_sampled != null && v.cells_total > v.cells_sampled && (
          <> &middot; {v.cells_sampled} of {v.cells_total} contacts drawn</>
        )}
      </div>
    </div>
  );
}
