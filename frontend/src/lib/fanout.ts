/**
 * The fan-out matrix's ordinal port axis (spec 5.2).
 *
 * Separated from the drawing code because the axis choice is the whole point of
 * the visual and is worth asserting on directly.
 *
 * Port numbers are identifiers, not quantities. On a linear 0-65535 axis a scan
 * of ports 1-1024 occupies 1.5% of the width and renders as a smudge against
 * the left edge - which defeats the one panel whose job is to make the sweep's
 * shape obvious. Ranking the distinct observed ports and spacing them evenly
 * preserves ordering, discards the meaningless distance between port numbers,
 * and lets a 1024-port sweep and a three-port probe produce visibly different
 * pictures. The tick labels carry the real port numbers, so nothing about the
 * observation is hidden by the transform.
 */

export interface FanoutCell {
  /** Column: the port's rank among the distinct ports contacted. */
  col: number;
  /** Row: which time bucket the contact fell in. */
  row: number;
  refused: boolean;
}

export interface FanoutModel {
  /** Distinct contacted ports, ascending. Index is the column. */
  distinct: number[];
  cells: FanoutCell[];
}

export function fanoutModel(
  ports: number[],
  offsets: number[],
  rejected: boolean[],
  durationSec: number,
  rows: number
): FanoutModel {
  const distinct = [...new Set(ports)].sort((a, b) => a - b);
  if (distinct.length === 0 || rows <= 0) return { distinct, cells: [] };

  const rank = new Map(distinct.map((p, i) => [p, i]));
  const span = Math.max(durationSec, ...offsets, 1e-6);

  const seen = new Set<string>();
  const cells: FanoutCell[] = [];

  for (let i = 0; i < ports.length; i++) {
    const col = rank.get(ports[i]);
    if (col === undefined) continue;
    const row = Math.min(rows - 1, Math.max(0, Math.floor(((offsets[i] ?? 0) / span) * rows)));
    // Two contacts to the same port inside one time bucket are one cell.
    // Without this a repeated probe stacks invisible duplicate rects.
    const key = `${col}:${row}`;
    if (seen.has(key)) continue;
    seen.add(key);
    cells.push({ col, row, refused: Boolean(rejected[i]) });
  }

  return { distinct, cells };
}

/**
 * Indices to label on the ordinal axis: evenly spaced, always including the
 * last, so the reader can read real port numbers off the ranks.
 */
export function tickIndices(count: number, maxTicks = 6): number[] {
  if (count <= 0) return [];
  const step = Math.max(1, Math.ceil(count / maxTicks));
  const idx = new Set<number>();
  for (let i = 0; i < count; i += step) idx.add(i);
  idx.add(count - 1);
  return [...idx].sort((a, b) => a - b);
}
