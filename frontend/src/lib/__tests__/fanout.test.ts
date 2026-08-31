/**
 * Regression test for the fan-out matrix's port axis (spec 5.2).
 *
 * The bug: destination ports were treated as positions on a linear 0-65535
 * axis, so a scan of ports 1-1024 - the exact thing the panel exists to show -
 * occupied the leftmost 1.5% of the chart and read as a single smudge. The test
 * pins the property that fixes it: column position is the port's *rank* among
 * the distinct ports observed, so the drawn width of a sweep depends on how
 * many ports were touched and not on how large their numbers happen to be.
 */
import { describe, expect, it } from "vitest";
import { fanoutModel, tickIndices } from "../fanout";

/** Port `n` contacted at second `n`, as a 1024-port sweep would arrive. */
function sweep(from: number, to: number) {
  const ports: number[] = [];
  const offsets: number[] = [];
  for (let p = from; p <= to; p++) {
    ports.push(p);
    offsets.push(p - from);
  }
  return { ports, offsets, rejected: ports.map(() => false), duration: to - from };
}

describe("fanoutModel", () => {
  it("spreads a low-numbered sweep across the full axis instead of the left edge", () => {
    const s = sweep(1, 1024);
    const { distinct, cells } = fanoutModel(s.ports, s.offsets, s.rejected, s.duration, 14);

    expect(distinct).toHaveLength(1024);
    // The regression: on a linear 0-65535 axis every one of these ports landed
    // in the first 1.6% of the width. On the rank axis the columns span the
    // whole range, with port 1024 at the last column.
    expect(Math.max(...cells.map((c) => c.col))).toBe(1023);
    const fractionOfWidth = Math.max(...cells.map((c) => c.col)) / (distinct.length - 1);
    expect(fractionOfWidth).toBe(1);
  });

  it("gives a three-port probe three columns, not three adjacent pixels", () => {
    const ports = [22, 80, 443];
    const { distinct, cells } = fanoutModel(ports, [0, 1, 2], [false, false, false], 2, 14);
    expect(distinct).toEqual([22, 80, 443]);
    // Linearly, 22 and 80 are indistinguishable at chart resolution. By rank
    // they are adjacent columns, which is the whole point.
    expect(cells.map((c) => c.col).sort((a, b) => a - b)).toEqual([0, 1, 2]);
  });

  it("orders columns by port number", () => {
    const { distinct } = fanoutModel([443, 22, 8080, 80], [0, 1, 2, 3], [], 3, 14);
    expect(distinct).toEqual([22, 80, 443, 8080]);
  });

  it("buckets contacts down the time axis", () => {
    // One port, contacted at the start and at the end of a 100s window.
    const { cells } = fanoutModel([22, 22], [0, 100], [false, false], 100, 10);
    expect(cells.map((c) => c.row)).toEqual([0, 9]);
  });

  it("collapses repeat contacts within one bucket to a single cell", () => {
    const ports = [22, 22, 22, 22];
    const { cells } = fanoutModel(ports, [0, 0.1, 0.2, 0.3], [], 100, 10);
    expect(cells).toHaveLength(1);
  });

  it("marks refused contacts, since a wall of them is what makes a scan a scan", () => {
    const { cells } = fanoutModel([22, 80], [0, 50], [true, false], 100, 10);
    expect(cells.find((c) => c.col === 0)?.refused).toBe(true);
    expect(cells.find((c) => c.col === 1)?.refused).toBe(false);
  });

  it("reports nothing to draw when no ports were observed", () => {
    expect(fanoutModel([], [], [], 0, 14)).toEqual({ distinct: [], cells: [] });
  });
});

describe("tickIndices", () => {
  it("always labels the last observed port", () => {
    for (const n of [1, 3, 7, 64, 1024]) {
      const ticks = tickIndices(n);
      expect(ticks[ticks.length - 1]).toBe(n - 1);
      expect(ticks.length).toBeLessThanOrEqual(8);
    }
  });

  it("returns nothing for an empty axis", () => {
    expect(tickIndices(0)).toEqual([]);
  });
});
