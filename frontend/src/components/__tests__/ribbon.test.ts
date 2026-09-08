/**
 * The kill-chain ribbon's node layout.
 *
 * The ribbon's whole argument is that the sequence is evidence, which is why
 * nodes sit at their real position in elapsed time rather than at equal
 * spacing. That axis is also what makes label collisions possible: six alerts
 * inside ten seconds land on the same pixel and print on top of each other,
 * which is what the previous render did.
 *
 * `layoutNodes` resolves it by moving each label the minimum distance needed.
 * The properties worth pinning are the two that keep it honest: order is never
 * reversed, and nothing is pushed outside the track. The dot itself is drawn at
 * true time by the caller, so a shifted label never changes what the axis says.
 */
import { describe, expect, it } from "vitest";
import { layoutNodes } from "../IncidentsView";

const W = 1000;
const NODE = 104;

describe("layoutNodes", () => {
  it("places well-separated nodes at their true time position", () => {
    const xs = layoutNodes([0, 500, 1000], W, NODE);
    const usable = W - NODE;
    expect(xs[0]).toBeCloseTo(0, 5);
    expect(xs[1]).toBeCloseTo(usable / 2, 5);
    expect(xs[2]).toBeCloseTo(usable, 5);
  });

  it("separates labels that would otherwise overlap", () => {
    // Three alerts inside two seconds of a two-hour incident: true positions
    // are within a pixel of each other.
    const xs = layoutNodes([0, 1, 2, 7200], W, NODE);
    for (let i = 1; i < xs.length; i++) {
      expect(xs[i] - xs[i - 1]).toBeGreaterThanOrEqual(NODE - 1e-6);
    }
  });

  it("never reorders nodes and never leaves the track", () => {
    const times = [0, 0.2, 0.4, 0.6, 0.8, 1, 1.2, 600];
    const xs = layoutNodes(times, W, NODE);
    expect(xs).toHaveLength(times.length);
    for (let i = 1; i < xs.length; i++) expect(xs[i]).toBeGreaterThan(xs[i - 1]);
    expect(Math.min(...xs)).toBeGreaterThanOrEqual(0);
    // The last node's own width still has to fit inside the container.
    expect(Math.max(...xs) + NODE).toBeLessThanOrEqual(W + 1e-6);
  });

  it("centres a lone node and spaces a simultaneous burst evenly", () => {
    expect(layoutNodes([42], W, NODE)).toEqual([(W - NODE) / 2]);
    // Every member in the same instant: there is no time axis to honour, so
    // even spacing is the only reading available.
    const burst = layoutNodes([5, 5, 5], W, NODE);
    expect(burst[1] - burst[0]).toBeCloseTo(burst[2] - burst[1], 5);
  });

  it("returns nothing for an incident with no members", () => {
    expect(layoutNodes([], W, NODE)).toEqual([]);
  });
});
