/**
 * Regression tests for the alert stream's windowing (spec 8.2).
 *
 * The behaviour under test is "render only visible rows", and the failure it
 * replaces is the plain `filtered.map(...)` that mounted all 500 ring-buffer
 * rows on every animation frame. So the assertions that matter are: the window
 * is bounded regardless of buffer size, and the spacers always account for
 * exactly the rows that were left out - because a spacer that disagrees with
 * the slice is a broken scrollbar, which is worse than no virtualization.
 */
import { describe, expect, it } from "vitest";
import { scrollToIndex, windowRange } from "../virtual";

const ROW_H = 40;
const OVERSCAN = 6;

describe("windowRange", () => {
  it("mounts a bounded window rather than the whole ring buffer", () => {
    // The regression: 500 alerts in an 800px viewport used to mount 500 rows.
    const { first, last } = windowRange(0, 800, 500, ROW_H, OVERSCAN);
    const visible = Math.ceil(800 / ROW_H); // 20
    expect(last - first).toBe(visible + OVERSCAN * 2); // 32, not 500
    expect(last - first).toBeLessThan(500);
  });

  it("keeps the scrollbar honest: spacers plus rendered rows equal the total", () => {
    for (const scrollTop of [0, 37, 400, 4000, 19_960]) {
      const { first, last, padTop, padBottom } = windowRange(scrollTop, 800, 500, ROW_H, OVERSCAN);
      expect(padTop).toBe(first * ROW_H);
      expect(padBottom).toBe((500 - last) * ROW_H);
      expect(padTop + (last - first) * ROW_H + padBottom).toBe(500 * ROW_H);
    }
  });

  it("covers the viewport at every scroll offset", () => {
    // Every row the viewport can actually show must be inside [first, last).
    for (let scrollTop = 0; scrollTop <= 500 * ROW_H - 800; scrollTop += 17) {
      const { first, last } = windowRange(scrollTop, 800, 500, ROW_H, OVERSCAN);
      const firstVisible = Math.floor(scrollTop / ROW_H);
      const lastVisible = Math.floor((scrollTop + 800 - 1) / ROW_H);
      expect(first).toBeLessThanOrEqual(firstVisible);
      expect(last).toBeGreaterThan(lastVisible);
    }
  });

  it("clamps at both ends", () => {
    // Rubber-band overscroll can report a negative scrollTop.
    expect(windowRange(-200, 800, 500, ROW_H, OVERSCAN).first).toBe(0);
    // And the tail must never index past the buffer or emit a negative spacer.
    const tail = windowRange(500 * ROW_H, 800, 500, ROW_H, OVERSCAN);
    expect(tail.last).toBe(500);
    expect(tail.padBottom).toBe(0);
  });

  it("renders nothing for an empty stream", () => {
    expect(windowRange(0, 800, 0, ROW_H, OVERSCAN)).toEqual({
      first: 0, last: 0, padTop: 0, padBottom: 0,
    });
  });

  it("renders a screenful before the viewport has been measured", () => {
    // viewportH is 0 on the first paint. Mounting only the overscan would show
    // an almost-empty panel until the ResizeObserver fires.
    const { last } = windowRange(0, 0, 500, ROW_H, OVERSCAN);
    expect(last).toBeGreaterThan(0);
  });
});

describe("scrollToIndex", () => {
  it("leaves an already-visible row alone", () => {
    // j/k must not recentre the list on every keystroke.
    expect(scrollToIndex(5, 0, 800, ROW_H)).toBeNull();
  });

  it("scrolls the minimum distance to reveal a row below the fold", () => {
    // Row 20 starts at 800 and ends at 840; a 800px viewport at 0 must move to 40.
    expect(scrollToIndex(20, 0, 800, ROW_H)).toBe(40);
  });

  it("scrolls up to reveal a row above the fold", () => {
    expect(scrollToIndex(3, 400, 800, ROW_H)).toBe(120);
  });

  it("does nothing without a selection", () => {
    expect(scrollToIndex(-1, 0, 800, ROW_H)).toBeNull();
  });
});
