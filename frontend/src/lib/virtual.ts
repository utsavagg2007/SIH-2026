/**
 * Windowing arithmetic for the alert stream (spec 8.2: "Virtualize the alert
 * list. Render only visible rows.").
 *
 * Pulled out of the component because it is the part that can be wrong in a way
 * nobody notices until the DDoS demo: an off-by-one in the overscan shows up as
 * a flicker of blank rows during a fast scroll, and a spacer computed from the
 * wrong bound silently breaks the scrollbar. It is pure arithmetic over four
 * numbers, so it can be tested directly.
 *
 * Row height is a constant rather than a measurement because the spec fixes it
 * (2.4: 40px in the alert stream). Fixed pitch is what makes the first visible
 * index a division instead of a search, and is why this needs no dependency.
 */

export interface WindowRange {
  /** Index of the first row to mount. */
  first: number;
  /** Index one past the last row to mount. */
  last: number;
  /** Height of the spacer standing in for the rows above `first`. */
  padTop: number;
  /** Height of the spacer standing in for the rows below `last`. */
  padBottom: number;
}

export function windowRange(
  scrollTop: number,
  viewportH: number,
  total: number,
  rowH: number,
  overscan: number
): WindowRange {
  if (total <= 0 || rowH <= 0) {
    return { first: 0, last: 0, padTop: 0, padBottom: 0 };
  }

  // A negative scrollTop is reachable through rubber-band overscroll on macOS,
  // and would otherwise index backwards through the buffer.
  const top = Math.max(0, scrollTop);
  const first = Math.max(0, Math.floor(top / rowH) - overscan);

  // Before the first layout pass viewportH is 0. Falling through to a window of
  // just the overscan would mount two rows and leave the panel looking empty on
  // first paint, so an unmeasured viewport renders a screenful and is corrected
  // on the next frame.
  const rows = viewportH > 0 ? Math.ceil(viewportH / rowH) + overscan * 2 : overscan * 2;
  const last = Math.min(total, first + rows);

  return {
    first,
    last,
    padTop: first * rowH,
    padBottom: Math.max(0, (total - last) * rowH),
  };
}

/**
 * Minimum scroll offset that brings `index` fully into view, or null when it is
 * already visible.
 *
 * Returning null rather than the current offset matters: keyboard navigation
 * (spec 8.3) walks the list with j/k, and a virtualized list can move the
 * selection to a row that is not mounted. Scrolling the minimum distance keeps
 * that walk a row at a time instead of recentring the list on every keystroke,
 * which is disorienting on a wall display.
 */
export function scrollToIndex(
  index: number,
  scrollTop: number,
  viewportH: number,
  rowH: number
): number | null {
  if (index < 0 || viewportH <= 0) return null;
  const top = index * rowH;
  if (top < scrollTop) return top;
  if (top + rowH > scrollTop + viewportH) return top + rowH - viewportH;
  return null;
}
