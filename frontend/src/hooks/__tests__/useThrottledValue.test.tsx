/**
 * Regression test for spec 8.2's counter rule.
 *
 * "Throttle the visible counter to 4Hz ... The underlying count stays exact."
 * Both halves are load-bearing, and only one of them is about performance: a
 * throttle that also rounded, debounced or dropped the final value would make
 * the readout wrong, which is worse than making it jittery.
 */
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useThrottledValue } from "../useThrottledValue";

function Counter({ value }: { value: number }) {
  const shown = useThrottledValue(value);
  return <span data-testid="shown">{shown}</span>;
}

const shown = () => Number(screen.getByTestId("shown").textContent);

beforeEach(() => vi.useFakeTimers());
// Explicit rather than automatic: the runner is configured with `globals:
// false`, so testing-library never registers its own afterEach hook.
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("useThrottledValue", () => {
  it("holds the display steady while the source changes every frame", () => {
    const { rerender } = render(<Counter value={0} />);

    // 60 flushes, as a flood produces. Without the throttle this is 60 repaints
    // of the readout; with it, none until the next 250ms tick.
    for (let i = 1; i <= 60; i++) rerender(<Counter value={i} />);
    expect(shown()).toBe(0);

    act(() => { vi.advanceTimersByTime(250); });
    expect(shown()).toBe(60);
  });

  it("samples at 4Hz, not faster", () => {
    const { rerender } = render(<Counter value={0} />);

    rerender(<Counter value={10} />);
    act(() => { vi.advanceTimersByTime(240); });
    expect(shown()).toBe(0); // still inside the tick

    act(() => { vi.advanceTimersByTime(10); });
    expect(shown()).toBe(10);
  });

  it("settles on the true final value when the flood stops mid-tick", () => {
    // The failure this guards against: a throttle that only samples on change
    // can freeze one tick short and leave a permanently wrong number on a wall
    // display that nobody is scrolling.
    const { rerender } = render(<Counter value={0} />);
    rerender(<Counter value={497} />);
    act(() => { vi.advanceTimersByTime(250); });
    rerender(<Counter value={500} />);
    act(() => { vi.advanceTimersByTime(250); });
    expect(shown()).toBe(500);
  });

  it("passes the exact value through, never a rounded one", () => {
    const { rerender } = render(<Counter value={0} />);
    rerender(<Counter value={49_999} />);
    act(() => { vi.advanceTimersByTime(250); });
    expect(shown()).toBe(49_999);
  });
});
