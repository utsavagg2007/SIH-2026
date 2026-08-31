import { useEffect, useRef, useState } from "react";

/**
 * Sample a fast-changing value at a fixed display rate.
 *
 * Spec 8.2: "Throttle the visible counter to 4Hz. A number changing at 60Hz is
 * unreadable and looks like noise. The underlying count stays exact."
 *
 * The distinction is the whole point, so it is worth being precise about what
 * this does and does not do. The caller keeps passing the exact value on every
 * render; nothing here rounds, debounces, or drops an update from the source of
 * truth. Only the copy React re-renders on is held back. Filters, keyboard
 * navigation and the evidence panel all continue to read the exact array.
 *
 * The last value is always delivered: the interval keeps running until what is
 * displayed matches what was passed, so a flood that stops mid-tick still
 * settles on the true final number rather than freezing one tick short of it.
 */
export function useThrottledValue<T>(value: T, hz = 4): T {
  const [shown, setShown] = useState(value);
  const latest = useRef(value);
  latest.current = value;

  useEffect(() => {
    const id = window.setInterval(() => {
      setShown((prev) => (Object.is(prev, latest.current) ? prev : latest.current));
    }, 1000 / hz);
    return () => window.clearInterval(id);
  }, [hz]);

  return shown;
}
