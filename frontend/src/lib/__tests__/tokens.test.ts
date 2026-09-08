import { describe, it, expect, beforeAll } from "vitest";
import { T, SEV, paint } from "../tokens";

/**
 * `paint()` exists because a canvas 2D context silently ignores a colour it
 * cannot parse. Assigning `"var(--rule)"` to `strokeStyle` is a no-op, so the
 * Wire drew its axis, ticks, labels and marks in the context's initial black
 * on a near-black ground and looked like an empty strip. These tests assert the
 * property that failure violated: whatever `paint()` returns must be something
 * a canvas will actually accept.
 */
describe("paint", () => {
  beforeAll(() => {
    // jsdom resolves custom properties only when something declares them.
    const style = document.createElement("style");
    style.textContent = ":root { --rule: #252c31; --text-3: #7d878e; }";
    document.head.appendChild(style);
  });

  it("resolves a token to a literal colour, never a var() string", () => {
    expect(paint(T.rule)).toBe("#252c31");
    expect(paint(T.text3)).toBe("#7d878e");
    expect(paint(T.rule)).not.toContain("var(");
  });

  it("returns the same value on a second call, from cache", () => {
    expect(paint(T.rule)).toBe(paint(T.rule));
  });

  it("passes a literal colour through untouched", () => {
    // Wire marks carry a colour from the alert itself; it must not be mangled.
    expect(paint("#e04b3f")).toBe("#e04b3f");
    expect(paint("rgba(224, 75, 63, 0.12)")).toBe("rgba(224, 75, 63, 0.12)");
  });

  it("falls back to the token rather than to an empty string", () => {
    // An undeclared property resolves to "" - returning that would set the
    // canvas colour to nothing, which is the bug this function fixes.
    expect(paint("var(--not-declared-anywhere)")).toBe("var(--not-declared-anywhere)");
  });

  it("every severity colour survives the round trip", () => {
    for (const key of ["low", "medium", "high", "critical"] as const) {
      expect(paint(SEV[key].color)).not.toBe("");
    }
  });
});
