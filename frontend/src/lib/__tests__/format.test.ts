import { describe, it, expect } from "vitest";
import { fmt, fmtEndpoints } from "../format";

/**
 * The cases that were actually on screen.
 *
 * The evidence panel rendered `String(value)`, so the two floats below reached
 * the display at full double precision. They are kept here verbatim rather than
 * as round numbers, because a formatter that only ever sees `0.5` and `1.25`
 * proves nothing about the failure it exists to prevent.
 */
describe("fmt.metric", () => {
  it("cuts a full-precision float to a fixed width", () => {
    expect(fmt.metric(0.9996614928833266)).toBe("0.9997");
    expect(fmt.metric(63.43478298187256)).toBe("63.43");
  });

  it("groups large integers instead of running the digits together", () => {
    expect(fmt.metric(54506246)).toBe("54,506,246");
    expect(fmt.metric(52428800)).toBe("52,428,800");
  });

  it("keeps small magnitudes legible rather than rounding them to zero", () => {
    expect(fmt.metric(0.0004321)).toBe("4.32e-4");
    expect(fmt.metric(0.0125)).toBe("0.0125");
    expect(fmt.metric(0)).toBe("0");
  });

  it("never widens a column: no output exceeds the integer's own width + separators", () => {
    for (const n of [0.1234567, 1.23456789, 999.987654321, 12345.6789]) {
      expect(fmt.metric(n).length).toBeLessThanOrEqual(10);
    }
  });

  it("passes non-numeric evidence through untouched", () => {
    // A JA3 hash that got rounded would be worse than one that is long.
    expect(fmt.metric("771,4865-4867,0-23-65281")).toBe("771,4865-4867,0-23-65281");
    expect(fmt.metric(true)).toBe("true");
    expect(fmt.metric(null)).toBe("—");
    expect(fmt.metric(undefined)).toBe("—");
  });

  it("reports a non-finite value as absent rather than as NaN", () => {
    expect(fmt.metric(NaN)).toBe("—");
    expect(fmt.metric(Infinity)).toBe("—");
  });
});

/**
 * The cases that were actually on screen, again.
 *
 * A port scan has one source and hundreds of destinations, so the backend sends
 * no single `dst_ip`; a flood has one target and a distributed source. The rows
 * interpolated both fields unconditionally and printed the punctuation around
 * the hole - `10.4.2.19 → :` and `→ 10.4.1.10:80` - on four different screens.
 */
describe("fmtEndpoints", () => {
  it("renders both ends when both were reported", () => {
    expect(fmtEndpoints({ src_ip: "10.4.2.19", dst_ip: "185.62.11.4", dst_port: 443 })).toBe(
      "10.4.2.19 → 185.62.11.4:443"
    );
  });

  it("labels a missing destination rather than printing bare punctuation", () => {
    // The port-scan case: no single destination, and no ":" dangling either.
    expect(fmtEndpoints({ src_ip: "10.4.2.19", dst_ip: "", dst_port: 0 })).toBe("10.4.2.19 → —");
  });

  it("labels a missing source", () => {
    // The flood case.
    expect(fmtEndpoints({ src_ip: "", dst_ip: "10.4.1.10", dst_port: 80 })).toBe("— → 10.4.1.10:80");
  });

  it("omits a port the detector did not report", () => {
    expect(fmtEndpoints({ src_ip: "10.4.2.77", dst_ip: "10.4.1.5", dst_port: 0 })).toBe(
      "10.4.2.77 → 10.4.1.5"
    );
  });

  it("collapses to a single dash when neither end was reported", () => {
    expect(fmtEndpoints({})).toBe("—");
  });
});
