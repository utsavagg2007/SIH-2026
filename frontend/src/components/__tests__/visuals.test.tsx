/**
 * Regression test for the design spec's single most important rule (2.1):
 * colour is reserved entirely for severity and threat class.
 *
 * The bug: every class-specific visual hardcoded its own hue - the DGA string
 * inspector painted its n-gram heat in `--sev-crit`, the beacon comb drew its
 * ticks in `--sev-crit`, the subdomain counter used `--sev-high`. So a
 * low-severity DGA domain and a critical one rendered identically, and the
 * loudest thing on screen stopped correlating with the most urgent. That is not
 * a cosmetic defect: it makes the severity ramp stop carrying information in
 * the one place an operator reads it fastest.
 *
 * `classVisual` returns a React element rather than DOM, so the colour each
 * visual was handed is inspectable directly from props.
 */
import { describe, expect, it } from "vitest";
import type { ReactElement } from "react";
import { classVisual } from "../visuals";
import { SEV } from "../../lib/tokens";
import type { Alert, ClassVisual, Severity } from "../../lib/types";

function alertWith(visual: ClassVisual, severity: Severity): Alert {
  return {
    alert_id: "x",
    ts: 0,
    src_ip: "10.0.0.1",
    dst_ip: "10.0.0.2",
    dst_port: 53,
    threat_class: "dga_domain",
    threat_code: "DG",
    confidence: 0.5,
    severity,
    occurrences: 1,
    evidence: [],
    visual,
  } as unknown as Alert;
}

const STRING_INSPECTOR: ClassVisual = {
  kind: "string_inspector",
  domain: "kjqxvndhzpw.com",
  heat: [0.9, 0.8],
  nxdomain: [1, 2],
  score: 0.94,
};

function sevColorOf(visual: ClassVisual, severity: Severity): string {
  const cv = classVisual(alertWith(visual, severity));
  return ((cv!.node as ReactElement).props as { sevColor: string }).sevColor;
}

describe("class visuals take their colour from the alert's severity", () => {
  it("does not paint every DGA alert critical red", () => {
    // The regression, stated as directly as it can be: two DGA alerts of
    // different severity must not render in the same colour.
    const low = sevColorOf(STRING_INSPECTOR, "low");
    const critical = sevColorOf(STRING_INSPECTOR, "critical");

    expect(low).not.toBe(critical);
    expect(low).toBe(SEV.low.color);
    expect(critical).toBe(SEV.critical.color);
    expect(low).not.toBe(SEV.critical.color);
  });

  it("passes the matching ramp colour for every severity", () => {
    for (const s of ["low", "medium", "high", "critical"] as Severity[]) {
      expect(sevColorOf(STRING_INSPECTOR, s)).toBe(SEV[s].color);
    }
  });

  it("applies to every class visual, not just the DGA inspector", () => {
    const visuals: ClassVisual[] = [
      { kind: "beacon_comb", periods: 42, jitterPct: 4 },
      { kind: "fanout_matrix", cell_ports: [22], cell_offsets: [0], cell_rejected: [false] },
      { kind: "entropy_rate", rateSeries: [1], entropySeries: [0.5], spoofed: true, baselineLow: 0.1, baselineHigh: 0.9 },
      STRING_INSPECTOR,
      { kind: "subdomain_fanout", parent: "example.com", count: 300, subs: ["a"], lengths: [10] },
      { kind: "ja3_rarity", bins: [10, 1], tailIndex: 1, history: ["abc"] },
      { kind: "baseline_departure", series: [1, 9], baselineBand: [1, 2] },
    ];
    for (const v of visuals) {
      expect(sevColorOf(v, "low")).toBe(SEV.low.color);
      expect(sevColorOf(v, "critical")).toBe(SEV.critical.color);
    }
  });

  it("degrades to evidence bars alone for a visual kind this build does not know", () => {
    // Spec 5.2: a new detector must never break the interface.
    const unknown = { kind: "some_future_detector" } as unknown as ClassVisual;
    expect(classVisual(alertWith(unknown, "high"))).toBeNull();
    expect(classVisual(alertWith({ kind: "none" }, "high"))).toBeNull();
  });
});
