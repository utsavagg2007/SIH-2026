/**
 * Dispatch from an alert's `visual.kind` to the component that draws it.
 *
 * An unrecognized or absent kind returns null and the evidence bars carry the
 * alert alone (spec 5.2: "a missing class-specific visual degrades gracefully,
 * since the universal evidence layer still answers the question"). A new
 * detector shipping a visual this build has never heard of must never break the
 * interface.
 *
 * Every visual is handed the alert's severity colour. It is passed rather than
 * chosen because spec 2.1 reserves colour entirely for severity and threat
 * class: a component that reaches for `--sev-crit` itself is asserting a
 * severity the detector did not report, and the ramp stops meaning anything.
 */
import { createElement } from "react";
import { SEV } from "../../lib/tokens";
import type { Alert } from "../../lib/types";
import { BeaconComb } from "./BeaconComb";
import { FanoutMatrix } from "./FanoutMatrix";
import { EntropyRateChart } from "./EntropyRateChart";
import { StringInspector } from "./StringInspector";
import { SubdomainFanout } from "./SubdomainFanout";
import { Ja3Rarity } from "./Ja3Rarity";
import { BaselineDeparture } from "./BaselineDeparture";

export function classVisual(alert: Alert): { title: string; node: React.ReactNode } | null {
  const v = alert.visual;
  if (!v) return null;
  const sevColor = SEV[alert.severity].color;

  switch (v.kind) {
    case "beacon_comb":
      return { title: "The comb", node: createElement(BeaconComb, { ...v, sevColor }) };
    case "fanout_matrix":
      return { title: "Fan-out matrix", node: createElement(FanoutMatrix, { ...v, sevColor }) };
    case "entropy_rate":
      return { title: "Entropy against rate", node: createElement(EntropyRateChart, { ...v, sevColor }) };
    case "string_inspector":
      return { title: "The string inspector", node: createElement(StringInspector, { ...v, sevColor }) };
    case "subdomain_fanout":
      return { title: "Subdomain fan-out", node: createElement(SubdomainFanout, { ...v, sevColor }) };
    case "ja3_rarity":
      return { title: "Fingerprint rarity", node: createElement(Ja3Rarity, { ...v, sevColor }) };
    case "baseline_departure":
      return { title: "Baseline departure", node: createElement(BaselineDeparture, { ...v, sevColor }) };
    default:
      return null;
  }
}
