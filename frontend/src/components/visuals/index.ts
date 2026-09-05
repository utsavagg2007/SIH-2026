/**
 * Dispatch from an alert's `visual.kind` to the component that draws it.
 *
 * An unrecognized or absent kind returns null and the evidence bars carry the
 * alert alone: "a missing class-specific visual degrades gracefully, since the
 * universal evidence layer still answers the question". A new detector shipping
 * a visual this build has never heard of must never break the interface.
 *
 * THE SAME PROMISE APPLIES TO A KNOWN KIND WITH MISSING DATA, AND USED NOT TO.
 * Every one of these components indexed straight into the series it expected -
 * `Math.max(...series)`, `bins.map(...)`, `domain.split("")`. A backend that
 * sent `{"kind": "baseline_departure"}` with no series threw inside render, and
 * because nothing caught it React unmounted the whole tree: selecting one alert
 * turned the entire console blank. `REQUIRED_SERIES` is the guard, in the one
 * place every caller routes through rather than repeated in eight components.
 * An empty or absent series is reported as what it is - the detector did not
 * send the shape - which is also what DESIGN.md §11 requires: if the backend
 * did not send it, the component does not draw it.
 *
 * Every visual is handed the alert's severity colour. It is passed rather than
 * chosen because colour is reserved entirely for severity and threat class: a
 * component that reaches for `--sev-crit` itself is asserting a severity the
 * detector did not report, and the ramp stops meaning anything.
 */
import { createElement, type ReactNode } from "react";
import { SEV } from "../../lib/tokens";
import type { Alert, ClassVisual } from "../../lib/types";
import { BeaconComb } from "./BeaconComb";
import { FanoutMatrix } from "./FanoutMatrix";
import { EntropyRateChart } from "./EntropyRateChart";
import { StringInspector } from "./StringInspector";
import { SubdomainFanout } from "./SubdomainFanout";
import { Ja3Rarity } from "./Ja3Rarity";
import { BaselineDeparture } from "./BaselineDeparture";
import { MissingSeries } from "./chrome";

/** Fields each visual dereferences without checking. If one is absent or empty,
 *  the payload cannot be drawn and saying so beats throwing. */
const REQUIRED_SERIES: Record<string, string[]> = {
  beacon_comb: [],
  fanout_matrix: [],
  entropy_rate: ["rateSeries", "entropySeries"],
  string_inspector: ["domain", "heat"],
  subdomain_fanout: ["subs", "lengths"],
  ja3_rarity: ["bins", "history"],
  baseline_departure: ["series", "baselineBand"],
};

function missingFields(v: ClassVisual): string[] {
  const required = REQUIRED_SERIES[v.kind] ?? [];
  const bag = v as unknown as Record<string, unknown>;
  return required.filter((f) => {
    const value = bag[f];
    if (value === undefined || value === null) return true;
    return Array.isArray(value) ? value.length === 0 : false;
  });
}

const TITLES: Record<string, string> = {
  beacon_comb: "The comb",
  fanout_matrix: "Fan-out matrix",
  entropy_rate: "Entropy against rate",
  string_inspector: "The string inspector",
  subdomain_fanout: "Subdomain fan-out",
  ja3_rarity: "Fingerprint rarity",
  baseline_departure: "Baseline departure",
};

export function classVisual(alert: Alert): { title: string; node: ReactNode } | null {
  const v = alert.visual;
  if (!v || v.kind === "none") return null;
  const title = TITLES[v.kind];
  if (!title) return null;

  const missing = missingFields(v);
  if (missing.length) {
    return { title, node: createElement(MissingSeries, { fields: missing }) };
  }

  const sevColor = SEV[alert.severity].color;
  switch (v.kind) {
    case "beacon_comb":
      return { title, node: createElement(BeaconComb, { ...v, sevColor }) };
    case "fanout_matrix":
      return { title, node: createElement(FanoutMatrix, { ...v, sevColor }) };
    case "entropy_rate":
      return { title, node: createElement(EntropyRateChart, { ...v, sevColor }) };
    case "string_inspector":
      return { title, node: createElement(StringInspector, { ...v, sevColor }) };
    case "subdomain_fanout":
      return { title, node: createElement(SubdomainFanout, { ...v, sevColor }) };
    case "ja3_rarity":
      return { title, node: createElement(Ja3Rarity, { ...v, sevColor }) };
    case "baseline_departure":
      return { title, node: createElement(BaselineDeparture, { ...v, sevColor }) };
    default:
      return null;
  }
}
