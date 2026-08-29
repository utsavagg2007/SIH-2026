import { createElement } from "react";
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
  switch (v.kind) {
    case "beacon_comb":
      return { title: "The comb", node: createElement(BeaconComb, { periods: v.periods, jitterPct: v.jitterPct }) };
    case "fanout_matrix":
      return { title: "Fan-out matrix", node: createElement(FanoutMatrix, { sweep: v.sweep, refusedRatio: v.refusedRatio }) };
    case "entropy_rate":
      return { title: "Entropy against rate", node: createElement(EntropyRateChart, v) };
    case "string_inspector":
      return { title: "The string inspector", node: createElement(StringInspector, v) };
    case "subdomain_fanout":
      return { title: "Subdomain fan-out", node: createElement(SubdomainFanout, v) };
    case "ja3_rarity":
      return { title: "Fingerprint rarity", node: createElement(Ja3Rarity, v) };
    case "baseline_departure":
      return { title: "Baseline departure", node: createElement(BaselineDeparture, v) };
    default:
      return null;
  }
}