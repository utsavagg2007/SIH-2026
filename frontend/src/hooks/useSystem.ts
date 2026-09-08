import { useEffect, useState } from "react";
import { api } from "../lib/api";
import type { ConstraintProof, DetectorStatus, Health, Throughput } from "../lib/types";

/**
 * The REST half of the system readouts.
 *
 * One poller for the whole app: the instrument bar needs the traffic source,
 * the ledger needs the measured peak alert rate, and the System view needs all
 * four payloads. Fetching them per component would triple the request rate and
 * let two screens disagree about the same second.
 *
 * DESIGN.md §11: every figure here is measured by the backend. Nothing is
 * synthesised when a request fails - `error` is surfaced and the panels say
 * what is unavailable rather than drawing a plausible curve.
 */
export interface SystemSnapshot {
  health: Health | null;
  throughput: Throughput | null;
  constraints: ConstraintProof | null;
  detectors: DetectorStatus[] | null;
  /** Null until the first attempt resolves; a string once one has failed. */
  error: string | null;
  /** False until the first round-trip completes, so panels can distinguish
   *  "not asked yet" from "asked and got nothing". */
  loaded: boolean;
}

const EMPTY: SystemSnapshot = {
  health: null,
  throughput: null,
  constraints: null,
  detectors: null,
  error: null,
  loaded: false,
};

export function useSystem(intervalMs = 5000): SystemSnapshot {
  const [snap, setSnap] = useState<SystemSnapshot>(EMPTY);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      // Settled rather than all: the constraint proof and the detector list are
      // independent endpoints, and one being unavailable must not blank the
      // other three.
      const [health, throughput, constraints, detectors] = await Promise.allSettled([
        api.health(),
        api.throughput(),
        api.constraints(),
        api.detectors(),
      ]);
      if (cancelled) return;

      const failures = [health, throughput, constraints, detectors].filter(
        (r): r is PromiseRejectedResult => r.status === "rejected"
      );

      setSnap({
        health: health.status === "fulfilled" ? health.value : null,
        throughput: throughput.status === "fulfilled" ? throughput.value : null,
        constraints: constraints.status === "fulfilled" ? constraints.value : null,
        detectors: detectors.status === "fulfilled" ? detectors.value.items : null,
        error: failures.length ? String(failures[0].reason?.message ?? failures[0].reason) : null,
        loaded: true,
      });
    }

    poll();
    const timer = setInterval(poll, intervalMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [intervalMs]);

  return snap;
}
