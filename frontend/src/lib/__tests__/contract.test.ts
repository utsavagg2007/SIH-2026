/**
 * The class-vocabulary seam between this bundle and the backend.
 *
 * THE BUG THIS PINS. `CLASS_META` and the `ThreatClass` union listed eight
 * classes under names the detection layer does not emit - `ddos_flood`,
 * `dns_tunnel`, `encrypted_c2`, `exfiltration`, plus an `amplification` that
 * exists nowhere in the pipeline. The backend's frozen v1.1 enum has seven,
 * spelled `ddos`, `dns_tunnelling`, `encrypted_malware`, `data_exfiltration`.
 * So four of the seven real classes missed every lookup, and because a lookup
 * miss is silent, nothing failed: the host view printed `??` for their code and
 * the raw enum key for their name, and every layer's own tests stayed green
 * while the interface between them was wrong.
 *
 * These assertions are transcribed from `backend/app/schemas/enums.py`
 * (`ThreatClass`, `THREAT_CODE`, `THREAT_LABEL`). If the backend adds or renames
 * a class, this test fails and names the drift rather than letting it show up
 * as a `??` on a projector.
 */
import { describe, expect, it } from "vitest";
import { CLASS_META, SEV, SEV_ORDER, KILL_CHAIN } from "../tokens";

/** backend/app/schemas/enums.py — ThreatClass, THREAT_CODE, THREAT_LABEL. */
const BACKEND_CLASSES: Record<string, { code: string; name: string }> = {
  ddos: { code: "DF", name: "DDoS Flood" },
  dga_domain: { code: "DG", name: "DGA Domain" },
  dns_tunnelling: { code: "DT", name: "DNS Tunnelling" },
  port_scan: { code: "PS", name: "Port Scanning" },
  encrypted_malware: { code: "EC", name: "Encrypted-Session Malware" },
  c2_beaconing: { code: "BC", name: "Beaconing" },
  data_exfiltration: { code: "EX", name: "Exfiltration" },
};

describe("threat class vocabulary matches the backend enum", () => {
  it("covers every served class and invents none", () => {
    expect(Object.keys(CLASS_META).sort()).toEqual(Object.keys(BACKEND_CLASSES).sort());
  });

  it("uses the backend's own two-letter codes and labels", () => {
    for (const [key, expected] of Object.entries(BACKEND_CLASSES)) {
      expect(CLASS_META[key]).toEqual(expected);
    }
  });

  it("keeps every code distinct, since the code is the mark on the Wire", () => {
    const codes = Object.values(CLASS_META).map((c) => c.code);
    expect(new Set(codes).size).toBe(codes.length);
    for (const c of codes) expect(c).toMatch(/^[A-Z]{2}$/);
  });
});

describe("severity ramp", () => {
  it("orders critical first, which is what the ledger reads", () => {
    expect(SEV_ORDER).toEqual(["critical", "high", "medium", "low"]);
  });

  it("gives critical a second encoding channel beyond hue", () => {
    // Hue alone cannot make critical outrank high on a projector at 4m, so
    // critical draws a heavier rail. If this collapses to 2px, the ramp is
    // back to carrying one channel at the point it matters most.
    expect(SEV.critical.rail).toBeGreaterThan(SEV.high.rail);
  });

  it("carries a text label for every severity, so colour is never the only cue", () => {
    for (const k of SEV_ORDER) {
      expect(SEV[k].label).toBeTruthy();
      expect(SEV[k].short).toBeTruthy();
    }
  });
});

describe("kill chain", () => {
  it("matches the backend's KillChainStage order", () => {
    // The evidence panel draws position in the chain; a reordering here would
    // put an alert at the wrong point in the sequence.
    expect(KILL_CHAIN).toEqual([
      "reconnaissance",
      "delivery",
      "exploitation",
      "installation",
      "command_and_control",
      "actions_on_objectives",
    ]);
  });
});
