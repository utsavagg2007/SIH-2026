/**
 * Design tokens.
 *
 * DESIGN.md §12.1: the CSS custom properties in `styles.css` are the single
 * source of truth. These constants read them rather than restating the
 * literals, so a palette change happens in exactly one place and the inline
 * styles that compute values from data cannot drift from the stylesheet that
 * owns hover, focus and the reduced-motion branch.
 *
 * The governing rule (§2.1) is unchanged: colour is reserved entirely for
 * severity and threat state. Nothing else on screen is saturated.
 */
export const T = {
  /** The frame behind panels. Depth without a single shadow. */
  bgDeep: "var(--bg-deep)",
  bg: "var(--bg)",
  panel: "var(--panel)",
  panel2: "var(--panel-2)",
  /** Hover only. `--panel-2` doing double duty as hover *and* selected is what
   *  made the old build read as stateless. */
  panel3: "var(--panel-3)",
  rule: "var(--rule)",
  ruleBright: "var(--rule-bright)",
  text: "var(--text)",
  text2: "var(--text-2)",
  text3: "var(--text-3)",
  sevLow: "var(--sev-low)",
  sevMed: "var(--sev-med)",
  sevHigh: "var(--sev-high)",
  sevCrit: "var(--sev-crit)",
  /** Learned-normal bands, reference traces and focus rings. Never an alert
   *  colour. */
  baseline: "var(--baseline)",
} as const;

/**
 * A token as a literal colour, for the one place `var()` cannot go.
 *
 * `T.*` are `var(--x)` strings, which is exactly right everywhere the browser
 * parses CSS. A canvas 2D context is not one of those places: assigning an
 * unparseable string to `fillStyle`/`strokeStyle` is specified as a no-op, so
 * the context silently keeps whatever it held before - opaque black at
 * initialisation. The Wire was therefore drawing its baseline, its calibration
 * ticks, its `← 15s` labels and every severity mark in black on a #0b0d0f
 * ground. The strip was not empty; it was invisible, on every screen.
 *
 * Resolved once per token and cached: there is no theme switcher, and these
 * come off `:root`.
 */
const resolvedTokens = new Map<string, string>();
export function paint(token: string): string {
  const hit = resolvedTokens.get(token);
  if (hit !== undefined) return hit;
  const name = /^var\((--[\w-]+)\)$/.exec(token)?.[1];
  // Already a literal (an alert-supplied colour, say) - hand it straight back.
  if (!name || typeof document === "undefined") return token;
  const value =
    getComputedStyle(document.documentElement).getPropertyValue(name).trim() || token;
  resolvedTokens.set(token, value);
  return value;
}

/**
 * The severity ramp.
 *
 * `wash` is the same hue at 12% alpha and has exactly two uses (§2.3): the fill
 * of a ledger bar and the tint on a selected row's first 64px. A wash is never
 * a full-panel background.
 *
 * `rail` is critical's second encoding (§2.4). Hue alone cannot make critical
 * outrank high on a projector at four metres, so critical draws a 3px rail and
 * a filled chip where the rest of the ramp draws 2px and an outlined one - the
 * redline on a gauge is thicker than the gradations.
 */
export const SEV = {
  low: { color: T.sevLow, wash: "var(--sev-low-wash)", label: "LOW", short: "LOW", rail: 2 },
  medium: { color: T.sevMed, wash: "var(--sev-med-wash)", label: "MEDIUM", short: "MED", rail: 2 },
  high: { color: T.sevHigh, wash: "var(--sev-high-wash)", label: "HIGH", short: "HIGH", rail: 2 },
  critical: { color: T.sevCrit, wash: "var(--sev-crit-wash)", label: "CRITICAL", short: "CRIT", rail: 3 },
} as const;

/** Descending severity - the ledger and the keyboard filters both read this
 *  order, and "critical first" is the whole point of the strip. */
export const SEV_ORDER = ["critical", "high", "medium", "low"] as const;

/**
 * The two-letter threat class marks (§2.7). Monochrome: giving each detector a
 * hue would break the severity discipline and eight hues exceed what anyone
 * learns in a demo.
 *
 * KEYS AND VALUES BOTH MIRROR THE BACKEND, WHICH THEY PREVIOUSLY DID NOT.
 * The frozen v1.1 vocabulary is `backend/app/schemas/enums.py::ThreatClass`,
 * with `THREAT_CODE` and `THREAT_LABEL` beside it. This table listed eight
 * classes under invented names - `ddos_flood`, `dns_tunnel`, `encrypted_c2`,
 * `exfiltration`, plus an `amplification` the detector layer does not emit - so
 * four of the seven real classes missed every lookup: the host view printed
 * `??` for their code and the raw enum key for their name.
 *
 * Anywhere an alert is in hand, prefer its own `threat_code` / `threat_label`:
 * the backend serves both per alert, and reading them means a class this table
 * has never been taught still renders correctly. This map is the fallback for
 * the places that only hold a bare class key - the host view's class counts -
 * and the source for the filter chips.
 */
export const CLASS_META: Record<string, { code: string; name: string }> = {
  ddos: { code: "DF", name: "DDoS Flood" },
  dga_domain: { code: "DG", name: "DGA Domain" },
  dns_tunnelling: { code: "DT", name: "DNS Tunnelling" },
  port_scan: { code: "PS", name: "Port Scanning" },
  encrypted_malware: { code: "EC", name: "Encrypted-Session Malware" },
  c2_beaconing: { code: "BC", name: "Beaconing" },
  data_exfiltration: { code: "EX", name: "Exfiltration" },
};

/** The kill chain, in order. The evidence panel draws position in the chain
 *  rather than printing the stage as a string (§7.1). */
export const KILL_CHAIN = [
  "reconnaissance",
  "delivery",
  "exploitation",
  "installation",
  "command_and_control",
  "actions_on_objectives",
] as const;

// §3.1 — two faces from one family: mono for machine data, sans for interface
// chrome. This split is a rule, not a suggestion.
export const MONO = "'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
export const SANS = "'IBM Plex Sans', -apple-system, BlinkMacSystemFont, sans-serif";

// These three objects label essentially every readout in the product, so their
// size is the product's floor for legibility rather than a local choice. They
// were 9 and 10px in `--text-3`, which measured under 3:1 - the labels naming
// the numbers were the least readable text on a screen whose entire purpose is
// being read across a room. One step up each, and `--text-3` is now a passing
// value (see styles.css). Uppercase at 0.07em tracking needs the extra pixel
// more than lowercase would.
export const labelStyle = {
  fontFamily: SANS, fontSize: 11, color: T.text3, fontWeight: 600,
  textTransform: "uppercase" as const, letterSpacing: "0.07em",
};
export const microStyle = {
  fontFamily: SANS, fontSize: 10, color: T.text3, fontWeight: 600,
  textTransform: "uppercase" as const, letterSpacing: "0.07em",
};
export const headingStyle = {
  fontFamily: SANS, fontSize: 12, fontWeight: 600, color: T.text2,
  textTransform: "uppercase" as const, letterSpacing: "0.08em",
};

// §3.2 — near-zero radius everywhere except interactive elements, so they are
// distinguishable from readouts by shape alone.
export const RADIUS_INTERACTIVE = 2;
export const RADIUS_STATIC = 0;
