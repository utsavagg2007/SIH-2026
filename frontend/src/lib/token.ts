// Section 2.2 — colour tokens, verbatim. Colour is reserved entirely for
// severity and threat class; nothing else on screen is saturated.
export const T = {
  bg: "#0B0D0F",
  panel: "#14181B",
  panel2: "#1B2024",
  rule: "#252C31",
  ruleBright: "#38424A",
  text: "#E9ECED",
  text2: "#8B959C",
  text3: "#5A646B",
  sevLow: "#4E9C7F",
  sevMed: "#D2A03E",
  sevHigh: "#DB7038",
  sevCrit: "#C8453D",
  baseline: "#41718F",
} as const;

export const SEV = {
  low: { color: T.sevLow, label: "LOW" },
  medium: { color: T.sevMed, label: "MEDIUM" },
  high: { color: T.sevHigh, label: "HIGH" },
  critical: { color: T.sevCrit, label: "CRITICAL" },
} as const;

// Section 2.2 — the eight two-letter threat class marks
export const CLASS_META: Record<string, { code: string; name: string }> = {
  ddos_flood: { code: "DF", name: "DDoS flood" },
  amplification: { code: "AM", name: "Amplification" },
  port_scan: { code: "PS", name: "Port scan" },
  c2_beaconing: { code: "BC", name: "Beaconing" },
  dga_domain: { code: "DG", name: "DGA domain" },
  dns_tunnel: { code: "DT", name: "DNS tunnel" },
  encrypted_c2: { code: "EC", name: "Encrypted C2" },
  exfiltration: { code: "EX", name: "Exfiltration" },
};

// Section 2.3 — two faces from one family: mono for machine data, sans for
// interface chrome. This split is a rule, not a suggestion.
export const MONO = "'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
export const SANS = "'IBM Plex Sans', -apple-system, BlinkMacSystemFont, sans-serif";

export const labelStyle = {
  fontFamily: SANS, fontSize: 10, color: T.text3,
  textTransform: "uppercase" as const, letterSpacing: "0.06em",
};
export const headingStyle = {
  fontFamily: SANS, fontSize: 12, fontWeight: 600, color: T.text2,
  textTransform: "uppercase" as const, letterSpacing: "0.06em",
};

// Section 2.4 — near-zero radius everywhere except interactive elements
export const RADIUS_INTERACTIVE = 2;
export const RADIUS_STATIC = 0;