// Mirrors section 7's WebSocket alert payload. An unrecognized visual.kind
// must fall back to evidence bars alone — a new detector should never break
// the interface (see EvidencePanel / classVisual).
export type Severity = "low" | "medium" | "high" | "critical";

export type ThreatClass =
  | "ddos_flood" | "amplification" | "port_scan" | "c2_beaconing"
  | "dga_domain" | "dns_tunnel" | "encrypted_c2" | "exfiltration";

export interface EvidenceItem {
  feature: string;
  value: number | string;
  threshold?: number;
  direction?: "above" | "below";
  scale?: [number, number];
}

export type ClassVisual =
  | { kind: "beacon_comb"; periods: number; jitterPct: number }
  | { kind: "fanout_matrix"; sweep: "vertical" | "horizontal"; refusedRatio: number }
  | { kind: "entropy_rate"; rateSeries: number[]; entropySeries: number[]; spoofed: boolean; baselineLow: number; baselineHigh: number }
  | { kind: "string_inspector"; domain: string; heat: number[]; nxdomain: number[]; score: number }
  | { kind: "subdomain_fanout"; parent: string; count: number; subs: string[]; lengths: number[] }
  | { kind: "ja3_rarity"; bins: number[]; tailIndex: number; history: string[] }
  | { kind: "baseline_departure"; series: number[]; baselineBand: [number, number] }
  | { kind: "none" };

export interface Alert {
  alert_id: string;
  ts: number;
  detected_at?: number;
  flow_id?: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  threat_class: ThreatClass;
  confidence: number;
  severity: Severity;
  detector?: string;
  detector_version?: string;
  occurrences: number;
  first_seen?: number;
  evidence: EvidenceItem[];
  visual: ClassVisual;
  mitre_technique?: string | null;
  incident_id?: string | null;
}

export interface Incident {
  incident_id: string;
  host: string;
  opened_at: number;
  severity: Severity;
  stages: Alert[];
}

export interface Metrics {
  flowsPerSec: number;
  packetsPerSec?: number;
  mbps: number;
  p50: number;
  p95: number;
  detectorsOnline: number;
  detectorsTotal: number;
  uptime: string;
  connected: boolean;
}

export type ViewId = "live" | "incidents" | "host" | "system" | "replay";