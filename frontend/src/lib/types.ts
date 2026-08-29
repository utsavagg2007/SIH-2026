/**
 * Types mirroring what the backend actually serves.
 *
 * The frozen v1.1 enums come from SIH26_Alert_Output_Spec_v1.1_FINAL.md section
 * 12.  Everything else is the backend's view model: evidence projected into
 * bars, the class-specific `visual`, and the dedup/correlation state.
 */

export type ThreatClass =
  | "dga_domain"
  | "dns_tunnelling"
  | "c2_beaconing"
  | "encrypted_malware"
  | "ddos"
  | "port_scan"
  | "data_exfiltration";

export type Severity = "low" | "medium" | "high" | "critical";

export type ScoreType =
  | "calibrated_model"
  | "rule_score"
  | "anomaly_score"
  | "signature_match";

export type EventScope =
  | "flow"
  | "source_host"
  | "destination_host"
  | "host_pair"
  | "network";

export type KillChainStage = "recon" | "c2" | "exfil" | "impact";

export interface EvidenceItem {
  feature: string;
  label: string;
  value: string | number | boolean | null;
  unit: string | null;
  /** Present -> render a bar. Absent -> plain label/value pair, no invented scale. */
  threshold: number | null;
  direction: "above" | "below" | null;
  scale: [number, number] | null;
  exceeded: boolean | null;
  rank: number;
}

/** Provenance of a class-specific visual. See the backend's visuals module. */
export type VisualSource = "observed" | "reconstructed_from_summary_statistics";

export interface Visual {
  kind: string;
  source: VisualSource;
  [key: string]: unknown;
}

export interface Alert {
  alert_id: string;
  schema_version: string;

  ts: number;
  event_start: number;
  event_end: number;
  detected_at: number;
  ingested_at: number;
  event_start_iso: string;
  event_end_iso: string;
  detected_at_iso: string;

  event_scope: EventScope;
  flow_id: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: string | null;

  threat_class: ThreatClass;
  threat_code: string;
  threat_label: string;

  severity: Severity;
  score: number;
  confidence: number;
  score_type: ScoreType;

  evidence: EvidenceItem[];
  evidence_raw: Record<string, unknown>;
  visual: Visual | null;

  detector: string;
  detector_version: string;
  mitre_techniques: string[];

  incident_id: string | null;
  kill_chain_stage: KillChainStage;

  occurrences: number;
  first_seen: number;
  last_seen: number;
  dedup_key: string;

  detector_latency_ms: number;
  transport_latency_ms: number;
  pipeline_latency_ms: number;

  raw: Record<string, unknown>;
}

export interface IncidentMember {
  alert_id: string;
  ts: number;
  threat_class: ThreatClass;
  threat_code: string;
  severity: Severity;
  confidence: number;
  stage: KillChainStage;
  occurrences: number;
}

export interface Incident {
  incident_id: string;
  pivot_host: string;
  opened_at: number;
  updated_at: number;
  opened_at_iso: string;
  severity: Severity;
  confidence: number;
  escalated: boolean;
  alert_count: number;
  stages: KillChainStage[];
  threat_classes: ThreatClass[];
  members: IncidentMember[];
  members_truncated: boolean;
  elapsed_sec: number;
  narrative: string;
}

export interface Metrics {
  type: "metrics";
  ts: number;
  flows_per_sec: number;
  packets_per_sec: number;
  mbps: number;
  /** False -> show traffic figures as unavailable, not as a confident zero. */
  traffic_telemetry_live: boolean;
  alerts_per_sec: number;
  alerts_total: number;
  latency_p50_ms: number;
  latency_p95_ms: number;
  latency_max_ms: number;
  detectors_online: number;
  detectors_total: number;
  egress_blocked: boolean;
  uptime_s: number;
  ws_clients: number;
  ws_dropped: number;
}

export interface DetectorStatus {
  detector: string;
  detector_version: string;
  state: "online" | "degraded" | "unseen";
  alerts_produced: number;
  last_seen: number | null;
  mean_detector_latency_ms: number;
  threat_classes: string[];
}

export interface ConstraintProof {
  ingest_direction: string;
  egress_blocked: boolean;
  payload_decryption: string;
  outbound_attempts: number;
  write_routes_toward_network: number;
  checked_at: number;
  notes: string[];
}

export interface Throughput {
  alerts_per_sec: number;
  alerts_peak_per_sec: number;
  alerts_total: number;
  alerts_deduplicated: number;
  alerts_rejected: number;
  traffic_flows_per_sec: number;
  traffic_packets_per_sec: number;
  traffic_mbps: number;
  traffic_telemetry_live: boolean;
  traffic_source: string;
  traffic_reported_at: number | null;
  latency_p50_ms: number;
  latency_p95_ms: number;
  latency_max_ms: number;
  latency_histogram: { bin_start: number; bin_end: number; count: number }[];
  latency_definition: string;
  uptime_s: number;
}

export interface Health {
  status: "ok" | "degraded";
  version: string;
  schema_version: string;
  uptime_s: number;
  storage_backend: string;
  storage_healthy: boolean;
  storage_queue_depth: number;
  storage_writes_shed: number;
  storage_write_errors: number;
  alerts_total: number;
  alerts_deduplicated: number;
  alerts_rejected: number;
  incidents_total: number;
  dedup_keys_tracked: number;
  incidents_tracked: number;
  detectors: DetectorStatus[];
}

export interface Capture {
  capture: string;
  alerts: number;
  size_bytes: number;
  scenario: Record<string, unknown>;
}

export interface ReplayStatus {
  running: boolean;
  capture: string | null;
  speed: number;
  position: number;
  total: number;
  emitted: number;
  rejected: number;
  elapsed_s: number;
  loop: boolean;
  scenario: Record<string, unknown>;
}

/** Frames arriving on /ws/alerts. */
export type Frame =
  | { type: "snapshot"; data: { alerts: Alert[]; incidents: Incident[]; metrics: Metrics; schema_version: string } }
  | { type: "alert.created"; data: Alert }
  | { type: "alert.updated"; data: Alert }
  | { type: "incident.created"; data: Incident }
  | { type: "incident.updated"; data: Incident }
  | { type: "metrics"; data: Metrics }
  | { type: "system.status"; data: Record<string, unknown> }
  | { type: "pong"; data: { ts: number } };
