/**
 * The wire contract, mirrored from the backend.
 *
 * The authority for everything below is `backend/app/schemas/view.py`. That
 * module is explicit that the detector's frozen v1.1 alert and the dashboard's
 * view model are different shapes, and that the backend owns the translation
 * between them. This file is the client half of that view model and nothing
 * else: if a field is not served, it does not belong here.
 *
 * An unrecognized `visual.kind` must fall back to evidence bars alone - a new
 * detector should never break the interface (see EvidencePanel / classVisual).
 */
export type Severity = "low" | "medium" | "high" | "critical";

export type ThreatClass =
  | "ddos_flood" | "amplification" | "port_scan" | "c2_beaconing"
  | "dga_domain" | "dns_tunnel" | "encrypted_c2" | "exfiltration";

/** `ScoreType` in the backend enums. Spec 2.2: severity is not confidence, and
 *  a rule score must not be presented as a probability. */
export type ScoreType = "rule" | "model" | "anomaly" | "signature";

export type KillChainStage =
  | "reconnaissance" | "delivery" | "exploitation" | "installation"
  | "command_and_control" | "actions_on_objectives";

export interface EvidenceItem {
  feature: string;
  value: number | string;
  threshold?: number;
  direction?: "above" | "below";
  scale?: [number, number];
  /** Which side of the threshold the observed value landed on. The backend
   *  decides this; the panel colours the marker from it rather than
   *  recomputing the comparison and disagreeing. */
  exceeded?: boolean;
  label?: string;
  unit?: string | null;
  /** Spec 5.1: "Order by contribution, most decisive first." Lower sorts first. */
  rank?: number;
}

/**
 * Where a class visual's series came from.
 *
 * `backend/app/projection/visuals.py` is emphatic about this: when the frozen
 * v1.1 evidence bag carries no series, the backend can reconstruct a plausible
 * one from summary statistics, and such a payload is stamped
 * `reconstructed_from_summary_statistics`. A comb drawn from `mean_interval_sec`
 * looks like a perfect beacon *by construction*, so presenting it as observed
 * would fabricate the most convincing image in the product. The visuals badge
 * it instead.
 */
export type VisualSource = "observed" | "reconstructed_from_summary_statistics";

export type ClassVisual =
  | { kind: "beacon_comb"; source?: VisualSource; periods: number; jitterPct: number }
  | {
      kind: "fanout_matrix";
      source?: VisualSource;
      /** Destination ports contacted, one per cell. Sampled by the backend to
       *  at most 120 cells; `cells_total` reports the true count. Plotted on a
       *  rank axis, never a linear 0-65535 one - see FanoutMatrix. */
      cell_ports: number[];
      /** Seconds from the start of the observation window, one per cell. */
      cell_offsets: number[];
      /** Whether each contact was refused or reset. A wall of these is what
       *  makes a scan a scan (spec 5.2). */
      cell_rejected: boolean[];
      cells_sampled?: number;
      cells_total?: number;
      unique_dst_ports?: number | null;
      unique_dst_ips?: number | null;
      connection_attempts?: number | null;
      rejected_connections?: number | null;
      syn_no_ack_ratio?: number;
      duration_sec?: number;
      /** Vertical = many ports on few hosts; horizontal = few ports across many.
       *  Naming the pattern is what makes the picture read instantly. */
      pattern?: string;
    }
  | { kind: "entropy_rate"; source?: VisualSource; rateSeries: number[]; entropySeries: number[]; spoofed: boolean; baselineLow: number; baselineHigh: number }
  | { kind: "string_inspector"; source?: VisualSource; domain: string; heat: number[]; nxdomain: number[]; score: number }
  | { kind: "subdomain_fanout"; source?: VisualSource; parent: string; count: number; subs: string[]; lengths: number[] }
  | { kind: "ja3_rarity"; source?: VisualSource; bins: number[]; tailIndex: number; history: string[] }
  | { kind: "baseline_departure"; source?: VisualSource; series: number[]; baselineBand: [number, number] }
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
  /** Two-letter code for dense listings and Wire marks (spec 2.2). Served by
   *  the backend as `threat_code`; the Wire reads it per mark, so deriving it
   *  client-side from a lookup table would silently drop any class the table
   *  has not been taught. */
  threat_code: string;
  threat_label?: string;
  confidence: number;
  score?: number;
  score_type?: ScoreType;
  severity: Severity;
  detector?: string;
  detector_version?: string;
  occurrences: number;
  first_seen?: number;
  /** Most recent occurrence of this dedup key. `first_seen` alone cannot say
   *  whether a repeating alert is still active. */
  last_seen?: number;
  evidence: EvidenceItem[];
  /** The detector's untouched flat evidence bag, so a novel key still reaches
   *  the raw-record expander even when the threshold registry has no opinion. */
  evidence_raw?: Record<string, unknown>;
  visual: ClassVisual;
  mitre_technique?: string | null;
  mitre_techniques?: string[];
  incident_id?: string | null;
  kill_chain_stage?: KillChainStage;
  pipeline_latency_ms?: number;
}

/** One node on the kill-chain ribbon (spec 6.1). */
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
  /** The host the correlation pivoted on. Every member alert touches it. */
  pivot_host: string;
  opened_at: number;
  /** Last member arrival. The incident list sorts on this, so an incident that
   *  is still growing stays at the top. */
  updated_at: number;
  severity: Severity;
  confidence?: number;
  /** True when the incident spans more than one kill-chain stage. The sequence
   *  is itself evidence (spec 6.1), which is what justifies escalating past
   *  the highest member severity. */
  escalated?: boolean;
  /** Exact, even when `members` is a trimmed slice. */
  alert_count: number;
  stages?: KillChainStage[];
  threat_classes?: ThreatClass[];
  members: IncidentMember[];
  members_truncated?: boolean;
  elapsed_sec: number;
  narrative?: string;
}

/** Investigation view for one machine (spec 6.3). Mirrors `HostView` in
 *  `backend/app/schemas/view.py`; this replaces the `any` the REST client used
 *  to hand out, which defeated the point of typing the rest of the contract. */
export interface HostView {
  ip: string;
  first_seen: number;
  last_seen: number;
  alert_count: number;
  severity_counts: Record<string, number>;
  threat_class_counts: Record<string, number>;
  /** Peers observed with this host, most recent first. Novelty is a
   *  detector-side judgement, so the backend reports what it saw rather than
   *  guessing which peers are new. */
  peers: string[];
  ja3_history: string[];
  incidents: string[];
  alerts: Alert[];
}

export interface DetectorStatus {
  detector: string;
  detector_version: string;
  /** A detector that has never posted is `unseen`, not offline: the backend
   *  cannot tell a down detector from one with nothing to report. */
  state: "online" | "degraded" | "unseen";
  alerts_produced: number;
  last_seen: number | null;
  mean_detector_latency_ms: number;
  threat_classes: string[];
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
  ws_clients: number;
  alerts_total: number;
  alerts_deduplicated: number;
  alerts_rejected: number;
  incidents_total: number;
  dedup_keys_tracked: number;
  incidents_tracked: number;
  detectors: DetectorStatus[];
}

/** Requirement (d), with provenance attached: `alerts_*` are measured by the
 *  backend, `traffic_*` are reported to it by the ingestion layer. */
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
  latency_histogram: Record<string, number>[];
  latency_window_s: number;
  latency_definition: string;
  uptime_s: number;
}

export interface ConstraintProof {
  ingest_direction: "inbound_only";
  egress_blocked: boolean;
  payload_decryption: "never";
  outbound_attempts: number;
  write_routes_toward_network: number;
  checked_at: number;
  notes: string[];
}

export interface Capture {
  capture: string;
  alerts: number;
  size_bytes: number;
  /** Ground-truth manifest sitting beside the capture. Spec 6.4: naming the
   *  attacks a capture is known to contain is what makes "here it is at minute
   *  seven" a demo moment rather than a claim. */
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
  /** Whether the traffic figures came from a live telemetry post rather than a
   *  stale one. The backend never sees a packet, so flows/sec, packets/sec and
   *  Mb/s are reported by the ingestion and detection layers or not at all; the
   *  instrument bar shows a dash rather than a confident zero when this is
   *  false. */
  trafficLive?: boolean;
}

/** The once-per-second metrics frame as it arrives on the socket. */
export interface MetricsFrame {
  type: "metrics";
  ts: number;
  flows_per_sec: number;
  packets_per_sec: number;
  mbps: number;
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

/** A frame on `/ws/alerts`. Discriminated on `type` so an unknown frame is
 *  dropped by the caller's `default` branch rather than crashing the feed. */
export type Frame =
  | {
      type: "snapshot";
      data: { alerts: Alert[]; incidents: Incident[]; metrics: MetricsFrame };
    }
  | { type: "alert.created"; data: Alert }
  | { type: "alert.updated"; data: Alert }
  | { type: "incident.created"; data: Incident }
  | { type: "incident.updated"; data: Incident }
  | { type: "metrics"; data: MetricsFrame }
  | {
      type: "system.status";
      data: {
        ts: number;
        replay_active: boolean;
        storage_backend: string;
        storage_healthy: boolean;
        storage_queue_depth: number;
        detail: string | null;
      };
    };

// ---------------------------------------------------------------- analyst

/** One claim and the stored field it came from.
 *
 * Spec 6.5 is absolute here: "Statements that cannot be traced to a stored
 * field must not be shown at all." The analyst service returns this array for
 * exactly that purpose, so the panel renders references from it rather than
 * trusting prose. */
export interface Citation {
  text: string;
  source: string;
  value?: unknown;
}

export interface AnalystAnswer {
  subject: string;
  kind: "alert" | "incident" | "corpus";
  text: string;
  /** False when the text is the deterministic local rendering rather than
   *  model output. The panel badges this rather than hiding it. */
  generated: boolean;
  provider: string;
  model?: string | null;
  /** Present when generation was attempted and rejected or failed. */
  degraded_reason?: string | null;
  citations: Citation[];
  alert_ids: string[];
  /** How a question was resolved to filters. Only set by /ask. */
  interpreted_as?: string[] | null;
}

export interface AnalystHealth {
  status: "ok" | "degraded";
  provider: string;
  model: string | null;
  generation_enabled: boolean;
  alert_store: string;
  alert_store_reachable: boolean;
}

export type ViewId = "live" | "incidents" | "host" | "system" | "replay";
