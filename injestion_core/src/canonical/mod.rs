pub mod id;
pub mod producer;
pub mod time;

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ObservationType {
    Flow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TelemetrySource {
    Zeek,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Fidelity {
    Exact,
    Sampled,
    Estimated,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Quality {
    pub fidelity: Fidelity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling_rate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling_probability: Option<f64>,
    pub truncated: bool,
    pub loss_detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missed_content_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputMode {
    PcapFile,
    LiveInterface,
    ExportStream,
    ExportFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Provenance {
    pub input_mode: InputMode,
    pub parser_name: String,
    pub parser_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exporter_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_domain_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_sequence: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectionMode {
    OriginatorResponder,
    Unidirectional,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TcpFlag {
    Fin,
    Syn,
    Rst,
    Psh,
    Ack,
    Urg,
    Ece,
    Cwr,
    Ns,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectionCounters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l2_bytes: Option<u64>,
}

impl DirectionCounters {
    pub fn is_empty(&self) -> bool {
        self.packets.is_none()
            && self.payload_bytes.is_none()
            && self.ip_bytes.is_none()
            && self.l2_bytes.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowCounters {
    pub src_to_dst: DirectionCounters,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_to_src: Option<DirectionCounters>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowData {
    pub start_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
    pub src_ip: String,
    pub dst_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<u8>,
    pub ip_protocol: u8,
    pub direction_mode: DirectionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_history: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_flags: Option<Vec<TcpFlag>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_interface: Option<String>,
    pub counters: FlowCounters,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum CanonicalData {
    Flow(FlowData),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CanonicalObservation {
    pub schema_version: String,
    pub record_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_record_id: Option<String>,
    pub observation_type: ObservationType,
    pub telemetry_source: TelemetrySource,
    pub sensor_id: String,
    pub observed_at: String,
    pub quality: Quality,
    pub provenance: Provenance,
    pub data: CanonicalData,
}
