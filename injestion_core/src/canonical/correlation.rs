use std::collections::HashMap;
use std::net::IpAddr;

use crate::canonical::{CanonicalData, CanonicalObservation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowCorrelationCandidate {
    pub record_id: String,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub ip_protocol: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsCorrelationTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub ip_protocol: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointCorrelationTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorrelationOutcome {
    NoCandidates,
    Unique(String),
    Ambiguous,
    Inconsistent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateCorrelationOutcome {
    NoCandidates,
    Unique(FlowCorrelationCandidate),
    Ambiguous,
    Inconsistent,
}

#[derive(Debug, Clone, Default)]
pub struct FlowCorrelationIndex {
    by_uid: HashMap<String, Vec<FlowCorrelationCandidate>>,
}

impl FlowCorrelationIndex {
    pub fn from_flow_observations(observations: &[CanonicalObservation]) -> Self {
        let mut index = Self::default();
        for observation in observations {
            let Some(uid) = observation
                .source_record_id
                .as_ref()
                .filter(|uid| !uid.is_empty())
            else {
                continue;
            };
            let CanonicalData::Flow(flow) = &observation.data else {
                continue;
            };
            let (Ok(src_ip), Ok(dst_ip)) = (flow.src_ip.parse(), flow.dst_ip.parse()) else {
                continue;
            };
            index
                .by_uid
                .entry(uid.clone())
                .or_default()
                .push(FlowCorrelationCandidate {
                    record_id: observation.record_id.clone(),
                    src_ip,
                    dst_ip,
                    src_port: flow.src_port,
                    dst_port: flow.dst_port,
                    ip_protocol: flow.ip_protocol,
                });
        }
        index
    }

    pub fn insert(&mut self, uid: impl Into<String>, candidate: FlowCorrelationCandidate) {
        let uid = uid.into();
        if !uid.is_empty() {
            self.by_uid.entry(uid).or_default().push(candidate);
        }
    }

    pub fn correlate(&self, uid: &str, dns: DnsCorrelationTuple) -> CorrelationOutcome {
        let Some(candidates) = self.by_uid.get(uid) else {
            return CorrelationOutcome::NoCandidates;
        };
        let mut matching = candidates.iter().filter(|candidate| {
            candidate.src_ip == dns.src_ip
                && candidate.dst_ip == dns.dst_ip
                && candidate.ip_protocol == dns.ip_protocol
                && optional_port_matches(candidate.src_port, dns.src_port)
                && optional_port_matches(candidate.dst_port, dns.dst_port)
        });

        let Some(first) = matching.next() else {
            return CorrelationOutcome::Inconsistent;
        };
        if matching.next().is_some() {
            CorrelationOutcome::Ambiguous
        } else {
            CorrelationOutcome::Unique(first.record_id.clone())
        }
    }

    /// Resolve one canonical flow using a complete protocol tuple.
    ///
    /// Unlike DNS correlation, both candidate ports must be present and exactly
    /// equal. TLS/HTTP producers use this only for optional linking after their
    /// required protocol has already been established directly from the source.
    pub fn correlate_exact_protocol_tuple(
        &self,
        uid: &str,
        tuple: EndpointCorrelationTuple,
        ip_protocol: u8,
    ) -> CorrelationOutcome {
        let Some(candidates) = self.by_uid.get(uid) else {
            return CorrelationOutcome::NoCandidates;
        };
        let mut matching = candidates.iter().filter(|candidate| {
            candidate.src_ip == tuple.src_ip
                && candidate.dst_ip == tuple.dst_ip
                && candidate.src_port == Some(tuple.src_port)
                && candidate.dst_port == Some(tuple.dst_port)
                && candidate.ip_protocol == ip_protocol
        });

        let Some(first) = matching.next() else {
            return CorrelationOutcome::Inconsistent;
        };
        if matching.next().is_some() {
            CorrelationOutcome::Ambiguous
        } else {
            CorrelationOutcome::Unique(first.record_id.clone())
        }
    }

    /// Resolve one canonical flow by UID and an exact source-reported endpoint tuple.
    ///
    /// This deliberately excludes protocol so TLS/HTTP producers can establish a
    /// missing required `ip_protocol` only from one unambiguous flow candidate.
    pub fn correlate_endpoints(
        &self,
        uid: &str,
        tuple: EndpointCorrelationTuple,
    ) -> CandidateCorrelationOutcome {
        let Some(candidates) = self.by_uid.get(uid) else {
            return CandidateCorrelationOutcome::NoCandidates;
        };
        let mut matching = candidates.iter().filter(|candidate| {
            candidate.src_ip == tuple.src_ip
                && candidate.dst_ip == tuple.dst_ip
                && candidate.src_port == Some(tuple.src_port)
                && candidate.dst_port == Some(tuple.dst_port)
        });

        let Some(first) = matching.next() else {
            return CandidateCorrelationOutcome::Inconsistent;
        };
        if matching.next().is_some() {
            CandidateCorrelationOutcome::Ambiguous
        } else {
            CandidateCorrelationOutcome::Unique(first.clone())
        }
    }
}

fn optional_port_matches(flow: Option<u16>, dns: Option<u16>) -> bool {
    match (flow, dns) {
        (Some(flow), Some(dns)) => flow == dns,
        _ => true,
    }
}
