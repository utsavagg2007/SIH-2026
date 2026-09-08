use std::collections::{HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::features::flow::FlowFeatures;
use crate::utils::entropy::shannon_entropy;
use crate::zeek_parser::types::FlowRecord;

/// Aggregated features over a sliding time window of flows.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WindowFeatures {
    pub flow_rate: f64,
    pub byte_rate: f64,
    pub inter_arrival_mean: f64,
    pub inter_arrival_stddev: f64,
    pub unique_dst_ports: u32,
    pub unique_dst_ips: u32,
    /// Shannon entropy of source IPs in the window (low => spoofed DDoS).
    pub src_ip_entropy: f64,
}

/// A sliding window accumulator keyed on flow timestamps.
pub struct SlidingWindow {
    window_size: f64,
    flows: VecDeque<FlowFeatures>,
    timestamps: VecDeque<f64>,
}

impl SlidingWindow {
    pub fn new(window_size: f64) -> Self {
        Self {
            window_size,
            flows: VecDeque::new(),
            timestamps: VecDeque::new(),
        }
    }

    pub fn add(&mut self, ts: f64, f: FlowFeatures) {
        self.flows.push_back(f);
        self.timestamps.push_back(ts);
        while let Some(&oldest) = self.timestamps.front() {
            if ts - oldest > self.window_size {
                self.flows.pop_front();
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn features(&self) -> WindowFeatures {
        let n = self.flows.len() as f64;
        if n == 0.0 {
            return WindowFeatures::default();
        }
        let span = self.timestamps.back().unwrap() - self.timestamps.front().unwrap();
        let total_bytes: u64 = self.flows.iter().map(|f| f.orig_bytes + f.resp_bytes).sum();
        let flow_rate = n / (span + 1e-6);
        let byte_rate = total_bytes as f64 / (span + 1e-6);

        let unique_dst_ports: u32 = self
            .flows
            .iter()
            .map(|f| f.dst_port)
            .collect::<HashSet<_>>()
            .len() as u32;
        let unique_dst_ips: u32 = self
            .flows
            .iter()
            .map(|f| f.dst_ip.clone())
            .collect::<HashSet<_>>()
            .len() as u32;

        let ts: Vec<f64> = self.timestamps.iter().copied().collect();
        let inter: Vec<f64> = ts.windows(2).map(|w| w[1] - w[0]).collect();
        let mean = if inter.is_empty() {
            0.0
        } else {
            inter.iter().sum::<f64>() / inter.len() as f64
        };
        let stddev = if inter.len() < 2 {
            0.0
        } else {
            let v =
                inter.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (inter.len() - 1) as f64;
            v.sqrt()
        };

        let src_ips: Vec<&str> = self.flows.iter().map(|f| f.src_ip.as_str()).collect();
        let src_ip_entropy = shannon_entropy(&src_ips);

        WindowFeatures {
            flow_rate,
            byte_rate,
            inter_arrival_mean: mean,
            inter_arrival_stddev: stddev,
            unique_dst_ports,
            unique_dst_ips,
            src_ip_entropy,
        }
    }
}

/// Compute one [`WindowFeatures`] per flow using a sliding window of
/// `window_size` seconds ending at each flow's timestamp.
pub fn sliding_window_features(records: &[FlowRecord], window_size: f64) -> Vec<WindowFeatures> {
    let mut sorted = records.to_vec();
    sorted.sort_by(|a, b| a.timestamp.partial_cmp(&b.timestamp).unwrap());

    let mut win = SlidingWindow::new(window_size);
    let mut out = Vec::with_capacity(sorted.len());
    for r in &sorted {
        let f = FlowFeatures::from_flow_record(r);
        win.add(r.timestamp, f);
        out.push(win.features());
    }
    out
}
