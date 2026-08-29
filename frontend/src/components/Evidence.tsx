/**
 * The evidence readout (Frontend spec section 5).
 *
 * "Evidence gets the larger pane because it is the graded requirement and the
 * thing that convinces."
 *
 * Two layers: a universal evidence-bar readout, then a class-specific visual.
 * An alert with no `visual` degrades to bars alone, which still answer the
 * supporting-evidence requirement on their own.
 */

import { useMemo } from "react";
import type { Alert, EvidenceItem, Visual } from "../lib/types";
import { fmt } from "../lib/format";

export function EvidenceBar({ item }: { item: EvidenceItem }) {
  // No threshold -> plain label/value pair, no bar. Spec 5.1 is explicit:
  // "Do not invent a scale to make them look uniform."
  if (item.threshold === null || item.scale === null) {
    return (
      <div className="ev-plain">
        <span className="label" style={{ textTransform: "none" }}>
          {item.label}
        </span>
        <span className="data">{fmt.value(item.value, item.unit)}</span>
      </div>
    );
  }

  const [lo, hi] = item.scale;
  const span = hi - lo || 1;
  const pct = (v: number) =>
    Math.max(0, Math.min(100, ((v - lo) / span) * 100));
  const observed = typeof item.value === "number" ? item.value : Number(item.value);
  const obsPct = pct(observed);
  const thrPct = pct(item.threshold);

  return (
    <div className="ev">
      <div className="ev-head">
        <span className="label" style={{ textTransform: "none" }}>
          {item.label}
        </span>
        <span className="data">{fmt.value(item.value, item.unit)}</span>
      </div>
      <div className="ev-track">
        <div className="ev-fill" style={{ width: `${obsPct}%` }} />
        <div className="ev-thresh" style={{ left: `${thrPct}%` }} />
        <div
          className={`ev-mark${item.exceeded ? " exceeded" : ""}`}
          style={{ left: `calc(${obsPct}% - 1px)` }}
        />
      </div>
      <div className="ev-scale data-sm">
        <span>{fmt.compact(lo)}</span>
        <span>
          threshold {fmt.compact(item.threshold)}{" "}
          {item.direction === "above" ? "↑" : "↓"}
        </span>
        <span>{fmt.compact(hi)}</span>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- visuals */

function Comb({ v }: { v: Visual }) {
  const stamps = (v.timestamps as number[]) ?? [];
  const start = (v.window_start as number) ?? stamps[0] ?? 0;
  const end = (v.window_end as number) ?? stamps.at(-1) ?? start + 1;
  const span = end - start || 1;
  const hist = (v.interval_histogram as { count: number }[]) ?? [];
  const peak = Math.max(1, ...hist.map((h) => h.count));

  return (
    <div>
      {/* A beacon renders as an evenly spaced comb; human-driven traffic
          renders as scattered clusters. No legend is required. */}
      <svg width="100%" height="46" style={{ display: "block" }}>
        {stamps.map((t, i) => (
          <line
            key={i}
            x1={`${((t - start) / span) * 100}%`}
            x2={`${((t - start) / span) * 100}%`}
            y1={6}
            y2={32}
            stroke="var(--sev)"
            strokeWidth={1.5}
          />
        ))}
        <line
          x1="0"
          x2="100%"
          y1={33}
          y2={33}
          stroke="var(--rule-bright)"
          strokeWidth={1}
        />
      </svg>
      <div className="data-sm" style={{ color: "var(--text-3)" }}>
        {stamps.length} connections over {fmt.duration(span)}
      </div>

      {hist.length > 1 && (
        <>
          <div className="label" style={{ marginTop: 12 }}>
            Interval distribution
          </div>
          {/* A beacon's intervals pile into one narrow bin; the tightness of
              that pile is the detection. */}
          <div
            style={{
              display: "flex",
              alignItems: "flex-end",
              gap: 1,
              height: 40,
              marginTop: 4,
            }}
          >
            {hist.map((h, i) => (
              <div
                key={i}
                title={`${h.count}`}
                style={{
                  flex: 1,
                  height: `${(h.count / peak) * 100}%`,
                  background: h.count ? "var(--text-2)" : "transparent",
                  minHeight: h.count ? 2 : 0,
                }}
              />
            ))}
          </div>
        </>
      )}
      <div className="kv data-sm" style={{ marginTop: 10 }}>
        <dt>jitter</dt>
        <dd>{fmt.value(v.jitter_pct as number, "%")}</dd>
        <dt>mean interval</dt>
        <dd>{fmt.value(v.mean_interval_sec as number, "s")}</dd>
      </div>
    </div>
  );
}

function FanoutMatrix({ v }: { v: Visual }) {
  const ports = (v.cell_ports as number[]) ?? [];
  const offsets = (v.cell_offsets as number[]) ?? [];
  const rejected = (v.cell_rejected as boolean[]) ?? [];
  const maxPort = Math.max(1, ...ports);
  const maxT = Math.max(1e-6, ...offsets);

  return (
    <div>
      {/* Destination port horizontal, time vertical. A vertical scan fills a
          dense vertical band; a horizontal sweep fills across. */}
      <svg width="100%" height="120" style={{ display: "block" }}>
        {ports.map((p, i) => (
          <rect
            key={i}
            x={`${(p / maxPort) * 98}%`}
            y={(offsets[i] / maxT) * 110}
            width={3}
            height={3}
            // Cells that were refused or reset take the severity colour - a
            // wall of rejected connections is what makes a scan a scan.
            fill={rejected[i] ? "var(--sev)" : "var(--text-2)"}
          />
        ))}
      </svg>
      <div className="kv data-sm" style={{ marginTop: 8 }}>
        <dt>pattern</dt>
        <dd>{String(v.pattern ?? "unknown")}</dd>
        <dt>distinct ports</dt>
        <dd>{fmt.value(v.unique_dst_ports as number)}</dd>
        <dt>distinct hosts</dt>
        <dd>{fmt.value(v.unique_dst_ips as number)}</dd>
        <dt>cells shown</dt>
        <dd>
          {String(v.cells_sampled ?? 0)} sampled of {String(v.cells_total ?? 0)}
        </dd>
      </div>
    </div>
  );
}

function RateEntropy({ v }: { v: Visual }) {
  const rate = (v.rate_series as number[]) ?? [];
  const entropy = (v.entropy_series as number[]) ?? [];
  const band = (v.baseline_band as number[]) ?? [];
  const rPeak = Math.max(1, ...rate);
  const ePeak = Math.max(1, ...entropy);

  const path = (series: number[], peak: number, h: number) =>
    series
      .map(
        (val, i) =>
          `${i === 0 ? "M" : "L"} ${(i / Math.max(series.length - 1, 1)) * 100} ${
            h - (val / peak) * h
          }`
      )
      .join(" ");

  return (
    <div>
      <div className="label">
        Packet rate / source-IP entropy &mdash; {String(v.signature)}
      </div>
      {rate.length > 1 && (
        <svg
          width="100%"
          height="52"
          viewBox="0 0 100 52"
          preserveAspectRatio="none"
          style={{ display: "block", marginTop: 4 }}
        >
          <path d={path(rate, rPeak, 50)} stroke="var(--text-2)" fill="none" strokeWidth={0.8} />
        </svg>
      )}
      {entropy.length > 1 && (
        <svg
          width="100%"
          height="52"
          viewBox="0 0 100 52"
          preserveAspectRatio="none"
          style={{ display: "block", marginTop: 2 }}
        >
          {/* The learned-normal band, in --baseline. Never an alert colour. */}
          {band.length === 2 && (
            <rect
              x="0"
              y={50 - (band[1] / ePeak) * 50}
              width="100"
              height={Math.max(1, ((band[1] - band[0]) / ePeak) * 50)}
              fill="var(--baseline)"
              opacity={0.28}
            />
          )}
          <path d={path(entropy, ePeak, 50)} stroke="var(--sev)" fill="none" strokeWidth={0.8} />
        </svg>
      )}
      <div className="kv data-sm" style={{ marginTop: 8 }}>
        <dt>flows/sec</dt>
        <dd>{fmt.value(v.flows_per_sec as number)}</dd>
        <dt>source entropy</dt>
        <dd>{fmt.value(v.source_ip_entropy as number, "bits")}</dd>
        <dt>unique sources</dt>
        <dd>{fmt.value(v.unique_sources as number)}</dd>
        {v.amplification_factor != null && (
          <>
            <dt>amplification</dt>
            <dd>
              {fmt.value(v.amplification_factor as number, "x")} via port{" "}
              {String(v.reflector_port ?? "-")}
            </dd>
          </>
        )}
      </div>
    </div>
  );
}

function StringInspector({ v }: { v: Visual }) {
  const chars = (v.characters as string[]) ?? [];
  const heat = (v.ngram_heat as number[]) ?? [];
  const nx = (v.nxdomain_series as number[]) ?? [];
  const nxPeak = Math.max(1, ...nx);

  return (
    <div>
      {/* N-gram improbability drawn as a band behind each character span:
          the suspicious region of the string is visible directly. */}
      <div style={{ display: "flex", gap: 1, marginBottom: 6 }}>
        {chars.map((ch, i) => (
          <div
            key={i}
            style={{
              flex: "0 0 auto",
              padding: "6px 3px",
              textAlign: "center",
              minWidth: 15,
              background: `rgba(200, 69, 61, ${(heat[i] ?? 0) * 0.55})`,
              fontFamily: "var(--mono)",
              fontSize: 15,
            }}
          >
            {ch}
          </div>
        ))}
      </div>
      <div className="kv data-sm">
        <dt>model score</dt>
        <dd>{fmt.value(v.model_score as number)}</dd>
        <dt>n-gram score</dt>
        <dd>{fmt.value(v.ngram_score as number)}</dd>
        <dt>entropy</dt>
        <dd>{fmt.value(v.query_entropy as number, "bits/char")}</dd>
      </div>
      {nx.length > 1 && (
        <>
          <div className="label" style={{ marginTop: 12 }}>
            NXDOMAIN responses from this host
          </div>
          {/* The behavioural half of the detection, on the same screen as the
              string half. A burst of failed resolutions is the other signal. */}
          <div
            style={{ display: "flex", alignItems: "flex-end", gap: 2, height: 32 }}
          >
            {nx.map((n, i) => (
              <div
                key={i}
                style={{
                  flex: 1,
                  height: `${(n / nxPeak) * 100}%`,
                  background: "var(--sev)",
                  minHeight: 1,
                }}
              />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function SubdomainFanout({ v }: { v: Visual }) {
  const subs = (v.subdomains as string[]) ?? [];
  const dist = (v.query_length_distribution as { bin_start: number; count: number }[]) ?? [];
  const peak = Math.max(1, ...dist.map((d) => d.count));

  return (
    <div>
      <div className="ev-head">
        <span className="label">{String(v.parent_domain ?? "parent domain")}</span>
        <span className="readout">{fmt.value(v.cardinality as number)}</span>
      </div>
      <div className="note">distinct subdomains under one parent</div>
      <div
        className="data-sm"
        style={{
          maxHeight: 92,
          overflowY: "auto",
          marginTop: 8,
          border: "1px solid var(--rule)",
          padding: 6,
          color: "var(--text-2)",
        }}
      >
        {subs.slice(0, 60).map((s, i) => (
          <div key={i} style={{ overflow: "hidden", textOverflow: "ellipsis" }}>
            {s}
          </div>
        ))}
      </div>
      {dist.length > 0 && (
        <>
          <div className="label" style={{ marginTop: 10 }}>
            Query-length distribution
          </div>
          <div style={{ display: "flex", alignItems: "flex-end", gap: 2, height: 30 }}>
            {dist.map((d, i) => (
              <div
                key={i}
                title={`${d.bin_start}+ chars: ${d.count}`}
                style={{
                  flex: 1,
                  height: `${(d.count / peak) * 100}%`,
                  background: "var(--text-2)",
                  minHeight: 1,
                }}
              />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function FingerprintRarity({ v }: { v: Visual }) {
  const hist = (v.baseline_histogram as number[]) ?? [];
  const peak = Math.max(1, ...hist);
  const history = (v.host_history as string[]) ?? [];

  return (
    <div>
      <div className="label">Baseline JA3 frequency (log), rarest at right</div>
      <div
        style={{
          display: "flex",
          alignItems: "flex-end",
          gap: 2,
          height: 54,
          marginTop: 4,
        }}
      >
        {hist.map((n, i) => (
          <div
            key={i}
            style={{
              flex: 1,
              height: `${(Math.log10(n + 1) / Math.log10(peak + 1)) * 100}%`,
              background: "var(--text-2)",
              minHeight: 1,
            }}
          />
        ))}
        {/* This connection's fingerprint, marked far out in the tail. The
            point - this client looks like almost nothing else on the network -
            needs no caption. */}
        <div style={{ flex: 1, height: "100%", background: "var(--sev)", minHeight: 2 }} />
      </div>
      <div className="kv data-sm" style={{ marginTop: 10 }}>
        <dt>fingerprint</dt>
        <dd style={{ wordBreak: "break-all" }}>{String(v.fingerprint)}</dd>
        <dt>seen in baseline</dt>
        <dd>{fmt.value(v.frequency as number)} times</dd>
        <dt>rarity</dt>
        <dd>{fmt.value(v.rarity as number)}</dd>
        {v.matched_family != null && (
          <>
            <dt>matched family</dt>
            <dd>{String(v.matched_family)}</dd>
          </>
        )}
        {v.sni != null && (
          <>
            <dt>SNI</dt>
            <dd>{String(v.sni)}</dd>
          </>
        )}
      </div>
      {history.length > 0 && (
        <>
          <div className="label" style={{ marginTop: 10 }}>
            Fingerprints this host has presented
          </div>
          <div className="data-sm" style={{ color: "var(--text-2)" }}>
            {history.map((h, i) => (
              <div key={i} style={{ wordBreak: "break-all" }}>
                {h === v.fingerprint ? "▸ " : "  "}
                {h}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function BaselineDeparture({ v }: { v: Visual }) {
  const series = (v.outbound_series as number[]) ?? [];
  const band = (v.baseline_band as number[]) ?? [];
  const peak = Math.max(1, ...series);

  return (
    <div>
      <div className="label">Outbound volume against learned baseline</div>
      <svg width="100%" height="60" viewBox="0 0 100 60" preserveAspectRatio="none"
           style={{ display: "block", marginTop: 4 }}>
        {band.length === 2 && (
          <rect
            x="0"
            y={58 - (band[1] / peak) * 58}
            width="100"
            height={Math.max(1, ((band[1] - band[0]) / peak) * 58)}
            fill="var(--baseline)"
            opacity={0.3}
          />
        )}
        {series.map((val, i) => (
          <rect
            key={i}
            x={(i / series.length) * 100}
            y={58 - (val / peak) * 58}
            width={100 / series.length - 0.2}
            height={(val / peak) * 58}
            fill={
              band.length === 2 && val > band[1] ? "var(--sev)" : "var(--text-2)"
            }
          />
        ))}
      </svg>
      <div className="kv data-sm" style={{ marginTop: 8 }}>
        <dt>outbound</dt>
        <dd>{fmt.bytes(v.outbound_bytes as number)}</dd>
        <dt>inbound</dt>
        <dd>{fmt.bytes(v.inbound_bytes as number)}</dd>
        <dt>out/in ratio</dt>
        <dd>{fmt.value(v.out_in_byte_ratio as number, "x")}</dd>
        {/* Destination novelty deserves prominence: volume alone produces false
            positives on backups; volume to somewhere never seen before is the
            real signal. */}
        <dt>destination</dt>
        <dd className={v.destination_novel ? "bad" : ""}>
          {String(v.destination ?? "-")}{" "}
          {v.destination_novel === true
            ? "— never contacted before"
            : v.destination_novel === false
              ? "— previously seen"
              : ""}
        </dd>
      </div>
    </div>
  );
}

const VISUALS: Record<string, (p: { v: Visual }) => JSX.Element> = {
  beacon_comb: Comb,
  fanout_matrix: FanoutMatrix,
  rate_entropy: RateEntropy,
  string_inspector: StringInspector,
  subdomain_fanout: SubdomainFanout,
  fingerprint_rarity: FingerprintRarity,
  baseline_departure: BaselineDeparture,
};

export function ClassVisual({ visual }: { visual: Visual }) {
  const Component = VISUALS[visual.kind];
  // An unknown kind falls back to evidence bars alone, so a new detector never
  // breaks the interface (spec 7).
  if (!Component) return null;
  const reconstructed = visual.source !== "observed";
  return (
    <div className="section">
      <div className="ev-head">
        <span className="label">Detector logic</span>
        {reconstructed && (
          // The backend flags visuals it rebuilt from summary statistics rather
          // than from an observed series. Showing that distinction is the whole
          // reason the flag exists.
          <span className="badge" title="Rebuilt from the reported summary statistics, not from an observed series">
            reconstructed
          </span>
        )}
      </div>
      <Component v={visual} />
    </div>
  );
}

export function EvidencePanel({
  alert,
  onHost,
}: {
  alert: Alert | null;
  onHost: (ip: string) => void;
}) {
  const bars = useMemo(() => alert?.evidence ?? [], [alert]);

  if (!alert) {
    return (
      <div className="panel">
        <div className="panel-head">
          <span className="heading">Evidence</span>
        </div>
        <div className="empty">Select an alert to see why it fired.</div>
      </div>
    );
  }

  return (
    <div className="panel" style={{ ["--sev" as string]: `var(--sev-${sevKey(alert.severity)})` }}>
      <div className="panel-head">
        <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span className="code">{alert.threat_code}</span>
          <span className="heading">{alert.threat_label}</span>
        </span>
        <span className="sev-label">{alert.severity}</span>
      </div>

      <div className="panel-body">
        <div className="section">
          <div className="ev-head">
            <span className="data">
              {alert.src_ip ? (
                <button className="ip" onClick={() => onHost(alert.src_ip!)}>
                  {alert.src_ip}
                </button>
              ) : (
                <span style={{ color: "var(--text-3)" }}>&mdash;</span>
              )}
              {" → "}
              {alert.dst_ip ? (
                <button className="ip" onClick={() => onHost(alert.dst_ip!)}>
                  {alert.dst_ip}
                </button>
              ) : (
                <span style={{ color: "var(--text-3)" }}>&mdash;</span>
              )}
              {alert.dst_port !== null && `:${alert.dst_port}`}
            </span>
            <span className="data-sm" style={{ color: "var(--text-2)" }}>
              {alert.protocol?.toUpperCase() ?? "—"}
            </span>
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              marginTop: 10,
            }}
          >
            <span className="label">Threat score</span>
            <span className="readout">{(alert.confidence * 100).toFixed(0)}%</span>
            <span className="conf-track">
              <span
                className="conf-fill"
                style={{ width: `${alert.confidence * 100}%` }}
              />
            </span>
            {/* Severity is colour; confidence is a number plus a bar. They are
                different quantities and never share an encoding (spec 2.2). */}
            <span className="badge">{scoreBadge(alert.score_type)}</span>
            {alert.occurrences > 1 && (
              <span className="badge">&times;{alert.occurrences}</span>
            )}
          </div>

          <div className="data-sm" style={{ color: "var(--text-3)", marginTop: 8 }}>
            {fmt.clock(alert.event_start)} &rarr; {fmt.clock(alert.event_end)}
            {alert.occurrences > 1 && ` · first seen ${fmt.clock(alert.first_seen)}`}
          </div>
        </div>

        <div className="section">
          <div className="label" style={{ marginBottom: 10 }}>
            Why this fired
          </div>
          {bars.length === 0 ? (
            <div className="note">No evidence features supplied.</div>
          ) : (
            bars.map((item) => <EvidenceBar key={item.feature} item={item} />)
          )}
        </div>

        {alert.visual && <ClassVisual visual={alert.visual} />}

        <div className="section">
          <div className="label" style={{ marginBottom: 8 }}>
            Provenance
          </div>
          <dl className="kv data-sm">
            <dt>detector</dt>
            <dd>
              {alert.detector} v{alert.detector_version}
            </dd>
            <dt>score type</dt>
            <dd>{alert.score_type}</dd>
            <dt>scope</dt>
            <dd>{alert.event_scope}</dd>
            <dt>kill-chain stage</dt>
            <dd>{alert.kill_chain_stage}</dd>
            <dt>MITRE</dt>
            <dd>{alert.mitre_techniques.join(", ") || "—"}</dd>
            <dt>flow id</dt>
            <dd style={{ wordBreak: "break-all" }}>{alert.flow_id ?? "—"}</dd>
            <dt>incident</dt>
            <dd>{alert.incident_id ?? "—"}</dd>
            <dt>detect latency</dt>
            <dd>{alert.detector_latency_ms.toFixed(1)} ms</dd>
            <dt>packet&rarr;alert</dt>
            <dd>{alert.pipeline_latency_ms.toFixed(1)} ms</dd>
          </dl>
        </div>

        <details className="section">
          <summary className="label" style={{ cursor: "pointer" }}>
            Raw v1.1 alert
          </summary>
          <pre
            className="data-sm"
            style={{
              marginTop: 8,
              color: "var(--text-2)",
              overflowX: "auto",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}
          >
            {JSON.stringify(alert.raw, null, 2)}
          </pre>
        </details>
      </div>
    </div>
  );
}

export function sevKey(s: string): string {
  return s === "critical" ? "crit" : s === "medium" ? "med" : s;
}

function scoreBadge(t: string): string {
  return t === "calibrated_model"
    ? "model"
    : t === "rule_score"
      ? "rule"
      : t === "anomaly_score"
        ? "anomaly"
        : "signature";
}
