/**
 * Incidents, System, Host and Replay views.
 *
 * These exist to verify the backend end to end: every REST surface the design
 * spec names has a screen that reads it, so a broken route is visible rather
 * than theoretical.
 */

import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { fmt } from "../lib/format";
import { sevKey } from "../components/EvidencePanel";
import type {
  Alert,
  Capture,
  ConstraintProof,
  Health,
  Incident,
  ReplayStatus,
  Throughput,
} from "../lib/types";

/* --------------------------------------------------------------- incidents */

export function IncidentsView({
  incidents,
  onAlert,
  onHost,
}: {
  incidents: Incident[];
  onAlert: (id: string) => void;
  onHost: (ip: string) => void;
}) {
  if (incidents.length === 0) {
    return <div className="empty">No correlated incidents yet.</div>;
  }
  return (
    <div className="panel-body pad">
      {incidents.map((i) => (
        <div
          key={i.incident_id}
          style={{
            border: "1px solid var(--rule)",
            borderLeft: `2px solid var(--sev-${sevKey(i.severity)})`,
            padding: 14,
            marginBottom: 12,
          }}
        >
          <div className="ev-head">
            <span>
              <button className="ip" onClick={() => onHost(i.pivot_host)}>
                {i.pivot_host}
              </button>
              <span className="note"> · {i.incident_id}</span>
            </span>
            <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
              {i.escalated && <span className="badge">escalated</span>}
              <span
                className="sev-label"
                style={{ ["--sev" as string]: `var(--sev-${sevKey(i.severity)})` }}
              >
                {i.severity}
              </span>
            </span>
          </div>

          {/* The kill-chain ribbon: these findings are one story, and the
              sequence is itself evidence (spec 6.1). */}
          <div style={{ display: "flex", marginTop: 14, marginBottom: 6 }}>
            {i.members.map((m, idx) => (
              <div key={m.alert_id} style={{ flex: 1, position: "relative" }}>
                {idx > 0 && (
                  <div
                    style={{
                      position: "absolute",
                      top: 4,
                      left: "-50%",
                      width: "100%",
                      height: 1,
                      background: "var(--rule-bright)",
                    }}
                  />
                )}
                <button
                  onClick={() => onAlert(m.alert_id)}
                  title={`${m.threat_class} · ${m.stage}`}
                  style={{
                    position: "relative",
                    width: 9,
                    height: 9,
                    padding: 0,
                    borderRadius: "50%",
                    border: "none",
                    background: `var(--sev-${sevKey(m.severity)})`,
                  }}
                />
                <div className="data-sm" style={{ marginTop: 6 }}>
                  {m.threat_code}
                </div>
                <div className="data-sm" style={{ color: "var(--text-3)" }}>
                  {fmt.clock(m.ts)}
                </div>
                <div className="data-sm" style={{ color: "var(--text-3)" }}>
                  conf {m.confidence.toFixed(2)}
                  {m.occurrences > 1 && ` ×${m.occurrences}`}
                </div>
              </div>
            ))}
          </div>

          <div className="note" style={{ marginTop: 10 }}>
            {i.narrative}
          </div>
          <div className="data-sm" style={{ color: "var(--text-3)", marginTop: 4 }}>
            {i.alert_count} alerts · {fmt.duration(i.elapsed_sec)} elapsed ·
            stages {(i.stages ?? []).join(" → ")}
            {i.members_truncated && " · ribbon truncated"}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ system */

export function SystemView() {
  const [health, setHealth] = useState<Health | null>(null);
  const [tp, setTp] = useState<Throughput | null>(null);
  const [con, setCon] = useState<ConstraintProof | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [h, t, c] = await Promise.all([
          api.health(),
          api.throughput(),
          api.constraints(),
        ]);
        if (!alive) return;
        setHealth(h);
        setTp(t);
        setCon(c);
        setErr(null);
      } catch (e) {
        if (alive) setErr(String(e));
      }
    };
    load();
    const id = setInterval(load, 2000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  if (err) return <div className="empty bad">{err}</div>;
  if (!health || !tp || !con) return <div className="empty">Reading system state.</div>;

  const peak = Math.max(1, ...tp.latency_histogram.map((b) => b.count));

  return (
    <div className="panel-body">
      <div className="cols">
        <div>
          <div className="label">Throughput — measured by this service</div>
          <div className="readout-lg" style={{ margin: "10px 0" }}>
            {tp.alerts_per_sec.toFixed(1)}
            <span className="label" style={{ marginLeft: 8 }}>
              alerts/sec
            </span>
          </div>
          <dl className="kv data-sm">
            <dt>peak (1s bucket)</dt>
            <dd>{tp.alerts_peak_per_sec.toFixed(1)}/s</dd>
            <dt>total ingested</dt>
            <dd>{tp.alerts_total.toLocaleString()}</dd>
            <dt>deduplicated</dt>
            <dd>{tp.alerts_deduplicated.toLocaleString()}</dd>
            <dt>rejected (bad schema)</dt>
            <dd>{tp.alerts_rejected.toLocaleString()}</dd>
          </dl>

          <div className="label" style={{ marginTop: 16 }}>
            Traffic — reported by the ingestion layer
          </div>
          {tp.traffic_telemetry_live ? (
            <dl className="kv data-sm" style={{ marginTop: 6 }}>
              <dt>flows/sec</dt>
              <dd>{tp.traffic_flows_per_sec.toLocaleString()}</dd>
              <dt>packets/sec</dt>
              <dd>{tp.traffic_packets_per_sec.toLocaleString()}</dd>
              <dt>Mb/s</dt>
              <dd>{tp.traffic_mbps.toFixed(1)}</dd>
              <dt>source</dt>
              <dd>{tp.traffic_source}</dd>
            </dl>
          ) : (
            // The backend never sees a packet, so it reports these as
            // unavailable rather than as a confident zero.
            <div className="note" style={{ marginTop: 6 }}>
              No traffic telemetry received. The backend observes alerts, not
              packets — flow and bit rates are reported by the ingestion layer
              via POST /api/v1/telemetry.
            </div>
          )}
        </div>

        <div>
          <div className="label">Packet-to-alert latency</div>
          <div className="readout-lg" style={{ margin: "10px 0" }}>
            {tp.latency_p95_ms.toFixed(1)}
            <span className="label" style={{ marginLeft: 8 }}>
              ms p95
            </span>
          </div>
          <dl className="kv data-sm">
            <dt>p50</dt>
            <dd>{tp.latency_p50_ms.toFixed(1)} ms</dd>
            <dt>max</dt>
            <dd>{tp.latency_max_ms.toFixed(1)} ms</dd>
          </dl>
          <div
            style={{
              display: "flex",
              alignItems: "flex-end",
              gap: 1,
              height: 60,
              marginTop: 10,
            }}
          >
            {tp.latency_histogram.map((b, i) => (
              <div
                key={i}
                title={`${b.bin_start.toFixed(1)}–${b.bin_end.toFixed(1)} ms: ${b.count}`}
                style={{
                  flex: 1,
                  height: `${(b.count / peak) * 100}%`,
                  background: "var(--text-2)",
                  minHeight: b.count ? 2 : 0,
                }}
              />
            ))}
          </div>
          <div className="note" style={{ marginTop: 8 }}>
            {tp.latency_definition}
          </div>
        </div>
      </div>

      <div className="section">
        <div className="label" style={{ marginBottom: 8 }}>
          Detector status
        </div>
        <table className="grid">
          <thead>
            <tr>
              <th>Detector</th>
              <th>Version</th>
              <th>State</th>
              <th>Alerts</th>
              <th>Mean detect latency</th>
              <th>Classes</th>
            </tr>
          </thead>
          <tbody>
            {health.detectors.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ color: "var(--text-3)" }}>
                  No detector has posted yet.
                </td>
              </tr>
            ) : (
              health.detectors.map((d) => (
                <tr key={d.detector}>
                  <td>{d.detector}</td>
                  <td>{d.detector_version}</td>
                  {/* Degraded detectors show as degraded rather than
                      disappearing (spec 6.2). */}
                  <td className={d.state === "online" ? "ok" : "warn"}>
                    {d.state}
                  </td>
                  <td>{d.alerts_produced.toLocaleString()}</td>
                  <td>{d.mean_detector_latency_ms.toFixed(1)} ms</td>
                  <td style={{ color: "var(--text-2)" }}>
                    {d.threat_classes.join(", ")}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* The panel to point at during the demo (spec 6.2). */}
      <div className="section">
        <div className="label" style={{ marginBottom: 8 }}>
          Read-only constraint
        </div>
        <dl className="kv">
          <dt>ingest direction</dt>
          <dd className="ok">{con.ingest_direction}</dd>
          <dt>egress toward monitored network</dt>
          <dd className={con.egress_blocked ? "ok" : "bad"}>
            {con.egress_blocked ? "blocked" : `${con.outbound_attempts} attempts`}
          </dd>
          <dt>payload decryption</dt>
          <dd className="ok">{con.payload_decryption}</dd>
          <dt>routes toward network</dt>
          <dd className="ok">{con.write_routes_toward_network}</dd>
        </dl>
        <ul className="note" style={{ marginTop: 10, paddingLeft: 18 }}>
          {con.notes.map((n, i) => (
            <li key={i} style={{ marginBottom: 4 }}>
              {n}
            </li>
          ))}
        </ul>
      </div>

      <div className="section">
        <div className="label" style={{ marginBottom: 8 }}>
          Storage
        </div>
        <dl className="kv data-sm">
          <dt>backend</dt>
          <dd>{health.storage_backend}</dd>
          <dt>healthy</dt>
          <dd className={health.storage_healthy ? "ok" : "bad"}>
            {String(health.storage_healthy)}
          </dd>
          <dt>write queue depth</dt>
          <dd>{health.storage_queue_depth}</dd>
          <dt>writes shed</dt>
          <dd className={health.storage_writes_shed ? "warn" : ""}>
            {health.storage_writes_shed}
          </dd>
          <dt>write errors</dt>
          <dd className={health.storage_write_errors ? "bad" : ""}>
            {health.storage_write_errors}
          </dd>
          <dt>dedup keys tracked</dt>
          <dd>{health.dedup_keys_tracked.toLocaleString()}</dd>
          <dt>incidents tracked</dt>
          <dd>{health.incidents_tracked.toLocaleString()}</dd>
        </dl>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------- host */

export function HostView({
  ip,
  onAlert,
  onHost,
}: {
  ip: string | null;
  onAlert: (id: string) => void;
  onHost: (ip: string) => void;
}) {
  const [data, setData] = useState<any>(null);
  const [hosts, setHosts] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.hosts().then((h) => setHosts(h.items)).catch(() => setHosts([]));
  }, []);

  useEffect(() => {
    if (!ip) return;
    setErr(null);
    setData(null);
    api
      .host(ip)
      .then(setData)
      .catch((e) => setErr(String(e)));
  }, [ip]);

  return (
    <div className="panel-body pad">
      <div className="label">Hosts seen in alerts</div>
      <div className="chips" style={{ marginTop: 6, marginBottom: 16 }}>
        {hosts.slice(0, 40).map((h) => (
          <button
            key={h}
            className="chip mono"
            aria-pressed={h === ip}
            onClick={() => onHost(h)}
            style={{ textTransform: "none", letterSpacing: 0 }}
          >
            {h}
          </button>
        ))}
      </div>

      {!ip && <div className="note">Select a host, or click any IP address in the product.</div>}
      {err && <div className="empty">{err}</div>}
      {data && (
        <>
          <div className="readout" style={{ marginBottom: 10 }}>
            {data.ip}
          </div>
          <dl className="kv data-sm" style={{ marginBottom: 16 }}>
            <dt>alerts</dt>
            <dd>{data.alert_count}</dd>
            <dt>first seen</dt>
            <dd>{fmt.clock(data.first_seen)}</dd>
            <dt>last seen</dt>
            <dd>{fmt.clock(data.last_seen)}</dd>
            <dt>by severity</dt>
            <dd>
              {Object.entries(data.severity_counts as Record<string, number>)
                .map(([k, v]) => `${k} ${v}`)
                .join(" · ")}
            </dd>
            <dt>by class</dt>
            <dd>
              {Object.entries(data.threat_class_counts as Record<string, number>)
                .map(([k, v]) => `${k} ${v}`)
                .join(" · ")}
            </dd>
            <dt>incidents</dt>
            <dd>{(data.incidents as string[]).join(", ") || "—"}</dd>
            {(data.ja3_history as string[]).length > 0 && (
              <>
                <dt>JA3 history</dt>
                <dd style={{ wordBreak: "break-all" }}>
                  {(data.ja3_history as string[]).join(", ")}
                </dd>
              </>
            )}
          </dl>

          <div className="label" style={{ marginBottom: 6 }}>
            Peers
          </div>
          <div className="chips" style={{ marginBottom: 16 }}>
            {(data.peers as string[]).slice(0, 20).map((p) => (
              <button
                key={p}
                className="chip mono"
                onClick={() => onHost(p)}
                style={{ textTransform: "none", letterSpacing: 0 }}
              >
                {p}
              </button>
            ))}
          </div>

          <div className="label" style={{ marginBottom: 6 }}>
            Timeline
          </div>
          <table className="grid">
            <thead>
              <tr>
                <th>Time</th>
                <th>Class</th>
                <th>Severity</th>
                <th>Score</th>
                <th>Peer</th>
                <th>Detector</th>
              </tr>
            </thead>
            <tbody>
              {(data.alerts as Alert[]).slice(0, 60).map((a) => (
                <tr
                  key={a.alert_id}
                  onClick={() => onAlert(a.alert_id)}
                  style={{ cursor: "pointer" }}
                >
                  <td>{fmt.clock(a.ts)}</td>
                  <td>{a.threat_code}</td>
                  <td style={{ color: `var(--sev-${sevKey(a.severity)})` }}>
                    {a.severity}
                  </td>
                  <td>{a.confidence.toFixed(2)}</td>
                  <td>{(a.src_ip === data.ip ? a.dst_ip : a.src_ip) ?? "—"}</td>
                  <td style={{ color: "var(--text-2)" }}>{a.detector}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ replay */

export function ReplayView() {
  const [captures, setCaptures] = useState<Capture[]>([]);
  const [status, setStatus] = useState<ReplayStatus | null>(null);
  const [capture, setCapture] = useState("");
  const [speed, setSpeed] = useState(10);
  const [maxRate, setMaxRate] = useState<number | "">("");
  const [loop, setLoop] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const refresh = useCallback(() => {
    api.replayStatus().then(setStatus).catch(() => undefined);
  }, []);

  useEffect(() => {
    api
      .captures()
      .then((c) => {
        setCaptures(c.items);
        if (c.items.length && !capture) setCapture(c.items[0].capture);
      })
      .catch((e) => setErr(String(e)));
    refresh();
    const id = setInterval(refresh, 1000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refresh]);

  const selected = captures.find((c) => c.capture === capture);
  const truth = (selected?.scenario?.ground_truth ?? []) as Record<string, unknown>[];

  const start = async () => {
    setErr(null);
    try {
      setStatus(
        await api.replayStart(capture, speed, {
          maxRate: maxRate === "" ? undefined : maxRate,
          loop,
        })
      );
    } catch (e) {
      setErr(String(e));
    }
  };

  return (
    <div className="panel-body pad">
      <div className="label" style={{ marginBottom: 8 }}>
        Replay control
      </div>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <select value={capture} onChange={(e) => setCapture(e.target.value)}>
          {captures.map((c) => (
            <option key={c.capture} value={c.capture}>
              {c.capture} ({c.alerts} alerts)
            </option>
          ))}
        </select>
        <label className="data-sm" style={{ color: "var(--text-2)" }}>
          speed{" "}
          <input
            type="number"
            min={0.1}
            max={1000}
            step={1}
            value={speed}
            onChange={(e) => setSpeed(Number(e.target.value))}
            style={{ width: 72 }}
          />
          ×
        </label>
        <label className="data-sm" style={{ color: "var(--text-2)" }}>
          max rate{" "}
          <input
            type="number"
            min={1}
            placeholder="none"
            value={maxRate}
            onChange={(e) =>
              setMaxRate(e.target.value === "" ? "" : Number(e.target.value))
            }
            style={{ width: 80 }}
          />
          /s
        </label>
        <label className="data-sm" style={{ color: "var(--text-2)" }}>
          <input
            type="checkbox"
            checked={loop}
            onChange={(e) => setLoop(e.target.checked)}
            style={{ width: "auto", cursor: "pointer" }}
          />{" "}
          loop
        </label>
        <button onClick={start} disabled={!capture}>
          Start
        </button>
        <button onClick={() => api.replayStop().then(setStatus)}>Stop</button>
      </div>

      {err && (
        <div className="bad data-sm" style={{ marginTop: 10 }}>
          {err}
        </div>
      )}

      {status && (
        <dl className="kv data-sm" style={{ marginTop: 16 }}>
          <dt>state</dt>
          <dd className={status.running ? "ok" : ""}>
            {status.running ? "running" : "stopped"}
          </dd>
          <dt>capture</dt>
          <dd>{status.capture ?? "—"}</dd>
          <dt>position</dt>
          <dd>
            {status.position} / {status.total}
          </dd>
          <dt>emitted</dt>
          <dd>{status.emitted}</dd>
          <dt>rejected</dt>
          <dd className={status.rejected ? "warn" : ""}>{status.rejected}</dd>
          <dt>elapsed</dt>
          <dd>{status.elapsed_s.toFixed(1)}s</dd>
        </dl>
      )}

      {/* The scenario label: what this capture is known to contain, read from
          the ground-truth manifest (spec 6.4). */}
      {selected && (
        <div className="section" style={{ marginTop: 16, paddingLeft: 0 }}>
          <div className="label" style={{ marginBottom: 6 }}>
            Known contents of this capture
          </div>
          <div className="note" style={{ marginBottom: 8 }}>
            {String(selected.scenario?.description ?? "No manifest for this capture.")}
          </div>
          {truth.length > 0 && (
            <table className="grid">
              <thead>
                <tr>
                  <th>At</th>
                  <th>Threat class</th>
                  <th>Source</th>
                  <th>Destination</th>
                </tr>
              </thead>
              <tbody>
                {truth.map((g, i) => (
                  <tr key={i}>
                    <td>t+{String(g.at_s)}s</td>
                    <td>{String(g.threat_class)}</td>
                    <td>{String(g.src ?? "—")}</td>
                    <td>{String(g.dst ?? "—")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
