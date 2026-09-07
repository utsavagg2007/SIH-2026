/**
 * Single-host investigation (DESIGN.md §8.3).
 *
 * Reached by clicking any IP anywhere in the product. Everything on screen now
 * comes from `GET /api/v1/hosts/{ip}` — severity and class distributions, the
 * alert timeline, observed peers, JA3 history, and the incidents the host
 * appears in.
 *
 * What it replaces was entirely invented: a `Math.random()` baseline curve, a
 * "current" trace derived from it by multiplication, and a destination list of
 * fabricated addresses with a coin-flip "never seen" badge. None of it was
 * observed, and the novelty badge in particular asserted a detector-side
 * judgement nobody had made. The backend reports the peers it saw and does not
 * guess which are new; this screen now says the same thing.
 */
import { useEffect, useState } from "react";
import { T, SEV, SEV_ORDER, CLASS_META, MONO, SANS, microStyle } from "../lib/tokens";
import { fmtEndpoints, fmtTime, fmt } from "../lib/format";
import { api } from "../lib/api";
import type { Alert, HostView as HostViewModel, Incident, Severity } from "../lib/types";

function Card({ title, note, children }: { title: string; note?: string; children: React.ReactNode }) {
  return (
    <div style={{ border: `1px solid ${T.rule}`, background: T.panel, marginBottom: 12 }}>
      <div className="panel-head" style={{ background: "transparent", borderBottom: `1px solid ${T.rule}` }}>
        <span className="panel-title">{title}</span>
        {note && <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, marginLeft: "auto" }}>{note}</span>}
      </div>
      <div style={{ padding: 16 }}>{children}</div>
    </div>
  );
}

/** Severity mix as a single proportional strip. Counts are exact and printed;
 *  the strip only makes the shape readable at a glance. */
function SeverityStrip({ counts }: { counts: Record<string, number> }) {
  const total = SEV_ORDER.reduce((n, k) => n + (counts[k] ?? 0), 0);
  if (!total) return <span style={{ fontFamily: SANS, fontSize: 12, color: T.text3 }}>No alerts recorded.</span>;
  return (
    <div>
      <div style={{ display: "flex", height: 8, background: T.rule, marginBottom: 8 }}>
        {SEV_ORDER.map((k) => {
          const n = counts[k] ?? 0;
          if (!n) return null;
          return <div key={k} style={{ width: `${(n / total) * 100}%`, background: SEV[k].color }} title={`${n} ${k}`} />;
        })}
      </div>
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        {SEV_ORDER.map((k) => (
          <div key={k} style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
            <span style={{ width: 8, height: 8, background: SEV[k].color, display: "inline-block" }} />
            <span style={{ fontFamily: MONO, fontSize: 13, color: T.text }}>{counts[k] ?? 0}</span>
            <span style={microStyle}>{SEV[k].short}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * What the Host view shows before an address has been chosen.
 *
 * `GET /api/v1/hosts` is the list of every machine that appears in a stored
 * alert, so the view opens onto something usable instead of a sentence telling
 * the operator to go and click an IP somewhere else.
 */
function HostPicker({ onOpenHost }: { onOpenHost: (ip: string) => void }) {
  const [hosts, setHosts] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .hosts()
      .then((r) => {
        if (!cancelled) setHosts(r.items);
      })
      .catch((e) => {
        if (!cancelled) {
          setHosts([]);
          setError(String((e as Error)?.message ?? e));
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: T.bg }}>
      <div className="panel-head">
        <span className="panel-title">Host</span>
        <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, marginLeft: "auto" }}>
          {hosts ? `${hosts.length} seen in stored alerts` : ""}
        </span>
      </div>
      <div className="launcher-clearance" style={{ flex: 1, overflowY: "auto", padding: 16 }}>
        <div style={{ fontFamily: SANS, fontSize: 13, color: T.text3, marginBottom: 14 }}>
          Every IP address in the interface opens its host view. These are the machines that appear in a stored alert.
        </div>
        {error && (
          <div style={{ fontFamily: SANS, fontSize: 12, color: T.text2, marginBottom: 12 }}>
            Host list unavailable (<span style={{ fontFamily: MONO, color: T.text3 }}>{error}</span>).
          </div>
        )}
        {hosts === null && <div style={{ fontFamily: SANS, fontSize: 12, color: T.text3 }}>Reading host list…</div>}
        {hosts?.length === 0 && !error && (
          <div style={{ fontFamily: SANS, fontSize: 12, color: T.text3 }}>No hosts recorded yet.</div>
        )}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 1, background: T.rule, border: `1px solid ${T.rule}` }}>
          {hosts?.map((ip) => (
            <button
              key={ip}
              className="pick-row"
              onClick={() => onOpenHost(ip)}
              style={{ background: T.panel, padding: "8px 12px", fontFamily: MONO, fontSize: 13, color: T.text }}
            >
              {ip}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

interface Props {
  host: string | null;
  /** Live alerts, used only while the REST view is loading so the screen is
   *  never blank on a host that is currently firing. */
  alerts: Alert[];
  incidents: Incident[];
  onSelectAlert: (id: string) => void;
  onOpenHost: (ip: string) => void;
}

export function HostView({ host, alerts, incidents, onSelectAlert, onOpenHost }: Props) {
  const [view, setView] = useState<HostViewModel | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!host) {
      setView(null);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .host(host)
      .then((v) => {
        if (!cancelled) setView(v);
      })
      .catch((e) => {
        if (!cancelled) {
          setView(null);
          setError(String(e?.message ?? e));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [host]);

  if (!host) return <HostPicker onOpenHost={onOpenHost} />;

  // Fall back to the live ring buffer while the fetch is in flight, so a host
  // that is firing right now is never shown as empty.
  const timeline = view?.alerts ?? alerts.filter((a) => a.src_ip === host || a.dst_ip === host);
  const hostIncidents = view
    ? incidents.filter((i) => view.incidents.includes(i.incident_id))
    : incidents.filter((i) => i.pivot_host === host);

  const severityCounts: Record<string, number> =
    view?.severity_counts ??
    timeline.reduce<Record<string, number>>((acc, a) => {
      acc[a.severity] = (acc[a.severity] ?? 0) + 1;
      return acc;
    }, {});

  const classCounts: Record<string, number> =
    view?.threat_class_counts ??
    timeline.reduce<Record<string, number>>((acc, a) => {
      acc[a.threat_class] = (acc[a.threat_class] ?? 0) + 1;
      return acc;
    }, {});
  const classMax = Math.max(1, ...Object.values(classCounts));

  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: T.bg }}>
      <div className="panel-head">
        <span className="panel-title">Host</span>
        <span style={{ fontFamily: MONO, fontSize: 15, color: T.text }}>{host}</span>
        {view && (
          <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, marginLeft: "auto" }}>
            {view.alert_count.toLocaleString()} alerts · first {fmtTime(view.first_seen)} · last {fmtTime(view.last_seen)}
          </span>
        )}
      </div>

      <div className="launcher-clearance" style={{ flex: 1, overflowY: "auto", padding: 16 }}>
        {error && (
          <div style={{ fontFamily: SANS, fontSize: 12, color: T.text2, marginBottom: 12 }}>
            Host record unavailable (<span style={{ fontFamily: MONO, color: T.text3 }}>{error}</span>). Showing what the live
            feed holds for this address.
          </div>
        )}
        {loading && !view && (
          <div style={{ fontFamily: SANS, fontSize: 12, color: T.text3, marginBottom: 12 }}>Reading host record…</div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <Card title="Severity mix">
            <SeverityStrip counts={severityCounts} />
          </Card>

          <Card title="Threat classes">
            {Object.keys(classCounts).length === 0 ? (
              <span style={{ fontFamily: SANS, fontSize: 12, color: T.text3 }}>No detections on this host.</span>
            ) : (
              Object.entries(classCounts)
                .sort(([, a], [, b]) => b - a)
                .map(([key, n]) => {
                  const meta = CLASS_META[key];
                  return (
                    <div key={key} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 0" }}>
                      <span style={{ fontFamily: MONO, fontSize: 10, color: T.text2, border: `1px solid ${T.ruleBright}`, padding: "1px 3px", width: 26, textAlign: "center" }}>
                        {meta?.code ?? "??"}
                      </span>
                      <span style={{ fontFamily: SANS, fontSize: 11, color: T.text2, width: 110 }}>{meta?.name ?? key}</span>
                      <div style={{ flex: 1, height: 5, background: T.rule }}>
                        <div style={{ height: 5, width: `${(n / classMax) * 100}%`, background: T.text2 }} />
                      </div>
                      <span style={{ fontFamily: MONO, fontSize: 12, color: T.text, width: 40, textAlign: "right" }}>{n}</span>
                    </div>
                  );
                })
            )}
          </Card>
        </div>

        <Card title="Timeline" note={`${timeline.length} shown`}>
          {timeline.length === 0 ? (
            <div style={{ fontFamily: SANS, fontSize: 13, color: T.text3 }}>No traffic on this interface.</div>
          ) : (
            timeline.slice(0, 40).map((a) => {
              const meta = CLASS_META[a.threat_class];
              const sev = SEV[a.severity as Severity];
              return (
                <button
                  key={a.alert_id}
                  className="pick-row"
                  onClick={() => onSelectAlert(a.alert_id)}
                  style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 4px", borderBottom: `1px solid ${T.rule}` }}
                >
                  <span style={{ width: 2, alignSelf: "stretch", background: sev.color }} />
                  <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, width: 96 }}>{fmtTime(a.ts)}</span>
                  <span style={{ fontFamily: MONO, fontSize: 10, color: T.text2, border: `1px solid ${T.ruleBright}`, padding: "1px 3px" }}>
                    {a.threat_code || meta?.code || "??"}
                  </span>
                  <span style={{ fontFamily: SANS, fontSize: 12, color: T.text2 }}>{meta?.name ?? a.threat_class}</span>
                  <span style={{ fontFamily: MONO, fontSize: 12, color: T.text, marginLeft: 8 }}>
                    {fmtEndpoints(a)}
                  </span>
                  <span style={{ fontFamily: SANS, fontSize: 9, fontWeight: 600, letterSpacing: "0.07em", color: sev.color, marginLeft: "auto" }}>
                    {sev.label}
                  </span>
                </button>
              );
            })
          )}
        </Card>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
          <Card title="Peers observed" note={view ? String(view.peers.length) : undefined}>
            {!view ? (
              <span style={{ fontFamily: SANS, fontSize: 12, color: T.text3 }}>Available from the host record.</span>
            ) : view.peers.length === 0 ? (
              <span style={{ fontFamily: SANS, fontSize: 12, color: T.text3 }}>No peers recorded.</span>
            ) : (
              <>
                {view.peers.slice(0, 12).map((p) => (
                  <div key={p} style={{ padding: "3px 0" }}>
                    <button className="ip" onClick={() => onOpenHost(p)} style={{ fontSize: 12, color: T.text2 }}>
                      {p}
                    </button>
                  </div>
                ))}
                {/* Novelty is a detector-side judgement. The backend reports the
                    peers it saw rather than guessing which are new, so this
                    screen does not badge any of them. */}
                <div style={{ fontFamily: SANS, fontSize: 10, color: T.text3, marginTop: 8, lineHeight: 1.4 }}>
                  Most recent first. Destination novelty is reported by the detector, not inferred here.
                </div>
              </>
            )}
          </Card>

          <Card title="JA3 history" note={view ? String(view.ja3_history.length) : undefined}>
            {!view || view.ja3_history.length === 0 ? (
              <span style={{ fontFamily: SANS, fontSize: 12, color: T.text3 }}>No fingerprints recorded.</span>
            ) : (
              view.ja3_history.slice(0, 12).map((h, i) => (
                <div key={`${h}-${i}`} style={{ fontFamily: MONO, fontSize: 11, color: T.text2, padding: "3px 0", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {h}
                </div>
              ))
            )}
          </Card>

          <Card title="Incidents" note={String(hostIncidents.length)}>
            {hostIncidents.length === 0 ? (
              <span style={{ fontFamily: SANS, fontSize: 12, color: T.text3 }}>None.</span>
            ) : (
              hostIncidents.map((inc) => (
                <div key={inc.incident_id} style={{ padding: "5px 0", borderBottom: `1px solid ${T.rule}` }}>
                  <div style={{ fontFamily: MONO, fontSize: 11, color: T.text3 }}>
                    {inc.incident_id} · {fmt.duration(inc.elapsed_sec)}
                  </div>
                  <div style={{ fontFamily: MONO, fontSize: 12, color: T.text2 }}>
                    {(inc.members ?? [])
                      .map((m) => m.threat_code || CLASS_META[m.threat_class]?.code || "??")
                      .join(" → ")}
                  </div>
                </div>
              ))
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
