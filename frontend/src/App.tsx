/**
 * Application shell.
 *
 * Five views behind a persistent left rail, with the Wire fixed at the top and
 * the instrument bar fixed at the bottom (Frontend spec section 4). The app
 * opens directly into the live view - no sign-in, no onboarding (spec 1.1).
 *
 * Scope note: this is the verification console for the backend, not the final
 * dashboard. It reads every REST route and every WebSocket frame type the
 * backend serves, so a regression anywhere in the API shows up on a screen.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertStream, type Filters } from "./components/AlertStream";
import { EvidencePanel } from "./components/Evidence";
import { Wire } from "./components/Wire";
import { api } from "./lib/api";
import { fmt } from "./lib/format";
import { useLiveFeed } from "./lib/store";
import type { Alert } from "./lib/types";
import { HostView, IncidentsView, ReplayView, SystemView } from "./views/Views";

type View = "live" | "incidents" | "host" | "system" | "replay";

const NAV: { id: View; label: string }[] = [
  { id: "live", label: "Live" },
  { id: "incidents", label: "Incid" },
  { id: "host", label: "Host" },
  { id: "system", label: "Sys" },
  { id: "replay", label: "Replay" },
];

export default function App() {
  const { alerts, incidents, metrics, conn, received, wire } = useLiveFeed();
  const [view, setView] = useState<View>("live");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [host, setHost] = useState<string | null>(null);
  const [filters, setFilters] = useState<Filters>({
    severities: new Set(),
    classes: new Set(),
  });
  // An alert selected from a screen that reads history (Host, Incidents) may
  // have scrolled out of the live ring buffer, so it is fetched on demand.
  const [fetched, setFetched] = useState<Alert | null>(null);

  const selected = useMemo(
    () =>
      alerts.find((a) => a.alert_id === selectedId) ??
      (fetched?.alert_id === selectedId ? fetched : null),
    [alerts, fetched, selectedId]
  );

  useEffect(() => {
    if (!selectedId || selected) return;
    let alive = true;
    api
      .alert(selectedId)
      .then((a) => alive && setFetched(a))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [selectedId, selected]);

  const selectAlert = useCallback((id: string) => {
    setSelectedId(id || null);
  }, []);

  const openHost = useCallback((ip: string) => {
    setHost(ip);
    setView("host");
  }, []);

  const openAlert = useCallback((id: string) => {
    setSelectedId(id);
    setView("live");
  }, []);

  return (
    <div className="app">
      <nav className="nav">
        {NAV.map((n) => (
          <button
            key={n.id}
            aria-current={view === n.id}
            onClick={() => setView(n.id)}
          >
            {n.label}
          </button>
        ))}
      </nav>

      {/* Fixed height, always visible, never scrolls away (spec 3.2). */}
      <Wire buffer={wire} conn={conn} onSelect={openAlert} />

      <main className="main">
        {view === "live" && (
          <div className="split">
            <AlertStream
              alerts={alerts}
              selectedId={selectedId}
              onSelect={selectAlert}
              filters={filters}
              onFilters={setFilters}
              received={received}
            />
            <EvidencePanel alert={selected} onHost={openHost} />
          </div>
        )}
        {view === "incidents" && (
          <IncidentsView
            incidents={incidents}
            onAlert={openAlert}
            onHost={openHost}
          />
        )}
        {view === "host" && (
          <HostView ip={host} onAlert={openAlert} onHost={setHost} />
        )}
        {view === "system" && <SystemView />}
        {view === "replay" && <ReplayView />}
      </main>

      <InstrumentBar metrics={metrics} conn={conn} />
    </div>
  );
}

/**
 * The instrument bar (spec 4.2).
 *
 * Values update at 1Hz - fast enough to feel live, slow enough to read. Feed
 * state is the only element permitted colour, and only when disconnected.
 */
function InstrumentBar({
  metrics,
  conn,
}: {
  metrics: ReturnType<typeof useLiveFeed>["metrics"];
  conn: ReturnType<typeof useLiveFeed>["conn"];
}) {
  const m = metrics;
  return (
    <div className="bar">
      <span className="cell">
        <span className="v">{m ? m.alerts_per_sec.toFixed(1) : "—"}</span>
        <span className="u">alerts/s</span>
      </span>
      <span className="cell">
        {/* Traffic figures come from the ingestion layer. When nothing has
            reported, say so rather than showing a confident zero. */}
        <span className="v">
          {m?.traffic_telemetry_live ? m.flows_per_sec.toLocaleString() : "—"}
        </span>
        <span className="u">flows/s</span>
      </span>
      <span className="cell">
        <span className="v">
          {m?.traffic_telemetry_live ? m.mbps.toFixed(1) : "—"}
        </span>
        <span className="u">Mb/s</span>
      </span>
      <span className="cell">
        <span className="v">{m ? m.latency_p95_ms.toFixed(0) : "—"}</span>
        <span className="u">ms p95</span>
      </span>
      <span className="cell">
        <span className="v">
          {m ? `${m.detectors_online}/${m.detectors_total}` : "—"}
        </span>
        <span className="u">detectors</span>
      </span>
      <span className="cell">
        <span className="v">{m ? fmt.uptime(m.uptime_s) : "—"}</span>
        <span className="u">uptime</span>
      </span>
      <span className="cell">
        <span className={`v${conn !== "open" ? " disconnected" : ""}`}>
          {conn === "open" ? "live" : conn === "connecting" ? "connecting" : "feed stopped"}
        </span>
        {m && m.ws_dropped > 0 && (
          // The dashboard is behind. Saying so beats silently implying the
          // stream is complete.
          <span className="u">{m.ws_dropped} dropped</span>
        )}
      </span>
    </div>
  );
}
