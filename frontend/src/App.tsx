import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { MessageSquare } from "lucide-react";
import { T, SEV_ORDER, SANS } from "./lib/tokens";
import type { Severity, ViewId } from "./lib/types";
import { useFeed } from "./hooks/useFeed";
import { useSystem } from "./hooks/useSystem";
import { api } from "./lib/api";
import type { Alert } from "./lib/types";
import { Wire } from "./components/Wire";
import { NavRail } from "./components/NavRail";
import { ThreatLedger } from "./components/ThreatLedger";
import { InstrumentBar } from "./components/InstrumentBar";
import { AlertStream, applyFilters, type StreamFilters } from "./components/AlertStream";
import { EvidencePanel } from "./components/EvidencePanel";
import { AnalystPanel } from "./components/AnalystPanel";
import { IncidentsView } from "./components/IncidentsView";
import { HostView } from "./components/HostView";
import { ReplayView } from "./components/ReplayView";
import { SystemView } from "./components/SystemView";

/** The sampler that drives ages, the recency decay and the ledger counts.
 *  4Hz: fast enough to feel live, slow enough to read. The underlying data is
 *  exact and unthrottled - this only paces what is drawn. */
const TICK_MS = 250;

export default function App() {
  const { alerts, incidents, metrics, getWireData, getArrivals, getLastArrival } = useFeed();
  const system = useSystem();

  const [view, setView] = useState<ViewId>("live");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [showAnalyst, setShowAnalyst] = useState(false);
  const [rawOpen, setRawOpen] = useState(false);
  const [filters, setFilters] = useState<StreamFilters>({ severity: "all", classes: [], host: "" });
  /** Set when the evidence panel jumps to an incident, so that ribbon opens
   *  first rather than making the operator find it in the list. */
  const [focusedIncident, setFocusedIncident] = useState<string | null>(null);

  // One 4Hz heartbeat for the whole shell. Time-derived readouts (ages, the
  // rolling ledger window, the recency decay) need a clock as well as data, and
  // one sampler beats four independent intervals disagreeing about the second.
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((n) => n + 1), TICK_MS);
    return () => clearInterval(t);
  }, []);

  /**
   * Observed alert rate over time, for the System view's throughput trace.
   *
   * Sampled from the backend's own `alerts_per_sec` once per poll. The previous
   * build filled this array with `p95 + (Math.random() - 0.5) * 10` and drew it
   * as a latency distribution - a convincing curve out of a random number
   * generator, on the screen whose entire job is proving measured throughput.
   */
  const [rateHistory, setRateHistory] = useState<number[]>([]);
  const lastRate = useRef<number | null>(null);
  useEffect(() => {
    const r = system.throughput?.alerts_per_sec;
    if (r === undefined || r === lastRate.current) return;
    lastRate.current = r;
    setRateHistory((h) => [...h, r].slice(-90));
  }, [system.throughput]);

  const filtered = useMemo(() => applyFilters(alerts, filters), [alerts, filters]);
  const inBuffer = alerts.find((a) => a.alert_id === selectedId) || null;

  /**
   * An alert selected from somewhere other than the stream - an incident node,
   * a Wire mark - may have aged out of the 500-alert ring. `GET /alerts/{id}`
   * is exactly the route for that case, and without it clicking an older
   * incident member showed "Waiting for first detection" as though nothing had
   * been selected at all.
   */
  const [fetched, setFetched] = useState<Alert | null>(null);
  useEffect(() => {
    if (!selectedId || inBuffer) {
      setFetched(null);
      return;
    }
    let cancelled = false;
    api
      .alert(selectedId)
      .then((a) => {
        if (!cancelled) setFetched(a);
      })
      .catch(() => {
        // The id is not in the store either. The panel's empty state is the
        // honest outcome; a thrown error here would blank the console.
        if (!cancelled) setFetched(null);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId, inBuffer]);

  // The live copy always wins: the socket revises occurrences and last_seen in
  // place, so a stored row for the same id is by definition the older one.
  const selectedAlert = inBuffer ?? (fetched?.alert_id === selectedId ? fetched : null);

  const handleSelect = useCallback((id: string) => {
    setSelectedId(id);
    setRawOpen(false);
  }, []);

  /**
   * Open on the newest alert instead of on an empty panel.
   *
   * With nothing selected, two thirds of the screen read "Waiting for first
   * detection" while the stream beside it listed sixty-six of them. The first
   * thing anyone saw - judge or analyst - was an empty evidence panel next to
   * a full stream, which reads as a broken feed rather than as an unmade
   * choice. This selects once, on the first render that has something to
   * select; the latch means a deliberate Esc clears the panel and it stays
   * cleared, and an operator's own selection is never overridden.
   */
  const autoSelected = useRef(false);
  useEffect(() => {
    if (autoSelected.current || selectedId || filtered.length === 0) return;
    autoSelected.current = true;
    setSelectedId(filtered[0].alert_id);
  }, [filtered, selectedId]);

  /** Selecting from another view brings the operator back to the evidence. */
  const selectAndShow = useCallback((id: string) => {
    setSelectedId(id);
    setRawOpen(false);
    setView("live");
  }, []);

  const openHost = useCallback((ip: string) => {
    setSelectedHost(ip);
    setView("host");
  }, []);

  const openIncident = useCallback((id: string) => {
    setFocusedIncident(id);
    setView("incidents");
  }, []);
  const goto = useCallback((v: ViewId) => setView(v), []);
  const toggleRaw = useCallback(() => setRawOpen((v) => !v), []);
  const pickSeverity = useCallback(
    (s: Severity | "all") => setFilters((f) => ({ ...f, severity: s })),
    []
  );
  const setStreamFilters = useCallback((f: StreamFilters) => setFilters(f), []);

  // Keyboard: security tools are keyboard-driven, and it makes the demo faster
  // to drive. Esc undoes one thing at a time - it closes the analyst panel
  // first and only clears the selection once the panel is shut, so it never
  // drops the operator's place in the stream along with the panel.
  useEffect(() => {
    if (view !== "live") return;
    function onKey(e: KeyboardEvent) {
      const tag = (document.activeElement as HTMLElement | null)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const idx = filtered.findIndex((a) => a.alert_id === selectedId);
      if (e.key === "j") {
        e.preventDefault();
        const next = filtered[Math.min(filtered.length - 1, idx + 1)];
        if (next) handleSelect(next.alert_id);
      } else if (e.key === "k") {
        e.preventDefault();
        const prev = filtered[Math.max(0, idx - 1)];
        if (prev) handleSelect(prev.alert_id);
      } else if (e.key === "Escape") {
        if (showAnalyst) setShowAnalyst(false);
        else setSelectedId(null);
      } else if (e.key === "a" || e.key === "A") {
        e.preventDefault();
        setShowAnalyst((v) => !v);
      } else if (e.key === "e" || e.key === "E") {
        e.preventDefault();
        setRawOpen((v) => !v);
      } else if (e.key >= "1" && e.key <= "4") {
        e.preventDefault();
        setFilters((f) => ({ ...f, severity: SEV_ORDER[Number(e.key) - 1] }));
      } else if (e.key === "0") {
        e.preventDefault();
        setFilters({ severity: "all", classes: [], host: "" });
      } else if (e.key === "Enter" && filtered[idx]) {
        setShowAnalyst(true);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [view, filtered, selectedId, showAnalyst, handleSelect]);

  // Read once per tick rather than held in state: these come from refs the
  // WebSocket handler writes to, and putting them in state would drag the
  // stream's arrival path through a render per message.
  const arrivals = getArrivals();
  const lastArrival = getLastArrival();
  const stoppedFor = lastArrival ? (performance.now() - lastArrival) / 1000 : 0;

  return (
    <div
      style={{
        width: "100%", height: "100vh", minHeight: 640, minWidth: 1280,
        background: T.bgDeep, display: "flex", fontVariantNumeric: "tabular-nums",
      }}
    >
      <NavRail active={view} onSelect={goto} />

      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, gap: 1, background: T.bgDeep }}>
        <Wire getData={getWireData} onSelect={selectAndShow} />

        <ThreatLedger
          alerts={alerts}
          arrivals={arrivals}
          sessionTotal={metrics.alertsTotal}
          peakPerSec={system.throughput?.alerts_peak_per_sec ?? 0}
          connected={metrics.connected}
          sevFilter={filters.severity}
          onPickSeverity={pickSeverity}
          tick={tick}
        />

        {view === "live" && (
          <div style={{ flex: 1, display: "flex", minHeight: 0, gap: 1, background: T.bgDeep }}>
            <div style={{ width: "34%", minWidth: 420, display: "flex", flexDirection: "column", minHeight: 0 }}>
              <AlertStream
                alerts={alerts}
                filtered={filtered}
                incidents={incidents}
                selectedId={selectedId}
                onSelect={handleSelect}
                filters={filters}
                setFilters={setStreamFilters}
                connected={metrics.connected}
                stoppedFor={stoppedFor}
                tick={tick}
              />
            </div>
            <div style={{ flex: 1, minWidth: 0, position: "relative", display: "flex", flexDirection: "column", minHeight: 0 }}>
              {selectedAlert && (
                <button
                  // The "Explain" control opens rather than toggles: the word
                  // names an outcome, so pressing it must always end with an
                  // explanation on screen. `a` is the toggle.
                  onClick={() => setShowAnalyst(true)}
                  title="Explain this alert (a)"
                  className="ctl"
                  style={{ position: "absolute", top: 6, right: 12, zIndex: 2, display: "flex", alignItems: "center", gap: 5 }}
                >
                  <MessageSquare size={11} /> Explain
                </button>
              )}
              <EvidencePanel
                alert={selectedAlert}
                onOpenHost={openHost}
                onOpenIncident={openIncident}
                rawOpen={rawOpen}
                onToggleRaw={toggleRaw}
              />
            </div>
            {showAnalyst && <AnalystPanel alert={selectedAlert} onClose={() => setShowAnalyst(false)} />}
          </div>
        )}

        {view === "incidents" && (
          <IncidentsView
            incidents={incidents}
            selectedId={selectedId}
            focusedIncident={focusedIncident}
            onSelectAlert={selectAndShow}
            onOpenHost={openHost}
          />
        )}

        {view === "host" && (
          <HostView
            host={selectedHost}
            alerts={alerts}
            incidents={incidents}
            onSelectAlert={selectAndShow}
            onOpenHost={openHost}
          />
        )}

        {view === "system" && <SystemView system={system} metrics={metrics} rateHistory={rateHistory} />}

        {view === "replay" && <ReplayView />}

        <InstrumentBar metrics={metrics} trafficSource={system.throughput?.traffic_source} />
      </div>
    </div>
  );
}
