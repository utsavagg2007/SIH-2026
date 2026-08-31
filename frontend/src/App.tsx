import { useCallback, useEffect, useRef, useState } from "react";
import { MessageSquare } from "lucide-react";
import { T, SANS } from "./lib/tokens";
import type { Severity, ViewId } from "./lib/types";
import { useFeed } from "./hooks/useFeed";
import { Wire } from "./components/Wire";
import { NavRail } from "./components/NavRail";
import { InstrumentBar } from "./components/InstrumentBar";
import { AlertStream } from "./components/AlertStream";
import { EvidencePanel } from "./components/EvidencePanel";
import { AnalystPanel } from "./components/AnalystPanel";
import { IncidentsView } from "./components/IncidentsView";
import { HostView } from "./components/HostView";
import { ReplayView, type ReplayState } from "./components/ReplayView";
import { SystemView } from "./components/SystemView";

export default function App() {
  const { alerts, incidents, metrics, getWireData } = useFeed();

  const [view, setView] = useState<ViewId>("live");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [filterSev, setFilterSev] = useState<Severity | "all">("all");
  const [showAnalyst, setShowAnalyst] = useState(false);
  const [replay, setReplay] = useState<ReplayState>({ capture: null, speed: 1, running: false, elapsed: 0 });

  // Throughput/latency history for the System view — accumulated from the
  // metrics stream, not re-fetched.
  const [throughputHistory, setThroughputHistory] = useState<{ t: number; flowsPerSec: number }[]>([]);
  const [latencySamples, setLatencySamples] = useState<number[]>([]);
  const tickRef = useRef(0);

  useEffect(() => {
    tickRef.current += 1;
    setThroughputHistory((h) => [...h, { t: tickRef.current, flowsPerSec: metrics.flowsPerSec }].slice(-60));
    setLatencySamples((prev) => [...prev, metrics.p95 + (Math.random() - 0.5) * 10].slice(-120));
  }, [metrics.flowsPerSec]);

  useEffect(() => {
    if (!replay.running) return;
    const interval = setInterval(() => setReplay((r) => ({ ...r, elapsed: r.elapsed + 1 })), 1000 / (replay.speed || 1));
    return () => clearInterval(interval);
  }, [replay.running, replay.speed]);

  const selectedAlert = alerts.find((a) => a.alert_id === selectedId) || null;
  const handleSelect = useCallback((id: string) => setSelectedId(id), []);
  const openHost = useCallback((ip: string) => {
    setSelectedHost(ip);
    setView("host");
  }, []);
  const goto = useCallback((v: ViewId) => setView(v), []);

  // Keyboard nav — section 8.3: j/k move, Enter opens, Esc clears. Security
  // tools are keyboard-driven, and it makes the demo faster to drive.
  //
  // `a` toggles the analyst panel, which is the keyboard half of spec 6.5's
  // "toggled by keyboard or by an 'Explain' control on any alert". Esc closes
  // the panel first and only clears the selection once it is shut, so the key
  // undoes one thing at a time rather than dropping the operator's place in
  // the stream along with the panel.
  useEffect(() => {
    if (view !== "live") return;
    const filtered = filterSev === "all" ? alerts : alerts.filter((a) => a.severity === filterSev);
    function onKey(e: KeyboardEvent) {
      const tag = (document.activeElement as HTMLElement | null)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const idx = filtered.findIndex((a) => a.alert_id === selectedId);
      if (e.key === "j") {
        e.preventDefault();
        const next = filtered[Math.min(filtered.length - 1, idx + 1)];
        if (next) setSelectedId(next.alert_id);
      } else if (e.key === "k") {
        e.preventDefault();
        const prev = filtered[Math.max(0, idx - 1)];
        if (prev) setSelectedId(prev.alert_id);
      } else if (e.key === "Escape") {
        if (showAnalyst) setShowAnalyst(false);
        else setSelectedId(null);
      } else if (e.key === "a" || e.key === "A") {
        e.preventDefault();
        setShowAnalyst((v) => !v);
      } else if (e.key === "Enter" && filtered[idx]) {
        setShowAnalyst(true);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [view, alerts, filterSev, selectedId, showAnalyst]);

  return (
    <div style={{ width: "100%", height: "100vh", minHeight: 640, background: T.bg, display: "flex", fontVariantNumeric: "tabular-nums" }}>
      <NavRail active={view} onSelect={goto} />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        <Wire getData={getWireData} />

        {view === "live" && (
          <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
            <div style={{ width: "38%", borderRight: `1px solid ${T.rule}`, minWidth: 280 }}>
              <AlertStream alerts={alerts} selectedId={selectedId} onSelect={handleSelect} filterSev={filterSev} setFilterSev={setFilterSev} />
            </div>
            <div style={{ flex: 1, minWidth: 0, position: "relative" }}>
              {selectedAlert && (
                <button
                  // Spec 6.5's "Explain" control. It opens rather than toggles:
                  // the word names an outcome, so pressing it must always end
                  // with an explanation on screen. `a` is the toggle.
                  onClick={() => setShowAnalyst(true)}
                  title="Explain this alert (a)"
                  style={{
                    position: "absolute", top: 12, right: 12, zIndex: 1, fontFamily: SANS, fontSize: 11, fontWeight: 600,
                    color: T.text2, background: T.panel2, border: `1px solid ${T.rule}`, borderRadius: 2, padding: "5px 8px",
                    cursor: "pointer", display: "flex", alignItems: "center", gap: 5,
                  }}
                >
                  <MessageSquare size={12} /> Explain
                </button>
              )}
              <EvidencePanel alert={selectedAlert} onOpenHost={openHost} />
            </div>
            {showAnalyst && <AnalystPanel alert={selectedAlert} onClose={() => setShowAnalyst(false)} />}
          </div>
        )}

        {view === "incidents" && (
          <IncidentsView incidents={incidents} onSelectAlert={(id) => { setSelectedId(id); setView("live"); }} onOpenHost={openHost} />
        )}

        {view === "host" && (
          <HostView host={selectedHost} alerts={alerts} incidents={incidents} onSelectAlert={(id) => { setSelectedId(id); setView("live"); }} />
        )}

        {view === "system" && (
          <SystemView metrics={metrics} throughputHistory={throughputHistory} latencySamples={latencySamples} alerts={alerts} />
        )}

        {view === "replay" && <ReplayView replay={replay} setReplay={setReplay} />}

        <InstrumentBar metrics={metrics} />
      </div>
    </div>
  );
}