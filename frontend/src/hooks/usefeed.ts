/// <reference types="vite/client" />
import { useCallback, useEffect, useRef, useState } from "react";
import type { Alert, Incident, Metrics } from "../lib/types";
import { fmtUptime } from "../lib/format";

const WS_URL = (import.meta.env.DEV ? "ws://localhost:5173" : window.location.origin.replace("http", "ws")) + "/ws";

/**
 * Owns the WebSocket connection to the mock/replay server (or, later, the
 * real FastAPI backend — section 8.1: "React should talk to it directly").
 * Section 8.2's performance rules live here:
 *   - ring buffer capped at 500 alerts
 *   - batched state updates (accumulate, flush once per animation frame)
 *   - the Wire's density/mark buffers are refs, never React state, so the
 *     rAF animation loop in <Wire> never triggers a React render.
 */
export function useFeed() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [metrics, setMetrics] = useState<Metrics>({
    flowsPerSec: 0, mbps: 0, p50: 0, p95: 0,
    detectorsOnline: 8, detectorsTotal: 8, uptime: "00:00:00", connected: false,
  });

  // Refs feeding the Wire's canvas loop directly — never React state.
  const samplesRef = useRef<{ t: number; v: number }[]>([]);
  const marksRef = useRef<{ t: number; code: string; color: string }[]>([]);
  const pendingAlerts = useRef<Alert[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  const getWireData = useCallback(
    () => ({ samples: samplesRef.current, marks: marksRef.current, connected: metrics.connected }),
    [metrics.connected]
  );

  useEffect(() => {
    let raf: number;
    let reconnectTimer: ReturnType<typeof setTimeout>;

    function connect() {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => setMetrics((m) => ({ ...m, connected: true }));
      ws.onclose = () => {
        setMetrics((m) => ({ ...m, connected: false }));
        reconnectTimer = setTimeout(connect, 2000);
      };
      ws.onerror = () => ws.close();

      ws.onmessage = (evt) => {
        const msg = JSON.parse(evt.data);
        if (msg.type === "hello") {
          setAlerts(msg.alerts ?? []);
        } else if (msg.type === "alert") {
          pendingAlerts.current.push(msg);
          const now = performance.now();
          samplesRef.current.push({ t: now, v: msg.__density ?? 3200 + Math.random() * 800 });
          marksRef.current.push({ t: now, code: msg.threat_class, color: "" });
        } else if (msg.type === "incident") {
          setIncidents((prev) => [msg, ...prev].slice(0, 20));
        } else if (msg.type === "metrics") {
          setMetrics({
            flowsPerSec: msg.flows_per_sec,
            packetsPerSec: msg.packets_per_sec,
            mbps: msg.mbps,
            p50: msg.latency_p50_ms,
            p95: msg.latency_p95_ms,
            detectorsOnline: msg.detectors_online,
            detectorsTotal: msg.detectors_total,
            uptime: fmtUptime(msg.uptime_s),
            connected: true,
          });
          samplesRef.current.push({ t: performance.now(), v: msg.flows_per_sec });
        }
      };
    }
    connect();

    // density sampler trim — ring buffer bounded to the Wire's 60s window
    function trim() {
      const now = performance.now();
      samplesRef.current = samplesRef.current.filter((s) => now - s.t < 65000);
      marksRef.current = marksRef.current.filter((m) => now - m.t < 65000);
      raf = requestAnimationFrame(trim);
    }
    raf = requestAnimationFrame(trim);

    // flush batched alerts once per animation frame — never per message
    let flushRaf: number;
    function flush() {
      if (pendingAlerts.current.length) {
        const batch = pendingAlerts.current;
        pendingAlerts.current = [];
        setAlerts((prev) => [...batch.reverse(), ...prev].slice(0, 500));
      }
      flushRaf = requestAnimationFrame(flush);
    }
    flushRaf = requestAnimationFrame(flush);

    return () => {
      cancelAnimationFrame(raf);
      cancelAnimationFrame(flushRaf);
      clearTimeout(reconnectTimer);
      wsRef.current?.close();
    };
  }, []);

  return { alerts, incidents, metrics, getWireData };
}