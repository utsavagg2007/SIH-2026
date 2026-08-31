/// <reference types="vite/client" />
import { useCallback, useEffect, useRef, useState } from "react";
import type { Alert, Incident, Metrics } from "../lib/types";
import { fmtUptime } from "../lib/format";
import { SEV } from "../lib/tokens";

/**
 * The live feed, against the real backend.
 *
 * WHAT THIS USED TO DO, AND WHY IT MATTERED
 * -----------------------------------------
 * This hook previously connected to `ws://localhost:5173/ws` - the Vite dev
 * server's own port, not the API's - and branched on frame types
 * `hello` / `alert` / `incident` / `metrics` read off the top level of the
 * message. No server in this repository has ever emitted that shape. It was
 * written against the Node mock server the frontend spec (8.1) recommends and
 * which was never built, so the screen that was wired up could not read the
 * backend at all, while `lib/store.ts` - which speaks the real protocol
 * correctly - was imported by nothing.
 *
 * It also filled the Wire's density trace with
 * `msg.__density ?? 3200 + Math.random() * 800`, which drew a convincing
 * traffic graph out of a random number generator. On a product whose entire
 * argument is that every number on screen came from an observation, that is the
 * worst possible defect, and it would have been on the projector.
 *
 * THE REAL PROTOCOL
 * -----------------
 * Every frame is `{"type": <name>, "data": {...}}` (see backend
 * `core/hub.py::broadcast`). The names are:
 *
 *   snapshot          once on connect - recent alerts, incidents, metrics
 *   alert.created     a new deduplicated finding
 *   alert.updated     a repeat folding into an existing one (occurrences++)
 *   incident.created  correlation opened an incident
 *   incident.updated  an alert joined an existing incident
 *   metrics           once per second
 *   system.status     storage/replay state changed
 *   pong              reply to a ping
 *
 * Section 8.2's performance rules still live here: a ring buffer capped at 500
 * alerts, state batched onto an animation frame rather than set per message,
 * and the Wire's buffers held in refs so its rAF loop never triggers a render.
 */

/** Same origin: the Vite proxy forwards /ws to the API in development, and the
 *  backend serves the built bundle itself in production, so this is correct in
 *  both without a build-time switch. */
const WS_PATH = "/ws/alerts";

const RING_CAPACITY = 500;
const WIRE_WINDOW_MS = 65_000;

type Frame = { type: string; data: any };

export function useFeed() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [metrics, setMetrics] = useState<Metrics>({
    flowsPerSec: 0,
    packetsPerSec: 0,
    mbps: 0,
    p50: 0,
    p95: 0,
    detectorsOnline: 0,
    detectorsTotal: 0,
    uptime: "00:00:00",
    connected: false,
    trafficLive: false,
  });

  // Refs feeding the Wire's canvas loop directly - never React state.
  const samplesRef = useRef<{ t: number; v: number }[]>([]);
  const marksRef = useRef<{ t: number; code: string; color: string }[]>([]);
  const pendingCreated = useRef<Alert[]>([]);
  const pendingUpdated = useRef<Map<string, Alert>>(new Map());
  const wsRef = useRef<WebSocket | null>(null);

  const getWireData = useCallback(
    () => ({
      samples: samplesRef.current,
      marks: marksRef.current,
      connected: metrics.connected,
    }),
    [metrics.connected]
  );

  useEffect(() => {
    let trimRaf = 0;
    let flushRaf = 0;
    let reconnectTimer: ReturnType<typeof setTimeout>;
    let closed = false;

    function mark(alert: Alert) {
      marksRef.current.push({
        t: performance.now(),
        code: alert.threat_code,
        color: SEV[alert.severity]?.color ?? "",
      });
    }

    function applyMetrics(data: any) {
      setMetrics({
        flowsPerSec: data.flows_per_sec ?? 0,
        packetsPerSec: data.packets_per_sec ?? 0,
        mbps: data.mbps ?? 0,
        p50: Math.round(data.latency_p50_ms ?? 0),
        p95: Math.round(data.latency_p95_ms ?? 0),
        detectorsOnline: data.detectors_online ?? 0,
        detectorsTotal: data.detectors_total ?? 0,
        uptime: fmtUptime(data.uptime_s ?? 0),
        connected: true,
        // The backend reports whether the traffic figures came from a live
        // telemetry post or are stale. The bar shows a dash rather than a
        // confident zero when they are not live, because this process never
        // sees a packet and cannot know the flow rate on its own.
        trafficLive: Boolean(data.traffic_telemetry_live),
      });

      // The density trace is flows per second, and only the ingestion and
      // detection layers can count those. A sample is pushed only when the
      // figure is genuinely live; when it is not, the trace stays flat and the
      // bar says so. Drawing an invented curve here is exactly what this hook
      // used to do.
      if (data.traffic_telemetry_live) {
        samplesRef.current.push({
          t: performance.now(),
          v: data.flows_per_sec ?? 0,
        });
      }
    }

    function connect() {
      if (closed) return;
      const url = `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}${WS_PATH}`;
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => setMetrics((m) => ({ ...m, connected: true }));
      ws.onclose = () => {
        setMetrics((m) => ({ ...m, connected: false }));
        if (!closed) reconnectTimer = setTimeout(connect, 2000);
      };
      ws.onerror = () => ws.close();

      ws.onmessage = (evt) => {
        let frame: Frame;
        try {
          frame = JSON.parse(evt.data);
        } catch {
          return; // a frame we cannot parse is not a reason to drop the feed
        }
        const data = frame.data ?? {};

        switch (frame.type) {
          case "snapshot": {
            // ws.py sends the recent window oldest-first; the stream reads
            // newest-first.
            const recent: Alert[] = [...(data.alerts ?? [])].reverse();
            setAlerts(recent.slice(0, RING_CAPACITY));
            setIncidents((data.incidents ?? []).slice(0, 20));
            if (data.metrics) applyMetrics(data.metrics);
            break;
          }

          case "alert.created":
            pendingCreated.current.push(data as Alert);
            mark(data as Alert);
            break;

          case "alert.updated":
            // A repeat folding into an existing finding. It carries the
            // SURVIVING alert_id, so it replaces a row rather than adding one -
            // which is the whole point of deduplication, and only works because
            // the backend now projects the surviving id rather than the id this
            // occurrence happened to arrive with.
            pendingUpdated.current.set((data as Alert).alert_id, data as Alert);
            mark(data as Alert);
            break;

          case "incident.created":
          case "incident.updated": {
            const incident = data as Incident;
            setIncidents((prev) => {
              const next = prev.filter((i) => i.incident_id !== incident.incident_id);
              return [incident, ...next].slice(0, 20);
            });
            break;
          }

          case "metrics":
            applyMetrics(data);
            break;

          case "system.status":
          case "pong":
            break;

          default:
            break; // an unknown frame must never break the interface
        }
      };
    }

    connect();

    function trim() {
      const now = performance.now();
      const cutoff = now - WIRE_WINDOW_MS;
      // Bounded from the front rather than filtered: the buffers are already
      // in time order, so this is O(dropped) instead of O(n) every frame.
      let i = 0;
      while (i < samplesRef.current.length && samplesRef.current[i].t < cutoff) i++;
      if (i) samplesRef.current.splice(0, i);
      let j = 0;
      while (j < marksRef.current.length && marksRef.current[j].t < cutoff) j++;
      if (j) marksRef.current.splice(0, j);
      trimRaf = requestAnimationFrame(trim);
    }
    trimRaf = requestAnimationFrame(trim);

    function flush() {
      const created = pendingCreated.current;
      const updated = pendingUpdated.current;
      if (created.length || updated.size) {
        pendingCreated.current = [];
        pendingUpdated.current = new Map();
        setAlerts((prev) => {
          let next = prev;
          if (updated.size) {
            // Replace in place, preserving position. An update that appended
            // instead would grow the stream by one row per repeat and undo the
            // deduplication the backend just performed.
            next = next.map((a) => updated.get(a.alert_id) ?? a);
            const known = new Set(next.map((a) => a.alert_id));
            for (const [id, alert] of updated) {
              if (!known.has(id)) created.push(alert);
            }
          }
          if (created.length) {
            next = [...created.reverse(), ...next];
          }
          return next.slice(0, RING_CAPACITY);
        });
      }
      flushRaf = requestAnimationFrame(flush);
    }
    flushRaf = requestAnimationFrame(flush);

    return () => {
      closed = true;
      cancelAnimationFrame(trimRaf);
      cancelAnimationFrame(flushRaf);
      clearTimeout(reconnectTimer);
      wsRef.current?.close();
    };
  }, []);

  return { alerts, incidents, metrics, getWireData };
}
