/// <reference types="vite/client" />
import { useCallback, useEffect, useRef, useState } from "react";
import type { Alert, Incident, Metrics } from "../lib/types";
import { fmtEndpoints, fmtUptime } from "../lib/format";
import { SEV } from "../lib/tokens";
import { api } from "../lib/api";

/**
 * The live feed, against the real backend.
 *
 * THE PROTOCOL
 * ------------
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
 * Nothing here invents a value. The density trace is flows per second, and only
 * the ingestion and detection layers can count those, so a sample is pushed
 * only when the backend says the figure is genuinely live; otherwise the trace
 * stays flat and the instrument bar shows a dash. Drawing an invented curve
 * here is exactly what this hook used to do, and on a product whose entire
 * argument is that every number came from an observation it is the worst
 * possible defect.
 *
 * DESIGN.md §12.2's performance rules live here: a ring buffer capped at 500
 * alerts, state batched onto an animation frame rather than set per message,
 * and the Wire's buffers held in refs so its rAF loop never triggers a render.
 */

/** Same origin: the Vite proxy forwards /ws to the API in development, and the
 *  backend serves the built bundle itself in production, so this is correct in
 *  both without a build-time switch. */
const WS_PATH = "/ws/alerts";

const RING_CAPACITY = 500;
/**
 * Incident records held alongside the ring buffer.
 *
 * This has to cover the incidents the buffered alerts belong to, because the
 * stream groups alerts under the incident that correlated them and reads the
 * pivot host from these records. The cap used to be written three times - 50
 * on both REST seeding paths and 20 on the `incident.created` path - so live
 * arrivals steadily evicted incident records whose member alerts were still on
 * screen, and those groups fell back to rendering a bare `INC-8030094c1a18`
 * where a host address belongs. One constant, one value.
 */
const INCIDENT_CAPACITY = 50;
const WIRE_WINDOW_MS = 65_000;
/** The ledger's rolling window (§4.1). Arrivals older than this stop counting;
 *  an all-time total only ever goes up and stops carrying information after a
 *  minute. */
const LEDGER_WINDOW_MS = 300_000;

type Frame = { type: string; data: any };

/**
 * Live records win; stored ones fill the gaps.
 *
 * The socket carries the authoritative current state of an alert - occurrences
 * and last_seen are revised in place as repeats fold in - so a REST row for an
 * id already in memory is by definition the older copy and must not overwrite
 * it. Ordering is newest-first, matching how the stream reads.
 */
function mergeById<T extends { ts?: number; updated_at?: number }>(
  live: T[],
  stored: T[],
  id: (x: T) => string
): T[] {
  const known = new Set(live.map(id));
  const extra = stored.filter((x) => !known.has(id(x)));
  if (extra.length === 0) return live;
  const at = (x: T) => x.updated_at ?? x.ts ?? 0;
  return [...live, ...extra].sort((a, b) => at(b) - at(a));
}

/**
 * One detection on the Wire.
 *
 * Severity, timestamp and endpoints ride along with the mark because the Wire
 * now encodes severity in mark height and answers a hover with a tooltip
 * (§6). Looking those up in React state from inside the rAF loop would put the
 * animation path back through a render, which is the one thing that path must
 * never do.
 */
export interface WireMark {
  /** `performance.now()` at arrival - the same clock the loop draws against. */
  t: number;
  alertId: string;
  code: string;
  severity: string;
  color: string;
  /** Wall-clock seconds, for the tooltip's readout. */
  ts: number;
  endpoints: string;
}

/** What the instrument bar and ledger read. Everything is measured by the
 *  backend; a field it did not report stays undefined rather than defaulting
 *  to a confident zero. */
export interface FeedMetrics extends Metrics {
  alertsPerSec: number;
  alertsTotal: number;
  alertsDeduplicated: number;
  wsClients: number;
}

export function useFeed() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [metrics, setMetrics] = useState<FeedMetrics>({
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
    alertsPerSec: 0,
    alertsTotal: 0,
    alertsDeduplicated: 0,
    wsClients: 0,
  });

  // Refs feeding the Wire's canvas loop directly - never React state.
  const samplesRef = useRef<{ t: number; v: number }[]>([]);
  const marksRef = useRef<WireMark[]>([]);
  /** Arrival instants inside the ledger window, for the observed alert rate and
   *  for "feed stopped, last alert N ago". Trimmed from the front. */
  const arrivalsRef = useRef<number[]>([]);
  const lastArrivalRef = useRef<number>(0);
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

  /** Arrival instants, newest last. The ledger derives its rate from this
   *  rather than from a counter, so a paused feed reads zero immediately
   *  instead of holding the last rate the backend happened to report. */
  const getArrivals = useCallback(() => arrivalsRef.current, []);
  const getLastArrival = useCallback(() => lastArrivalRef.current, []);

  useEffect(() => {
    let trimRaf = 0;
    let flushRaf = 0;
    let reconnectTimer: ReturnType<typeof setTimeout>;
    let closed = false;

    function mark(alert: Alert) {
      const now = performance.now();
      marksRef.current.push({
        t: now,
        alertId: alert.alert_id,
        code: alert.threat_code,
        severity: alert.severity,
        color: SEV[alert.severity]?.color ?? "",
        ts: alert.ts,
        endpoints: fmtEndpoints(alert),
      });
      arrivalsRef.current.push(now);
      lastArrivalRef.current = now;
    }

    function applyMetrics(data: any, live = true) {
      setMetrics((prev) => ({
        ...prev,
        flowsPerSec: data.flows_per_sec ?? 0,
        packetsPerSec: data.packets_per_sec ?? 0,
        mbps: data.mbps ?? 0,
        p50: Math.round(data.latency_p50_ms ?? 0),
        p95: Math.round(data.latency_p95_ms ?? 0),
        detectorsOnline: data.detectors_online ?? 0,
        detectorsTotal: data.detectors_total ?? 0,
        uptime: fmtUptime(data.uptime_s ?? 0),
        // Only the socket may assert the feed is live. A REST poll proves the
        // API is reachable, not that frames are arriving, and the bar must not
        // say "streaming" when nothing is streaming.
        connected: live ? true : prev.connected,
        // The backend reports whether the traffic figures came from a live
        // telemetry post or are stale. The bar shows a dash rather than a
        // confident zero when they are not live, because this process never
        // sees a packet and cannot know the flow rate on its own.
        trafficLive: Boolean(data.traffic_telemetry_live),
        alertsPerSec: data.alerts_per_sec ?? 0,
        alertsTotal: data.alerts_total ?? 0,
        alertsDeduplicated: data.alerts_deduplicated ?? prev.alertsDeduplicated,
        wsClients: data.ws_clients ?? prev.wsClients,
      }));

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
            // newest-first. Merged rather than assigned: the REST history seed
            // may already have landed, and replacing the list here would throw
            // away everything older than the socket's recent window.
            const recent: Alert[] = [...(data.alerts ?? [])].reverse();
            setAlerts((prev) =>
              mergeById(recent, prev, (a) => a.alert_id).slice(0, RING_CAPACITY)
            );
            setIncidents((prev) =>
              mergeById(data.incidents ?? [], prev, (i) => i.incident_id).slice(0, INCIDENT_CAPACITY)
            );
            if (data.metrics) applyMetrics(data.metrics);
            // The snapshot is history, not arrivals: seeding the rate from it
            // would report a burst that happened before the page was open.
            break;
          }

          case "alert.created":
            pendingCreated.current.push(data as Alert);
            mark(data as Alert);
            break;

          case "alert.updated":
            // A repeat folding into an existing finding. It carries the
            // SURVIVING alert_id, so it replaces a row rather than adding one -
            // which is the whole point of deduplication.
            pendingUpdated.current.set((data as Alert).alert_id, data as Alert);
            mark(data as Alert);
            break;

          case "incident.created":
          case "incident.updated": {
            const incident = data as Incident;
            setIncidents((prev) => {
              const next = prev.filter((i) => i.incident_id !== incident.incident_id);
              return [incident, ...next].slice(0, INCIDENT_CAPACITY);
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

    // History seed over REST, in parallel with the socket.
    //
    // The snapshot frame is the fast path and wins wherever both have an
    // alert, but it only arrives if the socket connects. Seeding from
    // `GET /alerts` and `GET /incidents` means the console opens with history
    // on screen even when the feed is down - which is exactly the moment an
    // operator most wants to see what was already found, and the moment the
    // previous build showed an empty stream and nothing else.
    Promise.allSettled([
      api.alerts({ limit: RING_CAPACITY }),
      api.incidents(),
    ]).then(([alertPage, incidentPage]) => {
      if (closed) return;
      if (alertPage.status === "fulfilled") {
        setAlerts((live) =>
          mergeById(live, alertPage.value.items, (a) => a.alert_id).slice(0, RING_CAPACITY)
        );
      }
      if (incidentPage.status === "fulfilled") {
        setIncidents((live) =>
          mergeById(live, incidentPage.value.items, (i) => i.incident_id).slice(0, INCIDENT_CAPACITY)
        );
      }
      // A failure here is not worth surfacing: the socket is the primary path,
      // and its own state already drives the feed indicator.
    });

    /**
     * Metrics over REST while the socket is down.
     *
     * `GET /system/metrics` serves the same frame the socket pushes once a
     * second. A blocked or proxied WebSocket is a real deployment failure, and
     * without this the instrument bar reads all zeros while the API is
     * perfectly reachable. The feed indicator still says "feed stopped",
     * because that is the thing that is actually broken.
     */
    const metricsPoll = setInterval(() => {
      if (closed) return;
      if (wsRef.current?.readyState === WebSocket.OPEN) return;
      api
        .metricsFrame()
        .then((f) => {
          if (!closed) applyMetrics(f, false);
        })
        .catch(() => {
          /* API unreachable too; the bar's feed cell already says so */
        });
    }, 5000);

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
      const ledgerCutoff = now - LEDGER_WINDOW_MS;
      let k = 0;
      while (k < arrivalsRef.current.length && arrivalsRef.current[k] < ledgerCutoff) k++;
      if (k) arrivalsRef.current.splice(0, k);
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
      clearInterval(metricsPoll);
      cancelAnimationFrame(trimRaf);
      cancelAnimationFrame(flushRaf);
      clearTimeout(reconnectTimer);
      wsRef.current?.close();
    };
  }, []);

  return { alerts, incidents, metrics, getWireData, getArrivals, getLastArrival };
}
