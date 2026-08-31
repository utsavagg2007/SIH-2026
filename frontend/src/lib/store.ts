/**
 * Live-feed state.
 *
 * Two performance rules from the design spec section 8.2, both load-bearing
 * during the DDoS demo:
 *
 *   * Ring buffer capped at 500 alerts, so memory stays flat during a flood.
 *     Older alerts remain available over REST.
 *   * Batch state updates on an animation frame. Never call a state setter per
 *     message - accumulate incoming alerts and flush once per frame.
 *
 * The Wire reads from `wireRef` directly rather than from React state, so the
 * animation loop never triggers a render.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { connectFeed, type ConnState } from "./api";
import type { Alert, Frame, Incident, MetricsFrame } from "./types";

const RING = 500;

export interface WireMark {
  t: number;
  severity: string;
  code: string;
  alertId: string;
}

export interface WireBuffer {
  marks: WireMark[];
  /** Alerts-per-second samples, one per metrics frame, for the density trace. */
  density: { t: number; v: number }[];
}

export interface LiveState {
  alerts: Alert[];
  incidents: Incident[];
  /** The last metrics frame as it arrived on the socket. Kept in wire
   *  shape rather than mapped to a view model here: the System view needs
   *  fields the instrument bar does not, and re-deriving them from a lossy
   *  intermediate is how the two screens drift apart. */
  metrics: MetricsFrame | null;
  conn: ConnState;
  /** Alerts received since load, including ones evicted from the ring. */
  received: number;
}

export function useLiveFeed() {
  const [state, setState] = useState<LiveState>({
    alerts: [],
    incidents: [],
    metrics: null,
    conn: "connecting",
    received: 0,
  });

  // Accumulators drained once per animation frame.
  const pending = useRef<Alert[]>([]);
  const pendingIncidents = useRef<Incident[]>([]);
  const pendingMetrics = useRef<MetricsFrame | null>(null);
  const raf = useRef<number | undefined>(undefined);

  // Read by the Wire's own rAF loop. Deliberately outside React state.
  const wire = useRef<WireBuffer>({ marks: [], density: [] });

  const flush = useCallback(() => {
    raf.current = undefined;
    const incoming = pending.current;
    const incidents = pendingIncidents.current;
    const metrics = pendingMetrics.current;
    if (!incoming.length && !incidents.length && !metrics) return;
    pending.current = [];
    pendingIncidents.current = [];
    pendingMetrics.current = null;

    setState((prev) => {
      let alerts = prev.alerts;
      if (incoming.length) {
        const byId = new Map(alerts.map((a) => [a.alert_id, a]));
        for (const a of incoming) byId.set(a.alert_id, a);
        alerts = [...byId.values()]
          .sort((x, y) => y.ts - x.ts)
          .slice(0, RING);
      }

      let inc = prev.incidents;
      if (incidents.length) {
        const byId = new Map(inc.map((i) => [i.incident_id, i]));
        for (const i of incidents) byId.set(i.incident_id, i);
        inc = [...byId.values()]
          .sort((x, y) => y.updated_at - x.updated_at)
          .slice(0, 200);
      }

      return {
        alerts,
        incidents: inc,
        metrics: metrics ?? prev.metrics,
        conn: prev.conn,
        received: prev.received + incoming.length,
      };
    });
  }, []);

  const schedule = useCallback(() => {
    if (raf.current === undefined) {
      raf.current = requestAnimationFrame(flush);
    }
  }, [flush]);

  useEffect(() => {
    const onFrame = (f: Frame) => {
      switch (f.type) {
        case "snapshot": {
          const now = Date.now() / 1000;
          for (const a of f.data.alerts) {
            wire.current.marks.push({
              t: a.ts,
              severity: a.severity,
              code: a.threat_code,
              alertId: a.alert_id,
            });
          }
          // Only the last minute is on screen; drop the rest immediately so a
          // large snapshot does not leave stale marks in the buffer.
          wire.current.marks = wire.current.marks.filter((m) => m.t > now - 60);
          pending.current.push(...f.data.alerts);
          pendingIncidents.current.push(...f.data.incidents);
          pendingMetrics.current = f.data.metrics;
          schedule();
          break;
        }
        case "alert.created":
        case "alert.updated":
          pending.current.push(f.data);
          wire.current.marks.push({
            t: f.data.ts,
            severity: f.data.severity,
            code: f.data.threat_code,
            alertId: f.data.alert_id,
          });
          if (wire.current.marks.length > 800) {
            wire.current.marks.splice(0, wire.current.marks.length - 800);
          }
          schedule();
          break;
        case "incident.created":
        case "incident.updated":
          pendingIncidents.current.push(f.data);
          schedule();
          break;
        case "metrics":
          pendingMetrics.current = f.data;
          wire.current.density.push({
            t: f.data.ts,
            v: f.data.alerts_per_sec,
          });
          if (wire.current.density.length > 120) wire.current.density.shift();
          schedule();
          break;
        default:
          break;
      }
    };

    const disconnect = connectFeed(onFrame, (conn) =>
      setState((p) => ({ ...p, conn }))
    );
    return () => {
      disconnect();
      if (raf.current !== undefined) cancelAnimationFrame(raf.current);
    };
  }, [schedule]);

  return { ...state, wire };
}
