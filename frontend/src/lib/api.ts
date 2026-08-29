/**
 * REST client and the live WebSocket feed.
 *
 * React talks to FastAPI directly. There is no Node tier in between: the design
 * spec rules one out for exactly the path where latency is graded.
 */

import type {
  Alert,
  Capture,
  ConstraintProof,
  Frame,
  Health,
  Incident,
  ReplayStatus,
  Throughput,
} from "./types";

const BASE = "/api/v1";

async function get<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE}${path}`);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} on ${path}`);
  return r.json() as Promise<T>;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const r = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!r.ok) {
    let detail = `${r.status} ${r.statusText}`;
    try {
      const j = await r.json();
      detail = j.detail ?? JSON.stringify(j);
    } catch {
      /* non-JSON error body; the status line is what we have */
    }
    throw new Error(detail);
  }
  return (r.status === 204 ? undefined : await r.json()) as T;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export const api = {
  alerts: (q: Record<string, string | number | undefined> = {}) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(q)) {
      if (v !== undefined && v !== "") p.set(k, String(v));
    }
    return get<Page<Alert>>(`/alerts?${p}`);
  },
  alert: (id: string) => get<Alert>(`/alerts/${encodeURIComponent(id)}`),
  incidents: () => get<{ items: Incident[]; total: number }>("/incidents"),
  incident: (id: string) =>
    get<{ incident: Incident; alerts: Alert[] }>(
      `/incidents/${encodeURIComponent(id)}`
    ),
  hosts: () => get<{ items: string[]; total: number }>("/hosts"),
  host: (ip: string) => get<any>(`/hosts/${encodeURIComponent(ip)}`),

  health: () => get<Health>("/system/health"),
  throughput: () => get<Throughput>("/system/throughput"),
  constraints: () => get<ConstraintProof>("/system/constraints"),

  captures: () => get<{ items: Capture[] }>("/replay/captures"),
  replayStatus: () => get<ReplayStatus>("/replay/status"),
  replayStart: (capture: string, speed: number, maxRate?: number) =>
    post<ReplayStatus>("/replay/start", {
      capture,
      speed,
      max_rate: maxRate ?? null,
    }),
  replayStop: () => post<ReplayStatus>("/replay/stop"),

  telemetry: (body: Record<string, unknown>) =>
    post<void>("/telemetry", body),
};

export type ConnState = "connecting" | "open" | "closed";

/**
 * Live feed with reconnect.
 *
 * Frames are handed to the caller one at a time; batching into React state is
 * the caller's job (spec 8.2: never call a state setter per message).
 */
export function connectFeed(
  onFrame: (f: Frame) => void,
  onState: (s: ConnState) => void
): () => void {
  let ws: WebSocket | null = null;
  let closed = false;
  let retry = 0;
  let timer: number | undefined;

  const open = () => {
    if (closed) return;
    onState("connecting");
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(`${proto}//${location.host}/ws/alerts`);

    ws.onopen = () => {
      retry = 0;
      onState("open");
    };
    ws.onmessage = (e) => {
      try {
        onFrame(JSON.parse(e.data) as Frame);
      } catch {
        // A frame we cannot parse is dropped rather than tearing down the feed.
        // The backend serialises with allow_nan=false precisely so this does
        // not happen; if it ever does, losing one frame beats losing the feed.
      }
    };
    ws.onclose = () => {
      onState("closed");
      if (closed) return;
      // Back off to 8s. The trace freezes and the bar says "feed stopped"
      // meanwhile - it never fakes movement (spec 3.2).
      retry = Math.min(retry + 1, 4);
      timer = window.setTimeout(open, 250 * 2 ** retry);
    };
    ws.onerror = () => ws?.close();
  };

  open();
  return () => {
    closed = true;
    if (timer) clearTimeout(timer);
    ws?.close();
  };
}
