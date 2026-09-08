/**
 * REST client and the live WebSocket feed.
 *
 * React talks to FastAPI directly. There is no Node tier in between: the design
 * spec rules one out for exactly the path where latency is graded.
 */

import type {
  Alert,
  AnalystAnswer,
  AnalystHealth,
  Capture,
  ConstraintProof,
  DetectorStatus,
  Frame,
  Health,
  HostView,
  Incident,
  MetricsFrame,
  ReplayStatus,
  Throughput,
} from "./types";

/**
 * Where the backend REST API lives.
 *
 * Relative by default, which is correct under the Vite dev proxy and correct
 * again when the backend serves the built bundle itself. It is NOT correct when
 * the bundle is hosted on a different origin (Vercel) from the API (Render):
 * there is no proxy there, so every call would hit the static host and 404.
 * Set VITE_API_BASE at build time to the absolute API root in that deployment.
 */
const BASE =
  (import.meta.env?.VITE_API_BASE as string | undefined) || "/api/v1";

/**
 * Where the analyst service lives.
 *
 * Same-origin by default, which is correct under the Vite dev server: its proxy
 * routes `/api/v1/analyst` to :8100 ahead of the backend rule. It is NOT correct
 * when the built bundle is served by the backend itself on :8000, because that
 * process does not serve those routes and the call 404s - the analyst panel
 * would report a healthy service as broken.
 *
 * So the base is a build-time setting. To serve the bundle from the backend and
 * still reach Layer 8:
 *
 *     VITE_ANALYST_BASE=http://127.0.0.1:8100/api/v1/analyst npm run build
 *
 * The analyst allows that origin in its CORS list. Left unset, this is exactly
 * the previous behaviour.
 */
const ANALYST_BASE =
  (import.meta.env?.VITE_ANALYST_BASE as string | undefined) || `${BASE}/analyst`;

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
  host: (ip: string) => get<HostView>(`/hosts/${encodeURIComponent(ip)}`),

  health: () => get<Health>("/system/health"),
  throughput: () => get<Throughput>("/system/throughput"),
  constraints: () => get<ConstraintProof>("/system/constraints"),
  /** Per-detector state, versions and mean scoring time. The System view reads
   *  this rather than inventing figures: the backend measures all three, and a
   *  fabricated latency on a screen whose purpose is proving throughput is a
   *  correctness bug, not a placeholder. */
  detectors: () =>
    get<{ items: DetectorStatus[]; online: number; total: number }>("/system/detectors"),
  /** The same frame pushed over the WebSocket once per second, over REST. Used
   *  as a fallback where a view needs metrics without holding a socket. */
  metricsFrame: () => get<MetricsFrame>("/system/metrics"),

  captures: () => get<{ items: Capture[] }>("/replay/captures"),
  replayStatus: () => get<ReplayStatus>("/replay/status"),
  /**
   * `ReplayStartRequest` in the backend accepts `loop`, and the replay screen
   * has always had a checkbox for it, but the flag was never put on the wire -
   * so the control moved and nothing happened. Options object rather than a
   * fourth positional argument: `(capture, speed, maxRate, loop)` puts two
   * optionals of different types in a row, which is how the flag went missing
   * in the first place.
   */
  replayStart: (
    capture: string,
    speed: number,
    opts: { maxRate?: number; loop?: boolean } = {}
  ) =>
    post<ReplayStatus>("/replay/start", {
      capture,
      speed,
      loop: opts.loop ?? false,
      max_rate: opts.maxRate ?? null,
    }),
  replayStop: () => post<ReplayStatus>("/replay/stop"),

  telemetry: (body: Record<string, unknown>) =>
    post<void>("/telemetry", body),
};

/**
 * Layer 8 runs in its own process on its own port (see analyst/README.md), and
 * that separation is the point: stop it and nothing upstream changes. The dev
 * proxy routes `/api/v1/analyst` to :8100 ahead of the backend rule, so the
 * paths below stay relative and the browser never learns there are two
 * services.
 *
 * Every call here can fail without consequence. `AnalystUnavailable` marks the
 * failures that mean "the service is not there" - a transport error, or a 502
 * or 503 from a proxy with nothing to reach - so the panel can say so in the
 * register spec 9 asks for instead of showing a stack trace.
 */
export class AnalystUnavailable extends Error {
  constructor(message = "Analyst unavailable. Detection is unaffected.") {
    super(message);
    this.name = "AnalystUnavailable";
  }
}

async function analystPost<T>(path: string, body: unknown): Promise<T> {
  let r: Response;
  try {
    r = await fetch(`${ANALYST_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    // Connection refused, DNS failure, proxy with no upstream. The service is
    // not running; that is a statement about the analyst layer and nothing else.
    throw new AnalystUnavailable();
  }
  if (r.status === 502 || r.status === 503 || r.status === 504) {
    throw new AnalystUnavailable();
  }
  if (!r.ok) {
    // A 404 or 422 is the service answering, so it is reported as itself: the
    // analyst is up and this particular request did not resolve.
    let detail = `${r.status} ${r.statusText}`;
    try {
      const j = await r.json();
      detail = j.detail ?? detail;
    } catch {
      /* non-JSON error body; the status line is what we have */
    }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return (await r.json()) as T;
}

export const analyst = {
  explain: (alertId: string) =>
    analystPost<AnalystAnswer>("/explain", { alert_id: alertId }),
  narrate: (incidentId: string) =>
    analystPost<AnalystAnswer>("/narrate", { incident_id: incidentId }),
  ask: (question: string, limit?: number) =>
    analystPost<AnalystAnswer>("/ask", { question, limit: limit ?? null }),
  health: async (): Promise<AnalystHealth> => {
    let r: Response;
    try {
      r = await fetch(`${ANALYST_BASE}/health`);
    } catch {
      throw new AnalystUnavailable();
    }
    if (!r.ok) throw new AnalystUnavailable();
    return (await r.json()) as AnalystHealth;
  },
};

/**
 * The live feed's address.
 *
 * Same-origin by default. A Vercel-hosted bundle cannot reach the socket that
 * way and cannot be rescued by a rewrite either - Vercel's rewrites do not
 * upgrade a WebSocket - so a split-origin deploy must point VITE_WS_URL
 * straight at the backend, e.g. wss://sih-backend.onrender.com/ws/alerts.
 */
export const WS_URL =
  (import.meta.env?.VITE_WS_URL as string | undefined) ||
  `${location.protocol === "https:" ? "wss:" : "ws:"}//${location.host}/ws/alerts`;

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
    ws = new WebSocket(WS_URL);

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
