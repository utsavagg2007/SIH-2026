/**
 * The live path must speak the backend's protocol.
 *
 * This hook previously connected to the Vite dev server's own port and branched
 * on frame names no server in this repository emits, so the wired-up screen
 * could not read the backend at all. Nothing caught it because there was no
 * test. These assert against the frame shapes in backend/app/core/hub.py and
 * backend/app/api/ws.py, so the two halves cannot drift apart again silently.
 */

import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useFeed } from "../useFeed";
import type { Alert } from "../../lib/types";

// -- a WebSocket double ----------------------------------------------------

class FakeSocket {
  static last: FakeSocket | null = null;
  static instances: FakeSocket[] = [];

  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  closed = false;

  constructor(public url: string) {
    FakeSocket.last = this;
    FakeSocket.instances.push(this);
  }
  close() {
    this.closed = true;
    this.onclose?.();
  }
  open() {
    this.onopen?.();
  }
  deliver(type: string, data: unknown) {
    this.onmessage?.({ data: JSON.stringify({ type, data }) });
  }
  deliverRaw(text: string) {
    this.onmessage?.({ data: text });
  }
}

function alert(id: string, overrides: Partial<Alert> = {}): Alert {
  return {
    alert_id: id,
    ts: 1_700_000_000,
    src_ip: "10.4.2.19",
    dst_ip: "185.62.11.4",
    dst_port: 443,
    threat_class: "c2_beaconing",
    threat_code: "BC",
    confidence: 0.91,
    severity: "critical",
    occurrences: 1,
    evidence: [],
    visual: null,
    ...overrides,
  } as Alert;
}

/** Drive the hook's two requestAnimationFrame loops forward one tick. */
async function frame() {
  await act(async () => {
    vi.advanceTimersByTime(20);
    await Promise.resolve();
  });
}

beforeEach(() => {
  FakeSocket.last = null;
  FakeSocket.instances = [];
  vi.stubGlobal("WebSocket", FakeSocket as unknown as typeof WebSocket);
  vi.useFakeTimers();
  let now = 0;
  vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) =>
    setTimeout(() => cb((now += 16)), 16) as unknown as number
  );
  vi.stubGlobal("cancelAnimationFrame", (id: number) => clearTimeout(id));
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("useFeed", () => {
  it("connects to the backend's alert socket, not the dev server", () => {
    renderHook(() => useFeed());
    expect(FakeSocket.last?.url).toContain("/ws/alerts");
    expect(FakeSocket.last?.url).not.toContain("5173");
  });

  it("loads the snapshot frame newest-first", async () => {
    const { result } = renderHook(() => useFeed());
    act(() => {
      FakeSocket.last!.open();
      // ws.py sends the recent window oldest-first.
      FakeSocket.last!.deliver("snapshot", {
        alerts: [alert("oldest"), alert("newest")],
        incidents: [],
        metrics: null,
      });
    });
    expect(result.current.alerts).toHaveLength(2);
    expect(result.current.alerts[0].alert_id).toBe("newest");
  });

  it("prepends alert.created", async () => {
    const { result } = renderHook(() => useFeed());
    act(() => {
      FakeSocket.last!.open();
      FakeSocket.last!.deliver("alert.created", alert("a1"));
    });
    await frame();
    expect(result.current.alerts.map((a) => a.alert_id)).toEqual(["a1"]);
  });

  it("alert.updated replaces a row instead of adding one", async () => {
    // The point of deduplication. The frame carries the SURVIVING alert_id, so
    // sixty beacon check-ins must leave one row with occurrences at sixty - not
    // sixty rows.
    const { result } = renderHook(() => useFeed());
    act(() => {
      FakeSocket.last!.open();
      FakeSocket.last!.deliver("alert.created", alert("beacon", { occurrences: 1 }));
    });
    await frame();

    for (let i = 2; i <= 60; i++) {
      act(() => {
        FakeSocket.last!.deliver("alert.updated", alert("beacon", { occurrences: i }));
      });
      await frame();
    }

    expect(result.current.alerts).toHaveLength(1);
    expect(result.current.alerts[0].occurrences).toBe(60);
  });

  it("an update for an alert it never saw is added rather than dropped", async () => {
    // A dashboard that connected mid-run has no row to replace, and losing the
    // finding entirely would be worse than showing it late.
    const { result } = renderHook(() => useFeed());
    act(() => {
      FakeSocket.last!.open();
      FakeSocket.last!.deliver("alert.updated", alert("unseen", { occurrences: 7 }));
    });
    await frame();
    expect(result.current.alerts.map((a) => a.alert_id)).toEqual(["unseen"]);
  });

  it("upserts incidents by id", async () => {
    const { result } = renderHook(() => useFeed());
    act(() => {
      FakeSocket.last!.open();
      FakeSocket.last!.deliver("incident.created", {
        incident_id: "INC-1",
        alert_count: 1,
      });
      FakeSocket.last!.deliver("incident.updated", {
        incident_id: "INC-1",
        alert_count: 3,
      });
    });
    expect(result.current.incidents).toHaveLength(1);
    expect(result.current.incidents[0].alert_count).toBe(3);
  });

  it("reads the metrics frame", async () => {
    const { result } = renderHook(() => useFeed());
    act(() => {
      FakeSocket.last!.open();
      FakeSocket.last!.deliver("metrics", {
        flows_per_sec: 3412,
        packets_per_sec: 41200,
        mbps: 284.1,
        traffic_telemetry_live: true,
        latency_p50_ms: 18.4,
        latency_p95_ms: 42.7,
        detectors_online: 7,
        detectors_total: 7,
        uptime_s: 862,
      });
    });
    expect(result.current.metrics.flowsPerSec).toBe(3412);
    expect(result.current.metrics.p95).toBe(43);
    expect(result.current.metrics.detectorsOnline).toBe(7);
    expect(result.current.metrics.trafficLive).toBe(true);
  });

  it("never invents a Wire density sample when telemetry is not live", async () => {
    // The previous implementation drew the density trace from
    // `3200 + Math.random() * 800`. On a product whose argument is that every
    // number came from an observation, that was the worst defect in the tree.
    const { result } = renderHook(() => useFeed());
    act(() => {
      FakeSocket.last!.open();
      FakeSocket.last!.deliver("metrics", {
        flows_per_sec: 0,
        mbps: 0,
        traffic_telemetry_live: false,
        latency_p50_ms: 0,
        latency_p95_ms: 0,
        detectors_online: 7,
        detectors_total: 7,
        uptime_s: 5,
      });
      FakeSocket.last!.deliver("alert.created", alert("a1"));
    });
    await frame();

    expect(result.current.getWireData().samples).toHaveLength(0);
    expect(result.current.metrics.trafficLive).toBe(false);
    // The detection mark still lands: an alert IS an observation.
    expect(result.current.getWireData().marks).toHaveLength(1);
  });

  it("marks carry the real threat code and severity colour", async () => {
    const { result } = renderHook(() => useFeed());
    act(() => {
      FakeSocket.last!.open();
      FakeSocket.last!.deliver(
        "alert.created",
        alert("a1", { threat_code: "PS", severity: "high" })
      );
    });
    await frame();
    const [m] = result.current.getWireData().marks;
    expect(m.code).toBe("PS");
    expect(m.color).toBeTruthy();
  });

  it("an unknown frame type does not break the feed", async () => {
    const { result } = renderHook(() => useFeed());
    act(() => {
      FakeSocket.last!.open();
      FakeSocket.last!.deliver("some.future.frame", { anything: true });
      FakeSocket.last!.deliver("alert.created", alert("a1"));
    });
    await frame();
    expect(result.current.alerts).toHaveLength(1);
  });

  it("an unparseable frame does not break the feed", async () => {
    const { result } = renderHook(() => useFeed());
    act(() => {
      FakeSocket.last!.open();
      FakeSocket.last!.deliverRaw("{not json");
      FakeSocket.last!.deliver("alert.created", alert("a1"));
    });
    await frame();
    expect(result.current.alerts).toHaveLength(1);
  });

  it("reports the feed as stopped on close and reconnects", async () => {
    const { result } = renderHook(() => useFeed());
    act(() => FakeSocket.last!.open());
    expect(result.current.metrics.connected).toBe(true);

    act(() => FakeSocket.last!.close());
    expect(result.current.metrics.connected).toBe(false);

    await act(async () => {
      vi.advanceTimersByTime(2100);
    });
    expect(FakeSocket.instances.length).toBeGreaterThan(1);
  });

  it("caps the stream at 500 alerts so memory stays flat under a flood", async () => {
    const { result } = renderHook(() => useFeed());
    act(() => {
      FakeSocket.last!.open();
      for (let i = 0; i < 700; i++) {
        FakeSocket.last!.deliver("alert.created", alert(`a${i}`));
      }
    });
    await frame();
    expect(result.current.alerts).toHaveLength(500);
  });
});
