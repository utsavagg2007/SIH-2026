/**
 * Regression tests for the REST client.
 *
 * Two behavioural fixes are pinned here:
 *
 *   * The replay `loop` flag reached the backend. It was a dead control: the
 *     checkbox had state, the backend had `ReplayStartRequest.loop`, and the
 *     value was dropped in between.
 *
 *   * A missing analyst service is distinguishable from a request the analyst
 *     declined. Spec 6.5 requires the panel to say the layer is unavailable
 *     without disturbing anything else, and it can only do that if the client
 *     tells it which kind of failure occurred.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { analyst, api, AnalystUnavailable } from "../api";

function jsonOk(body: unknown) {
  return { ok: true, status: 200, statusText: "OK", json: async () => body } as Response;
}

/** Typed stand-in for `fetch`, so `mock.calls[0]` has known argument types
 *  rather than the empty tuple a zero-arg `vi.fn` infers. */
type FetchStub = (url: string, init?: RequestInit) => Promise<Response>;

function lastCall(fetchMock: ReturnType<typeof vi.fn<FetchStub>>) {
  return fetchMock.mock.calls[0];
}

function lastBody(fetchMock: ReturnType<typeof vi.fn<FetchStub>>) {
  return JSON.parse(lastCall(fetchMock)[1]!.body as string);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api.replayStart", () => {
  it("puts the loop flag on the wire", () => {
    const f = vi.fn<FetchStub>(async () => jsonOk({}));
    vi.stubGlobal("fetch", f);

    void api.replayStart("beacon.jsonl", 10, { loop: true });

    // The regression: this key was absent entirely, so the backend applied its
    // `loop: bool = False` default and the checkbox did nothing.
    expect(lastBody(f)).toMatchObject({ capture: "beacon.jsonl", speed: 10, loop: true });
  });

  it("defaults loop to false rather than omitting it", () => {
    const f = vi.fn<FetchStub>(async () => jsonOk({}));
    vi.stubGlobal("fetch", f);
    void api.replayStart("beacon.jsonl", 1);
    expect(lastBody(f)).toMatchObject({ loop: false, max_rate: null });
  });

  it("still carries max_rate, which shares the options object", () => {
    const f = vi.fn<FetchStub>(async () => jsonOk({}));
    vi.stubGlobal("fetch", f);
    void api.replayStart("flood.jsonl", 50, { maxRate: 400, loop: true });
    expect(lastBody(f)).toMatchObject({ max_rate: 400, loop: true, speed: 50 });
  });
});

describe("analyst client", () => {
  it("routes explain to the analyst prefix with the alert id", async () => {
    const f = vi.fn<FetchStub>(async () => jsonOk({ text: "", generated: false, citations: [] }));
    vi.stubGlobal("fetch", f);

    await analyst.explain("a7f3c210");

    expect(lastCall(f)[0]).toBe("/api/v1/analyst/explain");
    expect(lastBody(f)).toEqual({ alert_id: "a7f3c210" });
  });

  it("reports a refused connection as the layer being unavailable", async () => {
    // No process on :8100. This must not read as a failed alert lookup.
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("Failed to fetch"); }));
    await expect(analyst.explain("a1")).rejects.toBeInstanceOf(AnalystUnavailable);
  });

  it("reports a proxy with no upstream as unavailable", async () => {
    for (const status of [502, 503, 504]) {
      vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status, statusText: "" }) as Response));
      await expect(analyst.ask("how many beacons")).rejects.toBeInstanceOf(AnalystUnavailable);
    }
  });

  it("does NOT report a 404 as unavailable - the service answered", async () => {
    // An unknown alert id is the analyst working correctly. Calling that
    // "unavailable" would tell the operator to go restart a healthy service.
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: false, status: 404, statusText: "Not Found",
      json: async () => ({ detail: "alert not found" }),
    }) as Response));

    const err = await analyst.explain("nope").catch((e) => e);
    expect(err).not.toBeInstanceOf(AnalystUnavailable);
    expect(err.message).toBe("alert not found");
  });

  it("passes narrate an incident id", async () => {
    const f = vi.fn<FetchStub>(async () => jsonOk({ text: "", generated: true, citations: [] }));
    vi.stubGlobal("fetch", f);
    await analyst.narrate("inc-9");
    expect(lastCall(f)[0]).toBe("/api/v1/analyst/narrate");
    expect(lastBody(f)).toEqual({ incident_id: "inc-9" });
  });
});
