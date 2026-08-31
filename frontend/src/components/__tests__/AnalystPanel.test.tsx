/**
 * Regression tests for the analyst panel (spec 6.5 and 9).
 *
 * The panel is the UI for a service that is deliberately allowed to be absent,
 * so the properties worth pinning are mostly about honesty:
 *
 *   * It explains the selected alert without anyone typing.
 *   * A locally-rendered answer is badged as one, and `degraded_reason` is
 *     shown rather than swallowed.
 *   * Every claim appears with the stored field it came from.
 *   * An absent service produces the spec's exact sentence, and no apology.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AnalystPanel } from "../AnalystPanel";
import { AnalystUnavailable } from "../../lib/api";
import type { Alert, AnalystAnswer } from "../../lib/types";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return {
    ...actual,
    analyst: { explain: vi.fn(), ask: vi.fn(), narrate: vi.fn(), health: vi.fn() },
  };
});

const { analyst } = await import("../../lib/api");

const ALERT = {
  alert_id: "a7f3c210",
  ts: 1735689612.88,
  src_ip: "10.4.2.19",
  dst_ip: "185.22.11.8",
  dst_port: 443,
  threat_class: "c2_beaconing",
  threat_code: "BC",
  confidence: 0.91,
  severity: "high",
  occurrences: 42,
  evidence: [],
  visual: { kind: "none" },
  incident_id: null,
} as unknown as Alert;

function answer(over: Partial<AnalystAnswer> = {}): AnalystAnswer {
  return {
    subject: "a7f3c210",
    kind: "alert",
    text: "A host on the internal network contacted one destination at a fixed interval.",
    generated: true,
    provider: "gemini",
    model: "gemini-2.5-flash-lite",
    degraded_reason: null,
    citations: [
      { text: "Intervals varied by 4.1%.", source: "evidence.coefficient_of_variation", value: 0.041 },
      { text: "42 connections were observed.", source: "occurrences, first_seen", value: 42 },
    ],
    alert_ids: ["a7f3c210"],
    ...over,
  };
}

afterEach(cleanup);

describe("AnalystPanel", () => {
  it("explains the selected alert without the user typing", async () => {
    vi.mocked(analyst.explain).mockResolvedValue(answer());
    render(<AnalystPanel alert={ALERT} onClose={() => {}} />);

    await waitFor(() => expect(analyst.explain).toHaveBeenCalledWith("a7f3c210"));
    expect(await screen.findByText(/contacted one destination at a fixed interval/)).toBeTruthy();
  });

  it("renders every claim with the stored field it came from", async () => {
    vi.mocked(analyst.explain).mockResolvedValue(answer());
    render(<AnalystPanel alert={ALERT} onClose={() => {}} />);

    // Spec 6.5: statements that cannot be traced to a stored field must not be
    // shown at all, so claims are rendered from `citations`, each beside its
    // source field.
    expect(await screen.findByText("Intervals varied by 4.1%.")).toBeTruthy();
    expect(screen.getByText("[evidence.coefficient_of_variation]")).toBeTruthy();
    expect(screen.getByText("[occurrences, first_seen]")).toBeTruthy();
  });

  it("badges a locally-rendered answer instead of hiding it", async () => {
    vi.mocked(analyst.explain).mockResolvedValue(
      answer({ generated: false, provider: "template", model: null })
    );
    render(<AnalystPanel alert={ALERT} onClose={() => {}} />);

    expect(await screen.findByText(/rendered locally/i)).toBeTruthy();
  });

  it("surfaces degraded_reason when generation was declined", async () => {
    vi.mocked(analyst.explain).mockResolvedValue(
      answer({
        generated: false,
        degraded_reason: "model returned a figure absent from the fact sheet",
      })
    );
    render(<AnalystPanel alert={ALERT} onClose={() => {}} />);

    // The rejection is the verification layer working. Hiding it would waste
    // the strongest thing this layer has to show.
    expect(
      await screen.findByText(/model returned a figure absent from the fact sheet/)
    ).toBeTruthy();
  });

  it("states the spec's sentence when the service is absent, and does not apologise", async () => {
    vi.mocked(analyst.explain).mockRejectedValue(new AnalystUnavailable());
    render(<AnalystPanel alert={ALERT} onClose={() => {}} />);

    expect(
      await screen.findByText("Analyst unavailable. Detection is unaffected.")
    ).toBeTruthy();
    // Spec 9: nothing apologises - an instrument that apologises is an
    // instrument nobody trusts.
    expect(document.body.textContent).not.toMatch(/sorry|oops|apolog|went wrong/i);
  });

  it("does not call the service when no alert is selected", () => {
    render(<AnalystPanel alert={null} onClose={() => {}} />);
    expect(analyst.explain).not.toHaveBeenCalled();
    expect(screen.getByText(/No alert selected/)).toBeTruthy();
  });

  it("offers the narrate path only for an alert inside an incident", async () => {
    vi.mocked(analyst.explain).mockResolvedValue(answer());
    const { rerender } = render(<AnalystPanel alert={ALERT} onClose={() => {}} />);
    expect(screen.queryByText(/Narrate incident/)).toBeNull();

    rerender(<AnalystPanel alert={{ ...ALERT, incident_id: "inc-9" }} onClose={() => {}} />);
    expect(await screen.findByText(/Narrate incident/)).toBeTruthy();
  });
});
