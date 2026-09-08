/**
 * The chat dock (spec 6.5 and 9).
 *
 * The properties worth pinning are the ones that make the layer defensible
 * rather than the ones that make it pretty:
 *
 *   * It stays out of the way until asked for, and does not touch :8100 while
 *     closed.
 *   * An answer renders its claims from the citations array, and reference
 *     material is visibly not measurement.
 *   * A locally-rendered answer is badged as one rather than passed off as
 *     model output.
 *   * An absent service produces the spec's exact sentence, once, in the turn
 *     that failed - and the dock keeps working afterwards.
 */
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AnalystChat } from "../AnalystChat";
import { AnalystUnavailable } from "../../lib/api";
import type { AnalystAnswer, AnalystHealth } from "../../lib/types";

vi.mock("../../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../../lib/api")>("../../lib/api");
  return {
    ...actual,
    analyst: { explain: vi.fn(), ask: vi.fn(), narrate: vi.fn(), health: vi.fn() },
  };
});

const { analyst } = await import("../../lib/api");

const HEALTH: AnalystHealth = {
  status: "ok",
  provider: "gemini",
  model: "gemini-2.5-flash-lite",
  generation_enabled: true,
  alert_store: "http://127.0.0.1:8000",
  alert_store_reachable: true,
};

/** A knowledge answer: no alerts matched, and the reference material carries
 *  the question anyway. This is the shape the chatbot exists to produce. */
const KNOWLEDGE_ANSWER: AnalystAnswer = {
  subject: "what is dns tunnelling?",
  kind: "corpus",
  text: "DNS tunnelling carries data inside DNS queries rather than using DNS to look names up.",
  generated: true,
  provider: "gemini",
  model: "gemini-2.5-flash-lite",
  degraded_reason: null,
  citations: [
    { text: "No stored alert matches this query.", source: "GET /api/v1/alerts", value: 0 },
    {
      text: "DNS Tunnelling: a host is carrying data inside DNS queries.",
      source: "knowledge base: dns_tunnelling",
    },
    { text: "It maps to MITRE ATT&CK T1071.004.", source: "knowledge base: dns_tunnelling" },
  ],
  alert_ids: [],
  interpreted_as: ["threat class: dns_tunnelling"],
};

function open() {
  fireEvent.click(screen.getByRole("button", { name: /ask analyst/i }));
}

function askFor(text: string) {
  fireEvent.change(screen.getByLabelText(/ask the analyst a question/i), {
    target: { value: text },
  });
  fireEvent.click(screen.getByRole("button", { name: "Ask" }));
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("AnalystChat", () => {
  it("stays closed and silent until it is opened", () => {
    render(<AnalystChat />);
    expect(screen.getByRole("button", { name: /ask analyst/i })).toBeTruthy();
    expect(screen.queryByLabelText(/ask the analyst a question/i)).toBeNull();
    // A dock nobody opened is not a reason to send a request to Layer 8.
    expect(analyst.health).not.toHaveBeenCalled();
  });

  it("answers a threat question and cites the knowledge base apart from measurement", async () => {
    vi.mocked(analyst.health).mockResolvedValue(HEALTH);
    vi.mocked(analyst.ask).mockResolvedValue(KNOWLEDGE_ANSWER);

    render(<AnalystChat />);
    open();
    askFor("what is dns tunnelling?");

    await waitFor(() => expect(screen.getByText(/carries data inside DNS queries/)).toBeTruthy());
    expect(analyst.ask).toHaveBeenCalledWith("what is dns tunnelling?");

    // The question stays on screen above its answer.
    expect(screen.getByText("what is dns tunnelling?")).toBeTruthy();

    // Claims come from the citations array, and a reference source is labelled
    // as reference rather than presented as a stored field.
    // Both knowledge citations, each labelled; neither borrows an evidence key.
    expect(screen.getAllByText(/reference · dns_tunnelling/)).toHaveLength(2);
    expect(screen.getByText("[GET /api/v1/alerts]")).toBeTruthy();
    expect(screen.getByText(/1 measured, 2 reference/)).toBeTruthy();
  });

  it("badges a locally rendered answer rather than passing it off as model output", async () => {
    vi.mocked(analyst.health).mockResolvedValue({
      ...HEALTH,
      provider: "template",
      model: null,
      generation_enabled: false,
    });
    vi.mocked(analyst.ask).mockResolvedValue({
      ...KNOWLEDGE_ANSWER,
      generated: false,
      provider: "template",
      model: null,
      degraded_reason: "the generated text quoted 4.7, which no stored evidence field supports",
    });

    render(<AnalystChat />);
    open();
    await waitFor(() => expect(screen.getByText(/no model · local rendering/i)).toBeTruthy());

    askFor("explain beaconing");
    await waitFor(() => expect(screen.getByText(/rendered locally · no model/i)).toBeTruthy());
    // The rejection is the system working; saying why beats hiding it.
    expect(screen.getByText(/generation declined:.*4\.7/)).toBeTruthy();
  });

  it("states the absence of the service without apologising, and keeps working", async () => {
    vi.mocked(analyst.health).mockRejectedValue(new AnalystUnavailable());
    vi.mocked(analyst.ask).mockRejectedValueOnce(new AnalystUnavailable());

    render(<AnalystChat />);
    open();
    askFor("anything critical in the last hour?");

    await waitFor(() =>
      expect(screen.getByText("Analyst unavailable. Detection is unaffected.")).toBeTruthy()
    );
    expect(screen.queryByText(/sorry/i)).toBeNull();

    // The dock is not wedged by one failure: the next question still runs, and
    // lands in its own turn rather than overwriting the failed one.
    vi.mocked(analyst.ask).mockResolvedValue(KNOWLEDGE_ANSWER);
    askFor("what is dns tunnelling?");

    await waitFor(() => expect(screen.getByText(/carries data inside DNS queries/)).toBeTruthy());
    expect(screen.getByText("Analyst unavailable. Detection is unaffected.")).toBeTruthy();
  });

  it("sends an opener as a question", async () => {
    vi.mocked(analyst.health).mockResolvedValue(HEALTH);
    vi.mocked(analyst.ask).mockResolvedValue(KNOWLEDGE_ANSWER);

    render(<AnalystChat />);
    open();
    fireEvent.click(screen.getByText("Explain beaconing"));

    await waitFor(() => expect(analyst.ask).toHaveBeenCalledWith("Explain beaconing"));
  });

  it("sends on Enter, which is how the question actually gets asked", async () => {
    vi.mocked(analyst.health).mockResolvedValue(HEALTH);
    vi.mocked(analyst.ask).mockResolvedValue(KNOWLEDGE_ANSWER);

    render(<AnalystChat />);
    open();
    const field = screen.getByLabelText(/ask the analyst a question/i);
    fireEvent.change(field, { target: { value: "what is a port scan" } });
    fireEvent.keyDown(field, { key: "Enter" });

    await waitFor(() => expect(analyst.ask).toHaveBeenCalledWith("what is a port scan"));
    // The field clears, so the next question does not start with the last one.
    expect((field as HTMLInputElement).value).toBe("");
  });

  it("opens on / from anywhere, and not while something else is being typed into", () => {
    vi.mocked(analyst.health).mockResolvedValue(HEALTH);
    render(<AnalystChat />);

    // A "/" typed into a field is a slash, not a shortcut. The alert stream's
    // host filter is an input on the same screen.
    const elsewhere = document.createElement("input");
    document.body.appendChild(elsewhere);
    elsewhere.focus();
    fireEvent.keyDown(window, { key: "/" });
    expect(screen.queryByLabelText(/ask the analyst a question/i)).toBeNull();

    elsewhere.blur();
    document.body.removeChild(elsewhere);
    fireEvent.keyDown(window, { key: "/" });
    expect(screen.getByLabelText(/ask the analyst a question/i)).toBeTruthy();
  });

  it("stands down while the analyst panel is open, and an open dock does not", async () => {
    vi.mocked(analyst.health).mockResolvedValue(HEALTH);
    vi.mocked(analyst.ask).mockResolvedValue(KNOWLEDGE_ANSWER);

    // The panel docks to the right edge and its ask input sits in a footer
    // outside any scroll region, so the launcher landed on top of it.
    const { rerender } = render(<AnalystChat suppressed />);
    expect(screen.queryByRole("button", { name: /ask analyst/i })).toBeNull();
    // The shortcut goes with it, or "/" would drop a dock over that panel.
    fireEvent.keyDown(window, { key: "/" });
    expect(screen.queryByLabelText(/ask the analyst a question/i)).toBeNull();

    rerender(<AnalystChat suppressed={false} />);
    expect(screen.getByRole("button", { name: /ask analyst/i })).toBeTruthy();

    // An already-open dock is never closed by the panel opening behind it:
    // that would take away what someone is reading.
    open();
    askFor("what is dns tunnelling?");
    await waitFor(() => expect(screen.getByText(/carries data inside DNS queries/)).toBeTruthy());

    rerender(<AnalystChat suppressed />);
    expect(screen.getByText(/carries data inside DNS queries/)).toBeTruthy();
  });

  it("does not let typing reach the stream's global j/k bindings", () => {
    vi.mocked(analyst.health).mockResolvedValue(HEALTH);
    const onKey = vi.fn();
    window.addEventListener("keydown", onKey);

    render(<AnalystChat />);
    open();
    fireEvent.keyDown(screen.getByLabelText(/ask the analyst a question/i), { key: "j" });

    expect(onKey).not.toHaveBeenCalled();
    window.removeEventListener("keydown", onKey);
  });
});
