/**
 * Regression test for spec 8.2: "Memoize the evidence panel on alert id. It
 * re-renders on every stream update otherwise."
 *
 * The parent re-renders once per animation frame while the feed runs, and this
 * subtree is the most expensive in the product. The test counts renders of the
 * panel's own body across parent updates that did not change which alert is
 * selected.
 */
import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EvidencePanel } from "../EvidencePanel";
import type { Alert } from "../../lib/types";

const renders = vi.fn();
vi.mock("../visuals", () => ({
  classVisual: () => {
    renders();
    return null;
  },
}));

function makeAlert(over: Partial<Alert> = {}): Alert {
  return {
    alert_id: "a1",
    ts: 1735689612.88,
    src_ip: "10.4.2.19",
    dst_ip: "185.22.11.8",
    dst_port: 443,
    threat_class: "c2_beaconing",
    threat_code: "BC",
    confidence: 0.91,
    severity: "high",
    occurrences: 1,
    last_seen: 1735689612.88,
    evidence: [],
    visual: { kind: "none" },
    ...over,
  } as unknown as Alert;
}

afterEach(() => {
  cleanup();
  renders.mockClear();
});

describe("EvidencePanel memoization", () => {
  it("does not re-render when the stream flushes but the selection is unchanged", () => {
    const onOpenHost = () => {};
    const alert = makeAlert();
    const { rerender } = render(<EvidencePanel alert={alert} onOpenHost={onOpenHost} />);
    expect(renders).toHaveBeenCalledTimes(1);

    // 60 parent re-renders, one per animation frame, same selected alert. The
    // regression rendered the whole subtree 60 more times.
    for (let i = 0; i < 60; i++) {
      rerender(<EvidencePanel alert={alert} onOpenHost={onOpenHost} />);
    }
    expect(renders).toHaveBeenCalledTimes(1);
  });

  it("does not re-render for a newly-constructed object describing the same alert", () => {
    // The feed rebuilds alert objects on every flush, so identity comparison
    // alone would defeat the memo entirely.
    const onOpenHost = () => {};
    const { rerender } = render(<EvidencePanel alert={makeAlert()} onOpenHost={onOpenHost} />);
    rerender(<EvidencePanel alert={makeAlert()} onOpenHost={onOpenHost} />);
    expect(renders).toHaveBeenCalledTimes(1);
  });

  it("re-renders when the operator selects a different alert", () => {
    const onOpenHost = () => {};
    const { rerender } = render(<EvidencePanel alert={makeAlert()} onOpenHost={onOpenHost} />);
    rerender(<EvidencePanel alert={makeAlert({ alert_id: "a2" })} onOpenHost={onOpenHost} />);
    expect(renders).toHaveBeenCalledTimes(2);
  });

  it("re-renders when the selected alert's own dedup state advances", () => {
    // A repeating alert keeps its id. Memoizing on the id alone would freeze
    // the occurrence count of the alert the operator is watching.
    const onOpenHost = () => {};
    const { rerender } = render(<EvidencePanel alert={makeAlert()} onOpenHost={onOpenHost} />);
    rerender(
      <EvidencePanel alert={makeAlert({ occurrences: 2, last_seen: 1735689699 })} onOpenHost={onOpenHost} />
    );
    expect(renders).toHaveBeenCalledTimes(2);
  });
});
