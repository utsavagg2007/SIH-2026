import { describe, expect, it } from "vitest";
import { groupStream, rowIndexOfAlert } from "../group";
import type { Alert, Incident } from "../types";

function alert(over: Partial<Alert> & { alert_id: string; ts: number }): Alert {
  return {
    src_ip: "10.4.2.19",
    dst_ip: "185.62.11.4",
    dst_port: 443,
    threat_class: "c2_beaconing",
    threat_code: "BC",
    confidence: 0.9,
    severity: "high",
    occurrences: 1,
    evidence: [],
    visual: { kind: "none" },
    ...over,
  } as Alert;
}

const INC: Incident = {
  incident_id: "INC-1",
  pivot_host: "10.4.2.19",
  opened_at: 0,
  updated_at: 30,
  severity: "critical",
  alert_count: 9,
  members: [],
  elapsed_sec: 30,
  escalated: true,
};

describe("groupStream", () => {
  it("collapses an incident's members behind one header", () => {
    const rows = groupStream(
      [
        alert({ alert_id: "c", ts: 30, incident_id: "INC-1", severity: "critical", threat_code: "EX" }),
        alert({ alert_id: "b", ts: 20, incident_id: "INC-1", threat_code: "BC" }),
        alert({ alert_id: "a", ts: 10, incident_id: "INC-1", severity: "low", threat_code: "PS" }),
      ],
      [INC],
      new Set()
    );

    expect(rows).toHaveLength(1);
    expect(rows[0].kind).toBe("group");
    if (rows[0].kind !== "group") throw new Error("unreachable");
    const g = rows[0].group;
    expect(g.label).toBe("10.4.2.19");
    // Worst member wins, not the newest and not the first.
    expect(g.severity).toBe("critical");
    expect(g.shown).toBe(3);
    // The backend's exact count, kept distinct from what survived the filter.
    expect(g.total).toBe(9);
    // Oldest first: the sequence is the story.
    expect(g.codes).toEqual(["PS", "BC", "EX"]);
    expect(g.latest).toBe(30);
  });

  it("expands members under their header when open", () => {
    const rows = groupStream(
      [
        alert({ alert_id: "b", ts: 20, incident_id: "INC-1" }),
        alert({ alert_id: "a", ts: 10, incident_id: "INC-1" }),
      ],
      [INC],
      new Set(["INC-1"])
    );
    expect(rows.map((r) => r.kind)).toEqual(["group", "alert", "alert"]);
    expect(rowIndexOfAlert(rows, "a")).toBe(2);
  });

  it("never groups alerts the correlator left uncorrelated", () => {
    // Same host, same class, adjacent in time - and still two separate rows,
    // because grouping these would be a correlation claim made by the UI.
    const rows = groupStream(
      [alert({ alert_id: "b", ts: 20 }), alert({ alert_id: "a", ts: 19 })],
      [],
      new Set()
    );
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.kind === "alert")).toBe(true);
  });

  it("gives a one-member incident no header", () => {
    const rows = groupStream([alert({ alert_id: "a", ts: 10, incident_id: "INC-1" })], [INC], new Set());
    expect(rows).toEqual([{ kind: "alert", key: "a", alert: expect.anything(), depth: 0 }]);
  });

  it("orders groups by most recent activity, and survives a missing incident record", () => {
    const rows = groupStream(
      [
        alert({ alert_id: "d", ts: 40, incident_id: "INC-2" }),
        alert({ alert_id: "c", ts: 35, incident_id: "INC-2" }),
        alert({ alert_id: "b", ts: 20, incident_id: "INC-1" }),
        alert({ alert_id: "a", ts: 10, incident_id: "INC-1" }),
      ],
      [], // both incidents aged out of the buffer
      new Set()
    );
    // Every member shares a source address, so that is what the header is
    // named from - and it is flagged as derived, not as the correlator's pivot.
    expect(rows.map((r) => (r.kind === "group" ? r.group.label : "?"))).toEqual([
      "10.4.2.19",
      "10.4.2.19",
    ]);
    if (rows[0].kind !== "group") throw new Error("unreachable");
    expect(rows[0].group.labelDerived).toBe(true);
    // No incident record means no invented total.
    expect(rows[0].group.total).toBeUndefined();
  });

  it("falls back to the incident id when members disagree on a source", () => {
    const rows = groupStream(
      [
        alert({ alert_id: "b", ts: 20, incident_id: "INC-1", src_ip: "10.4.2.19" }),
        alert({ alert_id: "a", ts: 10, incident_id: "INC-1", src_ip: "10.4.9.9" }),
      ],
      [],
      new Set()
    );
    if (rows[0].kind !== "group") throw new Error("unreachable");
    expect(rows[0].group.label).toBe("INC-1");
    expect(rows[0].group.labelDerived).toBe(true);
  });

  it("prefers the correlator's pivot host over any derived one", () => {
    const rows = groupStream(
      [
        alert({ alert_id: "b", ts: 20, incident_id: "INC-1", src_ip: "10.4.9.9" }),
        alert({ alert_id: "a", ts: 10, incident_id: "INC-1", src_ip: "10.4.9.9" }),
      ],
      [INC],
      new Set()
    );
    if (rows[0].kind !== "group") throw new Error("unreachable");
    expect(rows[0].group.label).toBe("10.4.2.19");
    expect(rows[0].group.labelDerived).toBe(false);
  });
});
