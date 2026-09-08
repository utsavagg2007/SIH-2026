/**
 * Layer 8's surface (spec 6.5).
 *
 * A right-docked 380px panel. Not a page, and deliberately not a chat bubble:
 * the analyst is an annotation on the alert you are already looking at, so it
 * sits beside the evidence rather than replacing it or floating over it. The
 * chat bubble exists separately, in `AnalystChat` - a question you arrived
 * with is a different act from an explanation of what is already selected, and
 * conflating the two would make each worse. Both render answers through
 * `AnalystAnswer`, so provenance looks identical in either place.
 *
 * Three things this component holds to, all of them from the spec:
 *
 *   * Opening it with an alert selected explains that alert immediately. The
 *     analyst is worth nothing if the operator has to compose a prompt during
 *     an incident, so there is no empty input waiting for them.
 *
 *   * Every claim carries the stored field it came from. The service returns
 *     `citations` as atomic statements each tagged with its source field for
 *     exactly this, so the panel renders claims *from that array* rather than
 *     from prose. Spec 6.5: "Statements that cannot be traced to a stored field
 *     must not be shown at all" - rendering the citation list is what makes
 *     that structurally true instead of merely intended.
 *
 *   * `generated: false` is badged, never hidden. It means the text is the
 *     deterministic local rendering rather than model output, which is a
 *     stronger claim about provenance, not a weaker one. A judge asking "did
 *     an LLM write this" should be able to read the answer off the panel.
 *
 * When the service is down the panel says so in one line and everything else
 * on screen keeps working. This layer is never on the critical path, so it
 * fails quietly and factually - and it never apologises (spec 9).
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { X } from "lucide-react";
import { T, MONO, SANS, headingStyle, labelStyle } from "../lib/tokens";
import { analyst, AnalystUnavailable } from "../lib/api";
import { Answer } from "./AnalystAnswer";
import type { Alert, AnalystAnswer } from "../lib/types";

const PANEL_WIDTH = 380;

type Status =
  | { state: "idle" }
  | { state: "working"; note: string }
  | { state: "answered"; answer: AnalystAnswer }
  | { state: "unavailable" }
  | { state: "failed"; detail: string };

interface Props {
  alert: Alert | null;
  onClose: () => void;
}

export function AnalystPanel({ alert, onClose }: Props) {
  const [status, setStatus] = useState<Status>({ state: "idle" });
  const [question, setQuestion] = useState("");

  // Requests are numbered so a slow explain cannot overwrite the answer to a
  // question asked after it. The panel is driven by selection changes, so this
  // race is routine rather than exotic.
  const seq = useRef(0);

  const run = useCallback(
    async (note: string, call: () => Promise<AnalystAnswer>) => {
      const mine = ++seq.current;
      setStatus({ state: "working", note });
      try {
        const answer = await call();
        if (seq.current === mine) setStatus({ state: "answered", answer });
      } catch (e) {
        if (seq.current !== mine) return;
        if (e instanceof AnalystUnavailable) setStatus({ state: "unavailable" });
        else setStatus({ state: "failed", detail: e instanceof Error ? e.message : String(e) });
      }
    },
    []
  );

  const alertId = alert?.alert_id ?? null;
  const incidentId = alert?.incident_id ?? null;

  // Spec 6.5: opening with an alert selected produces the explanation without
  // the user typing anything. Keyed on the alert id, so moving the selection
  // with j/k re-explains as the operator walks the stream.
  useEffect(() => {
    if (!alertId) {
      setStatus({ state: "idle" });
      return;
    }
    void run("Reading stored evidence for this alert.", () => analyst.explain(alertId));
  }, [alertId, run]);

  const ask = () => {
    const q = question.trim();
    if (!q) return;
    void run("Querying stored alert history.", () => analyst.ask(q));
  };

  return (
    <aside
      style={{
        width: PANEL_WIDTH,
        flexShrink: 0,
        borderLeft: `1px solid ${T.rule}`,
        background: T.panel,
        display: "flex",
        flexDirection: "column",
        minHeight: 0,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", borderBottom: `1px solid ${T.rule}`, flexShrink: 0 }}>
        <span style={headingStyle}>Analyst</span>
        {alert && (
          <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {alert.alert_id}
          </span>
        )}
        <button
          onClick={onClose}
          aria-label="Close analyst panel"
          style={{ marginLeft: "auto", background: "none", border: "none", color: T.text3, cursor: "pointer", padding: 2, display: "flex" }}
        >
          <X size={14} />
        </button>
      </div>

      <div className="launcher-clearance" style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>
        {status.state === "idle" && (
          <div style={{ padding: 14, fontFamily: SANS, fontSize: 13, color: T.text3, lineHeight: 1.6 }}>
            No alert selected. Select one for an explanation, or ask a question below.
          </div>
        )}

        {status.state === "working" && (
          <div style={{ padding: 14, fontFamily: SANS, fontSize: 13, color: T.text3 }}>
            {status.note}
          </div>
        )}

        {status.state === "unavailable" && (
          // Spec 9, verbatim. It names what failed and what still works, and it
          // does not apologise - an instrument that apologises is an instrument
          // nobody trusts.
          <div style={{ padding: 14 }}>
            <div style={{ fontFamily: SANS, fontSize: 13, color: T.text2, lineHeight: 1.6 }}>
              Analyst unavailable. Detection is unaffected.
            </div>
            <div style={{ marginTop: 8, fontFamily: MONO, fontSize: 10, color: T.text3, lineHeight: 1.5 }}>
              Layer 8 runs as a separate process on :8100. Every other panel reads
              the backend directly and is unchanged by its absence.
            </div>
          </div>
        )}

        {status.state === "failed" && (
          <div style={{ padding: 14 }}>
            <div style={{ fontFamily: SANS, fontSize: 13, color: T.text2, lineHeight: 1.6 }}>
              Analyst reached, request not resolved.
            </div>
            <div style={{ marginTop: 6, fontFamily: MONO, fontSize: 11, color: T.text3, lineHeight: 1.5 }}>
              {status.detail}
            </div>
          </div>
        )}

        {status.state === "answered" && <Answer answer={status.answer} />}
      </div>

      <div style={{ borderTop: `1px solid ${T.rule}`, padding: 12, flexShrink: 0 }}>
        {incidentId && (
          <button
            onClick={() => void run("Narrating incident from stored alerts.", () => analyst.narrate(incidentId))}
            style={{
              width: "100%", marginBottom: 10, background: T.panel2, border: `1px solid ${T.rule}`,
              borderRadius: 2, color: T.text2, fontFamily: SANS, fontSize: 12, fontWeight: 600,
              padding: "6px 8px", cursor: "pointer", textAlign: "left",
            }}
          >
            Narrate incident <span style={{ fontFamily: MONO, fontWeight: 400, color: T.text3 }}>{incidentId}</span>
          </button>
        )}

        <div style={{ ...labelStyle, marginBottom: 6 }}>Ask about stored alerts</div>
        <div style={{ display: "flex", gap: 6 }}>
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => {
              // The stream's j/k bindings are global; stop them reaching the
              // window while the operator is typing a question.
              e.stopPropagation();
              if (e.key === "Enter") ask();
            }}
            placeholder="beaconing on 10.4.2.19 this week"
            style={{
              flex: 1, minWidth: 0, background: T.panel2, border: `1px solid ${T.rule}`, borderRadius: 2,
              color: T.text, fontFamily: SANS, fontSize: 12, padding: "6px 8px", outline: "none",
            }}
          />
          <button
            onClick={ask}
            style={{
              background: T.panel2, border: `1px solid ${T.rule}`, borderRadius: 2, color: T.text2,
              fontFamily: SANS, fontSize: 12, padding: "6px 10px", cursor: "pointer", flexShrink: 0,
            }}
          >
            Ask
          </button>
        </div>
      </div>
    </aside>
  );
}
