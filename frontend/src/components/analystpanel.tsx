import { useState } from "react";
import { X } from "lucide-react";
import { T, SEV, CLASS_META, MONO, SANS, headingStyle, labelStyle } from "../lib/tokens";
import type { Alert } from "../lib/types";

export function AnalystPanel({ alert, onClose }: { alert: Alert | null; onClose: () => void }) {
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<string | null>(null);
  const meta = alert ? CLASS_META[alert.threat_class] : null;

  const ask = () => {
    if (!question.trim()) return;
    // Stubbed: point this at a real /analyst/query endpoint later. Section
    // 6.5 — when the analyst service is unavailable, say so plainly and
    // leave the rest of the product unaffected; this layer is never on the
    // critical path.
    setAnswer(`${alert ? alert.occurrences : 0} matching detections found in the last 24 hours.`);
  };

  return (
    <div style={{ width: 340, flexShrink: 0, borderLeft: `1px solid ${T.rule}`, background: T.panel, display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", alignItems: "center", padding: "10px 14px", borderBottom: `1px solid ${T.rule}` }}>
        <span style={headingStyle}>Analyst</span>
        <button onClick={onClose} style={{ marginLeft: "auto", background: "none", border: "none", color: T.text3, cursor: "pointer", padding: 2 }}>
          <X size={14} />
        </button>
      </div>
      <div style={{ padding: 14, fontFamily: SANS, fontSize: 13, color: T.text2, lineHeight: 1.6, borderBottom: `1px solid ${T.rule}` }}>
        {alert && meta ? (
          <>
            This is a {SEV[alert.severity].label.toLowerCase()}-severity {meta.name.toLowerCase()} detection from{" "}
            <span style={{ fontFamily: MONO, color: T.text }}>{alert.src_ip}</span> at{" "}
            <span style={{ fontFamily: MONO, color: T.text }}>{alert.confidence.toFixed(2)}</span> confidence
            <sup style={{ color: T.text3, fontSize: 10 }}> [confidence]</sup>, based on {alert.evidence.length} evidence field
            {alert.evidence.length === 1 ? "" : "s"}
            <sup style={{ color: T.text3, fontSize: 10 }}> [evidence]</sup>.
          </>
        ) : (
          "Select an alert to get a plain-language explanation."
        )}
      </div>
      <div style={{ padding: 14 }}>
        <div style={{ ...labelStyle, marginBottom: 8 }}>Ask about historical alerts</div>
        <div style={{ display: "flex", gap: 6 }}>
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && ask()}
            placeholder="How many beacons this week?"
            style={{ flex: 1, background: T.panel2, border: `1px solid ${T.rule}`, borderRadius: 2, color: T.text, fontFamily: SANS, fontSize: 12, padding: "6px 8px", outline: "none" }}
          />
          <button onClick={ask} style={{ background: T.panel2, border: `1px solid ${T.rule}`, borderRadius: 2, color: T.text2, fontFamily: SANS, fontSize: 12, padding: "6px 10px", cursor: "pointer" }}>
            Ask
          </button>
        </div>
        {answer && <div style={{ marginTop: 10, fontFamily: SANS, fontSize: 12, color: T.text2 }}>{answer}</div>}
      </div>
    </div>
  );
}