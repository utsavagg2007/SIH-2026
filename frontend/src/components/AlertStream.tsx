import { T, SEV, CLASS_META, MONO, SANS } from "../lib/tokens";
import { fmtTime } from "../lib/format";
import type { Alert, Severity } from "../lib/types";

function AlertRow({ alert, selected, onSelect }: { alert: Alert; selected: boolean; onSelect: (id: string) => void }) {
  const sev = SEV[alert.severity];
  const meta = CLASS_META[alert.threat_class];
  return (
    <div
      onClick={() => onSelect(alert.alert_id)}
      style={{
        display: "flex", alignItems: "center", gap: 8, height: 40, padding: "0 10px",
        borderLeft: `2px solid ${sev.color}`, background: selected ? T.panel2 : "transparent",
        cursor: "pointer", borderBottom: `1px solid ${T.rule}`,
      }}
    >
      <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, width: 92, flexShrink: 0 }}>{fmtTime(alert.ts)}</span>
      <span style={{ fontFamily: MONO, fontSize: 11, color: T.text2, border: `1px solid ${T.rule}`, padding: "1px 4px", flexShrink: 0 }}>{meta.code}</span>
      <span style={{ fontFamily: SANS, fontSize: 10, fontWeight: 600, color: sev.color, width: 56, flexShrink: 0 }}>{sev.label}</span>
      <span style={{ fontFamily: MONO, fontSize: 12, color: T.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>
        {alert.src_ip} &rarr; {alert.dst_ip}
      </span>
      <span style={{ fontFamily: MONO, fontSize: 11, color: T.text2, flexShrink: 0 }}>{alert.confidence.toFixed(2)}</span>
    </div>
  );
}

interface Props {
  alerts: Alert[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  filterSev: Severity | "all";
  setFilterSev: (s: Severity | "all") => void;
}

export function AlertStream({ alerts, selectedId, onSelect, filterSev, setFilterSev }: Props) {
  const filtered = filterSev === "all" ? alerts : alerts.filter((a) => a.severity === filterSev);
  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={{ display: "flex", gap: 4, padding: 8, borderBottom: `1px solid ${T.rule}`, flexShrink: 0 }}>
        {(["all", "critical", "high", "medium", "low"] as const).map((s) => (
          <button
            key={s}
            onClick={() => setFilterSev(s)}
            style={{
              fontFamily: SANS, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em",
              padding: "4px 8px", borderRadius: 2, border: `1px solid ${filterSev === s ? T.ruleBright : T.rule}`,
              background: filterSev === s ? T.panel2 : "transparent",
              color: s === "all" ? T.text2 : SEV[s as Severity].color, cursor: "pointer",
            }}
          >
            {s}
          </button>
        ))}
      </div>
      {/* Virtualization note (section 8.2): at demo scale (a few hundred rows
          capped by the ring buffer) a plain map holds 60fps. If you need to
          go well past that, swap this list for react-window / react-virtual
          without touching anything else in this file's props contract. */}
      <div style={{ overflowY: "auto", flex: 1 }}>
        {filtered.length === 0 && <div style={{ padding: 16, fontFamily: SANS, fontSize: 13, color: T.text3 }}>Waiting for first detection.</div>}
        {filtered.map((a) => (
          <AlertRow key={a.alert_id} alert={a} selected={a.alert_id === selectedId} onSelect={onSelect} />
        ))}
      </div>
      <div style={{ padding: "5px 10px", borderTop: `1px solid ${T.rule}`, fontFamily: SANS, fontSize: 10, color: T.text3 }}>
        j / k move &middot; enter open &middot; esc clear
      </div>
    </div>
  );
}