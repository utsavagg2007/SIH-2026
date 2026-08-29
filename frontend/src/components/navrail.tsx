import { Activity, GitMerge, Server, Cpu, PlayCircle } from "lucide-react";
import { T, SANS } from "../lib/tokens";
import type { ViewId } from "../lib/types";

const ITEMS: { id: ViewId; icon: typeof Activity; label: string }[] = [
  { id: "live", icon: Activity, label: "Live" },
  { id: "incidents", icon: GitMerge, label: "Incidents" },
  { id: "host", icon: Server, label: "Host" },
  { id: "system", icon: Cpu, label: "System" },
  { id: "replay", icon: PlayCircle, label: "Replay" },
];

export function NavRail({ active, onSelect }: { active: ViewId; onSelect: (v: ViewId) => void }) {
  return (
    <div style={{ width: 56, flexShrink: 0, borderRight: `1px solid ${T.rule}`, display: "flex", flexDirection: "column", alignItems: "center", paddingTop: 12, gap: 4, background: T.panel }}>
      {ITEMS.map((it) => {
        const Icon = it.icon;
        const isActive = it.id === active;
        return (
          <div
            key={it.id}
            title={it.label}
            onClick={() => onSelect(it.id)}
            style={{
              width: 44, height: 44, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
              gap: 2, color: isActive ? T.text : T.text3, background: isActive ? T.panel2 : "transparent", borderRadius: 2, cursor: "pointer",
            }}
          >
            <Icon size={16} strokeWidth={1.75} />
            <span style={{ fontFamily: SANS, fontSize: 8, letterSpacing: "0.02em" }}>{it.label}</span>
          </div>
        );
      })}
    </div>
  );
}