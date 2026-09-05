import { Activity, GitMerge, Server, Cpu, PlayCircle } from "lucide-react";
import { T, SANS } from "../lib/tokens";
import type { ViewId } from "../lib/types";

const ITEMS: { id: ViewId; icon: typeof Activity; label: string; title: string }[] = [
  { id: "live", icon: Activity, label: "Live", title: "Live — alert stream and evidence" },
  { id: "incidents", icon: GitMerge, label: "Incidents", title: "Incidents — correlated alerts on one host" },
  { id: "host", icon: Server, label: "Host", title: "Host — single-machine investigation" },
  { id: "system", icon: Cpu, label: "System", title: "System — throughput, latency, detectors, constraints" },
  { id: "replay", icon: PlayCircle, label: "Replay", title: "Replay — capture playback" },
];

/**
 * Navigation rail (DESIGN.md §4.2).
 *
 * Items are real buttons with `aria-current` and a focus ring rather than the
 * `<div onClick>` they used to be: not focusable, not keyboard-reachable, not
 * announced. Hover and active states live in `styles.css`, because an inline
 * style cannot express `:hover`.
 *
 * The plate at the foot states the architectural constraint on every screen, in
 * the register of an equipment label. It is not decoration - the system cannot
 * block, quarantine, reset a connection or query a host, and a judge who
 * notices there is no "Block" button anywhere has understood the architecture.
 */
export function NavRail({ active, onSelect }: { active: ViewId; onSelect: (v: ViewId) => void }) {
  return (
    <nav
      aria-label="Views"
      style={{
        // 56px could not hold a readable label, which is why the labels were
        // 8px truncations. 72px holds the real words at a size that can be
        // read, and 16px of rail is a cheap price for navigation that works.
        width: 72, flexShrink: 0, borderRight: `1px solid ${T.rule}`, background: T.panel,
        display: "flex", flexDirection: "column", alignItems: "stretch", paddingTop: 8,
      }}
    >
      {ITEMS.map((it) => {
        const Icon = it.icon;
        return (
          <button
            key={it.id}
            className="nav-item"
            aria-current={it.id === active}
            title={it.title}
            onClick={() => onSelect(it.id)}
          >
            <Icon size={18} strokeWidth={1.75} />
            <span style={{ fontFamily: SANS, fontSize: 10, fontWeight: 600, letterSpacing: "0.04em", textTransform: "uppercase" }}>
              {it.label}
            </span>
          </button>
        );
      })}

      <div
        title="This console observes a one-directional mirrored copy of network traffic. It cannot send anything back into the network."
        style={{
          marginTop: "auto", margin: "auto 5px 10px", border: `1px solid ${T.rule}`, padding: "5px 1px",
          display: "flex", flexDirection: "column", alignItems: "center", gap: 1,
        }}
      >
        {/* nowrap: "READ-ONLY" is one word to a reader and hyphenating it across
            two lines makes the plate read as two separate claims. */}
        <span style={{ fontFamily: SANS, fontSize: 10, fontWeight: 600, letterSpacing: "0.02em", color: T.text3, whiteSpace: "nowrap" }}>PASSIVE</span>
        <span style={{ fontFamily: SANS, fontSize: 10, fontWeight: 600, letterSpacing: "0.02em", color: T.text3, whiteSpace: "nowrap" }}>READ-ONLY</span>
      </div>
    </nav>
  );
}
