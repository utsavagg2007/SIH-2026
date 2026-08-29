/**
 * The alert stream (Frontend spec 4.1).
 *
 * A selector, not the product: the evidence panel beside it is the product.
 * Keyboard-driven, because security tools are (spec 8.3): j/k to move, Enter to
 * open, Esc to clear.
 */

import { useEffect, useMemo, useRef } from "react";
import type { Alert, Severity, ThreatClass } from "../lib/types";
import { fmt } from "../lib/format";
import { sevKey } from "./Evidence";

const SEVERITIES: Severity[] = ["low", "medium", "high", "critical"];

const CLASS_CODES: Record<ThreatClass, string> = {
  ddos: "DF",
  dga_domain: "DG",
  dns_tunnelling: "DT",
  port_scan: "PS",
  encrypted_malware: "EC",
  c2_beaconing: "BC",
  data_exfiltration: "EX",
};

export interface Filters {
  severities: Set<Severity>;
  classes: Set<ThreatClass>;
}

export function AlertStream({
  alerts,
  selectedId,
  onSelect,
  filters,
  onFilters,
  received,
}: {
  alerts: Alert[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  filters: Filters;
  onFilters: (f: Filters) => void;
  received: number;
}) {
  const listRef = useRef<HTMLDivElement>(null);

  const visible = useMemo(
    () =>
      alerts.filter(
        (a) =>
          (filters.severities.size === 0 || filters.severities.has(a.severity)) &&
          (filters.classes.size === 0 || filters.classes.has(a.threat_class))
      ),
    [alerts, filters]
  );

  // j/k/Enter/Esc. Bound on the document so the stream is drivable without
  // clicking into it first, which is what makes the demo fast to drive.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "SELECT" || tag === "TEXTAREA") return;
      if (!["j", "k", "Escape"].includes(e.key)) return;
      e.preventDefault();
      if (e.key === "Escape") {
        onSelect("");
        return;
      }
      const i = visible.findIndex((a) => a.alert_id === selectedId);
      const next =
        e.key === "j"
          ? Math.min(i + 1, visible.length - 1)
          : Math.max(i - 1, 0);
      const target = visible[i === -1 ? 0 : next];
      if (target) onSelect(target.alert_id);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [visible, selectedId, onSelect]);

  useEffect(() => {
    if (!selectedId || !listRef.current) return;
    listRef.current
      .querySelector(`[data-id="${CSS.escape(selectedId)}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [selectedId]);

  const toggle = <T,>(set: Set<T>, v: T): Set<T> => {
    const next = new Set(set);
    next.has(v) ? next.delete(v) : next.add(v);
    return next;
  };

  return (
    <div className="panel">
      <div className="panel-head" style={{ flexWrap: "wrap" }}>
        <span className="heading">Alert stream</span>
        <span className="data-sm" style={{ color: "var(--text-3)" }}>
          {visible.length} shown · {received} received
        </span>
      </div>

      <div
        className="panel-head"
        style={{ flexDirection: "column", alignItems: "stretch", gap: 6 }}
      >
        <div className="chips">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              className="chip"
              aria-pressed={filters.severities.has(s)}
              onClick={() =>
                onFilters({ ...filters, severities: toggle(filters.severities, s) })
              }
            >
              {s}
            </button>
          ))}
        </div>
        <div className="chips">
          {(Object.keys(CLASS_CODES) as ThreatClass[]).map((c) => (
            <button
              key={c}
              className="chip mono"
              title={c}
              aria-pressed={filters.classes.has(c)}
              onClick={() =>
                onFilters({ ...filters, classes: toggle(filters.classes, c) })
              }
            >
              {CLASS_CODES[c]}
            </button>
          ))}
        </div>
      </div>

      <div className="panel-body" ref={listRef}>
        {visible.length === 0 ? (
          <div className="empty">
            {alerts.length === 0
              ? "Waiting for first detection. Start a replay from the Replay view."
              : "No alerts match the active filters."}
          </div>
        ) : (
          <div className="rows">
            {visible.map((a) => (
              <button
                key={a.alert_id}
                data-id={a.alert_id}
                className="row"
                aria-selected={a.alert_id === selectedId}
                style={{ ["--sev" as string]: `var(--sev-${sevKey(a.severity)})` }}
                onClick={() => onSelect(a.alert_id)}
              >
                <span className="row-top">
                  <span className="data-sm" style={{ color: "var(--text-2)" }}>
                    {fmt.clock(a.ts)}
                  </span>
                  <span className="code">{a.threat_code}</span>
                  <span className="sev-label">{a.severity}</span>
                  <span className="grow" />
                  {a.occurrences > 1 && (
                    <span className="data-sm" style={{ color: "var(--text-3)" }}>
                      &times;{a.occurrences}
                    </span>
                  )}
                </span>
                <span className="row-sub data-sm">
                  <span className="grow">
                    {a.src_ip ?? "—"} → {a.dst_ip ?? "—"}
                    {a.dst_port !== null && `:${a.dst_port}`}
                  </span>
                  <span>{a.confidence.toFixed(2)}</span>
                  <span className="conf-track">
                    <span
                      className="conf-fill"
                      style={{ width: `${a.confidence * 100}%` }}
                    />
                  </span>
                </span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
