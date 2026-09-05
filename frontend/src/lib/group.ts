/**
 * Grouping the alert stream by the incident the backend already correlated.
 *
 * THE PROBLEM THIS SOLVES
 * ----------------------
 * On the demo capture the stream renders 95 rows. Those 95 rows are about
 * seven actual situations: eighteen of them are one host being scanned, then
 * beaconing, then exfiltrating, and the correlation layer had already worked
 * that out and stamped every one of them with the same `incident_id`. The
 * stream threw that away and listed the events flat, so the screen asked a
 * viewer to re-derive by eye a grouping the backend had already computed and
 * put on the wire.
 *
 * That is the whole "too much on screen at once" problem. It is not density -
 * density is the point of this product - it is that the display was showing
 * events where the reader needed situations.
 *
 * WHAT IS AND IS NOT DERIVED HERE
 * -------------------------------
 * DESIGN.md §11 forbids inventing structure as firmly as it forbids inventing
 * numbers, so the rule here is narrow: **a group is an incident the backend
 * opened, and nothing else.** Alerts the correlator did not place in an
 * incident are not bundled by shared host, shared class or proximity in time -
 * they render exactly as they do today, as their own top-level rows. A
 * client-side "these look related" grouping would be a correlation claim made
 * by the presentation layer, which is precisely the kind of assertion this
 * console exists not to make.
 *
 * `total` likewise comes from `Incident.alert_count` - the backend's own exact
 * figure - and is deliberately kept separate from `shown`, the number of
 * members that survived the active filter. A group header that printed one
 * number for both would silently misreport an incident every time a severity
 * chip was pressed.
 *
 * FIXED PITCH IS PRESERVED
 * ------------------------
 * §12.2 makes `ROW_H = 40` load-bearing: virtualization is fixed-pitch
 * arithmetic, and a variable row height means a dependency and a rewrite. So
 * this flattens the group tree into a flat array in which *every* entry -
 * group headers included - is one 40px row. `windowRange` and `scrollToIndex`
 * are untouched and need to be: the stream is still a fixed-pitch list, it just
 * has two kinds of row in it now.
 */
import type { Alert, Incident, Severity } from "./types";

/** Ascending urgency, for picking the worst member of a group. */
const SEV_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export interface StreamGroup {
  /** The backend's incident id. Groups are never formed client-side. */
  id: string;
  /**
   * What to call the group, by a fixed precedence:
   *
   *   1. `pivot_host` from the incident record - the host the correlator itself
   *      pivoted on, and the only authoritative answer.
   *   2. The source address every member shares, when the record has aged out
   *      of the backend but the members agree. This is an observation about the
   *      alerts on screen, not a guess at what the correlator decided.
   *   3. The incident id, when the members do not agree on one host.
   *
   * The backend expires incidents well before the client's 500-alert ring lets
   * go of their members, so (2) is not an edge case: on the demo capture the
   * correlator holds five incidents while the buffer still carries alerts from
   * thirteen, and without it most of the list is headed by opaque hex.
   */
  label: string;
  /** True when `label` came from rule 2 or 3 - the correlator's own record was
   *  not available. The header shows the id alongside so the two are never
   *  confused. */
  labelDerived: boolean;
  /** Worst severity among the members actually on screen. */
  severity: Severity;
  /** Members surviving the active filter. */
  shown: number;
  /** The backend's exact member count, when the incident record is in hand.
   *  Differs from `shown` under a filter, and the header says so. */
  total?: number;
  /** Distinct threat codes, oldest first. The sequence is the story: a
   *  `PS → BC → EC → EX` header says "scanned, then beaconed, then ran
   *  encrypted C2, then exfiltrated" in four tokens. */
  codes: string[];
  /** Newest member timestamp, in detector seconds. Drives the age readout. */
  latest: number;
  /** The incident spans more than one kill-chain stage. */
  escalated?: boolean;
}

export type StreamRow =
  /** A collapsed or expanded incident header. */
  | { kind: "group"; key: string; group: StreamGroup; expanded: boolean }
  /** An alert row. `depth` is 1 for a member of an expanded group, 0 for an
   *  uncorrelated alert standing on its own. */
  | { kind: "alert"; key: string; alert: Alert; depth: 0 | 1 };

/**
 * Flatten filtered alerts into the fixed-pitch row list the stream renders.
 *
 * `alerts` must be newest-first, which is how `useFeed` maintains the ring
 * buffer. Group order then falls out for free: the first time a group is seen
 * walking that list is its newest member, so first-appearance order *is*
 * most-recently-active order, in one pass and without a sort.
 */
export function groupStream(
  alerts: Alert[],
  incidents: Incident[],
  expanded: ReadonlySet<string>
): StreamRow[] {
  const byId = new Map<string, Incident>();
  for (const inc of incidents) byId.set(inc.incident_id, inc);

  // First appearance order, newest-active first.
  const order: string[] = [];
  const members = new Map<string, Alert[]>();
  const loose: Alert[] = [];

  for (const a of alerts) {
    const id = a.incident_id;
    if (!id) {
      // Uncorrelated: the backend made no claim about this alert's relations,
      // so neither do we.
      loose.push(a);
      continue;
    }
    let bucket = members.get(id);
    if (!bucket) {
      bucket = [];
      members.set(id, bucket);
      order.push(id);
    }
    bucket.push(a);
  }

  const rows: StreamRow[] = [];

  // A single-member incident gets no header: a group of one is a row with an
  // extra row on top of it, which costs 40px and tells the reader nothing.
  const emitLoose = (a: Alert) => rows.push({ kind: "alert", key: a.alert_id, alert: a, depth: 0 });

  for (const id of order) {
    const bucket = members.get(id)!;
    if (bucket.length === 1) {
      emitLoose(bucket[0]);
      continue;
    }

    const inc = byId.get(id);
    let severity: Severity = "low";
    let latest = 0;
    const codes: string[] = [];
    // A source address is only usable as a label if every member agrees on it.
    let sharedSrc: string | null | undefined;
    // Members arrive newest-first; walking backwards puts the story in the
    // order it happened.
    for (let i = bucket.length - 1; i >= 0; i--) {
      const a = bucket[i];
      if (SEV_RANK[a.severity] > SEV_RANK[severity]) severity = a.severity;
      if (a.ts > latest) latest = a.ts;
      const code = a.threat_code || "??";
      if (!codes.includes(code)) codes.push(code);
      const src = a.src_ip?.trim() || null;
      if (sharedSrc === undefined) sharedSrc = src;
      else if (sharedSrc !== src) sharedSrc = null;
    }

    const pivot = inc?.pivot_host;
    const group: StreamGroup = {
      id,
      label: pivot || sharedSrc || id,
      labelDerived: !pivot,
      severity,
      shown: bucket.length,
      total: inc?.alert_count,
      codes,
      latest,
      escalated: inc?.escalated,
    };
    const isOpen = expanded.has(id);
    rows.push({ kind: "group", key: id, group, expanded: isOpen });
    if (isOpen) {
      for (const a of bucket) rows.push({ kind: "alert", key: a.alert_id, alert: a, depth: 1 });
    }
  }

  for (const a of loose) emitLoose(a);
  return rows;
}

/** Row index of an alert in a flattened list, or -1. The stream scrolls the
 *  selection into view by row index, and after grouping that is no longer the
 *  alert's index in the filtered array. */
export function rowIndexOfAlert(rows: StreamRow[], alertId: string | null): number {
  if (!alertId) return -1;
  return rows.findIndex((r) => r.kind === "alert" && r.alert.alert_id === alertId);
}
