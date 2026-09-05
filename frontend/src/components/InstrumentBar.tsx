import { T, MONO, microStyle } from "../lib/tokens";
import type { FeedMetrics } from "../hooks/useFeed";

/**
 * The instrument bar (DESIGN.md §1.1C).
 *
 * The previous bar showed five readouts while the metrics frame carried eleven.
 * `alerts/sec` in particular - the most important "is it detecting" number in
 * the product - was measured by the backend, put on the wire, and never drawn.
 *
 * Then it showed all ten at one size, which traded one failure for another. Ten
 * equal readouts is not a hierarchy, it is a list, and a viewer with eight
 * seconds reads a list by starting at the left and giving up. Worse, most of
 * them are dashes or zeros on a bench with no telemetry source posting, so the
 * bar spent its full width saying `0 / — / — / — / 0ms / 0ms` in the same
 * weight as the one figure that proves the system is working.
 *
 * So the bar is now two tiers. Three primary readouts answer "is it detecting,
 * how much has it found, is the feed alive" at 15px; the rest are the
 * engineering detail behind them, at 12px in `--text-2`, still present and
 * still exact. Nothing was removed - §0 is explicit that where the two
 * audiences conflict you add hierarchy and never take detail away.
 *
 * The honesty rule here is unchanged and applies to every cell: the backend
 * never sees a packet. Flow, packet and bit rates are reported to it by the
 * ingestion and detection layers over POST /api/v1/telemetry, or not at all.
 * When nothing has reported, they read as a dash rather than as zero - a
 * confident 0.0 Mb/s beside a live alert stream is a lie about what the system
 * knows, and it is the readout requirement (d) is graded on.
 */
export function InstrumentBar({
  metrics,
  trafficSource,
}: {
  metrics: FeedMetrics;
  trafficSource?: string;
}) {
  const traffic = (value: string) => (metrics.trafficLive ? value : "—");
  const live = (value: string) => (metrics.connected ? value : "—");

  /** The three that answer "is this thing working". */
  const primary: Cell[] = [
    { l: "alerts/sec", v: live(metrics.alertsPerSec.toFixed(1)), title: "Measured by the backend" },
    { l: "alerts total", v: metrics.alertsTotal.toLocaleString() },
    {
      l: "deduplicated",
      v: metrics.alertsDeduplicated.toLocaleString(),
      title: "Repeats folded into an existing finding",
    },
  ];

  /** Everything behind them. Exact, and deliberately quieter. */
  const secondary: Cell[] = [
    { l: "flows/sec", v: traffic(Math.round(metrics.flowsPerSec).toLocaleString()), title: "Reported by the ingestion layer" },
    { l: "packets/sec", v: traffic(Math.round(metrics.packetsPerSec ?? 0).toLocaleString()) },
    { l: "Mb/s", v: traffic(metrics.mbps.toFixed(1)) },
    { l: "p50", v: `${metrics.p50}ms`, title: "Median pipeline latency" },
    { l: "p95", v: `${metrics.p95}ms`, title: "95th-percentile pipeline latency" },
    { l: "detectors", v: `${metrics.detectorsOnline}/${metrics.detectorsTotal}` },
    { l: "uptime", v: metrics.uptime },
  ];

  return (
    <div
      style={{
        height: 48, flexShrink: 0, background: T.panel, display: "flex", alignItems: "center",
        padding: "0 16px", overflow: "hidden",
      }}
    >
      {primary.map((it) => (
        <Readout key={it.l} cell={it} size={15} color={T.text} pad={18} />
      ))}

      {/* The tier break is a heavier rule, so the eye can see where the answer
          ends and the engineering detail starts without reading either. */}
      <div style={{ width: 1, alignSelf: "stretch", background: T.ruleBright, margin: "10px 18px 10px 0", flexShrink: 0 }} />

      {secondary.map((it) => (
        <Readout key={it.l} cell={it} size={12} color={T.text2} pad={14} />
      ))}

      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 16, flexShrink: 0 }}>
        {/* Where the traffic figures came from. Labelled, because the bare
            value the backend reports when nothing has posted is the word
            "none", and an unlabelled "none" beside "streaming" reads as a
            fault in the feed rather than an absent telemetry source. */}
        {trafficSource && (
          <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, whiteSpace: "nowrap" }}>
            traffic source {trafficSource}
          </span>
        )}
        {/* The only element in the bar permitted colour, and only when the feed
            is down. It never fakes movement or a healthy state. */}
        <div style={{ display: "flex", alignItems: "center", gap: 7, borderLeft: `1px solid ${T.rule}`, paddingLeft: 16 }}>
          <span style={{ width: 6, height: 6, background: metrics.connected ? T.text2 : T.sevCrit }} />
          <span style={{ fontFamily: MONO, fontSize: 12, color: metrics.connected ? T.text2 : T.sevCrit }}>
            {metrics.connected ? "streaming" : "feed stopped"}
          </span>
        </div>
      </div>
    </div>
  );
}

interface Cell {
  l: string;
  v: string;
  title?: string;
}

function Readout({ cell, size, color, pad }: { cell: Cell; size: number; color: string; pad: number }) {
  return (
    <div
      title={cell.title}
      style={{
        display: "flex", flexDirection: "column", gap: 2, paddingRight: pad, marginRight: pad,
        borderRight: `1px solid ${T.rule}`, flexShrink: 0,
      }}
    >
      <span style={{ fontFamily: MONO, fontWeight: 500, fontSize: size, lineHeight: 1, color }}>{cell.v}</span>
      <span style={{ ...microStyle, whiteSpace: "nowrap" }}>{cell.l}</span>
    </div>
  );
}
