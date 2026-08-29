/**
 * The Wire (Frontend spec section 3).
 *
 * A single horizontal trace showing traffic flowing right to left, with
 * detections landing on it as they are found. It exists because liveness is the
 * hardest property to convey and the one requirement judges are most sceptical
 * of - a number that increments could be a timer; a continuous trace with
 * detections landing on it in real time is direct visual evidence of streaming.
 *
 * Canvas, not DOM (spec 3.2). One requestAnimationFrame loop owns it and reads
 * from the ring buffer the WebSocket handler writes to. React state is never
 * involved in the animation path.
 */

import { useEffect, useRef } from "react";
import type { ConnState } from "../lib/api";
import type { WireBuffer } from "../lib/store";

const WINDOW_S = 60;
const HEIGHT = 88;

const SEV_COLOR: Record<string, string> = {
  low: "#4e9c7f",
  medium: "#d2a03e",
  high: "#db7038",
  critical: "#c8453d",
};

export function Wire({
  buffer,
  conn,
  onSelect,
}: {
  buffer: React.MutableRefObject<WireBuffer>;
  conn: ConnState;
  onSelect: (alertId: string) => void;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const connRef = useRef(conn);
  connRef.current = conn;
  const hitRef = useRef<{ x: number; id: string }[]>([]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reduced = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;

    let raf = 0;
    let stopped = false;
    let lastDraw = 0;

    const draw = (now: number) => {
      if (stopped) return;
      // Under reduced motion the trace redraws in one-second steps instead of
      // continuously (spec 2.5). Everything remains functional.
      if (reduced && now - lastDraw < 1000) {
        raf = requestAnimationFrame(draw);
        return;
      }
      lastDraw = now;

      const dpr = window.devicePixelRatio || 1;
      const w = canvas.clientWidth;
      if (canvas.width !== w * dpr || canvas.height !== HEIGHT * dpr) {
        canvas.width = w * dpr;
        canvas.height = HEIGHT * dpr;
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      const css = getComputedStyle(document.documentElement);
      const panel = css.getPropertyValue("--panel").trim() || "#14181b";
      const rule = css.getPropertyValue("--rule").trim() || "#252c31";
      const text3 = css.getPropertyValue("--text-3").trim() || "#5a646b";

      ctx.fillStyle = panel;
      ctx.fillRect(0, 0, w, HEIGHT);

      // When the feed is stopped the trace freezes at the moment it stopped -
      // it never fakes movement (spec 3.2).
      const live = connRef.current === "open";
      const nowS = live
        ? Date.now() / 1000
        : (buffer.current.marks.at(-1)?.t ?? Date.now() / 1000);
      const t0 = nowS - WINDOW_S;
      const xOf = (t: number) => ((t - t0) / WINDOW_S) * w;

      // Time axis: ticks every fifteen seconds, right edge is now.
      ctx.strokeStyle = rule;
      ctx.fillStyle = text3;
      ctx.font = '11px "IBM Plex Mono", monospace';
      ctx.lineWidth = 1;
      for (let s = 0; s <= WINDOW_S; s += 15) {
        const x = Math.round(xOf(nowS - s)) + 0.5;
        ctx.beginPath();
        ctx.moveTo(x, HEIGHT - 16);
        ctx.lineTo(x, HEIGHT - 11);
        ctx.stroke();
        const label = s === 0 ? "now" : `-${s}s`;
        ctx.textAlign = s === 0 ? "right" : s === WINDOW_S ? "left" : "center";
        ctx.fillText(label, s === 0 ? x - 3 : x, HEIGHT - 3);
      }

      // Baseline rule.
      ctx.strokeStyle = rule;
      ctx.beginPath();
      ctx.moveTo(0, HEIGHT - 16.5);
      ctx.lineTo(w, HEIGHT - 16.5);
      ctx.stroke();

      // Density trace: a thin line whose height encodes alerts per second.
      // Drawn in --text-3; this is the ambient signal, never saturated.
      const density = buffer.current.density.filter((d) => d.t >= t0);
      if (density.length > 1) {
        const peak = Math.max(1, ...density.map((d) => d.v));
        ctx.strokeStyle = text3;
        ctx.beginPath();
        density.forEach((d, i) => {
          const x = xOf(d.t);
          const y = HEIGHT - 20 - (d.v / peak) * 34;
          if (i === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        });
        ctx.stroke();
      }

      // Detection marks: a 2px vertical tick in the severity colour with the
      // two-letter threat code beside it. Marks persist as they scroll left.
      const marks = buffer.current.marks.filter((m) => m.t >= t0);
      const hits: { x: number; id: string }[] = [];
      let lastLabelX = -Infinity;
      ctx.font = '10px "IBM Plex Mono", monospace';
      ctx.textAlign = "left";
      for (const m of marks) {
        const x = Math.round(xOf(m.t));
        if (x < 0 || x > w) continue;
        ctx.fillStyle = SEV_COLOR[m.severity] ?? text3;
        ctx.fillRect(x, 8, 2, 40);
        // Only label when there is room; at flood rates the codes would
        // otherwise overprint into an unreadable smear.
        if (x - lastLabelX > 22) {
          ctx.fillStyle = text3;
          ctx.fillText(m.code, x + 4, 18);
          lastLabelX = x;
        }
        hits.push({ x, id: m.alertId });
      }
      hitRef.current = hits;

      // Drop marks that have scrolled off, so the buffer does not grow.
      if (marks.length !== buffer.current.marks.length) {
        buffer.current.marks = marks;
      }

      raf = requestAnimationFrame(draw);
    };

    raf = requestAnimationFrame(draw);
    return () => {
      stopped = true;
      cancelAnimationFrame(raf);
    };
  }, [buffer]);

  const handleClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left;
    let best: { x: number; id: string } | null = null;
    for (const h of hitRef.current) {
      if (!best || Math.abs(h.x - x) < Math.abs(best.x - x)) best = h;
    }
    if (best && Math.abs(best.x - x) < 8) onSelect(best.id);
  };

  return (
    <div className="wire-slot">
      <canvas
        ref={canvasRef}
        onClick={handleClick}
        role="img"
        aria-label="Live detection trace, last 60 seconds"
      />
      {conn !== "open" && (
        <span className="wire-status data-sm">
          {conn === "connecting" ? "connecting" : "feed stopped"}
        </span>
      )}
    </div>
  );
}
