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
import { T, MONO } from "../lib/tokens";

interface WireData {
  samples: { t: number; v: number }[];
  marks: { t: number; code: string; color: string }[];
  connected: boolean;
}

export function Wire({ getData, height = 88 }: { getData: () => WireData; height?: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current!;
    const ctx = canvas.getContext("2d")!;
    let raf: number;
    let lastStep = 0;
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    function resize() {
      const rect = canvas.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      canvas.width = rect.width * dpr;
      canvas.height = height * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    resize();
    window.addEventListener("resize", resize);

    function draw(now: number) {
      // Under prefers-reduced-motion: redraw in one-second steps, section 2.5
      if (reducedMotion) {
        if (now - lastStep < 1000) {
          raf = requestAnimationFrame(draw);
          return;
        }
        lastStep = now;
      }

      const rect = canvas.getBoundingClientRect();
      const w = rect.width;
      const h = height;
      const windowSec = 60;
      const pxPerSec = w / windowSec;
      ctx.clearRect(0, 0, w, h);

      const { samples, marks, connected } = getData();
      const nowMs = performance.now();
      const baselineY = h - 22;

      ctx.strokeStyle = T.rule;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, baselineY);
      ctx.lineTo(w, baselineY);
      ctx.stroke();

      ctx.fillStyle = T.text3;
      ctx.font = `11px ${MONO}`;
      ctx.textBaseline = "top";
      [60, 30, 0].forEach((s) => {
        const x = w - s * pxPerSec;
        const lbl = s === 0 ? "now" : `\u2190 ${s}s`;
        const tw = ctx.measureText(lbl).width;
        const clampedX = Math.max(2, Math.min(w - tw - 2, x - (s === 0 ? tw : 0)));
        ctx.fillText(lbl, clampedX, 4);
      });

      if (samples.length > 1) {
        ctx.strokeStyle = T.text3;
        ctx.lineWidth = 1.25;
        ctx.beginPath();
        const maxDensity = Math.max(1, ...samples.map((s) => s.v));
        samples.forEach((s, i) => {
          const ageMs = nowMs - s.t;
          const x = w - (ageMs / 1000) * pxPerSec;
          const y = 30 - (s.v / maxDensity) * 20;
          if (x < -10) return;
          if (i === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        });
        ctx.stroke();
      }

      marks.forEach((m) => {
        const ageMs = nowMs - m.t;
        const x = w - (ageMs / 1000) * pxPerSec;
        if (x < -20 || x > w + 20) return;
        const color = m.color || T.sevMed;
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(x, 12);
        ctx.lineTo(x, baselineY);
        ctx.stroke();
        ctx.fillStyle = T.text2;
        ctx.font = `10px ${MONO}`;
        ctx.fillText(m.code, x + 3, 12);
      });

      if (!connected) {
        ctx.fillStyle = T.text3;
        ctx.font = `12px ${MONO}`;
        ctx.textAlign = "right";
        ctx.fillText("feed stopped", w - 8, h - 16);
        ctx.textAlign = "left";
      }

      raf = requestAnimationFrame(draw);
    }
    raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, [getData, height]);

  return <canvas ref={canvasRef} style={{ width: "100%", height, display: "block", background: T.bg, flexShrink: 0 }} />;
}