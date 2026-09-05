/**
 * Replay control (DESIGN.md §8.4).
 *
 * Deliberately plain, and now actually wired: captures come from
 * `GET /api/v1/replay/captures`, position from `GET /api/v1/replay/status`,
 * and the buttons call `POST /api/v1/replay/start` and `/stop`. The previous
 * screen held a hardcoded list of three capture names and a local `running`
 * flag, so pressing Start moved a counter in the browser and nothing else.
 *
 * The one control that earns its place beyond transport is the scenario label
 * read from the capture's ground-truth manifest. Being able to say "this
 * capture contains a beacon at minute seven, and here it is at minute seven"
 * is a strong demo moment, so it gets real estate.
 */
import { useCallback, useEffect, useState } from "react";
import { Play, Square } from "lucide-react";
import { T, MONO, SANS, microStyle } from "../lib/tokens";
import { fmt } from "../lib/format";
import { api } from "../lib/api";
import type { Capture, ReplayStatus } from "../lib/types";

const SPEEDS = [1, 2, 5, 10, 25];

/** Renders a ground-truth manifest without assuming its shape. The manifest is
 *  authored beside the capture and the backend passes it through untouched, so
 *  a key this build has never seen must still be readable. */
function scenarioLines(scenario: Record<string, unknown> | undefined): string[] {
  if (!scenario) return [];
  const out: string[] = [];
  for (const [k, v] of Object.entries(scenario)) {
    if (v === null || v === undefined || v === "") continue;
    const label = k.replace(/_/g, " ");
    if (Array.isArray(v)) {
      // A ground-truth list is the interesting part of the manifest - the
      // attacks and the minute each one lands. Flattening it onto one line
      // makes the demo moment unreadable, so each entry gets its own row and
      // an object entry is rendered as `key=value` pairs rather than as JSON.
      out.push(`${label}:`);
      for (const item of v) {
        out.push(
          typeof item === "object" && item !== null
            ? "  " + Object.entries(item as Record<string, unknown>).map(([ik, iv]) => `${ik}=${iv}`).join("  ")
            : `  ${String(item)}`
        );
      }
    } else if (typeof v === "object") {
      for (const [ik, iv] of Object.entries(v as Record<string, unknown>)) {
        out.push(`${label} · ${ik.replace(/_/g, " ")}: ${typeof iv === "object" ? JSON.stringify(iv) : String(iv)}`);
      }
    } else {
      out.push(`${label}: ${String(v)}`);
    }
  }
  return out;
}

export function ReplayView() {
  const [captures, setCaptures] = useState<Capture[] | null>(null);
  const [status, setStatus] = useState<ReplayStatus | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [speed, setSpeed] = useState(1);
  const [loop, setLoop] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refreshStatus = useCallback(async () => {
    try {
      const s = await api.replayStatus();
      setStatus(s);
      // Follow the server's truth rather than the local controls: if a replay
      // was started elsewhere - another operator, a previous session - this
      // screen shows the capture and speed that are actually running instead
      // of its own defaults.
      if (s.capture) setSelected((cur) => cur ?? s.capture);
      if (s.running && s.speed) setSpeed(s.speed);
      return s;
    } catch (e) {
      setStatus(null);
      setError(String((e as Error)?.message ?? e));
      return null;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    api
      .captures()
      .then((r) => {
        if (!cancelled) setCaptures(r.items);
      })
      .catch((e) => {
        if (!cancelled) {
          setCaptures([]);
          setError(String((e as Error)?.message ?? e));
        }
      });
    refreshStatus();
    const timer = setInterval(refreshStatus, 1000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [refreshStatus]);

  const running = status?.running ?? false;
  const active = captures?.find((c) => c.capture === (status?.capture ?? selected));
  const position = status && status.total > 0 ? status.position / status.total : 0;

  async function start() {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      setStatus(await api.replayStart(selected, speed, { loop }));
    } catch (e) {
      setError(String((e as Error)?.message ?? e));
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    setBusy(true);
    setError(null);
    try {
      setStatus(await api.replayStop());
    } catch (e) {
      setError(String((e as Error)?.message ?? e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", background: T.bg }}>
      <div className="panel-head">
        <span className="panel-title">Replay</span>
        <span style={{ fontFamily: MONO, fontSize: 11, color: running ? T.text2 : T.text3, marginLeft: "auto" }}>
          {running ? `running at ${status?.speed ?? speed}×` : "stopped"}
        </span>
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: 16, maxWidth: 820 }}>
        {error && (
          <div style={{ fontFamily: SANS, fontSize: 12, color: T.text2, marginBottom: 12 }}>
            Replay control unavailable (<span style={{ fontFamily: MONO, color: T.text3 }}>{error}</span>). Detection is unaffected.
          </div>
        )}

        <div style={{ ...microStyle, marginBottom: 6 }}>Capture</div>
        <div style={{ border: `1px solid ${T.rule}`, marginBottom: 16 }}>
          {captures === null && (
            <div style={{ padding: "10px 12px", fontFamily: SANS, fontSize: 12, color: T.text3 }}>Reading capture list…</div>
          )}
          {captures?.length === 0 && (
            <div style={{ padding: "10px 12px", fontFamily: SANS, fontSize: 12, color: T.text3 }}>
              No captures on this host.
            </div>
          )}
          {captures?.map((c) => (
            <button
              key={c.capture}
              className="pick-row"
              aria-selected={selected === c.capture}
              onClick={() => setSelected(c.capture)}
              style={{ padding: "10px 12px", borderBottom: `1px solid ${T.rule}` }}
            >
              <div style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
                <span style={{ fontFamily: MONO, fontSize: 13, color: T.text }}>{c.capture}</span>
                <span style={{ fontFamily: MONO, fontSize: 11, color: T.text3, marginLeft: "auto" }}>
                  {c.alerts.toLocaleString()} alerts · {(c.size_bytes / 1e6).toFixed(1)} MB
                </span>
              </div>
            </button>
          ))}
        </div>

        <div style={{ display: "flex", gap: 32, marginBottom: 16, flexWrap: "wrap" }}>
          <div>
            <div style={{ ...microStyle, marginBottom: 6 }}>Speed</div>
            <div style={{ display: "flex", gap: 6 }}>
              {SPEEDS.map((s) => (
                <button
                  key={s}
                  className="chip mono"
                  aria-pressed={speed === s}
                  onClick={() => setSpeed(s)}
                  style={{ color: speed === s ? T.text : T.text2 }}
                >
                  {s}&times;
                </button>
              ))}
            </div>
          </div>
          <div>
            <div style={{ ...microStyle, marginBottom: 6 }}>Loop</div>
            <button className="chip" aria-pressed={loop} onClick={() => setLoop((v) => !v)} style={{ color: loop ? T.text : T.text2 }}>
              {loop ? "on" : "off"}
            </button>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <button
            onClick={running ? stop : start}
            disabled={busy || (!running && !selected)}
            style={{
              display: "flex", alignItems: "center", gap: 6, fontFamily: SANS, fontSize: 12, fontWeight: 600,
              padding: "8px 14px", borderRadius: 2, border: `1px solid ${T.ruleBright}`,
              background: running ? T.panel2 : "transparent", color: selected || running ? T.text : T.text3,
            }}
          >
            {running ? <Square size={13} /> : <Play size={13} />}
            {running ? "Stop" : "Start"}
          </button>
          <span style={{ fontFamily: MONO, fontSize: 12, color: T.text2 }}>
            {status
              ? running
                ? `${status.position.toLocaleString()} / ${status.total.toLocaleString()} · ${status.emitted.toLocaleString()} emitted · ${fmt.duration(status.elapsed_s)}`
                : selected
                  ? "stopped"
                  : "no capture selected"
              : "status unavailable"}
          </span>
        </div>

        {status && status.total > 0 && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ height: 6, background: T.rule, position: "relative" }}>
              <div style={{ position: "absolute", left: 0, top: 0, bottom: 0, background: T.text2, width: `${(position * 100).toFixed(2)}%` }} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", marginTop: 4, fontFamily: MONO, fontSize: 10, color: T.text3 }}>
              <span>0</span>
              <span>{(position * 100).toFixed(1)}%</span>
              <span>{status.total.toLocaleString()}</span>
            </div>
            {status.rejected > 0 && (
              <div style={{ fontFamily: MONO, fontSize: 11, color: T.sevMed, marginTop: 6 }}>
                {status.rejected.toLocaleString()} rejected by schema validation
              </div>
            )}
          </div>
        )}

        {active && (
          <div style={{ borderTop: `1px solid ${T.rule}`, paddingTop: 12 }}>
            <div style={{ ...microStyle, marginBottom: 6 }}>Ground truth · this capture is known to contain</div>
            {scenarioLines(active.scenario).length === 0 ? (
              <div style={{ fontFamily: SANS, fontSize: 12, color: T.text3 }}>No manifest published beside this capture.</div>
            ) : (
              scenarioLines(active.scenario).map((line, i) => (
                <div key={i} style={{ fontFamily: MONO, fontSize: 12, color: T.text2, padding: "3px 0" }}>
                  {line}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}
