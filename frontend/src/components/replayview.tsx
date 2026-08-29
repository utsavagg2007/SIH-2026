import { Play, Square } from "lucide-react";
import { T, MONO, SANS, headingStyle } from "../lib/tokens";

export interface ReplayState {
  capture: { id: string; name: string; scenario: string } | null;
  speed: number;
  running: boolean;
  elapsed: number;
}

const CAPTURES = [
  { id: "cap_beacon_01", name: "beacon_and_scan.pcap", scenario: "port scan at 0:30, beaconing C2 at 7:00" },
  { id: "cap_ddos_01", name: "flood_amplification.pcap", scenario: "spoofed DDoS flood at 2:00, amplification at 9:15" },
  { id: "cap_exfil_01", name: "dga_exfil.pcap", scenario: "DGA domain query at 1:10, exfiltration breakout at 14:40" },
];

// POST /replay/start { capture, speed } and POST /replay/stop, per section 7,
// live in the setReplay callbacks below — wire them to the mock server /
// real backend here.
export function ReplayView({ replay, setReplay }: { replay: ReplayState; setReplay: (updater: (r: ReplayState) => ReplayState) => void }) {
  return (
    <div style={{ flex: 1, padding: 24, maxWidth: 560 }}>
      <div style={{ ...headingStyle, marginBottom: 10 }}>Capture</div>
      <div style={{ border: `1px solid ${T.rule}`, marginBottom: 16 }}>
        {CAPTURES.map((c) => (
          <div
            key={c.id}
            onClick={() => setReplay((r) => ({ ...r, capture: c }))}
            style={{ padding: "10px 12px", borderBottom: `1px solid ${T.rule}`, cursor: "pointer", background: replay.capture?.id === c.id ? T.panel2 : "transparent" }}
          >
            <div style={{ fontFamily: MONO, fontSize: 13, color: T.text }}>{c.name}</div>
            <div style={{ fontFamily: SANS, fontSize: 11, color: T.text3, marginTop: 2 }}>{c.scenario}</div>
          </div>
        ))}
      </div>

      <div style={{ ...headingStyle, marginBottom: 10 }}>Speed</div>
      <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
        {[1, 2, 5, 10].map((s) => (
          <button
            key={s}
            onClick={() => setReplay((r) => ({ ...r, speed: s }))}
            style={{ fontFamily: MONO, fontSize: 12, padding: "5px 10px", borderRadius: 2, border: `1px solid ${replay.speed === s ? T.ruleBright : T.rule}`, background: replay.speed === s ? T.panel2 : "transparent", color: T.text2, cursor: "pointer" }}
          >
            {s}&times;
          </button>
        ))}
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
        <button
          onClick={() => setReplay((r) => ({ ...r, running: !r.running }))}
          disabled={!replay.capture}
          style={{
            display: "flex", alignItems: "center", gap: 6, fontFamily: SANS, fontSize: 12, fontWeight: 600,
            padding: "8px 14px", borderRadius: 2, border: `1px solid ${T.ruleBright}`,
            background: replay.running ? T.panel2 : "transparent", color: replay.capture ? T.text : T.text3,
            cursor: replay.capture ? "pointer" : "default",
          }}
        >
          {replay.running ? <Square size={13} /> : <Play size={13} />}
          {replay.running ? "Stop" : "Start"}
        </button>
        <span style={{ fontFamily: MONO, fontSize: 12, color: T.text2 }}>
          {replay.running ? `position ${replay.elapsed}s` : replay.capture ? "stopped" : "no capture loaded"}
        </span>
      </div>

      {replay.capture && (
        <div style={{ fontFamily: SANS, fontSize: 12, color: T.text2, borderTop: `1px solid ${T.rule}`, paddingTop: 12 }}>
          This capture contains: {replay.capture.scenario}.
        </div>
      )}
    </div>
  );
}