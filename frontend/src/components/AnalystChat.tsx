/**
 * The analyst chat dock: bottom-right launcher, corpus-scoped question and
 * answer over the stored alert history.
 *
 * This is deliberately a second surface rather than a replacement for
 * `AnalystPanel`. The two answer different questions and the distinction is
 * worth keeping:
 *
 *   * The panel is an annotation on the alert you are already looking at. It
 *     explains without being asked, and it follows the selection.
 *   * This is a question you came with. Nothing needs to be selected, and the
 *     subject is the corpus - "what is DNS tunnelling", "which hosts beaconed
 *     in the last hour", "anything critical on 10.4.2.19".
 *
 * Both call the same Layer 8 service and render answers through the same
 * `AnalystAnswer` components, so provenance is badged identically in both.
 *
 * Every rule the panel holds to holds here. Claims render from the citations
 * array rather than from the prose. `generated: false` is badged rather than
 * hidden. The service being down is one line of fact, not a stack trace, and
 * nothing else on the console is affected by it - Layer 8 is never on the
 * critical path.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { MessageSquare, X } from "lucide-react";
import { T, MONO, SANS, headingStyle, labelStyle } from "../lib/tokens";
import { analyst, AnalystUnavailable } from "../lib/api";
import { Answer, Badge } from "./AnalystAnswer";
import type { AnalystAnswer, AnalystHealth } from "../lib/types";

/** Clear of the 48px instrument bar, which owns the bottom edge. */
const BOTTOM = 64;
const WIDTH = 400;

/**
 * Openers, one per kill-chain stage rather than one per threat class.
 *
 * An empty input is the thing that stops an analyst using a tool during an
 * incident, and seven chips would be a menu rather than a prompt. These four
 * are phrased as an operator would actually type them, and each exercises a
 * different half of the layer: the first two resolve to a threat class the
 * knowledge base answers, the last two to filters retrieval answers.
 */
const OPENERS = [
  "What is DGA and how is it detected?",
  "Explain beaconing",
  "Anything critical in the last hour?",
  "Which hosts are exfiltrating data?",
];

type Turn = {
  /** Issued from a ref, not derived from the array length. The length is only
   *  knowable inside a state updater, and an updater is not the place to
   *  produce a value the rest of the call depends on - React is free to invoke
   *  it more than once. */
  id: number;
  question: string;
  state: "working" | "answered" | "unavailable" | "failed";
  answer?: AnalystAnswer;
  detail?: string;
};

/** Health line under the header: what is answering, and whether a model is
 *  involved at all. "Does your LLM have network access" should be readable off
 *  the panel rather than requiring an explanation. */
function Provenance({ health }: { health: AnalystHealth | null }) {
  if (!health) return null;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
      {health.generation_enabled ? (
        <Badge>
          {health.provider}
          {health.model ? ` ${health.model}` : ""}
        </Badge>
      ) : (
        <Badge strong>no model &middot; local rendering</Badge>
      )}
      {!health.alert_store_reachable && <Badge strong>alert store unreachable</Badge>}
    </div>
  );
}

interface Props {
  /**
   * True while `AnalystPanel` is on screen.
   *
   * The panel is docked to the right edge and carries its own ask input in a
   * footer outside its scroll region, so the launcher landed directly on top of
   * that input's button - and unlike the scrolling regions, a footer cannot be
   * scrolled clear of it.
   *
   * Standing the launcher down is the right fix rather than nudging it aside,
   * because the collision was the visible half of a redundancy: both surfaces
   * call the same `/ask`, so with the panel open the launcher offered a second
   * route to something already on screen. Nothing is lost while it is hidden,
   * and it returns the moment the panel closes.
   */
  suppressed?: boolean;
}

export function AnalystChat({ suppressed = false }: Props) {
  const [open, setOpen] = useState(false);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [question, setQuestion] = useState("");
  const [health, setHealth] = useState<AnalystHealth | null>(null);

  const scroller = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const nextId = useRef(0);

  // Ask on open rather than on mount: an unopened dock should not be the reason
  // a process on :8100 gets a request, and the health line is only ever read
  // while the dock is visible.
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    analyst
      .health()
      .then((h) => !cancelled && setHealth(h))
      .catch(() => !cancelled && setHealth(null));
    input.current?.focus();
    return () => {
      cancelled = true;
    };
  }, [open]);

  // "/" opens the dock, from any view. The console is keyboard-driven and the
  // stream already binds j/k/a/e/0-4, but all of those are scoped to the live
  // view; this one is global because the dock is. Registered here rather than
  // in App's handler for the same reason - the shortcut belongs to the
  // component that owns the surface it opens.
  useEffect(() => {
    if (open || suppressed) return;
    function onKey(e: KeyboardEvent) {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      const tag = (document.activeElement as HTMLElement | null)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") return;
      // Firefox opens quick-find on "/", which would steal the keystroke and
      // put a search bar over the console.
      e.preventDefault();
      setOpen(true);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, suppressed]);

  // Newest turn to the TOP of the viewport, not the bottom of the transcript.
  // Pinning to scrollHeight put the end of the newest answer on screen and its
  // first line above it, so every answer long enough to need the space had to
  // be scrolled back up before it could be read. Scrolling to the question
  // instead puts the start of what you just asked - and the answer under it -
  // where reading starts. The browser clamps scrollTop, so a short transcript
  // simply stays where it is.
  useEffect(() => {
    const el = scroller.current;
    const newest = el?.lastElementChild;
    if (!el || !newest) return;
    el.scrollTop += newest.getBoundingClientRect().top - el.getBoundingClientRect().top;
  }, [turns]);

  const ask = useCallback(async (raw: string) => {
    const q = raw.trim();
    if (!q) return;
    setQuestion("");

    // The id is this turn's identity for the rest of the call, so two questions
    // asked in quick succession cannot resolve into each other's slot.
    const id = nextId.current++;
    setTurns((prev) => [...prev, { id, question: q, state: "working" }]);

    const settle = (patch: Omit<Turn, "id" | "question">) =>
      setTurns((prev) => prev.map((t) => (t.id === id ? { ...t, ...patch } : t)));

    try {
      settle({ state: "answered", answer: await analyst.ask(q) });
    } catch (e) {
      if (e instanceof AnalystUnavailable) settle({ state: "unavailable" });
      else settle({ state: "failed", detail: e instanceof Error ? e.message : String(e) });
    }
  }, []);

  // Suppressed only gates the launcher, never an open dock: closing the thing
  // someone is reading because a panel opened behind it would be worse than
  // the overlap.
  if (!open && suppressed) return null;

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        // Must begin with the visible label. Browsers name this button from
        // the title rather than from its content, and "Ask the analyst" does
        // not contain "Ask analyst" - which fails WCAG 2.5.3 and means a
        // speech-input user saying what they can see does not activate it.
        title="Ask analyst (/)"
        className="ask-launcher"
        style={{ position: "fixed", right: 16, bottom: BOTTOM, zIndex: 40 }}
      >
        <MessageSquare size={15} />
        Ask analyst
        {/* The shortcut is shown rather than documented. A floating control
            with no neighbour to explain it has to teach its own affordance,
            and a key nobody can discover is a key nobody presses. */}
        <kbd aria-hidden="true">/</kbd>
      </button>
    );
  }

  return (
    <section
      aria-label="Analyst chat"
      onKeyDown={(e) => {
        // The stream owns j/k/Escape globally. Inside the dock they belong to
        // the dock, or typing "jack" in the input would walk the alert list.
        e.stopPropagation();
        if (e.key === "Escape") setOpen(false);
      }}
      style={{
        position: "fixed",
        right: 16,
        bottom: BOTTOM,
        zIndex: 40,
        width: WIDTH,
        maxWidth: "calc(100vw - 32px)",
        height: "min(620px, calc(100vh - 140px))",
        background: T.panel,
        border: `1px solid ${T.ruleBright}`,
        display: "flex",
        flexDirection: "column",
        minHeight: 0,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "10px 14px",
          borderBottom: `1px solid ${T.rule}`,
          flexShrink: 0,
        }}
      >
        <span style={headingStyle}>Analyst</span>
        <Provenance health={health} />
        <button
          onClick={() => setOpen(false)}
          aria-label="Close analyst chat"
          style={{
            marginLeft: "auto",
            background: "none",
            border: "none",
            color: T.text3,
            cursor: "pointer",
            padding: 2,
            display: "flex",
          }}
        >
          <X size={14} />
        </button>
      </div>

      <div ref={scroller} style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>
        {turns.length === 0 && (
          <div style={{ padding: 14 }}>
            <div style={{ fontFamily: SANS, fontSize: 13, color: T.text2, lineHeight: 1.6 }}>
              Ask about a threat class, or about what this network has actually
              seen. Answers come from stored alerts and cite the field behind
              every claim.
            </div>
            <div style={{ ...labelStyle, marginTop: 14, marginBottom: 6 }}>Try</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {OPENERS.map((o) => (
                <button
                  key={o}
                  onClick={() => void ask(o)}
                  style={{
                    background: T.panel2,
                    border: `1px solid ${T.rule}`,
                    borderRadius: 2,
                    color: T.text2,
                    fontFamily: SANS,
                    fontSize: 12,
                    padding: "6px 8px",
                    cursor: "pointer",
                    textAlign: "left",
                  }}
                >
                  {o}
                </button>
              ))}
            </div>
          </div>
        )}

        {turns.map((turn) => (
          <div key={turn.id} style={{ borderBottom: `1px solid ${T.rule}` }}>
            <div
              style={{
                padding: "10px 14px",
                background: T.panel2,
                fontFamily: SANS,
                fontSize: 13,
                color: T.text,
                lineHeight: 1.5,
              }}
            >
              {turn.question}
            </div>

            {turn.state === "working" && (
              <div style={{ padding: 14, fontFamily: SANS, fontSize: 13, color: T.text3 }}>
                Querying stored alert history.
              </div>
            )}

            {turn.state === "unavailable" && (
              // Spec 9: name what failed and what still works, and do not
              // apologise. An instrument that apologises is one nobody trusts.
              <div style={{ padding: 14 }}>
                <div style={{ fontFamily: SANS, fontSize: 13, color: T.text2, lineHeight: 1.6 }}>
                  Analyst unavailable. Detection is unaffected.
                </div>
                <div style={{ marginTop: 8, fontFamily: MONO, fontSize: 10, color: T.text3, lineHeight: 1.5 }}>
                  Layer 8 runs as a separate process on :8100. Every other panel
                  reads the backend directly and is unchanged by its absence.
                </div>
              </div>
            )}

            {turn.state === "failed" && (
              <div style={{ padding: 14 }}>
                <div style={{ fontFamily: SANS, fontSize: 13, color: T.text2, lineHeight: 1.6 }}>
                  Analyst reached, request not resolved.
                </div>
                <div style={{ marginTop: 6, fontFamily: MONO, fontSize: 11, color: T.text3, lineHeight: 1.5 }}>
                  {turn.detail}
                </div>
              </div>
            )}

            {turn.state === "answered" && turn.answer && <Answer answer={turn.answer} />}
          </div>
        ))}
      </div>

      <div style={{ borderTop: `1px solid ${T.rule}`, padding: 12, flexShrink: 0, display: "flex", gap: 6 }}>
        <input
          ref={input}
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void ask(question);
          }}
          aria-label="Ask the analyst a question"
          placeholder="what is dns tunnelling?"
          style={{
            flex: 1,
            minWidth: 0,
            background: T.panel2,
            border: `1px solid ${T.rule}`,
            borderRadius: 2,
            color: T.text,
            fontFamily: SANS,
            fontSize: 12,
            padding: "6px 8px",
            outline: "none",
          }}
        />
        <button
          onClick={() => void ask(question)}
          className="ctl"
          style={{ flexShrink: 0, padding: "6px 10px" }}
        >
          Ask
        </button>
      </div>
    </section>
  );
}
