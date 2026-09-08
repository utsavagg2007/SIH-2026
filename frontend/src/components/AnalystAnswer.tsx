/**
 * How a Layer 8 answer is rendered, wherever it is rendered.
 *
 * Extracted from `AnalystPanel` when the chat dock arrived, because provenance
 * is the whole argument of this layer and two surfaces rendering it two ways
 * would be two chances to render it weakly. Both the alert-scoped panel and the
 * corpus-scoped chat import these, so a badge or a citation looks and means the
 * same thing in either place.
 *
 * The rules these components enforce, all from spec 6.5:
 *
 *   * Claims render from the `citations` array, not from the prose. Statements
 *     that cannot be traced to a stored field must not be shown at all, and
 *     rendering the array is what makes that structurally true rather than
 *     merely intended.
 *
 *   * `generated: false` is badged, never hidden. It means the text is the
 *     deterministic local rendering rather than model output - a stronger claim
 *     about provenance, not a weaker one.
 *
 *   * A source naming the knowledge base is badged apart from one naming an
 *     evidence field. Background about a threat class and a measurement taken
 *     off this network are both legitimate, and they are not the same kind of
 *     statement; a judge asking "where did that sentence come from" should get
 *     different answers for the two without having to ask twice.
 */
import { T, MONO, SANS, labelStyle } from "../lib/tokens";
import type { AnalystAnswer } from "../lib/types";

/**
 * The provenance badge. 9px sans, uppercase, 1px rule, unsaturated - the
 * console's existing badge idiom, because colour in this product is reserved
 * entirely for severity and threat class (spec 2.1). Provenance is information,
 * but it is not severity, so it must not borrow the ramp.
 */
export function Badge({ children, strong = false }: { children: React.ReactNode; strong?: boolean }) {
  return (
    <span
      style={{
        fontFamily: SANS,
        fontSize: 9,
        fontWeight: 600,
        letterSpacing: "0.07em",
        textTransform: "uppercase",
        color: strong ? T.text2 : T.text3,
        border: `1px solid ${strong ? T.ruleBright : T.rule}`,
        padding: "3px 4px",
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

/** Sources of the form `knowledge base: c2_beaconing`, which the analyst layer
 *  uses for reference material rather than for anything measured here. */
const KNOWLEDGE_SOURCE = /^knowledge base: /;

/**
 * One traced claim: the statement, then the stored field it came from as a
 * small inline reference. The reference is mono because it names a field the
 * machine produced; the claim is sans because it is a sentence written for a
 * human (spec 2.3).
 */
export function Claim({ text, source, value }: { text: string; source: string; value?: unknown }) {
  const shown =
    value === null || value === undefined || typeof value === "object"
      ? null
      : String(value);
  const isReference = KNOWLEDGE_SOURCE.test(source);
  return (
    <div style={{ padding: "7px 0", borderBottom: `1px solid ${T.rule}` }}>
      <div
        style={{
          fontFamily: SANS,
          fontSize: 13,
          lineHeight: 1.5,
          // Reference material is set one step back from measurement. It is
          // true and it is cited, but it is not something this network
          // observed, and the eye should be able to tell without reading the
          // source line.
          color: isReference ? T.text2 : T.text,
        }}
      >
        {text}
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 6, marginTop: 3, flexWrap: "wrap" }}>
        <span style={{ fontFamily: MONO, fontSize: 10, color: T.text3 }}>
          {isReference ? source.replace(KNOWLEDGE_SOURCE, "reference · ") : `[${source}]`}
        </span>
        {shown !== null && (
          <span style={{ fontFamily: MONO, fontSize: 10, color: T.text2, fontVariantNumeric: "tabular-nums" }}>
            {shown}
          </span>
        )}
      </div>
    </div>
  );
}

export function Answer({ answer }: { answer: AnalystAnswer }) {
  const measured = answer.citations.filter((c) => !KNOWLEDGE_SOURCE.test(c.source)).length;
  const reference = answer.citations.length - measured;

  return (
    <>
      <div style={{ padding: "12px 14px", borderBottom: `1px solid ${T.rule}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8, flexWrap: "wrap" }}>
          {answer.generated ? (
            <Badge>model output &middot; {answer.provider}{answer.model ? ` ${answer.model}` : ""}</Badge>
          ) : (
            <Badge strong>rendered locally &middot; no model</Badge>
          )}
        </div>
        <div style={{ fontFamily: SANS, fontSize: 13, lineHeight: 1.6, color: T.text }}>
          {answer.text}
        </div>
        {answer.degraded_reason && (
          // Surfaced, not swallowed. When generation was attempted and the
          // result was rejected as ungrounded, that rejection is the system
          // working, and saying why is more reassuring than hiding it.
          <div style={{ marginTop: 8, fontFamily: MONO, fontSize: 10, color: T.text3, lineHeight: 1.5 }}>
            generation declined: {answer.degraded_reason}
          </div>
        )}
        {answer.interpreted_as && answer.interpreted_as.length > 0 && (
          <div style={{ marginTop: 8 }}>
            <div style={{ ...labelStyle, marginBottom: 3 }}>read as</div>
            <div style={{ fontFamily: MONO, fontSize: 11, color: T.text2, lineHeight: 1.5 }}>
              {answer.interpreted_as.join(" · ")}
            </div>
          </div>
        )}
      </div>

      <div style={{ padding: "12px 14px" }}>
        <div style={{ ...labelStyle, marginBottom: 4 }}>
          Claims and their fields ({answer.citations.length})
          {reference > 0 && (
            <span style={{ fontWeight: 400, textTransform: "none", letterSpacing: 0 }}>
              {" "}— {measured} measured, {reference} reference
            </span>
          )}
        </div>
        {answer.citations.length === 0 ? (
          <div style={{ fontFamily: SANS, fontSize: 12, color: T.text3, paddingTop: 4 }}>
            No stored field supports a statement about this subject.
          </div>
        ) : (
          answer.citations.map((c, i) => (
            <Claim key={`${c.source}-${i}`} text={c.text} source={c.source} value={c.value} />
          ))
        )}
      </div>
    </>
  );
}
