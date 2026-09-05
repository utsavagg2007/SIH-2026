/**
 * Shared chrome for the class-specific evidence visuals.
 *
 * Two things every visual in section 5.2 needs and none of them owned:
 *
 *   * The severity colour, passed in rather than picked. Spec 2.1 is explicit
 *     that colour is reserved entirely for severity and threat class, which
 *     means a visual must not choose a hue. Every one of these components used
 *     to hardcode `--sev-crit` or `--sev-high`, so a low-severity DGA domain
 *     and a critical one drew identically in critical red - the ramp stopped
 *     carrying information at exactly the moment it mattered.
 *
 *   * The provenance badge. The backend stamps a visual it reconstructed from
 *     summary statistics rather than observed series, precisely because such a
 *     picture is convincing by construction. Rendering that badge is what keeps
 *     the image an argument rather than an assertion.
 *
 * The badge now renders once, in the evidence panel's visual header beside the
 * title, rather than once per visual: six components each drawing their own
 * copy meant the placement drifted between classes, and the panel is where the
 * reader is already looking when the picture appears. `SourceBadge` stays
 * exported for any visual that needs to place it inline.
 */
import { Component, type ReactNode } from "react";
import { T, SANS } from "../../lib/tokens";
import type { VisualSource } from "../../lib/types";

/** Every class visual receives its alert's severity colour. */
export interface VisualChrome {
  sevColor: string;
}

/**
 * What a known visual kind renders when the backend did not send the series it
 * draws from. Naming the absent fields is the honest report: it says the
 * detector did not publish the shape, rather than showing an empty chart that
 * reads as "nothing happened".
 */
export function MissingSeries({ fields }: { fields: string[] }) {
  return (
    <div style={{ fontFamily: SANS, fontSize: 12, lineHeight: 1.5, color: T.text3, padding: "8px 0" }}>
      This detector reported no {fields.join(" or ")} for this alert. The evidence bars below carry the detection.
    </div>
  );
}

/**
 * Backstop for the class-visual slot.
 *
 * The contract is that an unknown or malformed `visual` degrades to evidence
 * bars and never breaks the interface. `classVisual` guards the shapes this
 * build knows about; this catches everything it does not - a future detector
 * with a field of the wrong type, a series of NaN - and keeps the failure
 * inside the one panel it belongs to. Without it, one bad payload unmounts the
 * whole console: React tears the tree down and the operator gets a blank
 * screen mid-demo.
 */
export class VisualBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidUpdate(prev: { children: ReactNode }) {
    // Reset on a new selection, so one broken alert does not suppress the
    // visual for every alert chosen after it.
    if (this.state.failed && prev.children !== this.props.children) {
      this.setState({ failed: false });
    }
  }

  render() {
    if (this.state.failed) {
      return (
        <div style={{ fontFamily: SANS, fontSize: 12, lineHeight: 1.5, color: T.text3, padding: "8px 0" }}>
          This visual could not be drawn from the payload the detector sent. The evidence bars below carry the detection.
        </div>
      );
    }
    return this.props.children;
  }
}

export function SourceBadge({ source }: { source?: VisualSource }) {
  if (source !== "reconstructed_from_summary_statistics") return null;
  return (
    <div
      style={{
        display: "inline-block",
        fontFamily: SANS,
        fontSize: 9,
        fontWeight: 600,
        letterSpacing: "0.07em",
        textTransform: "uppercase",
        color: T.text2,
        border: `1px solid ${T.ruleBright}`,
        padding: "3px 4px",
        marginBottom: 8,
      }}
      title="No observed series was reported for this alert. The shape below was derived from summary statistics and is illustrative, not observed."
    >
      reconstructed from summary statistics
    </div>
  );
}
