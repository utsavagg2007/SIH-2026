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
 */
import { T, SANS } from "../../lib/tokens";
import type { VisualSource } from "../../lib/types";

/** Every class visual receives its alert's severity colour. */
export interface VisualChrome {
  sevColor: string;
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
