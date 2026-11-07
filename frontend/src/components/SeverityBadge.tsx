import type { IncidentStatus, Severity } from "../api/types";
import { SEVERITY_LABEL, STATUS_LABEL } from "../lib/severity";
import ui from "../ui.module.css";

// Shape + word + colour: severity never depends on colour alone.
const GLYPH: Record<Severity, string> = {
  info: "M12 5a7 7 0 1 0 0 14 7 7 0 0 0 0-14Zm0 2a5 5 0 1 1 0 10 5 5 0 0 1 0-10Z", // ring
  low: "M12 6a6 6 0 1 0 0 12 6 6 0 0 0 0-12Z", // disc
  medium: "M12 3 21 12 12 21 3 12Z", // diamond
  high: "M12 3 22 20H2Z", // triangle
  critical: "M8.5 3h7L21 8.5v7L15.5 21h-7L3 15.5v-7Z", // octagon
};

export function SeverityBadge({ severity, large = false }: { severity: Severity; large?: boolean }) {
  const size = large ? "1em" : "13px";
  return (
    <span
      className={ui.chip}
      style={{
        borderColor: `var(--sev-${severity})`,
        ...(large ? { fontSize: "clamp(1.3rem, 2.8vw, 2.8rem)", padding: "0.1em 0.6em", borderWidth: 2, gap: "0.4em" } : {}),
      }}
    >
      <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path d={GLYPH[severity]} fill={`var(--sev-${severity})`} fillRule="evenodd" />
      </svg>
      <span>{SEVERITY_LABEL[severity]}</span>
    </span>
  );
}

export function StatusChip({ status }: { status: IncidentStatus }) {
  const dim = status === "resolved" || status === "false_positive";
  return (
    <span className={ui.chip} style={dim ? { color: "var(--text-muted)" } : undefined}>
      {STATUS_LABEL[status]}
    </span>
  );
}
