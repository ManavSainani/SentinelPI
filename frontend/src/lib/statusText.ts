import type { Overall, SystemStatus } from "../api/types";
import { SEVERITY_LABEL } from "./severity";

export interface Headline {
  tone: Overall | "offline";
  label: string;
  sentence: string;
}

/** The one-sentence answer to "is anything wrong?", from the API summary (or its absence). */
export function describeStatus(status: SystemStatus | null, failing: boolean): Headline {
  if (status === null) {
    return failing
      ? {
          tone: "offline",
          label: "No connection",
          sentence: "Cannot reach the SentinelPi server, so nothing here can be trusted right now.",
        }
      : { tone: "offline", label: "Connecting", sentence: "Contacting the SentinelPi server…" };
  }
  const top = status.active_alert;
  const open = status.incidents.open;
  if (top && open > 0) {
    const more = open > 1 ? ` and ${open - 1} more open` : "";
    return {
      tone: status.overall,
      label: status.overall === "alert" ? "Alert" : "Needs attention",
      sentence: `${top.title} (${SEVERITY_LABEL[top.severity].toLowerCase()})${more}.`,
    };
  }
  if (status.overall !== "ok" && status.reasons.length > 0) {
    const first = status.reasons[0];
    return {
      tone: status.overall,
      label: "Needs attention",
      sentence: first.charAt(0).toUpperCase() + first.slice(1) + ".",
    };
  }
  return { tone: "ok", label: "All quiet", sentence: `Nothing needs attention on ${status.host}.` };
}
