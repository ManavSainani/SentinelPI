import type { IncidentStatus, Severity } from "../api/types";

export const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

export const severityRank = (s: Severity): number => SEVERITIES.indexOf(s);

export const atLeast = (s: Severity, minimum: Severity): boolean =>
  severityRank(s) >= severityRank(minimum);

export const SEVERITY_LABEL: Record<Severity, string> = {
  info: "Info",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

export const STATUS_LABEL: Record<IncidentStatus, string> = {
  open: "Open",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
  false_positive: "False positive",
};

/** Incidents at or above this severity take over the kiosk screen while unacknowledged. */
export const KIOSK_ALERT_MINIMUM: Severity = "high";
