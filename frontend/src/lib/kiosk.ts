import type { SystemStatus } from "../api/types";
import { atLeast, KIOSK_ALERT_MINIMUM } from "./severity";

export type KioskMode = "waiting" | "offline" | "alert" | "normal";

export interface KioskState {
  mode: KioskMode;
  /** The figures on screen are old: refreshes are failing or the monitor has stopped. */
  stale: boolean;
}

const STALE_AFTER_MS = 30_000;

/**
 * What the HDMI screen should show. A full-screen alert needs an *unacknowledged* incident at
 * High or above (the API's `active_alert` is already the most severe open one), and it keeps
 * showing the last known alert even if the server stops answering: losing the connection must
 * never hide a problem that was already on screen.
 */
export function kioskState(
  status: SystemStatus | null,
  failures: number,
  updatedAt: number | null,
  now: number,
): KioskState {
  if (status === null) return { mode: failures > 0 ? "offline" : "waiting", stale: true };
  const stale =
    failures >= 2 ||
    (updatedAt !== null && now - updatedAt > STALE_AFTER_MS) ||
    !status.monitor.running ||
    (status.metrics?.stale ?? true);
  const alert = status.active_alert;
  if (alert && atLeast(alert.severity, KIOSK_ALERT_MINIMUM)) return { mode: "alert", stale };
  return { mode: "normal", stale };
}
