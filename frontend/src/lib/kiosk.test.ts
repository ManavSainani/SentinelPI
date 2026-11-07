import { describe, expect, it } from "vitest";
import { alerting, status } from "../test/fixtures";
import { kioskState } from "./kiosk";

const NOW = 1_000_000;

describe("kioskState", () => {
  it("waits for the first answer, then reports being offline if it never comes", () => {
    expect(kioskState(null, 0, null, NOW).mode).toBe("waiting");
    expect(kioskState(null, 1, null, NOW).mode).toBe("offline");
  });
  it("shows the normal screen when nothing is open", () => {
    expect(kioskState(status(), 0, NOW, NOW)).toEqual({ mode: "normal", stale: false });
  });
  it.each(["high", "critical"] as const)("goes full screen for an open %s incident", (sev) => {
    expect(kioskState(alerting(sev), 0, NOW, NOW).mode).toBe("alert");
  });
  it.each(["low", "medium"] as const)("keeps the normal screen for %s severity", (sev) => {
    expect(kioskState(alerting(sev), 0, NOW, NOW).mode).toBe("normal");
  });
  it("never hides an alert that was already showing when the connection fails", () => {
    const s = kioskState(alerting("high"), 5, NOW - 120_000, NOW);
    expect(s).toEqual({ mode: "alert", stale: true });
  });
  it("marks readings stale when refreshes fail, are old, or the monitor stopped", () => {
    expect(kioskState(status(), 2, NOW, NOW).stale).toBe(true);
    expect(kioskState(status(), 0, NOW - 31_000, NOW).stale).toBe(true);
    expect(kioskState(status({ monitor: { running: false, last_heartbeat: null, age_seconds: null } }), 0, NOW, NOW).stale).toBe(true);
    const m = status();
    m.metrics = { ...m.metrics!, stale: true };
    expect(kioskState(m, 0, NOW, NOW).stale).toBe(true);
    expect(kioskState(status({ metrics: null }), 0, NOW, NOW).stale).toBe(true);
  });
});
