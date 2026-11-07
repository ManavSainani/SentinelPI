import { describe, expect, it } from "vitest";
import { alerting, status } from "../test/fixtures";
import { describeStatus } from "./statusText";

describe("describeStatus", () => {
  it("says it is connecting before the first answer", () => {
    expect(describeStatus(null, false)).toMatchObject({ tone: "offline", label: "Connecting" });
  });
  it("says there is no connection, and that nothing can be trusted", () => {
    const h = describeStatus(null, true);
    expect(h.label).toBe("No connection");
    expect(h.sentence).toMatch(/nothing here can be trusted/);
  });
  it("says all quiet when nothing is wrong", () => {
    expect(describeStatus(status(), false)).toEqual({
      tone: "ok",
      label: "All quiet",
      sentence: "Nothing needs attention on manavpi.",
    });
  });
  it("names the most serious open incident and counts the rest", () => {
    const s = alerting("high");
    s.incidents.open = 3;
    const h = describeStatus(s, false);
    expect(h.tone).toBe("alert");
    expect(h.label).toBe("Alert");
    expect(h.sentence).toBe("Repeated SSH failures from 203.0.113.9 (high) and 2 more open.");
  });
  it("uses a warning for lower severities", () => {
    expect(describeStatus(alerting("medium"), false)).toMatchObject({ tone: "warning", label: "Needs attention" });
  });
  it("explains a stopped monitor even with no incidents", () => {
    const s = status({ overall: "warning", reasons: ["the monitor is not running (data may be out of date)"] });
    expect(describeStatus(s, false).sentence).toBe("The monitor is not running (data may be out of date).");
  });
});
