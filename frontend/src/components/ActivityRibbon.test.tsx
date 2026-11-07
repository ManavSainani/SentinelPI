import { describe, expect, it } from "vitest";
import type { Severity } from "../api/types";
import { event } from "../test/fixtures";
import { bucketEvents } from "./ActivityRibbon";

const NOW = Date.parse("2026-11-05T12:00:30Z");
const at = (minutesAgo: number, severity: Severity = "low") =>
  event({ timestamp: new Date(NOW - minutesAgo * 60_000).toISOString(), severity });

describe("bucketEvents", () => {
  it("puts the newest minute last and keeps the worst severity per minute", () => {
    const b = bucketEvents([at(0), at(0, "high"), at(0), at(2), at(59)], NOW);
    expect(b).toHaveLength(60);
    expect(b[59]).toEqual({ count: 3, top: "high" });
    expect(b[57]).toEqual({ count: 1, top: "low" });
    expect(b[0]).toEqual({ count: 1, top: "low" });
    expect(b[58]).toEqual({ count: 0, top: null });
  });
  it("ignores events outside the hour and from the future", () => {
    const b = bucketEvents([at(61), at(-5)], NOW);
    expect(b.every((x) => x.count === 0)).toBe(true);
  });
});
