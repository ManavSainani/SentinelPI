import { describe, expect, it } from "vitest";
import { eventTypeLabel, formatAge, formatPercent, formatTemp, formatUptime } from "./format";

describe("formatting", () => {
  it("describes ages in the largest sensible unit", () => {
    expect(formatAge(0)).toBe("just now");
    expect(formatAge(4)).toBe("just now");
    expect(formatAge(12)).toBe("12 s ago");
    expect(formatAge(180)).toBe("3 min ago");
    expect(formatAge(7300)).toBe("2 h ago");
    expect(formatAge(3 * 86_400)).toBe("3 d ago");
    expect(formatAge(-50)).toBe("just now"); // a clock a little ahead of the server
  });
  it("formats uptime", () => {
    expect(formatUptime(59)).toBe("0 min");
    expect(formatUptime(3700)).toBe("1 h 1 min");
    expect(formatUptime(2 * 86_400 + 3 * 3600)).toBe("2 d 3 h");
  });
  it("formats percentages and temperatures, including missing ones", () => {
    expect(formatPercent(12.34)).toBe("12.3%");
    expect(formatPercent(100)).toBe("100%");
    expect(formatTemp(51.46)).toBe("51.5 °C");
    expect(formatTemp(null)).toBe("n/a");
  });
  it("turns event types into words", () => {
    expect(eventTypeLabel("auth.ssh_failed_login")).toBe("ssh failed login");
    expect(eventTypeLabel("detection.new_listening_port")).toBe("new listening port");
    expect(eventTypeLabel("plain")).toBe("plain");
  });
});
