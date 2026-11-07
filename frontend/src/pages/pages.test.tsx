import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { StatusBand } from "../components/StatusBand";
import { StatusProvider } from "../hooks/status";
import { alerting, detail, event, incident, status } from "../test/fixtures";
import { errorResponse, mockApi, page } from "../test/mockApi";
import { IncidentDetail } from "./IncidentDetail";
import { Incidents } from "./Incidents";
import { Kiosk } from "./Kiosk";
import { Network } from "./Network";
import { Overview } from "./Overview";
import { Events } from "./Events";

afterEach(() => vi.unstubAllGlobals());

const base = {
  "/events": page([event()]),
  "/system/metrics": { from: "", to: "", interval_seconds: null, truncated: false, points: [] },
  "/incidents": page([]),
  "/rules": { items: [{ id: "SP-001", name: "Repeated SSH failures", enabled: true, severity: "high", description: "Many failed sign-ins.", thresholds: {} }] },
};
const wrap = (ui: React.ReactNode) => render(<StatusProvider intervalMs={60_000}>{ui}</StatusProvider>);

describe("Kiosk", () => {
  it("shows the normal screen with readings when all is quiet", async () => {
    mockApi({ ...base, "/system/status": status() });
    wrap(<Kiosk />);
    expect(await screen.findByText("All quiet")).toBeInTheDocument();
    expect(screen.getByText("12.5%")).toBeInTheDocument();
    expect(screen.getByText(/None\. Nothing has needed attention/)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });
  it("takes over the screen for a high-severity open incident, with details", async () => {
    mockApi({ ...base, "/system/status": alerting("high"), "/incidents/11111111-1111-4111-8111-111111111111": detail() });
    wrap(<Kiosk />);
    const alertBox = await screen.findByRole("alert");
    expect(within(alertBox).getByRole("heading", { name: "Repeated SSH failures from 203.0.113.9" })).toBeInTheDocument();
    expect(within(alertBox).getByText("High")).toBeInTheDocument(); // the word, not just a colour
    expect(within(alertBox).getByText("203.0.113.9")).toBeInTheDocument();
    expect(await within(alertBox).findByText(/8 failed SSH attempts/)).toBeInTheDocument();
    expect(within(alertBox).getByText(/Acknowledge this incident from the dashboard/)).toBeInTheDocument();
  });
  it("keeps medium severity on the normal screen", async () => {
    mockApi({ ...base, "/system/status": alerting("medium") });
    wrap(<Kiosk />);
    expect(await screen.findByText("Needs attention")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getAllByText(/Repeated SSH failures/).length).toBeGreaterThan(0);
  });
  it("says so plainly when the server cannot be reached", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("down")));
    wrap(<Kiosk />);
    expect(await screen.findByText("SentinelPi is not answering")).toBeInTheDocument();
  });
  it("warns when the monitor has stopped, without hiding the readings", async () => {
    mockApi({ ...base, "/system/status": status({ monitor: { running: false, last_heartbeat: null, age_seconds: null } }) });
    wrap(<Kiosk />);
    expect(await screen.findByText(/the monitor is not running/)).toBeInTheDocument();
    expect(screen.getByText("12.5%")).toBeInTheDocument();
  });
});

describe("StatusBand", () => {
  it("pairs the state with a word, and reports a lost connection", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("down")));
    wrap(<StatusBand />);
    expect(await screen.findByText("No connection")).toBeInTheDocument();
  });
  it("reads all quiet", async () => {
    mockApi({ ...base, "/system/status": status() });
    wrap(<StatusBand />);
    expect(await screen.findByText("All quiet")).toBeInTheDocument();
    expect(await screen.findByRole("img", { name: /event/i })).toBeInTheDocument();
  });
});

describe("Overview", () => {
  it("tells you what to do when nothing has been collected", async () => {
    mockApi({ ...base, "/system/status": status({ metrics: null }) });
    wrap(<Overview />);
    expect(await screen.findByText(/No system metrics have been collected yet/)).toBeInTheDocument();
    expect(screen.getByText(/No open incidents/)).toBeInTheDocument();
  });
  it("shows an error with a retry when the server is down", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("down")));
    wrap(<Overview />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/Could not reach the SentinelPi server/);
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });
  it("summarises open incidents by severity", async () => {
    mockApi({
      ...base,
      "/system/status": alerting("high"),
      "/incidents": page([incident(), incident({ id: "b", severity: "medium", title: "New listening port on manavpi" })]),
    });
    wrap(<Overview />);
    expect(await screen.findByText("1 high, 1 medium")).toBeInTheDocument();
  });
});

describe("Incidents", () => {
  it("lists incidents with a clear empty state per tab", async () => {
    mockApi({ ...base });
    wrap(<Incidents />);
    expect(await screen.findByText(/No open incidents/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Resolved" }));
    expect(await screen.findByText("No resolved incidents yet.")).toBeInTheDocument();
  });
  it("shows rows with severity words and links to the detail page", async () => {
    mockApi({ ...base, "/incidents": page([incident()], { total: 1 }) });
    wrap(<Incidents />);
    const link = await screen.findByRole("link", { name: "Repeated SSH failures from 203.0.113.9" });
    expect(link).toHaveAttribute("href", "#/incidents/11111111-1111-4111-8111-111111111111");
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("Showing 1 of 1")).toBeInTheDocument();
  });
  it("loads older incidents with the cursor", async () => {
    const { calls } = mockApi({
      ...base,
      "/incidents": (url: URL) =>
        url.searchParams.get("cursor")
          ? page([incident({ id: "older", title: "Older incident" })], { total: 2 })
          : page([incident()], { total: 2, next_cursor: "CUR" }),
    });
    wrap(<Incidents />);
    fireEvent.click(await screen.findByRole("button", { name: "Show older" }));
    expect(await screen.findByText("Older incident")).toBeInTheDocument();
    expect(calls[calls.length - 1]?.search).toContain("cursor=CUR");
    expect(screen.queryByRole("button", { name: "Show older" })).toBeNull();
  });
});

describe("IncidentDetail", () => {
  const route = "/incidents/11111111-1111-4111-8111-111111111111";
  const id = "11111111-1111-4111-8111-111111111111";

  it("shows what happened, why it scored, and the timeline", async () => {
    mockApi({ ...base, [route]: detail() });
    render(<IncidentDetail id={id} />);
    expect(await screen.findByRole("heading", { name: "Repeated SSH failures from 203.0.113.9" })).toBeInTheDocument();
    expect(screen.getByText(/Why it scored 35/)).toBeInTheDocument();
    expect(await screen.findByText(/Many failed sign-ins\./)).toBeInTheDocument();
    expect(screen.getByText(/SentinelPi opened this incident/)).toBeInTheDocument();
    expect(screen.getByText(/not a probability of compromise/)).toBeInTheDocument();
  });
  it("acknowledges straight away but asks before a final change", async () => {
    const { calls } = mockApi({ ...base, [route]: detail(), [`PATCH ${route}`]: incident({ status: "acknowledged" }) });
    render(<IncidentDetail id={id} />);
    fireEvent.change(await screen.findByLabelText(/Note/), { target: { value: "looking" } });
    fireEvent.click(screen.getByRole("button", { name: "Acknowledge" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ status: "acknowledged", note: "looking" });

    fireEvent.click(screen.getByRole("button", { name: "Mark resolved" }));
    expect(screen.getByRole("alertdialog")).toHaveTextContent(/This is final/);
    expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1); // nothing sent yet
    fireEvent.click(screen.getByRole("button", { name: /Yes, mark resolved/ }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(2));
    expect(calls.filter((c) => c.method === "PATCH")[1].body).toEqual({ status: "resolved" });
  });
  it("cancelling a final change sends nothing", async () => {
    const { calls } = mockApi({ ...base, [route]: detail() });
    render(<IncidentDetail id={id} />);
    fireEvent.click(await screen.findByRole("button", { name: "Mark false positive" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
  });
  it("shows the server's reason when a change is refused", async () => {
    mockApi({ ...base, [route]: detail(), [`PATCH ${route}`]: () => errorResponse(409, "invalid_transition", "cannot change an incident from resolved to resolved") });
    render(<IncidentDetail id={id} />);
    fireEvent.click(await screen.findByRole("button", { name: "Acknowledge" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/cannot change an incident/);
  });
  it("offers no actions once an incident is final", async () => {
    mockApi({ ...base, [route]: detail({ status: "resolved", resolution_note: "blocked at the router" }) });
    render(<IncidentDetail id={id} />);
    expect(await screen.findByText(/can no longer be changed/)).toHaveTextContent("blocked at the router");
    expect(screen.queryByRole("button", { name: "Acknowledge" })).toBeNull();
  });
  it("explains a missing incident", async () => {
    mockApi({ ...base, [route]: () => errorResponse(404, "not_found", "No such incident.") });
    render(<IncidentDetail id={id} />);
    expect(await screen.findByText(/does not exist/)).toBeInTheDocument();
  });
});

describe("Events", () => {
  it("filters server-side and shows details with redacted metadata", async () => {
    const { calls } = mockApi({ ...base, "/events": page([event({ metadata: { attempts: 8 } })], { total: 1 }) });
    render(<Events />);
    fireEvent.click(await screen.findByRole("button", { name: "ssh failed login" }));
    expect(screen.getByLabelText("Event details")).toHaveTextContent('"attempts": 8');
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "high" } });
    fireEvent.change(screen.getByLabelText("Source address"), { target: { value: "203.0.113.9" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(calls[calls.length - 1]?.search).toContain("severity=high"));
    expect(calls[calls.length - 1]?.search).toContain("source_ip=203.0.113.9");
  });
  it("explains an empty result and a rejected filter", async () => {
    mockApi({ ...base, "/events": () => errorResponse(400, "bad_ip", "source_ip must be an IPv4 or IPv6 address.") });
    render(<Events />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/source_ip must be an IPv4/);
  });
});

describe("Network", () => {
  it("flags ports that are new since the baseline, in words", async () => {
    mockApi({
      "/network/listeners": {
        observed_at: new Date().toISOString(),
        baseline_captured_at: new Date().toISOString(),
        items: [
          { protocol: "tcp", local_address: "0.0.0.0", port: 22, process_name: "sshd", pid: 1, reachable_beyond_loopback: true, in_baseline: true },
          { protocol: "tcp", local_address: "0.0.0.0", port: 8765, process_name: "python", pid: 2, reachable_beyond_loopback: true, in_baseline: false },
          { protocol: "udp", local_address: "::", port: 5353, process_name: null, pid: null, reachable_beyond_loopback: true, in_baseline: null },
        ],
        total: 3,
        limit: 200,
      },
    });
    render(<Network />);
    expect(await screen.findByText("New since baseline")).toBeInTheDocument();
    expect(screen.getByText("Expected")).toBeInTheDocument();
    expect(screen.getByText("Not compared")).toBeInTheDocument();
  });
  it("tells you how to create a baseline when there is none", async () => {
    mockApi({ "/network/listeners": { observed_at: null, baseline_captured_at: null, items: [], total: 0, limit: 200 } });
    render(<Network />);
    expect(await screen.findByText(/No port baseline is approved yet/)).toBeInTheDocument();
  });
});
