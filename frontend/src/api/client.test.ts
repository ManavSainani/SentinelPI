import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "./client";
import { errorResponse, mockApi } from "../test/mockApi";

afterEach(() => vi.unstubAllGlobals());

describe("api client", () => {
  it("builds query strings and leaves out empty values", async () => {
    const { calls } = mockApi({ "/events": { items: [], total: 0, limit: 50, next_cursor: null } });
    await api.events({ severity: "high", type: "", source_ip: undefined, limit: 5, cursor: null });
    expect(calls[0].search).toBe("?severity=high&limit=5");
  });
  it("turns the API's error shape into an ApiError", async () => {
    mockApi({ "/incidents/abc": () => errorResponse(404, "not_found", "No such incident.") });
    await expect(api.incident("abc")).rejects.toMatchObject({ status: 404, code: "not_found", message: "No such incident." });
  });
  it("copes with an error that is not JSON", async () => {
    mockApi({ "/system/status": () => new Response("<html>bad gateway</html>", { status: 502 }) });
    const err = await api.status().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 502, code: "http_error" });
  });
  it("reports an unreachable server in plain words", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(api.status()).rejects.toMatchObject({ code: "unreachable" });
  });
  it("lets a caller's own abort through untouched", async () => {
    const ctrl = new AbortController();
    vi.stubGlobal("fetch", vi.fn((_u: string, init: RequestInit) => new Promise((_r, reject) => {
      init.signal!.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    })));
    const p = api.status(ctrl.signal);
    ctrl.abort();
    await expect(p).rejects.toMatchObject({ name: "AbortError" });
  });
  it("sends status changes as JSON PATCH and encodes ids", async () => {
    const { calls } = mockApi({ "PATCH /incidents/a%2Fb": { id: "x" } });
    await api.setIncidentStatus("a/b", "resolved", "done");
    expect(calls[0]).toMatchObject({ method: "PATCH", body: { status: "resolved", note: "done" } });
    await api.setIncidentStatus("a/b", "acknowledged");
    expect(calls[1].body).toEqual({ status: "acknowledged" });
  });
});
