import { vi } from "vitest";

type Handler = unknown | ((url: URL, init?: RequestInit) => unknown);
export interface Call { method: string; path: string; search: string; body: unknown }

/** Replace fetch with an in-memory API. Keys are paths below /api/v1, e.g. "/system/status". */
export function mockApi(routes: Record<string, Handler>) {
  const calls: Call[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost");
    const path = url.pathname.replace(/^\/api\/v1/, "");
    const method = init?.method ?? "GET";
    calls.push({ method, path, search: url.search, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    const key = routes[`${method} ${path}`] !== undefined ? `${method} ${path}` : path;
    const handler = routes[key];
    if (handler === undefined) {
      return new Response(JSON.stringify({ error: { code: "not_found", message: "Not found." } }), { status: 404 });
    }
    const out = typeof handler === "function" ? (handler as (u: URL, i?: RequestInit) => unknown)(url, init) : handler;
    if (out instanceof Response) return out;
    return new Response(JSON.stringify(out), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock };
}

export const errorResponse = (status: number, code: string, message: string) =>
  new Response(JSON.stringify({ error: { code, message } }), { status });

export const page = <T,>(items: T[], extra: Record<string, unknown> = {}) => ({
  items, total: items.length, limit: 50, next_cursor: null, ...extra,
});
