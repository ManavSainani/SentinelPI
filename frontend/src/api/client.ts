import type {
  About,
  Health,
  Incident,
  IncidentDetail,
  IncidentStatus,
  ListenerList,
  MetricsSeries,
  Page,
  ProcessList,
  Rule,
  SentinelEvent,
  Severity,
  SystemStatus,
} from "./types";

const BASE = "/api/v1";
const TIMEOUT_MS = 10_000;

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

type Query = Record<string, string | number | boolean | null | undefined>;

function url(path: string, query?: Query): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const qs = params.toString();
  return `${BASE}${path}${qs ? `?${qs}` : ""}`;
}

/** One request with a timeout, JSON in and out, and the API's error shape turned into ApiError. */
async function request<T>(
  path: string,
  opts: { query?: Query; signal?: AbortSignal; method?: string; body?: unknown } = {},
): Promise<T> {
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), TIMEOUT_MS);
  const onAbort = () => timeout.abort();
  opts.signal?.addEventListener("abort", onAbort);
  try {
    const res = await fetch(url(path, opts.query), {
      method: opts.method ?? "GET",
      signal: timeout.signal,
      headers: opts.body === undefined ? undefined : { "Content-Type": "application/json" },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    });
    if (!res.ok) {
      let code = "http_error";
      let message = `The server answered HTTP ${res.status}.`;
      try {
        const data = (await res.json()) as { error?: { code?: string; message?: string } };
        if (data.error?.code) code = data.error.code;
        if (data.error?.message) message = data.error.message;
      } catch {
        /* not JSON: keep the generic message */
      }
      throw new ApiError(res.status, code, message);
    }
    return (await res.json()) as T;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (opts.signal?.aborted) throw err; // the caller cancelled: let it see the abort
    if (timeout.signal.aborted) {
      throw new ApiError(0, "timeout", "The server took too long to answer.");
    }
    throw new ApiError(0, "unreachable", "Could not reach the SentinelPi server.");
  } finally {
    clearTimeout(timer);
    opts.signal?.removeEventListener("abort", onAbort);
  }
}

export interface EventQuery {
  severity?: Severity;
  type?: string;
  source_ip?: string;
  from?: string;
  to?: string;
  limit?: number;
  cursor?: string | null;
}

export interface IncidentQuery {
  status?: IncidentStatus;
  severity?: Severity;
  limit?: number;
  cursor?: string | null;
}

export const api = {
  health: (signal?: AbortSignal) => request<Health>("/health", { signal }),
  status: (signal?: AbortSignal) => request<SystemStatus>("/system/status", { signal }),
  about: (signal?: AbortSignal) => request<About>("/system/about", { signal }),
  metrics: (query: { from?: string; to?: string; interval_seconds?: number }, signal?: AbortSignal) =>
    request<MetricsSeries>("/system/metrics", { query, signal }),
  events: (query: EventQuery, signal?: AbortSignal) =>
    request<Page<SentinelEvent>>("/events", { query: { ...query }, signal }),
  event: (id: string, signal?: AbortSignal) =>
    request<SentinelEvent>(`/events/${encodeURIComponent(id)}`, { signal }),
  incidents: (query: IncidentQuery, signal?: AbortSignal) =>
    request<Page<Incident>>("/incidents", { query: { ...query }, signal }),
  incident: (id: string, signal?: AbortSignal) =>
    request<IncidentDetail>(`/incidents/${encodeURIComponent(id)}`, { signal }),
  setIncidentStatus: (
    id: string,
    status: "acknowledged" | "resolved" | "false_positive",
    note?: string,
  ) =>
    request<Incident>(`/incidents/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: note ? { status, note } : { status },
    }),
  processes: (query: { sort?: string; limit?: number }, signal?: AbortSignal) =>
    request<ProcessList>("/processes", { query, signal }),
  listeners: (query: { protocol?: string; exposed_only?: boolean }, signal?: AbortSignal) =>
    request<ListenerList>("/network/listeners", { query, signal }),
  rules: (signal?: AbortSignal) => request<{ items: Rule[] }>("/rules", { signal }),
};
