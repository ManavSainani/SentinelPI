import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { SentinelEvent, Severity } from "../api/types";
import { SeverityBadge } from "../components/SeverityBadge";
import { Empty, ErrorBox, Loading, StaleNotice } from "../components/States";
import { Time } from "../components/Time";
import { usePolling } from "../hooks/usePolling";
import { eventTypeLabel } from "../lib/format";
import ui from "../ui.module.css";
import styles from "./Events.module.css";

const RANGES = [
  { id: "1h", label: "Last hour", ms: 3_600_000 },
  { id: "24h", label: "Last 24 hours", ms: 86_400_000 },
  { id: "7d", label: "Last 7 days", ms: 7 * 86_400_000 },
  { id: "all", label: "Everything kept", ms: 0 },
];
const TYPES = [
  "auth.ssh_failed_login",
  "auth.ssh_invalid_user",
  "auth.ssh_successful_login",
  "detection.ssh_repeated_failures",
  "detection.new_listening_port",
  "detection.sustained_high_cpu",
  "detection.watchlisted_process",
];
const MIN_SEVERITIES: { value: "" | Severity; label: string }[] = [
  { value: "", label: "Any severity" },
  { value: "low", label: "Low and above" },
  { value: "medium", label: "Medium and above" },
  { value: "high", label: "High and above" },
];

interface Filters {
  range: string;
  severity: "" | Severity;
  type: string;
  ip: string;
}

export function Events() {
  const [draft, setDraft] = useState<Filters>({ range: "24h", severity: "", type: "", ip: "" });
  const [applied, setApplied] = useState(draft);
  const [more, setMore] = useState<SentinelEvent[]>([]);
  const [cursor, setCursor] = useState<string | null | undefined>(undefined);
  const [selected, setSelected] = useState<SentinelEvent | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<Error | null>(null);

  const key = JSON.stringify(applied);
  const query = () => {
    const ms = RANGES.find((r) => r.id === applied.range)?.ms ?? 0;
    return {
      from: ms ? new Date(Date.now() - ms).toISOString() : undefined,
      severity: applied.severity || undefined,
      type: applied.type || undefined,
      source_ip: applied.ip.trim() || undefined,
      limit: 50,
    };
  };
  const first = usePolling(`events:${key}`, (s) => api.events(query(), s), more.length > 0 ? null : 10_000);

  useEffect(() => {
    setMore([]);
    setCursor(undefined);
    setSelected(null);
    setMoreError(null);
  }, [key]);

  const next = cursor === undefined ? first.data?.next_cursor ?? null : cursor;
  const rows = [...(first.data?.items ?? []), ...more];

  async function loadMore() {
    if (!next) return;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const page = await api.events({ ...query(), cursor: next });
      setMore((m) => [...m, ...page.items]);
      setCursor(page.next_cursor);
    } catch (err) {
      setMoreError(err instanceof Error ? err : new Error("failed"));
    } finally {
      setLoadingMore(false);
    }
  }
  function submit(e: FormEvent) {
    e.preventDefault();
    setApplied(draft);
  }

  return (
    <div>
      <div className={ui.pageHead}>
        <div>
          <h1>Events</h1>
          <p>Everything SentinelPi has recorded, newest first. Times are shown in your local time zone.</p>
        </div>
      </div>
      <form className={ui.toolbar} onSubmit={submit}>
        <label className={ui.field}>
          Time range
          <select value={draft.range} onChange={(e) => setDraft({ ...draft, range: e.target.value })}>
            {RANGES.map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}
          </select>
        </label>
        <label className={ui.field}>
          Severity
          <select value={draft.severity} onChange={(e) => setDraft({ ...draft, severity: e.target.value as Filters["severity"] })}>
            {MIN_SEVERITIES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
          </select>
        </label>
        <label className={ui.field}>
          Type
          <select value={draft.type} onChange={(e) => setDraft({ ...draft, type: e.target.value })}>
            <option value="">Any type</option>
            {TYPES.map((t) => <option key={t} value={t}>{eventTypeLabel(t)}</option>)}
          </select>
        </label>
        <label className={ui.field}>
          Source address
          <input value={draft.ip} onChange={(e) => setDraft({ ...draft, ip: e.target.value })} placeholder="e.g. 192.168.4.40" inputMode="text" autoComplete="off" />
        </label>
        <button type="submit" className={`${ui.button} ${ui.primary}`}>Apply filters</button>
      </form>

      <StaleNotice error={first.data ? first.error : null} updatedAt={first.updatedAt} />
      {first.loading && <Loading what="events" />}
      {first.data === null && first.error && <ErrorBox what="events" error={first.error} onRetry={first.refresh} />}
      {first.data !== null && rows.length === 0 && (
        <Empty>No events match these filters. Widen the time range, or clear the severity, type and address filters.</Empty>
      )}
      {rows.length > 0 && (
        <div className={styles.layout}>
          <div className={`${ui.card} ${ui.tableWrap}`}>
            <table className={ui.table}>
              <caption className="sr-only">Events</caption>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Severity</th>
                  <th scope="col">What</th>
                  <th scope="col">Source</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id} className={`${ui.clickRow} ${selected?.id === e.id ? ui.rowSelected : ""}`} onClick={() => setSelected(e)}>
                    <td><Time iso={e.timestamp} /></td>
                    <td><SeverityBadge severity={e.severity} /></td>
                    <td>
                      <button type="button" className={styles.link} onClick={() => setSelected(e)} aria-pressed={selected?.id === e.id}>
                        {eventTypeLabel(e.event_type)}
                      </button>
                      <div className={`${ui.muted} ${ui.small}`}>{e.summary}</div>
                    </td>
                    <td>{e.source_ip ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <aside className={`${ui.card} ${styles.panel}`} aria-label="Event details">
            {selected === null ? (
              <p className={ui.muted}>Select an event to see its details.</p>
            ) : (
              <>
                <h2>{eventTypeLabel(selected.event_type)}</h2>
                <p>{selected.summary}</p>
                <dl className={ui.kv}>
                  <dt>Time</dt><dd><Time iso={selected.timestamp} /></dd>
                  <dt>Severity</dt><dd><SeverityBadge severity={selected.severity} /></dd>
                  <dt>Source</dt><dd>{selected.source.replace("_", " ")}</dd>
                  <dt>Host</dt><dd>{selected.host}</dd>
                  {selected.source_ip && (<><dt>Address</dt><dd>{selected.source_ip}</dd></>)}
                  {selected.username && (<><dt>User</dt><dd>{selected.username}</dd></>)}
                  {selected.process_name && (<><dt>Process</dt><dd>{selected.process_name}</dd></>)}
                  <dt>ID</dt><dd className={ui.mono}>{selected.id}</dd>
                </dl>
                <h3 style={{ marginTop: 16, fontSize: "0.95rem" }}>Details</h3>
                <pre className={styles.json}>{JSON.stringify(selected.metadata, null, 2)}</pre>
                <p className={`${ui.muted} ${ui.small}`}>Secrets are redacted before anything is stored.</p>
              </>
            )}
          </aside>
        </div>
      )}
      <div className={ui.toolbar} style={{ marginTop: 16 }}>
        {first.data && <span className={ui.muted}>Showing {rows.length} of {first.data.total}</span>}
        {next && <button type="button" className={ui.button} onClick={loadMore} disabled={loadingMore}>{loadingMore ? "Loading…" : "Show older"}</button>}
        {more.length > 0 && (
          <>
            <button type="button" className={ui.button} onClick={() => { setMore([]); setCursor(undefined); }}>Back to latest</button>
            <span className={`${ui.muted} ${ui.small}`}>Live refresh is paused while you browse older events.</span>
          </>
        )}
      </div>
      {moreError && <ErrorBox what="older events" error={moreError} />}
    </div>
  );
}
