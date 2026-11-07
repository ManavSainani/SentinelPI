import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Incident, IncidentStatus } from "../api/types";
import { SeverityBadge, StatusChip } from "../components/SeverityBadge";
import { Empty, ErrorBox, Loading, StaleNotice } from "../components/States";
import { Time } from "../components/Time";
import { usePolling } from "../hooks/usePolling";
import { href } from "../lib/router";
import { STATUS_LABEL } from "../lib/severity";
import ui from "../ui.module.css";

const TABS: IncidentStatus[] = ["open", "acknowledged", "resolved", "false_positive"];
const EMPTY_TEXT: Record<IncidentStatus, string> = {
  open: "No open incidents. Detections that need a look will appear here.",
  acknowledged: "Nothing is acknowledged. Acknowledge an incident to say you have seen it.",
  resolved: "No resolved incidents yet.",
  false_positive: "No incidents have been marked as false positives.",
};

export function Incidents() {
  const [tab, setTab] = useState<IncidentStatus>("open");
  const [more, setMore] = useState<Incident[]>([]);
  const [cursor, setCursor] = useState<string | null | undefined>(undefined);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<Error | null>(null);

  // Older pages are fetched once and appended, so polling stops while you are browsing them
  // (otherwise newly arriving rows would shift the pages and leave gaps).
  const first = usePolling(`incidents:${tab}`, (s) => api.incidents({ status: tab, limit: 25 }, s), more.length > 0 ? null : 10_000);

  useEffect(() => {
    setMore([]);
    setCursor(undefined);
    setMoreError(null);
  }, [tab]);

  const next = cursor === undefined ? first.data?.next_cursor ?? null : cursor;
  const rows = [...(first.data?.items ?? []), ...more];

  async function loadMore() {
    if (!next) return;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const page = await api.incidents({ status: tab, limit: 25, cursor: next });
      setMore((m) => [...m, ...page.items]);
      setCursor(page.next_cursor);
    } catch (err) {
      setMoreError(err instanceof Error ? err : new Error("failed"));
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <div>
      <div className={ui.pageHead}>
        <div>
          <h1>Incidents</h1>
          <p>Related detections grouped by host and source, newest activity first.</p>
        </div>
      </div>
      <div className={ui.tabs} role="tablist" aria-label="Incident status">
        {TABS.map((t) => (
          <button
            key={t}
            type="button"
            role="tab"
            aria-selected={tab === t}
            className={`${ui.tab} ${tab === t ? ui.tabOn : ""}`}
            onClick={() => setTab(t)}
          >
            {STATUS_LABEL[t]}
          </button>
        ))}
      </div>

      <StaleNotice error={first.data ? first.error : null} updatedAt={first.updatedAt} />
      {first.loading && <Loading what="incidents" />}
      {first.data === null && first.error && <ErrorBox what="incidents" error={first.error} onRetry={first.refresh} />}
      {first.data !== null && rows.length === 0 && <Empty>{EMPTY_TEXT[tab]}</Empty>}
      {rows.length > 0 && (
        <div className={`${ui.card} ${ui.tableWrap}`}>
          <table className={ui.table}>
            <caption className="sr-only">{STATUS_LABEL[tab]} incidents</caption>
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col">Incident</th>
                <th scope="col">Source</th>
                <th scope="col" className={ui.right}>Risk score</th>
                <th scope="col">Last activity</th>
                <th scope="col" className={ui.right}>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((i) => (
                <tr key={i.id}>
                  <td><SeverityBadge severity={i.severity} /></td>
                  <td>
                    <a href={href(`/incidents/${i.id}`)}>{i.title}</a>
                    {i.status !== tab && <> <StatusChip status={i.status} /></>}
                  </td>
                  <td>{i.source_ip ?? <span className={ui.muted}>this host</span>}</td>
                  <td className={ui.right}>{i.risk_score}</td>
                  <td><Time iso={i.last_seen} /></td>
                  <td className={ui.right}>{i.evidence_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className={ui.toolbar} style={{ marginTop: 16 }}>
        {first.data && <span className={ui.muted}>Showing {rows.length} of {first.data.total}</span>}
        {next && (
          <button type="button" className={ui.button} onClick={loadMore} disabled={loadingMore}>
            {loadingMore ? "Loading…" : "Show older"}
          </button>
        )}
        {more.length > 0 && (
          <button type="button" className={ui.button} onClick={() => { setMore([]); setCursor(undefined); }}>
            Back to latest
          </button>
        )}
      </div>
      {moreError && <ErrorBox what="older incidents" error={moreError} />}
    </div>
  );
}
