import { useState } from "react";
import { api } from "../api/client";
import { Empty, ErrorBox, Loading, StaleNotice } from "../components/States";
import { Time } from "../components/Time";
import { usePolling } from "../hooks/usePolling";
import { formatPercent } from "../lib/format";
import ui from "../ui.module.css";

const SORTS = [
  { id: "cpu", label: "Processor use" },
  { id: "memory", label: "Memory use" },
  { id: "name", label: "Name" },
];

export function Processes() {
  const [sort, setSort] = useState("cpu");
  const p = usePolling(`processes:${sort}`, (s) => api.processes({ sort, limit: 100 }, s), 15_000);
  return (
    <div>
      <div className={ui.pageHead}>
        <div>
          <h1>Processes</h1>
          <p>
            The busiest processes at the last check{p.data?.observed_at ? <> (<Time iso={p.data.observed_at} />)</> : ""}.
            Command lines are never collected, and some processes owned by other users may be missing.
          </p>
        </div>
        <label className={ui.field}>
          Sort by
          <select value={sort} onChange={(e) => setSort(e.target.value)}>
            {SORTS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
        </label>
      </div>
      <StaleNotice error={p.data ? p.error : null} updatedAt={p.updatedAt} />
      {p.loading && <Loading what="processes" />}
      {p.data === null && p.error && <ErrorBox what="processes" error={p.error} onRetry={p.refresh} />}
      {p.data && p.data.items.length === 0 && <Empty>No process snapshot has been collected yet. Start the monitor on the Pi.</Empty>}
      {p.data && p.data.items.length > 0 && (
        <div className={`${ui.card} ${ui.tableWrap}`}>
          <table className={ui.table}>
            <caption className="sr-only">Running processes</caption>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col" className={ui.right}>PID</th>
                <th scope="col">Owner</th>
                <th scope="col" className={ui.right}>Processor</th>
                <th scope="col" className={ui.right}>Memory</th>
              </tr>
            </thead>
            <tbody>
              {p.data.items.map((r) => (
                <tr key={r.pid}>
                  <td>{r.name}</td>
                  <td className={ui.right}>{r.pid}</td>
                  <td>{r.username ?? <span className={ui.muted}>unknown</span>}</td>
                  <td className={ui.right}>{formatPercent(r.cpu_percent)}</td>
                  <td className={ui.right}>{formatPercent(r.memory_percent)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {p.data && p.data.total > p.data.items.length && (
        <p className={ui.muted}>Showing {p.data.items.length} of {p.data.total} processes.</p>
      )}
    </div>
  );
}
