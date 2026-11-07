import { api } from "../api/client";
import type { Severity } from "../api/types";
import { MetricCard } from "../components/MetricCard";
import { SeverityBadge } from "../components/SeverityBadge";
import { Sparkline } from "../components/Sparkline";
import { Empty, ErrorBox, Loading, StaleNotice } from "../components/States";
import { Time } from "../components/Time";
import { useStatus } from "../hooks/status";
import { usePolling } from "../hooks/usePolling";
import { eventTypeLabel, formatPercent, formatTemp, formatUptime } from "../lib/format";
import { href } from "../lib/router";
import { SEVERITIES, SEVERITY_LABEL } from "../lib/severity";
import ui from "../ui.module.css";

export function Overview() {
  const status = useStatus();
  const series = usePolling("overview:metrics", (s) => api.metrics({}, s), 30_000);
  const open = usePolling("overview:open", (s) => api.incidents({ status: "open", limit: 100 }, s), 10_000);
  const events = usePolling("overview:events", (s) => api.events({ limit: 8 }, s), 10_000);

  if (status.loading) return <Loading what="the overview" />;
  if (status.data === null && status.error) {
    return <ErrorBox what="the overview" error={status.error} onRetry={status.refresh} />;
  }
  const m = status.data?.metrics ?? null;
  const points = series.data?.points ?? [];

  const counts = new Map<Severity, number>();
  for (const i of open.data?.items ?? []) counts.set(i.severity, (counts.get(i.severity) ?? 0) + 1);

  return (
    <div className={ui.stack}>
      <h1 className="sr-only">Overview</h1>
      <StaleNotice error={status.error} updatedAt={status.updatedAt} />
      {m === null ? (
        <Empty>
          No system metrics have been collected yet. Start the monitor on the Pi with{" "}
          <span className={ui.mono}>python -m sentinelpi.monitor</span>.
        </Empty>
      ) : (
        <div className={ui.metrics}>
          <MetricCard
            label="Processor"
            value={formatPercent(m.cpu_percent)}
            chart={<Sparkline label="Processor use over the last hour" values={points.map((p) => p.cpu_percent)} />}
          />
          <MetricCard
            label="Memory"
            value={formatPercent(m.memory_percent)}
            chart={<Sparkline label="Memory use over the last hour" values={points.map((p) => p.memory_percent)} />}
          />
          <MetricCard label="Disk" value={formatPercent(m.disk_percent)} note="Used on the monitored volume" />
          <MetricCard
            label="Temperature"
            value={formatTemp(m.temperature_c)}
            note={m.temperature_c === null ? "This host does not report a temperature" : undefined}
          />
          <MetricCard label="Uptime" value={formatUptime(m.uptime_seconds)} note={m.stale ? "Metrics are out of date" : undefined} />
        </div>
      )}

      <div className={ui.split}>
        <section className={ui.card} aria-labelledby="open-h">
          <div className={ui.cardHead}>
            <h2 id="open-h">Open incidents</h2>
            <a href={href("/incidents")}>All incidents</a>
          </div>
          {open.data === null && open.error && <ErrorBox what="incidents" error={open.error} onRetry={open.refresh} />}
          {open.data !== null && open.data.items.length === 0 && (
            <Empty>No open incidents. Detections that need a look will appear here.</Empty>
          )}
          {open.data !== null && open.data.items.length > 0 && (
            <>
              <p className={ui.muted} aria-label="Open incidents by severity">
                {SEVERITIES.filter((s) => counts.has(s))
                  .reverse()
                  .map((s) => `${counts.get(s)} ${SEVERITY_LABEL[s].toLowerCase()}`)
                  .join(", ")}
              </p>
              <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: 10 }}>
                {open.data.items.slice(0, 6).map((i) => (
                  <li key={i.id}>
                    <SeverityBadge severity={i.severity} />{" "}
                    <a href={href(`/incidents/${i.id}`)}>{i.title}</a>{" "}
                    <span className={`${ui.muted} ${ui.small}`}>
                      · <Time iso={i.last_seen} />
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>

        <section className={ui.card} aria-labelledby="events-h">
          <div className={ui.cardHead}>
            <h2 id="events-h">Recent events</h2>
            <a href={href("/events")}>All events</a>
          </div>
          {events.data === null && events.error && <ErrorBox what="events" error={events.error} onRetry={events.refresh} />}
          {events.data !== null && events.data.items.length === 0 && (
            <Empty>No events yet. SSH sign-in attempts and detections will be listed here.</Empty>
          )}
          {events.data !== null && events.data.items.length > 0 && (
            <div className={ui.tableWrap}>
              <table className={ui.table}>
                <caption className="sr-only">Most recent events</caption>
                <tbody>
                  {events.data.items.map((e) => (
                    <tr key={e.id}>
                      <td><SeverityBadge severity={e.severity} /></td>
                      <td>
                        {eventTypeLabel(e.event_type)}
                        {e.source_ip ? <span className={ui.muted}> from {e.source_ip}</span> : null}
                      </td>
                      <td className={ui.muted}><Time iso={e.timestamp} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
