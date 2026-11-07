import { useState } from "react";
import { api } from "../api/client";
import { MetricCard } from "../components/MetricCard";
import { Sparkline } from "../components/Sparkline";
import { Empty, ErrorBox, Loading, StaleNotice } from "../components/States";
import { Time } from "../components/Time";
import { useNow, useStatus } from "../hooks/status";
import { usePolling } from "../hooks/usePolling";
import { formatAge, formatPercent, formatTemp, formatUptime } from "../lib/format";
import ui from "../ui.module.css";

const WINDOWS = [
  { id: "1h", label: "Last hour", ms: 3_600_000 },
  { id: "6h", label: "Last 6 hours", ms: 6 * 3_600_000 },
  { id: "24h", label: "Last 24 hours", ms: 24 * 3_600_000 },
];

export function System() {
  const [win, setWin] = useState("1h");
  const status = useStatus();
  const about = usePolling("about", (s) => api.about(s), null);
  const ms = WINDOWS.find((w) => w.id === win)?.ms ?? 3_600_000;
  const series = usePolling(`system:${win}`, (s) => api.metrics({ from: new Date(Date.now() - ms).toISOString() }, s), 30_000);
  const now = useNow(1000);

  const points = series.data?.points ?? [];
  const m = status.data?.metrics ?? null;
  const range = (values: number[]) =>
    values.length ? `lowest ${Math.min(...values).toFixed(0)}, highest ${Math.max(...values).toFixed(0)}` : "no data in this window";

  return (
    <div className={ui.stack}>
      <div className={ui.pageHead}>
        <div>
          <h1>System</h1>
          <p>Current readings and how they changed.</p>
        </div>
        <label className={ui.field}>
          Window
          <select value={win} onChange={(e) => setWin(e.target.value)}>
            {WINDOWS.map((w) => <option key={w.id} value={w.id}>{w.label}</option>)}
          </select>
        </label>
      </div>
      <StaleNotice error={status.data ? status.error : null} updatedAt={status.updatedAt} />
      {status.loading && <Loading what="system readings" />}
      {status.data === null && status.error && <ErrorBox what="system readings" error={status.error} onRetry={status.refresh} />}

      {m && (
        <div className={ui.grid}>
          <MetricCard label="Processor" value={formatPercent(m.cpu_percent)} note={range(points.map((p) => p.cpu_percent))}
            chart={<Sparkline height={90} label="Processor use" values={points.map((p) => p.cpu_percent)} />} />
          <MetricCard label="Memory" value={formatPercent(m.memory_percent)} note={range(points.map((p) => p.memory_percent))}
            chart={<Sparkline height={90} label="Memory use" values={points.map((p) => p.memory_percent)} />} />
          <MetricCard label="Disk" value={formatPercent(m.disk_percent)} note={range(points.map((p) => p.disk_percent))}
            chart={<Sparkline height={90} label="Disk use" values={points.map((p) => p.disk_percent)} />} />
          <MetricCard label="Temperature" value={formatTemp(m.temperature_c)}
            note={m.temperature_c === null ? "Not reported by this host" : "Throttling status is not collected"}
            chart={
              points.some((p) => p.temperature_c !== null) ? (
                <Sparkline height={90} min={20} max={90} label="Temperature in degrees Celsius"
                  values={points.map((p) => p.temperature_c).filter((v): v is number => v !== null)} />
              ) : undefined
            } />
        </div>
      )}
      {series.data?.truncated && <p className={ui.muted}>This window holds more samples than can be shown; the oldest are left out.</p>}
      {series.data !== null && points.length === 0 && <Empty>No samples in this window yet.</Empty>}
      {series.data === null && series.error && <ErrorBox what="history" error={series.error} onRetry={series.refresh} />}
      {series.data?.interval_seconds ? (
        <p className={`${ui.muted} ${ui.small}`}>Each point on the charts averages {series.data.interval_seconds} seconds of samples.</p>
      ) : null}

      <section className={ui.card} aria-labelledby="col-h">
        <h2 id="col-h" style={{ marginBottom: 12 }}>Collection status</h2>
        {status.data && (
          <dl className={ui.kv}>
            <dt>Monitor</dt>
            <dd>
              {status.data.monitor.running ? "Running" : "Not running"}
              {status.data.monitor.last_heartbeat ? <> — last report <Time iso={status.data.monitor.last_heartbeat} /></> : " — it has never reported"}
            </dd>
            <dt>Latest reading</dt>
            <dd>{m ? <>{formatAge((now - new Date(m.observed_at).getTime()) / 1000)}{m.stale ? " (out of date)" : ""}</> : "none yet"}</dd>
            <dt>Uptime</dt>
            <dd>{m ? formatUptime(m.uptime_seconds) : "unknown"}</dd>
            {about.data && (
              <>
                <dt>Checks every</dt>
                <dd>
                  metrics {about.data.intervals_seconds.metrics} s, processes and ports {about.data.intervals_seconds.processes_and_ports} s, SSH logs {about.data.intervals_seconds.ssh_logs} s, detection {about.data.intervals_seconds.detection} s
                </dd>
              </>
            )}
          </dl>
        )}
      </section>
    </div>
  );
}
