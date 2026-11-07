import { api } from "../api/client";
import { SeverityBadge } from "../components/SeverityBadge";
import { Sparkline } from "../components/Sparkline";
import { useNow, useStatus } from "../hooks/status";
import { usePolling } from "../hooks/usePolling";
import { eventTypeLabel, formatAge, formatClock, formatDay, formatPercent, formatTemp } from "../lib/format";
import { kioskState } from "../lib/kiosk";
import { describeStatus } from "../lib/statusText";
import { SEVERITY_LABEL } from "../lib/severity";
import styles from "./Kiosk.module.css";

const TONE = {
  ok: "var(--ok)",
  warning: "var(--sev-medium)",
  alert: "var(--sev-high)",
  offline: "var(--text-muted)",
} as const;

function AlertScreen({ id }: { id: string }) {
  const { data: status } = useStatus();
  const detail = usePolling(`kiosk:incident:${id}`, (s) => api.incident(id, s), 10_000, { pauseWhenHidden: false });
  const now = useNow(1000);
  const alert = status?.active_alert;
  if (!alert) return null;
  const more = (status?.incidents.open ?? 1) - 1;
  const detections = (detail.data?.timeline ?? []).filter((t) => t.kind === "event" && t.event_type?.startsWith("detection."));
  return (
    <main className={styles.alert} role="alert" aria-live="assertive" style={{ ["--sev" as string]: `var(--sev-${alert.severity})` }}>
      <div className={styles.alertHead}>
        <SeverityBadge severity={alert.severity} large />
        <span>Security alert</span>
        <span className={styles.alertClock}>{formatClock(new Date(now))}</span>
      </div>
      <h1 className={styles.alertTitle}>{alert.title}</h1>
      <dl className={styles.alertFacts}>
        <div><dt>Started</dt><dd>{formatAge((now - new Date(alert.first_seen).getTime()) / 1000)}</dd></div>
        <div><dt>Latest activity</dt><dd>{formatAge((now - new Date(alert.last_seen).getTime()) / 1000)}</dd></div>
        <div><dt>Source</dt><dd>{alert.source_ip ?? "This device"}</dd></div>
        <div><dt>Risk score</dt><dd>{alert.risk_score} of 100</dd></div>
      </dl>
      {detections.length > 0 && (
        <ul className={styles.reasons}>
          {detections.slice(-3).map((t, n) => <li key={n}>{t.summary}</li>)}
        </ul>
      )}
      <p className={styles.alertFoot}>
        {more > 0 ? `${more} more open incident${more === 1 ? "" : "s"}. ` : ""}
        Acknowledge this incident from the dashboard to clear the screen.
      </p>
    </main>
  );
}

export function Kiosk() {
  const { data: status, failures, updatedAt } = useStatus();
  const now = useNow(1000);
  const series = usePolling("kiosk:metrics", (s) => api.metrics({}, s), 30_000, { pauseWhenHidden: false });
  const events = usePolling("kiosk:events", (s) => api.events({ limit: 5 }, s), 10_000, { pauseWhenHidden: false });
  const state = kioskState(status, failures, updatedAt, now);
  const head = describeStatus(status, failures > 0);
  const points = series.data?.points ?? [];
  const m = status?.metrics ?? null;
  const date = new Date(now);

  const banner = state.stale && status !== null && (
    <p className={styles.stale} role="status">
      Readings may be out of date: {!status.monitor.running ? "the monitor is not running" : "the connection to SentinelPi is failing"}.
    </p>
  );

  if (state.mode === "alert" && status?.active_alert) {
    return (
      <>
        <AlertScreen id={status.active_alert.id} />
        {banner}
      </>
    );
  }
  if (status === null) {
    return (
      <main className={styles.waiting} role="status">
        <h1>{state.mode === "offline" ? "SentinelPi is not answering" : "Starting up"}</h1>
        <p>
          {state.mode === "offline"
            ? "The monitoring service could not be reached. Nothing on this screen can be trusted until it is back."
            : "Waiting for the first reading…"}
        </p>
      </main>
    );
  }

  return (
    <main className={styles.screen}>
      {banner}
      <header className={styles.top}>
        <div>
          <div className={styles.time}>{formatClock(date)}</div>
          <div className={styles.day}>{formatDay(date)} · {status.host}</div>
        </div>
        <div className={styles.headline} style={{ borderLeftColor: TONE[head.tone] }}>
          <strong style={{ color: TONE[head.tone] }}>{head.label}</strong>
          <span>{head.sentence}</span>
        </div>
      </header>

      <section className={styles.tiles} aria-label="System readings">
        <Tile label="Processor" value={m ? formatPercent(m.cpu_percent) : "–"} values={points.map((p) => p.cpu_percent)} />
        <Tile label="Memory" value={m ? formatPercent(m.memory_percent) : "–"} values={points.map((p) => p.memory_percent)} />
        <Tile label="Disk" value={m ? formatPercent(m.disk_percent) : "–"} />
        <Tile label="Temperature" value={m ? formatTemp(m.temperature_c) : "–"} />
      </section>

      <div className={styles.lower}>
        <section aria-labelledby="k-inc">
          <h2 id="k-inc">Open incidents</h2>
          {status.open_incidents.length === 0 ? (
            <p className={styles.quiet}>None. Nothing has needed attention.</p>
          ) : (
            <ul className={styles.list}>
              {status.open_incidents.map((i) => (
                <li key={i.id}>
                  <SeverityBadge severity={i.severity} /> {i.title}
                  <span className={styles.dim}> · {SEVERITY_LABEL[i.severity]} · {formatAge((now - new Date(i.last_seen).getTime()) / 1000)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section aria-labelledby="k-ev">
          <h2 id="k-ev">Latest events</h2>
          {events.data && events.data.items.length === 0 ? (
            <p className={styles.quiet}>No events yet.</p>
          ) : (
            <ul className={styles.list}>
              {(events.data?.items ?? []).map((e) => (
                <li key={e.id}>
                  {eventTypeLabel(e.event_type)}{e.source_ip ? ` from ${e.source_ip}` : ""}
                  <span className={styles.dim}> · {formatAge((now - new Date(e.timestamp).getTime()) / 1000)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </main>
  );
}

function Tile({ label, value, values }: { label: string; value: string; values?: number[] }) {
  return (
    <div className={styles.tile}>
      <div className={styles.tileLabel}>{label}</div>
      <div className={styles.tileValue}>{value}</div>
      {values && <Sparkline label={`${label} over the last hour`} values={values} height={56} />}
    </div>
  );
}
