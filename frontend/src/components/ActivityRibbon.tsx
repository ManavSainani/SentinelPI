import { api } from "../api/client";
import type { Severity, SentinelEvent } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { severityRank, SEVERITY_LABEL } from "../lib/severity";
import styles from "./ActivityRibbon.module.css";

const MINUTES = 60;

export interface Bucket {
  count: number;
  top: Severity | null;
}

/** Count events per minute over the last hour, remembering the worst severity in each minute. */
export function bucketEvents(events: SentinelEvent[], now: number): Bucket[] {
  const buckets: Bucket[] = Array.from({ length: MINUTES }, () => ({ count: 0, top: null }));
  for (const e of events) {
    const minutesAgo = Math.floor((now - new Date(e.timestamp).getTime()) / 60_000);
    if (minutesAgo < 0 || minutesAgo >= MINUTES) continue;
    const b = buckets[MINUTES - 1 - minutesAgo];
    b.count += 1;
    if (b.top === null || severityRank(e.severity) > severityRank(b.top)) b.top = e.severity;
  }
  return buckets;
}

/** The last hour at a glance: one bar per minute, tall when busy, coloured by worst severity. */
export function ActivityRibbon() {
  const { data, error } = usePolling(
    "ribbon",
    (signal) =>
      api.events({ from: new Date(Date.now() - MINUTES * 60_000).toISOString(), limit: 200 }, signal),
    30_000,
  );
  if (data === null) {
    return <div className={styles.ribbon} aria-hidden="true" />;
  }
  const buckets = bucketEvents(data.items, Date.now());
  const peak = Math.max(1, ...buckets.map((b) => b.count));
  const worst = buckets.reduce<Severity | null>(
    (w, b) => (b.top !== null && (w === null || severityRank(b.top) > severityRank(w)) ? b.top : w),
    null,
  );
  const label =
    data.total === 0
      ? "No events in the last hour."
      : `${data.total} event${data.total === 1 ? "" : "s"} in the last hour; most serious: ${
          worst ? SEVERITY_LABEL[worst].toLowerCase() : "none"
        }.`;
  return (
    <figure className={styles.figure}>
      <div className={styles.ribbon} role="img" aria-label={label}>
        {buckets.map((b, i) => (
          <span
            key={i}
            className={styles.bar}
            style={{
              height: b.count === 0 ? 2 : 6 + Math.round((b.count / peak) * 22),
              background: b.top ? `var(--sev-${b.top})` : "var(--line)",
            }}
          />
        ))}
      </div>
      <figcaption className={styles.caption}>
        <span>60 min ago</span>
        <span>{error ? "Could not refresh" : label}</span>
        <span>now</span>
      </figcaption>
    </figure>
  );
}

