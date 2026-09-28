import { useEffect, useState } from "react";
import styles from "./App.module.css";
import { fetchHealth, type Health } from "./api";

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const ctrl = new AbortController();
    fetchHealth(ctrl.signal)
      .then(setHealth)
      .catch((e: Error) => {
        if (e.name !== "AbortError") setError(e.message);
      });
    return () => ctrl.abort();
  }, []);

  return (
    <main className={styles.page}>
      <h1 className={styles.title}>SentinelPi</h1>
      <section className={styles.card} aria-live="polite">
        {error && <p className={styles.crit}>Backend unreachable: {error}</p>}
        {!error && !health && <p className={styles.muted}>Connecting…</p>}
        {health && (
          <>
            <div className={styles.row}>
              <span>Status</span>
              <span className={styles.ok}>{health.status}</span>
            </div>
            <div className={styles.row}>
              <span>Version</span>
              <span>{health.version}</span>
            </div>
            <div className={styles.row}>
              <span>Host</span>
              <span>
                {health.platform} / {health.arch}
              </span>
            </div>
            <div className={styles.row}>
              <span>Uptime</span>
              <span>{Math.round(health.uptime_seconds)}s</span>
            </div>
          </>
        )}
      </section>
    </main>
  );
}
