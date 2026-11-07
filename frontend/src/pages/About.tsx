import { api } from "../api/client";
import { Empty, ErrorBox, Loading } from "../components/States";
import { usePolling } from "../hooks/usePolling";
import ui from "../ui.module.css";

const RETENTION_LABEL: Record<string, string> = {
  events: "Events",
  metrics: "System readings",
  snapshots: "Process and port snapshots",
  resolved_incidents: "Resolved incidents",
};

export function About() {
  const about = usePolling("about-page", (s) => api.about(s), null);
  const rules = usePolling("rules-page", (s) => api.rules(s), null);
  return (
    <div className={ui.stack}>
      <div className={ui.pageHead}>
        <div>
          <h1>About this installation</h1>
          <p>What SentinelPi watches, what it keeps, and the rules it applies.</p>
        </div>
      </div>
      {about.loading && <Loading what="settings" />}
      {about.data === null && about.error && <ErrorBox what="settings" error={about.error} onRetry={about.refresh} />}
      {about.data && (
        <>
          <section className={ui.card} aria-labelledby="ver-h">
            <h2 id="ver-h" style={{ marginBottom: 12 }}>This installation</h2>
            <dl className={ui.kv}>
              <dt>Version</dt><dd>{about.data.version}</dd>
              <dt>Host</dt><dd>{about.data.host}</dd>
            </dl>
          </section>
          <div className={ui.split}>
            <section className={ui.card} aria-labelledby="col-h">
              <h2 id="col-h" style={{ marginBottom: 12 }}>What it collects</h2>
              <ul>{about.data.collects.map((c) => <li key={c}>{c}</li>)}</ul>
              <h3 style={{ margin: "16px 0 8px", fontSize: "1rem" }}>What it never collects</h3>
              <ul>{about.data.never_collects.map((c) => <li key={c}>{c}</li>)}</ul>
            </section>
            <section className={ui.card} aria-labelledby="ret-h">
              <h2 id="ret-h" style={{ marginBottom: 12 }}>How long data is kept</h2>
              <dl className={ui.kv}>
                {Object.entries(about.data.retention_days).map(([k, v]) => (
                  <div key={k} style={{ display: "contents" }}>
                    <dt>{RETENTION_LABEL[k] ?? k}</dt><dd>{v} days</dd>
                  </div>
                ))}
              </dl>
              <p className={`${ui.muted} ${ui.small}`}>
                Open incidents and their evidence are kept until you resolve them. Nothing leaves this device.
              </p>
            </section>
          </div>
        </>
      )}
      <section className={ui.card} aria-labelledby="rules-h">
        <h2 id="rules-h" style={{ marginBottom: 12 }}>Detection rules</h2>
        {rules.data === null && rules.error && <ErrorBox what="rules" error={rules.error} onRetry={rules.refresh} />}
        {rules.data && rules.data.items.length === 0 && <Empty>No rules are configured.</Empty>}
        {rules.data && (
          <div className={ui.tableWrap}>
            <table className={ui.table}>
              <caption className="sr-only">Detection rules</caption>
              <thead>
                <tr><th scope="col">Rule</th><th scope="col">Status</th><th scope="col">What it looks for</th><th scope="col">Settings</th></tr>
              </thead>
              <tbody>
                {rules.data.items.map((r) => (
                  <tr key={r.id}>
                    <td><strong>{r.id}</strong> {r.name}</td>
                    <td>{r.enabled ? "On" : "Off"}</td>
                    <td>{r.description}</td>
                    <td className={`${ui.mono} ${ui.small}`}>{JSON.stringify(r.thresholds)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className={`${ui.muted} ${ui.small}`}>Rules are changed in the configuration file on the Pi, not here.</p>
      </section>
    </div>
  );
}
