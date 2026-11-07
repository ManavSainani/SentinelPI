import { useState } from "react";
import { api, ApiError } from "../api/client";
import type { IncidentStatus, TimelineItem } from "../api/types";
import { SeverityBadge, StatusChip } from "../components/SeverityBadge";
import { Empty, ErrorBox, Loading, StaleNotice } from "../components/States";
import { Time } from "../components/Time";
import { usePolling } from "../hooks/usePolling";
import { eventTypeLabel } from "../lib/format";
import { href } from "../lib/router";
import { STATUS_LABEL } from "../lib/severity";
import ui from "../ui.module.css";
import styles from "./IncidentDetail.module.css";

type Action = "acknowledged" | "resolved" | "false_positive";
const ACTION_LABEL: Record<Action, string> = {
  acknowledged: "Acknowledge",
  resolved: "Mark resolved",
  false_positive: "Mark false positive",
};
const FINAL: Action[] = ["resolved", "false_positive"];

function actionsFor(status: IncidentStatus): Action[] {
  if (status === "open") return ["acknowledged", "resolved", "false_positive"];
  if (status === "acknowledged") return ["resolved", "false_positive"];
  return [];
}

function TimelineRow({ item }: { item: TimelineItem }) {
  if (item.kind === "event") {
    return (
      <li className={styles.row}>
        <span className={styles.when}><Time iso={item.at} /></span>
        <span>
          {item.severity && <SeverityBadge severity={item.severity} />}{" "}
          <strong>{eventTypeLabel(item.event_type ?? "event")}</strong>
          <span className={ui.muted}> {item.summary}</span>
        </span>
      </li>
    );
  }
  const text =
    item.audit_kind === "status_changed"
      ? `${item.actor === "user" ? "You" : "SentinelPi"} changed the status from ${(item.from_status ?? "").replace("_", " ")} to ${(item.to_status ?? "").replace("_", " ")}`
      : item.audit_kind === "created"
        ? "SentinelPi opened this incident"
        : item.audit_kind === "escalated"
          ? "SentinelPi raised the severity"
          : "SentinelPi added evidence";
  return (
    <li className={`${styles.row} ${styles.audit}`}>
      <span className={styles.when}><Time iso={item.at} /></span>
      <span>
        {text}
        {item.note || item.summary ? <span className={ui.muted}>: {item.note ?? item.summary}</span> : null}
      </span>
    </li>
  );
}

export function IncidentDetail({ id }: { id: string }) {
  const incident = usePolling(`incident:${id}`, (s) => api.incident(id, s), 10_000);
  const rules = usePolling("rules", (s) => api.rules(s), null);
  const [note, setNote] = useState("");
  const [pending, setPending] = useState<Action | null>(null);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  if (incident.loading) return <Loading what="the incident" />;
  if (incident.data === null) {
    const missing = incident.error instanceof ApiError && incident.error.status === 404;
    return missing ? (
      <Empty>
        That incident does not exist (it may have been removed by retention). <a href={href("/incidents")}>Back to incidents</a>
      </Empty>
    ) : (
      <ErrorBox what="the incident" error={incident.error ?? new Error("unknown")} onRetry={incident.refresh} />
    );
  }
  const i = incident.data;
  const matched = (rules.data?.items ?? []).filter((r) => i.rule_ids.includes(r.id));

  async function apply(action: Action) {
    setBusy(true);
    setProblem(null);
    try {
      await api.setIncidentStatus(id, action, note.trim() || undefined);
      setPending(null);
      setNote("");
      incident.refresh();
    } catch (err) {
      setProblem(err instanceof Error ? err.message : "The change could not be saved.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={ui.stack}>
      <p><a href={href("/incidents")}>← All incidents</a></p>
      <StaleNotice error={incident.error} updatedAt={incident.updatedAt} />
      <header className={ui.pageHead}>
        <div>
          <h1>{i.title}</h1>
          <p>
            <SeverityBadge severity={i.severity} /> <StatusChip status={i.status} /> Risk score {i.risk_score} of 100
          </p>
        </div>
      </header>

      {actionsFor(i.status).length > 0 ? (
        <section className={ui.card} aria-labelledby="act-h">
          <h2 id="act-h" className={styles.h}>Update status</h2>
          <label className={ui.field}>
            Note (optional, kept in the history)
            <textarea value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
          </label>
          <div className={ui.toolbar} style={{ marginTop: 12, marginBottom: 0 }}>
            {actionsFor(i.status).map((a) => (
              <button
                key={a}
                type="button"
                className={ui.button}
                disabled={busy}
                onClick={() => (FINAL.includes(a) ? setPending(a) : void apply(a))}
              >
                {ACTION_LABEL[a]}
              </button>
            ))}
          </div>
          {pending && (
            <div className={styles.confirm} role="alertdialog" aria-label="Confirm status change">
              <p>
                {ACTION_LABEL[pending]}? This is final. If the activity returns, SentinelPi opens a new incident.
              </p>
              <button type="button" className={`${ui.button} ${ui.primary}`} disabled={busy} onClick={() => void apply(pending)}>
                {busy ? "Saving…" : `Yes, ${ACTION_LABEL[pending].toLowerCase()}`}
              </button>{" "}
              <button type="button" className={ui.button} onClick={() => setPending(null)}>Cancel</button>
            </div>
          )}
          {problem && <p role="alert" style={{ color: "var(--sev-high)" }}>{problem}</p>}
        </section>
      ) : (
        <p className={ui.muted}>
          This incident is {STATUS_LABEL[i.status].toLowerCase()} and can no longer be changed.
          {i.resolution_note ? ` Note: ${i.resolution_note}` : ""}
        </p>
      )}

      <div className={ui.split}>
        <section className={ui.card} aria-labelledby="sum-h">
          <h2 id="sum-h" className={styles.h}>What happened</h2>
          <p>{i.description}</p>
          <dl className={ui.kv}>
            <dt>Host</dt><dd>{i.host}</dd>
            <dt>Source</dt><dd>{i.source_ip ?? "This host (no remote address)"}</dd>
            <dt>First activity</dt><dd><Time iso={i.first_seen} /></dd>
            <dt>Latest activity</dt><dd><Time iso={i.last_seen} /></dd>
            <dt>Evidence</dt><dd>{i.evidence_count} linked event{i.evidence_count === 1 ? "" : "s"}</dd>
          </dl>
        </section>
        <section className={ui.card} aria-labelledby="why-h">
          <h2 id="why-h" className={styles.h}>Why it scored {i.risk_score}</h2>
          <ul className={styles.plain}>
            {i.risk_breakdown.map((b, n) => (
              <li key={n}><strong className="tnum">{b.points > 0 ? `+${b.points}` : b.points}</strong> {b.label}</li>
            ))}
          </ul>
          <p className={`${ui.muted} ${ui.small}`}>The score is a heuristic for ordering your attention, not a probability of compromise.</p>
          {matched.map((r) => (
            <p key={r.id} className={ui.small}><strong>{r.id} {r.name}.</strong> {r.description}</p>
          ))}
        </section>
      </div>

      <section className={ui.card} aria-labelledby="tl-h">
        <h2 id="tl-h" className={styles.h}>Timeline</h2>
        {i.timeline.length === 0 ? <Empty>No evidence is linked to this incident.</Empty> : (
          <ol className={styles.timeline}>
            {i.timeline.map((t, n) => <TimelineRow key={n} item={t} />)}
          </ol>
        )}
        {i.evidence_count > i.timeline_limit && (
          <p className={`${ui.muted} ${ui.small}`}>Showing the first {i.timeline_limit} of {i.evidence_count} linked events.</p>
        )}
      </section>
    </div>
  );
}
