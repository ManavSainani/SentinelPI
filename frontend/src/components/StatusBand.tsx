import { describeStatus } from "../lib/statusText";
import { formatAge } from "../lib/format";
import { useNow, useStatus } from "../hooks/status";
import { ActivityRibbon } from "./ActivityRibbon";
import styles from "./StatusBand.module.css";

const TONE_VAR = {
  ok: "var(--ok)",
  warning: "var(--sev-medium)",
  alert: "var(--sev-high)",
  offline: "var(--text-muted)",
} as const;

// The shape repeats the word, so the state survives colour-blindness and greyscale screens.
const TONE_GLYPH = {
  ok: "M12 5a7 7 0 1 0 0 14 7 7 0 0 0 0-14Z",
  warning: "M12 3 21 12 12 21 3 12Z",
  alert: "M12 3 22 20H2Z",
  offline: "M5 11h14v2H5Z",
} as const;

export function StatusBand() {
  const { data, error, updatedAt, failures } = useStatus();
  const now = useNow(1000);
  const head = describeStatus(data, error !== null && data === null);
  const color = TONE_VAR[head.tone];
  const age = updatedAt === null ? null : (now - updatedAt) / 1000;
  return (
    <section className={styles.band} style={{ borderLeftColor: color }} aria-label="Current status">
      <div className={styles.top}>
        <svg width="22" height="22" viewBox="0 0 24 24" aria-hidden="true">
          <path d={TONE_GLYPH[head.tone]} fill={color} />
        </svg>
        <div className={styles.text} role="status">
          <strong className={styles.label} style={{ color }}>
            {head.label}
          </strong>
          <span className={styles.sentence}>{head.sentence}</span>
        </div>
        <span className={styles.age}>
          {age === null ? "" : `Updated ${formatAge(age)}`}
          {failures > 0 && data !== null ? " (refresh failing)" : ""}
        </span>
      </div>
      <ActivityRibbon />
    </section>
  );
}
