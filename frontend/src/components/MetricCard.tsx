import type { ReactNode } from "react";
import ui from "../ui.module.css";
import styles from "./MetricCard.module.css";

export function MetricCard({
  label,
  value,
  note,
  chart,
}: {
  label: string;
  value: string;
  note?: ReactNode;
  chart?: ReactNode;
}) {
  return (
    <section className={ui.card} aria-label={label}>
      <h3 className={styles.label}>{label}</h3>
      <p className={styles.value}>{value}</p>
      {note && <p className={`${ui.muted} ${ui.small} ${styles.note}`}>{note}</p>}
      {chart && <div className={styles.chart}>{chart}</div>}
    </section>
  );
}
