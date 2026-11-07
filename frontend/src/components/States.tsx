import type { ReactNode } from "react";
import { ApiError } from "../api/client";
import { formatAge } from "../lib/format";
import ui from "../ui.module.css";
import styles from "./States.module.css";

export function Loading({ what }: { what: string }) {
  return (
    <p className={styles.loading} role="status">
      Loading {what}…
    </p>
  );
}

function explain(error: Error): string {
  if (error instanceof ApiError) {
    if (error.code === "unreachable" || error.code === "timeout") {
      return `${error.message} Check that the SentinelPi server is running on the Pi.`;
    }
    if (error.code === "database_unavailable") {
      return "The server is up but its database is not ready. Run the migrate command, then retry.";
    }
    return error.message;
  }
  return "Something went wrong while loading this.";
}

export function ErrorBox({ what, error, onRetry }: { what: string; error: Error; onRetry?: () => void }) {
  return (
    <div className={styles.error} role="alert">
      <strong>Could not load {what}.</strong>
      <span>{explain(error)}</span>
      {onRetry && (
        <button type="button" className={ui.button} onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className={styles.empty}>{children}</p>;
}

/** Shown above data that is still on screen but no longer being refreshed. */
export function StaleNotice({ error, updatedAt }: { error: Error | null; updatedAt: number | null }) {
  if (!error || updatedAt === null) return null;
  return (
    <p className={styles.stale} role="status">
      Showing the last data received {formatAge((Date.now() - updatedAt) / 1000)}. Refreshing is failing:{" "}
      {explain(error)}
    </p>
  );
}
