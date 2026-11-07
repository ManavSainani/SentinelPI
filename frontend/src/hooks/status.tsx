import { createContext, useContext, type ReactNode } from "react";
import { api } from "../api/client";
import type { SystemStatus } from "../api/types";
import { usePolling, type Polled } from "./usePolling";

const StatusContext = createContext<Polled<SystemStatus> | null>(null);

/** One shared poll of /system/status for the whole app (banner, overview and kiosk). */
export function StatusProvider({
  children,
  intervalMs = 5000,
  pauseWhenHidden = true,
}: {
  children: ReactNode;
  intervalMs?: number;
  pauseWhenHidden?: boolean;
}) {
  const polled = usePolling("status", (s) => api.status(s), intervalMs, { pauseWhenHidden });
  return <StatusContext.Provider value={polled}>{children}</StatusContext.Provider>;
}

export function useStatus(): Polled<SystemStatus> {
  const ctx = useContext(StatusContext);
  if (ctx === null) throw new Error("useStatus must be used inside <StatusProvider>");
  return ctx;
}

/** Re-render every `ms` so "3 s ago" labels keep moving. */
export { useNow } from "./useNow";
