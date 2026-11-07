import { useCallback, useEffect, useRef, useState } from "react";

export interface Polled<T> {
  data: T | null;
  error: Error | null;
  /** True until the first answer (or failure) arrives. */
  loading: boolean;
  /** Epoch ms of the last successful fetch. */
  updatedAt: number | null;
  /** Consecutive failures since the last success. */
  failures: number;
  refresh: () => void;
}

interface Options {
  /** Stop polling while the tab is hidden (default true). The kiosk turns this off. */
  pauseWhenHidden?: boolean;
}

/**
 * Fetch now, then again `intervalMs` after each answer (so slow requests never pile up).
 * The last good data is kept while a refresh fails, so a blip does not blank the screen.
 * `key` names the request: change it to start over (new filters, new id). Passing a null
 * interval pauses polling (the current data stays); passing a number again resumes it.
 */
export function usePolling<T>(
  key: string,
  fetcher: (signal: AbortSignal) => Promise<T>,
  intervalMs: number | null,
  { pauseWhenHidden = true }: Options = {},
): Polled<T> {
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;
  // Read at each step, so pausing or resuming polling never restarts the request in flight.
  const intervalRef = useRef(intervalMs);
  intervalRef.current = intervalMs;
  const [state, setState] = useState<Omit<Polled<T>, "refresh">>({
    data: null,
    error: null,
    loading: true,
    updatedAt: null,
    failures: 0,
  });
  const [tick, setTick] = useState(0);
  const refresh = useCallback(() => setTick((n) => n + 1), []);

  // Resuming from a pause (null -> a number) fetches straight away and restarts the cycle.
  const wasPaused = useRef(intervalMs === null);
  useEffect(() => {
    if (wasPaused.current && intervalMs !== null) setTick((n) => n + 1);
    wasPaused.current = intervalMs === null;
  }, [intervalMs]);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const controller = new AbortController();
    setState((s) => ({ ...s, loading: s.data === null }));

    const schedule = () => {
      if (cancelled || intervalRef.current === null) return;
      timer = setTimeout(() => void run(false), intervalRef.current);
    };
    const run = async (initial: boolean) => {
      if (!initial && intervalRef.current === null) return; // paused while waiting
      if (pauseWhenHidden && document.hidden) {
        schedule();
        return;
      }
      try {
        const data = await fetcherRef.current(controller.signal);
        if (cancelled) return;
        setState({ data, error: null, loading: false, updatedAt: Date.now(), failures: 0 });
      } catch (err) {
        if (cancelled) return;
        setState((s) => ({
          ...s,
          error: err instanceof Error ? err : new Error(String(err)),
          loading: false,
          failures: s.failures + 1,
        }));
      }
      schedule();
    };
    void run(true);
    return () => {
      cancelled = true;
      controller.abort();
      if (timer) clearTimeout(timer);
    };
  }, [key, pauseWhenHidden, tick]);

  return { ...state, refresh };
}
