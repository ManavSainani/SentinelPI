import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { usePolling } from "./usePolling";

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

const flush = async (ms = 0) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms); }); };

describe("usePolling", () => {
  it("fetches at once and then after each interval", async () => {
    const fetcher = vi.fn().mockResolvedValue("a");
    const { result } = renderHook(() => usePolling("k", fetcher, 1000));
    expect(result.current.loading).toBe(true);
    await flush();
    expect(result.current).toMatchObject({ data: "a", loading: false, failures: 0 });
    await flush(1000);
    await flush(1000);
    expect(fetcher).toHaveBeenCalledTimes(3);
  });
  it("keeps the last good data while refreshes fail, and counts the failures", async () => {
    const fetcher = vi.fn().mockResolvedValueOnce("good").mockRejectedValue(new Error("down"));
    const { result } = renderHook(() => usePolling("k", fetcher, 1000));
    await flush();
    await flush(1000);
    await flush(1000);
    expect(result.current.data).toBe("good");
    expect(result.current.error?.message).toBe("down");
    expect(result.current.failures).toBe(2);
    fetcher.mockResolvedValue("back");
    await flush(1000);
    expect(result.current).toMatchObject({ data: "back", error: null, failures: 0 });
  });
  it("does not start a new request while one is still running", async () => {
    let release: (v: string) => void = () => {};
    const fetcher = vi.fn(() => new Promise<string>((r) => { release = r; }));
    renderHook(() => usePolling("k", fetcher, 1000));
    await flush(5000);
    expect(fetcher).toHaveBeenCalledTimes(1);
    release("x");
    await flush();
  });
  it("polls once only when the interval is null, and restarts when the key changes", async () => {
    const fetcher = vi.fn().mockResolvedValue("v");
    const { rerender } = renderHook(({ k }) => usePolling(k, fetcher, null), { initialProps: { k: "one" } });
    await flush(10_000);
    expect(fetcher).toHaveBeenCalledTimes(1);
    rerender({ k: "two" });
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it("pauses without refetching, and resumes with a fresh fetch", async () => {
    const fetcher = vi.fn().mockResolvedValue("v");
    const { rerender, result } = renderHook(({ i }) => usePolling("k", fetcher, i), {
      initialProps: { i: 1000 as number | null },
    });
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(1);
    rerender({ i: null });
    await flush(5000);
    expect(fetcher).toHaveBeenCalledTimes(1); // paused: no extra request, data kept
    expect(result.current.data).toBe("v");
    rerender({ i: 1000 });
    await flush();
    expect(fetcher).toHaveBeenCalledTimes(2);
    await flush(1000);
    expect(fetcher).toHaveBeenCalledTimes(3);
  });
  it("stops and aborts on unmount", async () => {
    const seen: AbortSignal[] = [];
    const fetcher = vi.fn((s: AbortSignal) => { seen.push(s); return Promise.resolve("x"); });
    const { unmount } = renderHook(() => usePolling("k", fetcher, 1000));
    await flush();
    unmount();
    await flush(5000);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(seen[0].aborted).toBe(true);
  });
  it("skips fetching while the tab is hidden when asked to", async () => {
    Object.defineProperty(document, "hidden", { value: true, configurable: true });
    const fetcher = vi.fn().mockResolvedValue("x");
    renderHook(() => usePolling("k", fetcher, 1000));
    await flush(3000);
    expect(fetcher).not.toHaveBeenCalled();
    Object.defineProperty(document, "hidden", { value: false, configurable: true });
    await flush(1000);
    expect(fetcher).toHaveBeenCalled();
  });
});
