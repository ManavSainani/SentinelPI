export interface Health {
  status: string;
  version: string;
  uptime_seconds: number;
  platform: string;
  arch: string;
  python: string;
}

export async function fetchHealth(signal?: AbortSignal): Promise<Health> {
  const res = await fetch("/api/health", { signal });
  if (!res.ok) throw new Error(`Health check failed: HTTP ${res.status}`);
  return (await res.json()) as Health;
}
