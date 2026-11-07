const dateTime = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
  second: "2-digit",
});
const clock = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" });
const clockSeconds = new Intl.DateTimeFormat(undefined, {
  hour: "numeric",
  minute: "2-digit",
  second: "2-digit",
});
const dayLong = new Intl.DateTimeFormat(undefined, {
  weekday: "long",
  month: "long",
  day: "numeric",
});

/** Local-time presentation of a UTC ISO timestamp. */
export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "unknown time" : dateTime.format(d);
}
export const formatClock = (d: Date): string => clock.format(d);
export const formatClockSeconds = (d: Date): string => clockSeconds.format(d);
export const formatDay = (d: Date): string => dayLong.format(d);

/** "4 s ago", "3 min ago", "2 h ago", "5 d ago". */
export function formatAge(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 5) return "just now";
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86_400)} d ago`;
}

export function ageSince(iso: string, now: number = Date.now()): number {
  return (now - new Date(iso).getTime()) / 1000;
}

export function formatUptime(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86_400);
  const h = Math.floor((s % 86_400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d} d ${h} h`;
  if (h > 0) return `${h} h ${m} min`;
  return `${m} min`;
}

export const formatPercent = (value: number): string => `${value.toFixed(value >= 100 ? 0 : 1)}%`;

export function formatTemp(celsius: number | null): string {
  return celsius === null ? "n/a" : `${celsius.toFixed(1)} °C`;
}

/** Last path segment of a dotted event type: "auth.ssh_failed_login" -> "ssh failed login". */
export function eventTypeLabel(type: string): string {
  const tail = type.split(".").slice(1).join(" ") || type;
  return tail.replace(/_/g, " ");
}
