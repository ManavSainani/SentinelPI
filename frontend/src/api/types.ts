// Shapes returned by the SentinelPi API (backend/src/sentinelpi/api). Timestamps are UTC ISO-8601.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type IncidentStatus = "open" | "acknowledged" | "resolved" | "false_positive";
export type Overall = "ok" | "warning" | "alert";

export interface Health {
  status: string;
  version: string;
  uptime_seconds: number;
  platform: string;
  arch: string;
  python: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  next_cursor: string | null;
}

export interface SentinelEvent {
  id: string;
  timestamp: string;
  source: string;
  event_type: string;
  severity: Severity;
  summary: string;
  source_ip: string | null;
  username: string | null;
  process_name: string | null;
  host: string;
  metadata: Record<string, unknown>;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  risk_score: number;
  status: IncidentStatus;
  host: string;
  source_ip: string | null;
  rule_ids: string[];
  risk_breakdown: { rule_id?: string; label: string; points: number }[];
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  resolution_note: string | null;
  evidence_count: number;
}

export interface TimelineItem {
  at: string;
  kind: "event" | "audit";
  event_id: string | null;
  event_type: string | null;
  severity: Severity | null;
  summary: string | null;
  audit_kind: string | null;
  actor: string | null;
  from_status: string | null;
  to_status: string | null;
  note: string | null;
}

export interface IncidentDetail extends Incident {
  timeline: TimelineItem[];
  timeline_limit: number;
}

export interface AlertSummary {
  id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  status: IncidentStatus;
  source_ip: string | null;
  first_seen: string;
  last_seen: string;
}

export interface SystemStatus {
  generated_at: string;
  host: string;
  overall: Overall;
  reasons: string[];
  monitor: { running: boolean; last_heartbeat: string | null; age_seconds: number | null };
  metrics: {
    observed_at: string;
    age_seconds: number;
    stale: boolean;
    cpu_percent: number;
    memory_percent: number;
    disk_percent: number;
    temperature_c: number | null;
    uptime_seconds: number;
  } | null;
  incidents: Record<IncidentStatus, number>;
  active_alert: AlertSummary | null;
  open_incidents: AlertSummary[];
}

export interface MetricPoint {
  timestamp: string;
  cpu_percent: number;
  memory_percent: number;
  disk_percent: number;
  temperature_c: number | null;
  uptime_seconds: number;
}

export interface MetricsSeries {
  from: string;
  to: string;
  interval_seconds: number | null;
  truncated: boolean;
  points: MetricPoint[];
}

export interface ProcessRow {
  pid: number;
  name: string;
  username: string | null;
  cpu_percent: number;
  memory_percent: number;
}

export interface ProcessList {
  observed_at: string | null;
  items: ProcessRow[];
  total: number;
  limit: number;
}

export interface Listener {
  protocol: "tcp" | "udp";
  local_address: string;
  port: number;
  process_name: string | null;
  pid: number | null;
  reachable_beyond_loopback: boolean;
  in_baseline: boolean | null;
}

export interface ListenerList {
  observed_at: string | null;
  baseline_captured_at: string | null;
  items: Listener[];
  total: number;
  limit: number;
}

export interface Rule {
  id: string;
  name: string;
  enabled: boolean;
  severity: string;
  description: string;
  thresholds: Record<string, unknown>;
}

export interface About {
  version: string;
  host: string;
  retention_days: Record<string, number>;
  intervals_seconds: Record<string, number>;
  collects: string[];
  never_collects: string[];
}
