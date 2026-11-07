import type { AlertSummary, Incident, IncidentDetail, SentinelEvent, SystemStatus } from "../api/types";

export const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

export function alert(over: Partial<AlertSummary> = {}): AlertSummary {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    title: "Repeated SSH failures from 203.0.113.9",
    severity: "high",
    risk_score: 35,
    status: "open",
    source_ip: "203.0.113.9",
    first_seen: iso(240_000),
    last_seen: iso(30_000),
    ...over,
  };
}

export function status(over: Partial<SystemStatus> = {}): SystemStatus {
  return {
    generated_at: iso(0),
    host: "manavpi",
    overall: "ok",
    reasons: [],
    monitor: { running: true, last_heartbeat: iso(2000), age_seconds: 2 },
    metrics: {
      observed_at: iso(3000),
      age_seconds: 3,
      stale: false,
      cpu_percent: 12.5,
      memory_percent: 31.2,
      disk_percent: 44,
      temperature_c: 51.5,
      uptime_seconds: 90_000,
    },
    incidents: { open: 0, acknowledged: 0, resolved: 0, false_positive: 0 },
    active_alert: null,
    open_incidents: [],
    ...over,
  };
}

export function alerting(sev: AlertSummary["severity"] = "high"): SystemStatus {
  const a = alert({ severity: sev });
  return status({
    overall: sev === "high" || sev === "critical" ? "alert" : "warning",
    incidents: { open: 1, acknowledged: 0, resolved: 0, false_positive: 0 },
    active_alert: a,
    open_incidents: [a],
  });
}

export function incident(over: Partial<Incident> = {}): Incident {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    title: "Repeated SSH failures from 203.0.113.9",
    description: "Detections: SP-001 Repeated SSH failures. 2 evidence event(s).",
    severity: "high",
    risk_score: 35,
    status: "open",
    host: "manavpi",
    source_ip: "203.0.113.9",
    rule_ids: ["SP-001"],
    risk_breakdown: [{ rule_id: "SP-001", label: "SP-001: Repeated SSH failures", points: 35 }],
    first_seen: iso(240_000),
    last_seen: iso(30_000),
    created_at: iso(200_000),
    updated_at: iso(30_000),
    resolution_note: null,
    evidence_count: 2,
    ...over,
  };
}

export function detail(over: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    ...incident(),
    timeline: [
      {
        at: iso(240_000), kind: "event", event_id: "e1", event_type: "auth.ssh_failed_login", severity: "low",
        summary: "Failed SSH login from 203.0.113.9", audit_kind: null, actor: null, from_status: null, to_status: null, note: null,
      },
      {
        at: iso(30_000), kind: "event", event_id: "e2", event_type: "detection.ssh_repeated_failures", severity: "high",
        summary: "SP-001: 8 failed SSH attempts from 203.0.113.9 within 5 min", audit_kind: null, actor: null, from_status: null, to_status: null, note: null,
      },
      {
        at: iso(29_000), kind: "audit", event_id: null, event_type: null, severity: null, summary: "detail", audit_kind: "created",
        actor: "system", from_status: null, to_status: null, note: null,
      },
    ],
    timeline_limit: 200,
    ...over,
  };
}

export function event(over: Partial<SentinelEvent> = {}): SentinelEvent {
  return {
    id: "22222222-2222-4222-8222-222222222222",
    timestamp: iso(60_000),
    source: "auth_log",
    event_type: "auth.ssh_failed_login",
    severity: "low",
    summary: "Failed SSH login from 203.0.113.9",
    source_ip: "203.0.113.9",
    username: null,
    process_name: null,
    host: "manavpi",
    metadata: {},
    ...over,
  };
}
