import base64
import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from sentinelpi.collectors.metrics import MetricsSample
from sentinelpi.collectors.ports import ListeningPort, PortSnapshot
from sentinelpi.collectors.processes import ProcessInfo, ProcessSnapshot
from sentinelpi.config import Settings
from sentinelpi.events import Severity
from sentinelpi.main import create_app
from sentinelpi.monitor import HEARTBEAT_KEY
from sentinelpi.storage import events_repo, state_repo, telemetry_repo
from sentinelpi.timeutil import to_db, utc_now
from tests.conftest import NOW
from tests.helpers_detection import auth_event
from tests.helpers_incidents import correlator, detection, put

H = {"Content-Type": "application/json"}


def make_settings(db, **server):
    return Settings.model_validate(
        {"storage": {"db_path": str(db.path)}, "frontend_dist": "/nonexistent", "server": server}
    )


@pytest.fixture
def client(db):
    return TestClient(create_app(make_settings(db)), base_url="http://localhost:8787")


def seed_incident(db, ts=None, ip="203.0.113.9", rule="SP-001"):
    ts = ts or utc_now()
    with db.session() as c:
        put(c, detection(ts, rule, ip=None if rule != "SP-001" else ip))
        correlator().run(c, ts)


def incidents(client, **params):
    return client.get("/api/v1/incidents", params=params).json()


# ======================================================================== security
def test_unknown_host_names_are_refused(db):
    c = TestClient(create_app(make_settings(db)), base_url="http://evil.example")
    r = c.get("/api/v1/health")
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden_host"


@pytest.mark.parametrize("host", ["localhost:8787", "127.0.0.1:8787", "localhost"])
def test_loopback_names_are_accepted(db, host):
    c = TestClient(create_app(make_settings(db)), base_url=f"http://{host}")
    assert c.get("/api/v1/health").status_code == 200


@pytest.mark.parametrize(
    ("header", "ok"),
    [
        ("[::1]:8787", True),
        ("[::1]", True),
        ("LOCALHOST:8787", True),
        ("localhost.evil.com", False),
        ("[::2]:8787", False),
        ("", False),
        ("localhost:8787, evil.com", False),
    ],
)
def test_host_header_forms(client, header, ok):
    r = client.get("/api/v1/health", headers={"Host": header})
    assert r.is_success is ok


def test_allowed_hosts_can_be_extended(db):
    s = make_settings(db, allowed_hosts=["manavpi.local"])
    assert (
        TestClient(create_app(s), base_url="http://manavpi.local:8787")
        .get("/api/v1/health")
        .is_success
    )


def test_state_changes_reject_foreign_and_opaque_origins(client, db):
    seed_incident(db)
    inc = incidents(client)["items"][0]["id"]
    body = {"status": "acknowledged"}
    for origin in ("http://evil.example", "http://localhost:9999", "null"):
        r = client.patch(f"/api/v1/incidents/{inc}", json=body, headers={**H, "Origin": origin})
        assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden_origin", origin
    assert incidents(client)["items"][0]["status"] == "open"  # nothing happened
    ok = client.patch(
        f"/api/v1/incidents/{inc}", json=body, headers={**H, "Origin": "http://localhost:8787"}
    )
    assert ok.status_code == 200


def test_configured_extra_origin_is_allowed(db):
    s = make_settings(db, allowed_origins=["http://localhost:5173"])
    c = TestClient(create_app(s), base_url="http://localhost:8787")
    seed_incident(db)
    inc = c.get("/api/v1/incidents").json()["items"][0]["id"]
    r = c.patch(
        f"/api/v1/incidents/{inc}",
        json={"status": "resolved"},
        headers={**H, "Origin": "http://localhost:5173"},
    )
    assert r.status_code == 200


def test_state_changes_require_json(client, db):
    seed_incident(db)
    inc = incidents(client)["items"][0]["id"]
    r = client.patch(
        f"/api/v1/incidents/{inc}",
        content="status=resolved",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 415
    assert incidents(client)["items"][0]["status"] == "open"


def test_docs_only_on_a_local_server(db):
    local = TestClient(create_app(make_settings(db)), base_url="http://localhost")
    assert local.get("/api/docs").status_code == 200
    assert "/api/v1/incidents/{incident_id}" in local.get("/api/openapi.json").json()["paths"]
    lan = make_settings(db, host="0.0.0.0", allowed_hosts=["pi.local"])  # noqa: S104
    c = TestClient(create_app(lan), base_url="http://pi.local")
    assert c.get("/api/docs").status_code == 404 and c.get("/api/openapi.json").status_code == 404


# ======================================================================== errors
def test_error_shapes(client):
    r = client.get("/api/v1/nope")
    assert r.status_code == 404 and r.json() == {
        "error": {"code": "not_found", "message": "Not found."}
    }
    r = client.delete("/api/v1/incidents", headers=H)
    assert r.status_code == 405 and r.json()["error"]["code"] == "method_not_allowed"


def test_validation_errors_do_not_echo_input(client):
    r = client.get("/api/v1/events/not-a-uuid-<script>")
    assert r.status_code == 422
    body = json.dumps(r.json())
    assert "script" not in body and r.json()["error"]["code"] == "validation_error"


def test_unexpected_failures_do_not_leak(db, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("/home/secret/path password=hunter2")

    monkeypatch.setattr(events_repo, "get_event", boom)
    c = TestClient(
        create_app(make_settings(db)), base_url="http://localhost", raise_server_exceptions=False
    )
    r = c.get("/api/v1/events/6f1b1a1e-0000-4000-8000-000000000000")
    assert r.status_code == 500 and "hunter2" not in r.text and "secret" not in r.text


def test_uninitialised_database_is_a_503(tmp_path):
    s = Settings.model_validate(
        {"storage": {"db_path": str(tmp_path / "fresh.db")}, "frontend_dist": "/nonexistent"}
    )
    c = TestClient(create_app(s), base_url="http://localhost", raise_server_exceptions=False)
    r = c.get("/api/v1/incidents")
    assert r.status_code == 503 and r.json()["error"]["code"] == "database_unavailable"


def test_versioned_health(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert client.get("/api/health").status_code == 200


# ======================================================================== events
@pytest.fixture
def events_db(db):
    evs = []
    for i in range(8):
        ts = NOW + timedelta(seconds=i // 2)  # pairs share a timestamp: tests the tiebreak
        evs.append(auth_event(ts, ip="203.0.113.1" if i % 2 else "203.0.113.2", port=40000 + i))
    evs.append(detection(NOW + timedelta(minutes=1), "SP-002"))
    with db.session() as c:
        put(c, *evs)
    return db


def test_event_list_shape_and_order(client, events_db):
    body = client.get("/api/v1/events").json()
    assert set(body) == {"items", "total", "limit", "next_cursor"}
    assert body["total"] == 9 and body["limit"] == 50 and body["next_cursor"] is None
    stamps = [e["timestamp"] for e in body["items"]]
    assert stamps == sorted(stamps, reverse=True)
    assert body["items"][0]["event_type"] == "detection.new_listening_port"
    assert {"id", "timestamp", "source", "severity", "summary", "metadata"} <= set(body["items"][0])


def test_event_pagination_walks_every_row_exactly_once(client, events_db):
    seen, cursor, pages = [], None, 0
    while True:
        params = {"limit": 2, **({"cursor": cursor} if cursor else {})}
        body = client.get("/api/v1/events", params=params).json()
        seen += [e["id"] for e in body["items"]]
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break
        assert len(body["items"]) == 2
    assert len(seen) == 9 == len(set(seen)) and pages == 5


def test_event_filters(client, events_db):
    def ids(**p):
        return client.get("/api/v1/events", params=p).json()

    assert ids(source_ip="203.0.113.1")["total"] == 4
    assert ids(type="detection.new_listening_port")["total"] == 1
    assert ids(severity="medium")["total"] == 1
    assert ids(source="auth_log")["total"] == 8
    window = ids(**{"from": NOW.isoformat(), "to": (NOW + timedelta(seconds=2)).isoformat()})
    assert window["total"] == 4  # 'to' is exclusive
    both = ids(source_ip="203.0.113.1", severity="low")
    assert both["total"] == 4 and all(e["source_ip"] == "203.0.113.1" for e in both["items"])


@pytest.mark.parametrize(
    ("params", "status", "code"),
    [
        ({"source_ip": "999.1.1.1"}, 400, "bad_ip"),
        ({"source_ip": "' OR 1=1 --"}, 400, "bad_ip"),
        ({"from": "2026-09-28T12:00:00", "to": "2026-09-28T13:00:00Z"}, 400, "bad_timestamp"),
        ({"from": "2026-09-28T13:00:00Z", "to": "2026-09-28T12:00:00Z"}, 400, "bad_range"),
        ({"from": "2026-09-28T12:00:00Z", "to": "2026-09-28T12:00:00Z"}, 400, "bad_range"),
        ({"cursor": "garbage"}, 400, "invalid_cursor"),
        ({"cursor": base64.urlsafe_b64encode(b'["x","y"]').decode()}, 400, "invalid_cursor"),
        ({"cursor": base64.urlsafe_b64encode(b'{"a":1}').decode()}, 400, "invalid_cursor"),
        ({"limit": 0}, 422, "validation_error"),
        ({"limit": 201}, 422, "validation_error"),
        ({"limit": "ten"}, 422, "validation_error"),
        ({"severity": "catastrophic"}, 422, "validation_error"),
        ({"source": "carrier_pigeon"}, 422, "validation_error"),
        ({"type": "x" * 65}, 422, "validation_error"),
    ],
)
def test_event_list_rejects_bad_input(client, params, status, code):
    r = client.get("/api/v1/events", params=params)
    assert r.status_code == status and r.json()["error"]["code"] == code


def test_event_detail_and_missing(client, events_db):
    first = client.get("/api/v1/events").json()["items"][-1]
    got = client.get(f"/api/v1/events/{first['id']}")
    assert got.status_code == 200 and got.json() == first
    missing = client.get("/api/v1/events/6f1b1a1e-0000-4000-8000-000000000000")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "not_found"


def test_event_metadata_is_redacted_in_responses(client, db):
    with db.session() as c:
        put(c, detection(NOW, "SP-002", metadata={"password": "hunter2", "note": "token=abc12345"}))
    text = client.get("/api/v1/events").text
    assert "hunter2" not in text and "abc12345" not in text


# ======================================================================== incidents
def test_incident_list_filters_and_paginates(client, db):
    now = utc_now()
    for n in range(5):
        seed_incident(db, now - timedelta(hours=n), ip=f"203.0.113.{n + 1}")
    seed_incident(db, now, rule="SP-002")
    body = incidents(client)
    assert body["total"] == 6 and body["limit"] == 25
    assert incidents(client, severity="high")["total"] == 5
    assert incidents(client, status="resolved")["total"] == 0

    seen, cursor = [], None
    while True:
        page = incidents(client, limit=4, **({"cursor": cursor} if cursor else {}))
        seen += [i["id"] for i in page["items"]]
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(seen) == 6 == len(set(seen))
    assert client.get("/api/v1/incidents", params={"status": "nope"}).status_code == 422
    assert client.get("/api/v1/incidents", params={"limit": 101}).status_code == 422


def test_incident_detail_has_timeline(client, db):
    with db.session() as c:
        ev = auth_event(NOW - timedelta(minutes=1), ip="203.0.113.9")
        put(c, ev, detection(NOW, "SP-001", ip="203.0.113.9", evidence=[ev.id]))
        correlator().run(c, NOW)
    inc_id = incidents(client)["items"][0]["id"]
    body = client.get(f"/api/v1/incidents/{inc_id}").json()
    assert body["evidence_count"] == 2 and body["rule_ids"] == ["SP-001"]
    kinds = [(t["kind"], t.get("audit_kind") or t["event_type"]) for t in body["timeline"]]
    assert kinds == [
        ("event", "auth.ssh_failed_login"),
        ("event", "detection.ssh_repeated_failures"),
        ("audit", "created"),
    ]
    assert body["risk_breakdown"][0]["points"] == 35
    assert (
        client.get(f"/api/v1/incidents/{inc_id}", params={"timeline_limit": 1}).json()[
            "timeline_limit"
        ]
        == 1
    )
    assert (
        client.get(f"/api/v1/incidents/{inc_id}", params={"timeline_limit": 501}).status_code == 422
    )


def test_incident_lookup_errors(client):
    assert client.get("/api/v1/incidents/not-a-uuid").status_code == 422
    r = client.get("/api/v1/incidents/6f1b1a1e-0000-4000-8000-000000000000")
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"
    r = client.patch(
        "/api/v1/incidents/6f1b1a1e-0000-4000-8000-000000000000",
        json={"status": "resolved"},
        headers=H,
    )
    assert r.status_code == 404


def test_patch_lifecycle(client, db):
    seed_incident(db)
    inc_id = incidents(client)["items"][0]["id"]
    url = f"/api/v1/incidents/{inc_id}"
    r = client.patch(url, json={"status": "acknowledged", "note": "on it"}, headers=H)
    assert r.status_code == 200 and r.json()["status"] == "acknowledged"
    r = client.patch(url, json={"status": "resolved", "note": "blocked"}, headers=H)
    assert r.json()["status"] == "resolved" and r.json()["resolution_note"] == "blocked"
    audit = [t for t in client.get(url).json()["timeline"] if t["audit_kind"] == "status_changed"]
    assert [(a["from_status"], a["to_status"], a["actor"]) for a in audit] == [
        ("open", "acknowledged", "user"),
        ("acknowledged", "resolved", "user"),
    ]
    again = client.patch(url, json={"status": "resolved"}, headers=H)
    assert again.status_code == 409 and again.json()["error"]["code"] == "invalid_transition"


@pytest.mark.parametrize(
    "body",
    [
        {"status": "open"},
        {"status": "deleted"},
        {"status": "resolved", "severity": "low"},
        {"status": "resolved", "note": "x" * 501},
        {"note": "no status"},
        {"status": ["resolved"]},
        {},
    ],
)
def test_patch_rejects_bad_bodies(client, db, body):
    seed_incident(db)
    inc = incidents(client)["items"][0]
    r = client.patch(f"/api/v1/incidents/{inc['id']}", json=body, headers=H)
    assert r.status_code == 422
    assert incidents(client)["items"][0]["status"] == "open"


def test_patch_with_malformed_json(client, db):
    seed_incident(db)
    inc = incidents(client)["items"][0]["id"]
    r = client.patch(f"/api/v1/incidents/{inc}", content="{nope", headers=H)
    assert r.status_code == 422


def test_incident_notes_are_redacted(client, db):
    seed_incident(db)
    inc = incidents(client)["items"][0]["id"]
    r = client.patch(
        f"/api/v1/incidents/{inc}",
        json={"status": "resolved", "note": "password=hunter2"},
        headers=H,
    )
    assert "hunter2" not in r.text


# ======================================================================== system
def fresh_metrics(db, cpu=20.0, age=2):
    with db.session() as c:
        telemetry_repo.insert_metrics(
            c,
            MetricsSample(
                timestamp=utc_now() - timedelta(seconds=age),
                cpu_percent=cpu,
                memory_percent=30.0,
                disk_percent=40.0,
                temperature_c=51.5,
                uptime_seconds=1234.0,
            ),
        )


def heartbeat(db, age=1):
    with db.session() as c:
        state_repo.set_state(c, HEARTBEAT_KEY, to_db(utc_now() - timedelta(seconds=age)))


def test_status_with_an_empty_database_says_what_is_missing(client):
    body = client.get("/api/v1/system/status").json()
    assert body["overall"] == "warning" and body["metrics"] is None
    assert body["monitor"] == {"running": False, "last_heartbeat": None, "age_seconds": None}
    assert body["active_alert"] is None and body["open_incidents"] == []
    assert body["incidents"] == {"open": 0, "acknowledged": 0, "resolved": 0, "false_positive": 0}
    assert any("monitor is not running" in r for r in body["reasons"])


def test_status_ok_when_everything_is_fresh_and_quiet(client, db):
    fresh_metrics(db)
    heartbeat(db)
    body = client.get("/api/v1/system/status").json()
    assert body["overall"] == "ok" and body["reasons"] == []
    assert body["monitor"]["running"] is True
    assert body["metrics"]["cpu_percent"] == 20.0 and body["metrics"]["stale"] is False
    assert body["metrics"]["temperature_c"] == 51.5


def test_status_flags_stale_data(client, db):
    fresh_metrics(db, age=600)
    heartbeat(db, age=600)
    body = client.get("/api/v1/system/status").json()
    assert body["overall"] == "warning" and body["metrics"]["stale"] is True
    assert body["monitor"]["running"] is False and len(body["reasons"]) == 2


def test_status_alert_follows_the_incident_lifecycle(client, db):
    fresh_metrics(db)
    heartbeat(db)
    seed_incident(db, rule="SP-002")  # medium
    body = client.get("/api/v1/system/status").json()
    assert body["overall"] == "warning" and body["active_alert"]["severity"] == "medium"

    seed_incident(db)  # high
    body = client.get("/api/v1/system/status").json()
    assert body["overall"] == "alert" and body["active_alert"]["severity"] == "high"
    assert [i["severity"] for i in body["open_incidents"]] == ["high", "medium"]
    assert body["incidents"]["open"] == 2
    top = body["active_alert"]["id"]

    client.patch(f"/api/v1/incidents/{top}", json={"status": "acknowledged"}, headers=H)
    body = client.get("/api/v1/system/status").json()
    assert body["active_alert"]["severity"] == "medium"  # acknowledged stops alerting
    assert body["incidents"]["acknowledged"] == 1 and body["overall"] == "warning"


def test_metrics_series_raw_and_bucketed(client, db):
    base = utc_now().replace(microsecond=0) - timedelta(minutes=10)
    with db.session() as c:
        for i in range(60):
            telemetry_repo.insert_metrics(
                c,
                MetricsSample(
                    timestamp=base + timedelta(seconds=10 * i),
                    cpu_percent=float(i % 2 * 10),
                    memory_percent=30.0,
                    disk_percent=40.0,
                    temperature_c=None,
                    uptime_seconds=1000.0 + i,
                ),
            )
    raw = client.get("/api/v1/system/metrics").json()
    assert raw["interval_seconds"] is None and len(raw["points"]) == 60 and not raw["truncated"]
    stamps = [p["timestamp"] for p in raw["points"]]
    assert stamps == sorted(stamps) and raw["points"][0]["temperature_c"] is None
    assert set(raw) == {"from", "to", "interval_seconds", "truncated", "points"}

    bucketed = client.get("/api/v1/system/metrics", params={"interval_seconds": 60}).json()
    assert bucketed["interval_seconds"] == 60 and 9 <= len(bucketed["points"]) <= 11
    assert all(p["cpu_percent"] == 5.0 for p in bucketed["points"][1:-1])  # mean of 0 and 10
    assert bucketed["points"][-1]["uptime_seconds"] == 1059.0  # counters keep the latest


def test_metrics_series_is_always_bounded(client, db):
    base = utc_now().replace(microsecond=0) - timedelta(hours=1)
    with db.session() as c:
        telemetry_repo.insert_metrics_many(
            c,
            [
                MetricsSample(
                    timestamp=base + timedelta(seconds=i),
                    cpu_percent=10.0,
                    memory_percent=30.0,
                    disk_percent=40.0,
                    uptime_seconds=float(i),
                )
                for i in range(2500)
            ],
        )
    auto = client.get("/api/v1/system/metrics").json()
    assert len(auto["points"]) <= 1000 and auto["interval_seconds"] > 1
    # a tiny requested interval is raised so the response cannot exceed the cap
    tiny = client.get("/api/v1/system/metrics", params={"interval_seconds": 1}).json()
    assert len(tiny["points"]) <= 1000


@pytest.mark.parametrize(
    ("params", "status"),
    [
        ({"interval_seconds": 0}, 422),
        ({"interval_seconds": 100000}, 422),
        ({"interval_seconds": "x"}, 422),
        ({"from": "2026-09-28T13:00:00Z", "to": "2026-09-28T12:00:00Z"}, 400),
        ({"from": "2026-09-28T12:00:00"}, 400),
    ],
)
def test_metrics_rejects_bad_input(client, params, status):
    assert client.get("/api/v1/system/metrics", params=params).status_code == status


# ======================================================================== snapshots and rules
def test_processes(client, db):
    assert client.get("/api/v1/processes").json() == {
        "observed_at": None,
        "items": [],
        "total": 0,
        "limit": 50,
        "next_cursor": None,
    }
    procs = [
        ProcessInfo(
            pid=1,
            name="zeta",
            username="root",
            cpu_percent=1,
            memory_percent=9,
            command_redacted="zeta --secret-flag",
        ),
        ProcessInfo(
            pid=2,
            name="alpha",
            username="pi",
            cpu_percent=50,
            memory_percent=1,
            command_redacted="alpha",
        ),
        ProcessInfo(
            pid=3,
            name="mid",
            username=None,
            cpu_percent=5,
            memory_percent=5,
            command_redacted="mid",
        ),
    ]
    with db.session() as c:
        telemetry_repo.insert_process_snapshot(
            c, ProcessSnapshot(timestamp=utc_now(), total_count=3, truncated=False, processes=procs)
        )
    body = client.get("/api/v1/processes").json()
    assert [p["name"] for p in body["items"]] == ["alpha", "mid", "zeta"] and body["total"] == 3
    assert "command" not in json.dumps(body) and "secret-flag" not in json.dumps(body)
    by_mem = client.get("/api/v1/processes", params={"sort": "memory", "limit": 1}).json()
    assert [p["name"] for p in by_mem["items"]] == ["zeta"] and by_mem["total"] == 3
    by_name = client.get("/api/v1/processes", params={"sort": "name"}).json()
    assert [p["name"] for p in by_name["items"]] == ["alpha", "mid", "zeta"]
    assert client.get("/api/v1/processes", params={"sort": "pid; drop"}).status_code == 422
    assert client.get("/api/v1/processes", params={"limit": 201}).status_code == 422


def test_listeners(client, db):
    ports = [
        ListeningPort(protocol="tcp", local_address="0.0.0.0", port=22, process_name="sshd", pid=1),  # noqa: S104
        ListeningPort(protocol="tcp", local_address="127.0.0.1", port=631, process_name="cupsd"),
        ListeningPort(protocol="udp", local_address="::", port=5353, process_name="avahi"),
    ]
    with db.session() as c:
        telemetry_repo.insert_port_snapshot(
            c, PortSnapshot(timestamp=utc_now(), total_count=3, truncated=False, ports=ports)
        )
    body = client.get("/api/v1/network/listeners").json()
    exposed = {p["port"]: p["reachable_beyond_loopback"] for p in body["items"]}
    assert exposed == {22: True, 631: False, 5353: True} and body["total"] == 3
    assert client.get("/api/v1/network/listeners", params={"protocol": "udp"}).json()["total"] == 1
    only = client.get("/api/v1/network/listeners", params={"exposed_only": "true"}).json()
    assert {p["port"] for p in only["items"]} == {22, 5353}
    assert client.get("/api/v1/network/listeners", params={"protocol": "icmp"}).status_code == 422
    empty = TestClient(  # no snapshot yet
        create_app(make_settings(db.__class__(db.path.parent / "x.db"))),
        base_url="http://localhost",
    )
    assert empty.get("/api/v1/network/listeners").status_code == 503  # unmigrated file


def test_rules(client):
    body = client.get("/api/v1/rules").json()
    assert [r["id"] for r in body["items"]] == ["SP-001", "SP-002", "SP-003", "SP-004"]
    assert body["total"] == 4 and body["items"][0]["thresholds"]["threshold"] == 5
    assert all(r["enabled"] for r in body["items"])
    assert client.put("/api/v1/rules", json={}, headers=H).status_code == 405  # read-only


def test_every_documented_route_exists(client):
    paths = client.get("/api/openapi.json").json()["paths"]
    expected = {
        ("/api/v1/health", "get"),
        ("/api/v1/system/status", "get"),
        ("/api/v1/system/metrics", "get"),
        ("/api/v1/events", "get"),
        ("/api/v1/events/{event_id}", "get"),
        ("/api/v1/incidents", "get"),
        ("/api/v1/incidents/{incident_id}", "get"),
        ("/api/v1/incidents/{incident_id}", "patch"),
        ("/api/v1/processes", "get"),
        ("/api/v1/network/listeners", "get"),
        ("/api/v1/rules", "get"),
    }
    assert expected <= {(p, m) for p, ms in paths.items() for m in ms}
    assert all(
        m == "get" for p, ms in paths.items() if p != "/api/v1/incidents/{incident_id}" for m in ms
    )  # only the incident status endpoint can change anything
    assert Severity.HIGH and datetime.now(UTC)  # imports used
