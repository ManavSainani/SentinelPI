from fastapi.testclient import TestClient

from sentinelpi.config import Settings
from sentinelpi.main import create_app


def test_health_ok():
    client = TestClient(create_app(Settings()))
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"] == "0.1.0"
    assert body["uptime_seconds"] >= 0


def test_serves_built_frontend(tmp_path):
    (tmp_path / "index.html").write_text("<html>hi</html>")
    client = TestClient(create_app(Settings(frontend_dist=str(tmp_path))))
    assert client.get("/").text == "<html>hi</html>"
    assert client.get("/api/health").status_code == 200  # API not shadowed


def test_api_only_when_no_frontend(tmp_path):
    client = TestClient(create_app(Settings(frontend_dist=str(tmp_path / "missing"))))
    assert client.get("/api/health").status_code == 200
    assert client.get("/").status_code == 404
