from types import SimpleNamespace as NS

from sentinelpi.collectors.base import CollectorState
from sentinelpi.collectors.metrics import MetricsCollector


def fake_ps(**over):
    base = {
        "cpu_percent": lambda interval=None: 12.5,
        "virtual_memory": lambda: NS(percent=40.0),
        "disk_usage": lambda path: NS(percent=55.5),
        "boot_time": lambda: 1000.0,
        "net_io_counters": lambda: NS(bytes_recv=10, bytes_sent=20),
    }
    base.update(over)
    return NS(**base)


def make(tmp_path, ps, thermal=None):
    return MetricsCollector(
        psutil_mod=ps, thermal_path=thermal or tmp_path / "none", clock=lambda: 1600.0
    )


def test_normal_sample(tmp_path):
    r = make(tmp_path, fake_ps()).collect()
    assert r.status.state == CollectorState.OK
    d = r.data
    assert (d.cpu_percent, d.memory_percent, d.disk_percent) == (12.5, 40.0, 55.5)
    assert d.uptime_seconds == 600.0
    assert (d.net_rx_bytes, d.net_tx_bytes) == (10, 20)


def test_missing_temperature_is_ok_not_error(tmp_path):
    r = make(tmp_path, fake_ps()).collect()
    assert r.status.state == CollectorState.OK
    assert r.data.temperature_c is None
    assert r.status.missing == ["temperature_c"]


def test_temperature_from_psutil_prefers_cpu_sensor(tmp_path):
    sensors = {"nvme": [NS(current=70.0)], "cpu_thermal": [NS(current=48.3)]}
    r = make(tmp_path, fake_ps(sensors_temperatures=lambda: sensors)).collect()
    assert r.data.temperature_c == 48.3
    assert r.status.missing == []


def test_temperature_from_sysfs_fallback(tmp_path):
    f = tmp_path / "temp"
    f.write_text("51234\n")
    r = make(tmp_path, fake_ps(), thermal=f).collect()
    assert r.data.temperature_c == 51.234


def test_implausible_temperature_rejected(tmp_path):
    f = tmp_path / "temp"
    f.write_text("200000")  # 200 C
    r = make(tmp_path, fake_ps(), thermal=f).collect()
    assert r.data.temperature_c is None


def test_percentages_are_clamped(tmp_path):
    ps = fake_ps(cpu_percent=lambda interval=None: 100.4)
    assert make(tmp_path, ps).collect().data.cpu_percent == 100.0


def test_no_network_interfaces(tmp_path):
    r = make(tmp_path, fake_ps(net_io_counters=lambda: None)).collect()
    assert r.data.net_rx_bytes is None
    assert "net_rx_bytes" in r.status.missing


def test_failure_reports_type_only_never_message(tmp_path):
    def boom():
        raise RuntimeError("/home/secret/path")

    r = make(tmp_path, fake_ps(virtual_memory=boom)).collect()
    assert r.status.state == CollectorState.ERROR
    assert r.status.detail == "RuntimeError"
    assert r.data is None


def test_cpu_counter_primed_on_init(tmp_path):
    calls = []
    ps = fake_ps(cpu_percent=lambda interval=None: calls.append(1) or 5.0)
    make(tmp_path, ps)
    assert len(calls) == 1
