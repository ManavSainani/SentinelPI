from datetime import timedelta

import pytest

from sentinelpi.config import CpuRule as Cfg
from sentinelpi.config import ScoringSettings
from sentinelpi.detection.rules.cpu import CpuRule
from sentinelpi.events import EventSource, Severity
from sentinelpi.storage import telemetry_repo
from tests.conftest import NOW
from tests.helpers_detection import cpu_series, metric


def rule(**kw):
    return CpuRule(Cfg(**kw), ScoringSettings())


def run(conn, samples, r=None):
    telemetry_repo.insert_metrics_many(conn, samples)
    return (r or rule()).evaluate(conn, NOW)


def test_positive_sustained_for_the_whole_window(conn):
    res = run(conn, cpu_series(NOW, 95.0))
    assert res.skipped_reason is None and len(res.detections) == 1
    d = res.detections[0]
    e = d.event
    assert d.dedupe_key == "SP-003:cpu" and e.severity == Severity.LOW
    assert e.source == EventSource.SYSTEM_METRICS and e.event_type == "detection.sustained_high_cpu"
    assert e.metadata["samples"] == 31 and e.metadata["cpu_avg"] == 95.0
    assert e.metadata["risk_points"] == 10 and "90% for 5 minutes" in e.metadata["trigger"]


def test_very_high_average_raises_severity_to_medium(conn):
    assert run(conn, cpu_series(NOW, 99.0)).detections[0].event.severity == Severity.MEDIUM


def test_negative_cpu_below_threshold(conn):
    assert run(conn, cpu_series(NOW, 60.0)).detections == []


def test_boundary_exactly_at_threshold_is_not_above(conn):
    res = run(conn, cpu_series(NOW, 90.0))
    assert res.detections == [] and res.skipped_reason is None  # judged, not skipped


def test_boundary_just_above_threshold_triggers(conn):
    assert len(run(conn, cpu_series(NOW, 90.1)).detections) == 1


def test_one_dip_inside_the_window_prevents_the_alert(conn):
    samples = cpu_series(NOW, 95.0)
    samples[15] = metric(samples[15].timestamp, 40.0)
    assert run(conn, samples).detections == []


def test_old_spike_before_the_window_does_not_matter(conn):
    samples = [metric(NOW - timedelta(seconds=301), 5.0)] + cpu_series(NOW, 95.0)
    assert len(run(conn, samples).detections) == 1


def test_high_cpu_only_in_the_last_minute_is_not_sustained(conn):
    samples = cpu_series(NOW, 20.0)
    for i in range(-6, 0):
        samples[i] = metric(samples[i].timestamp, 99.0)
    assert run(conn, samples).detections == []


def test_too_few_samples_is_skipped_not_guessed(conn):
    res = run(conn, cpu_series(NOW, 95.0, step=60))  # only 6 samples
    assert "only 6 samples" in res.skipped_reason and res.detections == []


def test_gap_in_the_middle_means_the_window_is_not_covered(conn):
    res = run(conn, cpu_series(NOW, 95.0, skip=range(10, 20)))  # 100 s hole
    assert "do not cover" in res.skipped_reason


def test_window_start_not_covered(conn):
    samples = [s for s in cpu_series(NOW, 95.0) if s.timestamp >= NOW - timedelta(seconds=200)]
    assert "do not cover" in run(conn, samples, rule(min_samples=5)).skipped_reason


def test_stale_latest_sample_is_not_covered(conn):
    # window start is covered, but the newest sample is 120 s old (> 60 s max gap)
    samples = [
        s
        for s in cpu_series(NOW - timedelta(seconds=120), 95.0)
        if s.timestamp >= NOW - timedelta(seconds=300)
    ]
    assert samples[0].timestamp == NOW - timedelta(seconds=300)
    res = run(conn, samples)
    assert "do not cover" in res.skipped_reason and res.detections == []


def test_newest_sample_within_the_gap_tolerance_still_counts(conn):
    # control for the test above: same data but the newest sample is only 50 s old
    samples = [
        s
        for s in cpu_series(NOW - timedelta(seconds=50), 95.0)
        if s.timestamp >= NOW - timedelta(seconds=300)
    ]
    samples.insert(0, metric(NOW - timedelta(seconds=300), 95.0))
    assert len(run(conn, samples).detections) == 1


def test_configurable_threshold_and_window(conn):
    assert (
        len(
            run(
                conn, cpu_series(NOW, 60.0, seconds=120), rule(cpu_percent=50, window_minutes=2)
            ).detections
        )
        == 1
    )


@pytest.mark.parametrize(
    "bad",
    [
        {"cpu_percent": 100},
        {"cpu_percent": 0},
        {"min_samples": 1},
        {"high_cpu_percent": 80, "cpu_percent": 90},
    ],
)
def test_invalid_config_rejected(bad):
    with pytest.raises(ValueError):
        Cfg(**bad)
