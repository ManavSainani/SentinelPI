from datetime import timedelta

from sentinelpi.events import EventSource
from sentinelpi.synthetic import generate_events, generate_metrics
from tests.conftest import NOW

DOC_PREFIXES = ("203.0.113.", "198.51.100.", "192.0.2.")


def test_same_seed_is_identical_including_ids():
    a = [e.model_dump() for e in generate_events(50, start=NOW, seed=7)]
    b = [e.model_dump() for e in generate_events(50, start=NOW, seed=7)]
    assert a == b


def test_different_seed_differs():
    a = generate_events(50, start=NOW, seed=1)
    b = generate_events(50, start=NOW, seed=2)
    assert [e.id for e in a] != [e.id for e in b]


def test_events_are_clearly_marked_and_safe():
    events = generate_events(200, start=NOW)
    assert len(events) == 200 and len({e.id for e in events}) == 200
    assert all(e.source == EventSource.TEST for e in events)
    assert all(e.source_ip.startswith(DOC_PREFIXES) for e in events if e.source_ip)
    assert events[1].timestamp - events[0].timestamp == timedelta(seconds=30)
    assert {e.event_type for e in events} >= {"auth.ssh_failed_login", "network.new_listening_port"}


def test_metrics_are_bounded_deterministic_and_monotonic_counters():
    a = generate_metrics(300, start=NOW, seed=3)
    assert a == generate_metrics(300, start=NOW, seed=3)
    assert all(0 <= s.cpu_percent <= 100 for s in a)
    assert all(a[i].net_rx_bytes < a[i + 1].net_rx_bytes for i in range(len(a) - 1))
