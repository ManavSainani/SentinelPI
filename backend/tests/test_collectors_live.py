"""Smoke test against the real host. Passes on any OS; asserts shape, not values."""

import json

from sentinelpi.collectors import HostCollectors
from sentinelpi.collectors.base import CollectorState
from sentinelpi.config import Settings, load_settings


def test_live_collection_never_crashes_and_is_json_safe():
    t = HostCollectors().collect_all()
    for result in (t.metrics, t.processes, t.ports):
        assert result.status.state in set(CollectorState)
        if result.status.state in {CollectorState.OK, CollectorState.DEGRADED}:
            assert result.data is not None
    json.loads(t.model_dump_json())
    assert t.metrics.data is not None and t.processes.data is not None


def test_collection_settings_bounds(tmp_path):
    import pytest
    from pydantic import ValidationError

    assert Settings().collection.process_limit == 50
    f = tmp_path / "c.toml"
    f.write_text("[collection]\nprocess_limit = 100000\n")
    with pytest.raises(ValidationError):
        load_settings(f)
