from datetime import UTC, datetime

import pytest

from sentinelpi.storage.db import Database

NOW = datetime(2026, 9, 28, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "data" / "test.db")
    database.migrate()
    return database


@pytest.fixture
def conn(db):
    with db.session() as c:
        yield c
