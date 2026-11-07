def test_a_connection_can_finish_its_work_in_another_thread(tmp_path):
    """FastAPI opens a request's connection in one worker thread and may use and close it in
    another; this used to fail at random with ProgrammingError (seen live on the first run)."""
    import threading

    from sentinelpi.storage.db import connect

    conn = connect(tmp_path / "t.db")
    result: list[object] = []

    def work() -> None:
        try:
            result.append(conn.execute("SELECT 1").fetchone()[0])
            conn.close()
        except Exception as exc:  # noqa: BLE001
            result.append(exc)

    t = threading.Thread(target=work)
    t.start()
    t.join()
    assert result == [1]
