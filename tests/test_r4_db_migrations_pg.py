"""Migrations next to a running release (red-team verification 2, M3).

A migration takes ACCESS EXCLUSIVE only on the tables its pending revisions
alter, in the portal's writer order, and the audit chain lock last and only
when a revision writes audited rows. It requests every lock without waiting,
so the old release's transactions complete (or wait a few milliseconds) and
never deadlock, and an open read transaction does not stall writers behind
a waiting migration.
"""

import threading
import time

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from cli import db_cmd

CHAIN_LOCK_KEY = 815000001


def _upgrade(url, revision):
    cfg = Config(f"{db_cmd.ROOT}/alembic.ini")
    cfg.set_main_option("script_location", f"{db_cmd.ROOT}/migrations")
    cfg.attributes["configure_logging"] = False
    cfg.attributes["url_override"] = url
    command.upgrade(cfg, revision)


def _seed(url):
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO controls (id, name, category) VALUES ('c1', 'C', 'security')"))
        conn.execute(text(
            "INSERT INTO team_members (id, name, email, role, is_active, is_compliance_admin) "
            "VALUES ('tm1', 'Member', 'member@example.com', 'human', true, false)"))
    engine.dispose()


def _revision(url):
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    finally:
        engine.dispose()


class _Probe:
    """Autocommit statements every 20 ms on a second connection, recording latency."""

    def __init__(self, url, sql):
        self.url, self.sql = url, sql
        self.latencies, self.errors = [], []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        engine = create_engine(self.url, isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            while not self._stop.is_set():
                started = time.monotonic()
                try:
                    conn.execute(text(self.sql), {"v": f"probe {started}"})
                except Exception as exc:  # noqa: BLE001 - recorded and asserted on
                    self.errors.append(str(exc).splitlines()[0])
                self.latencies.append(time.monotonic() - started)
                time.sleep(0.02)
        engine.dispose()

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(10)


def _old_release_transaction(url, steps, outcome, started):
    """An old-release transaction: each step is (sql, pause_after_seconds)."""
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            for index, (sql, pause) in enumerate(steps):
                began = time.monotonic()
                conn.execute(text(sql))
                outcome.setdefault("durations", []).append(time.monotonic() - began)
                if index == 0:
                    started.set()
                time.sleep(pause)
            conn.commit()
            outcome["committed"] = True
    except Exception as exc:  # noqa: BLE001 - asserted on by the test
        outcome["error"] = str(exc).splitlines()[0]
        started.set()
    finally:
        engine.dispose()


OLD_RELEASE_TRANSACTIONS = {
    # The red team's inversion: a plain read of a table the migration alters,
    # then an audited write of a table it does not alter.
    "read_then_audited_write": [
        ("SELECT count(*) FROM collector_run", 1.5),
        ("UPDATE controls SET name = 'old release edit' WHERE id = 'c1'", 0.0),
    ],
    # The same, with the audited write on a table the migration also alters.
    "read_then_write_of_an_altered_table": [
        ("SELECT count(*) FROM collector_run", 1.5),
        ("UPDATE team_members SET name = 'old release edit' WHERE id = 'tm1'", 0.0),
    ],
    # The other order: the chain lock (an audited write) first, then a read of
    # a table the migration alters.
    "audited_write_then_read": [
        ("UPDATE controls SET name = 'old release edit' WHERE id = 'c1'", 1.5),
        ("SELECT count(*) FROM collector_run", 0.0),
    ],
}


@pytest.mark.parametrize("scenario", sorted(OLD_RELEASE_TRANSACTIONS))
def test_m3_old_release_transaction_during_migration_never_deadlocks(pg_url, scenario):
    """017 -> head alters team_members, collector_run, ... and writes audited
    rows; the old release's transaction must commit, waiting at most briefly."""
    _upgrade(pg_url, "017")
    _seed(pg_url)
    outcome, started = {}, threading.Event()
    worker = threading.Thread(target=_old_release_transaction,
                              args=(pg_url, OLD_RELEASE_TRANSACTIONS[scenario], outcome, started))
    worker.start()
    assert started.wait(10)
    time.sleep(0.2)
    result = db_cmd.run_migrations(pg_url)
    worker.join(30)
    assert "error" not in outcome, outcome
    assert outcome.get("committed") is True
    assert max(outcome["durations"]) < 1.0, outcome
    assert result == "upgraded" and _revision(pg_url) == db_cmd.code_revisions()[0]


def test_m3_open_audit_log_read_neither_blocks_the_migration_nor_stalls_writers(pg_url, monkeypatch):
    """An auditor's open transaction on audit_log: 018 -> head alters neither
    audit_log nor writes audited rows, so it takes neither lock."""
    _upgrade(pg_url, "018")
    _seed(pg_url)
    monkeypatch.setattr(db_cmd, "MIGRATION_LOCK_TIMEOUT", "1s")
    monkeypatch.setattr(db_cmd, "MIGRATION_ATTEMPTS", 2)
    monkeypatch.setattr(db_cmd, "RETRY_DELAY_SECONDS", 0.2)
    reader = create_engine(pg_url)
    sleeps = []
    try:
        with reader.connect() as held:
            held.execute(text("SELECT count(*) FROM audit_log"))  # ACCESS SHARE until rollback
            with _Probe(pg_url, "UPDATE controls SET name = :v WHERE id = 'c1'") as probe:
                began = time.monotonic()
                result = db_cmd.run_migrations(pg_url, sleep=sleeps.append)
                elapsed = time.monotonic() - began
                time.sleep(0.2)
            held.rollback()
    finally:
        reader.dispose()
    assert result == "upgraded" and sleeps == [] and elapsed < 5
    assert probe.errors == [] and max(probe.latencies) < 0.5, max(probe.latencies)


def test_m3_open_read_on_an_altered_table_gives_bounded_writer_delay(pg_url, monkeypatch):
    """An open read of a table the migration alters (019 alters team_members):
    the migration gives up after its bounded attempts, and writers of that
    table are never queued behind a waiting lock request."""
    _upgrade(pg_url, "018")
    _seed(pg_url)
    monkeypatch.setattr(db_cmd, "MIGRATION_LOCK_TIMEOUT", "1s")
    monkeypatch.setattr(db_cmd, "MIGRATION_ATTEMPTS", 3)
    monkeypatch.setattr(db_cmd, "RETRY_DELAY_SECONDS", 0.2)
    reader = create_engine(pg_url)
    try:
        with reader.connect() as held:
            held.execute(text("SELECT count(*) FROM team_members"))
            with _Probe(pg_url, "UPDATE team_members SET name = :v WHERE id = 'tm1'") as writes, \
                    _Probe(pg_url, "SELECT count(*) FROM team_members WHERE name <> :v") as reads:
                began = time.monotonic()
                with pytest.raises(Exception) as excinfo:
                    db_cmd.run_migrations(pg_url, sleep=time.sleep)
                elapsed = time.monotonic() - began
            held.rollback()
    finally:
        reader.dispose()
    assert "lock timeout" in str(excinfo.value) and "team_members" in str(excinfo.value)
    assert elapsed < 8
    for probe in (writes, reads):
        assert probe.errors == []
        assert max(probe.latencies) < 0.3, max(probe.latencies)
        assert sum(latency for latency in probe.latencies if latency > 0.05) < 0.5
    assert _revision(pg_url) == "018"


def test_m3_chain_lock_is_taken_only_for_revisions_that_write_audited_rows(pg_url, monkeypatch):
    monkeypatch.setattr(db_cmd, "MIGRATION_LOCK_TIMEOUT", "500ms")
    monkeypatch.setattr(db_cmd, "MIGRATION_ATTEMPTS", 2)
    monkeypatch.setattr(db_cmd, "RETRY_DELAY_SECONDS", 0.1)
    _upgrade(pg_url, "017")
    holder = create_engine(pg_url)
    try:
        with holder.connect() as conn:
            conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": CHAIN_LOCK_KEY})
            conn.commit()
            # 018 closes interrupted collector runs (audited writes): it needs the chain lock.
            with pytest.raises(Exception) as excinfo:
                db_cmd.run_migrations(pg_url, sleep=time.sleep)
            assert "audit chain lock" in str(excinfo.value)
            assert _revision(pg_url) == "017"
            conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": CHAIN_LOCK_KEY})
            _upgrade(pg_url, "018")
            conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": CHAIN_LOCK_KEY})
            conn.commit()
            # 019 and later write no audited rows: the held chain lock does not matter.
            assert db_cmd.run_migrations(pg_url, sleep=time.sleep) == "upgraded"
            conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": CHAIN_LOCK_KEY})
            conn.commit()
    finally:
        holder.dispose()
    assert _revision(pg_url) == db_cmd.code_revisions()[0]
