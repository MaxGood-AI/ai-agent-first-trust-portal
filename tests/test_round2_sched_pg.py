"""Scheduler behaviour on PostgreSQL.

Covered: a real leader that starts after a missed fire queues exactly one
run, and a handover after that run happened queues nothing; a lock or
statement timeout and a cancel leave the lock held, while a missing lock row
or a terminated session is lock loss; a commit whose ownership check times
out keeps ownership (the run survives a migration's table lock, and a
migration queued behind the executor's own transaction does not stall the
commit) and is checked in full at the next commit; the lock connections
carry their keepalives and timeouts; and a failing reconcile costs the
leader neither its leadership nor its other duties.
"""

import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from app.models import db
from app.models.collector_check_result import CollectorCheckResult
from app.models.collector_config import CollectorConfig
from app.models.collector_run import CollectorRun
from app.services import scheduler
from collectors.base import CheckResult
from tests.test_scheduler_redteam_pg import _start_executor, _stored, _wait_for


@pytest.fixture
def admin_conn(pg_app):
    engine = create_engine(db.engine.url, isolation_level="AUTOCOMMIT", poolclass=NullPool)
    with engine.connect() as conn:
        yield conn
    engine.dispose()


@pytest.fixture
def table_locker(pg_app):
    """A second engine whose transactions play a migration holding a table."""
    engine = create_engine(db.engine.url, poolclass=NullPool)
    yield engine
    engine.dispose()


def _daily_fire():
    fire = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(second=0, microsecond=0)
    return fire, f"{fire.minute} {fire.hour} * * *"


def _config(cron=None, created_at=None):
    config = CollectorConfig(id=str(uuid.uuid4()), name="policy", enabled=True, credential_mode="none",
                             schedule_cron=cron, created_at=created_at or datetime.now(timezone.utc))
    db.session.add(config)
    db.session.commit()
    return config.id


def _scheduled_runs(config_id):
    db.session.expire_all()
    runs = CollectorRun.query.filter_by(collector_config_id=config_id, trigger_type="scheduled").all()
    db.session.rollback()
    return runs


def _succeed(run):
    run.status = "success"
    run.finished_at = datetime.now(timezone.utc)
    db.session.commit()


# ============================================================================
# Missed fires on leader handover
# ============================================================================


def test_leader_that_starts_after_a_missed_fire_queues_and_runs_it_once(pg_app, monkeypatch):
    monkeypatch.setattr(scheduler, "DISPATCH_INTERVAL", 0.05)
    monkeypatch.setattr(scheduler, "RECONCILE_INTERVAL", 0.1)
    fire, cron = _daily_fire()
    config_id = _config(cron, fire - timedelta(days=3))
    executed = []

    def execute(run):
        executed.append(run.id)
        _succeed(run)

    with patch("app.services.collector_executor.execute_run", side_effect=execute):
        service = scheduler.SchedulerService(pg_app)
        service.start()
        try:
            assert _wait_for(lambda: executed), "the new leader did not queue the missed fire"
            time.sleep(0.6)  # several more reconciles and dispatches
        finally:
            service.stop()

    runs = _scheduled_runs(config_id)
    assert [(run.id, run.status) for run in runs] == [(executed[0], "success")]
    assert executed == [runs[0].id]


def test_handover_after_the_missed_run_happened_queues_nothing(pg_app):
    fire, cron = _daily_fire()
    config_id = _config(cron, fire - timedelta(days=3))
    old, new = scheduler.SchedulerService(pg_app), scheduler.SchedulerService(pg_app)
    try:
        assert old._try_become_leader()
        old.reconcile()
        (caught_up,) = _scheduled_runs(config_id)
        _succeed(db.session.get(CollectorRun, caught_up.id))
        assert not new._try_become_leader()

        old._step_down()  # the old leader's process goes away
        assert new._try_become_leader()
        new.reconcile()
        new.reconcile()
    finally:
        old._step_down()
        new._step_down()
    assert [run.id for run in _scheduled_runs(config_id)] == [caught_up.id]


# ============================================================================
# Ownership: timeout versus loss
# ============================================================================


@pytest.fixture
def held_lock(pg_app):
    """A running collector run and its target lock, held on a lock connection."""
    config_id = _config()
    token = str(uuid.uuid4())
    run = CollectorRun(id=str(uuid.uuid4()), collector_config_id=config_id, status="running",
                       executor_token=token, started_at=datetime.now(timezone.utc),
                       heartbeat_at=datetime.now(timezone.utc))
    db.session.add(run)
    db.session.commit()
    run_id = run.id
    db.session.remove()
    lock = scheduler.TargetLock(db.engine, scheduler.KINDS["collector"].lock_class, config_id)
    assert lock.acquire()
    pid = lock.conn.execute(text("SELECT pg_backend_pid()")).scalar()
    yield lock, run_id, token, pid
    lock.release()


def test_ownership_lock_timeout_keeps_the_lock(held_lock, table_locker):
    lock, run_id, token, _ = held_lock
    with table_locker.connect() as conn:
        conn.execute(text("LOCK TABLE collector_run IN ACCESS EXCLUSIVE MODE"))
        started = time.monotonic()
        with pytest.raises(scheduler.OwnershipUnknown) as timeout:
            lock.ownership("collector_run", run_id, token)
        assert time.monotonic() - started < 5
        assert timeout.value.sqlstate == "55P03"
        assert lock.holds() is True
        conn.rollback()
    assert lock.ownership("collector_run", run_id, token) == (True, "running")


def test_ownership_statement_cancel_keeps_the_lock(held_lock, table_locker, admin_conn):
    lock, run_id, token, pid = held_lock
    lock.conn.execute(text("SET lock_timeout = 0"))  # wait until cancelled
    outcome = {}

    def check():
        try:
            outcome["result"] = lock.ownership("collector_run", run_id, token)
        except Exception as exc:  # noqa: BLE001 - asserted below
            outcome["error"] = exc

    with table_locker.connect() as conn:
        conn.execute(text("LOCK TABLE collector_run IN ACCESS EXCLUSIVE MODE"))
        thread = threading.Thread(target=check, daemon=True)
        thread.start()
        assert _wait_for(lambda: admin_conn.execute(text(
            "SELECT wait_event_type FROM pg_stat_activity WHERE pid = :pid"), {"pid": pid}).scalar() == "Lock")
        admin_conn.execute(text("SELECT pg_cancel_backend(:pid)"), {"pid": pid})
        thread.join(10)
        conn.rollback()
    assert isinstance(outcome.get("error"), scheduler.OwnershipUnknown)
    assert outcome["error"].sqlstate == "57014"
    assert lock.ownership("collector_run", run_id, token) == (True, "running")


def test_missing_lock_row_is_lock_loss(held_lock):
    lock, run_id, token, _ = held_lock
    lock.conn.execute(text("SELECT pg_advisory_unlock(:a, :b)"), lock.keys)
    assert lock.ownership("collector_run", run_id, token) == (False, "running")
    guard = scheduler.RunGuard(scheduler.KINDS["collector"], run_id, token, lock, db.session())
    with pytest.raises(scheduler.LockLostError, match="lost its target lock"):
        guard.verify()


def test_terminated_lock_session_is_lock_loss(held_lock, admin_conn):
    lock, run_id, token, pid = held_lock
    admin_conn.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid})
    assert _wait_for(lambda: not admin_conn.execute(text(
        "SELECT count(*) FROM pg_stat_activity WHERE pid = :pid"), {"pid": pid}).scalar())
    with pytest.raises(scheduler.LockLostError):
        lock.ownership("collector_run", run_id, token)
    with pytest.raises(scheduler.LockLostError):
        lock.heartbeat("collector_run", run_id, token)
    guard = scheduler.RunGuard(scheduler.KINDS["collector"], run_id, token, lock, db.session())
    with pytest.raises(scheduler.LockLostError, match="lost its target lock"):
        guard.verify()


def _collect_under_table_lock(pg_app, admin_conn, table_locker, hold_seconds):
    """Run a real collector run whose check result is committed while another
    transaction (a migration) holds ``collector_run`` for ``hold_seconds``,
    after the run's heartbeat has beaten at least once."""
    config_id = _config()
    run, _ = scheduler.enqueue_collector_run(db.session.get(CollectorConfig, config_id), "manual")
    run_id = run.id
    db.session.remove()
    collecting, release = threading.Event(), threading.Event()

    class GatedCollector:
        def __init__(self, config, resolver):
            self.config = config

        def run(self):
            collecting.set()
            release.wait(30)
            return [CheckResult(check_name="probe", status="pass", message="ok")]

    def heartbeat_at():
        return admin_conn.execute(text("SELECT heartbeat_at FROM collector_run WHERE id = :id"),
                                  {"id": run_id}).scalar()

    outcomes = {}
    with patch("app.services.collector_executor.get_collector_class", return_value=GatedCollector):
        thread = _start_executor(pg_app, "collector", run_id, outcomes)
        try:
            assert collecting.wait(10)
            first_beat = heartbeat_at()
            assert _wait_for(lambda: heartbeat_at() > first_beat), "heartbeat did not advance"
            with table_locker.connect() as conn:
                conn.execute(text("SET lock_timeout = '5s'"))
                conn.execute(text("LOCK TABLE collector_run IN ACCESS EXCLUSIVE MODE"))
                release.set()
                time.sleep(hold_seconds)
                conn.rollback()
        finally:
            release.set()
            thread.join(30)
    return run_id, outcomes


def test_commit_waits_out_a_table_lock_instead_of_dropping_the_run(
        pg_app, admin_conn, table_locker, monkeypatch, caplog):
    monkeypatch.setattr(scheduler, "HEARTBEAT_INTERVAL", 0.05)
    run_id, outcomes = _collect_under_table_lock(pg_app, admin_conn, table_locker, 1.5)

    assert outcomes[run_id] == "executed"
    final = _stored(CollectorRun, run_id)
    assert (final.status, final.check_pass_count, final.error_message) == ("success", 1, None)
    assert CollectorCheckResult.query.filter_by(collector_run_id=run_id).count() == 1
    assert "ownership check did not answer" in caplog.text


def test_commit_is_not_held_up_by_a_migration_waiting_for_its_own_transaction(
        held_lock, table_locker, admin_conn):
    """The executor's transaction holds the run table and a migration queues
    behind it; the ownership check queues behind the migration. The commit
    must go through (releasing the table) instead of waiting in that cycle."""
    lock, run_id, token, _ = held_lock
    guard = scheduler.RunGuard(scheduler.KINDS["collector"], run_id, token, lock, db.session())
    guard.start()
    migration = {}

    def migrate():
        with table_locker.connect() as conn:
            conn.execute(text("SET lock_timeout = '20s'"))
            started = time.monotonic()
            conn.execute(text("LOCK TABLE collector_run IN ACCESS EXCLUSIVE MODE"))
            migration["waited"] = time.monotonic() - started
            conn.rollback()

    try:
        db.session.execute(text("UPDATE collector_run SET check_pass_count = 1 WHERE id = :id"), {"id": run_id})
        thread = threading.Thread(target=migrate, daemon=True)
        thread.start()
        assert _wait_for(lambda: admin_conn.execute(text(
            "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
            "AND query LIKE 'LOCK TABLE collector_run%'")).scalar() == 1)
        started = time.monotonic()
        db.session.commit()
        committed_in = time.monotonic() - started
        thread.join(30)
    finally:
        guard.close()
    assert committed_in < 5
    assert migration["waited"] < 10
    assert guard.lost_reason is None
    assert _stored(CollectorRun, run_id).check_pass_count == 1


def _verify_within(guard, seconds):
    """``guard.verify()`` in a thread: {"ok": True}, {"error": exc}, or {} while it still waits."""
    outcome = {}

    def target():
        try:
            guard.verify()
            outcome["ok"] = True
        except Exception as exc:  # noqa: BLE001 - reported to the caller
            outcome["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(seconds)
    return outcome


def test_timed_out_check_keeps_ownership_and_checks_again_at_the_next_commit(
        held_lock, table_locker, admin_conn):
    lock, run_id, token, _ = held_lock
    guard = scheduler.RunGuard(scheduler.KINDS["collector"], run_id, token, lock, db.session())
    with table_locker.connect() as conn:
        conn.execute(text("LOCK TABLE collector_run IN ACCESS EXCLUSIVE MODE"))
        outcome = _verify_within(guard, 5)  # the run table does not answer; the lock is held
        conn.rollback()
    assert outcome == {"ok": True}
    assert guard.lost_reason is None

    admin_conn.execute(text("UPDATE collector_run SET status = 'failure' WHERE id = :id"), {"id": run_id})
    with pytest.raises(scheduler.LockLostError, match="no longer running"):
        guard.verify()


def test_timed_out_check_still_catches_a_missing_lock_row(held_lock, table_locker):
    lock, run_id, token, _ = held_lock
    lock.conn.execute(text("SELECT pg_advisory_unlock(:a, :b)"), lock.keys)
    guard = scheduler.RunGuard(scheduler.KINDS["collector"], run_id, token, lock, db.session())
    with table_locker.connect() as conn:
        conn.execute(text("LOCK TABLE collector_run IN ACCESS EXCLUSIVE MODE"))
        outcome = _verify_within(guard, 5)
        conn.rollback()
    assert isinstance(outcome.get("error"), scheduler.LockLostError)
    assert "lost its target lock" in str(outcome["error"])


# ============================================================================
# Lock connections
# ============================================================================


def test_lock_connections_carry_keepalives_and_timeouts(pg_app):
    conn = scheduler.lock_connection(db.engine)
    try:
        dsn = conn.connection.dbapi_connection.get_dsn_parameters()
        assert {name: dsn.get(name) for name in (
            "connect_timeout", "keepalives", "keepalives_idle", "keepalives_interval",
            "keepalives_count", "tcp_user_timeout")} == {
            "connect_timeout": "10", "keepalives": "1", "keepalives_idle": "30",
            "keepalives_interval": "10", "keepalives_count": "3", "tcp_user_timeout": "30000"}
        settings = dict(conn.execute(text(
            "SELECT name, setting FROM pg_settings WHERE name IN ('lock_timeout', "
            "'tcp_keepalives_idle', 'tcp_keepalives_interval', 'tcp_keepalives_count')")).all())
        assert settings == {"lock_timeout": "500", "tcp_keepalives_idle": "30",
                            "tcp_keepalives_interval": "10", "tcp_keepalives_count": "3"}
        assert conn.execute(text("SELECT inet_client_addr() IS NOT NULL")).scalar(), "expects a TCP session"
    finally:
        conn.close()


# ============================================================================
# A failing duty keeps the leader
# ============================================================================


def test_a_failing_reconcile_costs_neither_leadership_nor_the_other_duties(pg_app, monkeypatch):
    monkeypatch.setattr(scheduler, "DISPATCH_INTERVAL", 0.05)
    monkeypatch.setattr(scheduler, "ELECTION_INTERVAL", 0.05)
    monkeypatch.setattr(scheduler, "RECONCILE_INTERVAL", 0.1)
    acquisitions, ticks = [], []
    real_start = scheduler.SchedulerService._start_leader_duties

    def counting_start(self):
        acquisitions.append(1)
        real_start(self)

    def bad_row():
        raise ValueError("a schedule row the scheduler cannot read")

    monkeypatch.setattr(scheduler.SchedulerService, "_start_leader_duties", counting_start)
    monkeypatch.setattr(scheduler, "desired_schedules", bad_row)
    config_id = _config()
    run, _ = scheduler.enqueue_collector_run(db.session.get(CollectorConfig, config_id), "manual")
    run_id = run.id
    db.session.remove()
    scheduler.register_periodic("probe_ticks", 0.05, lambda app: ticks.append(1))
    service = scheduler.SchedulerService(pg_app)
    try:
        with patch("app.services.collector_executor.execute_run", side_effect=_succeed):
            service.start()
            assert _wait_for(lambda: len(ticks) >= 3), "periodic tasks stopped"
            assert _wait_for(lambda: _stored(CollectorRun, run_id).status == "success"), "dispatch stopped"
            time.sleep(0.5)
            assert service.is_leader
    finally:
        service.stop()
        scheduler.unregister_periodic("probe_ticks")
    assert len(acquisitions) == 1
