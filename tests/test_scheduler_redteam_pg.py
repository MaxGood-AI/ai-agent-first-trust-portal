"""Scheduler safety under lock loss and long collector runs (PostgreSQL).

The executor runs in worker threads against a real database (``pg_app``).
A second, autocommit connection plays the database administrator: it ends
the session that holds a run's target lock (``pg_terminate_backend``), ages
heartbeats, and inspects ``pg_locks`` / ``pg_stat_activity``.

Covered:

- the reaper spares a ``running`` run whose heartbeat is fresh, even when
  its target lock is free, and closes it once the heartbeat is stale;
- claiming a run stamps an executor token and a heartbeat, and the heartbeat
  advances while the executor holds the lock;
- an executor that lost its lock records nothing: its commits are refused,
  its late completion cannot overwrite the reaper's status, and at most one
  session ever holds a target's lock;
- a collector run keeps no transaction open while the collector works, so
  DDL on ``collector_config`` is not blocked.
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
from app.models.git_source import GitSource
from app.services import scheduler
from collectors.base import CheckResult


@pytest.fixture
def admin_conn(pg_app):
    engine = create_engine(db.engine.url, isolation_level="AUTOCOMMIT", poolclass=NullPool)
    with engine.connect() as conn:
        yield conn
    engine.dispose()


def _wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _new_target(kind_name):
    if kind_name == "collector":
        target = CollectorConfig(id=str(uuid.uuid4()), name="policy", enabled=True, credential_mode="none")
    else:
        target = GitSource(id=str(uuid.uuid4()), name="gov", role="governance", provider="local",
                           repository="/tmp", branch="main", credential_mode="none", enabled=True)
    db.session.add(target)
    db.session.commit()
    return target


def _enqueue(kind_name, target):
    if kind_name == "collector":
        return scheduler.enqueue_collector_run(target, "manual")
    return scheduler.enqueue_git_sync(target, "manual")


def _lock_holders(conn, kind_name, target_id):
    kind = scheduler.KINDS[kind_name]
    return conn.execute(text(
        "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted AND classid::bigint = :a "
        "AND objid::bigint = :b AND objsubid = 2"),
        {"a": kind.lock_class, "b": scheduler.target_lock_key(target_id) & 0xFFFFFFFF}).scalars().all()


def _end_lock_session(conn, kind_name, target_id):
    """Terminate the database session holding the target lock (failover, admin kill, network drop)."""
    holders = _lock_holders(conn, kind_name, target_id)
    assert len(holders) == 1
    conn.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": holders[0]})
    assert _wait_for(lambda: not _lock_holders(conn, kind_name, target_id))


def _age(conn, table, run_id, *, started=True, heartbeat=True):
    sets = []
    if started:
        sets.append("started_at = now() - interval '30 minutes'")
    if heartbeat:
        sets.append("heartbeat_at = now() - interval '30 minutes'")
    conn.execute(text(f"UPDATE {table} SET {', '.join(sets)} WHERE id = :id"), {"id": run_id})


def _stored(model, row_id):
    """The committed row, detached, without leaving a transaction open."""
    db.session.expire_all()
    stored = db.session.get(model, row_id)
    db.session.expunge(stored)
    db.session.rollback()
    return stored


class BlockingExecutions:
    """Stands in for the job body: blocks until released, then records a
    result and ``success`` through the ORM the way a real job does."""

    def __init__(self, kind_name):
        self.kind_name = kind_name
        self.model = scheduler.KINDS[kind_name].model()
        self.started = []
        self.release = {}
        self.commit_errors = {}
        self._guard = threading.Lock()

    def gate(self, run_id):
        with self._guard:
            return self.release.setdefault(run_id, threading.Event())

    def __call__(self, run_or_id):
        run_id = getattr(run_or_id, "id", run_or_id)
        with self._guard:
            self.started.append(run_id)
        self.gate(run_id).wait(30)
        run = db.session.get(self.model, run_id)
        if self.kind_name == "collector":
            db.session.add(CollectorCheckResult(id=str(uuid.uuid4()), collector_run_id=run_id,
                                                check_name="probe", status="pass"))
            run.check_pass_count = 1
        else:
            run.files_changed = 1
        run.status = "success"
        run.finished_at = datetime.now(timezone.utc)
        try:
            db.session.commit()
        except Exception as exc:
            self.commit_errors[run_id] = exc
            raise

    def patch(self):
        if self.kind_name == "collector":
            return patch("app.services.collector_executor.execute_run", side_effect=self)
        return patch("app.services.git_sources.sync.execute_sync_run", side_effect=self)


def _start_executor(app, kind_name, run_id, outcomes):
    def target():
        with app.app_context():
            try:
                outcomes[run_id] = scheduler.execute_claimed(kind_name, run_id)
            except Exception as exc:  # noqa: BLE001 - reported through outcomes
                outcomes[run_id] = f"raised {type(exc).__name__}: {exc}"
            finally:
                db.session.remove()

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread


# ============================================================================
# Reaper: heartbeat AND free lock
# ============================================================================


def test_reaper_spares_fresh_heartbeat_even_when_lock_is_free(pg_app, admin_conn):
    config = _new_target("collector")
    run = CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id, status="running",
                       started_at=datetime.now(timezone.utc) - timedelta(minutes=30),
                       heartbeat_at=datetime.now(timezone.utc), executor_token=str(uuid.uuid4()))
    db.session.add(run)
    db.session.commit()
    run_id = run.id
    assert not _lock_holders(admin_conn, "collector", config.id)

    assert scheduler.reap_once() == 0
    assert _stored(CollectorRun, run_id).status == "running"

    _age(admin_conn, "collector_run", run_id, started=False)
    assert scheduler.reap_once() == 1
    reaped = _stored(CollectorRun, run_id)
    assert reaped.status == "failure"
    assert reaped.error_message == scheduler.REAPED_MESSAGE


def test_claim_stamps_token_and_heartbeat_advances_while_lock_is_held(pg_app, admin_conn, monkeypatch):
    monkeypatch.setattr(scheduler, "HEARTBEAT_INTERVAL", 0.05)
    config = _new_target("collector")
    run, _ = _enqueue("collector", config)
    run_id, config_id = run.id, config.id
    db.session.remove()
    executions = BlockingExecutions("collector")
    outcomes = {}

    def heartbeat():
        return admin_conn.execute(text("SELECT executor_token, heartbeat_at FROM collector_run "
                                       "WHERE id = :id"), {"id": run_id}).one()

    with executions.patch():
        thread = _start_executor(pg_app, "collector", run_id, outcomes)
        assert _wait_for(lambda: run_id in executions.started)
        token, first_beat = heartbeat()
        assert token is not None and len(token) == 36
        assert first_beat is not None
        assert _wait_for(lambda: heartbeat()[1] > first_beat), "heartbeat did not advance"
        assert len(_lock_holders(admin_conn, "collector", config_id)) == 1
        executions.gate(run_id).set()
        thread.join(30)

    assert outcomes[run_id] == "executed"
    assert _stored(CollectorRun, run_id).status == "success"
    assert not _lock_holders(admin_conn, "collector", config_id)


def test_blocked_heartbeat_times_out_without_losing_ownership(pg_app, admin_conn, monkeypatch, caplog):
    monkeypatch.setattr(scheduler, "HEARTBEAT_INTERVAL", 0.05)
    config = _new_target("collector")
    run, _ = _enqueue("collector", config)
    run_id = run.id
    db.session.remove()
    executions = BlockingExecutions("collector")
    outcomes = {}
    row_locker = create_engine(db.engine.url, poolclass=NullPool)

    def heartbeat_at():
        return admin_conn.execute(text("SELECT heartbeat_at FROM collector_run WHERE id = :id"),
                                  {"id": run_id}).scalar()

    with executions.patch():
        thread = _start_executor(pg_app, "collector", run_id, outcomes)
        assert _wait_for(lambda: run_id in executions.started)
        with row_locker.connect() as conn:
            conn.execute(text("SELECT id FROM collector_run WHERE id = :id FOR UPDATE"), {"id": run_id})
            held_from = heartbeat_at()
            time.sleep(1.5)  # several heartbeats wait for the row and give up
            assert heartbeat_at() == held_from
            conn.rollback()
        assert _wait_for(lambda: heartbeat_at() > held_from), "heartbeat did not resume"
        executions.gate(run_id).set()
        thread.join(30)
    row_locker.dispose()

    assert "heartbeat skipped (OperationalError)" in caplog.text
    assert run_id not in executions.commit_errors
    assert _stored(CollectorRun, run_id).status == "success"


# ============================================================================
# Lock loss
# ============================================================================


def test_lock_loss_with_fresh_heartbeat_is_not_reaped_and_records_nothing(pg_app, admin_conn):
    config = _new_target("collector")
    run1, _ = _enqueue("collector", config)
    run1_id, config_id = run1.id, config.id
    db.session.remove()
    executions = BlockingExecutions("collector")
    outcomes = {}

    with executions.patch():
        thread = _start_executor(pg_app, "collector", run1_id, outcomes)
        assert _wait_for(lambda: run1_id in executions.started)

        _end_lock_session(admin_conn, "collector", config_id)
        # A long run: started long ago, heartbeat still fresh.
        _age(admin_conn, "collector_run", run1_id, heartbeat=False)

        assert scheduler.reap_once() == 0
        assert _stored(CollectorRun, run1_id).status == "running"
        again, created = _enqueue("collector", db.session.get(CollectorConfig, config_id))
        assert (again.id, created) == (run1_id, False)
        assert scheduler.dispatch_once() == 0
        db.session.remove()

        executions.gate(run1_id).set()
        thread.join(30)

    assert outcomes[run1_id] == "executed"
    assert isinstance(executions.commit_errors[run1_id], scheduler.LockLostError)
    final = _stored(CollectorRun, run1_id)
    assert final.status == "failure"
    assert final.error_message.startswith("Interrupted: the executor lost its target lock")
    assert CollectorCheckResult.query.filter_by(collector_run_id=run1_id).count() == 0
    assert executions.started == [run1_id]
    # The target is free again for the next run.
    _, created = _enqueue("collector", db.session.get(CollectorConfig, config_id))
    assert created is True


@pytest.mark.parametrize("kind_name", ["collector", "git_sync"])
def test_stale_run_is_reaped_and_late_completion_cannot_overwrite(pg_app, admin_conn, kind_name):
    kind = scheduler.KINDS[kind_name]
    model = kind.model()
    target = _new_target(kind_name)
    target_id = target.id
    run1, _ = _enqueue(kind_name, target)
    run1_id = run1.id
    db.session.remove()
    executions = BlockingExecutions(kind_name)
    outcomes = {}

    with executions.patch():
        thread1 = _start_executor(pg_app, kind_name, run1_id, outcomes)
        assert _wait_for(lambda: run1_id in executions.started)

        _end_lock_session(admin_conn, kind_name, target_id)
        _age(admin_conn, kind.table, run1_id)

        assert scheduler.reap_once() == 1
        reaped = _stored(model, run1_id)
        assert reaped.status == "failure"
        assert reaped.error_message == scheduler.REAPED_MESSAGE
        reaped_at = reaped.finished_at

        # The next run takes the target while the old executor is still inside its job.
        run2, created = _enqueue(kind_name, db.session.get(kind.target_model(), target_id))
        run2_id = run2.id
        assert created
        db.session.remove()
        thread2 = _start_executor(pg_app, kind_name, run2_id, outcomes)
        assert _wait_for(lambda: run2_id in executions.started)
        assert len(_lock_holders(admin_conn, kind_name, target_id)) == 1

        # The old executor completes late: its commit is refused.
        executions.gate(run1_id).set()
        thread1.join(30)
        assert isinstance(executions.commit_errors[run1_id], scheduler.LockLostError)
        assert len(_lock_holders(admin_conn, kind_name, target_id)) == 1

        executions.gate(run2_id).set()
        thread2.join(30)

    assert outcomes == {run1_id: "executed", run2_id: "executed"}
    final1 = _stored(model, run1_id)
    assert final1.status == "failure"
    assert final1.error_message == scheduler.REAPED_MESSAGE
    assert final1.finished_at == reaped_at
    assert _stored(model, run2_id).status == "success"
    if kind_name == "collector":
        assert CollectorCheckResult.query.filter_by(collector_run_id=run1_id).count() == 0
        assert CollectorCheckResult.query.filter_by(collector_run_id=run2_id).count() == 1
    else:
        assert final1.files_changed == 0
    assert run2_id not in executions.commit_errors
    assert not _lock_holders(admin_conn, kind_name, target_id)


def test_late_terminal_write_is_compare_and_set(pg_app):
    """The executor's terminal write applies only to its own running run."""
    from app.services.collector_executor import _record_outcome

    config = _new_target("collector")
    token = str(uuid.uuid4())
    run = CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id, status="running",
                       executor_token=token)
    db.session.add(run)
    db.session.commit()
    run_id = run.id
    now = datetime.now(timezone.utc)

    assert _record_outcome(run_id, str(uuid.uuid4()), status="success", finished_at=now) is False
    assert _stored(CollectorRun, run_id).status == "running"
    db.session.execute(text("UPDATE collector_run SET status = 'failure' WHERE id = :id"), {"id": run_id})
    db.session.commit()
    assert _record_outcome(run_id, token, status="success", finished_at=now) is False
    assert _stored(CollectorRun, run_id).status == "failure"
    assert scheduler._fail_run(scheduler.KINDS["collector"], run_id, "late", token=token) is False
    assert _stored(CollectorRun, run_id).error_message is None


# ============================================================================
# No transaction open while the collector works
# ============================================================================


def test_collector_run_keeps_no_transaction_open_while_collecting(pg_app, admin_conn):
    config = _new_target("collector")
    run, _ = _enqueue("collector", config)
    run_id, config_id = run.id, config.id
    db.session.remove()
    in_run = threading.Event()
    release = threading.Event()

    class SlowCollector:
        def __init__(self, config, resolver):
            self.config = config

        def run(self):
            in_run.set()
            release.wait(30)
            return [CheckResult(check_name="probe", status="pass", message="ok")]

    outcomes = {}
    with patch("app.services.collector_executor.get_collector_class", return_value=SlowCollector):
        thread = _start_executor(pg_app, "collector", run_id, outcomes)
        try:
            assert in_run.wait(10)
            idle_in_transaction = admin_conn.execute(text(
                "SELECT pid FROM pg_stat_activity WHERE datname = current_database() "
                "AND pid <> pg_backend_pid() AND state LIKE 'idle in transaction%'")).scalars().all()
            assert idle_in_transaction == []
            admin_conn.execute(text("SET lock_timeout = '2s'"))
            admin_conn.execute(text("ALTER TABLE collector_config ADD COLUMN ddl_probe integer"))
        finally:
            release.set()
            thread.join(30)

    assert outcomes[run_id] == "executed"
    final = _stored(CollectorRun, run_id)
    assert final.status == "success" and final.check_pass_count == 1
    stored_config = _stored(CollectorConfig, config_id)
    assert stored_config.last_run_status == "success"
    assert CollectorCheckResult.query.filter_by(collector_run_id=run_id).count() == 1
