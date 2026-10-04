"""Scheduler behaviour on SQLite and without a database.

Covered: a new leader queues one run for a schedule whose fire passed
without a run (and nothing when the run happened, the target is newer than
the fire, or the schedule is added while leading); each leader duty survives
the failure of another; crontab ``N/step`` day-of-week fields; a scheduled
fire that coalesces into an active run it cannot read back; and the
connection settings of the lock connections.
"""

import logging
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, event

from app import create_app
from app.config import TestConfig
from app.models import CollectorConfig, CollectorRun, db
from app.models.git_source import GitSource, GitSyncRun
from app.services import scheduler


@pytest.fixture
def app_ctx(monkeypatch):
    monkeypatch.setenv("COLLECTOR_ENCRYPTION_KEY", Fernet.generate_key().decode())
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def leader(app_ctx):
    """A service that has just gained leadership (APScheduler started, catch-up pending)."""
    service = scheduler.SchedulerService(app_ctx)
    service._start_leader_duties()
    yield service
    service._step_down()


def _daily_fire():
    """A fire time two hours ago and a daily cron for it (next fire ~22 hours away)."""
    fire = (datetime.now(timezone.utc) - timedelta(hours=2)).replace(second=0, microsecond=0)
    return fire, f"{fire.minute} {fire.hour} * * *"


def _config(cron, created_at, name="policy"):
    config = CollectorConfig(id=str(uuid.uuid4()), name=name, enabled=True, credential_mode="none",
                             schedule_cron=cron, created_at=created_at)
    db.session.add(config)
    db.session.commit()
    return config


def _collector_run(config, started_at, status="success", trigger="scheduled"):
    db.session.add(CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id, status=status,
                                trigger_type=trigger, started_at=started_at,
                                finished_at=started_at + timedelta(minutes=1)))
    db.session.commit()


def _scheduled_runs(config):
    return CollectorRun.query.filter_by(collector_config_id=config.id, trigger_type="scheduled").all()


# ============================================================================
# Missed fires on leader handover
# ============================================================================


def test_new_leader_queues_one_run_for_a_fire_missed_during_handover(leader):
    fire, cron = _daily_fire()
    config = _config(cron, fire - timedelta(days=3))
    _collector_run(config, fire - timedelta(days=1) + timedelta(seconds=5))  # yesterday's fire ran

    leader.reconcile()
    leader.reconcile()

    runs = _scheduled_runs(config)
    queued = [run for run in runs if run.status == "queued"]
    assert len(queued) == 1
    assert len(runs) == 2


def test_new_leader_coalesces_several_missed_fires_into_one_run(leader):
    fire, cron = _daily_fire()
    config = _config(cron, fire - timedelta(days=30))
    _collector_run(config, fire - timedelta(days=10))

    leader.reconcile()

    assert [run.status for run in _scheduled_runs(config)].count("queued") == 1


def test_new_leader_skips_a_fire_whose_run_already_happened(leader):
    fire, cron = _daily_fire()
    config = _config(cron, fire - timedelta(days=3))
    _collector_run(config, fire + timedelta(seconds=3))  # the old leader ran it

    leader.reconcile()

    assert [run.status for run in _scheduled_runs(config)] == ["success"]


def test_new_leader_skips_a_fire_from_before_the_target_existed(leader):
    fire, cron = _daily_fire()
    config = _config(cron, fire + timedelta(minutes=10))

    leader.reconcile()

    assert _scheduled_runs(config) == []


def test_new_leader_catches_up_a_git_source_by_its_queue_time(leader):
    fire, cron = _daily_fire()
    missed = GitSource(id=str(uuid.uuid4()), name="gov", role="governance", provider="local",
                       repository="/tmp", branch="main", credential_mode="none", enabled=True,
                       schedule_cron=cron, created_at=fire - timedelta(days=3))
    synced = GitSource(id=str(uuid.uuid4()), name="evidence", role="evidence", provider="local",
                       repository="/tmp", branch="main", credential_mode="none", enabled=True,
                       schedule_cron=cron, created_at=fire - timedelta(days=3))
    db.session.add_all([missed, synced])
    db.session.add(GitSyncRun(id=str(uuid.uuid4()), source_id=synced.id, trigger_type="scheduled",
                              status="success", queued_at=fire + timedelta(seconds=2)))
    db.session.commit()

    leader.reconcile()

    assert GitSyncRun.query.filter_by(source_id=missed.id, status="queued",
                                      trigger_type="scheduled").count() == 1
    assert GitSyncRun.query.filter_by(source_id=synced.id).count() == 1


def test_catch_up_runs_once_per_leadership(app_ctx, leader):
    fire, cron = _daily_fire()
    config = _config(cron, fire - timedelta(days=3))
    leader.reconcile()
    (caught_up,) = _scheduled_runs(config)
    caught_up.status = "success"
    db.session.commit()

    leader.reconcile()
    assert len(_scheduled_runs(config)) == 1

    successor = scheduler.SchedulerService(app_ctx)
    successor._start_leader_duties()
    try:
        successor.reconcile()
    finally:
        successor._step_down()
    assert len(_scheduled_runs(config)) == 1


def test_schedule_added_while_leading_starts_from_the_present(leader):
    leader.reconcile()
    fire, cron = _daily_fire()
    config = _config(cron, fire - timedelta(days=3))

    leader.reconcile()

    assert [job.id for job in leader._aps.get_jobs()] == [f"collector:{config.id}"]
    assert _scheduled_runs(config) == []


def test_catch_up_waits_for_a_reconcile_that_completes(leader, monkeypatch):
    fire, cron = _daily_fire()
    config = _config(cron, fire - timedelta(days=3))
    real_desired = scheduler.desired_schedules
    calls = []

    def flaky_desired():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database hiccup")
        return real_desired()

    monkeypatch.setattr(scheduler, "desired_schedules", flaky_desired)
    leader.leader_iteration(now=1000.0)
    assert _scheduled_runs(config) == []
    leader.leader_iteration(now=1000.0 + scheduler.RECONCILE_INTERVAL)
    assert len(_scheduled_runs(config)) == 1


def test_first_fire_between_is_strictly_inside_the_window():
    after = datetime(2026, 9, 28, 3, 0, tzinfo=timezone.utc)
    assert scheduler.first_fire_between("0 3 * * *", after, after + timedelta(days=1)) is None
    assert scheduler.first_fire_between("0 3 * * *", after, after + timedelta(days=1, seconds=1)) \
        == after + timedelta(days=1)
    assert scheduler.first_fire_between("0 3 * * *", after.replace(tzinfo=None), after + timedelta(days=2)) \
        == after + timedelta(days=1)
    assert scheduler.first_fire_between("bogus", after, after + timedelta(days=2)) is None


# ============================================================================
# Leader duties are independent
# ============================================================================


def test_a_failing_reconcile_leaves_periodic_tasks_and_dispatch_running(app_ctx, monkeypatch, caplog):
    service = scheduler.SchedulerService(app_ctx)
    service._aps = BackgroundScheduler(timezone="UTC")
    dispatched, periodic = [], []

    def bad_row():
        raise ValueError("bad row")

    monkeypatch.setattr(scheduler, "desired_schedules", bad_row)
    monkeypatch.setattr(service, "dispatch", lambda: dispatched.append(1))
    monkeypatch.setattr(service, "run_periodic", lambda now: periodic.append(now))

    with caplog.at_level(logging.ERROR, logger="app.services.scheduler"):
        service.leader_iteration(now=1000.0)
        service.leader_iteration(now=1001.0)
        service.leader_iteration(now=1000.0 + scheduler.RECONCILE_INTERVAL)

    assert caplog.text.count("Scheduler reconcile failed") == 2
    assert periodic == [1000.0, 1001.0, 1000.0 + scheduler.RECONCILE_INTERVAL]
    assert len(dispatched) == 3


def test_a_failing_dispatch_is_retried_at_the_next_turn(app_ctx, monkeypatch):
    service = scheduler.SchedulerService(app_ctx)
    service._aps = BackgroundScheduler(timezone="UTC")
    attempts = []

    def failing_dispatch():
        attempts.append(1)
        raise RuntimeError("pool gone")

    monkeypatch.setattr(service, "dispatch", failing_dispatch)
    service.leader_iteration(now=1000.0)
    service.leader_iteration(now=1005.0)
    assert len(attempts) == 2


# ============================================================================
# Crontab N/step day of week; coalescing into an active run
# ============================================================================


@pytest.mark.parametrize("field,expected", [
    ("1/2", "sun,mon,wed,fri"),
    ("0/3", "sun,wed,sat"),
    ("5/1", "sun,fri,sat"),
    ("7/2", "sun"),
    ("mon/3", "sun,mon,thu"),
    ("1-5/2,6", "mon,wed,fri,sat"),
])
def test_crontab_day_of_week_step_from_a_single_day_runs_to_sunday(field, expected):
    assert scheduler.crontab_day_of_week(field) == expected


def test_cron_with_single_day_step_matches_crontab():
    now = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)  # a Monday
    trigger = scheduler.parse_cron("0 0 * * 1/2")
    fires, previous, current = [], None, now
    for _ in range(4):
        upcoming = trigger.get_next_fire_time(previous, current)
        fires.append(upcoming.strftime("%a %d"))
        previous = current = upcoming
    assert fires == ["Wed 30", "Fri 02", "Sun 04", "Mon 05"]


def test_scheduled_fire_coalesces_into_an_active_run_it_cannot_read_back(app_ctx, monkeypatch):
    config = _config(None, datetime.now(timezone.utc))
    db.session.add(CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id, status="running"))
    db.session.commit()
    monkeypatch.setattr(scheduler, "_active_run", lambda kind, target_id: None)

    assert scheduler.enqueue_scheduled("collector", config.id) is None
    scheduler.SchedulerService(app_ctx)._cron_fire("collector", config.id, "0 3 * * *")
    assert CollectorRun.query.filter_by(collector_config_id=config.id).count() == 1


# ============================================================================
# Lock connection settings
# ============================================================================


class _Captured(Exception):
    pass


def _connect_params(url):
    """The DBAPI keyword arguments a lock connection is opened with (nothing is connected)."""
    engine = scheduler.lock_engine(create_engine(url))
    seen = {}

    def capture(dialect, conn_rec, cargs, cparams):  # noqa: ARG001 - SQLAlchemy event signature
        seen.update(cparams)
        raise _Captured

    event.listen(engine, "do_connect", capture)
    try:
        with pytest.raises(_Captured):
            engine.connect()
    finally:
        event.remove(engine, "do_connect", capture)
    return seen


def test_lock_connections_detect_half_open_sessions():
    params = _connect_params(f"postgresql+psycopg2://portal:pw@db-{uuid.uuid4().hex[:8]}.invalid:5432/portal")
    assert params["connect_timeout"] == 10
    assert (params["keepalives"], params["keepalives_idle"], params["keepalives_interval"],
            params["keepalives_count"]) == (1, 30, 10, 3)
    assert params["tcp_user_timeout"] == 30_000
    assert params["options"] == ("-c lock_timeout=500ms -c tcp_keepalives_idle=30 "
                                 "-c tcp_keepalives_interval=10 -c tcp_keepalives_count=3")
    assert (params["dbname"], params["user"]) == ("portal", "portal")


def test_lock_connections_keep_options_from_the_database_url():
    params = _connect_params(f"postgresql+psycopg2://portal:pw@db-{uuid.uuid4().hex[:8]}.invalid/portal"
                             "?options=-c%20search_path%3Dportal&sslmode=require")
    assert params["options"].startswith("-c search_path=portal -c lock_timeout=500ms ")
    assert params["sslmode"] == "require"


def test_sqlite_lock_engine_takes_no_postgres_arguments():
    with patch("sqlalchemy.create_engine", wraps=create_engine) as spy:
        scheduler.lock_engine(create_engine(f"sqlite:///file:{uuid.uuid4().hex}?mode=memory&uri=true"))
    assert "connect_args" not in spy.call_args.kwargs
