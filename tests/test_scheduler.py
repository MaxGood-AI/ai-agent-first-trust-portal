"""Scheduler, job runner and collector dashboard tests.

SQLite tests cover enqueueing (including the conflict paths of "Run now"),
dispatch, reaping, crontab semantics, schedule reconciliation, periodic
tasks, shutdown and the admin surfaces; PostgreSQL tests (``pg_app``) cover
leader election, per-target advisory locks and the leader loop.
``test_scheduler_redteam_pg.py`` covers run ownership under lock loss.
"""

import importlib
import logging
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import update

from app import create_app
from app.config import TestConfig
from app.models import CollectorConfig, CollectorRun, db
from app.models.git_source import GitSource, GitSyncRun
from app.services import scheduler, team_service
from app.services.collector_status import get_overview
from tests.conftest import login


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
def admin(app_ctx):
    return team_service.create_member(
        "Admin", "admin@example.com", "human", is_compliance_admin=True
    )


@pytest.fixture
def client(app_ctx):
    return app_ctx.test_client()


def _login_admin(client, admin):
    login(client, admin)


def _config(name="policy", enabled=True, cron=None):
    config = CollectorConfig(id=str(uuid.uuid4()), name=name, enabled=enabled,
                             credential_mode="none", schedule_cron=cron)
    db.session.add(config)
    db.session.commit()
    return config


def _source(name="gov", enabled=True, cron=None):
    source = GitSource(id=str(uuid.uuid4()), name=name, role="governance", provider="local",
                       repository="/tmp", branch="main", credential_mode="none",
                       enabled=enabled, schedule_cron=cron)
    db.session.add(source)
    db.session.commit()
    return source


def _wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def periodic_names():
    """Names of periodic tasks a test registers; unregistered afterwards."""
    names = []
    yield names
    for name in names:
        scheduler.unregister_periodic(name)


# ============================================================================
# Enqueue / dispatch / reap
# ============================================================================


def test_enqueue_collector_run_creates_queued_run(app_ctx):
    config = _config()
    run, created = scheduler.enqueue_collector_run(config, "manual")
    assert created is True
    assert run.status == "queued"
    assert run.trigger_type == "manual"


def test_enqueue_returns_existing_active_run(app_ctx):
    config = _config()
    first, _ = scheduler.enqueue_collector_run(config, "manual")
    second, created = scheduler.enqueue_collector_run(config, "scheduled")
    assert created is False
    assert second.id == first.id


def test_partial_unique_index_blocks_two_active_runs(app_ctx):
    config = _config()
    db.session.add(CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id, status="running"))
    db.session.commit()
    db.session.add(CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id, status="queued"))
    with pytest.raises(Exception):
        db.session.commit()
    db.session.rollback()


def test_enqueue_git_sync_creates_and_dedupes(app_ctx):
    source = _source()
    run, created = scheduler.enqueue_git_sync(source, "api")
    assert created and run.status == "queued"
    again, created_again = scheduler.enqueue_git_sync(source, "manual")
    assert not created_again and again.id == run.id


def test_dispatch_once_executes_queued_collector_run(app_ctx):
    config = _config()
    run, _ = scheduler.enqueue_collector_run(config, "manual")

    def fake_execute(r):
        r.status = "success"
        r.finished_at = datetime.now(timezone.utc)
        db.session.commit()

    with patch("app.services.collector_executor.execute_run", side_effect=fake_execute) as mocked:
        assert scheduler.dispatch_once() == 1
    mocked.assert_called_once()
    assert db.session.get(CollectorRun, run.id).status == "success"


def test_execute_claimed_marks_failure_when_job_raises(app_ctx):
    config = _config()
    run, _ = scheduler.enqueue_collector_run(config, "manual")
    with patch("app.services.collector_executor.execute_run", side_effect=RuntimeError("boom")):
        assert scheduler.execute_claimed("collector", run.id) == "executed"
    db.session.expire_all()
    stored = db.session.get(CollectorRun, run.id)
    assert stored.status == "failure"
    assert "boom" in stored.error_message


def test_execute_claimed_marks_failure_when_job_records_nothing(app_ctx):
    config = _config()
    run, _ = scheduler.enqueue_collector_run(config, "manual")
    with patch("app.services.collector_executor.execute_run", return_value=None):
        scheduler.execute_claimed("collector", run.id)
    db.session.expire_all()
    assert db.session.get(CollectorRun, run.id).status == "failure"


def test_execute_claimed_ignores_non_queued_run(app_ctx):
    config = _config()
    run = CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id, status="success")
    db.session.add(run)
    db.session.commit()
    assert scheduler.execute_claimed("collector", run.id) == "gone"
    assert scheduler.execute_claimed("collector", "missing") == "gone"


def test_reap_once_fails_stuck_running_runs(app_ctx):
    config = _config()
    old = datetime.now(timezone.utc) - timedelta(minutes=10)
    stuck = CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id,
                         status="running", started_at=old)
    db.session.add(stuck)
    db.session.commit()
    assert scheduler.reap_once() == 1
    db.session.expire_all()
    reaped = db.session.get(CollectorRun, stuck.id)
    assert reaped.status == "failure"
    assert "Interrupted" in reaped.error_message


def test_reap_once_leaves_recent_runs(app_ctx):
    config = _config()
    db.session.add(CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id,
                                status="running", started_at=datetime.now(timezone.utc)))
    db.session.commit()
    assert scheduler.reap_once() == 0


def test_reap_once_judges_staleness_by_heartbeat(app_ctx):
    config = _config()
    long_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    run = CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id, status="running",
                       started_at=long_ago, heartbeat_at=datetime.now(timezone.utc))
    db.session.add(run)
    db.session.commit()
    assert scheduler.reap_once() == 0
    run.heartbeat_at = datetime.now(timezone.utc) - scheduler.REAP_GRACE - timedelta(seconds=5)
    db.session.commit()
    assert scheduler.reap_once() == 1


def test_claim_stamps_executor_token_and_heartbeat(app_ctx):
    config = _config()
    run, _ = scheduler.enqueue_collector_run(config, "manual")
    seen = {}

    def fake_execute(r):
        seen["token"], seen["heartbeat_at"] = r.executor_token, r.heartbeat_at
        r.status = "success"
        db.session.commit()

    with patch("app.services.collector_executor.execute_run", side_effect=fake_execute):
        scheduler.execute_claimed("collector", run.id)
    assert len(seen["token"]) == 36
    assert seen["heartbeat_at"] is not None


# ============================================================================
# "Run now" conflicts: 409, never 500
# ============================================================================


def _active_collector_run(config):
    run = CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id, status="running")
    db.session.add(run)
    db.session.commit()
    return run.id


def test_enqueue_retries_once_when_the_conflicting_run_finished_meanwhile(app_ctx, monkeypatch):
    config = _config()
    blocker_id = _active_collector_run(config)
    real_active_run = scheduler._active_run
    calls = []

    def racing_active_run(kind, target_id):
        calls.append(target_id)
        if len(calls) == 1:
            return None  # the blocking run is not visible yet
        if len(calls) == 2:
            # ...and it finished before the conflict could be read back.
            db.session.execute(update(CollectorRun).where(CollectorRun.id == blocker_id)
                               .values(status="success"))
            db.session.commit()
            return None
        return real_active_run(kind, target_id)

    monkeypatch.setattr(scheduler, "_active_run", racing_active_run)
    run, created = scheduler.enqueue_collector_run(config, "manual")
    assert created is True
    assert run.status == "queued" and run.id != blocker_id


def test_enqueue_raises_active_run_conflict_when_the_conflict_persists(app_ctx, monkeypatch):
    config = _config()
    _active_collector_run(config)
    monkeypatch.setattr(scheduler, "_active_run", lambda kind, target_id: None)
    with pytest.raises(scheduler.ActiveRunConflict):
        scheduler.enqueue_collector_run(config, "manual")
    assert CollectorRun.query.filter_by(collector_config_id=config.id).count() == 1


def test_enqueue_git_sync_raises_active_run_conflict_when_the_conflict_persists(app_ctx, monkeypatch):
    source = _source()
    db.session.add(GitSyncRun(id=str(uuid.uuid4()), source_id=source.id, status="running"))
    db.session.commit()
    monkeypatch.setattr(scheduler, "_active_run", lambda kind, target_id: None)
    with pytest.raises(scheduler.ActiveRunConflict):
        scheduler.enqueue_git_sync(source, "api")


def test_run_now_returns_409_when_the_active_run_cannot_be_read_back(client, admin, monkeypatch):
    config = _config("policy")
    _active_collector_run(config)
    monkeypatch.setattr(scheduler, "_active_run", lambda kind, target_id: None)
    resp = client.post("/api/collectors/policy/run", headers={"X-API-Key": admin.issued_api_key})
    assert resp.status_code == 409
    assert "already queued or running" in resp.get_json()["error"]


# ============================================================================
# Schedules
# ============================================================================


def test_parse_cron_and_next_run_time():
    assert scheduler.parse_cron("0 6 * * 1") is not None
    assert scheduler.parse_cron("not a cron") is None
    assert scheduler.parse_cron(None) is None
    now = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)  # a Monday
    upcoming = scheduler.next_run_time("0 6 * * 1", now)
    assert upcoming.isoformat().startswith("2026-10-05T06:00")
    assert scheduler.next_run_time("", now) is None


@pytest.mark.parametrize("field,expected", [
    ("*", "*"),
    ("1", "mon"),
    ("0", "sun"),
    ("7", "sun"),
    ("1-5", "mon,tue,wed,thu,fri"),
    ("0-6", "sun,mon,tue,wed,thu,fri,sat"),
    ("5-7", "sun,fri,sat"),
    ("*/2", "sun,tue,thu,sat"),
    ("mon,wed", "mon,wed"),
    ("1-5/2", "mon,wed,fri"),
])
def test_crontab_day_of_week_uses_sunday_zero(field, expected):
    assert scheduler.crontab_day_of_week(field) == expected


@pytest.mark.parametrize("bad", ["8", "5-1", "*/0", "funday"])
def test_crontab_day_of_week_rejects_invalid(bad):
    with pytest.raises(ValueError):
        scheduler.crontab_day_of_week(bad)


def test_monday_cron_fires_on_monday():
    now = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)  # a Tuesday
    assert scheduler.next_run_time("0 6 * * 1", now).strftime("%A %H:%M") == "Monday 06:00"
    assert scheduler.next_run_time("30 2 * * 0", now).strftime("%A %H:%M") == "Sunday 02:30"
    assert scheduler.parse_cron("0 6 * *") is None


def _fires(expression, now, count):
    trigger = scheduler.parse_cron(expression)
    fires, previous, current = [], None, now
    for _ in range(count):
        upcoming = trigger.get_next_fire_time(previous, current)
        fires.append(upcoming.strftime("%Y-%m-%d %H:%M %a"))
        previous = current = upcoming
    return fires


def test_cron_with_both_day_fields_restricted_fires_when_either_matches():
    now = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)  # a Monday
    assert _fires("0 3 1 * 1", now, 4) == [
        "2026-10-01 03:00 Thu", "2026-10-05 03:00 Mon", "2026-10-12 03:00 Mon", "2026-10-19 03:00 Mon",
    ]
    assert scheduler.next_run_time("0 3 1 * 1", now).isoformat() == "2026-10-01T03:00:00+00:00"
    assert _fires("0 3 1,15 * 0,6", now, 3) == [
        "2026-10-01 03:00 Thu", "2026-10-03 03:00 Sat", "2026-10-04 03:00 Sun",
    ]


@pytest.mark.parametrize("expression,expected", [
    ("0 3 1 * *", ["2026-10-01 03:00 Thu", "2026-11-01 03:00 Sun"]),
    ("0 3 * * 1", ["2026-10-05 03:00 Mon", "2026-10-12 03:00 Mon"]),
    # crontab(5): a day field starting with "*" is unrestricted, so both must match.
    ("0 3 */10 * 1", ["2026-12-21 03:00 Mon", "2027-01-11 03:00 Mon"]),
])
def test_cron_with_one_day_field_restricted_matches_that_field(expression, expected):
    now = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)
    assert _fires(expression, now, 2) == expected


def test_reconcile_schedules_crontab_trigger_with_coalesced_single_instance(app_ctx):
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.combining import OrTrigger

    _config(cron="0 3 1 * 1")
    service = scheduler.SchedulerService(app_ctx)
    service._aps = BackgroundScheduler(timezone="UTC")
    service.reconcile()
    (job,) = service._aps.get_jobs()
    assert isinstance(job.trigger, OrTrigger)
    assert job.coalesce is True
    assert job.max_instances == 1


def test_desired_schedules_include_enabled_valid_targets(app_ctx):
    good = _config("policy", cron="0 6 * * 1")
    _config("vendor", enabled=False, cron="0 6 * * 1")
    _config("aws", cron="bogus")
    source = _source(cron="*/30 * * * *")
    desired = scheduler.desired_schedules()
    assert desired == {
        f"collector:{good.id}": ("collector", good.id, "0 6 * * 1"),
        f"git_sync:{source.id}": ("git_sync", source.id, "*/30 * * * *"),
    }


def test_reconcile_applies_schedule_changes_without_restart(app_ctx):
    from apscheduler.schedulers.background import BackgroundScheduler

    config = _config(cron="0 6 * * 1")
    service = scheduler.SchedulerService(app_ctx)
    service._aps = BackgroundScheduler(timezone="UTC")
    service.reconcile()
    assert [job.id for job in service._aps.get_jobs()] == [f"collector:{config.id}"]

    config.schedule_cron = "0 7 * * *"
    db.session.commit()
    service.reconcile()
    jobs = service._aps.get_jobs()
    assert len(jobs) == 1 and jobs[0].kwargs["cron"] == "0 7 * * *"

    config.enabled = False
    db.session.commit()
    service.reconcile()
    assert service._aps.get_jobs() == []


def test_enqueue_scheduled_respects_disabled_targets(app_ctx):
    config = _config(enabled=False)
    scheduler.enqueue_scheduled("collector", config.id)
    assert CollectorRun.query.count() == 0
    config.enabled = True
    db.session.commit()
    scheduler.enqueue_scheduled("collector", config.id)
    assert CollectorRun.query.filter_by(trigger_type="scheduled").count() == 1
    source = _source()
    scheduler.enqueue_scheduled("git_sync", source.id)
    assert GitSyncRun.query.count() == 1
    scheduler.enqueue_scheduled("collector", "missing-id")


def test_cron_fire_enqueues_inside_app_context(app_ctx):
    config = _config()
    service = scheduler.SchedulerService(app_ctx)
    service._cron_fire("collector", config.id, "0 6 * * 1")
    assert CollectorRun.query.filter_by(collector_config_id=config.id).count() == 1


def test_leader_inactive_on_sqlite(app_ctx):
    assert scheduler.leader_active() is False
    service = scheduler.SchedulerService(app_ctx)
    assert service._try_become_leader() is False
    assert service.is_leader is False


def test_start_and_stop_background_on_sqlite(app_ctx, monkeypatch):
    monkeypatch.setattr(scheduler, "ELECTION_INTERVAL", 0.01)
    service = scheduler.start_background(app_ctx)
    assert scheduler.start_background(app_ctx) is service
    time.sleep(0.05)
    scheduler.stop_background()
    assert scheduler._service is None


def test_stop_background_is_safe_to_call_twice(app_ctx, monkeypatch):
    monkeypatch.setattr(scheduler, "ELECTION_INTERVAL", 0.01)
    service = scheduler.start_background(app_ctx)
    scheduler.stop_background()
    scheduler.stop_background()
    service.stop()
    assert scheduler._service is None


def test_stop_cancels_pending_runs_and_reports_running_ones(app_ctx, caplog):
    service = scheduler.SchedulerService(app_ctx)
    service._pool = ThreadPoolExecutor(max_workers=1)
    release = threading.Event()
    running = service._pool.submit(release.wait, 10)
    pending = service._pool.submit(lambda: None)
    service._inflight.add(("collector", "run-123"))
    try:
        with caplog.at_level(logging.WARNING, logger="app.services.scheduler"):
            service.stop()
            service.stop()
        assert pending.cancelled()
        assert service._pool is None
        assert "still executing: collector run-123" in caplog.text
    finally:
        release.set()
    assert running.result(5) is True


def test_runs_dispatched_after_stop_are_not_claimed(app_ctx):
    config = _config()
    run, _ = scheduler.enqueue_collector_run(config, "manual")
    service = scheduler.SchedulerService(app_ctx)
    service._stop.set()
    with patch("app.services.collector_executor.execute_run") as mocked:
        service._execute("collector", run.id)
    mocked.assert_not_called()
    assert db.session.get(CollectorRun, run.id).status == "queued"


# ============================================================================
# Periodic tasks
# ============================================================================


def test_register_periodic_at_import_time_from_another_module(tmp_path, monkeypatch, periodic_names):
    (tmp_path / "periodic_probe_module.py").write_text(
        "from app.services.scheduler import register_periodic\n"
        "\n"
        "def publish(app):\n"
        "    return app\n"
        "\n"
        "register_periodic('probe_witness', 3600, publish)\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, "periodic_probe_module", raising=False)
    periodic_names.append("probe_witness")
    probe = importlib.import_module("periodic_probe_module")
    tasks = {task.name: task for task in scheduler.periodic_tasks()}
    assert tasks["probe_witness"].interval == 3600.0
    assert tasks["probe_witness"].func is probe.publish
    assert {"reap_interrupted_runs", "prune_rate_limits"} <= set(tasks)
    with pytest.raises(ValueError):
        scheduler.register_periodic("probe_invalid", 0, probe.publish)


def test_run_periodic_runs_due_tasks_in_an_app_context_and_survives_errors(
        app_ctx, periodic_names, caplog):
    from flask import current_app

    calls = []

    def failing(app):
        raise RuntimeError("witness unavailable")

    def recording(app):
        calls.append((app, current_app._get_current_object(), CollectorConfig.query.count()))

    scheduler.register_periodic("probe_failing", 60, failing)
    scheduler.register_periodic("probe_recording", 60, recording)
    periodic_names.extend(["probe_failing", "probe_recording"])
    service = scheduler.SchedulerService(app_ctx)

    with caplog.at_level(logging.ERROR, logger="app.services.scheduler"):
        ran = service.run_periodic(now=1000.0)
    assert {"probe_failing", "probe_recording", "reap_interrupted_runs", "prune_rate_limits"} <= set(ran)
    assert calls == [(app_ctx, app_ctx, 0)]
    assert "Periodic task probe_failing failed" in caplog.text

    assert "probe_recording" not in service.run_periodic(now=1059.0)
    assert {"probe_failing", "probe_recording"} <= set(service.run_periodic(now=1060.0))
    assert len(calls) == 2


def test_target_lock_key_is_stable_signed_int():
    key = scheduler.target_lock_key("abc")
    assert key == scheduler.target_lock_key("abc")
    assert -(1 << 31) <= key < (1 << 31)


# ============================================================================
# Run now (API) is asynchronous; schedule edits validated
# ============================================================================


def test_run_now_api_queues_and_returns_poll_url(client, admin):
    _config("policy")
    resp = client.post("/api/collectors/policy/run",
                       headers={"X-API-Key": admin.issued_api_key})
    assert resp.status_code == 202
    body = resp.get_json()
    assert body["status"] == "queued"
    assert body["poll_url"] == f"/api/collectors/runs/{body['id']}"

    again = client.post("/api/collectors/policy/run",
                        headers={"X-API-Key": admin.issued_api_key})
    assert again.status_code == 409
    assert again.get_json()["id"] == body["id"]

    poll = client.get(body["poll_url"], headers={"X-API-Key": admin.issued_api_key})
    assert poll.status_code == 200
    assert poll.get_json()["run"]["status"] == "queued"


def test_configure_api_rejects_invalid_cron(client, admin):
    resp = client.post("/api/collectors/policy/configure",
                       json={"credential_mode": "none", "schedule_cron": "every monday"},
                       headers={"X-API-Key": admin.issued_api_key})
    assert resp.status_code == 400
    assert "Invalid cron" in resp.get_json()["error"]


def test_configure_api_reports_next_run(client, admin):
    resp = client.post("/api/collectors/policy/configure",
                       json={"credential_mode": "none", "schedule_cron": "0 6 * * 1", "enabled": True},
                       headers={"X-API-Key": admin.issued_api_key})
    assert resp.status_code == 200
    assert resp.get_json()["next_run_at"] is not None


def test_admin_form_rejects_invalid_cron(client, admin):
    _login_admin(client, admin)
    resp = client.post("/admin/collectors/policy", data={
        "credential_mode": "none", "schedule_cron": "nope", "enabled": "on",
    })
    assert resp.status_code == 302
    assert CollectorConfig.query.filter_by(name="policy").first() is None


def test_admin_form_saves_schedule(client, admin):
    _login_admin(client, admin)
    resp = client.post("/admin/collectors/policy", data={
        "credential_mode": "none", "schedule_cron": "0 6 * * 1", "enabled": "on",
    })
    assert resp.status_code == 302
    config = CollectorConfig.query.filter_by(name="policy").first()
    assert config.schedule_cron == "0 6 * * 1"


# ============================================================================
# PostgreSQL: leader election and per-target locks
# ============================================================================


def test_only_one_leader_per_database(pg_app):
    first = scheduler.SchedulerService(pg_app)
    second = scheduler.SchedulerService(pg_app)
    try:
        assert first._try_become_leader() is True
        assert second._try_become_leader() is False
        assert scheduler.leader_active() is True
        first._step_down()
        assert second._try_become_leader() is True
    finally:
        first._step_down()
        second._step_down()
    assert scheduler.leader_active() is False


def test_target_lock_prevents_overlapping_runs(pg_app):
    config = CollectorConfig(id=str(uuid.uuid4()), name="policy", enabled=True, credential_mode="none")
    db.session.add(config)
    db.session.commit()
    run, _ = scheduler.enqueue_collector_run(config, "manual")

    held = scheduler.TargetLock(db.engine, scheduler.KINDS["collector"].lock_class, config.id)
    assert held.acquire() is True
    try:
        assert scheduler.target_is_locked(db.engine, scheduler.KINDS["collector"].lock_class, config.id)
        assert scheduler.execute_claimed("collector", run.id) == "busy"
        assert db.session.get(CollectorRun, run.id).status == "queued"
    finally:
        held.release()
    assert not scheduler.target_is_locked(db.engine, scheduler.KINDS["collector"].lock_class, config.id)


def test_reaper_skips_runs_whose_executor_is_alive(pg_app):
    config = CollectorConfig(id=str(uuid.uuid4()), name="policy", enabled=True, credential_mode="none")
    db.session.add(config)
    db.session.commit()
    run = CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id, status="running",
                       started_at=datetime.now(timezone.utc) - timedelta(minutes=30))
    db.session.add(run)
    db.session.commit()
    lock = scheduler.TargetLock(db.engine, scheduler.KINDS["collector"].lock_class, config.id)
    assert lock.acquire()
    try:
        assert scheduler.reap_once() == 0
    finally:
        lock.release()
    assert scheduler.reap_once() == 1


def test_leader_loop_dispatches_queued_runs(pg_app, monkeypatch):
    monkeypatch.setattr(scheduler, "DISPATCH_INTERVAL", 0.05)
    config = CollectorConfig(id=str(uuid.uuid4()), name="policy", enabled=True, credential_mode="none")
    db.session.add(config)
    db.session.commit()
    run, _ = scheduler.enqueue_collector_run(config, "manual")
    run_id = run.id
    done = threading.Event()

    def fake_execute(r):
        r.status = "success"
        r.finished_at = datetime.now(timezone.utc)
        db.session.commit()
        done.set()

    with patch("app.services.collector_executor.execute_run", side_effect=fake_execute):
        service = scheduler.SchedulerService(pg_app)
        service.start()
        try:
            assert done.wait(10), "leader did not execute the queued run"
        finally:
            service.stop()
    db.session.expire_all()
    assert db.session.get(CollectorRun, run_id).status == "success"


def test_leader_runs_periodic_tasks_on_gaining_leadership_and_survives_failures(
        pg_app, monkeypatch, periodic_names):
    monkeypatch.setattr(scheduler, "DISPATCH_INTERVAL", 0.02)
    hourly_calls, failing_calls = [], []

    def hourly(app):
        hourly_calls.append(app)

    def failing(app):
        failing_calls.append(app)
        raise RuntimeError("boom")

    scheduler.register_periodic("probe_hourly", 3600, hourly)
    scheduler.register_periodic("probe_failing", 0.05, failing)
    periodic_names.extend(["probe_hourly", "probe_failing"])
    service = scheduler.SchedulerService(pg_app)
    service.start()
    try:
        assert _wait_for(lambda: hourly_calls), "periodic task did not run on gaining leadership"
        assert _wait_for(lambda: len(failing_calls) >= 3), "a failing task stopped the leader loop"
        assert service.is_leader
        assert hourly_calls == [pg_app]
    finally:
        service.stop()
    assert not service.is_leader


# ============================================================================
# Dashboard widget
# ============================================================================


def test_dashboard_widget_hidden_when_setup_needed(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/")
    body = resp.get_data(as_text=True)
    # needs_setup=True shows the banner, not the widget
    assert "Set up evidence collection" in body
    assert "collector-widget" not in body


def test_dashboard_widget_shows_after_successful_run(client, admin):
    _login_admin(client, admin)
    config = CollectorConfig(
        id=str(uuid.uuid4()),
        name="policy",
        enabled=True,
        credential_mode="none",
        last_run_status="success",
        last_run_at=datetime.now(timezone.utc),
    )
    db.session.add(config)
    db.session.commit()

    resp = client.get("/admin/")
    body = resp.get_data(as_text=True)
    # setup banner is hidden, widget is shown
    assert "Set up evidence collection" not in body
    assert "collector-widget" in body
    assert "Evidence Collection" in body
    assert "Running" in body
    assert "Last Success" in body
    assert "Evidence (7d)" in body


def test_dashboard_widget_highlights_failing_collectors(client, admin):
    _login_admin(client, admin)
    # One successful, one failing
    db.session.add(CollectorConfig(
        id=str(uuid.uuid4()),
        name="policy",
        enabled=True,
        credential_mode="none",
        last_run_status="success",
        last_run_at=datetime.now(timezone.utc),
    ))
    db.session.add(CollectorConfig(
        id=str(uuid.uuid4()),
        name="vendor",
        enabled=True,
        credential_mode="none",
        last_run_status="failure",
        last_run_at=datetime.now(timezone.utc),
    ))
    db.session.commit()

    resp = client.get("/admin/")
    body = resp.get_data(as_text=True)
    assert "collector-widget" in body
    assert "has-failing" in body
    assert "Attention" in body


def test_overview_computes_7d_evidence_count(app_ctx):
    # Seed a policy config with a successful run
    config = CollectorConfig(
        id=str(uuid.uuid4()),
        name="policy",
        enabled=True,
        credential_mode="none",
        last_run_status="success",
        last_run_at=datetime.now(timezone.utc),
    )
    db.session.add(config)

    # Three recent evidence items + one old one that should not count
    from app.models import Control, Evidence, TestRecord
    control = Control(id=str(uuid.uuid4()), name="CC6.1", category="security", state="adopted")
    db.session.add(control)
    db.session.flush()
    test = TestRecord(id=str(uuid.uuid4()), control_id=control.id, name="MFA check")
    db.session.add(test)
    db.session.flush()

    now = datetime.now(timezone.utc)
    for i in range(3):
        db.session.add(Evidence(
            id=str(uuid.uuid4()),
            test_record_id=test.id,
            evidence_type="automated",
            description=f"recent evidence {i}",
            collector_name="policy",
            collected_at=now - timedelta(days=i),
        ))
    # Old evidence — should not count
    db.session.add(Evidence(
        id=str(uuid.uuid4()),
        test_record_id=test.id,
        evidence_type="automated",
        description="old evidence",
        collector_name="policy",
        collected_at=now - timedelta(days=30),
    ))
    db.session.commit()

    overview = get_overview()
    assert overview.evidence_last_7_days == 3
    assert overview.most_recent_success_at is not None
    assert overview.running_successfully == 1
    assert overview.any_failing is False


def test_overview_detects_any_failing(app_ctx):
    db.session.add(CollectorConfig(
        id=str(uuid.uuid4()),
        name="policy",
        credential_mode="none",
        last_run_status="partial",
    ))
    db.session.commit()
    overview = get_overview()
    assert overview.any_failing is True


# ============================================================================
# Collectors list page shows scheduler state + next run
# ============================================================================


def test_collectors_list_shows_scheduler_state(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/collectors")
    body = resp.get_data(as_text=True)
    assert "Scheduler:" in body
    # Under TESTING the scheduler is not running
    assert "Not running" in body


def test_collectors_list_has_next_run_column(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/collectors")
    body = resp.get_data(as_text=True)
    assert "<th>Next Run</th>" in body
