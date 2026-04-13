"""Phase 6 tests — APScheduler integration, scheduled run execution, dashboard widget."""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.config import TestConfig
from app.models import CollectorConfig, CollectorRun, Evidence, Policy, db
from app.services import collector_scheduler, team_service
from app.services.collector_status import get_overview


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
    with client.session_transaction() as sess:
        sess["api_key"] = admin.api_key


# ============================================================================
# Scheduler lifecycle
# ============================================================================


def test_start_is_noop_under_testing(app_ctx):
    """TestConfig sets TESTING=True so start() should not initialize."""
    assert app_ctx.config.get("TESTING") is True
    collector_scheduler.start(app_ctx)
    assert collector_scheduler.is_running() is False


def test_start_initializes_real_scheduler_when_not_testing():
    """With TESTING disabled, start() should launch a real scheduler."""
    from app.services import collector_scheduler as sched_mod

    app = create_app(TestConfig)
    app.config["TESTING"] = False
    app.debug = False
    # Ensure module-level state is clean before the test
    sched_mod.shutdown()
    try:
        with app.app_context():
            db.create_all()
            sched_mod.start(app)
            assert sched_mod.is_running() is True
            db.session.remove()
            db.drop_all()
    finally:
        sched_mod.shutdown()


def test_start_skips_flask_reloader_parent(monkeypatch):
    from app.services import collector_scheduler as sched_mod

    app = create_app(TestConfig)
    app.config["TESTING"] = False
    app.debug = True
    monkeypatch.delenv("WERKZEUG_RUN_MAIN", raising=False)
    sched_mod.shutdown()
    try:
        sched_mod.start(app)
        assert sched_mod.is_running() is False
    finally:
        sched_mod.shutdown()


# ============================================================================
# Schedule sync — with a real in-memory scheduler
# ============================================================================


@pytest.fixture
def live_scheduler(monkeypatch):
    """Start a real scheduler for sync tests and shut it down after."""
    from app.services import collector_scheduler as sched_mod

    app = create_app(TestConfig)
    app.config["TESTING"] = False
    app.debug = False
    sched_mod.shutdown()
    with app.app_context():
        db.create_all()
        sched_mod.start(app)
        yield app, sched_mod
        sched_mod.shutdown()
        db.session.remove()
        db.drop_all()


def _make_config(name="aws", **overrides):
    defaults = {
        "id": str(uuid.uuid4()),
        "name": name,
        "enabled": True,
        "credential_mode": "task_role",
    }
    defaults.update(overrides)
    c = CollectorConfig(**defaults)
    db.session.add(c)
    db.session.commit()
    return c


def test_sync_schedule_registers_enabled_cron(live_scheduler):
    app, sched_mod = live_scheduler
    config = _make_config("policy", credential_mode="none", schedule_cron="0 6 * * 1")
    sched_mod.sync_schedule_for(config)
    jobs = sched_mod.list_scheduled_jobs()
    assert len(jobs) == 1
    assert jobs[0]["id"] == f"collector-{config.id}"
    assert jobs[0]["next_run_time"] is not None


def test_sync_schedule_removes_disabled_config(live_scheduler):
    app, sched_mod = live_scheduler
    config = _make_config("policy", credential_mode="none", schedule_cron="0 6 * * 1")
    sched_mod.sync_schedule_for(config)
    assert len(sched_mod.list_scheduled_jobs()) == 1

    config.enabled = False
    db.session.commit()
    sched_mod.sync_schedule_for(config)
    assert len(sched_mod.list_scheduled_jobs()) == 0


def test_sync_schedule_without_cron_removes_job(live_scheduler):
    app, sched_mod = live_scheduler
    config = _make_config("policy", credential_mode="none", schedule_cron="0 6 * * 1")
    sched_mod.sync_schedule_for(config)
    assert len(sched_mod.list_scheduled_jobs()) == 1

    config.schedule_cron = None
    db.session.commit()
    sched_mod.sync_schedule_for(config)
    assert len(sched_mod.list_scheduled_jobs()) == 0


def test_sync_schedule_invalid_cron_logs_and_removes(live_scheduler):
    app, sched_mod = live_scheduler
    config = _make_config("policy", credential_mode="none", schedule_cron="not-a-cron")
    sched_mod.sync_schedule_for(config)
    # Invalid cron expressions are silently dropped; no job registered
    assert len(sched_mod.list_scheduled_jobs()) == 0


def test_sync_schedule_update_replaces_existing_job(live_scheduler):
    app, sched_mod = live_scheduler
    config = _make_config("policy", credential_mode="none", schedule_cron="0 6 * * 1")
    sched_mod.sync_schedule_for(config)
    job_before = sched_mod.list_scheduled_jobs()[0]

    config.schedule_cron = "0 3 * * *"
    db.session.commit()
    sched_mod.sync_schedule_for(config)
    jobs_after = sched_mod.list_scheduled_jobs()
    assert len(jobs_after) == 1
    # The trigger should reflect the new cron (different trigger string).
    assert jobs_after[0]["trigger"] != job_before["trigger"]


def test_unschedule_removes_job(live_scheduler):
    app, sched_mod = live_scheduler
    config = _make_config("policy", credential_mode="none", schedule_cron="0 6 * * 1")
    sched_mod.sync_schedule_for(config)
    sched_mod.unschedule(config.id)
    assert len(sched_mod.list_scheduled_jobs()) == 0


def test_start_rebuilds_from_existing_configs(monkeypatch):
    """start() should pick up existing enabled configs from the DB."""
    from app.services import collector_scheduler as sched_mod

    # First, create configs in a temporary app
    app = create_app(TestConfig)
    app.config["TESTING"] = False
    app.debug = False
    sched_mod.shutdown()
    with app.app_context():
        db.create_all()
        # Seed two configs — one scheduled, one not
        c1 = CollectorConfig(
            id=str(uuid.uuid4()),
            name="policy",
            enabled=True,
            credential_mode="none",
            schedule_cron="0 6 * * 1",
        )
        c2 = CollectorConfig(
            id=str(uuid.uuid4()),
            name="vendor",
            enabled=False,
            credential_mode="none",
            schedule_cron="0 7 * * 1",
        )
        db.session.add_all([c1, c2])
        db.session.commit()

        sched_mod.start(app)
        try:
            jobs = sched_mod.list_scheduled_jobs()
            assert len(jobs) == 1  # only the enabled one
            assert jobs[0]["id"] == f"collector-{c1.id}"
        finally:
            sched_mod.shutdown()
            db.session.remove()
            db.drop_all()


# ============================================================================
# Scheduled job callback
# ============================================================================


def test_scheduled_job_callback_creates_run_and_executes(live_scheduler):
    app, sched_mod = live_scheduler
    # Seed a policy so the collector has something to check
    p = Policy(
        id=str(uuid.uuid4()),
        title="Test Policy",
        category="security",
        status="approved",
        next_review_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    db.session.add(p)

    config = _make_config("policy", credential_mode="none")
    db.session.commit()

    # Call the job callback directly (the scheduler would call this on fire).
    from app.services.collector_scheduler import _scheduled_job_callback
    _scheduled_job_callback(config.id)

    # A CollectorRun should exist with trigger_type='scheduled'
    runs = CollectorRun.query.filter_by(collector_config_id=config.id).all()
    assert len(runs) == 1
    assert runs[0].trigger_type == "scheduled"
    assert runs[0].triggered_by_team_member_id is None
    assert runs[0].status in ("success", "partial", "failure")


def test_scheduled_callback_skips_disabled_config(live_scheduler):
    app, sched_mod = live_scheduler
    config = _make_config("policy", credential_mode="none", enabled=False)

    from app.services.collector_scheduler import _scheduled_job_callback
    _scheduled_job_callback(config.id)

    runs = CollectorRun.query.filter_by(collector_config_id=config.id).all()
    assert len(runs) == 0


def test_scheduled_callback_handles_missing_config(live_scheduler):
    app, sched_mod = live_scheduler
    # Should not raise when config was deleted
    from app.services.collector_scheduler import _scheduled_job_callback
    _scheduled_job_callback("nonexistent-id")
    # No runs created, no exception propagated


# ============================================================================
# Admin form sync integration
# ============================================================================


def test_admin_form_save_calls_scheduler_sync(client, admin):
    _login_admin(client, admin)
    with patch("app.services.collector_scheduler.sync_schedule_for") as sync_mock:
        resp = client.post(
            "/admin/collectors/policy",
            data={
                "credential_mode": "none",
                "schedule_cron": "0 6 * * 1",
                "enabled": "on",
                "review_warning_days": "30",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        sync_mock.assert_called_once()
        # The argument is the saved CollectorConfig
        config = sync_mock.call_args.args[0]
        assert config.name == "policy"
        assert config.schedule_cron == "0 6 * * 1"


def test_admin_form_scheduler_sync_failure_does_not_block_save(client, admin):
    _login_admin(client, admin)
    with patch(
        "app.services.collector_scheduler.sync_schedule_for",
        side_effect=RuntimeError("scheduler is borked"),
    ):
        resp = client.post(
            "/admin/collectors/policy",
            data={
                "credential_mode": "none",
                "schedule_cron": "0 6 * * 1",
                "enabled": "on",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
    # Config should still have been saved
    config = CollectorConfig.query.filter_by(name="policy").first()
    assert config is not None
    assert config.schedule_cron == "0 6 * * 1"


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
