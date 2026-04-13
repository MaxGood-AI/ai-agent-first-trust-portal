"""In-process APScheduler for collector runs.

Each enabled ``CollectorConfig`` with a cron expression is registered as
a scheduled job. The scheduler is the authoritative executor for
scheduled runs — when a job fires, it creates a ``CollectorRun`` row
with ``trigger_type='scheduled'`` and calls ``collector_executor.execute_run``
inside a Flask app context.

Key design points:

- **Schedules live in the DB, not in the scheduler.** On startup, the
  scheduler is rebuilt from ``collector_config.schedule_cron``. Saving a
  config calls ``sync_schedule_for`` to add/update/remove the
  corresponding job. This avoids any risk of the scheduler drifting from
  the config table.
- **Single-process only.** The scheduler runs in the Flask process with
  a ``MemoryJobStore``. Multi-worker gunicorn deployments will have one
  scheduler per worker — acceptable in v1 since we target a single-task
  ECS service. A PostgreSQL advisory-lock pattern is documented for
  multi-task scale-out.
- **Not started in tests or reloader parent.** ``TESTING=True`` or the
  Flask dev-server reloader parent (``WERKZEUG_RUN_MAIN`` unset with
  debug on) skips scheduler startup so tests and dev reloads don't get
  duplicate schedulers.
"""

import logging
import os
import uuid
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from flask import Flask

    from app.models.collector_config import CollectorConfig


_scheduler = None  # module-level BackgroundScheduler instance
_app = None        # Flask app needed by job callbacks for db access


def _build_scheduler():
    """Create a BackgroundScheduler. Separated so tests can patch it."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:  # pragma: no cover
        raise RuntimeError(
            "APScheduler is not installed. Add it to requirements.txt and rebuild."
        )
    return BackgroundScheduler(timezone="UTC")


def _job_id_for(config_id: str) -> str:
    return f"collector-{config_id}"


def start(app: "Flask") -> None:
    """Start the scheduler and register all enabled schedules.

    Idempotent — calling twice is a no-op. Skipped when running under
    ``TESTING`` or when the Flask dev-server reloader parent is running
    (detected by the absence of ``WERKZEUG_RUN_MAIN`` while debug is on).
    """
    global _scheduler, _app

    if app.config.get("TESTING"):
        logger.info("Skipping collector scheduler startup (TESTING mode)")
        return

    if app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        # Flask dev server reloader: parent process watches for changes,
        # child process handles requests. Only the child should run jobs.
        logger.info("Skipping collector scheduler startup (reloader parent)")
        return

    if _scheduler is not None:
        logger.info("Collector scheduler already running")
        return

    _app = app
    _scheduler = _build_scheduler()
    _scheduler.start()
    logger.info("Collector scheduler started")

    # Rebuild schedules from the DB.
    from app.models.collector_config import CollectorConfig

    with app.app_context():
        configs = CollectorConfig.query.all()
        for config in configs:
            _sync_locked(config)

    # Ensure the scheduler shuts down cleanly when the app exits.
    import atexit
    atexit.register(_atexit_shutdown)


def _atexit_shutdown():
    global _scheduler, _app
    if _scheduler is not None:
        try:
            _scheduler.shutdown(wait=False)
        except Exception:  # noqa: BLE001
            logger.exception("Scheduler shutdown failed")
        _scheduler = None
        _app = None


def shutdown() -> None:
    """Public shutdown hook (tests / graceful reconfiguration)."""
    _atexit_shutdown()


def is_running() -> bool:
    return _scheduler is not None and _scheduler.running


def sync_schedule_for(config: "CollectorConfig") -> None:
    """Ensure the scheduler's state matches ``config.schedule_cron``.

    - If the config is enabled and has a valid cron expression, add/update
      the job.
    - Otherwise, remove the job if one exists.

    Called by the admin form handler after a config is saved. No-op when
    the scheduler isn't running (tests).
    """
    if _scheduler is None:
        return
    _sync_locked(config)


def unschedule(config_id: str) -> None:
    if _scheduler is None:
        return
    job_id = _job_id_for(config_id)
    try:
        _scheduler.remove_job(job_id)
        logger.info("Removed scheduled job %s", job_id)
    except Exception:  # job didn't exist
        pass


def _sync_locked(config: "CollectorConfig") -> None:
    """Internal sync — not guarded by the module-level running check so the
    initial-load loop in ``start()`` can register jobs during startup."""
    from apscheduler.triggers.cron import CronTrigger

    job_id = _job_id_for(config.id)

    # Remove any existing job first so updates pick up new cron expressions.
    try:
        _scheduler.remove_job(job_id)
    except Exception:  # noqa: BLE001
        pass  # no existing job

    if not config.enabled or not config.schedule_cron:
        return

    try:
        trigger = CronTrigger.from_crontab(config.schedule_cron, timezone="UTC")
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Invalid cron expression for collector %s: %s (%s)",
            config.name, config.schedule_cron, exc,
        )
        return

    _scheduler.add_job(
        _scheduled_job_callback,
        trigger=trigger,
        args=[config.id],
        id=job_id,
        name=f"collector-{config.name}",
        replace_existing=True,
        misfire_grace_time=300,
        coalesce=True,
    )
    logger.info(
        "Scheduled collector %s (%s) with cron %s",
        config.name, config.id, config.schedule_cron,
    )


def _scheduled_job_callback(config_id: str) -> None:
    """Callback invoked by APScheduler when a collector's cron fires.

    Runs inside a fresh Flask app context so DB access works.
    """
    if _app is None:
        logger.error("Scheduler fired for %s but no Flask app bound", config_id)
        return

    with _app.app_context():
        from app.models import CollectorRun, db
        from app.models.collector_config import CollectorConfig
        from app.services.collector_executor import execute_run

        config = db.session.get(CollectorConfig, config_id)
        if config is None:
            logger.warning("Scheduled collector %s no longer exists", config_id)
            unschedule(config_id)
            return
        if not config.enabled:
            logger.info("Scheduled collector %s is disabled; skipping", config.name)
            unschedule(config_id)
            return

        run = CollectorRun(
            id=str(uuid.uuid4()),
            collector_config_id=config.id,
            triggered_by_team_member_id=None,
            trigger_type="scheduled",
            status="running",
        )
        db.session.add(run)
        db.session.commit()

        logger.info("Running scheduled collector %s (run %s)", config.name, run.id)
        try:
            execute_run(run)
        except Exception:  # noqa: BLE001
            logger.exception("Scheduled run %s failed", run.id)


def list_scheduled_jobs() -> list[dict]:
    """Return a structured snapshot of currently-scheduled jobs. Used by
    the admin UI to display next-run times."""
    if _scheduler is None:
        return []
    jobs: list[dict] = []
    for job in _scheduler.get_jobs():
        jobs.append({
            "id": job.id,
            "name": job.name,
            "next_run_time": (
                job.next_run_time.isoformat() if job.next_run_time else None
            ),
            "trigger": str(job.trigger),
        })
    return jobs
