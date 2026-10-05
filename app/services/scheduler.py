"""Background scheduler and job runner: exactly one leader per database.

Leader election
---------------
Every gunicorn worker starts a standby thread (``start_background``). The
threads compete for a PostgreSQL session-level advisory lock
(``pg_try_advisory_lock``) held on a dedicated autocommit connection; the
holder is the leader. Because the lock belongs to the database, there is one
leader across all workers, all nodes and both sides of a rolling deploy.
When the leader's process exits or its connection drops, the lock is
released and another standby takes over within ``ELECTION_INTERVAL`` seconds.

The leader:

- keeps an APScheduler instance whose cron jobs mirror the enabled
  ``collector_config`` and ``git_sources`` rows; it re-reads them every
  ``RECONCILE_INTERVAL`` seconds, so schedule edits made through the API or
  the admin UI (on any process) apply without a restart. Cron expressions
  follow crontab(5), in UTC: day of week 0 or 7 is Sunday, ``N/step`` in the
  day-of-week field runs from N to 7, and when both the day-of-month and the
  day-of-week field are restricted (neither starts with ``*``) a day matches
  when either field matches. Several fires that fall due together are
  coalesced into one, and a job never runs twice at once;
- on gaining leadership, queues exactly one ``scheduled`` run for each enabled
  schedule that fired, before the new leader's schedule took over, with no
  run of its target queued or started since that fire (``collector_run.
  started_at``, ``git_sync_runs.queued_at``) and since the target was
  created: fires missed during a leader handover, or while no leader ran,
  are coalesced into that one run. A schedule added or changed while a
  leader runs starts from the present;
- dispatches queued runs (``collector_run``, ``git_sync_runs`` and
  ``evidence_store_sync_runs`` rows with ``status = 'queued'``) to a small
  thread pool. "Run now" and "Sync now"
  only enqueue a row and return its id; clients poll the run. A partial
  unique index allows at most one queued/running run per target, and
  enqueueing returns the active run instead of creating a second one;
- runs the registered periodic tasks (see below), which include the reaper
  of interrupted runs and the pruning of old rate-limit rows.

The evidence store has no cron schedule: while ``EVIDENCE_STORE_BUCKET`` is
set, the periodic task ``evidence_store_sync`` (registered by
``start_background``) queues a ``scheduled`` sync of the bucket when a
process gains leadership and then every hour; like every run, it coalesces
into the bucket's active run.

Each duty runs on its own: one that raises (a bad schedule row, a failing
task) is logged and retried at its next turn while the process keeps its
leadership. The leader steps down when its lock connection fails, when its
loop meets an error outside the duties, or when it stops.

Lock connections
----------------
Advisory locks (the leader lock and the per-target run locks) are held on
dedicated, unpooled autocommit connections (``lock_connection``) opened with
``LOCK_CONNECT_ARGS``: a 10 s connect timeout, client TCP keepalives (idle
30 s, interval 10 s, 3 probes) and a 30 s TCP user timeout, so a half-open
connection fails within about a minute instead of hanging; and, as session
settings, the same keepalives on the server side, so the server ends the
session of a vanished client (releasing its locks) within about a minute,
and a ``lock_timeout`` of ``LOCK_WAIT_TIMEOUT`` for every statement.

Run execution and ownership
---------------------------
A run executes under a per-target advisory lock, held on its own lock
connection, so two runs of the same collector or source never overlap.
Claiming a run (``queued`` -> ``running``) stamps it with a fresh
``executor_token`` and ``heartbeat_at``. While the run executes:

- a heartbeat thread refreshes ``heartbeat_at`` every ``HEARTBEAT_INTERVAL``
  seconds through the lock's own connection, and the refresh applies only
  while that connection still holds the target lock and the run is still
  ``running`` under the executor's token. A refresh that waits longer than
  ``LOCK_WAIT_TIMEOUT`` for a lock gives up and retries at the next
  interval, so the heartbeat never holds up the executor's own transaction;
- every commit of the executing session first verifies that the lock
  connection still holds the target lock and that the run is still
  ``running`` under the executor's token. A failed check raises
  ``LockLostError`` before anything is written, stops the heartbeat and
  refuses every later commit of that execution, so an executor that lost its
  lock records nothing further;
- the lock counts as lost only when its session is gone (the connection
  closed, was terminated or dropped) or the session no longer holds it. A
  statement on a live session that hits the lock or statement timeout, is
  cancelled or is chosen as a deadlock victim (``OwnershipUnknown``) leaves
  the lock held: a live session keeps its session-level locks. The heartbeat
  then retries at its next interval. The commit check, when it cannot read
  the run table in time (for example while a migration holds or waits for
  it), confirms the lock through ``pg_locks`` alone and lets the commit
  proceed; while the lock is held no other process can change the run, and
  the full check runs again at the next commit;
- the run's terminal status is written compare-and-set: only from
  ``running`` and only with the executor's token.

The reaper closes a ``running`` run only when its heartbeat (or
``started_at``, before the first heartbeat) is older than ``REAP_GRACE`` and
it can take the target lock itself; its update repeats the staleness
condition, so a heartbeat refreshed in between keeps the run alive.

Periodic tasks
--------------
``register_periodic(name, interval_seconds, func)`` registers ``func(app)``
to run on the leader, inside its own application context, as soon as a
process gains leadership and then every ``interval_seconds``. Registering an
existing name replaces it; ``unregister_periodic(name)`` removes it. Any
module may register at import time, before or after the scheduler starts;
the leader reads the registry on every loop iteration. A task that raises is
logged and runs again at its next interval; it never stops the leader loop.
Tasks run one after another on the leader thread, so each one keeps its work
short.

Shutdown
--------
``stop_background()`` (safe to call more than once) stops the leader loop,
cancels dispatched runs that have not started (none is claimed after the
stop), releases leadership, and logs the runs still executing; their
heartbeats stop with the process and the reaper closes them.

On SQLite (unit tests) advisory locks are no-ops and the same code paths run
synchronously through ``dispatch_once`` / ``reap_once``.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy import event, func, select, text, update
from sqlalchemy.exc import DBAPIError, IntegrityError

logger = logging.getLogger(__name__)

LEADER_LOCK_KEY = 815000002
ELECTION_INTERVAL = 15.0
DISPATCH_INTERVAL = 5.0
RECONCILE_INTERVAL = 30.0
REAP_INTERVAL = 60.0
PRUNE_INTERVAL = 3600.0
HEARTBEAT_INTERVAL = 30.0
LOCK_WAIT_TIMEOUT = "500ms"
REAP_GRACE = timedelta(minutes=5)
MAX_CONCURRENT_RUNS = 2
REAPED_MESSAGE = "Interrupted: the process executing this run stopped before it finished"

# libpq parameters of every lock connection (see "Lock connections" above).
LOCK_CONNECT_ARGS = {
    "connect_timeout": 10,
    "keepalives": 1,
    "keepalives_idle": 30,
    "keepalives_interval": 10,
    "keepalives_count": 3,
    "tcp_user_timeout": 30_000,
}
# Session settings of every lock connection, sent as startup options.
LOCK_SESSION_SETTINGS = {
    "lock_timeout": LOCK_WAIT_TIMEOUT,
    "tcp_keepalives_idle": "30",
    "tcp_keepalives_interval": "10",
    "tcp_keepalives_count": "3",
}
# Errors a live session reports for one statement: lock_not_available
# (lock_timeout), query_canceled (statement_timeout, pg_cancel_backend),
# deadlock_detected and serialization_failure.
_TRANSIENT_SQLSTATES = frozenset({"55P03", "57014", "40P01", "40001"})


def _now():
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    """``value`` as an aware UTC datetime (SQLite returns naive ones)."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


class LockLostError(RuntimeError):
    """The executor no longer holds its run's target lock, or no longer owns the run."""


class OwnershipUnknown(RuntimeError):
    """A statement on a live lock session timed out, was cancelled or lost a
    deadlock: the session, and so its lock, is still held."""

    def __init__(self, cause: str, sqlstate: str):
        super().__init__(f"{cause} (SQLSTATE {sqlstate})")
        self.cause = cause
        self.sqlstate = sqlstate


class ActiveRunConflict(RuntimeError):
    """A run of the target is already active but could not be read back."""

    def __init__(self, kind_name: str, target_id: str):
        super().__init__(f"A {kind_name} run of {target_id} is already queued or running")
        self.kind_name = kind_name
        self.target_id = target_id


# ----------------------------------------------------------------------------
# Job kinds
# ----------------------------------------------------------------------------

@dataclass(frozen=True)
class JobKind:
    name: str
    lock_class: int                     # first key of the two-key advisory lock
    table: str
    target_column: str
    queued_order_column: str
    model: Callable                     # returns the SQLAlchemy model class
    execute: Callable[[str], None]      # executes a claimed run by id (inside an app context)
    target_model: Callable | None       # returns the target (config) model class; None: no cron schedule
    active_index: str                   # partial unique index: one queued/running run per target


def _collector_model():
    from app.models.collector_run import CollectorRun
    return CollectorRun


def _collector_target_model():
    from app.models.collector_config import CollectorConfig
    return CollectorConfig


def _execute_collector(run_id: str) -> None:
    from app.models import db
    from app.services.collector_executor import execute_run

    run = db.session.get(_collector_model(), run_id)
    execute_run(run)


def _git_model():
    from app.models.git_source import GitSyncRun
    return GitSyncRun


def _git_target_model():
    from app.models.git_source import GitSource
    return GitSource


def _execute_git_sync(run_id: str) -> None:
    from app.services.git_sources.sync import execute_sync_run
    execute_sync_run(run_id)


def _store_model():
    from app.models.evidence_store import EvidenceStoreSyncRun
    return EvidenceStoreSyncRun


def _execute_store_sync(run_id: str) -> None:
    from app.services.evidence_store.sync import execute_sync_run
    execute_sync_run(run_id)


# Lock classes are unique per kind (8150 collectors, 8151 git sources, 8152 the
# evidence store). An evidence-store run's target is its bucket.
KINDS = {
    "collector": JobKind("collector", 8150, "collector_run", "collector_config_id", "started_at",
                         _collector_model, _execute_collector, _collector_target_model,
                         "uq_collector_run_one_active"),
    "git_sync": JobKind("git_sync", 8151, "git_sync_runs", "source_id", "queued_at",
                        _git_model, _execute_git_sync, _git_target_model,
                        "uq_git_sync_runs_one_active"),
    "evidence_store_sync": JobKind("evidence_store_sync", 8152, "evidence_store_sync_runs", "bucket", "queued_at",
                                   _store_model, _execute_store_sync, None,
                                   "uq_evidence_store_sync_runs_one_active"),
}


def target_lock_key(target_id: str) -> int:
    """Stable signed 32-bit key for a target id (second key of the advisory lock)."""
    value = zlib.crc32(target_id.encode("utf-8"))
    return value - (1 << 32) if value >= (1 << 31) else value


# ----------------------------------------------------------------------------
# Enqueueing (called from request handlers, the CLI and cron jobs)
# ----------------------------------------------------------------------------

def _active_run(kind: JobKind, target_id: str):
    model = kind.model()
    return (
        model.query
        .filter(getattr(model, kind.target_column) == target_id)
        .filter(model.status.in_(("queued", "running")))
        .first()
    )


def _is_active_run_conflict(kind: JobKind, exc: IntegrityError) -> bool:
    message = str(getattr(exc, "orig", exc))
    return kind.active_index in message or f"{kind.table}.{kind.target_column}" in message


def _enqueue(kind: JobKind, target_id: str, build_run: Callable):
    """Insert a queued run built by ``build_run()`` unless one is active.

    Returns ``(run, created)``. When the insert conflicts with an active run,
    that run is returned; when the conflicting run finished before it could
    be read back, the insert is retried once. ``ActiveRunConflict`` is raised
    only when the retry conflicts too and no active run can be read.
    """
    from app.models import db

    existing = _active_run(kind, target_id)
    if existing is not None:
        return existing, False
    for _attempt in range(2):
        run = build_run()
        db.session.add(run)
        try:
            db.session.commit()
            return run, True
        except IntegrityError as exc:
            db.session.rollback()
            if not _is_active_run_conflict(kind, exc):
                raise
            existing = _active_run(kind, target_id)
            if existing is not None:
                return existing, False
    raise ActiveRunConflict(kind.name, target_id)


def enqueue_collector_run(config, trigger_type: str, member_id: str | None = None):
    """Queue a run of ``config``. Returns ``(run, created)``; when a run is
    already queued or running for this collector, that run is returned with
    ``created=False``. Raises ``ActiveRunConflict`` when a concurrent run
    blocks the insert twice and cannot be read back."""
    from app.models.collector_run import CollectorRun

    def build():
        return CollectorRun(
            id=str(uuid.uuid4()),
            collector_config_id=config.id,
            triggered_by_team_member_id=member_id,
            trigger_type=trigger_type,
            status="queued",
            started_at=_now(),
        )

    return _enqueue(KINDS["collector"], config.id, build)


def enqueue_git_sync(source, trigger_type: str, member_id: str | None = None, full: bool = False):
    """Queue a sync of ``source``. Returns ``(run, created)`` like
    ``enqueue_collector_run`` (and raises ``ActiveRunConflict`` like it).
    ``full=True`` asks for a full re-import: every mapped file at head is
    processed again (still diff-only per record)."""
    from app.models.git_source import GitSyncRun

    def build():
        return GitSyncRun(
            id=str(uuid.uuid4()),
            source_id=source.id,
            trigger_type=trigger_type,
            triggered_by_team_member_id=member_id,
            status="queued",
            queued_at=_now(),
            details={"requested": {"full": True}} if full else None,
        )

    return _enqueue(KINDS["git_sync"], source.id, build)


def enqueue_evidence_store_sync(bucket: str, trigger_type: str, member_id: str | None = None):
    """Queue a sync of the evidence store ``bucket``. Returns ``(run, created)``
    like ``enqueue_collector_run`` (and raises ``ActiveRunConflict`` like it)."""
    from app.models.evidence_store import EvidenceStoreSyncRun

    def build():
        return EvidenceStoreSyncRun(
            id=str(uuid.uuid4()),
            bucket=bucket,
            trigger_type=trigger_type,
            triggered_by_team_member_id=member_id,
            status="queued",
            queued_at=_now(),
        )

    return _enqueue(KINDS["evidence_store_sync"], bucket, build)


# ----------------------------------------------------------------------------
# Locks
# ----------------------------------------------------------------------------

def _is_postgres(engine) -> bool:
    return engine.dialect.name == "postgresql"


_lock_engines: dict[str, object] = {}
_lock_engines_guard = threading.Lock()


def _lock_connect_args(url) -> dict:
    """``LOCK_CONNECT_ARGS`` plus ``LOCK_SESSION_SETTINGS`` appended to any
    ``options`` the database URL already carries."""
    settings = " ".join(f"-c {name}={value}" for name, value in LOCK_SESSION_SETTINGS.items())
    existing = url.query.get("options")
    if isinstance(existing, tuple):
        existing = " ".join(existing)
    return {**LOCK_CONNECT_ARGS, "options": f"{existing} {settings}" if existing else settings}


def lock_engine(engine):
    """The unpooled autocommit engine (one per database URL) behind ``lock_connection``."""
    from sqlalchemy import create_engine
    from sqlalchemy.pool import NullPool

    key = engine.url.render_as_string(hide_password=False)
    with _lock_engines_guard:
        found = _lock_engines.get(key)
        if found is None:
            options = {"connect_args": _lock_connect_args(engine.url)} if _is_postgres(engine) else {}
            found = create_engine(engine.url, poolclass=NullPool, isolation_level="AUTOCOMMIT", **options)
            _lock_engines[key] = found
    return found


def lock_connection(engine):
    """A dedicated, unpooled autocommit connection for session-level advisory locks.

    Closing it really closes the database session, so a lock can never
    linger on a connection returned to the application's pool. It is opened
    with ``LOCK_CONNECT_ARGS`` and ``LOCK_SESSION_SETTINGS``.
    """
    return lock_engine(engine).connect()


def _transient_sqlstate(exc: Exception) -> str | None:
    """The SQLSTATE of a statement that failed on a live session with a lock
    or statement timeout, a cancel or a deadlock; None for anything else."""
    if not isinstance(exc, DBAPIError) or exc.connection_invalidated:
        return None
    code = getattr(exc.orig, "pgcode", None)
    return code if code in _TRANSIENT_SQLSTATES else None


# pg_locks shows the two int4 keys of pg_advisory_lock(a, b) as classid / objid
# (unsigned oids) with objsubid = 2.
_HELD_BY_THIS_SESSION = (
    "SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND classid::bigint = :ua "
    "AND objid::bigint = :ub AND objsubid = 2 AND pid = pg_backend_pid() AND granted"
)


class TargetLock:
    """Session-level advisory lock on a dedicated autocommit connection.

    The connection is shared by the executing thread and its heartbeat
    thread; every use goes through ``_mutex``. ``holds``, ``ownership`` and
    ``heartbeat`` raise ``LockLostError`` when the lock's session is gone and
    ``OwnershipUnknown`` when their statement timed out, was cancelled or
    lost a deadlock on the live session (which still holds the lock).
    """

    def __init__(self, engine, lock_class: int, target_id: str):
        self.engine = engine
        self.keys = {"a": lock_class, "b": target_lock_key(target_id)}
        self.conn = None
        self._mutex = threading.Lock()

    @property
    def _unsigned_keys(self) -> dict[str, int]:
        return {"ua": self.keys["a"] & 0xFFFFFFFF, "ub": self.keys["b"] & 0xFFFFFFFF}

    def acquire(self) -> bool:
        if not _is_postgres(self.engine):
            return True
        conn = lock_connection(self.engine)
        try:
            acquired = bool(conn.execute(text("SELECT pg_try_advisory_lock(:a, :b)"), self.keys).scalar())
        except Exception:
            conn.close()
            raise
        if not acquired:
            conn.close()
            return False
        with self._mutex:
            self.conn = conn
        return True

    def holds(self) -> bool:
        """True while this lock's own database session holds the lock."""
        if not _is_postgres(self.engine):
            return True
        return bool(self._execute(f"SELECT EXISTS ({_HELD_BY_THIS_SESSION})", self._unsigned_keys)[0])

    def ownership(self, table: str, run_id: str, token: str) -> tuple[bool, str | None]:
        """``(held, status)``: whether this session holds the lock, and the
        committed status of ``run_id`` when it carries ``token`` (else None).

        The lock's own autocommit session sees committed rows only, so the
        executor's uncommitted writes never mask a status another process set.
        """
        row = self._execute(
            f"SELECT EXISTS ({_HELD_BY_THIS_SESSION}), "
            f"(SELECT status FROM {table} WHERE id = :id AND executor_token = :token)",
            {"id": run_id, "token": token, **self._unsigned_keys},
        )
        return bool(row[0]), row[1]

    def heartbeat(self, table: str, run_id: str, token: str) -> bool:
        """Refresh ``heartbeat_at`` of ``run_id`` through this lock's session.

        The update applies only while this session holds the lock and the run
        is ``running`` under ``token``; returns whether it applied. A lock
        wait longer than ``LOCK_WAIT_TIMEOUT`` raises ``OwnershipUnknown``, so
        a heartbeat never holds up the executor's own transaction.
        """
        rowcount = self._execute(
            f"UPDATE {table} SET heartbeat_at = :now WHERE id = :id AND status = 'running' "
            f"AND executor_token = :token AND EXISTS ({_HELD_BY_THIS_SESSION})",
            {"now": _now(), "id": run_id, "token": token, **self._unsigned_keys},
        )
        return rowcount == 1

    def _execute(self, sql: str, params: dict):
        """Run ``sql`` on the lock's session: its first row, or its rowcount
        when it returns no rows. Raises ``LockLostError`` when the session is
        gone and ``OwnershipUnknown`` when the statement failed on the live
        session with a timeout, a cancel or a deadlock."""
        with self._mutex:
            if self.conn is None:
                raise LockLostError("the lock's database session is closed")
            try:
                result = self.conn.execute(text(sql), params)
                return result.first() if result.returns_rows else result.rowcount
            except Exception as exc:  # noqa: BLE001 - classified below
                sqlstate = _transient_sqlstate(exc)
                if sqlstate is not None:
                    try:
                        self.conn.rollback()
                    except Exception:  # noqa: BLE001 - a session that cannot reset is gone
                        sqlstate = None
                if sqlstate is not None:
                    raise OwnershipUnknown(type(exc).__name__, sqlstate) from exc
                logger.warning("Advisory lock %s: its database session failed (%s)",
                               self.keys, type(exc).__name__)
                raise LockLostError("the lock's database session ended") from exc

    def release(self) -> None:
        with self._mutex:
            conn, self.conn = self.conn, None
        if conn is None:
            return
        try:
            conn.execute(text("SELECT pg_advisory_unlock(:a, :b)"), self.keys)
        except Exception:  # noqa: BLE001 - closing the session releases the lock anyway
            logger.warning("Advisory lock %s: unlock failed; closing its connection", self.keys)
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def target_is_locked(engine, lock_class: int, target_id: str) -> bool:
    """True when some session holds the target lock (i.e. a run is executing)."""
    lock = TargetLock(engine, lock_class, target_id)
    if not _is_postgres(engine):
        return False
    if lock.acquire():
        lock.release()
        return False
    return True


# ----------------------------------------------------------------------------
# Execution
# ----------------------------------------------------------------------------

class RunGuard:
    """Heartbeat and commit guard for one claimed run (see the module docstring)."""

    def __init__(self, kind: JobKind, run_id: str, token: str, lock: TargetLock, session):
        self.kind = kind
        self.run_id = run_id
        self.token = token
        self.lock = lock
        self.session = session
        self.lost_reason: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._listening = False

    def start(self) -> None:
        event.listen(self.session, "before_commit", self._before_commit)
        self._listening = True
        if self.lock.conn is not None:
            self._thread = threading.Thread(target=self._heartbeat_loop, daemon=True,
                                            name=f"heartbeat-{self.run_id[:8]}")
            self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(10.0)
            self._thread = None
        if self._listening:
            event.remove(self.session, "before_commit", self._before_commit)
            self._listening = False

    def _mark_lost(self, reason: str) -> None:
        if self.lost_reason is None:
            self.lost_reason = reason
            logger.error("%s run %s: %s; nothing further is recorded for it",
                         self.kind.name, self.run_id, reason)
        self._stop.set()

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(HEARTBEAT_INTERVAL):
            if not self.beat():
                return

    def beat(self) -> bool:
        """Refresh the heartbeat once; False once ownership is lost."""
        try:
            refreshed = self.lock.heartbeat(self.kind.table, self.run_id, self.token)
        except OwnershipUnknown as exc:
            logger.warning("%s run %s: heartbeat skipped (%s); retrying in %ss (SQLSTATE %s)",
                           self.kind.name, self.run_id, exc.cause, HEARTBEAT_INTERVAL, exc.sqlstate)
            return True
        except LockLostError:
            self._mark_lost("the executor lost its target lock")
            return False
        if not refreshed:
            self._mark_lost("the executor lost its target lock or its claim on the run")
            return False
        return True

    def verify(self) -> None:
        """Raise ``LockLostError`` unless the lock is held and the run, as
        committed, is still ``running`` under this executor's token.

        When the check cannot read the run table in time (``OwnershipUnknown``:
        a lock or statement timeout, a cancel), the lock alone is confirmed
        through ``pg_locks``, which waits on no table: while the lock's live
        session holds it, no other process can change the run, so the commit
        proceeds and the full check runs again at the next commit.
        """
        if self.lost_reason is not None:
            raise LockLostError(self.lost_reason)
        if not _is_postgres(self.lock.engine):
            return
        try:
            held, status = self.lock.ownership(self.kind.table, self.run_id, self.token)
        except LockLostError:
            held, status = False, None
        except OwnershipUnknown as exc:
            held, status = self._lock_still_held(exc), "running"
        if not held:
            self._mark_lost("the executor lost its target lock")
            raise LockLostError(self.lost_reason)
        if status != "running":
            self._mark_lost("the run is no longer running under this executor")
            raise LockLostError(self.lost_reason)

    def _lock_still_held(self, cause: OwnershipUnknown) -> bool:
        try:
            held = self.lock.holds()
        except LockLostError:
            return False
        except OwnershipUnknown:
            held = True  # the session answered, so it is alive and keeps its lock
        if held:
            logger.warning("%s run %s: ownership check did not answer (%s); the target lock is held, "
                           "so the commit proceeds and the run is checked again at the next commit",
                           self.kind.name, self.run_id, cause)
        return held

    def _before_commit(self, session) -> None:  # noqa: ARG002 - SQLAlchemy event signature
        self.verify()


def execute_claimed(kind_name: str, run_id: str) -> str:
    """Claim and execute one queued run. Returns what happened:
    ``executed`` | ``busy`` (target locked elsewhere) | ``gone`` (no longer queued)."""
    from app.models import db

    kind = KINDS[kind_name]
    model = kind.model()
    run = db.session.get(model, run_id)
    if run is None or run.status != "queued":
        return "gone"
    target_id = getattr(run, kind.target_column)
    lock = TargetLock(db.engine, kind.lock_class, target_id)
    if not lock.acquire():
        return "busy"
    try:
        token = str(uuid.uuid4())
        now = _now()
        claimed = db.session.execute(
            update(model)
            .where(model.id == run_id, model.status == "queued")
            .values(status="running", started_at=now, heartbeat_at=now, executor_token=token)
            .execution_options(synchronize_session=False)
        ).rowcount
        db.session.commit()
        if claimed != 1:
            return "gone"
        db.session.expire_all()
        guard = RunGuard(kind, run_id, token, lock, db.session())
        guard.start()
        error = None
        try:
            kind.execute(run_id)
        except LockLostError as exc:
            db.session.rollback()
            error = f"Interrupted: {exc}"
        except Exception as exc:  # noqa: BLE001 - a failing job must not kill the runner
            logger.exception("%s run %s raised", kind_name, run_id)
            db.session.rollback()
            error = f"Run raised: {exc}"
        finally:
            guard.close()
        if error is None:
            error = (f"Interrupted: {guard.lost_reason}" if guard.lost_reason
                     else "Run ended without recording a result")
        # Compare-and-set: applies only while the run is still running under our token.
        _fail_run(kind, run_id, error, token=token)
        return "executed"
    finally:
        lock.release()


def _fail_run(kind: JobKind, run_id: str, message: str, token: str) -> bool:
    """Record ``failure`` for a run still ``running`` under ``token``."""
    from app.models import db

    model = kind.model()
    failed = db.session.execute(
        update(model)
        .where(model.id == run_id, model.status == "running", model.executor_token == token)
        .values(status="failure", finished_at=_now(), error_message=message[:2000])
        .execution_options(synchronize_session=False)
    ).rowcount
    db.session.commit()
    return failed == 1


def queued_run_ids(kind_name: str, limit: int = 10) -> list[str]:
    from app.models import db

    kind = KINDS[kind_name]
    rows = db.session.execute(
        text(f"SELECT id FROM {kind.table} WHERE status = 'queued' "
             f"ORDER BY {kind.queued_order_column} LIMIT :limit"),
        {"limit": limit},
    ).all()
    return [row[0] for row in rows]


def dispatch_once() -> int:
    """Execute every currently queued run synchronously (CLI, tests)."""
    executed = 0
    for kind_name in KINDS:
        for run_id in queued_run_ids(kind_name, limit=100):
            if execute_claimed(kind_name, run_id) == "executed":
                executed += 1
    return executed


def _last_sign_of_life(model):
    return func.coalesce(model.heartbeat_at, model.started_at)


def _reap_run(kind: JobKind, run_id: str, target_id: str, cutoff: datetime) -> bool:
    from app.models import db

    lock = TargetLock(db.engine, kind.lock_class, target_id)
    if not lock.acquire():
        return False  # an executor holds the target lock: the run is alive
    try:
        model = kind.model()
        closed = db.session.execute(
            update(model)
            .where(model.id == run_id, model.status == "running", _last_sign_of_life(model) < cutoff)
            .values(status="failure", finished_at=_now(), error_message=REAPED_MESSAGE)
            .execution_options(synchronize_session=False)
        ).rowcount
        db.session.commit()
    finally:
        lock.release()
    return closed == 1


def reap_once(grace: timedelta = REAP_GRACE) -> int:
    """Close ``running`` runs whose heartbeat is older than ``grace`` and whose
    target lock is free (the process executing them stopped)."""
    from app.models import db

    reaped = 0
    cutoff = _now() - grace
    for kind in KINDS.values():
        model = kind.model()
        stale = db.session.execute(
            select(model.id, getattr(model, kind.target_column))
            .where(model.status == "running", _last_sign_of_life(model) < cutoff)
        ).all()
        db.session.commit()
        for run_id, target_id in stale:
            try:
                if _reap_run(kind, run_id, target_id, cutoff):
                    reaped += 1
                    logger.warning("Reaped %s run %s (no live executor)", kind.name, run_id)
            except Exception:  # noqa: BLE001 - one run must not stop the reaper
                db.session.rollback()
                logger.exception("Could not reap %s run %s", kind.name, run_id)
    return reaped


# ----------------------------------------------------------------------------
# Periodic tasks
# ----------------------------------------------------------------------------

@dataclass(frozen=True)
class PeriodicTask:
    name: str
    interval: float
    func: Callable


_periodic: dict[str, PeriodicTask] = {}
_periodic_guard = threading.Lock()


def register_periodic(name: str, interval_seconds: float, func: Callable) -> None:
    """Run ``func(app)`` on the scheduler leader every ``interval_seconds``
    (and as soon as a process gains leadership), inside its own app context.
    Registering an existing ``name`` replaces it."""
    if interval_seconds <= 0:
        raise ValueError("interval_seconds must be positive")
    with _periodic_guard:
        _periodic[name] = PeriodicTask(name, float(interval_seconds), func)


def unregister_periodic(name: str) -> None:
    with _periodic_guard:
        _periodic.pop(name, None)


def periodic_tasks() -> list[PeriodicTask]:
    with _periodic_guard:
        return list(_periodic.values())


def _reap_task(app) -> None:  # noqa: ARG001 - periodic task signature
    reap_once()


def _prune_task(app) -> None:  # noqa: ARG001 - periodic task signature
    from app.services import rate_limit
    rate_limit.prune()


register_periodic("reap_interrupted_runs", REAP_INTERVAL, _reap_task)
register_periodic("prune_rate_limits", PRUNE_INTERVAL, _prune_task)


# ----------------------------------------------------------------------------
# Schedules
# ----------------------------------------------------------------------------

_DOW_NAMES = ("sun", "mon", "tue", "wed", "thu", "fri", "sat")


def _dow_value(token: str) -> int:
    token = token.strip().lower()
    if token[:3] in _DOW_NAMES:
        return _DOW_NAMES.index(token[:3])
    value = int(token)
    if not 0 <= value <= 7:
        raise ValueError(f"day of week out of range: {token}")
    return value % 7


def crontab_day_of_week(field: str) -> str:
    """Translate a crontab day-of-week field (0 or 7 = Sunday) into day names.

    APScheduler 3 numbers days from Monday = 0, so numeric crontab fields
    must not be passed through unchanged ("1" would mean Tuesday). As in
    crontab(5), ``N/step`` runs from N to 7 ("1/2" is Monday, Wednesday,
    Friday and Sunday), and a range ``A-B`` covers A to B with 7 counted
    as 7 at either end ("7-7" is Sunday alone, "6-7" Saturday and Sunday).
    """
    field = field.strip()
    if field in ("*", "?"):
        return "*"
    days: list[int] = []
    for part in field.split(","):
        step = None
        if "/" in part:
            part, step_text = part.split("/", 1)
            step = int(step_text)
            if step < 1:
                raise ValueError("step must be >= 1")
        if part in ("*", ""):
            start, end = 0, 6
        elif "-" in part:
            first, last = part.split("-", 1)
            start = 7 if first.strip() == "7" else _dow_value(first)
            end = 7 if last.strip() == "7" else _dow_value(last)
        else:
            start = 7 if part.strip() == "7" else _dow_value(part)
            end = 7 if step is not None else start
        step = step or 1
        if end < start:
            raise ValueError(f"descending day-of-week range: {part}")
        for value in range(start, end + 1, step):
            if value % 7 not in days:
                days.append(value % 7)
    return ",".join(_DOW_NAMES[d] for d in sorted(days))


def _day_restricted(field: str) -> bool:
    """crontab(5): a day field starting with ``*`` (or ``?``) is unrestricted."""
    return not field.strip().startswith(("*", "?"))


def parse_cron(expression: str | None):
    """Return an APScheduler trigger for a standard 5-field crontab expression
    (minute hour day month day-of-week, UTC), or None if invalid.

    When both day fields are restricted, the trigger fires on days matching
    either field (an ``OrTrigger`` of two ``CronTrigger``); otherwise it is a
    single ``CronTrigger``.
    """
    if not expression:
        return None
    from apscheduler.triggers.combining import OrTrigger
    from apscheduler.triggers.cron import CronTrigger

    fields = expression.split()
    if len(fields) != 5:
        return None
    minute, hour, day, month, day_of_week = fields
    try:
        dow = crontab_day_of_week(day_of_week)
        if _day_restricted(day) and _day_restricted(day_of_week):
            return OrTrigger([
                CronTrigger(minute=minute, hour=hour, day=day, month=month, timezone="UTC"),
                CronTrigger(minute=minute, hour=hour, month=month, day_of_week=dow, timezone="UTC"),
            ])
        return CronTrigger(minute=minute, hour=hour, day=day, month=month,
                           day_of_week=dow, timezone="UTC")
    except (ValueError, TypeError):
        return None


def next_run_time(expression: str | None, now: datetime | None = None):
    trigger = parse_cron(expression)
    if trigger is None:
        return None
    return trigger.get_next_fire_time(None, now or _now())


def desired_schedules() -> dict[str, tuple[str, str, str]]:
    """{job_id: (kind, target_id, cron)} for every enabled target with a valid cron."""
    from app.models.collector_config import CollectorConfig
    from app.models.git_source import GitSource

    desired: dict[str, tuple[str, str, str]] = {}
    for config in CollectorConfig.query.filter_by(enabled=True).all():
        if parse_cron(config.schedule_cron):
            desired[f"collector:{config.id}"] = ("collector", config.id, config.schedule_cron)
    for source in GitSource.query.filter_by(enabled=True).all():
        if parse_cron(source.schedule_cron):
            desired[f"git_sync:{source.id}"] = ("git_sync", source.id, source.schedule_cron)
    return desired


def enqueue_scheduled(kind_name: str, target_id: str):
    """Cron callback body: queue a scheduled run of an enabled target.

    Returns ``(run, created)`` like ``enqueue_collector_run``, or None when
    the target is missing or disabled, or when a run of it is active but
    could not be read back (``ActiveRunConflict``): the fire then coalesces
    into that active run.
    """
    from app.models import db

    kind = KINDS[kind_name]
    if kind.target_model is None:
        return None
    target = db.session.get(kind.target_model(), target_id)
    if target is None or not target.enabled:
        return None
    try:
        if kind_name == "collector":
            return enqueue_collector_run(target, "scheduled")
        return enqueue_git_sync(target, "scheduled")
    except ActiveRunConflict:
        logger.info("Scheduled %s run of %s coalesced into its active run", kind_name, target_id)
        return None


def first_fire_between(expression: str | None, after: datetime, before: datetime) -> datetime | None:
    """The first fire time of ``expression`` strictly after ``after`` and
    strictly before ``before``, or None."""
    trigger = parse_cron(expression)
    if trigger is None:
        return None
    fire = trigger.get_next_fire_time(None, _aware(after) + timedelta(microseconds=1))
    return fire if fire is not None and fire < _aware(before) else None


def enqueue_missed_fire(kind_name: str, target_id: str, cron: str, until: datetime):
    """Queue one scheduled run when ``cron`` fired before ``until`` with no
    run of the target queued or started since that fire, and since the
    target was created. Returns ``(fire, run, created)`` or None."""
    from app.models import db

    kind = KINDS[kind_name]
    if kind.target_model is None:
        return None
    target = db.session.get(kind.target_model(), target_id)
    if target is None or not target.enabled:
        return None
    model = kind.model()
    run_time = getattr(model, kind.queued_order_column)
    latest = db.session.execute(
        select(func.max(run_time)).where(getattr(model, kind.target_column) == target_id)
    ).scalar()
    since = max(filter(None, (_aware(target.created_at), _aware(latest))))
    fire = first_fire_between(cron, since, until)
    if fire is None:
        return None
    queued = enqueue_scheduled(kind_name, target_id)
    if queued is None:
        return None
    run, created = queued
    return fire, run, created


def leader_active() -> bool:
    """True when some process currently holds the scheduler leader lock."""
    from app.models import db

    if not _is_postgres(db.engine):
        return False
    held = db.session.execute(text(
        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted "
        "AND classid = 0 AND objid = :key AND objsubid = 1"), {"key": LEADER_LOCK_KEY}).scalar()
    return bool(held)


# ----------------------------------------------------------------------------
# Leader loop
# ----------------------------------------------------------------------------

class SchedulerService:
    def __init__(self, app):
        self.app = app
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._leader_conn = None
        self._aps = None
        self._pool: ThreadPoolExecutor | None = None
        self._inflight: set[tuple[str, str]] = set()
        self._inflight_lock = threading.Lock()
        self._last_reconcile: float | None = None
        self._periodic_last: dict[str, float] = {}
        self._job_since: dict[str, datetime] = {}
        self._catch_up_pending = False

    # -- lifecycle --
    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="scheduler-standby", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        """Stop the loop, cancel runs not yet started and release leadership."""
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
        self._step_down()

    @property
    def is_leader(self) -> bool:
        return self._leader_conn is not None

    # -- election --
    def _try_become_leader(self) -> bool:
        from app.models import db

        if not _is_postgres(db.engine):
            return False
        conn = lock_connection(db.engine)
        try:
            got = bool(conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": LEADER_LOCK_KEY}).scalar())
        except Exception:  # noqa: BLE001
            conn.close()
            raise
        if not got:
            conn.close()
            return False
        self._leader_conn = conn
        self._start_leader_duties()
        logger.info("Scheduler leadership acquired")
        return True

    def _leader_alive(self) -> bool:
        try:
            self._leader_conn.execute(text("SELECT 1"))
            return True
        except Exception:  # noqa: BLE001
            logger.warning("Scheduler leader connection lost; stepping down")
            return False

    def _start_leader_duties(self) -> None:
        from apscheduler.schedulers.background import BackgroundScheduler

        self._aps = BackgroundScheduler(timezone="UTC")
        self._aps.start()
        self._pool = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_RUNS, thread_name_prefix="job-runner")
        self._last_reconcile = None
        self._periodic_last = {}
        self._job_since = {}
        self._catch_up_pending = True

    def _step_down(self) -> None:
        if self._aps is not None:
            try:
                self._aps.shutdown(wait=False)
            except Exception:  # noqa: BLE001
                logger.exception("APScheduler shutdown failed")
            self._aps = None
        if self._pool is not None:
            with self._inflight_lock:
                inflight = sorted(self._inflight)
            if inflight:
                logger.warning(
                    "Scheduler stopping with %d run(s) still executing: %s; the reaper closes "
                    "them if this process exits before they finish",
                    len(inflight), ", ".join(f"{kind} {run_id}" for kind, run_id in inflight))
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None
        if self._leader_conn is not None:
            try:
                self._leader_conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._leader_conn = None

    # -- main loop --
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                with self.app.app_context():
                    if not self.is_leader:
                        if not self._try_become_leader():
                            self._stop.wait(ELECTION_INTERVAL)
                            continue
                    if not self._leader_alive():
                        self._step_down()
                        continue
                    self.leader_iteration()
            except Exception:  # noqa: BLE001 - the loop must survive DB outages
                logger.exception("Scheduler loop error")
                self._step_down()
            finally:
                try:
                    from app.models import db
                    with self.app.app_context():
                        db.session.remove()
                except Exception:  # noqa: BLE001
                    pass
            self._stop.wait(DISPATCH_INTERVAL)

    def leader_iteration(self, now: float | None = None) -> None:
        """One turn of the leader's duties: reconcile (every
        ``RECONCILE_INTERVAL`` seconds), the due periodic tasks, then dispatch.
        A duty that raises is logged and retried at its next turn."""
        now = time.monotonic() if now is None else now
        if self._last_reconcile is None or now - self._last_reconcile >= RECONCILE_INTERVAL:
            self._last_reconcile = now
            self._duty("reconcile", self.reconcile)
        self.run_periodic(now)
        self._duty("dispatch", self.dispatch)

    def _duty(self, name: str, func: Callable[[], None]) -> None:
        from app.models import db

        try:
            func()
        except Exception:  # noqa: BLE001 - one failing duty must not stop the others
            logger.exception("Scheduler %s failed; retrying at its next turn", name)
            try:
                db.session.rollback()
            except Exception:  # noqa: BLE001 - a broken connection shows at the next liveness check
                pass

    def run_periodic(self, now: float | None = None) -> list[str]:
        """Run every registered periodic task that is due; returns their names."""
        from app.models import db

        now = time.monotonic() if now is None else now
        ran = []
        for task in periodic_tasks():
            last = self._periodic_last.get(task.name)
            if last is not None and now - last < task.interval:
                continue
            self._periodic_last[task.name] = now
            ran.append(task.name)
            try:
                with self.app.app_context():
                    try:
                        task.func(self.app)
                    finally:
                        db.session.remove()
            except Exception:  # noqa: BLE001 - a failing task must not stop the leader
                logger.exception("Periodic task %s failed", task.name)
        return ran

    def reconcile(self) -> None:
        """Make the cron jobs match the enabled schedules. A job's first fire
        is the first one at or after the moment it is added; after gaining
        leadership, the first reconcile that completes also queues the runs of
        fires missed before that moment (``catch_up``)."""
        now = _now()
        desired = desired_schedules()
        current = {job.id: job for job in self._aps.get_jobs()}
        for job_id, job in current.items():
            spec = desired.get(job_id)
            if spec is None or job.kwargs.get("cron") != spec[2]:
                self._aps.remove_job(job_id)
                self._job_since.pop(job_id, None)
                logger.info("Unscheduled %s", job_id)
        current_ids = {job.id for job in self._aps.get_jobs()}
        for job_id, (kind_name, target_id, cron) in desired.items():
            if job_id in current_ids:
                continue
            trigger = parse_cron(cron)
            first = trigger.get_next_fire_time(None, now)
            try:
                self._aps.add_job(
                    self._cron_fire, trigger=trigger, id=job_id, name=job_id,
                    kwargs={"kind_name": kind_name, "target_id": target_id, "cron": cron},
                    misfire_grace_time=300, coalesce=True, max_instances=1, replace_existing=True,
                    **({"next_run_time": first} if first is not None else {}),
                )
            except Exception:  # noqa: BLE001 - one bad schedule must not stop the others
                logger.exception("Could not schedule %s with cron %s", job_id, cron)
                continue
            self._job_since[job_id] = now
            logger.info("Scheduled %s with cron %s", job_id, cron)
        if self._catch_up_pending:
            self.catch_up(desired)
            self._catch_up_pending = False

    def catch_up(self, desired: dict[str, tuple[str, str, str]]) -> list[str]:
        """Queue one scheduled run per schedule whose fire before its job was
        added passed without a run (``enqueue_missed_fire``); returns the job
        ids that got a new run. A target that fails is logged and skipped."""
        from app.models import db

        queued = []
        for job_id, (kind_name, target_id, cron) in desired.items():
            since = self._job_since.get(job_id)
            if since is None:
                continue
            try:
                missed = enqueue_missed_fire(kind_name, target_id, cron, since)
            except Exception:  # noqa: BLE001 - one target must not stop the others
                logger.exception("Could not queue the missed run of %s", job_id)
                db.session.rollback()
                continue
            if missed is not None and missed[2]:
                queued.append(job_id)
                logger.info("Queued scheduled run %s of %s: its fire at %s passed without a run",
                            missed[1].id, job_id, missed[0].isoformat())
        return queued

    def _cron_fire(self, kind_name: str, target_id: str, cron: str) -> None:  # noqa: ARG002
        from app.models import db

        with self.app.app_context():
            try:
                enqueue_scheduled(kind_name, target_id)
            finally:
                db.session.remove()

    def dispatch(self) -> None:
        if self._pool is None:
            return
        for kind_name in KINDS:
            for run_id in queued_run_ids(kind_name):
                key = (kind_name, run_id)
                with self._inflight_lock:
                    if key in self._inflight or len(self._inflight) >= MAX_CONCURRENT_RUNS:
                        continue
                    self._inflight.add(key)
                self._pool.submit(self._execute, kind_name, run_id)

    def _execute(self, kind_name: str, run_id: str) -> None:
        from app.models import db

        try:
            if self._stop.is_set():
                return
            with self.app.app_context():
                try:
                    execute_claimed(kind_name, run_id)
                finally:
                    db.session.remove()
        except Exception:  # noqa: BLE001
            logger.exception("Job runner failed for %s %s", kind_name, run_id)
        finally:
            with self._inflight_lock:
                self._inflight.discard((kind_name, run_id))


_service: SchedulerService | None = None
_service_guard = threading.Lock()


def start_background(app) -> SchedulerService:
    """Start the standby/leader thread for this process (gunicorn worker hook)."""
    global _service
    with _service_guard:
        if _service is None:
            from app.services import audit_witness, evidence_store

            audit_witness.register()
            evidence_store.register()
            _service = SchedulerService(app)
            _service.start()
        return _service


def stop_background() -> None:
    """Stop this process's scheduler; safe to call more than once."""
    global _service
    with _service_guard:
        service, _service = _service, None
    if service is not None:
        service.stop()
