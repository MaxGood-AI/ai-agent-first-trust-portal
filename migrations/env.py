"""Alembic environment.

The database URL comes from ``app.runtime_config.migration_database_url()``:
the migration-owner role when ``DATABASE_OWNER_*`` is configured, otherwise
the application role. The Flask app is not created here, so running
migrations never starts background work and never touches application
tables before they exist.

Locking (PostgreSQL)
--------------------
Before the pending revisions run, the migration transaction takes the locks
they need, and only those:

- ACCESS EXCLUSIVE on every existing table a pending revision alters
  (``REVISION_LOCKS``), in the portal's writer order (``WRITER_ORDER``) with
  ``audit_log`` last and only when a revision alters it;
- then, last, the audit chain's advisory lock, only when a pending revision
  writes rows of audited tables (its audit rows extend the chain).

Every lock is requested without waiting (``LOCK TABLE ... NOWAIT``,
``pg_try_advisory_xact_lock``). When one is in use, the attempt releases
everything it took (rollback to a savepoint) and tries again shortly after,
until the ``lock_timeout`` budget (``MIGRATION_LOCK_TIMEOUT`` of
``cli/db_cmd.py``, 5 s) is spent; it then raises ``MigrationLockTimeout``
(SQLSTATE 55P03), which ``python -m cli db-migrate`` retries a bounded
number of times. Taking its locks, the migration never waits, so it is
never part of a lock cycle: a running portal's transactions complete or wait
a few milliseconds, and never deadlock or queue behind a waiting migration.
The statements of the revisions themselves run with the same
``lock_timeout``; ``REVISION_LOCKS`` names every existing table they lock
(beyond ACCESS SHARE), so they wait for nothing a running portal holds.
"""

import logging
import os
import random
import re
import sys
import time
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.models import db  # noqa: E402 - path set above
from app.runtime_config import load_runtime_environment, migration_database_url  # noqa: E402

config = context.config

if config.config_file_name is not None and config.attributes.get("configure_logging", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

if not config.attributes.get("connection") and not config.attributes.get("url_override"):
    load_runtime_environment()
    config.set_main_option("sqlalchemy.url", migration_database_url().replace("%", "%%"))
elif config.attributes.get("url_override"):
    config.set_main_option("sqlalchemy.url", config.attributes["url_override"].replace("%", "%%"))

target_metadata = db.metadata
logger = logging.getLogger("migrations.env")

AUDIT_CHAIN_LOCK_KEY = 815000001
LOCK_TIMEOUT = "5s"
# Pause between two lock attempts (plus up to the same again, at random).
LOCK_RETRY_SECONDS = 0.05
WRITER_ORDER = (
    "controls", "test_records", "policies", "evidence", "systems", "vendors", "risk_register",
    "pentest_findings", "team_members", "portal_settings", "collector_config", "collector_run",
    "collector_check_result", "decision_log_sessions", "decision_log_entries",
    "decision_log_transcripts", "git_sources", "git_source_files", "git_file_versions",
    "git_commits", "git_sync_runs", "policy_controls", "vendor_systems", "audit_log",
)
EVERY_TABLE = "*"

# What each revision alters: the existing tables it takes ACCESS EXCLUSIVE on
# (every table whose definition or rows it changes, and every table a new
# foreign key or index involves), and whether it writes rows of audited
# tables. A revision missing from this map is treated as altering every table
# and writing audited rows.
REVISION_LOCKS = {
    "016": (EVERY_TABLE, False),
    "017": (("team_members",), True),
    "018": (("pentest_findings", "team_members", "portal_settings", "collector_run",
             "decision_log_sessions", "decision_log_entries"), True),
    "019": (("team_members",), False),
    "020": ((), False),
}


class MigrationLockTimeout(RuntimeError):
    """A lock the pending migrations need stayed in use for the whole budget."""

    pgcode = "55P03"  # lock_not_available: python -m cli db-migrate retries it


def _seconds(setting: str) -> float:
    """A PostgreSQL duration (``5s``, ``300ms``, ``1min``, bare = ms) in seconds."""
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(ms|s|min)?\s*", str(setting))
    if not match:
        raise ValueError(f"unsupported lock_timeout {setting!r}")
    value, unit = float(match.group(1)), match.group(2) or "ms"
    return value * {"ms": 0.001, "s": 1.0, "min": 60.0}[unit]


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _writer_order_key(table: str):
    if table == "audit_log":
        return (2, 0, table)
    if table in WRITER_ORDER:
        return (0, WRITER_ORDER.index(table), table)
    return (1, 0, table)


def _lock_plan(connection):
    """(tables to lock in writer order, whether to take the chain lock), or
    None when no upgrade is pending."""
    from alembic.migration import MigrationContext
    from alembic.script import ScriptDirectory
    from sqlalchemy import text

    current = MigrationContext.configure(connection).get_current_revision()
    script = ScriptDirectory.from_config(config)
    if current == script.get_current_head():
        return None
    try:
        pending = [rev.revision for rev in script.iterate_revisions("head", current)]
    except Exception:  # noqa: BLE001 - a revision this code cannot place: lock everything
        pending = [None]
    existing = set(connection.execute(text(
        "SELECT c.relname FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') "
        "AND c.relname <> 'alembic_version'")).scalars())
    tables, chain = set(), False
    for revision in pending:
        declared, writes_audited_rows = REVISION_LOCKS.get(revision, (EVERY_TABLE, True))
        tables |= existing if declared == EVERY_TABLE else set(declared) & existing
        chain = chain or writes_audited_rows
    return sorted(tables, key=_writer_order_key), chain


def _try_locks(connection, tables, chain) -> str | None:
    """One attempt, without waiting: None when every lock is held, else what was busy."""
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    savepoint = connection.begin_nested()
    busy = None
    try:
        for table in tables:
            busy = f"table {table}"
            connection.execute(text(f"LOCK TABLE public.{_quote(table)} IN ACCESS EXCLUSIVE MODE NOWAIT"))
        busy = "the audit chain lock"
        if chain and not connection.execute(
                text("SELECT pg_catalog.pg_try_advisory_xact_lock(:k)"), {"k": AUDIT_CHAIN_LOCK_KEY}).scalar():
            savepoint.rollback()
            return busy
    except DBAPIError as exc:
        savepoint.rollback()
        if getattr(exc.orig, "pgcode", None) != MigrationLockTimeout.pgcode:
            raise
        return busy
    savepoint.commit()
    return None


def _take_locks(connection, tables, chain, lock_timeout) -> None:
    budget = _seconds(lock_timeout)
    deadline = time.monotonic() + budget
    logger.info("Migration locks: %s; audit chain lock: %s",
                ", ".join(tables) or "no existing table", "yes" if chain else "no")
    while True:
        busy = _try_locks(connection, tables, chain)
        if busy is None:
            return
        if time.monotonic() >= deadline:
            raise MigrationLockTimeout(
                f"Migration lock timeout: {busy} stayed in use by other sessions for {lock_timeout}")
        time.sleep(LOCK_RETRY_SECONDS + random.uniform(0, LOCK_RETRY_SECONDS))


def run_migrations_offline():
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connection = config.attributes.get("connection")
    if connection is not None:
        _run(connection, owned=False)
        return

    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        _run(connection, owned=True)


def _run(connection, owned):
    from sqlalchemy import text

    plan = _lock_plan(connection) if connection.dialect.name == "postgresql" else None
    if owned and connection.in_transaction():
        # End the read that checked the revision, so Alembic manages (and commits)
        # the migration transaction itself.
        connection.rollback()
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        if plan is not None:
            lock_timeout = config.attributes.get("lock_timeout", LOCK_TIMEOUT)
            _take_locks(connection, *plan, lock_timeout)
            connection.execute(text("SELECT pg_catalog.set_config('lock_timeout', :v, true)"), {"v": lock_timeout})
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
