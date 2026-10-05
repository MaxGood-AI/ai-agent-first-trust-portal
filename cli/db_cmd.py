"""Database lifecycle commands used by the container entrypoint.

``python -m cli db-wait``
    Wait until the database accepts connections (default 120 s).

``python -m cli db-migrate``
    Run ``alembic upgrade head`` (as the migration-owner role when
    ``DATABASE_OWNER_*`` / ``DATABASE_OWNER_URL`` is set in the process
    environment - never read from the runtime secret), then, in that two-role
    setup, provision the application role. When the database is at a revision
    this code does not know (a newer release migrated it), the upgrade is
    skipped with a warning, so the previous image can be redeployed.

    The migration takes only the locks its pending revisions need, without
    ever waiting while it holds one (``migrations/env.py``); a lock that
    stays in use for ``MIGRATION_LOCK_TIMEOUT`` (5 s), or a deadlock, fails
    the attempt, and the upgrade is retried up to ``MIGRATION_ATTEMPTS`` (5)
    times, ``RETRY_DELAY_SECONDS`` (3 s) apart.

    Provisioning the application role, in one transaction:

    - create the role named by the app URL / ``DATABASE_USER`` if it is missing,
      and set its password from ``DATABASE_PASSWORD`` (sent as a SCRAM-SHA-256
      verifier, so the plaintext never reaches the server or its logs);
    - give it exactly its final privileges on every object (nothing is granted
      and then revoked): CONNECT on the database, USAGE on schema ``public``,
      SELECT/INSERT/UPDATE/DELETE on every table and view, USAGE/SELECT on
      every sequence; SELECT only on ``audit_log``, ``audit_witness_arming``
      and ``alembic_version`` and on their sequences (the audit trigger runs
      as SECURITY DEFINER, so audited writes still produce audit rows);
      SELECT/INSERT on ``audit_witness_publications``; SELECT/INSERT/UPDATE
      (no DELETE) on ``evidence_store_objects``, ``evidence_documents``,
      ``evidence_store_sync_runs`` and ``evidence_store_retention_floors``,
      the portal's records of the evidence store, which it never deletes;
    - revoke everything else it could hold there: TEMPORARY and CREATE on the
      database, CREATE on schema ``public``, TRUNCATE, REFERENCES, TRIGGER and
      MAINTAIN on tables, UPDATE on sequences - so the role can create neither
      temporary nor permanent objects.

    With a single role (development) only the upgrade runs.

``python -m cli db-check-role``
    Report whether the application role is safe to serve with
    (``serving_role_problems``: the role and every role it can use, and what
    each may do to the audit trail). Exit 1 when unsafe.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import time

from sqlalchemy import bindparam, create_engine, text
from sqlalchemy.engine import make_url

logger = logging.getLogger(__name__)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRAM_ITERATIONS = 4096


def add_parsers(subparsers) -> None:
    wait = subparsers.add_parser("db-wait", help="Wait for the database to accept connections")
    wait.add_argument("--timeout", type=int, default=120, help="Seconds to wait (default 120)")
    subparsers.add_parser("db-migrate", help="Upgrade the schema to head and provision the app role")
    subparsers.add_parser("db-check-role", help="Check that the application role is safe to serve with")


def _bootstrap():
    from app.logging_config import configure_logging
    from app.runtime_config import load_runtime_environment

    load_runtime_environment()
    configure_logging()


def wait_for_database(timeout: int = 120, url: str | None = None, sleep=time.sleep) -> bool:
    from app.runtime_config import migration_database_url

    url = url or migration_database_url()
    deadline = time.monotonic() + timeout
    engine = create_engine(url, pool_pre_ping=False)
    try:
        while True:
            try:
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                logger.info("Database is reachable")
                return True
            except Exception as exc:  # noqa: BLE001
                if time.monotonic() >= deadline:
                    logger.error("Database not reachable after %s s: %s", timeout,
                                 str(exc).splitlines()[0])
                    return False
                sleep(2)
    finally:
        engine.dispose()


def scram_sha256_verifier(password: str, salt: bytes | None = None,
                          iterations: int = SCRAM_ITERATIONS) -> str:
    """PostgreSQL SCRAM-SHA-256 password verifier (``pg_authid.rolpassword`` format)."""
    salt = salt or os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda raw: base64.b64encode(raw).decode("ascii")  # noqa: E731
    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


def _alembic_config(url: str | None):
    from alembic.config import Config

    cfg = Config(os.path.join(ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(ROOT, "migrations"))
    cfg.attributes["configure_logging"] = False
    cfg.attributes["lock_timeout"] = MIGRATION_LOCK_TIMEOUT
    if url:
        cfg.attributes["url_override"] = url
    return cfg


_revision_cache: list = []


def code_revisions() -> tuple[str, set[str]]:
    """(head revision, every revision) known to this code (read once per process)."""
    if not _revision_cache:
        from alembic.script import ScriptDirectory

        script = ScriptDirectory.from_config(_alembic_config(None))
        _revision_cache.append((script.get_current_head(),
                                {rev.revision for rev in script.walk_revisions()}))
    return _revision_cache[0]


def database_revision(url: str) -> str | None:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            exists = conn.execute(text("SELECT to_regclass('alembic_version')")).scalar() \
                if engine.dialect.name == "postgresql" else True
            if not exists:
                return None
            return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
    except Exception:  # noqa: BLE001 - no alembic_version table yet
        return None
    finally:
        engine.dispose()


REVISION_ID = re.compile(r"^[0-9]{3,6}$")
MIGRATION_ATTEMPTS = 5
MIGRATION_LOCK_TIMEOUT = "5s"
RETRY_DELAY_SECONDS = 3.0
RETRYABLE_SQLSTATES = {"55P03", "40P01"}  # lock_not_available, deadlock_detected


class UnknownRevisionError(RuntimeError):
    pass


def classify_revision(current: str | None) -> str:
    """``current`` | ``behind`` | ``missing`` | ``newer`` | ``unknown`` for a database revision.

    ``newer`` only for a well-formed revision id greater than this image's head
    (a later release migrated the database); any other unknown value is
    ``unknown`` - an error, never silently served.
    """
    head, known = code_revisions()
    if current is None:
        return "missing"
    if current == head:
        return "current"
    if current in known:
        return "behind"
    if REVISION_ID.match(current) and REVISION_ID.match(head) and int(current) > int(head):
        return "newer"
    return "unknown"


def _retryable(exc) -> bool:
    """A lock timeout or deadlock from the database, or the migration
    environment's own lock timeout (``MigrationLockTimeout``, SQLSTATE 55P03)."""
    code = getattr(getattr(exc, "orig", None), "pgcode", None) or getattr(exc, "pgcode", None)
    return code in RETRYABLE_SQLSTATES


def run_migrations(url: str | None = None, sleep=time.sleep) -> str:
    """Upgrade to head. Returns ``upgraded``, or ``newer`` when a later release
    already migrated the database (nothing is changed). Raises
    UnknownRevisionError for a revision this image cannot place. A migration
    blocked by a lock (lock_timeout) or chosen as a deadlock victim is retried
    up to MIGRATION_ATTEMPTS times."""
    from alembic import command

    cfg = _alembic_config(url)
    if url:
        current = database_revision(url)
        state = classify_revision(current)
        if state == "newer":
            logger.warning(
                "Database is at revision %s, newer than this image's head (a later release "
                "migrated it); skipping the upgrade and the role provisioning.", current)
            return "newer"
        if state == "unknown":
            raise UnknownRevisionError(
                f"Database revision {current!r} is not a revision this image knows or can place "
                "after its head; refusing to migrate or serve.")
    for attempt in range(1, MIGRATION_ATTEMPTS + 1):
        try:
            command.upgrade(cfg, "head")
            return "upgraded"
        except Exception as exc:  # noqa: BLE001 - classified below
            if not _retryable(exc) or attempt == MIGRATION_ATTEMPTS:
                raise
            logger.warning("Migration attempt %d/%d blocked by a lock (%s); retrying",
                           attempt, MIGRATION_ATTEMPTS, str(exc).splitlines()[0])
            sleep(RETRY_DELAY_SECONDS)
    return "upgraded"  # pragma: no cover - loop always returns or raises


# Tables the application role may read but never write: the audit trail, the
# witness arming record and Alembic's revision. Absent tables are skipped.
SELECT_ONLY_TABLES = ("audit_log", "audit_witness_arming", "alembic_version")
# Tables the application role may read and append to, never change: the record
# of witness publications.
APPEND_ONLY_TABLES = ("audit_witness_publications",)
# Tables the application role may read, insert and update, never delete from:
# the records of the evidence store (a documented erasure marks a record), its
# sync runs (the retention each read) and its retention floors.
NO_DELETE_TABLES = ("evidence_store_objects", "evidence_documents", "evidence_store_sync_runs",
                    "evidence_store_retention_floors")
# The serving-role check refuses any way to write these.
PROTECTED_TABLES = ("audit_log", "audit_witness_arming")
# Predefined roles that run programs or write files as the database server.
SERVER_ACCESS_ROLES = ("pg_execute_server_program", "pg_write_server_files")
# Every catalog query below runs with this search_path and names pg_catalog
# objects explicitly, so no object in another schema (or a temporary one) can
# stand in for them, whatever search_path the role sets for itself.
FIXED_SEARCH_PATH = "SET LOCAL search_path = pg_catalog, pg_temp"

# One row (kind, subject, role) per unsafe capability of every role the
# serving role can use: itself and every role it is a member of, directly or
# indirectly, whether the membership inherits privileges or only allows SET
# ROLE. {write_privileges} and {parameter_findings} depend on the server
# version (MAINTAIN is PostgreSQL 17+, parameter privileges 15+).
SERVING_ROLE_SQL = """
WITH reach AS (
    SELECT r.oid, r.rolname, r.rolsuper, r.rolcreaterole, r.rolbypassrls, r.rolreplication
    FROM pg_catalog.pg_roles AS r
    WHERE pg_catalog.pg_has_role(session_user, r.oid, 'MEMBER')
), user_schemas AS (
    SELECT n.oid, n.nspname FROM pg_catalog.pg_namespace AS n
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname !~ '^pg_(toast|temp)'
), protected AS (
    SELECT c.oid, c.relname FROM pg_catalog.pg_class AS c
    WHERE c.relnamespace = 'public'::pg_catalog.regnamespace AND c.relname IN :protected
)
SELECT 'superuser' AS kind, NULL AS subject, reach.rolname FROM reach WHERE reach.rolsuper
UNION ALL SELECT 'createrole', NULL, reach.rolname FROM reach WHERE reach.rolcreaterole
UNION ALL SELECT 'bypassrls', NULL, reach.rolname FROM reach WHERE reach.rolbypassrls
UNION ALL SELECT 'replication', NULL, reach.rolname FROM reach WHERE reach.rolreplication
UNION ALL SELECT 'server_access', reach.rolname, reach.rolname FROM reach WHERE reach.rolname IN :server_roles
UNION ALL SELECT 'temp', NULL, reach.rolname FROM reach
    WHERE pg_catalog.has_database_privilege(reach.oid, pg_catalog.current_database(), 'TEMPORARY')
UNION ALL SELECT 'create_database', NULL, reach.rolname FROM reach
    WHERE pg_catalog.has_database_privilege(reach.oid, pg_catalog.current_database(), 'CREATE')
UNION ALL SELECT 'owns_database', NULL, reach.rolname FROM reach
    JOIN pg_catalog.pg_database AS d ON d.datdba = reach.oid WHERE d.datname = pg_catalog.current_database()
UNION ALL SELECT 'create_schema', s.nspname, reach.rolname FROM reach CROSS JOIN user_schemas AS s
    WHERE pg_catalog.has_schema_privilege(reach.oid, s.oid, 'CREATE')
UNION ALL SELECT 'trigger', c.relname, reach.rolname FROM reach
    CROSS JOIN pg_catalog.pg_class AS c JOIN user_schemas AS s ON s.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p') AND pg_catalog.has_table_privilege(reach.oid, c.oid, 'TRIGGER')
UNION ALL SELECT 'execute_definer', f.proname, reach.rolname FROM reach
    CROSS JOIN pg_catalog.pg_proc AS f JOIN user_schemas AS s ON s.oid = f.pronamespace
    WHERE f.prosecdef AND f.proowner NOT IN (SELECT reach.oid FROM reach)
      AND pg_catalog.has_function_privilege(reach.oid, f.oid, 'EXECUTE')
UNION ALL SELECT 'write', p.privilege || ' on ' || t.relname, reach.rolname FROM reach
    CROSS JOIN protected AS t CROSS JOIN (VALUES {write_privileges}) AS p(privilege)
    WHERE CASE WHEN p.privilege IN ('INSERT', 'UPDATE')
               THEN pg_catalog.has_any_column_privilege(reach.oid, t.oid, p.privilege)
               ELSE pg_catalog.has_table_privilege(reach.oid, t.oid, p.privilege) END
{parameter_findings}
"""
PARAMETER_FINDINGS_SQL = """
UNION ALL SELECT 'replication_role_parameter', NULL, reach.rolname FROM reach
    WHERE pg_catalog.has_parameter_privilege(reach.oid, 'session_replication_role', 'SET')
       OR pg_catalog.has_parameter_privilege(reach.oid, 'session_replication_role', 'ALTER SYSTEM')
"""
OWNED_OBJECTS_SQL = """
WITH reach AS (
    SELECT r.oid FROM pg_catalog.pg_roles AS r WHERE pg_catalog.pg_has_role(session_user, r.oid, 'MEMBER')
), user_schemas AS (
    SELECT n.oid, n.nspowner FROM pg_catalog.pg_namespace AS n
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND n.nspname !~ '^pg_(toast|temp)'
)
SELECT
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class AS c JOIN user_schemas AS s ON s.oid = c.relnamespace
      WHERE c.relowner IN (SELECT oid FROM reach)) AS owned_relations,
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc AS p JOIN user_schemas AS s ON s.oid = p.pronamespace
      WHERE p.proowner IN (SELECT oid FROM reach)) AS owned_functions,
    (SELECT pg_catalog.count(*) FROM user_schemas AS s WHERE s.nspowner IN (SELECT oid FROM reach)) AS owned_schemas,
    (SELECT c.relowner IN (SELECT oid FROM reach) FROM pg_catalog.pg_class AS c
      WHERE c.oid = 'public.audit_log'::pg_catalog.regclass) AS member_of_owner
"""


def _serving_role_sql(server_version: int) -> str:
    privileges = ["INSERT", "UPDATE", "DELETE", "TRUNCATE"] + (["MAINTAIN"] if server_version >= 170000 else [])
    return SERVING_ROLE_SQL.format(
        write_privileges=", ".join(f"('{p}')" for p in privileges),
        parameter_findings=PARAMETER_FINDINGS_SQL if server_version >= 150000 else "")


FINDING_MESSAGES = {
    "superuser": "the role is a superuser",
    "createrole": "the role has CREATEROLE",
    "bypassrls": "the role has BYPASSRLS",
    "replication": "the role has REPLICATION",
    "server_access": "the role may run programs or write files as the database server (member of {subjects})",
    "temp": "the role may create temporary objects (TEMPORARY on the database)",
    "create_database": "the role may create schemas (CREATE on the database)",
    "owns_database": "the role owns the database",
    "create_schema": "the role may create objects in schema(s): {subjects}",
    "trigger": "the role holds TRIGGER on {count} table(s)",
    "execute_definer": "the role may execute SECURITY DEFINER function(s) it does not own: {subjects}",
    "replication_role_parameter": "the role may set session_replication_role (it could switch the audit "
                                  "triggers off)",
}


def serving_role_problems(url: str) -> list[str]:
    """Reasons the role behind ``url`` must not serve requests (empty = safe).

    The check covers the login role and every role it can use - every role
    it is a member of, directly or indirectly, whether the membership
    inherits privileges or only allows ``SET ROLE``. None of them may be a
    superuser or have CREATEROLE, BYPASSRLS or REPLICATION; be (a member of)
    ``pg_execute_server_program`` or ``pg_write_server_files``; own the
    database or any table, sequence, view, function, trigger function or
    schema of the portal; hold TEMPORARY or CREATE on the database, CREATE on
    any schema or TRIGGER on any table; be able to write ``audit_log`` or
    ``audit_witness_arming`` (INSERT or UPDATE on any column, DELETE,
    TRUNCATE, or MAINTAIN - directly, through PUBLIC or through a role such
    as ``pg_write_all_data`` or ``pg_maintain``); be able to EXECUTE a
    SECURITY DEFINER function it does not own (directly or through PUBLIC);
    or be allowed to set
    ``session_replication_role``. A problem that comes only through another
    role names that role. The queries run with a fixed search_path and
    schema-qualified catalog references.
    """
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            if engine.dialect.name != "postgresql":
                return []
            conn.execute(text(FIXED_SEARCH_PATH))
            if conn.execute(text("SELECT pg_catalog.to_regclass('public.audit_log')")).scalar() is None:
                return ["audit_log does not exist"]
            me = conn.execute(text("SELECT session_user::text")).scalar()
            version = int(conn.execute(text("SELECT pg_catalog.current_setting('server_version_num')")).scalar())
            findings = conn.execute(
                text(_serving_role_sql(version)).bindparams(
                    bindparam("protected", expanding=True), bindparam("server_roles", expanding=True)),
                {"protected": list(PROTECTED_TABLES), "server_roles": list(SERVER_ACCESS_ROLES)}).all()
            owned = conn.execute(text(OWNED_OBJECTS_SQL)).mappings().first()
            conn.rollback()
    finally:
        engine.dispose()
    return _describe_problems(me, findings, owned)


def _describe_problems(me: str, findings, owned) -> list[str]:
    by_kind: dict[str, dict[str | None, set[str]]] = {}
    for kind, subject, role in findings:
        by_kind.setdefault(kind, {}).setdefault(subject, set()).add(role)

    def via(roles: set[str]) -> str:
        return "" if me in roles else f" (via role {', '.join(sorted(roles))})"

    problems = []
    for kind in ("superuser", "createrole", "bypassrls", "replication", "server_access", "temp",
                 "create_database", "owns_database", "create_schema", "trigger", "execute_definer",
                 "replication_role_parameter"):
        if kind not in by_kind:
            continue
        subjects = sorted(s for s in by_kind[kind] if s is not None)
        roles = set().union(*by_kind[kind].values())
        problems.append(FINDING_MESSAGES[kind].format(subjects=", ".join(subjects), count=len(subjects))
                        + ("" if kind == "server_access" else via(roles)))
    if owned["member_of_owner"]:
        problems.append("the role owns the audited tables (it could disable the audit triggers)")
    else:
        if owned["owned_relations"] or owned["owned_functions"] or owned["owned_schemas"]:
            problems.append(
                f"the role owns portal objects ({owned['owned_relations']} relation(s), "
                f"{owned['owned_functions']} function(s), {owned['owned_schemas']} schema(s))")
        for subject, roles in sorted(by_kind.get("write", {}).items()):
            problems.append(f"the role holds {subject}{via(roles)}")
    return problems


def _quote_ident(conn, name: str) -> str:
    return conn.execute(text("SELECT pg_catalog.quote_ident(:n)"), {"n": name}).scalar()


APP_RELATIONS_SQL = """
SELECT pg_catalog.quote_ident(c.relname) AS name, c.relname, c.relkind,
       (SELECT t.relname FROM pg_catalog.pg_depend AS d JOIN pg_catalog.pg_class AS t ON t.oid = d.refobjid
         WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.objid = c.oid
           AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.deptype IN ('a', 'i')
         LIMIT 1) AS owning_table
FROM pg_catalog.pg_class AS c
WHERE c.relnamespace = 'public'::pg_catalog.regnamespace AND c.relkind IN ('r', 'p', 'v', 'S')
ORDER BY c.relname
"""


def app_role_grants(conn, role: str, database: str) -> list[str]:
    """The GRANT/REVOKE statements that give ``role`` exactly its final
    privileges: each object gets only what the role keeps (nothing is granted
    and then revoked), and everything else it could hold there is revoked."""
    version = int(conn.execute(text("SELECT pg_catalog.current_setting('server_version_num')")).scalar())
    maintain = ", MAINTAIN" if version >= 170000 else ""
    statements = [
        f"GRANT CONNECT ON DATABASE {database} TO {role}",
        f"REVOKE TEMPORARY, CREATE ON DATABASE {database} FROM {role}",
        f"GRANT USAGE ON SCHEMA public TO {role}",
        f"REVOKE CREATE ON SCHEMA public FROM {role}",
    ]
    for name, relname, kind, owning_table in conn.execute(text(APP_RELATIONS_SQL)).all():
        target = f"public.{name}"
        if kind == "S":
            if owning_table in SELECT_ONLY_TABLES:
                statements += [f"GRANT SELECT ON SEQUENCE {target} TO {role}",
                               f"REVOKE USAGE, UPDATE ON SEQUENCE {target} FROM {role}"]
            else:
                statements += [f"GRANT USAGE, SELECT ON SEQUENCE {target} TO {role}",
                               f"REVOKE UPDATE ON SEQUENCE {target} FROM {role}"]
        elif relname in APPEND_ONLY_TABLES:
            statements += [f"GRANT SELECT, INSERT ON TABLE {target} TO {role}",
                           f"REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER{maintain} "
                           f"ON TABLE {target} FROM {role}"]
        elif relname in NO_DELETE_TABLES:
            statements += [f"GRANT SELECT, INSERT, UPDATE ON TABLE {target} TO {role}",
                           f"REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER{maintain} "
                           f"ON TABLE {target} FROM {role}"]
        elif relname in SELECT_ONLY_TABLES:
            statements += [f"GRANT SELECT ON TABLE {target} TO {role}",
                           f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER{maintain} "
                           f"ON TABLE {target} FROM {role}"]
        else:
            statements += [f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {target} TO {role}",
                           f"REVOKE TRUNCATE, REFERENCES, TRIGGER{maintain} ON TABLE {target} FROM {role}"]
    return statements


def provision_app_role(owner_url: str, app_url: str) -> bool:
    """Create/update the application role and apply least-privilege grants.

    Everything runs in one transaction, and each object gets exactly the
    role's final privileges (``app_role_grants``), so no other session ever
    sees the role holding more than it keeps - for example a write privilege
    on ``audit_log`` between a broad GRANT and a narrowing REVOKE.

    Returns False (and does nothing) when both URLs use the same role.
    """
    owner = make_url(owner_url)
    app = make_url(app_url)
    if not app.username or app.username == owner.username:
        logger.info("Single database role in use; skipping app-role provisioning")
        return False
    if not app.password:
        raise RuntimeError("The application role needs a password (DATABASE_PASSWORD)")

    engine = create_engine(owner_url)
    try:
        with engine.begin() as conn:
            conn.execute(text(FIXED_SEARCH_PATH))
            role = _quote_ident(conn, app.username)
            database = _quote_ident(
                conn, owner.database or conn.execute(text("SELECT pg_catalog.current_database()")).scalar())
            verifier = scram_sha256_verifier(app.password)
            exists = conn.execute(text("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = :r"),
                                  {"r": app.username}).first()
            verb = "ALTER" if exists else "CREATE"
            conn.execute(text(f"{verb} ROLE {role} LOGIN PASSWORD :pw").bindparams(pw=verifier))
            for statement in app_role_grants(conn, role, database):
                conn.execute(text(statement))
            # TEMPORARY and CREATE also reach the role through PUBLIC; remove them there
            # when this role may (it owns the database / schema).
            for statement in (f"REVOKE TEMPORARY ON DATABASE {database} FROM PUBLIC",
                              "REVOKE CREATE ON SCHEMA public FROM PUBLIC"):
                try:
                    with conn.begin_nested():
                        conn.execute(text(statement))
                except Exception as exc:  # noqa: BLE001 - not the owner of the database/schema
                    logger.warning("Could not run %r: %s", statement, str(exc).splitlines()[0])
            leaks = conn.execute(text(
                "SELECT pg_catalog.has_database_privilege(:r, pg_catalog.current_database(), 'TEMPORARY') "
                "AS temp, pg_catalog.has_schema_privilege(:r, 'public', 'CREATE') AS create_public"),
                {"r": app.username}).mappings().first()
            if leaks["temp"] or leaks["create_public"]:
                logger.warning("Application role %s can still create %s objects (granted to PUBLIC by "
                               "a role this migration cannot override)", app.username,
                               "temporary" if leaks["temp"] else "schema public")
        logger.info("Provisioned application role %s (%s)", app.username,
                    "altered" if verb == "ALTER" else "created")
        return True
    finally:
        engine.dispose()


def run(args) -> int:
    _bootstrap()
    from app.logging_config import shutdown_logging
    from app.runtime_config import database_url, migration_database_url, owner_database_url

    try:
        if args.command == "db-wait":
            return 0 if wait_for_database(args.timeout) else 1

        if args.command == "db-check-role":
            from sqlalchemy.engine import make_url

            url = database_url()
            problems = serving_role_problems(url)
            for problem in problems:
                logger.error("Unsafe serving role: %s", problem)
            role = make_url(url).username if url else None
            if problems:
                print(f"UNSAFE: role {role} must not serve requests ({len(problems)} problem(s); see the log)")
                return 1
            print(f"OK: role {role} is safe to serve requests")
            return 0

        url = migration_database_url()
        logger.info("Running database migrations")
        try:
            outcome = run_migrations(url)
        except UnknownRevisionError as exc:
            logger.error("%s", exc)
            return 1
        if outcome == "newer":
            logger.info("Migrations skipped (newer schema); role grants left as the newer release set them")
            return 0
        logger.info("Migrations complete")
        owner_url = owner_database_url()
        if owner_url:
            provision_app_role(owner_url, database_url())
        return 0
    finally:
        shutdown_logging()
