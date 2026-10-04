"""Serving-role check, app-role provisioning, digests and connections
(red-team verification 2: M4 and the database lows).

Runs as a real deployment does: migrations as a NON-superuser database owner,
the application as the role ``provision_app_role`` creates. Misconfigurations
are applied by the cluster superuser (an operator mistake).
"""

import hashlib
import os
import threading
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from cli import db_cmd


@pytest.fixture
def app_url(migrated_pg_url):
    role = f"tpa_{uuid.uuid4().hex[:8]}"
    url = make_url(migrated_pg_url).set(username=role, password="app-" + uuid.uuid4().hex)
    rendered = url.render_as_string(hide_password=False)
    assert db_cmd.provision_app_role(migrated_pg_url, rendered) is True
    return rendered


def _run(url, *statements):
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            for statement in statements:
                conn.execute(text(statement))
    finally:
        engine.dispose()


def _superuser_url(database_url):
    database = make_url(database_url).database
    return make_url(os.environ["TEST_DATABASE_URL"]).set(database=database).render_as_string(hide_password=False)


def _role(url):
    return make_url(url).username


def _database(url):
    return make_url(url).database


# --------------------------------------------------------------------------
# M4: the check cannot be spoofed and covers every role the app role can use
# --------------------------------------------------------------------------

SHADOWS = (
    # the red team's shadows of the privilege functions ...
    "CREATE FUNCTION rt_evil.has_schema_privilege(name, oid, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'",
    "CREATE FUNCTION rt_evil.has_database_privilege(name, name, text) RETURNS boolean LANGUAGE sql "
    "AS 'SELECT false'",
    "CREATE FUNCTION rt_evil.has_table_privilege(name, text, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'",
    "CREATE FUNCTION rt_evil.has_table_privilege(name, oid, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'",
    "CREATE FUNCTION rt_evil.pg_has_role(name, oid, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'",
    # ... the oid-argument forms ...
    "CREATE FUNCTION rt_evil.has_schema_privilege(oid, oid, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'",
    "CREATE FUNCTION rt_evil.has_database_privilege(oid, text, text) RETURNS boolean LANGUAGE sql "
    "AS 'SELECT false'",
    "CREATE FUNCTION rt_evil.has_table_privilege(oid, oid, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'",
    "CREATE FUNCTION rt_evil.has_any_column_privilege(oid, oid, text) RETURNS boolean LANGUAGE sql "
    "AS 'SELECT false'",
    "CREATE FUNCTION rt_evil.pg_has_role(name, name, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'",
    # ... and a catalog view.
    "CREATE VIEW rt_evil.pg_roles AS SELECT * FROM pg_catalog.pg_roles WHERE false",
)


def test_m4_search_path_spoofing_does_not_hide_problems(migrated_pg_url, app_url):
    """Red-team N4 spoof: an app role with CREATE on a schema plants shadows of
    the catalog functions and views and puts that schema first on its own
    default search_path."""
    role, database = _role(app_url), _database(app_url)
    _run(_superuser_url(migrated_pg_url), "CREATE SCHEMA rt_evil",
         f'GRANT USAGE, CREATE ON SCHEMA rt_evil TO "{role}"',
         f'GRANT TEMPORARY ON DATABASE "{database}" TO "{role}"')
    _run(app_url, *SHADOWS, f'ALTER ROLE "{role}" SET search_path = rt_evil, pg_catalog, public')
    assert _scalar(app_url, "SELECT has_database_privilege(current_user, current_database(), 'TEMPORARY')") \
        is False  # the shadow is what an unqualified call resolves to
    problems = db_cmd.serving_role_problems(app_url)
    assert any("TEMPORARY on the database" in p for p in problems), problems
    assert any("create objects in schema(s): rt_evil" in p for p in problems), problems


def test_m4_role_default_set_role_does_not_hide_the_login_role(migrated_pg_url, app_url):
    """ALTER ROLE app SET role = <harmless role>: the check examines the login
    (session) role and everything it can use, not only the current role."""
    role, database = _role(app_url), _database(app_url)
    _run(_superuser_url(migrated_pg_url), f'CREATE ROLE "{role}_low_own" NOLOGIN',
         f'GRANT "{role}_low_own" TO "{role}"',
         f'GRANT TEMPORARY ON DATABASE "{database}" TO "{role}"')
    _run(app_url, f'ALTER ROLE "{role}" SET role = \'{role}_low_own\'')
    assert _scalar(app_url, "SELECT current_user") == f"{role}_low_own"
    problems = db_cmd.serving_role_problems(app_url)
    assert any("TEMPORARY on the database" in p for p in problems), problems


def test_m4_session_replication_role_parameter_privilege_is_refused(migrated_pg_url, app_url):
    """SET on session_replication_role switches ordinary (audit) triggers off."""
    role = _role(app_url)
    superuser = _superuser_url(migrated_pg_url)
    _run(superuser, f'GRANT SET ON PARAMETER session_replication_role TO "{role}"')
    try:
        _run(migrated_pg_url, "INSERT INTO controls (id, name, category) VALUES ('c1', 'C', 'security')")
        _run(app_url, "SET session_replication_role = replica",
             "UPDATE controls SET name = 'unaudited' WHERE id = 'c1'")
        assert _scalar(migrated_pg_url, "SELECT count(*) FROM audit_log "
                                        "WHERE record_id = 'c1' AND action = 'UPDATE'") == 0  # the exploit is real
        problems = db_cmd.serving_role_problems(app_url)
        assert any("session_replication_role" in p for p in problems), problems
    finally:
        _run(superuser, f'REVOKE SET ON PARAMETER session_replication_role FROM "{role}"')


def test_m4_serving_role_messages_name_the_role_used(migrated_pg_url, app_url):
    role = _role(app_url)
    _run(_superuser_url(migrated_pg_url), f'CREATE ROLE "{role}_su_own" SUPERUSER',
         f'GRANT "{role}_su_own" TO "{role}" WITH INHERIT FALSE, SET TRUE')
    problems = db_cmd.serving_role_problems(app_url)
    assert f"the role is a superuser (via role {role}_su_own)" in problems, problems


def _scalar(url, sql, **params):
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return conn.execute(text(sql), params).scalar()
    finally:
        engine.dispose()


# --------------------------------------------------------------------------
# Low: provisioning grants only the final privileges
# --------------------------------------------------------------------------

EXPOSED_SQL = """
SELECT has_any_column_privilege(:r, 'public.audit_log', 'INSERT')
    OR has_any_column_privilege(:r, 'public.audit_log', 'UPDATE')
    OR has_table_privilege(:r, 'public.audit_log', 'DELETE')
    OR has_table_privilege(:r, 'public.audit_log', 'TRUNCATE')
    OR has_table_privilege(:r, 'public.alembic_version', 'UPDATE')
    OR NOT has_table_privilege(:r, 'public.controls', 'SELECT, INSERT, UPDATE, DELETE')
"""


def test_low_provisioning_never_shows_a_wider_grant_set(migrated_pg_url, app_url):
    """Red-team N4 grant window: while db-migrate re-provisions the role, no
    other session may see it holding a write on audit_log (or losing its
    ordinary grants)."""
    role = _role(app_url)
    stop, observations, polls = threading.Event(), [], [0]

    def poll():
        engine = create_engine(migrated_pg_url, isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            while not stop.is_set():
                if conn.execute(text(EXPOSED_SQL), {"r": role}).scalar():
                    observations.append(polls[0])
                polls[0] += 1
        engine.dispose()

    poller = threading.Thread(target=poll)
    poller.start()
    try:
        for _ in range(8):
            assert db_cmd.provision_app_role(migrated_pg_url, app_url) is True
    finally:
        stop.set()
        poller.join(10)
    assert polls[0] > 50
    assert observations == []


def test_low_provisioning_applies_exactly_the_final_grant_set(migrated_pg_url, app_url):
    role, database = _role(app_url), _database(app_url)
    _run(_superuser_url(migrated_pg_url),
         f'GRANT ALL ON public.audit_log TO "{role}"',
         f'GRANT INSERT (action) ON public.audit_log TO "{role}"',
         f'GRANT ALL ON public.controls TO "{role}"',
         f'GRANT ALL ON SEQUENCE public.audit_log_id_seq TO "{role}"',
         f'GRANT CREATE, TEMPORARY ON DATABASE "{database}" TO "{role}"')
    assert db_cmd.serving_role_problems(app_url)
    assert db_cmd.provision_app_role(migrated_pg_url, app_url) is True
    check = {
        "audit_log": ("SELECT", "INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN"),
        "alembic_version": ("SELECT", "INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN"),
        "controls": ("SELECT, INSERT, UPDATE, DELETE", "TRUNCATE, REFERENCES, TRIGGER, MAINTAIN"),
    }
    for table, (held, not_held) in check.items():
        assert _scalar(migrated_pg_url, "SELECT has_table_privilege(:r, :t, :p)",
                       r=role, t=f"public.{table}", p=held) is True, table
        for privilege in not_held.split(", "):
            assert _scalar(migrated_pg_url, "SELECT has_table_privilege(:r, :t, :p)",
                           r=role, t=f"public.{table}", p=privilege) is False, (table, privilege)
    assert _scalar(migrated_pg_url, "SELECT has_any_column_privilege(:r, 'public.audit_log', 'INSERT')",
                   r=role) is False
    assert _scalar(migrated_pg_url, "SELECT has_sequence_privilege(:r, 'public.audit_log_id_seq', 'USAGE') "
                                    "OR has_sequence_privilege(:r, 'public.audit_log_id_seq', 'UPDATE')",
                   r=role) is False
    assert db_cmd.serving_role_problems(app_url) == []


# --------------------------------------------------------------------------
# Low: bytea digests are computed from the raw bytes
# --------------------------------------------------------------------------

@pytest.mark.parametrize("table, column, setup, key", [
    ("evidence", "file_data",
     ("INSERT INTO controls (id, name, category) VALUES ('c1', 'C', 'security')",
      "INSERT INTO test_records (id, name, control_id) VALUES ('t1', 'T', 'c1')",
      "INSERT INTO evidence (id, test_record_id, evidence_type) VALUES ('e1', 't1', 'file')"), "e1"),
    ("collector_config", "encrypted_credentials",
     ("INSERT INTO collector_config (id, name, enabled, credential_mode) VALUES ('cc1', 'policy', true, 'none')",),
     "cc1"),
])
def test_low_bytea_digest_is_independent_of_bytea_output(migrated_pg_url, app_url, table, column, setup, key):
    _run(app_url, *setup)
    payloads = (b"\x00\xffA", b"\x01\x02", b"back\\slash\x7f")
    for output in ("hex", "escape"):
        for payload in payloads:
            _run(app_url, f"SET bytea_output = '{output}'",
                 f"UPDATE {table} SET {column} = decode('{payload.hex()}', 'hex') WHERE id = '{key}'")
    engine = create_engine(migrated_pg_url)
    with engine.connect() as conn:
        digests = conn.execute(text(
            f"SELECT new_values->>'{column}' FROM audit_log WHERE table_name = '{table}' "
            f"AND action = 'UPDATE' AND record_id = '{key}' ORDER BY id")).scalars().all()
    engine.dispose()
    expected = [f"sha256:{hashlib.sha256(p).hexdigest()}" for p in payloads] * 2
    assert digests == expected


# --------------------------------------------------------------------------
# Low: web database connections keep alive and keep the URL's options
# --------------------------------------------------------------------------

def _connection_settings(engine):
    with engine.connect() as conn:
        dsn = conn.connection.dbapi_connection.get_dsn_parameters()
        shown = {name: conn.execute(text(f"SHOW {name}")).scalar() for name in (
            "tcp_keepalives_idle", "tcp_keepalives_interval", "tcp_keepalives_count", "statement_timeout",
            "work_mem")}
    return dsn, shown


def test_low_web_connections_keep_alive_and_keep_url_options(migrated_pg_url, monkeypatch):
    from app import create_app
    from app.models import db
    from app.runtime_config import _reset_for_tests

    url = migrated_pg_url + "?options=-c%20work_mem%3D7MB"
    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.delenv("PORTAL_SECRET_ID", raising=False)
    monkeypatch.setenv("DATABASE_URL", url)
    _reset_for_tests()
    app = create_app(serving=True)
    with app.app_context():
        dsn, shown = _connection_settings(db.engine)
        db.engine.dispose()
    assert {k: dsn.get(k) for k in ("connect_timeout", "keepalives", "keepalives_idle", "keepalives_interval",
                                    "keepalives_count", "tcp_user_timeout")} == {
        "connect_timeout": "10", "keepalives": "1", "keepalives_idle": "30", "keepalives_interval": "10",
        "keepalives_count": "3", "tcp_user_timeout": "30000"}
    assert shown == {"tcp_keepalives_idle": "30", "tcp_keepalives_interval": "10", "tcp_keepalives_count": "3",
                     "statement_timeout": "1min", "work_mem": "7MB"}
