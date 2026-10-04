"""Audit-trail security on PostgreSQL, exercised as a real deployment runs:
the migrations run as a NON-superuser database owner (like a managed
database's master user) and the application connects as the provisioned
application role.

Covers the red-team findings on the audit trail: temporary-table shadowing
and trigger borrowing (2), the row-lock/chain-lock deadlock (12), bulky and
binary columns in audit rows (16), owner credentials in the serving process
(D-A), forks after serialization and the external chain-head witness (D-B).
"""

import json
import threading
import time
import uuid

import boto3
import pytest
from moto import mock_aws
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.services.audit_chain import verify_chain


@pytest.fixture
def app_url(migrated_pg_url):
    """The provisioned application role's URL (the owner stays migrated_pg_url)."""
    from cli.db_cmd import provision_app_role

    role = f"tpa_{uuid.uuid4().hex[:8]}"
    url = make_url(migrated_pg_url).set(username=role, password="app-" + uuid.uuid4().hex)
    rendered = url.render_as_string(hide_password=False)
    assert provision_app_role(migrated_pg_url, rendered) is True
    return rendered


def _engine(url):
    return create_engine(url, isolation_level="AUTOCOMMIT")


def _owner_exec(owner_url, *statements):
    engine = _engine(owner_url)
    try:
        with engine.connect() as conn:
            for statement in statements:
                conn.execute(text(statement))
    finally:
        engine.dispose()


def _scalar(url, sql, **params):
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return conn.execute(text(sql), params).scalar()
    finally:
        engine.dispose()


def _role(url):
    return make_url(url).username


def _database(url):
    return make_url(url).database


# --------------------------------------------------------------------------
# Finding 2: SECURITY DEFINER functions cannot be hijacked or borrowed
# --------------------------------------------------------------------------

def test_app_role_cannot_create_temporary_or_schema_objects(migrated_pg_url, app_url):
    engine = _engine(app_url)
    try:
        with engine.connect() as conn:
            for statement in ("CREATE TEMP TABLE audit_log (id int)",
                              "CREATE TABLE public.rogue (id int)"):
                with pytest.raises(Exception) as excinfo:
                    conn.execute(text(statement))
                assert "permission denied" in str(excinfo.value)
    finally:
        engine.dispose()


def test_temp_audit_log_shadow_does_not_divert_audit_rows(migrated_pg_url, app_url):
    """Red-team attack A, with TEMPORARY granted back to prove the functions
    themselves resolve only public.audit_log."""
    _owner_exec(migrated_pg_url,
                f'GRANT TEMPORARY ON DATABASE "{_database(migrated_pg_url)}" TO "{_role(app_url)}"')
    engine = _engine(app_url)
    try:
        with engine.connect() as conn:
            conn.execute(text(
                "CREATE TEMP TABLE audit_log (id int, table_name text, record_id text, action text, "
                "old_values jsonb, new_values jsonb, changed_by text, changed_at timestamptz, "
                "previous_hash text, row_hash text, hash_version smallint)"))
            conn.execute(text("INSERT INTO controls (id, name, category) VALUES ('hijack', 'x', 'security')"))
            assert conn.execute(text("SELECT count(*) FROM pg_temp.audit_log")).scalar() == 0
    finally:
        engine.dispose()
    assert _scalar(migrated_pg_url,
                   "SELECT count(*) FROM public.audit_log WHERE record_id = 'hijack'") == 1


def test_audit_trigger_cannot_be_attached_to_temp_tables(migrated_pg_url, app_url):
    """Red-team attack B: forging audit rows by attaching the trigger to a temp table."""
    _owner_exec(migrated_pg_url,
                f'GRANT TEMPORARY ON DATABASE "{_database(migrated_pg_url)}" TO "{_role(app_url)}"')
    engine = _engine(app_url)
    try:
        with engine.connect() as conn:
            conn.execute(text("CREATE TEMP TABLE controls (id text, name text)"))
            with pytest.raises(Exception) as excinfo:
                conn.execute(text("CREATE TRIGGER forge AFTER INSERT ON pg_temp.controls "
                                  "FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_func()"))
            assert "permission denied" in str(excinfo.value)
    finally:
        engine.dispose()


def test_audit_trigger_refuses_tables_outside_public(migrated_pg_url, app_url):
    """Defence in depth: even with EXECUTE granted, the function refuses non-public tables."""
    role = _role(app_url)
    _owner_exec(migrated_pg_url,
                f'GRANT TEMPORARY ON DATABASE "{_database(migrated_pg_url)}" TO "{role}"',
                f'GRANT EXECUTE ON FUNCTION public.audit_trigger_func() TO "{role}"')
    before = _scalar(migrated_pg_url, "SELECT count(*) FROM audit_log")
    engine = _engine(app_url)
    try:
        with engine.connect() as conn:
            conn.execute(text("CREATE TEMP TABLE controls (id text, name text)"))
            conn.execute(text("CREATE TRIGGER forge AFTER INSERT ON pg_temp.controls "
                              "FOR EACH ROW EXECUTE FUNCTION public.audit_trigger_func()"))
            with pytest.raises(Exception) as excinfo:
                conn.execute(text("INSERT INTO pg_temp.controls VALUES ('c1', 'forged')"))
            assert "schema public" in str(excinfo.value)
    finally:
        engine.dispose()
    assert _scalar(migrated_pg_url, "SELECT count(*) FROM audit_log") == before


@pytest.mark.parametrize("statement, message", [
    ("INSERT INTO public.audit_log (table_name, record_id, action) VALUES ('x', 'y', 'INSERT')",
     "permission denied"),
    ("UPDATE public.audit_log SET action = 'X'", "permission denied"),
    ("DELETE FROM public.audit_log", "permission denied"),
    ("TRUNCATE public.audit_log", "permission denied"),
    ("ALTER TABLE public.controls DISABLE TRIGGER audit_controls", "must be owner"),
    ("SET session_replication_role = replica", "permission denied"),
    ("SELECT public.audit_log_insert_anchor('a', repeat('a', 64), repeat('b', 64), 1, "
     "'archives/x/y.manifest.json', repeat('c', 64), NULL)",
     "permission denied"),
])
def test_app_role_bypass_attempts_fail(migrated_pg_url, app_url, statement, message):
    engine = _engine(app_url)
    try:
        with engine.connect() as conn:
            with pytest.raises(Exception) as excinfo:
                conn.execute(text(statement))
            assert message in str(excinfo.value)
    finally:
        engine.dispose()


def test_audited_writes_by_the_app_role_keep_a_valid_chain(migrated_pg_url, app_url):
    engine = _engine(app_url)
    try:
        with engine.connect() as conn:
            conn.execute(text("INSERT INTO controls (id, name, category) VALUES ('c1', 'MFA', 'security')"))
            conn.execute(text("UPDATE controls SET name = 'MFA everywhere' WHERE id = 'c1'"))
            conn.execute(text("DELETE FROM controls WHERE id = 'c1'"))
    finally:
        engine.dispose()
    from sqlalchemy.orm import Session

    owner = create_engine(migrated_pg_url)
    with Session(owner) as session:
        result = verify_chain(session)
    owner.dispose()
    assert result["status"] == "valid" and result["verified"] == 3


# --------------------------------------------------------------------------
# Finding 12: chain lock is taken before any row lock (no deadlock)
# --------------------------------------------------------------------------

def test_row_lock_then_chain_lock_cannot_deadlock(migrated_pg_url, app_url):
    setup = _engine(app_url)
    with setup.connect() as conn:
        conn.execute(text("INSERT INTO controls (id, name, category) VALUES "
                          "('x', 'x0', 'security'), ('y', 'y0', 'security')"))
    setup.dispose()

    engine_a, engine_b = create_engine(app_url), create_engine(app_url)
    errors = []
    b_started = threading.Event()

    def session_b():
        try:
            with engine_b.connect() as conn:
                b_started.set()
                conn.execute(text("UPDATE controls SET name = 'B1' WHERE id = 'y'"))
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    try:
        with engine_a.connect() as conn_a:
            conn_a.execute(text("UPDATE controls SET name = 'A1' WHERE id = 'x'"))
            thread = threading.Thread(target=session_b)
            thread.start()
            b_started.wait(5)
            time.sleep(0.5)  # B is now waiting
            conn_a.execute(text("UPDATE controls SET name = 'A2' WHERE id = 'y'"))
            conn_a.commit()
        thread.join(15)
    except Exception as exc:  # noqa: BLE001
        errors.append(exc)
    finally:
        engine_a.dispose()
        engine_b.dispose()
    assert not errors, errors
    assert _scalar(migrated_pg_url, "SELECT name FROM controls WHERE id = 'y'") == "B1"


def test_every_audited_table_takes_the_chain_lock_first(migrated_pg_url):
    audited = _scalar(migrated_pg_url, """
        SELECT count(DISTINCT tgrelid) FROM pg_trigger
        WHERE tgname LIKE 'audit\\_%' ESCAPE '\\' AND tgname NOT LIKE 'audit_lock\\_%' ESCAPE '\\'
          AND tgrelid <> 'public.audit_log'::regclass AND NOT tgisinternal""")
    locked = _scalar(migrated_pg_url, """
        SELECT count(DISTINCT tgrelid) FROM pg_trigger
        WHERE tgname LIKE 'audit_lock\\_%' ESCAPE '\\' AND NOT tgisinternal""")
    # Every audited table, plus the link tables holding foreign keys to audited rows.
    assert audited >= 20 and locked == audited + 2


# --------------------------------------------------------------------------
# Finding 16: binary and bulky columns enter audit_log as digests only
# --------------------------------------------------------------------------

def test_binary_and_bulky_columns_are_digested(migrated_pg_url, app_url):
    engine = _engine(app_url)
    secret_bytes = "AKIA-FILE-CONTENT-" + uuid.uuid4().hex
    try:
        with engine.connect() as conn:
            conn.execute(text("INSERT INTO controls (id, name, category) VALUES ('c1', 'C', 'security')"))
            conn.execute(text("INSERT INTO test_records (id, name, control_id) VALUES ('t1', 'T', 'c1')"))
            conn.execute(text(
                "INSERT INTO evidence (id, test_record_id, evidence_type, file_data) "
                "VALUES ('e1', 't1', 'file', convert_to(:d, 'UTF8'))"), {"d": secret_bytes})
            conn.execute(text("INSERT INTO decision_log_sessions (id) VALUES ('s1')"))
            conn.execute(text(
                "INSERT INTO decision_log_entries (session_id, role, content_text, tool_calls) "
                "VALUES ('s1', 'user', :t, '[]')"), {"t": "prompt text " + secret_bytes})
            conn.execute(text(
                "INSERT INTO decision_log_transcripts (id, session_id, status, entry_count, content_gz) "
                "VALUES ('v1', 's1', 'superseded', 1, convert_to(:d, 'UTF8'))"), {"d": secret_bytes})
    finally:
        engine.dispose()
    rows = create_engine(migrated_pg_url).connect().execute(text(
        "SELECT table_name, new_values::text FROM audit_log "
        "WHERE table_name IN ('evidence', 'decision_log_entries', 'decision_log_transcripts')")).all()
    # Decision-log entries are audited per stored version (decision_log_transcripts), not per row.
    assert {r[0] for r in rows} == {"evidence", "decision_log_transcripts"}
    for _, values in rows:
        assert secret_bytes not in values
        assert "sha256:" in values
    hex_bytes = secret_bytes.encode().hex()
    for _, values in rows:
        assert hex_bytes not in values


# --------------------------------------------------------------------------
# D-A: the serving process must not hold owner rights
# --------------------------------------------------------------------------

def test_serving_role_check(migrated_pg_url, app_url):
    from cli.db_cmd import serving_role_problems

    owner_problems = serving_role_problems(migrated_pg_url)
    assert any("owns the audited tables" in p for p in owner_problems)
    assert serving_role_problems(app_url) == []


def test_production_refuses_to_serve_as_owner(migrated_pg_url, app_url, monkeypatch):
    from app import create_app
    from app.config import TestConfig
    from app.runtime_config import ConfigurationError
    from app.serving import enforce_serving_role

    class OwnerConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = migrated_pg_url

    class AppRoleConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = app_url

    monkeypatch.setattr("app.serving.is_production", lambda: True)
    with pytest.raises(ConfigurationError, match="audit trail"):
        enforce_serving_role(create_app(OwnerConfig))
    assert enforce_serving_role(create_app(AppRoleConfig)) == []
    monkeypatch.setattr("app.serving.is_production", lambda: False)
    assert enforce_serving_role(create_app(OwnerConfig))  # warning only


def test_db_check_role_command(migrated_pg_url, app_url, monkeypatch):
    from app import runtime_config
    from cli.__main__ import main

    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.delenv("PORTAL_SECRET_ID", raising=False)
    runtime_config._reset_for_tests()
    monkeypatch.setenv("DATABASE_URL", migrated_pg_url)
    assert main(["db-check-role"]) == 1
    monkeypatch.setenv("DATABASE_URL", app_url)
    assert main(["db-check-role"]) == 0


def test_owner_keys_in_the_runtime_secret_are_ignored(monkeypatch):
    import json

    from app import runtime_config

    for name in ("DATABASE_OWNER_USER", "DATABASE_OWNER_PASSWORD", "DATABASE_OWNER_URL", "PORTAL_SECRET_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    runtime_config._reset_for_tests()
    with mock_aws():
        boto3.client("secretsmanager", region_name="us-east-1").create_secret(
            Name="rt", SecretString=json.dumps({"DATABASE_OWNER_USER": "master",
                                                "DATABASE_OWNER_PASSWORD": "pw",
                                                "DATABASE_OWNER_URL": "postgresql://m:pw@h/db"}))
        monkeypatch.setenv("PORTAL_SECRET_ID", "rt")
        assert runtime_config.load_runtime_environment() == []
    assert runtime_config.owner_database_url() is None
    runtime_config._reset_for_tests()


# --------------------------------------------------------------------------
# D-B: forks after serialization and the external witness
# --------------------------------------------------------------------------

def test_mislinked_rows_after_serialization_are_true_breaks(pg_app):
    from app.models import Control, db

    for name in ("a", "b", "c"):
        db.session.add(Control(id=name, name=name, category="security"))
        db.session.commit()
    rows = db.session.execute(text("SELECT id, row_hash FROM audit_log ORDER BY id")).all()
    db.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    db.session.execute(text("UPDATE audit_log SET previous_hash = :h WHERE id = :i"),
                       {"h": rows[0].row_hash, "i": rows[2].id})
    db.session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    db.session.commit()
    result = verify_chain(db.session)
    assert result["forks"] == 0 and result["true_breaks"] == 1
    assert result["first_true_break_id"] == rows[2].id
    assert result["status"] == "broken"


@mock_aws
def test_witness_publish_and_detect_truncated_tail(pg_app, monkeypatch):
    from app.models import Control, db
    from app.services import audit_witness

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="witness")
    monkeypatch.setenv("AUDIT_WITNESS_BUCKET", "witness")
    audit_witness.arm(db.session, note="test")
    db.session.commit()

    db.session.add(Control(id="c1", name="one", category="security"))
    db.session.commit()
    publisher = audit_witness.PeriodicPublisher()
    first = publisher(pg_app)
    assert first and publisher(pg_app) is None  # unchanged head: nothing new
    db.session.add(Control(id="c2", name="two", category="security"))
    db.session.commit()
    second = publisher(pg_app)
    assert second["head"]["id"] > first["head"]["id"]

    cid = audit_witness.chain_id(db.session)
    assert first["key"].startswith(f"chain-heads/{cid}/")
    assert first["key"].endswith(f"-{first['head']['id']}.json")
    heads = audit_witness.load_heads_s3("witness", cid, client=s3)
    assert len(heads["valid"]) == 2 and heads["invalid"] == []
    assert verify_chain(db.session, witness_heads=heads)["status"] == "valid"

    # The owner rewrites the tail: removes the newest row. The chain alone still
    # verifies, but the published head no longer matches.
    db.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    db.session.execute(text("DELETE FROM audit_log WHERE id = :i"), {"i": second["head"]["id"]})
    db.session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    db.session.commit()
    assert verify_chain(db.session)["status"] == "valid"
    tampered = verify_chain(db.session, witness_heads=heads)
    assert tampered["status"] == "broken"
    assert tampered["witness_mismatches"] == 1
    assert tampered["first_witness_mismatch_id"] == second["head"]["id"]
    assert tampered["witness"]["mismatches"][0]["issue"] == "row missing"


def test_witness_heads_from_file_and_api(pg_app, tmp_path):
    import json

    from app.models import Control, db
    from app.services import audit_witness, team_service

    db.session.add(Control(id="c1", name="one", category="security"))
    db.session.commit()
    head = audit_witness.current_head(db.session)
    key = audit_witness.object_key(head)
    entry = {"key": key, "version_id": None, "head": head}
    (tmp_path / "heads.jsonl").write_text(json.dumps({"key": key, "head": head}) + "\n")
    mirrored = tmp_path / "dir" / key
    mirrored.parent.mkdir(parents=True)
    mirrored.write_text(json.dumps(head))
    assert audit_witness.load_heads_file(str(tmp_path / "heads.jsonl")) == {"valid": [entry], "invalid": []}
    assert audit_witness.load_heads_file(str(tmp_path / "dir")) == {"valid": [entry], "invalid": []}
    forged = dict(head, row_hash="f" * 64)
    (tmp_path / "forged.json").write_text(json.dumps([{"key": key, "head": forged}]))
    assert audit_witness.load_heads_file(str(tmp_path / "forged.json"))["valid"][0]["head"] == forged
    (tmp_path / "bad.json").write_text(json.dumps([{"key": key, "head": {"id": "x"}}]))
    assert audit_witness.load_heads_file(str(tmp_path / "bad.json"))["invalid"][0]["key"] == key
    (tmp_path / "bare.json").write_text(json.dumps([head]))  # a head without its object key
    with pytest.raises(audit_witness.WitnessError):
        audit_witness.load_heads_file(str(tmp_path / "bare.json"))

    admin = team_service.create_member("Admin", "a@example.com", "human", is_compliance_admin=True)
    client = pg_app.test_client()
    headers = {"X-API-Key": admin.issued_api_key}
    ok = client.post("/api/audit-log/verify", json={"heads": [{"key": key, "head": head}]},
                     headers=headers).get_json()
    assert ok["status"] == "valid" and ok["witness"]["checked"] == 1
    bad = client.post("/api/audit-log/verify", json={"heads": [{"key": key, "head": forged}]},
                      headers=headers).get_json()
    assert bad["status"] == "broken" and bad["witness_mismatches"] == 1
    for malformed in ([{"key": key, "head": {"id": "x"}}], [head], [{"key": key.replace("-", "_"), "head": head}]):
        assert client.post("/api/audit-log/verify", json={"heads": malformed},
                           headers=headers).status_code == 400
    other = dict(head, chain_id="0" * 16)
    scan = {"valid": [{"key": audit_witness.object_key(other), "version_id": None, "head": other}], "invalid": []}
    assert audit_witness.check_heads(db.session, scan)["other_chain"] == 1
    # There is no HTTP anchor endpoint.
    assert client.post("/api/audit-log/anchor", json={}, headers=headers).status_code in (404, 405)


def test_anchor_is_owner_only_and_records_the_anchoring_role(migrated_pg_url, app_url):
    engine = _engine(app_url)
    try:
        with engine.connect() as conn:
            with pytest.raises(Exception, match="permission denied"):
                conn.execute(text("SELECT public.audit_log_insert_anchor('a', repeat('a', 64), "
                                  "repeat('b', 64), 1, 'archives/x/y.manifest.json', repeat('c', 64), NULL)"))
    finally:
        engine.dispose()
    _owner_exec(migrated_pg_url,
                "SELECT public.audit_log_insert_anchor('arch-1', repeat('a', 64), repeat('b', 64), 7, "
                "'archives/x/y.manifest.json', repeat('c', 64), 'cutover')")
    anchored_by = _scalar(migrated_pg_url,
                          "SELECT new_values->>'anchored_by' FROM audit_log WHERE action = 'ANCHOR'")
    assert anchored_by == _role(migrated_pg_url)


@mock_aws
def test_cli_anchor_runs_as_owner_and_publishes(migrated_pg_url, app_url, monkeypatch, tmp_path):
    from app import runtime_config
    from cli.__main__ import main

    for name in ("PORTAL_SECRET_ID", "DATABASE_OWNER_USER", "DATABASE_OWNER_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="witness", ObjectLockEnabledForBucket=True)
    monkeypatch.setenv("AUDIT_WITNESS_BUCKET", "witness")
    runtime_config._reset_for_tests()
    monkeypatch.setenv("DATABASE_URL", app_url)
    monkeypatch.setenv("DATABASE_OWNER_URL", migrated_pg_url)
    assert main(["create-admin", "--name", "Ops", "--email", "ops@example.com",
                 "--key-file", str(tmp_path / "ops.key")]) == 0  # app-role writes
    dump = tmp_path / "final.dump"
    dump.write_bytes(b"-- dump")
    assert main(["audit-archive-manifest", "--dump", str(dump), "--name", "final.dump"]) == 0
    _owner_exec(migrated_pg_url, "ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only",
                "DELETE FROM audit_log", "ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only")
    manifest = [o["Key"] for o in s3.list_objects_v2(Bucket="witness", Prefix="archives/")["Contents"]
                if o["Key"].endswith(".manifest.json")]
    assert main(["audit-anchor", "--manifest", manifest[0]]) == 0  # as the owner; EXECUTE is owner-only
    assert _scalar(migrated_pg_url, "SELECT new_values->>'anchored_by' FROM audit_log "
                                    "WHERE action = 'ANCHOR'") == _role(migrated_pg_url)
    heads = [o["Key"] for o in s3.list_objects_v2(Bucket="witness", Prefix="chain-heads/")["Contents"]]
    assert len(heads) == 2  # the archived chain's final head and the anchored chain's first
    assert main(["audit-publish-head"]) == 0
    monkeypatch.delenv("AUDIT_WITNESS_BUCKET")
    assert main(["audit-publish-head"]) == 2


def test_heartbeat_only_updates_are_not_audited(pg_app):
    from datetime import datetime, timezone

    from app.models import db
    from app.models.collector_config import CollectorConfig
    from app.models.collector_run import CollectorRun

    config = CollectorConfig(id=str(uuid.uuid4()), name="policy", enabled=True, credential_mode="none")
    db.session.add(config)
    db.session.commit()
    run = CollectorRun(id=str(uuid.uuid4()), collector_config_id=config.id, status="running")
    db.session.add(run)
    db.session.commit()
    before = db.session.execute(text("SELECT count(*) FROM audit_log")).scalar()
    for _ in range(3):
        run.heartbeat_at = datetime.now(timezone.utc)
        db.session.commit()
    assert db.session.execute(text("SELECT count(*) FROM audit_log")).scalar() == before
    run.status = "success"
    db.session.commit()
    assert db.session.execute(text("SELECT count(*) FROM audit_log")).scalar() == before + 1


def test_scheduler_registers_the_witness_publisher(pg_app, monkeypatch):
    from app.services import scheduler

    monkeypatch.setattr(scheduler, "ELECTION_INTERVAL", 0.01)
    scheduler.unregister_periodic("audit_witness")
    service = scheduler.start_background(pg_app)
    try:
        assert "audit_witness" in {task.name for task in scheduler.periodic_tasks()}
    finally:
        scheduler.stop_background()
        scheduler.unregister_periodic("audit_witness")
    assert service is not None


# --------------------------------------------------------------------------
# Round 2: operator hijack (N2) and the full serving-role check (N4)
# --------------------------------------------------------------------------

def test_operator_planted_in_public_is_never_resolved(migrated_pg_url, app_url):
    """Red-team N2: a role with CREATE on schema public plants `varchar || name`
    (no exact match in pg_catalog) to run code as the trigger function's owner."""
    role = _role(app_url)
    _owner_exec(migrated_pg_url, f'GRANT CREATE ON SCHEMA public TO "{role}"',
                "INSERT INTO controls (id, name, category) VALUES ('x', 'x0', 'security')")
    engine = _engine(app_url)
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                CREATE FUNCTION public.rt_cat(a varchar, b name) RETURNS text LANGUAGE plpgsql AS $$
                BEGIN
                    IF current_user <> session_user THEN
                        EXECUTE 'ALTER TABLE public.controls DISABLE TRIGGER audit_controls';
                    END IF;
                    RETURN a::text || b::text;
                END $$"""))
            conn.execute(text("CREATE OPERATOR public.|| (LEFTARG = varchar, RIGHTARG = name, "
                              "FUNCTION = public.rt_cat)"))
            conn.execute(text("UPDATE public.controls SET name = 'x1' WHERE id = 'x'"))
    finally:
        engine.dispose()
    assert _scalar(migrated_pg_url,
                   "SELECT tgenabled FROM pg_trigger WHERE tgname = 'audit_controls'") == "O"
    assert _scalar(migrated_pg_url,
                   "SELECT count(*) FROM audit_log WHERE record_id = 'x' AND action = 'UPDATE'") == 1
    from app.models import db  # noqa: F401 - keep the app models importable here
    from cli.db_cmd import serving_role_problems

    assert any("create objects in schema" in p for p in serving_role_problems(app_url))


@pytest.mark.parametrize("grant, expected", [
    ('GRANT TEMPORARY ON DATABASE "{db}" TO "{role}"', "TEMPORARY"),
    ('GRANT CREATE ON SCHEMA public TO "{role}"', "create objects in schema"),
    ('GRANT TRIGGER ON public.controls TO "{role}"', "TRIGGER on"),
    ('GRANT pg_write_all_data TO "{role}"', "INSERT on audit_log"),
    ('CREATE ROLE "{role}_own"; ALTER TABLE public.git_commits OWNER TO "{role}_own"; '
     'GRANT "{role}_own" TO "{role}" WITH INHERIT FALSE, SET FALSE', "owns portal objects"),
    ('ALTER ROLE "{role}" CREATEROLE', "CREATEROLE"),
    ('CREATE SEQUENCE public.rt_owned_seq; ALTER SEQUENCE public.rt_owned_seq OWNER TO "{role}"',
     "owns portal objects"),
    ('ALTER FUNCTION public.audit_chain_lock() OWNER TO "{role}"', "owns portal objects"),
    ('CREATE ROLE "{role}_own"; ALTER TABLE public.audit_log OWNER TO "{role}_own"; '
     'GRANT "{role}_own" TO "{role}"', "owns the audited tables"),
    # Round 4 (M4): every role the app role can SET ROLE to or inherits, and more capabilities.
    ('CREATE ROLE "{role}_w_own"; GRANT INSERT ON public.audit_log TO "{role}_w_own"; '
     'GRANT "{role}_w_own" TO "{role}" WITH INHERIT FALSE, SET TRUE', "INSERT on audit_log (via role"),
    ('CREATE ROLE "{role}_su_own" SUPERUSER; GRANT "{role}_su_own" TO "{role}" WITH INHERIT FALSE, SET TRUE',
     "superuser (via role"),
    ('ALTER ROLE "{role}" NOINHERIT; CREATE ROLE "{role}_ni_own"; '
     'GRANT UPDATE ON public.audit_log TO "{role}_ni_own"; GRANT "{role}_ni_own" TO "{role}"',
     "UPDATE on audit_log (via role"),
    ('CREATE ROLE "{role}_mid_own"; GRANT pg_write_all_data TO "{role}_mid_own"; '
     'GRANT "{role}_mid_own" TO "{role}" WITH INHERIT FALSE, SET TRUE', "DELETE on audit_log (via role"),
    ('GRANT INSERT (table_name, record_id, action, row_hash, previous_hash) ON public.audit_log TO "{role}"',
     "INSERT on audit_log"),
    ('GRANT INSERT ON public.audit_witness_arming TO "{role}"', "INSERT on audit_witness_arming"),
    ('GRANT CREATE ON DATABASE "{db}" TO "{role}"', "CREATE on the database"),
    ('GRANT MAINTAIN ON public.audit_log TO "{role}"', "MAINTAIN on audit_log"),
    ('GRANT pg_maintain TO "{role}"', "MAINTAIN on audit_log"),
    ('ALTER ROLE "{role}" REPLICATION', "REPLICATION"),
    ('GRANT pg_execute_server_program TO "{role}"', "pg_execute_server_program"),
    ('GRANT pg_write_server_files TO "{role}"', "pg_write_server_files"),
    ('ALTER DATABASE "{db}" OWNER TO "{role}"', "owns the database"),
])
def test_serving_role_check_catches_every_escalation(migrated_pg_url, app_url, grant, expected):
    from cli.db_cmd import serving_role_problems

    assert serving_role_problems(app_url) == []
    import os

    statement = grant.format(db=_database(migrated_pg_url), role=_role(app_url), owner=_role(migrated_pg_url))
    # Escalations are applied by the cluster superuser (an operator mistake), not the owner.
    superuser_url = make_url(os.environ["TEST_DATABASE_URL"]).set(database=_database(migrated_pg_url))
    _owner_exec(superuser_url.render_as_string(hide_password=False), *statement.split("; "))
    problems = serving_role_problems(app_url)
    assert any(expected in p for p in problems), problems


# --------------------------------------------------------------------------
# Round 2: the witness cannot be bypassed by replacing the chain (N1, N7, N6)
# --------------------------------------------------------------------------

def _witness_bucket(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="witness", ObjectLockEnabledForBucket=True)
    monkeypatch.setenv("AUDIT_WITNESS_BUCKET", "witness")
    return s3


def _arm():
    """Arm the witness (pg_app connects as the owner, who may execute audit_witness_arm)."""
    from app.models import db
    from app.services import audit_witness

    audit_witness.arm(db.session, note="test")
    db.session.commit()


def _owner_rewrite(sql, params=None):
    from app.models import db

    db.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    db.session.execute(text(sql), params or {})
    db.session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    db.session.commit()


@mock_aws
def test_witness_catches_delete_all_and_reanchor(pg_app, monkeypatch):
    from app.models import Control, db
    from app.services import audit_witness
    from app.services.audit_chain import insert_anchor

    s3 = _witness_bucket(monkeypatch)
    _arm()
    db.session.add(Control(id="c1", name="one", category="security"))
    db.session.commit()
    published = audit_witness.publish_head(db.session, client=s3)["head"]

    # The owner empties the audit log and starts a fresh chain with a fake anchor.
    _owner_rewrite("DELETE FROM audit_log")
    insert_anchor(db.session, archive_id="fake", archive_sha256="a" * 64,
                  archived_chain_head="b" * 64, archived_entries=0,
                  manifest_key="archives/x/y.manifest.json", manifest_sha256="c" * 64)
    db.session.commit()
    audit_witness.publish_head(db.session, client=s3)
    heads = audit_witness.load_heads_s3("witness", client=s3)
    assert len(heads["valid"]) == 2
    result = verify_chain(db.session, witness_heads=heads)
    assert result["status"] == "broken"
    assert any("no verified archive manifest of the current chain continues" in m["issue"]
               for m in result["witness"]["mismatches"])
    assert result["witness"]["mismatches"][0]["chain_id"] == published["chain_id"]


@mock_aws
def test_witness_catches_a_chain_recomputed_from_row_one(pg_app, monkeypatch):
    from app.models import Control, db
    from app.services import audit_witness

    s3 = _witness_bucket(monkeypatch)
    _arm()
    for name in ("a", "b"):
        db.session.add(Control(id=name, name=name, category="security"))
        db.session.commit()
    audit_witness.publish_head(db.session, client=s3)
    # Rewrite from row 1: delete everything, replay a different history.
    _owner_rewrite("DELETE FROM audit_log")
    db.session.execute(text("UPDATE controls SET name = 'rewritten' WHERE id = 'a'"))
    db.session.commit()
    result = verify_chain(db.session, witness_heads=audit_witness.load_heads_s3("witness", client=s3))
    assert result["status"] == "broken"
    assert result["witness"]["checked"] == 0
    assert result["witness_mismatches"] >= 1


@mock_aws
def test_witness_accepts_a_legitimately_anchored_predecessor(pg_app, monkeypatch):
    """The witness accepts a new database anchored at the archived chain's LAST
    published head; the anchor itself stays unverified until it is checked
    against its archive manifest (tests/test_audit_archive_pg.py)."""
    from app.models import Control, db
    from app.services import audit_witness
    from app.services.audit_chain import insert_anchor

    s3 = _witness_bucket(monkeypatch)
    _arm()
    db.session.add(Control(id="c1", name="one", category="security"))
    db.session.commit()
    last = audit_witness.publish_head(db.session, client=s3)["head"]
    _owner_rewrite("DELETE FROM audit_log")  # stands for: archive, then a fresh database
    insert_anchor(db.session, archive_id="archive-1", archive_sha256="c" * 64,
                  archived_chain_head=last["row_hash"], archived_entries=last["id"],
                  manifest_key="archives/x/y.manifest.json", manifest_sha256="c" * 64)
    db.session.commit()
    audit_witness.publish_head(db.session, client=s3)
    result = verify_chain(db.session, witness_heads=audit_witness.load_heads_s3("witness", client=s3))
    assert result["status"] == "unverified", result["witness"]
    assert result["witness"]["mismatches"] == [] and result["witness_mismatches"] == 0
    assert result["witness"]["checked"] == 1
    # Without the manifest check the archived chain is only an unverified continuation.
    assert result["witness"]["continued_chains"] == []
    assert result["witness"]["unverified_continuations"][0]["chain_id"] == last["chain_id"]


def test_heads_without_a_head_of_the_current_chain_fail(pg_app):
    from app.models import Control, db
    from app.services import audit_witness

    db.session.add(Control(id="c1", name="one", category="security"))
    db.session.commit()
    foreign = {"format": audit_witness.FORMAT, "chain_id": "f" * 16, "id": 1, "row_hash": "e" * 64,
               "published_at": "2026-10-01T00:00:00Z"}
    scan = audit_witness.heads_from_items([{"key": audit_witness.object_key(foreign), "head": foreign}],
                                          strict=True)
    result = verify_chain(db.session, witness_heads=scan)
    assert result["status"] == "broken"
    issues = [m["issue"] for m in result["witness"]["mismatches"]]
    assert any("none belongs to the current chain" in i for i in issues)
    assert verify_chain(db.session, witness_heads=audit_witness.empty_scan())["status"] == "valid"
    assert audit_witness.check_heads(db.session, audit_witness.empty_scan())["mismatches"] == []


@mock_aws
def test_head_objects_are_written_if_none_match_and_all_versions_are_read(pg_app, monkeypatch):
    from app.models import Control, db
    from app.services import audit_witness

    s3 = _witness_bucket(monkeypatch)
    calls = []
    real_put = s3.put_object

    def recording_put(**kwargs):
        calls.append(kwargs)
        return real_put(**kwargs)

    monkeypatch.setattr(s3, "put_object", recording_put)
    _arm()
    db.session.add(Control(id="c1", name="one", category="security"))
    db.session.commit()
    first = audit_witness.publish_head(db.session, client=s3)
    assert calls[0]["IfNoneMatch"] == "*" and calls[0]["ChecksumAlgorithm"] == "SHA256"
    # A head object overwritten without the condition (bucket policy bypassed) leaves the
    # original as an older version; the verifier reads every version.
    forged = dict(first["head"], row_hash="0" * 64)
    real_put(Bucket="witness", Key=first["key"], Body=json.dumps(forged).encode())
    heads = audit_witness.load_heads_s3("witness", client=s3)
    assert sorted(e["head"]["row_hash"] for e in heads["valid"]) == sorted([first["head"]["row_hash"], "0" * 64])
    assert verify_chain(db.session, witness_heads=heads)["status"] == "broken"


def test_publish_ends_the_read_transaction_before_the_s3_call(pg_app, monkeypatch):
    from app.models import Control, db
    from app.services import audit_witness

    monkeypatch.setenv("AUDIT_WITNESS_BUCKET", "witness")
    _arm()
    db.session.add(Control(id="c1", name="one", category="security"))
    db.session.commit()
    seen = {}

    class Client:
        def put_object(self, **kwargs):
            seen["in_transaction"] = db.session().in_transaction()
            return {}

    audit_witness.publish_head(db.session, client=Client())
    assert seen == {"in_transaction": False}
    config = audit_witness.s3_client().meta.config
    assert config.connect_timeout == 5 and config.read_timeout == 15
    assert config.retries.get("max_attempts", config.retries.get("total_max_attempts")) in (3, 4)
    assert config.retries["mode"] == "standard"


def test_verify_api_is_admin_only_and_bounded(pg_app):
    from app.models import db
    from app.services import team_service

    human = team_service.create_member("Human", "h@example.com", "human")
    admin = team_service.create_member("Admin", "a@example.com", "human", is_compliance_admin=True)
    client = pg_app.test_client()
    assert client.get("/api/audit-log/verify", headers={"X-API-Key": human.issued_api_key}).status_code == 403
    headers = {"X-API-Key": admin.issued_api_key}
    too_many = [{"chain_id": "a" * 16, "id": i, "row_hash": "b" * 64} for i in range(10_001)]
    assert client.post("/api/audit-log/verify", json={"heads": too_many}, headers=headers).status_code == 400
    big = client.get("/api/audit-log/verify?max_rows=5000000", headers=headers).get_json()
    assert big["complete"] is True  # capped, and this chain is short
    db.session.remove()


def test_forks_carry_their_reason(pg_app):
    from app.models import db

    genesis = "0" * 64
    db.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    for rid, prev in (("a", genesis), ("b", genesis)):
        db.session.execute(text(
            "INSERT INTO audit_log (table_name, record_id, action, new_values, previous_hash, row_hash) "
            "SELECT 'controls', CAST(:r AS varchar), 'INSERT', '{}'::jsonb, CAST(:p AS varchar), "
            "encode(sha256(convert_to(CAST(:p AS text) || 'controls' || CAST(:r AS text) || 'INSERT' || "
            "('{}'::jsonb)::text, 'UTF8')), 'hex')"), {"r": rid, "p": prev})
    db.session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    db.session.commit()
    result = verify_chain(db.session)
    assert result["status"] == "intact_with_forks" and result["forks"] == 1
    assert "unserialized trigger" in result["fork_reason"]


# --------------------------------------------------------------------------
# Round 2: remaining deadlock shapes (M12)
# --------------------------------------------------------------------------

def _two_sessions(app_url, first_a, second_a, statements_b):
    """A runs first_a, waits for B to start statements_b, then runs second_a."""
    engine_a, engine_b = create_engine(app_url), create_engine(app_url)
    errors, b_started = [], threading.Event()

    def session_b():
        try:
            with engine_b.connect() as conn:
                b_started.set()
                for statement in statements_b:
                    conn.execute(text(statement))
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    try:
        with engine_a.connect() as conn_a:
            for statement in first_a:
                conn_a.execute(text(statement))
            thread = threading.Thread(target=session_b)
            thread.start()
            b_started.wait(5)
            time.sleep(0.5)
            for statement in second_a:
                conn_a.execute(text(statement))
            conn_a.commit()
        thread.join(15)
    except Exception as exc:  # noqa: BLE001
        errors.append(exc)
    finally:
        engine_a.dispose()
        engine_b.dispose()
    return errors


def test_link_table_write_then_audited_write_cannot_deadlock(migrated_pg_url, app_url):
    """Red-team M12 shape 2: an insert into policy_controls (key-share lock on an
    audited control) before an audited write, racing a writer that deletes that control."""
    _owner_exec(migrated_pg_url,
                "INSERT INTO controls (id, name, category) VALUES ('x', 'x', 'security'), "
                "('c2', 'c2', 'security'), ('fk1', 'fk1', 'security')",
                "INSERT INTO policies (id, title, category) VALUES ('p1', 'P', 'security')")
    errors = _two_sessions(
        app_url,
        ["INSERT INTO policy_controls (policy_id, control_id) VALUES ('p1', 'fk1')"],
        ["UPDATE controls SET name = 'A after link' WHERE id = 'x'"],
        ["UPDATE controls SET name = 'B' WHERE id = 'c2'",
         "DELETE FROM controls WHERE id = 'fk1'"],
    )
    # B's delete of the now-linked control is refused by the foreign key; nobody deadlocks.
    assert not [e for e in errors if "deadlock" in str(e)], errors
    assert all("foreign key" in str(e) for e in errors), errors
    assert _scalar(migrated_pg_url, "SELECT name FROM controls WHERE id = 'x'") == "A after link"


def test_select_for_update_after_taking_the_chain_lock_cannot_deadlock(migrated_pg_url, app_url):
    """Red-team M12 shape 1: SELECT ... FOR UPDATE on an audited row, then an audited write.
    Code that row-locks audited rows takes the chain lock first (lock_audit_chain)."""
    from app.services.audit_chain import AUDIT_CHAIN_LOCK_KEY

    _owner_exec(migrated_pg_url,
                "INSERT INTO controls (id, name, category) VALUES ('x', 'x', 'security'), ('y', 'y', 'security')")
    errors = _two_sessions(
        app_url,
        [f"SELECT pg_advisory_xact_lock({AUDIT_CHAIN_LOCK_KEY})",
         "SELECT id FROM controls WHERE id = 'y' FOR UPDATE"],
        ["UPDATE controls SET name = 'A2' WHERE id = 'x'"],
        ["UPDATE controls SET name = 'B1' WHERE id = 'y'"],
    )
    assert not errors, errors


def test_lock_audit_chain_helper(pg_app):
    from app.models import db
    from app.services.audit_chain import AUDIT_CHAIN_LOCK_KEY, lock_audit_chain

    lock_audit_chain(db.session)
    held = db.session.execute(text(
        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = :k "
        "AND pid = pg_backend_pid() AND granted"), {"k": AUDIT_CHAIN_LOCK_KEY}).scalar()
    db.session.rollback()
    assert held == 1


# --------------------------------------------------------------------------
# Round 2: explicit witness kill switch for throwaway databases
# --------------------------------------------------------------------------

@mock_aws
def test_witness_disabled_overrides_the_bucket_from_the_secret(pg_app, monkeypatch):
    from app import runtime_config
    from app.models import Control, db
    from app.services import audit_witness

    s3 = _witness_bucket(monkeypatch)
    # AUDIT_WITNESS_BUCKET arrives through the runtime secret; the kill switch is env-only.
    monkeypatch.delenv("AUDIT_WITNESS_BUCKET")
    s3_secrets = boto3.client("secretsmanager", region_name="us-east-1")
    s3_secrets.create_secret(Name="rt-witness", SecretString=json.dumps(
        {"AUDIT_WITNESS_BUCKET": "witness", "AUDIT_WITNESS_DISABLED": "false"}))
    monkeypatch.setenv("PORTAL_SECRET_ID", "rt-witness")
    monkeypatch.setenv("AUDIT_WITNESS_DISABLED", "true")
    runtime_config._reset_for_tests()
    try:
        assert "AUDIT_WITNESS_BUCKET" in runtime_config.load_runtime_environment()
        import os
        assert os.environ["AUDIT_WITNESS_DISABLED"] == "true"  # never taken from the secret
        db.session.add(Control(id="c1", name="one", category="security"))
        db.session.commit()
        assert audit_witness.witness_state() == "disabled"
        assert audit_witness.witness_bucket() is None
        assert audit_witness.publish_head(db.session, bucket="witness", client=s3) is None
        assert audit_witness.PeriodicPublisher()(pg_app) is None
        assert s3.list_objects_v2(Bucket="witness").get("KeyCount", 0) == 0
        health = pg_app.test_client().get("/api/health").get_json()
        assert health["witness"] == "disabled"
        monkeypatch.setenv("AUDIT_WITNESS_DISABLED", "false")
        assert audit_witness.witness_state() == "enabled"
        monkeypatch.delenv("AUDIT_WITNESS_BUCKET")
        assert audit_witness.witness_state() == "unconfigured"
    finally:
        monkeypatch.delenv("AUDIT_WITNESS_BUCKET", raising=False)
        runtime_config._reset_for_tests()


def test_production_warns_when_the_witness_is_disabled(monkeypatch, caplog):
    import logging

    from app import create_app, runtime_config

    for name in ("PORTAL_SECRET_ID", "BOOTSTRAP_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PORTAL_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "k" * 48)
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("AUDIT_WITNESS_DISABLED", "yes")
    runtime_config._reset_for_tests()
    with caplog.at_level(logging.WARNING, logger="app"):
        create_app()
    assert any("AUDIT_WITNESS_DISABLED is set" in r.getMessage() for r in caplog.records)
    runtime_config._reset_for_tests()
