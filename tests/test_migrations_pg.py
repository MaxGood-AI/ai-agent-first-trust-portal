"""Alembic migrations on PostgreSQL: a fresh database reaches head without
the app (and its scheduler) being created, and an existing revision-015
database upgrades in place with its data intact and API keys still valid."""

import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from cli.db_cmd import ROOT, run_migrations


def _alembic_config(url):
    cfg = Config(f"{ROOT}/alembic.ini")
    cfg.set_main_option("script_location", f"{ROOT}/migrations")
    cfg.attributes["configure_logging"] = False
    cfg.attributes["url_override"] = url
    return cfg


def test_fresh_database_upgrades_to_head_without_starting_the_app(pg_url, monkeypatch):
    import app as app_package

    def forbidden(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("migrations must not create the Flask app")

    monkeypatch.setattr(app_package, "create_app", forbidden)
    run_migrations(pg_url)

    engine = create_engine(pg_url)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "020"
        tables = set(inspect(conn).get_table_names())
        assert {"git_sources", "git_sync_runs", "auth_rate_limit", "audit_log"} <= tables
        columns = {c["name"]: c for c in inspect(conn).get_columns("team_members")}
        assert "api_key_hash" in columns and "key_rotation_required" in columns
        # Expand-only: the legacy column stays (nullable) until a later release drops it.
        assert columns["api_key"]["nullable"] is True
    engine.dispose()
    # Running again is a no-op.
    run_migrations(pg_url)


def test_upgrade_from_015_revokes_every_existing_key(pg_url):
    """Finding 1 / D-C: keys issued before 017 appear in plaintext in append-only
    audit rows, so none of them may authenticate after the upgrade."""
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "015")

    raw_key = "legacy-key-" + uuid.uuid4().hex
    member_id = str(uuid.uuid4())
    config_id = str(uuid.uuid4())
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO team_members (id, name, email, role, api_key, is_active, is_compliance_admin) "
            "VALUES (:id, 'Legacy Admin', 'legacy@example.com', 'human', :key, true, true)"),
            {"id": member_id, "key": raw_key})
        conn.execute(text(
            "INSERT INTO collector_config (id, name, enabled, credential_mode) "
            "VALUES (:id, 'policy', true, 'none')"), {"id": config_id})
        for status in ("running", "running", "success"):
            conn.execute(text(
                "INSERT INTO collector_run (id, collector_config_id, status) VALUES (:id, :c, :s)"),
                {"id": str(uuid.uuid4()), "c": config_id, "s": status})
        legacy_rows = conn.execute(text("SELECT count(*) FROM audit_log")).scalar()
        # The pre-016 trigger recorded the key in plaintext.
        leaked = conn.execute(text(
            "SELECT new_values->>'api_key' FROM audit_log WHERE table_name = 'team_members'")).scalar()
        assert leaked == raw_key
    engine.dispose()

    command.upgrade(cfg, "head")

    engine = create_engine(pg_url)
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT api_key, api_key_hash, key_rotation_required, is_active FROM team_members WHERE id = :id"),
            {"id": member_id}).mappings().first()
        assert row["api_key"] is None and row["api_key_hash"] is None
        assert row["key_rotation_required"] is True and row["is_active"] is True
        statuses = [r[0] for r in conn.execute(text("SELECT status FROM collector_run ORDER BY status"))]
        assert statuses == ["failure", "failure", "success"]
        # The revoking UPDATE was audited with digests only.
        rows = conn.execute(text(
            "SELECT old_values::text, new_values::text FROM audit_log "
            "WHERE table_name = 'team_members' AND hash_version = 2")).all()
        assert rows
        for old, new in rows:
            assert raw_key not in (old or "") and raw_key not in (new or "")
        assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar() > legacy_rows
        legacy_values = conn.execute(text(
            "SELECT new_values->>'api_key' FROM audit_log WHERE table_name = 'team_members' "
            "AND hash_version IS NULL")).scalars().all()
    engine.dispose()

    from app import create_app
    from app.config import TestConfig

    class UpgradedConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = pg_url

    app = create_app(UpgradedConfig)
    client = app.test_client()
    # Neither the key itself nor anything recovered from legacy audit rows authenticates.
    for candidate in [raw_key] + [v for v in legacy_values if v]:
        assert client.get("/api/collectors", headers={"X-API-Key": candidate}).status_code == 401
        assert client.post("/admin/login", data={"api_key": candidate}).status_code in (400, 401)
    with app.app_context():
        from app.models import db
        from app.services import team_service
        from app.services.audit_chain import verify_chain

        # No admin holds a usable key: first-admin setup is open again.
        assert team_service.admin_exists() is False
        member = team_service.regenerate_key(member_id)
        assert member.id == member_id and member.key_rotation_required is False
        assert team_service.admin_exists() is True
        new_key = member.issued_api_key
        assert verify_chain(db.session)["status"] == "valid"
        db.session.remove()
        db.engine.dispose()
    assert client.get("/api/collectors", headers={"X-API-Key": new_key}).status_code == 200


def test_migrations_skip_when_database_is_newer(pg_url):
    """D-D: an older image redeployed onto a newer schema neither fails nor downgrades."""
    from cli.db_cmd import run_migrations

    assert run_migrations(pg_url) == "upgraded"
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = '999'"))
    engine.dispose()
    assert run_migrations(pg_url) == "newer"

    from app import create_app
    from app.config import TestConfig

    class NewerConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = pg_url
        HEALTH_REQUIRE_SCHEMA_HEAD = True

    app = create_app(NewerConfig)
    resp = app.test_client().get("/api/health")
    assert resp.status_code == 200 and resp.get_json()["schema"] == "newer"
    with app.app_context():
        from app.models import db
        db.engine.dispose()


def test_revision_017_downgrade_is_refused(pg_url):
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")
    with pytest.raises(RuntimeError, match="irreversible"):
        command.downgrade(cfg, "016")


def test_health_requires_schema_at_head(pg_url):
    from app import create_app
    from app.config import TestConfig

    class HealthConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = pg_url
        HEALTH_REQUIRE_SCHEMA_HEAD = True

    app = create_app(HealthConfig)
    client = app.test_client()
    missing = client.get("/api/health")
    assert missing.status_code == 503 and missing.get_json()["schema"] == "missing"

    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "018")
    behind = client.get("/api/health")
    assert behind.status_code == 503 and behind.get_json()["schema"] == "behind"

    command.upgrade(cfg, "head")
    ok = client.get("/api/health")
    assert ok.status_code == 200, ok.get_json()
    assert ok.get_json() == {"status": "ok", "service": "trust-portal", "database": "connected",
                             "schema": "current", "version": "test", "witness": "unconfigured",
                             "last_published_at": None, "witness_stale": False}
    with app.app_context():
        from app.models import db
        db.engine.dispose()


def test_health_reports_unreachable_database():
    from app import create_app
    from app.config import TestConfig

    class DownConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = "postgresql://nobody:nothing@127.0.0.1:1/none"

    resp = create_app(DownConfig).test_client().get("/api/health")
    assert resp.status_code == 503
    assert resp.get_json()["database"] == "unreachable"


def test_unknown_revision_is_an_error_not_newer(pg_url, monkeypatch):
    """M7: only a well-formed revision id after this image's head counts as newer."""
    from app import runtime_config
    from cli.__main__ import main
    from cli.db_cmd import UnknownRevisionError, classify_revision, run_migrations

    assert run_migrations(pg_url) == "upgraded"
    assert classify_revision("999") == "newer"
    assert classify_revision("018") == "behind"
    for bogus in ("999_future", "abc", "0019x", ""):
        assert classify_revision(bogus) == "unknown"
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = 'garbage'"))
    engine.dispose()
    with pytest.raises(UnknownRevisionError):
        run_migrations(pg_url)
    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.delenv("PORTAL_SECRET_ID", raising=False)
    monkeypatch.setenv("DATABASE_URL", pg_url)
    runtime_config._reset_for_tests()
    assert main(["db-migrate"]) == 1

    from app import create_app
    from app.config import TestConfig

    class UnknownConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = pg_url
        HEALTH_REQUIRE_SCHEMA_HEAD = True

    app = create_app(UnknownConfig)
    resp = app.test_client().get("/api/health")
    assert resp.status_code == 503 and resp.get_json()["schema"] == "unknown"
    with app.app_context():
        from app.models import db
        db.engine.dispose()


def test_newer_database_skips_role_provisioning(pg_url, monkeypatch):
    from cli import db_cmd

    assert db_cmd.run_migrations(pg_url) == "upgraded"
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        conn.execute(text("UPDATE alembic_version SET version_num = '999'"))
    engine.dispose()
    calls = []
    monkeypatch.setattr(db_cmd, "provision_app_role", lambda *a, **k: calls.append(a))
    monkeypatch.setattr(db_cmd, "owner_database_url", lambda: pg_url, raising=False)
    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.delenv("PORTAL_SECRET_ID", raising=False)
    monkeypatch.setenv("DATABASE_URL", pg_url)
    monkeypatch.setenv("DATABASE_OWNER_URL", pg_url)
    from app import runtime_config
    runtime_config._reset_for_tests()
    assert db_cmd.run(type("Args", (), {"command": "db-migrate"})()) == 0
    assert calls == []


def test_blocked_migration_times_out_and_retries(pg_url, monkeypatch):
    """N8: a migration waiting on a lock gives up after lock_timeout and retries,
    instead of queueing every writer behind it."""
    import threading
    import time as real_time

    from cli import db_cmd

    command.upgrade(_alembic_config(pg_url), "018")
    monkeypatch.setattr(db_cmd, "MIGRATION_LOCK_TIMEOUT", "300ms")
    monkeypatch.setattr(db_cmd, "RETRY_DELAY_SECONDS", 0.2)
    holder = create_engine(pg_url)
    conn = holder.connect()
    conn.execute(text("SELECT count(*) FROM team_members"))  # 019 alters it; AccessShare held until released
    released = threading.Event()

    def release_later():
        real_time.sleep(1.0)
        conn.rollback()
        conn.close()
        released.set()

    thread = threading.Thread(target=release_later)
    thread.start()
    sleeps = []

    def recording_sleep(seconds):
        sleeps.append(seconds)
        real_time.sleep(seconds)

    assert db_cmd.run_migrations(pg_url, sleep=recording_sleep) == "upgraded"
    thread.join(5)
    holder.dispose()
    assert released.is_set() and sleeps  # at least one attempt timed out and was retried


def test_blocked_migration_gives_up_after_bounded_attempts(pg_url, monkeypatch):
    from cli import db_cmd

    command.upgrade(_alembic_config(pg_url), "018")
    monkeypatch.setattr(db_cmd, "MIGRATION_LOCK_TIMEOUT", "100ms")
    monkeypatch.setattr(db_cmd, "MIGRATION_ATTEMPTS", 2)
    holder = create_engine(pg_url)
    with holder.connect() as conn:
        conn.execute(text("SELECT count(*) FROM team_members"))
        with pytest.raises(Exception) as excinfo:
            db_cmd.run_migrations(pg_url, sleep=lambda s: None)
        assert "lock timeout" in str(excinfo.value)
        conn.rollback()
    holder.dispose()
