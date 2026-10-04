"""PostgreSQL-backed web hardening: the failed-authentication budget is shared
by separate processes, and first-admin bootstrap creates at most one admin
when requests race."""

import hashlib
import threading
import time
import uuid

import pytest
from sqlalchemy import create_engine, text

from app import create_app
from app.config import TestConfig
from app.models import db


def _pg_app(url, **overrides):
    class PgConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = url
        SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
        AUTH_RATE_LIMIT_ATTEMPTS = 3

    for key, value in overrides.items():
        setattr(PgConfig, key, value)
    return create_app(PgConfig)


def _engine_of(app):
    with app.app_context():
        return db.engine


def _dispose(*apps):
    for app in apps:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()


def test_failed_login_budget_is_shared_across_processes(migrated_pg_url):
    first, second = _pg_app(migrated_pg_url), _pg_app(migrated_pg_url)
    try:
        assert _engine_of(first) is not _engine_of(second)
        one, two = first.test_client(), second.test_client()
        assert one.post("/admin/login", data={"api_key": "wrong-1"}).status_code == 401
        assert one.post("/admin/login", data={"api_key": "wrong-2"}).status_code == 401
        assert two.post("/admin/login", data={"api_key": "wrong-3"}).status_code == 401
        assert two.post("/admin/login", data={"api_key": "wrong-4"}).status_code == 429
        assert one.post("/admin/login", data={"api_key": "wrong-5"}).status_code == 429
        assert one.post("/admin/client-login", data={"api_key": "wrong"}).status_code == 401
    finally:
        _dispose(first, second)


def _waiting_advisory_locks(conn):
    return conn.execute(text(
        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted")).scalar()


def test_racing_bootstrap_creates_one_admin(migrated_pg_url):
    token = "t" * 40
    app = _pg_app(migrated_pg_url, BOOTSTRAP_TOKEN=token)
    engine = create_engine(migrated_pg_url)
    holder = engine.connect()
    observer = engine.connect()
    result = {}
    try:
        # A competing bootstrap: holds the bootstrap lock while its admin is uncommitted.
        tx = holder.begin()
        from app.routes import setup as setup_module

        holder.execute(text("SELECT pg_advisory_xact_lock(:k)"),
                       {"k": getattr(setup_module, "BOOTSTRAP_LOCK_KEY", 0)})
        holder.execute(text(
            "INSERT INTO team_members (id, name, email, role, api_key_hash, is_active, is_compliance_admin) "
            "VALUES (:id, 'First', 'first@example.com', 'human', :h, true, true)"),
            {"id": str(uuid.uuid4()), "h": hashlib.sha256(uuid.uuid4().bytes).hexdigest()})

        def racer():
            resp = app.test_client().post("/api/setup", headers={"Authorization": f"Bearer {token}"},
                                          json={"name": "Second", "email": "second@example.com"})
            result["status"] = resp.status_code

        thread = threading.Thread(target=racer)
        thread.start()
        deadline = time.monotonic() + 10
        while thread.is_alive() and time.monotonic() < deadline:
            if _waiting_advisory_locks(observer):
                break
            time.sleep(0.05)
        tx.commit()
        thread.join(timeout=10)
        assert not thread.is_alive()
        assert result["status"] == 404
        admins = observer.execute(text(
            "SELECT count(*) FROM team_members WHERE is_compliance_admin")).scalar()
        assert admins == 1
    finally:
        holder.close()
        observer.close()
        engine.dispose()
        _dispose(app)


@pytest.mark.parametrize("keyed", [False, True])
def test_setup_opens_only_while_no_admin_holds_a_key(migrated_pg_url, keyed):
    token = "k" * 40
    app = _pg_app(migrated_pg_url, BOOTSTRAP_TOKEN=token)
    engine = create_engine(migrated_pg_url)
    try:
        with engine.begin() as conn:
            conn.execute(text(
                "INSERT INTO team_members (id, name, email, role, api_key_hash, is_active, "
                "is_compliance_admin, key_rotation_required) "
                "VALUES (:id, 'Admin', 'a@example.com', 'human', :h, true, true, :rot)"),
                {"id": str(uuid.uuid4()), "rot": not keyed,
                 "h": hashlib.sha256(uuid.uuid4().bytes).hexdigest() if keyed else None})
        client = app.test_client()
        assert client.get("/setup").status_code == (404 if keyed else 200)
        resp = client.post("/api/setup", headers={"Authorization": f"Bearer {token}"},
                           json={"name": "Owner", "email": "o@example.com"})
        assert resp.status_code == (404 if keyed else 201)
    finally:
        engine.dispose()
        _dispose(app)
