"""Web hardening on PostgreSQL: concurrent authentication attempts never
exceed the rate-limit budget, logout revocation and public-section changes are
audited, concurrent deactivations always leave a usable admin, and CRUD
constraint violations answer 4xx."""

import hashlib
import threading
import time
import uuid

from sqlalchemy import create_engine, text

from app import create_app
from app.config import TestConfig
from app.models import db
from app.models.audit_log import AuditLog
from app.services import team_service

LIMIT = 5
THREADS = 24


def _pg_app(url, **overrides):
    class PgConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = url
        SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_size": THREADS, "max_overflow": 4}
        AUTH_RATE_LIMIT_ATTEMPTS = LIMIT

    for key, value in overrides.items():
        setattr(PgConfig, key, value)
    return create_app(PgConfig)


def _dispose(*apps):
    for app in apps:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()


def _race(apps, path, **request):
    barrier = threading.Barrier(THREADS)
    statuses = []
    lock = threading.Lock()

    def attempt(app):
        browser = app.test_client()
        barrier.wait()
        status = browser.post(path, **request).status_code
        with lock:
            statuses.append(status)

    threads = [threading.Thread(target=attempt, args=(apps[i % len(apps)],)) for i in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert len(statuses) == THREADS
    return statuses


def test_concurrent_attempts_never_exceed_the_budget(migrated_pg_url):
    token = "s" * 40
    apps = [_pg_app(migrated_pg_url, BOOTSTRAP_TOKEN=token) for _ in range(2)]
    try:
        logins = _race(apps, "/admin/login", data={"api_key": "wrong"})
        assert logins.count(401) == LIMIT and logins.count(429) == THREADS - LIMIT
        setups = _race(apps, "/api/setup", json={"name": "A", "email": "a@example.com"},
                       headers={"Authorization": "Bearer wrong"})
        assert setups.count(401) == LIMIT and setups.count(429) == THREADS - LIMIT
    finally:
        _dispose(*apps)


def test_concurrent_consumes_share_one_counter(migrated_pg_url):
    from app.services import rate_limit

    app = _pg_app(migrated_pg_url)
    barrier = threading.Barrier(THREADS)
    allowed = []

    def consume():
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "198.51.100.7"}):
            barrier.wait()
            allowed.append(rate_limit.consume("client_login"))
            db.session.remove()

    threads = [threading.Thread(target=consume) for _ in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    try:
        assert allowed.count(True) == LIMIT and len(allowed) == THREADS
    finally:
        _dispose(app)


def _audit_rows(table, record_id=None):
    query = AuditLog.query.filter_by(table_name=table)
    if record_id:
        query = query.filter_by(record_id=record_id)
    return query.order_by(AuditLog.id).all()


def test_logout_revocation_is_audited(pg_app):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    browser = pg_app.test_client()
    assert browser.post("/admin/login", data={"api_key": admin.issued_api_key}).status_code == 302
    copied = browser.get_cookie(pg_app.config["SESSION_COOKIE_NAME"]).value
    assert browser.post("/admin/logout").status_code == 302
    rows = [r for r in _audit_rows("team_members", admin.id) if r.action == "UPDATE"]
    assert any((r.new_values or {}).get("session_epoch") == 1 and r.changed_by == admin.id for r in rows)
    replay = pg_app.test_client()
    replay.set_cookie(pg_app.config["SESSION_COOKIE_NAME"], copied)
    assert replay.get("/admin/", headers={"Accept": "text/html"}).status_code == 302


def test_public_section_change_is_audited(pg_app):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    browser = pg_app.test_client()
    sections = ["overview", "controls", "risks"]
    resp = browser.put("/api/settings", headers={"X-API-Key": admin.issued_api_key},
                       json={"public_sections": sections})
    assert resp.status_code == 200
    rows = _audit_rows("portal_settings")
    assert rows and rows[-1].new_values["public_sections"] == sections
    assert rows[-1].changed_by == admin.id
    assert browser.get("/risks").status_code == 200


def _waiting_advisory_locks(conn):
    return conn.execute(text(
        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted")).scalar()


def test_concurrent_deactivations_leave_a_usable_admin(migrated_pg_url):
    app = _pg_app(migrated_pg_url)
    engine = create_engine(migrated_pg_url)
    first_id, second_id = str(uuid.uuid4()), str(uuid.uuid4())
    first_key = "k-" + uuid.uuid4().hex
    with engine.begin() as conn:
        for member_id, key in ((first_id, first_key), (second_id, "k-" + uuid.uuid4().hex)):
            conn.execute(text(
                "INSERT INTO team_members (id, name, email, role, api_key_hash, is_active, is_compliance_admin) "
                "VALUES (:id, 'Admin', :email, 'human', :h, true, true)"),
                {"id": member_id, "email": f"{member_id}@example.com",
                 "h": hashlib.sha256(key.encode()).hexdigest()})
    holder = engine.connect()
    observer = engine.connect()
    result = {}
    try:
        # A competing deactivation of the second admin holds the admin lock, uncommitted.
        tx = holder.begin()
        holder.execute(text("SELECT pg_advisory_xact_lock(:k)"),
                       {"k": getattr(team_service, "ADMIN_LOCK_KEY", 815000100)})
        holder.execute(text("UPDATE team_members SET is_active = false WHERE id = :id"), {"id": second_id})

        def racer():
            resp = app.test_client().post(f"/admin/team/{first_id}/deactivate",
                                          headers={"X-API-Key": first_key})
            result["status"] = resp.status_code

        thread = threading.Thread(target=racer)
        thread.start()
        deadline = time.monotonic() + 10
        while thread.is_alive() and time.monotonic() < deadline:
            if _waiting_advisory_locks(observer):
                break
            time.sleep(0.05)
        tx.commit()
        thread.join(10)
        assert not thread.is_alive()
        active = observer.execute(text(
            "SELECT count(*) FROM team_members WHERE is_compliance_admin AND is_active")).scalar()
        assert active == 1
    finally:
        holder.close()
        observer.close()
        engine.dispose()
        _dispose(app)


def test_crud_constraint_violations_are_client_errors(pg_app):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    headers = {"X-API-Key": admin.issued_api_key}
    browser = pg_app.test_client()
    assert browser.post("/api/tests", headers=headers,
                        json={"name": "n", "control_id": "missing-control"}).status_code == 400
    assert browser.post("/api/controls", headers=headers,
                        json={"id": "x" * 500, "name": "n", "category": "security"}).status_code == 400
    assert browser.post("/api/controls", headers=headers,
                        json={"id": "c1", "name": "n", "category": "security"}).status_code == 201
    assert browser.post("/api/controls", headers=headers,
                        json={"id": "c1", "name": "n", "category": "security"}).status_code == 409
    assert browser.put("/api/controls/c1", headers=headers, json={"name": "x" * 300}).status_code == 400
    assert browser.get("/api/controls/c1", headers=headers).get_json()["name"] == "n"
