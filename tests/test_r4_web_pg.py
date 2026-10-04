"""Round-4 web hardening on PostgreSQL: repeated client sign-ins cannot flood the audit log."""

from sqlalchemy import create_engine, text

from app import create_app
from app.config import TestConfig
from app.models import db
from app.services import team_service


def _audit_rows(url):
    engine = create_engine(url)
    with engine.connect() as conn:
        count = conn.execute(text("SELECT count(*) FROM audit_log")).scalar()
    engine.dispose()
    return count


def test_low_client_login_logout_cannot_flood_the_audit_log(migrated_pg_url):
    class PgConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = migrated_pg_url
        SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    app = create_app(PgConfig)
    with app.app_context():
        key = team_service.create_member("Reviewer", "rev@example.com", "client").issued_api_key
        limit = app.config["AUTH_RATE_LIMIT_ATTEMPTS"]
        db.session.remove()
    before = _audit_rows(migrated_pg_url)
    statuses = []
    for i in range(3 * limit):
        browser = app.test_client()
        statuses.append(browser.post("/admin/client-login", data={"api_key": key},
                                     environ_overrides={"REMOTE_ADDR": f"198.51.100.{i + 1}"}).status_code)
        browser.post("/admin/logout")
    added = _audit_rows(migrated_pg_url) - before
    assert statuses == [302] * limit + [429] * (2 * limit)
    assert added <= limit
    with app.app_context():
        db.engine.dispose()
