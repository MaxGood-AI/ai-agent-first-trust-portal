"""Shared test fixtures.

Most tests run on in-memory SQLite (``TestConfig``). Tests that need
PostgreSQL behaviour (audit triggers, advisory locks, migrations) use the
``pg_url`` / ``migrated_pg_url`` / ``pg_app`` fixtures, which create a fresh
database per test on the server named by ``TEST_DATABASE_URL`` and are
skipped when it is unset. ``docker-compose.test.yml`` provides that server.
"""

import os
import uuid

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from werkzeug.datastructures import Headers

from app.auth import SESSION_FINGERPRINT_KEY, SESSION_MEMBER_KEY
from app.security import CSRF_HEADER, CSRF_SESSION_KEY, UNSAFE_METHODS

TEST_CSRF_TOKEN = "test-csrf-token"


class CsrfTestClient(FlaskClient):
    """Test client that behaves like the portal's own pages: every
    state-changing request made without an API-key header carries the
    session's CSRF token (as a browser page would via the meta tag).

    Tests that exercise CSRF rejection use ``raw_client(app)`` instead.
    """

    def open(self, *args, **kwargs):
        method = str(kwargs.get("method") or "GET").upper()
        headers = Headers(kwargs.get("headers") or {})
        uses_key = headers.get("X-API-Key") or headers.get("Authorization", "").startswith("Bearer ")
        if method in UNSAFE_METHODS and not uses_key and CSRF_HEADER not in headers \
                and (not args or isinstance(args[0], str)):
            with self.session_transaction() as sess:
                token = sess.setdefault(CSRF_SESSION_KEY, TEST_CSRF_TOKEN)
            headers[CSRF_HEADER] = token
            kwargs["headers"] = headers
        return super().open(*args, **kwargs)


def raw_client(app):
    """A plain Flask test client (no automatic CSRF token)."""
    return FlaskClient(app, app.response_class, use_cookies=True)


@pytest.fixture(autouse=True)
def _csrf_aware_test_client(monkeypatch):
    monkeypatch.setattr(Flask, "test_client_class", CsrfTestClient)


def login(client, member, csrf_token=TEST_CSRF_TOKEN):
    """Log ``member`` into ``client``'s browser session; returns the CSRF token."""
    with client.session_transaction() as sess:
        sess[SESSION_MEMBER_KEY] = member.id
        sess[SESSION_FINGERPRINT_KEY] = member.key_fingerprint
        sess[CSRF_SESSION_KEY] = csrf_token
    return csrf_token


def set_csrf(client, csrf_token=TEST_CSRF_TOKEN):
    """Give an anonymous browser session a known CSRF token."""
    with client.session_transaction() as sess:
        sess[CSRF_SESSION_KEY] = csrf_token
    return csrf_token


def _admin_url():
    return os.environ.get("TEST_DATABASE_URL")


def _admin_engine():
    return create_engine(_admin_url(), isolation_level="AUTOCOMMIT")


def drop_database_and_roles(name, owner):
    """Drop a test database, the roles its owner created, and the owner."""
    admin = _admin_engine()
    try:
        with admin.connect() as conn:
            conn.execute(text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = :n AND pid <> pg_backend_pid()"), {"n": name})
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
            created = conn.execute(text(
                "SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid "
                "JOIN pg_roles o ON o.oid = m.member WHERE o.rolname = :o"), {"o": owner}).scalars().all()
            extra = conn.execute(text(
                "SELECT rolname FROM pg_roles WHERE rolname LIKE 'tpa\\_%\\_own' ESCAPE '\\' "
                "AND NOT EXISTS (SELECT 1 FROM pg_database d WHERE d.datdba = pg_roles.oid)")).scalars().all()
            for role in created + extra + [owner]:
                conn.execute(text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = :r"), {"r": role})
                conn.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
    finally:
        admin.dispose()


@pytest.fixture
def pg_url():
    """URL of a brand-new, empty PostgreSQL database, connecting as its owner.

    The owner is NOT a superuser: like a managed database's master user it has
    LOGIN and CREATEROLE and owns the database, so security tests exercise the
    privileges a real deployment has.
    """
    if not _admin_url():
        pytest.skip("TEST_DATABASE_URL not set (PostgreSQL tests run via docker-compose.test.yml)")
    suffix = uuid.uuid4().hex[:12]
    name, owner, password = f"tp_{suffix}", f"tpo_{suffix}", uuid.uuid4().hex
    admin = _admin_engine()
    with admin.connect() as conn:
        conn.execute(text(f'CREATE ROLE "{owner}" LOGIN CREATEROLE PASSWORD \'{password}\''))
        conn.execute(text(f'CREATE DATABASE "{name}" OWNER "{owner}"'))
    admin.dispose()
    url = make_url(_admin_url()).set(database=name, username=owner, password=password)
    try:
        yield url.render_as_string(hide_password=False)
    finally:
        drop_database_and_roles(name, owner)


@pytest.fixture
def migrated_pg_url(pg_url):
    """A fresh PostgreSQL database upgraded to the Alembic head."""
    from cli.db_cmd import run_migrations

    run_migrations(pg_url)
    return pg_url


@pytest.fixture
def pg_app(migrated_pg_url):
    """Flask app bound to a migrated PostgreSQL database."""
    from app import create_app
    from app.config import TestConfig
    from app.models import db

    class PgConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = migrated_pg_url
        SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    app = create_app(PgConfig)
    with app.app_context():
        yield app
        db.session.remove()
        db.engine.dispose()
