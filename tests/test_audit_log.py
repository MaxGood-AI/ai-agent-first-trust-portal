"""Tests for audit logging: model, API endpoint, admin page, and middleware."""

import json
from datetime import datetime, timezone, timedelta

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db
from app.models.audit_log import AuditLog
from app.services import team_service


@pytest.fixture
def app_ctx():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app_ctx):
    return app_ctx.test_client()


@pytest.fixture
def member(app_ctx):
    return team_service.create_member("Test User", "test@example.com", "human")


@pytest.fixture
def admin_member(app_ctx):
    return team_service.create_member("Admin", "admin@example.com", "human",
                                      is_compliance_admin=True)


def _insert_audit_entry(table_name="controls", record_id="abc-123", action="INSERT",
                         changed_by=None, changed_at=None, old_values=None, new_values=None):
    entry = AuditLog(
        table_name=table_name,
        record_id=record_id,
        action=action,
        old_values=old_values,
        new_values=new_values or {"name": "Test Control"},
        changed_by=changed_by,
        changed_at=changed_at or datetime.now(timezone.utc),
    )
    db.session.add(entry)
    db.session.commit()
    return entry


# --- Model tests ---

def test_audit_log_model_creation(app_ctx):
    entry = _insert_audit_entry()
    assert entry.id is not None
    assert entry.table_name == "controls"
    assert entry.action == "INSERT"
    assert entry.record_id == "abc-123"


def test_audit_log_repr(app_ctx):
    entry = _insert_audit_entry()
    assert "INSERT controls/abc-123" in repr(entry)


# --- API endpoint tests ---

def test_audit_log_api_requires_auth(client):
    resp = client.get("/api/audit-log")
    assert resp.status_code == 401


def test_audit_log_api_returns_entries(client, member, app_ctx):
    now = datetime.now(timezone.utc)
    _insert_audit_entry(changed_at=now - timedelta(seconds=10))
    _insert_audit_entry(record_id="def-456", changed_at=now)

    resp = client.get("/api/audit-log", headers={"X-API-Key": member.api_key})
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data) == 2
    # Most recent first
    assert data[0]["record_id"] == "def-456"
    assert data[1]["record_id"] == "abc-123"


def test_audit_log_api_filters_by_table(client, member, app_ctx):
    _insert_audit_entry(table_name="controls")
    _insert_audit_entry(table_name="policies", record_id="pol-1")

    resp = client.get("/api/audit-log?table=controls",
                      headers={"X-API-Key": member.api_key})
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]["table_name"] == "controls"


def test_audit_log_api_filters_by_record_id(client, member, app_ctx):
    _insert_audit_entry(record_id="aaa")
    _insert_audit_entry(record_id="bbb")

    resp = client.get("/api/audit-log?record_id=aaa",
                      headers={"X-API-Key": member.api_key})
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]["record_id"] == "aaa"


def test_audit_log_api_filters_by_action(client, member, app_ctx):
    _insert_audit_entry(action="INSERT")
    _insert_audit_entry(action="UPDATE", record_id="upd-1",
                         old_values={"name": "Old"}, new_values={"name": "New"})

    resp = client.get("/api/audit-log?action=UPDATE",
                      headers={"X-API-Key": member.api_key})
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]["action"] == "UPDATE"
    assert data[0]["old_values"]["name"] == "Old"


def test_audit_log_api_filters_by_changed_by(client, member, app_ctx):
    _insert_audit_entry(changed_by="user-1")
    _insert_audit_entry(changed_by="user-2", record_id="r2")

    resp = client.get("/api/audit-log?changed_by=user-1",
                      headers={"X-API-Key": member.api_key})
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]["changed_by"] == "user-1"


def test_audit_log_api_filters_by_since(client, member, app_ctx):
    old = datetime(2020, 1, 1)
    recent = datetime.now(timezone.utc).replace(tzinfo=None)
    _insert_audit_entry(changed_at=old, record_id="old-1")
    _insert_audit_entry(changed_at=recent, record_id="new-1")

    since = (recent - timedelta(hours=1)).isoformat()
    resp = client.get(f"/api/audit-log?since={since}",
                      headers={"X-API-Key": member.api_key})
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]["record_id"] == "new-1"


def test_audit_log_api_pagination(client, member, app_ctx):
    for i in range(60):
        _insert_audit_entry(record_id=f"rec-{i:03d}")

    # Default limit is 50
    resp = client.get("/api/audit-log", headers={"X-API-Key": member.api_key})
    assert len(resp.get_json()) == 50

    # Custom limit
    resp = client.get("/api/audit-log?limit=10", headers={"X-API-Key": member.api_key})
    assert len(resp.get_json()) == 10

    # Max limit capped at 200
    resp = client.get("/api/audit-log?limit=999", headers={"X-API-Key": member.api_key})
    assert len(resp.get_json()) == 60  # only 60 exist, 200 cap not reached


# --- Admin page tests ---

def test_audit_log_admin_page_requires_admin(client, member):
    resp = client.get("/admin/audit-log", headers={"X-API-Key": member.api_key})
    # Non-admin gets 403 (API-key request, not browser)
    assert resp.status_code == 403


def test_audit_log_admin_page_renders(client, admin_member, app_ctx):
    _insert_audit_entry()
    resp = client.get("/admin/audit-log",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    assert b"Audit Log" in resp.data
    assert b"controls" in resp.data


def test_audit_log_admin_page_filters(client, admin_member, app_ctx):
    _insert_audit_entry(table_name="controls")
    _insert_audit_entry(table_name="policies", record_id="pol-1")

    resp = client.get("/admin/audit-log?table=policies",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    assert b"policies" in resp.data


def test_audit_log_dashboard_link(client, admin_member):
    resp = client.get("/admin/", headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    assert b"audit-log" in resp.data


# --- Middleware tests ---

def test_audit_middleware_import(app_ctx):
    """Verify the audit middleware module loads and the function is callable."""
    from app.audit_middleware import register_audit_middleware
    assert callable(register_audit_middleware)


def test_audit_middleware_avoids_reserved_keyword():
    """The PostgreSQL session variable must not use 'current_user' (reserved keyword)."""
    import os
    middleware_path = os.path.join(
        os.path.dirname(__file__), "..", "app", "audit_middleware.py"
    )
    with open(middleware_path) as f:
        source = f.read()
    assert "app.current_user" not in source, (
        "audit_middleware.py uses 'app.current_user' which is a PostgreSQL reserved keyword. "
        "Use 'app.current_team_member' instead."
    )
    assert "app.current_team_member" in source


def test_audit_trigger_avoids_reserved_keyword():
    """The migration trigger function must not use 'current_user' (reserved keyword)."""
    import os
    migration_path = os.path.join(
        os.path.dirname(__file__), "..", "migrations", "versions",
        "010_add_audit_log_table.py"
    )
    with open(migration_path) as f:
        source = f.read()
    assert "app.current_user" not in source, (
        "Migration 010 trigger uses 'app.current_user' which is a PostgreSQL reserved keyword."
    )
    assert "app.current_team_member" in source


def test_audit_log_admin_shows_member_name(client, admin_member, app_ctx):
    """Audit log page should display team member name, not just truncated UUID."""
    _insert_audit_entry(changed_by=admin_member.id)

    resp = client.get("/admin/audit-log",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    # Should show the member's name, not just the UUID
    assert b"Admin" in resp.data


def test_audit_log_api_includes_member_name(client, member, app_ctx):
    """Audit log API should include changed_by_name for resolved members."""
    _insert_audit_entry(changed_by=member.id)

    resp = client.get("/api/audit-log",
                      headers={"X-API-Key": member.api_key})
    data = resp.get_json()
    assert len(data) == 1
    assert "changed_by_name" in data[0]
    assert data[0]["changed_by_name"] == "Test User"
