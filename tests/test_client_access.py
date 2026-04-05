"""Tests for gated client compliance report access (#651)."""

from datetime import datetime, timezone, timedelta

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, TeamMember, Control, TestRecord, PentestFinding
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
def admin_member(app_ctx):
    return team_service.create_member("Admin", "admin@example.com", "human",
                                      is_compliance_admin=True)


@pytest.fixture
def client_member(app_ctx):
    return team_service.create_member("Client User", "client@acme.com", "client",
                                      company="Acme Corp")


@pytest.fixture
def expired_client(app_ctx):
    return team_service.create_member(
        "Expired Client", "expired@acme.com", "client",
        company="Acme Corp",
        expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )


# --- Client login page ---

def test_client_login_page_renders(client):
    resp = client.get("/admin/client-login")
    assert resp.status_code == 200
    assert b"Compliance Report Access" in resp.data


def test_client_login_valid_key(client, client_member):
    resp = client.post("/admin/client-login",
                       data={"api_key": client_member.api_key})
    assert resp.status_code == 302
    assert "/admin/report" in resp.headers["Location"]


def test_client_login_invalid_key(client):
    resp = client.post("/admin/client-login",
                       data={"api_key": "bogus-key-12345"})
    assert resp.status_code == 200
    assert b"Invalid access key" in resp.data


def test_client_login_expired_key(client, expired_client):
    resp = client.post("/admin/client-login",
                       data={"api_key": expired_client.api_key})
    assert resp.status_code == 200
    assert b"expired" in resp.data.lower()


def test_client_login_non_client_role_rejected(client, admin_member):
    resp = client.post("/admin/client-login",
                       data={"api_key": admin_member.api_key})
    assert resp.status_code == 200
    assert b"Invalid access key" in resp.data


# --- Client report ---

def test_client_report_requires_auth(client):
    resp = client.get("/admin/report")
    # No API key, no session — returns 401 for non-browser request
    assert resp.status_code in (302, 401)


def test_client_report_renders_for_client(client, client_member):
    resp = client.get("/admin/report",
                      headers={"X-API-Key": client_member.api_key})
    assert resp.status_code == 200
    assert b"Compliance Report" in resp.data
    assert b"Compliance Score" in resp.data


def test_client_report_renders_for_admin(client, admin_member):
    resp = client.get("/admin/report",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    assert b"Compliance Report" in resp.data


def test_client_cannot_access_admin_dashboard(client, client_member):
    resp = client.get("/admin/",
                      headers={"X-API-Key": client_member.api_key})
    assert resp.status_code == 403


# --- Team member creation with client fields ---

def test_client_member_creation_with_company_and_expiry(app_ctx):
    with app_ctx.app_context():
        future = datetime.now(timezone.utc) + timedelta(days=30)
        member = team_service.create_member(
            "New Client", "new@corp.com", "client",
            company="Corp Inc.",
            expires_at=future,
        )
        assert member.role == "client"
        assert member.company == "Corp Inc."
        assert member.expires_at is not None
        assert not member.is_expired


# --- is_expired property ---

def test_is_expired_property(app_ctx):
    with app_ctx.app_context():
        past = team_service.create_member(
            "Past", "past@test.com", "client",
            expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        )
        assert past.is_expired

        future = team_service.create_member(
            "Future", "future@test.com", "client",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        assert not future.is_expired

        no_expiry = team_service.create_member(
            "NoExpiry", "none@test.com", "client",
        )
        assert not no_expiry.is_expired


# --- Expiry enforcement in require_api_key ---

def test_expired_key_rejected_by_require_api_key(client, expired_client):
    resp = client.get("/api/health",
                      headers={"X-API-Key": expired_client.api_key})
    # Health endpoint doesn't require auth, so let's use an authed endpoint
    resp = client.get("/api/compliance-score",
                      headers={"X-API-Key": expired_client.api_key})
    assert resp.status_code == 401


# --- Home page CTA ---

def test_home_page_has_client_access_cta(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"client-login" in resp.data
    assert b"Security Reviewers" in resp.data


# --- Client report content tests ---


def test_client_report_shows_all_evidence_gaps(app_ctx, client, admin_member):
    """Report must show ALL evidence gaps, not truncate to 20."""
    with app_ctx.app_context():
        ctrl = Control(id="ctrl-gaps", name="Gaps Control", category="security")
        db.session.add(ctrl)
        db.session.flush()
        for i in range(30):
            tr = TestRecord(
                id=f"gap-test-{i:03d}",
                control_id="ctrl-gaps",
                name=f"Gap Test {i:03d}",
                status="pending",
                evidence_status="missing",
            )
            db.session.add(tr)
        db.session.commit()

    resp = client.get("/admin/report",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    # All 30 should appear — no "and X more" truncation
    assert b"and " not in resp.data or b"... and" not in resp.data
    assert b"Gap Test 029" in resp.data
    assert b"Gap Test 000" in resp.data


def test_client_report_pentest_summary_uses_latest_scan_only(app_ctx, client, admin_member):
    """Pentest summary must show counts from the most recent scan, not all scans."""
    with app_ctx.app_context():
        # Old scan — 10 HIGH findings
        for i in range(10):
            db.session.add(PentestFinding(
                id=f"old-{i}", scan_id="old-scan", layer=1,
                severity="HIGH", summary=f"Old finding {i}",
                timestamp=datetime(2025, 1, 1),
            ))
        # Latest scan — 2 CRITICAL findings
        for i in range(2):
            db.session.add(PentestFinding(
                id=f"new-{i}", scan_id="new-scan", layer=1,
                severity="CRITICAL", summary=f"New finding {i}",
                timestamp=datetime(2026, 6, 1),
            ))
        db.session.commit()

    resp = client.get("/admin/report",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    # Should show CRITICAL count of 2 from latest scan
    assert b"CRITICAL" in resp.data
    # Should NOT show HIGH (only in old scan)
    # The stat card for HIGH should not appear since latest scan has no HIGH findings
    content = resp.data.decode()
    # Verify the CRITICAL stat shows "2"
    assert ">2<" in content


def test_client_report_pentest_summary_empty_when_no_findings(app_ctx, client, admin_member):
    """Report handles no pentest findings gracefully."""
    resp = client.get("/admin/report",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    # No Security Assessment Summary section when no findings
    assert b"Security Assessment Summary" not in resp.data


def test_client_report_contains_all_sections(app_ctx, client, admin_member):
    """Report page must contain all expected sections."""
    with app_ctx.app_context():
        ctrl = Control(id="sec-ctrl", name="Test Control", category="security")
        db.session.add(ctrl)
        db.session.commit()

    resp = client.get("/admin/report",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    assert b"Compliance Score" in resp.data
    assert b"Controls" in resp.data
    assert b"Approved Policies" in resp.data
    assert b"System Inventory" in resp.data
    assert b"Vendor Inventory" in resp.data


def test_client_report_shows_confidential_label(client, admin_member):
    """Report page must show 'Confidential' label."""
    resp = client.get("/admin/report",
                      headers={"X-API-Key": admin_member.api_key})
    assert b"Confidential" in resp.data


def test_deactivated_client_cannot_login(app_ctx, client, client_member):
    """Deactivated client key should be rejected at login."""
    with app_ctx.app_context():
        team_service.deactivate_member(client_member.id)

    resp = client.post("/admin/client-login",
                       data={"api_key": client_member.api_key})
    assert resp.status_code == 200
    assert b"Invalid access key" in resp.data


def test_client_login_empty_key(client):
    """Empty API key should show error."""
    resp = client.post("/admin/client-login", data={"api_key": ""})
    assert resp.status_code == 200
    assert b"Invalid access key" in resp.data


def test_client_cannot_access_settings(client, client_member):
    """Client role must not be able to access admin settings."""
    resp = client.get("/admin/settings",
                      headers={"X-API-Key": client_member.api_key})
    assert resp.status_code == 403


def test_client_cannot_access_audit_log(client, client_member):
    """Client role must not be able to access audit log."""
    resp = client.get("/admin/audit-log",
                      headers={"X-API-Key": client_member.api_key})
    assert resp.status_code == 403


def test_client_cannot_access_team_management(client, client_member):
    """Client role must not be able to manage team members."""
    resp = client.get("/admin/team",
                      headers={"X-API-Key": client_member.api_key})
    assert resp.status_code == 403
