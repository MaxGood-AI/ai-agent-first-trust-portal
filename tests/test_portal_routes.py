"""Tests for portal and API routes."""

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, Control, Policy, TestRecord
from app.services import team_service


@pytest.fixture
def admin_member(app_ctx):
    return team_service.create_member("Admin", "admin@example.com", "human",
                                      is_compliance_admin=True)


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
    return team_service.create_member("Test", "test@example.com", "human")


def _auth(member):
    return {"X-API-Key": member.api_key}


# --- Public portal routes (no auth) ---

def test_portal_index(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Trust Portal" in resp.data


def test_portal_policies(client):
    resp = client.get("/policies")
    assert resp.status_code == 200
    assert b"Policy Library" in resp.data


def test_portal_controls(client):
    resp = client.get("/controls")
    assert resp.status_code == 200
    assert b"SOC 2 Controls" in resp.data


def test_portal_status(client):
    resp = client.get("/status")
    assert resp.status_code == 200
    assert b"Compliance Status" in resp.data


def test_portal_policy_detail(app_ctx, client):
    with app_ctx.app_context():
        p = Policy(id="pol-detail", title="Test Policy", category="security", status="approved")
        db.session.add(p)
        db.session.commit()

    resp = client.get("/policies/pol-detail")
    assert resp.status_code == 200
    assert b"Test Policy" in resp.data


def test_portal_policy_detail_404(client):
    resp = client.get("/policies/nonexistent")
    assert resp.status_code == 404


def test_portal_systems(client):
    resp = client.get("/systems")
    assert resp.status_code == 200
    assert b"System Inventory" in resp.data


def test_portal_vendors(client):
    resp = client.get("/vendors")
    assert resp.status_code == 200
    assert b"Vendor Inventory" in resp.data


def test_portal_risks(client):
    resp = client.get("/risks")
    assert resp.status_code == 200
    assert b"Risk Register" in resp.data


def test_portal_control_detail(app_ctx, client):
    with app_ctx.app_context():
        c = Control(id="ctrl-det", name="Detail Test", category="security")
        db.session.add(c)
        db.session.commit()

    resp = client.get("/controls/ctrl-det")
    assert resp.status_code == 200
    assert b"Detail Test" in resp.data


def test_portal_control_detail_404(client):
    resp = client.get("/controls/nonexistent")
    assert resp.status_code == 404


# --- Public API routes (no auth) ---

def test_api_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "trust-portal"
    assert data["database"] == "connected"


def test_swagger_ui_accessible(client):
    resp = client.get("/api/docs/")
    assert resp.status_code == 200


# --- Authenticated API routes ---

def test_api_compliance_score_empty(client, member):
    resp = client.get("/api/compliance-score", headers=_auth(member))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["overall_score"] == 0


def test_api_gaps_empty(client, member):
    resp = client.get("/api/gaps", headers=_auth(member))
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_api_controls_empty(client, member):
    resp = client.get("/api/controls", headers=_auth(member))
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_api_decision_log_sessions_empty(client, member):
    resp = client.get("/api/decision-log/sessions", headers=_auth(member))
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_portal_index_shows_privacy_category(app_ctx, client):
    """Privacy category appears on home page when privacy controls exist."""
    with app_ctx.app_context():
        ctrl = Control(id="priv-portal", name="Privacy Control", category="privacy", state="adopted")
        db.session.add(ctrl)
        tr = TestRecord(id="priv-portal-t", control_id="priv-portal", name="Privacy Test",
                        status="passed", evidence_status="submitted")
        db.session.add(tr)
        db.session.commit()

    resp = client.get("/")
    assert resp.status_code == 200
    assert b"privacy" in resp.data


def test_status_page_shows_control_id(app_ctx, client):
    """Status page should display control_id_short alongside control name."""
    with app_ctx.app_context():
        ctrl = Control(id="ctrl-status-id", name="MFA Enforcement",
                       category="security", state="adopted",
                       control_id_short="SEC-42")
        db.session.add(ctrl)
        tr = TestRecord(id="test-status-id", control_id="ctrl-status-id",
                        name="MFA Test", status="passed", evidence_status="submitted")
        db.session.add(tr)
        db.session.commit()

    resp = client.get("/status")
    assert resp.status_code == 200
    assert b"SEC-42" in resp.data


# --- Admin navigation regression tests ---


def test_evidence_page_has_back_to_dashboard(client, admin_member):
    """Evidence management page must have a back-to-dashboard link."""
    resp = client.get("/admin/evidence",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    assert b"Back to Dashboard" in resp.data


def test_team_page_has_back_to_dashboard(client, admin_member):
    """Team members page must have a back-to-dashboard link."""
    resp = client.get("/admin/team",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    assert b"Back to Dashboard" in resp.data


def test_audit_log_page_has_back_to_dashboard(client, admin_member):
    """Audit log page must have a back-to-dashboard link."""
    resp = client.get("/admin/audit-log",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    assert b"Back to Dashboard" in resp.data


def test_settings_page_has_back_to_dashboard(client, admin_member):
    """Settings page must have a back-to-dashboard link."""
    resp = client.get("/admin/settings",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    assert b"Back to Dashboard" in resp.data


def test_dashboard_has_all_quick_action_links(client, admin_member):
    """Dashboard must link to evidence, team, audit log, and settings."""
    resp = client.get("/admin/",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    assert b"evidence" in resp.data.lower()
    assert b"team" in resp.data.lower()
    assert b"audit-log" in resp.data
    assert b"settings" in resp.data.lower()


def test_team_page_has_client_role_option(client, admin_member):
    """Team member creation form must include 'client' role option."""
    resp = client.get("/admin/team",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    assert b'value="client"' in resp.data


def test_footer_has_legal_link(client):
    """Every page footer must have a link to /legal."""
    resp = client.get("/")
    assert b"/legal" in resp.data


def test_navigation_has_ai_transparency(client):
    """Navigation must have AI Transparency link."""
    resp = client.get("/")
    assert b"ai-transparency" in resp.data
