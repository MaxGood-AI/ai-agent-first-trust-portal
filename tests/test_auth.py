"""Tests for API key authentication."""

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db
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


# --- Public routes (no auth required) ---

def test_health_no_auth(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200


def test_portal_index_no_auth(client):
    resp = client.get("/")
    assert resp.status_code == 200


def test_portal_policies_no_auth(client):
    resp = client.get("/policies")
    assert resp.status_code == 200


def test_portal_controls_no_auth(client):
    resp = client.get("/controls")
    assert resp.status_code == 200


def test_portal_status_no_auth(client):
    resp = client.get("/status")
    assert resp.status_code == 200


# --- Protected API routes require auth ---

def test_compliance_score_requires_auth(client):
    resp = client.get("/api/compliance-score")
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Missing API key"


def test_api_controls_requires_auth(client):
    resp = client.get("/api/controls")
    assert resp.status_code == 401


def test_api_gaps_requires_auth(client):
    resp = client.get("/api/gaps")
    assert resp.status_code == 401


def test_decision_log_sessions_requires_auth(client):
    resp = client.get("/api/decision-log/sessions")
    assert resp.status_code == 401


def test_decision_log_ingest_requires_auth(client):
    resp = client.post("/api/decision-log/ingest")
    assert resp.status_code == 401


def test_decision_log_upload_requires_auth(client):
    resp = client.post("/api/decision-log/upload", data="test")
    assert resp.status_code == 401


# --- Valid auth via X-API-Key header ---

def test_valid_api_key_header(client, member):
    resp = client.get("/api/compliance-score",
                      headers={"X-API-Key": member.api_key})
    assert resp.status_code == 200


# --- Valid auth via Bearer token ---

def test_valid_bearer_token(client, member):
    resp = client.get("/api/compliance-score",
                      headers={"Authorization": f"Bearer {member.api_key}"})
    assert resp.status_code == 200


# --- Invalid API key ---

def test_invalid_api_key(client):
    resp = client.get("/api/compliance-score",
                      headers={"X-API-Key": "totally-wrong-key"})
    assert resp.status_code == 401
    assert resp.get_json()["error"] == "Invalid or inactive API key"


# --- Inactive member ---

def test_inactive_member_rejected(client, member):
    team_service.deactivate_member(member.id)
    resp = client.get("/api/compliance-score",
                      headers={"X-API-Key": member.api_key})
    assert resp.status_code == 401


# --- Admin routes require admin role ---

def test_admin_dashboard_requires_admin(client, member):
    resp = client.get("/admin/",
                      headers={"X-API-Key": member.api_key})
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "Admin access required"


def test_admin_dashboard_accessible_by_admin(client, admin_member):
    resp = client.get("/admin/",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200


def test_admin_team_requires_admin(client, member):
    resp = client.get("/admin/team",
                      headers={"X-API-Key": member.api_key})
    assert resp.status_code == 403


def test_admin_team_accessible_by_admin(client, admin_member):
    resp = client.get("/admin/team",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
