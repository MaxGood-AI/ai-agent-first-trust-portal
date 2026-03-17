"""Tests for portal and API routes."""

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


# --- Public API routes (no auth) ---

def test_api_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "mgcompliance"
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
