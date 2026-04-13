"""Tests for the collectors API blueprint."""

import pytest
from cryptography.fernet import Fernet
from moto import mock_aws

from app import create_app
from app.config import TestConfig
from app.models import CollectorConfig, db
from app.services import team_service


@pytest.fixture
def app_ctx(monkeypatch):
    monkeypatch.setenv("COLLECTOR_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
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
def admin_headers(app_ctx):
    admin = team_service.create_member(
        "Admin", "admin@example.com", "human", is_compliance_admin=True
    )
    return {"X-API-Key": admin.api_key}


@pytest.fixture
def user_headers(app_ctx):
    user = team_service.create_member("User", "user@example.com", "human")
    return {"X-API-Key": user.api_key}


def test_list_collectors_empty(client, admin_headers):
    resp = client.get("/api/collectors", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.get_json() == []


def test_list_collectors_requires_auth(client):
    resp = client.get("/api/collectors")
    assert resp.status_code == 401


def test_list_collectors_requires_admin(client, user_headers):
    resp = client.get("/api/collectors", headers=user_headers)
    assert resp.status_code == 403


def test_configure_unknown_collector_rejected(client, admin_headers):
    resp = client.post(
        "/api/collectors/bogus/configure",
        headers=admin_headers,
        json={"credential_mode": "task_role"},
    )
    assert resp.status_code == 400


def test_configure_invalid_mode_rejected(client, admin_headers):
    resp = client.post(
        "/api/collectors/aws/configure",
        headers=admin_headers,
        json={"credential_mode": "nonsense"},
    )
    assert resp.status_code == 400


def test_configure_task_role_mode(client, admin_headers):
    resp = client.post(
        "/api/collectors/aws/configure",
        headers=admin_headers,
        json={
            "credential_mode": "task_role",
            "config": {"region": "ca-central-1"},
            "schedule_cron": "0 6 * * 1",
            "enabled": True,
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["name"] == "aws"
    assert data["credential_mode"] == "task_role"
    assert data["config"]["region"] == "ca-central-1"
    assert data["schedule_cron"] == "0 6 * * 1"
    assert data["enabled"] is True
    assert data["has_stored_credentials"] is False


def test_configure_access_keys_stores_encrypted(client, admin_headers, app_ctx):
    resp = client.post(
        "/api/collectors/aws/configure",
        headers=admin_headers,
        json={
            "credential_mode": "access_keys",
            "credentials": {
                "access_key_id": "AKIATEST",
                "secret_access_key": "SECRETTEST",
                "region": "ca-central-1",
            },
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["has_stored_credentials"] is True
    # Response NEVER contains raw credentials
    assert "credentials" not in data
    assert "access_key_id" not in resp.get_data(as_text=True)

    # Verify ciphertext is in DB and not plaintext
    config = CollectorConfig.query.filter_by(name="aws").one()
    assert config.encrypted_credentials is not None
    assert b"AKIATEST" not in config.encrypted_credentials
    assert b"SECRETTEST" not in config.encrypted_credentials


def test_configure_is_idempotent_update(client, admin_headers):
    # First call creates
    client.post(
        "/api/collectors/aws/configure",
        headers=admin_headers,
        json={"credential_mode": "task_role", "enabled": False},
    )
    # Second call updates
    resp = client.post(
        "/api/collectors/aws/configure",
        headers=admin_headers,
        json={"credential_mode": "task_role", "enabled": True},
    )
    assert resp.status_code == 200
    assert resp.get_json()["enabled"] is True
    assert CollectorConfig.query.count() == 1


def test_get_collector(client, admin_headers):
    client.post(
        "/api/collectors/aws/configure",
        headers=admin_headers,
        json={"credential_mode": "task_role"},
    )
    resp = client.get("/api/collectors/aws", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.get_json()["name"] == "aws"


def test_get_collector_not_found(client, admin_headers):
    resp = client.get("/api/collectors/aws", headers=admin_headers)
    assert resp.status_code == 404


def test_enable_toggle(client, admin_headers):
    client.post(
        "/api/collectors/aws/configure",
        headers=admin_headers,
        json={"credential_mode": "task_role", "enabled": False},
    )
    resp = client.post(
        "/api/collectors/aws/enable",
        headers=admin_headers,
        json={"enabled": True},
    )
    assert resp.status_code == 200
    assert resp.get_json()["enabled"] is True


def test_list_runs_empty(client, admin_headers):
    client.post(
        "/api/collectors/aws/configure",
        headers=admin_headers,
        json={"credential_mode": "task_role"},
    )
    resp = client.get("/api/collectors/aws/runs", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.get_json() == []


@mock_aws
def test_trigger_run_executes_and_finishes(client, admin_headers):
    client.post(
        "/api/collectors/aws/configure",
        headers=admin_headers,
        json={"credential_mode": "task_role", "config": {"region": "us-east-1"}},
    )
    resp = client.post("/api/collectors/aws/run", headers=admin_headers)
    assert resp.status_code == 200
    run_data = resp.get_json()
    assert run_data["trigger_type"] == "manual"
    assert run_data["status"] in ("success", "partial", "failure")
    assert run_data["finished_at"] is not None

    # Run appears in history
    resp = client.get("/api/collectors/aws/runs", headers=admin_headers)
    assert len(resp.get_json()) == 1


@mock_aws
def test_get_run_detail_includes_checks(client, admin_headers):
    client.post(
        "/api/collectors/aws/configure",
        headers=admin_headers,
        json={"credential_mode": "task_role", "config": {"region": "us-east-1"}},
    )
    resp = client.post("/api/collectors/aws/run", headers=admin_headers)
    run_id = resp.get_json()["id"]

    resp = client.get(f"/api/collectors/runs/{run_id}", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["run"]["id"] == run_id
    # Executor writes per-check rows; the AWS collector produces several.
    assert len(body["checks"]) > 0


def test_get_run_not_found(client, admin_headers):
    resp = client.get("/api/collectors/runs/nonexistent", headers=admin_headers)
    assert resp.status_code == 404
