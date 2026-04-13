"""Tests for the admin UI routes for evidence collectors."""

import uuid

import pytest
from cryptography.fernet import Fernet
from moto import mock_aws

from app import create_app
from app.config import TestConfig
from app.models import CollectorConfig, CollectorRun, db
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
def admin(app_ctx):
    return team_service.create_member(
        "Admin", "admin@example.com", "human", is_compliance_admin=True
    )


@pytest.fixture
def non_admin(app_ctx):
    return team_service.create_member("User", "user@example.com", "human")


def _login(client, member):
    with client.session_transaction() as sess:
        sess["api_key"] = member.api_key


def _login_admin(client, admin):
    _login(client, admin)


# ----- access control -----


def test_collectors_list_redirects_without_login(client):
    resp = client.get("/admin/collectors")
    # The auth decorator redirects to the admin login page (302).
    assert resp.status_code in (302, 401, 403)


def test_collectors_list_forbidden_for_non_admin(client, non_admin):
    _login(client, non_admin)
    resp = client.get("/admin/collectors")
    assert resp.status_code in (302, 403)


# ----- list page -----


def test_collectors_list_shows_catalog(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/collectors")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    # All five known collectors appear on the page.
    assert "AWS Infrastructure" in body
    assert "Git / CodeCommit" in body
    assert "Platform Services" in body
    assert "Policies" in body
    assert "Vendors" in body


def test_collectors_list_shows_status_for_configured(client, admin):
    _login_admin(client, admin)
    config = CollectorConfig(
        id=str(uuid.uuid4()),
        name="aws",
        enabled=True,
        credential_mode="task_role",
        schedule_cron="0 6 * * 1",
    )
    db.session.add(config)
    db.session.commit()

    resp = client.get("/admin/collectors")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Enabled" in body
    assert "0 6 * * 1" in body


# ----- configure page -----


def test_configure_page_first_time_setup(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/collectors/aws")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Configure: AWS Infrastructure" in body
    # Defaults to task_role mode
    assert 'value="task_role" selected' in body
    # All the credential panels exist so JS can toggle them
    assert 'data-mode="task_role_assume"' in body
    assert 'data-mode="access_keys"' in body
    # Action buttons present
    assert "Test Connection" in body
    assert "Recheck Permissions" in body
    assert "Run Now" in body
    assert "Load IAM Policy" in body


def test_configure_page_unknown_collector_redirects(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/collectors/nonsense", follow_redirects=False)
    assert resp.status_code == 302
    assert "/admin/collectors" in resp.headers["Location"]


def test_configure_page_shows_existing_values(client, admin):
    _login_admin(client, admin)
    config = CollectorConfig(
        id=str(uuid.uuid4()),
        name="aws",
        enabled=True,
        credential_mode="task_role_assume",
        schedule_cron="0 6 * * 1",
        config={"region": "ca-central-1"},
    )
    db.session.add(config)
    db.session.commit()

    resp = client.get("/admin/collectors/aws")
    body = resp.get_data(as_text=True)
    assert 'value="task_role_assume" selected' in body
    assert "0 6 * * 1" in body
    assert "ca-central-1" in body
    assert "checked" in body  # enabled checkbox


# ----- configure form submission -----


def test_configure_submit_creates_config_task_role(client, admin):
    _login_admin(client, admin)
    resp = client.post(
        "/admin/collectors/aws",
        data={
            "credential_mode": "task_role",
            "region": "ca-central-1",
            "schedule_cron": "0 6 * * 1",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    config = CollectorConfig.query.filter_by(name="aws").one()
    assert config.credential_mode == "task_role"
    assert config.enabled is True
    assert config.schedule_cron == "0 6 * * 1"
    assert config.config["region"] == "ca-central-1"
    assert config.encrypted_credentials is None


def test_configure_submit_stores_assume_role_credentials(client, admin):
    _login_admin(client, admin)
    resp = client.post(
        "/admin/collectors/aws",
        data={
            "credential_mode": "task_role_assume",
            "role_arn": "arn:aws:iam::123456789012:role/trust-portal-collector-role",
            "external_id": "externalid",
            "session_name": "trust-portal-aws",
            "region": "ca-central-1",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    config = CollectorConfig.query.filter_by(name="aws").one()
    assert config.credential_mode == "task_role_assume"
    assert config.encrypted_credentials is not None
    # Ciphertext never contains plaintext values
    assert b"externalid" not in config.encrypted_credentials
    assert b"trust-portal-collector-role" not in config.encrypted_credentials


def test_configure_submit_stores_access_keys(client, admin):
    _login_admin(client, admin)
    resp = client.post(
        "/admin/collectors/aws",
        data={
            "credential_mode": "access_keys",
            "access_key_id": "AKIAFAKE",
            "secret_access_key": "VERYSECRET",
            "region": "us-east-1",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    config = CollectorConfig.query.filter_by(name="aws").one()
    assert config.credential_mode == "access_keys"
    assert config.encrypted_credentials is not None
    assert b"AKIAFAKE" not in config.encrypted_credentials
    assert b"VERYSECRET" not in config.encrypted_credentials


def test_configure_submit_rejects_unknown_collector(client, admin):
    _login_admin(client, admin)
    resp = client.post(
        "/admin/collectors/nonsense",
        data={"credential_mode": "task_role"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    # Config was not created.
    assert CollectorConfig.query.count() == 0


def test_configure_submit_rejects_invalid_mode(client, admin):
    _login_admin(client, admin)
    resp = client.post(
        "/admin/collectors/aws",
        data={"credential_mode": "bogus"},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert CollectorConfig.query.count() == 0


def test_configure_submit_preserves_credentials_on_edit(client, admin):
    """Editing task-role config should not wipe previously stored credentials."""
    _login_admin(client, admin)
    # First save real assume-role creds
    client.post(
        "/admin/collectors/aws",
        data={
            "credential_mode": "task_role_assume",
            "role_arn": "arn:aws:iam::123:role/existing",
            "region": "us-east-1",
        },
    )
    config = CollectorConfig.query.filter_by(name="aws").one()
    ciphertext_before = config.encrypted_credentials
    assert ciphertext_before is not None

    # Edit without providing new credential fields, still in assume mode
    client.post(
        "/admin/collectors/aws",
        data={
            "credential_mode": "task_role_assume",
            "region": "ca-central-1",
        },
    )
    config = CollectorConfig.query.filter_by(name="aws").one()
    assert config.encrypted_credentials == ciphertext_before
    assert config.config["region"] == "ca-central-1"


def test_configure_submit_clears_credentials_when_switching_to_task_role(client, admin):
    _login_admin(client, admin)
    client.post(
        "/admin/collectors/aws",
        data={
            "credential_mode": "access_keys",
            "access_key_id": "AKIAFAKE",
            "secret_access_key": "SECRET",
        },
    )
    config = CollectorConfig.query.filter_by(name="aws").one()
    assert config.encrypted_credentials is not None

    client.post(
        "/admin/collectors/aws",
        data={"credential_mode": "task_role"},
    )
    config = CollectorConfig.query.filter_by(name="aws").one()
    assert config.encrypted_credentials is None


# ----- run history pages -----


def test_runs_page_unconfigured_redirects(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/collectors/aws/runs", follow_redirects=False)
    assert resp.status_code == 302


def test_runs_page_empty_history(client, admin):
    _login_admin(client, admin)
    config = CollectorConfig(
        id=str(uuid.uuid4()), name="aws", credential_mode="task_role"
    )
    db.session.add(config)
    db.session.commit()

    resp = client.get("/admin/collectors/aws/runs")
    assert resp.status_code == 200
    assert "No runs yet" in resp.get_data(as_text=True)


@mock_aws
def test_runs_page_shows_real_run_from_end_to_end(client, admin):
    _login_admin(client, admin)
    client.post(
        "/admin/collectors/aws",
        data={"credential_mode": "task_role", "region": "us-east-1"},
    )
    # Trigger via the API endpoint (same code path as the "Run Now" button)
    resp = client.post("/api/collectors/aws/run")
    assert resp.status_code == 200

    resp = client.get("/admin/collectors/aws/runs")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "manual" in body
    # Check that a status badge was rendered (one of these appears depending
    # on whether moto provided mocks for every probed service)
    assert any(
        label in body for label in ("Success", "Partial", "Failure")
    )


@mock_aws
def test_run_detail_page_shows_checks(client, admin):
    _login_admin(client, admin)
    client.post(
        "/admin/collectors/aws",
        data={"credential_mode": "task_role", "region": "us-east-1"},
    )
    resp = client.post("/api/collectors/aws/run")
    run_id = resp.get_json()["id"]

    resp = client.get(f"/admin/collectors/aws/runs/{run_id}")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Check Results" in body
    # At least one known check should be rendered
    assert "iam_password_policy" in body or "iam_mfa" in body


def test_run_detail_missing_run_redirects(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/collectors/aws/runs/nonexistent", follow_redirects=False)
    assert resp.status_code == 302


# ----- dashboard link -----


def test_dashboard_links_to_collectors(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Evidence Collectors" in body
    assert "/admin/collectors" in body
