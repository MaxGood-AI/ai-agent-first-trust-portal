"""Tests for the first-login collector setup wizard (Phase 4).

Covers:
- CollectorOverview status helper
- Dashboard banner appears/hides based on collector state
- Wizard welcome + finish routes
- return_to flow from wizard → config page → back to wizard
- /api/collectors/environment endpoint behavior
- Compliance journey phase 5 includes collector counts
"""

import uuid
from datetime import datetime, timezone

import pytest
from cryptography.fernet import Fernet
from moto import mock_aws

from app import create_app
from app.config import TestConfig
from app.models import CollectorConfig, db
from app.services import team_service
from app.services.collector_status import COLLECTOR_CATALOG, get_overview


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


def _login_admin(client, admin):
    with client.session_transaction() as sess:
        sess["api_key"] = admin.api_key


def _save_config(name="aws", **overrides):
    defaults = {
        "id": str(uuid.uuid4()),
        "name": name,
        "enabled": False,
        "credential_mode": "task_role",
    }
    defaults.update(overrides)
    config = CollectorConfig(**defaults)
    db.session.add(config)
    db.session.commit()
    return config


# ----- CollectorOverview service -----


def test_overview_empty(app_ctx):
    overview = get_overview()
    assert overview.total == len(COLLECTOR_CATALOG)
    assert overview.configured == 0
    assert overview.enabled == 0
    assert overview.running_successfully == 0
    assert overview.needs_setup is True
    assert all(not s.configured for s in overview.statuses)


def test_overview_configured_but_not_run(app_ctx):
    _save_config(enabled=True)
    overview = get_overview()
    assert overview.configured == 1
    assert overview.enabled == 1
    assert overview.running_successfully == 0
    assert overview.needs_setup is True  # not running = still needs setup


def test_overview_successful_run_clears_setup_need(app_ctx):
    _save_config(
        enabled=True,
        last_run_status="success",
        last_run_at=datetime.now(timezone.utc),
    )
    overview = get_overview()
    assert overview.running_successfully == 1
    assert overview.needs_setup is False


def test_overview_catalog_order_stable(app_ctx):
    overview = get_overview()
    names = [s.name for s in overview.statuses]
    assert names == [name for name, _, _ in COLLECTOR_CATALOG]


# ----- Dashboard banner -----


def test_dashboard_banner_shown_when_no_collectors(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/")
    body = resp.get_data(as_text=True)
    assert "Set up evidence collection" in body
    assert "/admin/setup/collectors" in body


def test_dashboard_banner_shown_when_configured_but_not_run(client, admin):
    _login_admin(client, admin)
    _save_config(enabled=True)
    resp = client.get("/admin/")
    body = resp.get_data(as_text=True)
    assert "Set up evidence collection" in body
    # Banner shows "X of Y configured" when at least one config exists
    assert "1 of 5" in body


def test_dashboard_banner_hidden_after_successful_run(client, admin):
    _login_admin(client, admin)
    _save_config(
        enabled=True,
        last_run_status="success",
        last_run_at=datetime.now(timezone.utc),
    )
    resp = client.get("/admin/")
    body = resp.get_data(as_text=True)
    assert "Set up evidence collection" not in body


# ----- Wizard welcome page -----


def test_wizard_welcome_renders(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/setup/collectors")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Set Up Evidence Collection" in body
    # All 5 collectors from the catalog should be rendered
    assert "AWS Infrastructure" in body
    assert "Git / CodeCommit" in body
    assert "Platform Services" in body
    assert "Policies" in body
    assert "Vendors" in body
    # Step progress indicators
    assert "Step 1 of 2" in body
    # Link to each collector's configure page has return_to pointing at the wizard
    assert "/admin/collectors/aws?return_to=" in body
    assert "/admin/collectors/git?return_to=" in body


def test_wizard_welcome_forbidden_for_non_admin(client, app_ctx):
    user = team_service.create_member("User", "u@example.com", "human")
    with client.session_transaction() as sess:
        sess["api_key"] = user.api_key
    resp = client.get("/admin/setup/collectors", follow_redirects=False)
    assert resp.status_code in (302, 403)


# ----- Wizard finish page -----


def test_wizard_finish_renders_when_no_collectors(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/setup/collectors/finish")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Review" in body
    # When nothing is configured, the warning flash is shown
    assert "You haven't configured any collectors yet" in body


def test_wizard_finish_shows_configured_collectors(client, admin):
    _login_admin(client, admin)
    _save_config(
        enabled=True,
        last_run_status="success",
        last_run_at=datetime.now(timezone.utc),
    )
    resp = client.get("/admin/setup/collectors/finish")
    body = resp.get_data(as_text=True)
    assert "Success" in body
    assert "Run Now" in body  # run-now button for configured collector


# ----- return_to flow -----


def test_configure_form_accepts_return_to(client, admin):
    _login_admin(client, admin)
    resp = client.get(
        "/admin/collectors/aws?return_to=/admin/setup/collectors"
    )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Back to Setup" in body
    assert '<input type="hidden" name="return_to"' in body
    assert 'value="/admin/setup/collectors"' in body


def test_configure_form_rejects_unsafe_return_to(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/collectors/aws?return_to=https://evil.example/")
    body = resp.get_data(as_text=True)
    # The page renders but the unsafe return_to is stripped
    assert "evil.example" not in body
    assert "Back to Setup" not in body


def test_configure_submit_redirects_to_wizard_when_return_to_set(client, admin):
    _login_admin(client, admin)
    resp = client.post(
        "/admin/collectors/aws",
        data={
            "credential_mode": "task_role",
            "region": "us-east-1",
            "return_to": "/admin/setup/collectors",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/admin/setup/collectors")


def test_configure_submit_ignores_unsafe_return_to(client, admin):
    _login_admin(client, admin)
    resp = client.post(
        "/admin/collectors/aws",
        data={
            "credential_mode": "task_role",
            "region": "us-east-1",
            "return_to": "https://evil.example/",
        },
        follow_redirects=False,
    )
    # Falls back to the configure form URL
    assert resp.status_code == 302
    assert "evil.example" not in resp.headers["Location"]
    assert "/admin/collectors/aws" in resp.headers["Location"]


# ----- Environment detection endpoint -----


def test_environment_endpoint_requires_admin(client, app_ctx):
    user = team_service.create_member("User", "u@example.com", "human")
    resp = client.get(
        "/api/collectors/environment",
        headers={"X-API-Key": user.api_key},
    )
    assert resp.status_code == 403


@mock_aws
def test_environment_endpoint_returns_identity(client, admin):
    _login_admin(client, admin)
    resp = client.get(
        "/api/collectors/environment",
        headers={"X-API-Key": admin.api_key},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    # moto returns a fake account id for STS GetCallerIdentity
    assert data["account_id"] is not None
    assert data["identity"] is not None
    assert "is_ecs" in data


# ----- Compliance journey integration -----


def test_compliance_journey_includes_collector_counts(client, admin):
    _login_admin(client, admin)
    resp = client.get(
        "/api/compliance-journey",
        headers={"X-API-Key": admin.api_key},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    p5 = data["journey"]["phases"]["5_evidence_collection"]["checks"]
    assert "collectors_total" in p5
    assert "collectors_configured" in p5
    assert "collectors_running_successfully" in p5
    assert p5["collectors_total"] == 5
    assert p5["collectors_running_successfully"] == 0


def test_compliance_journey_phase5_reflects_successful_run(client, admin):
    _login_admin(client, admin)
    _save_config(
        enabled=True,
        last_run_status="success",
        last_run_at=datetime.now(timezone.utc),
    )
    resp = client.get(
        "/api/compliance-journey",
        headers={"X-API-Key": admin.api_key},
    )
    data = resp.get_json()
    p5 = data["journey"]["phases"]["5_evidence_collection"]["checks"]
    assert p5["collectors_running_successfully"] == 1
    assert p5["collectors_configured"] == 1


# ----- Configure template renders environment detection placeholder -----


def test_configure_page_includes_env_detection_box(client, admin):
    _login_admin(client, admin)
    resp = client.get("/admin/collectors/aws")
    body = resp.get_data(as_text=True)
    assert "environment-detection" in body
    assert "data-detect-url" in body
    # Points at the JSON API endpoint for detection
    assert "/api/collectors/environment" in body
