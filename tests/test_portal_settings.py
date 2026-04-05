"""Tests for portal settings: company info (#646), SOC 2 badge (#650),
legal page (#649), AI transparency (#647), and settings API."""

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db
from app.models.portal_settings import PortalSettings
from app.services import team_service
from app.services.settings_service import get_portal_settings, update_portal_settings


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


# --- #646: Settings service tests ---

def test_get_settings_defaults_from_config(app_ctx):
    """No DB row — returns env/config defaults."""
    with app_ctx.app_context():
        settings = get_portal_settings()
        # Falls back to config values (which may come from .env or Config defaults)
        expected_name = app_ctx.config.get("PORTAL_COMPANY_NAME", "Your Company")
        assert settings["company_legal_name"] == expected_name
        assert settings["physical_address"] == ""
        assert settings["website_url"] == ""


def test_get_settings_db_overrides_config(app_ctx):
    """DB values take precedence over config defaults."""
    with app_ctx.app_context():
        ps = PortalSettings(id=1, company_legal_name="DB Corp")
        db.session.add(ps)
        db.session.commit()

        settings = get_portal_settings()
        assert settings["company_legal_name"] == "DB Corp"
        # brand_name still falls back to config
        expected_brand = app_ctx.config.get("PORTAL_BRAND_NAME", "Your Brand")
        assert settings["company_brand_name"] == expected_brand


def test_update_portal_settings_creates_row(app_ctx):
    """First update creates the single settings row."""
    with app_ctx.app_context():
        update_portal_settings({"company_legal_name": "New Corp"}, updated_by="test-id")
        ps = db.session.get(PortalSettings, 1)
        assert ps is not None
        assert ps.company_legal_name == "New Corp"
        assert ps.updated_by == "test-id"


def test_update_portal_settings_updates_existing(app_ctx):
    """Subsequent updates modify the existing row."""
    with app_ctx.app_context():
        update_portal_settings({"company_legal_name": "First"})
        update_portal_settings({"company_legal_name": "Second", "contact_email": "new@test.com"})
        ps = db.session.get(PortalSettings, 1)
        assert ps.company_legal_name == "Second"
        assert ps.contact_email == "new@test.com"


def test_context_processor_injects_portal(app_ctx, client):
    """The portal dict is available in all templates."""
    resp = client.get("/")
    assert resp.status_code == 200
    # Should contain the brand name from config (whatever it is)
    brand = app_ctx.config.get("PORTAL_BRAND_NAME", "Your Brand")
    assert brand.encode() in resp.data


def test_footer_shows_company_info(app_ctx, client):
    """Footer displays company info from settings."""
    with app_ctx.app_context():
        update_portal_settings({
            "company_legal_name": "Acme Inc.",
            "physical_address": "123 Main St",
            "website_url": "https://acme.example.com",
        })

    resp = client.get("/")
    assert b"Acme Inc." in resp.data
    assert b"123 Main St" in resp.data
    assert b"acme.example.com" in resp.data


# --- #646: Admin settings page tests ---

def test_admin_settings_page_requires_admin(client, member):
    resp = client.get("/admin/settings", headers={"X-API-Key": member.api_key})
    assert resp.status_code == 403


def test_admin_settings_page_renders(client, admin_member):
    resp = client.get("/admin/settings",
                      headers={"X-API-Key": admin_member.api_key})
    assert resp.status_code == 200
    assert b"Portal Settings" in resp.data
    assert b"company_legal_name" in resp.data


def test_admin_settings_update(app_ctx, client, admin_member):
    resp = client.post("/admin/settings",
                       headers={"X-API-Key": admin_member.api_key},
                       data={"company_legal_name": "Updated Corp",
                             "company_brand_name": "Updated Brand"})
    assert resp.status_code == 302  # redirect after save

    with app_ctx.app_context():
        settings = get_portal_settings()
        assert settings["company_legal_name"] == "Updated Corp"


# --- #646: Settings API tests ---

def test_settings_api_get(client, member):
    resp = client.get("/api/settings", headers={"X-API-Key": member.api_key})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "company_legal_name" in data
    assert "soc2_stages" in data


def test_settings_api_update_requires_admin(client, member):
    resp = client.put("/api/settings",
                      headers={"X-API-Key": member.api_key},
                      json={"company_legal_name": "No Access"})
    assert resp.status_code == 403


def test_settings_api_update(app_ctx, client, admin_member):
    resp = client.put("/api/settings",
                      headers={"X-API-Key": admin_member.api_key},
                      json={"company_legal_name": "API Corp"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["company_legal_name"] == "API Corp"


# --- #650: SOC 2 journey tests ---

def test_soc2_stages_default_not_started(app_ctx):
    with app_ctx.app_context():
        settings = get_portal_settings()
        assert settings["soc2_current_stage"] == "not_started"
        stages = settings["soc2_stages"]
        assert stages[0]["status"] == "current"
        assert all(s["status"] == "future" for s in stages[1:])


def test_soc2_stages_mid_journey(app_ctx):
    with app_ctx.app_context():
        update_portal_settings({"soc2_current_stage": "auditor_engaged"})
        settings = get_portal_settings()
        stages = settings["soc2_stages"]
        # First 3 completed, 4th current, rest future
        assert stages[0]["status"] == "completed"
        assert stages[1]["status"] == "completed"
        assert stages[2]["status"] == "completed"
        assert stages[3]["status"] == "current"
        assert stages[3]["key"] == "auditor_engaged"
        assert stages[4]["status"] == "future"


def test_soc2_stages_with_dates(app_ctx):
    with app_ctx.app_context():
        update_portal_settings({
            "soc2_current_stage": "collecting_continuous",
            "soc2_stage_dates": {"type_1_completed": "2026-06-15"},
        })
        settings = get_portal_settings()
        type_1 = next(s for s in settings["soc2_stages"] if s["key"] == "type_1_completed")
        assert type_1["date"] == "2026-06-15"
        assert type_1["status"] == "completed"


def test_soc2_journey_renders_on_home_page(app_ctx, client):
    with app_ctx.app_context():
        update_portal_settings({"soc2_current_stage": "policies_established"})

    resp = client.get("/")
    assert resp.status_code == 200
    assert b"SOC 2 Compliance Journey" in resp.data


def test_admin_settings_update_soc2_stage(app_ctx, client, admin_member):
    resp = client.post("/admin/settings",
                       headers={"X-API-Key": admin_member.api_key},
                       data={"soc2_current_stage": "auditor_engaged",
                             "type_1_date": "2026-07-01"})
    assert resp.status_code == 302

    with app_ctx.app_context():
        settings = get_portal_settings()
        assert settings["soc2_current_stage"] == "auditor_engaged"
        assert settings["soc2_stage_dates"]["type_1_completed"] == "2026-07-01"


def test_settings_api_includes_soc2_stages(client, member):
    resp = client.get("/api/settings", headers={"X-API-Key": member.api_key})
    data = resp.get_json()
    assert "soc2_current_stage" in data
    assert "soc2_stages" in data
    assert len(data["soc2_stages"]) == 7


# --- #649: Legal page tests ---

def test_legal_page_renders_default(client):
    resp = client.get("/legal")
    assert resp.status_code == 200
    assert b"Privacy Policy" in resp.data
    assert b"Terms of Use" in resp.data
    assert b"Accessibility" in resp.data


def test_legal_page_renders_db_content(app_ctx, client):
    with app_ctx.app_context():
        update_portal_settings({"legal_content_md": "# Custom Privacy\n\nCustom content here."})

    resp = client.get("/legal")
    assert resp.status_code == 200
    assert b"Custom Privacy" in resp.data
    assert b"Custom content here" in resp.data


def test_legal_page_redirects_to_external_url(app_ctx, client):
    with app_ctx.app_context():
        update_portal_settings({"legal_external_url": "https://example.com/privacy"})

    resp = client.get("/legal")
    assert resp.status_code == 302
    assert "example.com/privacy" in resp.headers["Location"]


def test_footer_contains_legal_link(client):
    resp = client.get("/")
    assert b"/legal" in resp.data


# --- #647: AI transparency tests ---

def test_ai_transparency_page_renders_default(client):
    resp = client.get("/ai-transparency")
    assert resp.status_code == 200
    assert b"AI-Driven Compliance" in resp.data
    assert b"Evidence Chain" in resp.data


def test_ai_transparency_page_renders_db_content(app_ctx, client):
    with app_ctx.app_context():
        update_portal_settings({"ai_transparency_md": "# Custom AI Statement\n\nOur custom approach."})

    resp = client.get("/ai-transparency")
    assert resp.status_code == 200
    assert b"Custom AI Statement" in resp.data


def test_home_page_has_ai_transparency_link(client):
    resp = client.get("/")
    assert b"ai-transparency" in resp.data
    assert b"AI-Driven Compliance" in resp.data


def test_navigation_has_ai_transparency_link(client):
    resp = client.get("/")
    assert b"AI Transparency" in resp.data


def test_admin_can_update_legal_and_ai_content(app_ctx, client, admin_member):
    resp = client.post("/admin/settings",
                       headers={"X-API-Key": admin_member.api_key},
                       data={
                           "legal_content_md": "# My Legal",
                           "ai_transparency_md": "# My AI",
                       })
    assert resp.status_code == 302

    with app_ctx.app_context():
        settings = get_portal_settings()
        assert settings["legal_content_md"] == "# My Legal"
        assert settings["ai_transparency_md"] == "# My AI"
