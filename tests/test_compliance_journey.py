"""Tests for the compliance-journey API endpoint."""

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, Control, TestRecord, Policy, System, Vendor, Evidence
from app.services import team_service


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_headers(app):
    with app.app_context():
        member = team_service.create_member("Test User", "test@test.com", "human")
        return {"X-API-Key": member.api_key}


class TestComplianceJourney:
    def test_empty_database_starts_at_discovery(self, client, auth_headers):
        """With team member from auth + default settings, bootstrap is auto-complete.
        Phase 2 (discovery) is the first real work phase."""
        resp = client.get("/api/compliance-journey", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()["journey"]
        # Bootstrap is satisfied by defaults + team member from auth fixture
        assert data["current_phase"] == 2
        assert data["current_phase_name"] == "discovery"
        assert data["compliance_score"] == 0.0
        assert data["soc2_stage"] == "not_started"
        assert len(data["next_actions"]) > 0

    def test_phase_1_complete_with_settings(self, client, auth_headers, app):
        """Settings configured + team member = Phase 1 complete, move to Phase 2."""
        with app.app_context():
            from app.models.portal_settings import PortalSettings
            settings = PortalSettings(id=1, company_legal_name="Test Corp")
            db.session.add(settings)
            db.session.commit()

        resp = client.get("/api/compliance-journey", headers=auth_headers)
        data = resp.get_json()["journey"]
        assert data["current_phase"] == 2
        assert data["phases"]["1_bootstrap"]["status"] == "completed"

    def test_phase_2_needs_systems_and_vendors(self, client, auth_headers, app):
        """Phase 2 requires at least one system and one vendor."""
        with app.app_context():
            from app.models.portal_settings import PortalSettings
            db.session.add(PortalSettings(id=1, company_legal_name="Test Corp"))
            db.session.add(System(id="sys-1", name="AWS"))
            db.session.commit()

        resp = client.get("/api/compliance-journey", headers=auth_headers)
        data = resp.get_json()["journey"]
        assert data["current_phase"] == 2  # still phase 2 — no vendors yet
        assert data["phases"]["2_discovery"]["checks"]["systems_registered"] is True
        assert data["phases"]["2_discovery"]["checks"]["vendors_registered"] is False

    def test_phase_2_complete(self, client, auth_headers, app):
        """System + vendor registered = Phase 2 complete."""
        with app.app_context():
            from app.models.portal_settings import PortalSettings
            db.session.add(PortalSettings(id=1, company_legal_name="Test Corp"))
            db.session.add(System(id="sys-1", name="AWS"))
            db.session.add(Vendor(id="vend-1", name="GitHub"))
            db.session.commit()

        resp = client.get("/api/compliance-journey", headers=auth_headers)
        data = resp.get_json()["journey"]
        assert data["current_phase"] == 3
        assert data["phases"]["2_discovery"]["status"] == "completed"

    def test_phase_3_needs_policies(self, client, auth_headers, app):
        """Phase 3 needs 5+ approved policies covering all TSC categories."""
        with app.app_context():
            from app.models.portal_settings import PortalSettings
            db.session.add(PortalSettings(id=1, company_legal_name="Test Corp"))
            db.session.add(System(id="sys-1", name="AWS"))
            db.session.add(Vendor(id="vend-1", name="GitHub"))
            # Only 2 policies, not enough
            db.session.add(Policy(id="pol-1", title="Security", category="security", status="approved"))
            db.session.add(Policy(id="pol-2", title="Privacy", category="privacy", status="approved"))
            db.session.commit()

        resp = client.get("/api/compliance-journey", headers=auth_headers)
        data = resp.get_json()["journey"]
        assert data["current_phase"] == 3
        assert data["phases"]["3_policies"]["checks"]["policies_count"] == 2
        assert len(data["phases"]["3_policies"]["checks"]["categories_missing"]) > 0

    def test_next_actions_populated(self, client, auth_headers, app):
        """Next actions should give specific guidance."""
        with app.app_context():
            from app.models.portal_settings import PortalSettings
            db.session.add(PortalSettings(id=1, company_legal_name="Test Corp"))
            db.session.add(System(id="sys-1", name="AWS"))
            db.session.add(Vendor(id="vend-1", name="GitHub"))
            db.session.commit()

        resp = client.get("/api/compliance-journey", headers=auth_headers)
        data = resp.get_json()["journey"]
        assert len(data["next_actions"]) > 0
        # Should mention policies since that's the current phase
        assert any("polic" in a.lower() for a in data["next_actions"])

    def test_requires_auth(self, client):
        resp = client.get("/api/compliance-journey")
        assert resp.status_code == 401

    def test_response_structure(self, client, auth_headers):
        """Verify the full response structure exists."""
        resp = client.get("/api/compliance-journey", headers=auth_headers)
        data = resp.get_json()
        assert "journey" in data
        j = data["journey"]
        assert "current_phase" in j
        assert "current_phase_name" in j
        assert "phases" in j
        assert "next_actions" in j
        assert "compliance_score" in j
        assert "soc2_stage" in j

        expected_phases = [
            "1_bootstrap", "2_discovery", "3_policies", "4_controls_and_tests",
            "5_evidence_collection", "6_gap_analysis", "7_audit_prep", "8_ongoing"
        ]
        for phase in expected_phases:
            assert phase in j["phases"]
            assert "status" in j["phases"][phase]
            assert "checks" in j["phases"][phase]
