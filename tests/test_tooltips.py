"""Tests for info tooltips on portal table headers (#648)."""

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, Control, System, Vendor, RiskRegister
from app.tooltip_definitions import TOOLTIPS


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


def test_tooltip_definitions_not_empty():
    assert len(TOOLTIPS) > 0
    for key, value in TOOLTIPS.items():
        assert isinstance(value, str)
        assert len(value) > 10


def test_tooltip_definitions_cover_all_pages():
    expected_keys = [
        "system_risk_score", "system_type", "system_provider",
        "vendor_status", "is_subprocessor", "vendor_classification",
        "risk_score", "risk_likelihood", "risk_impact", "risk_treatment", "risk_status",
        "policy_category", "policy_version",
        "control_category", "control_state",
        "test_status", "evidence_status",
    ]
    for key in expected_keys:
        assert key in TOOLTIPS, f"Missing tooltip definition: {key}"


def test_tooltips_injected_into_context(app_ctx, client):
    with app_ctx.app_context():
        System(id="sys-tt", name="Test System").save = None
        db.session.add(System(id="sys-tt", name="Test System"))
        db.session.commit()

    resp = client.get("/systems")
    assert resp.status_code == 200
    assert b"tooltip-icon" in resp.data


def test_systems_page_has_risk_score_tooltip(app_ctx, client):
    with app_ctx.app_context():
        db.session.add(System(id="sys-rs", name="RDS", risk_score=55.0))
        db.session.commit()

    resp = client.get("/systems")
    assert b"tooltip-content" in resp.data
    assert b"combined risk" in resp.data.lower()


def test_vendors_page_has_subprocessor_tooltip(app_ctx, client):
    with app_ctx.app_context():
        db.session.add(Vendor(id="vnd-tt", name="AWS", is_subprocessor=True))
        db.session.commit()

    resp = client.get("/vendors")
    assert b"tooltip-content" in resp.data
    assert b"personal data" in resp.data.lower()


def test_risks_page_has_tooltips(app_ctx, client):
    with app_ctx.app_context():
        db.session.add(RiskRegister(id="risk-tt", name="Test Risk", likelihood=3, impact=4))
        db.session.commit()

    resp = client.get("/risks")
    assert b"tooltip-content" in resp.data


def test_tooltip_macro_handles_missing_key(app_ctx, client):
    """Pages render fine even if a tooltip key doesn't exist."""
    resp = client.get("/systems")
    assert resp.status_code == 200


def test_policies_page_no_stale_brand_name_ref(client):
    """Policies page must not reference stale {{ brand_name }} variable."""
    resp = client.get("/policies")
    assert resp.status_code == 200
    assert b"brand_name" not in resp.data
