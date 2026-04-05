"""Tests for the compliance scoring engine."""

import uuid

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, Control, TestRecord
from app.services.compliance_engine import (
    calculate_overall_score,
    calculate_category_score,
    get_evidence_gaps,
    get_compliance_summary,
)


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def seed_data(app):
    """Seed the database with test controls and test records."""
    with app.app_context():
        control = Control(
            id=str(uuid.uuid4()),
            name="Test MFA Control",
            category="security",
            state="adopted",
        )
        db.session.add(control)

        for i, status in enumerate(["passed", "passed", "failed"]):
            tr = TestRecord(
                id=str(uuid.uuid4()),
                control_id=control.id,
                name=f"Test {i}",
                status=status,
                evidence_status="submitted" if status == "passed" else "missing",
            )
            db.session.add(tr)

        avail_control = Control(
            id=str(uuid.uuid4()),
            name="Backup Control",
            category="availability",
            state="adopted",
        )
        db.session.add(avail_control)

        tr_avail = TestRecord(
            id=str(uuid.uuid4()),
            control_id=avail_control.id,
            name="Backup test",
            status="passed",
            evidence_status="submitted",
        )
        db.session.add(tr_avail)

        db.session.commit()
        return {"security_control": control, "availability_control": avail_control}


def test_overall_score_empty_db(app):
    with app.app_context():
        assert calculate_overall_score() == 0.0


def test_overall_score_with_data(app, seed_data):
    with app.app_context():
        # 3 passed out of 4 total = 75.0%
        assert calculate_overall_score() == 75.0


def test_category_score(app, seed_data):
    with app.app_context():
        # Security: 2 passed / 3 total = 66.7%
        assert calculate_category_score("security") == 66.7
        # Availability: 1 passed / 1 total = 100.0%
        assert calculate_category_score("availability") == 100.0
        # Privacy: no controls = 0.0%
        assert calculate_category_score("privacy") == 0.0


def test_evidence_gaps(app, seed_data):
    with app.app_context():
        gaps = get_evidence_gaps()
        assert len(gaps) == 1
        assert gaps[0].evidence_status == "missing"


def test_compliance_summary(app, seed_data):
    with app.app_context():
        summary = get_compliance_summary()
        assert summary["overall_score"] == 75.0
        assert summary["total_controls"] == 2
        assert summary["total_tests"] == 4
        assert summary["evidence_gaps"] == 1
        assert summary["categories"]["security"] == 66.7
        assert summary["categories"]["availability"] == 100.0


def test_category_score_privacy_with_controls(app):
    """Privacy controls score correctly when data exists."""
    with app.app_context():
        ctrl = Control(id="priv-ctrl-1", name="Privacy Notice", category="privacy", state="adopted")
        db.session.add(ctrl)
        for i, status in enumerate(["passed", "pending"]):
            tr = TestRecord(
                id=f"priv-test-{i}",
                control_id="priv-ctrl-1",
                name=f"Privacy test {i}",
                status=status,
                evidence_status="submitted" if status == "passed" else "missing",
            )
            db.session.add(tr)
        db.session.commit()

        score = calculate_category_score("privacy")
        assert score == 50.0  # 1 passed / 2 total


def test_compliance_summary_includes_privacy(app):
    """Privacy category appears in summary when controls exist."""
    with app.app_context():
        for cat in ["security", "availability", "confidentiality", "privacy", "processing_integrity"]:
            ctrl = Control(id=f"sum-{cat}", name=f"{cat} control", category=cat, state="adopted")
            db.session.add(ctrl)
            tr = TestRecord(
                id=f"sum-test-{cat}",
                control_id=f"sum-{cat}",
                name=f"{cat} test",
                status="passed",
                evidence_status="submitted",
            )
            db.session.add(tr)
        db.session.commit()

        summary = get_compliance_summary()
        assert "privacy" in summary["categories"]
        assert summary["categories"]["privacy"] == 100.0
        assert summary["total_controls"] == 5
