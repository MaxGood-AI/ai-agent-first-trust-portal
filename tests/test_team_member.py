"""Tests for team member model and service."""

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, TeamMember
from app.services import team_service


@pytest.fixture
def app_ctx():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_create_human_member(app_ctx):
    member = team_service.create_member("Jane Smith", "jane@example.com", "human")
    assert member.name == "Jane Smith"
    assert member.email == "jane@example.com"
    assert member.role == "human"
    assert member.is_active is True
    assert member.is_compliance_admin is False
    assert len(member.api_key) > 0
    assert member.id is not None


def test_create_agent_member(app_ctx):
    member = team_service.create_member("Claude Opus", "claude@noreply.anthropic.com", "agent")
    assert member.role == "agent"
    assert member.email == "claude@noreply.anthropic.com"


def test_create_compliance_admin(app_ctx):
    member = team_service.create_member("Admin", "admin@example.com", "human",
                                        is_compliance_admin=True)
    assert member.is_compliance_admin is True


def test_api_key_uniqueness(app_ctx):
    m1 = team_service.create_member("A", "a@example.com", "human")
    m2 = team_service.create_member("B", "b@example.com", "human")
    assert m1.api_key != m2.api_key


def test_api_key_format(app_ctx):
    member = team_service.create_member("Test", "test@example.com", "human")
    # secrets.token_urlsafe(32) produces 43-character base64url string
    assert len(member.api_key) == 43


def test_list_members_excludes_inactive(app_ctx):
    team_service.create_member("Active", "active@example.com", "human")
    inactive = team_service.create_member("Inactive", "inactive@example.com", "human")
    team_service.deactivate_member(inactive.id)

    members = team_service.list_members()
    assert len(members) == 1
    assert members[0].name == "Active"


def test_list_members_include_inactive(app_ctx):
    team_service.create_member("Active", "active@example.com", "human")
    inactive = team_service.create_member("Inactive", "inactive@example.com", "human")
    team_service.deactivate_member(inactive.id)

    members = team_service.list_members(include_inactive=True)
    assert len(members) == 2


def test_deactivate_member(app_ctx):
    member = team_service.create_member("Test", "test@example.com", "human")
    result = team_service.deactivate_member(member.id)
    assert result.is_active is False


def test_deactivate_nonexistent(app_ctx):
    result = team_service.deactivate_member("nonexistent-id")
    assert result is None


def test_regenerate_key(app_ctx):
    member = team_service.create_member("Test", "test@example.com", "human")
    old_key = member.api_key
    result = team_service.regenerate_key(member.id)
    assert result.api_key != old_key
    assert len(result.api_key) == 43


def test_regenerate_key_nonexistent(app_ctx):
    result = team_service.regenerate_key("nonexistent-id")
    assert result is None
