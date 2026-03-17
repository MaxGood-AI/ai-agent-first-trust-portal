"""Tests for decision log upload endpoint."""

import json

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, DecisionLogSession, DecisionLogEntry
from app.services import team_service


SAMPLE_JSONL = "\n".join([
    json.dumps({
        "type": "user",
        "message": {"role": "user", "content": [{"type": "text", "text": "Hello"}], "id": "msg-1"},
        "timestamp": "2026-03-16T12:00:00Z",
        "cwd": "/home/dev",
        "gitBranch": "main",
    }),
    json.dumps({
        "type": "assistant",
        "message": {"role": "assistant", "content": [{"type": "text", "text": "Hi there"}],
                    "id": "msg-2", "model": "claude-opus-4-6"},
        "timestamp": "2026-03-16T12:00:01Z",
    }),
    json.dumps({
        "type": "user",
        "message": {"role": "user", "content": [{"type": "text", "text": "done."}], "id": "msg-3"},
        "timestamp": "2026-03-16T12:00:05Z",
    }),
])


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
    return team_service.create_member("Test Agent", "agent@example.com", "agent")


def _auth_headers(member):
    return {"X-API-Key": member.api_key}


def test_upload_valid_jsonl(client, member):
    resp = client.post(
        "/api/decision-log/upload?session_id=test-session-1",
        data=SAMPLE_JSONL,
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["session_id"] == "test-session-1"
    assert data["entries"] == 3


def test_upload_sets_submitted_by(client, member, app_ctx):
    client.post(
        "/api/decision-log/upload?session_id=test-session-2",
        data=SAMPLE_JSONL,
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    with app_ctx.app_context():
        session = DecisionLogSession.query.get("test-session-2")
        assert session.submitted_by == member.id


def test_upload_generates_session_id(client, member):
    resp = client.post(
        "/api/decision-log/upload",
        data=SAMPLE_JSONL,
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["session_id"] is not None
    assert len(data["session_id"]) > 0


def test_upload_with_exit_reason(client, member, app_ctx):
    client.post(
        "/api/decision-log/upload?session_id=test-session-3&exit_reason=user_exit",
        data=SAMPLE_JSONL,
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    with app_ctx.app_context():
        session = DecisionLogSession.query.get("test-session-3")
        assert session.exit_reason == "user_exit"


def test_upload_duplicate_session(client, member):
    client.post(
        "/api/decision-log/upload?session_id=dup-session",
        data=SAMPLE_JSONL,
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    resp = client.post(
        "/api/decision-log/upload?session_id=dup-session",
        data=SAMPLE_JSONL,
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    assert resp.status_code == 400
    assert "already exists" in resp.get_json()["error"]


def test_upload_empty_body(client, member):
    resp = client.post(
        "/api/decision-log/upload",
        data="",
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "Empty request body"


def test_upload_requires_auth(client):
    resp = client.post(
        "/api/decision-log/upload",
        data=SAMPLE_JSONL,
        content_type="application/jsonl",
    )
    assert resp.status_code == 401


def test_upload_detects_verification(client, member, app_ctx):
    client.post(
        "/api/decision-log/upload?session_id=verify-session",
        data=SAMPLE_JSONL,
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    with app_ctx.app_context():
        entries = DecisionLogEntry.query.filter_by(session_id="verify-session").all()
        verifications = [e for e in entries if e.is_verification]
        assert len(verifications) == 1
        assert verifications[0].content_text == "done."


def test_upload_parses_metadata(client, member, app_ctx):
    client.post(
        "/api/decision-log/upload?session_id=meta-session",
        data=SAMPLE_JSONL,
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    with app_ctx.app_context():
        session = DecisionLogSession.query.get("meta-session")
        assert session.model == "claude-opus-4-6"
        assert session.cwd == "/home/dev"
        assert session.git_branch == "main"
