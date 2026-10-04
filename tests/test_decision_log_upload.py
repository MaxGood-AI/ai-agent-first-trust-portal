"""Tests for decision log upload endpoint."""

import gzip
import io
import json

import pytest
from sqlalchemy.exc import OperationalError

from app import create_app
from app.config import TestConfig
from app.models import db, DecisionLogSession, DecisionLogEntry, DecisionLogTranscript
from app.services import evidence_import, team_service


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
    return {"X-API-Key": member.issued_api_key}


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
        session = db.session.get(DecisionLogSession, "test-session-2")
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
        session = db.session.get(DecisionLogSession, "test-session-3")
        assert session.exit_reason == "user_exit"


def _upload(client, member, session_id, body):
    return client.post(
        f"/api/decision-log/upload?session_id={session_id}",
        data=body,
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )


def test_identical_reupload_is_a_noop(client, member):
    first = _upload(client, member, "dup-session", SAMPLE_JSONL)
    assert first.get_json()["status"] == "created"
    again = _upload(client, member, "dup-session", SAMPLE_JSONL)
    assert again.status_code == 200
    body = again.get_json()
    assert body["status"] == "unchanged"
    assert body["entries"] == 3
    assert body["content_sha256"] == first.get_json()["content_sha256"]


def test_longer_export_replaces_stored_transcript(client, member, app_ctx):
    _upload(client, member, "grow-session", SAMPLE_JSONL)
    extra = json.dumps({
        "type": "assistant",
        "message": {"role": "assistant", "content": [{"type": "text", "text": "More work"}],
                    "id": "msg-4", "model": "claude-opus-4-6"},
        "timestamp": "2026-03-16T12:10:00Z",
    })
    resp = _upload(client, member, "grow-session", SAMPLE_JSONL + "\n" + extra)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "replaced"
    assert body["entries"] == 4
    with app_ctx.app_context():
        session = db.session.get(DecisionLogSession, "grow-session")
        assert session.replaced_at is not None
        assert session.content_bytes == len((SAMPLE_JSONL + "\n" + extra).encode())
        assert DecisionLogEntry.query.filter_by(session_id="grow-session").count() == 4


def test_shorter_export_keeps_stored_transcript(client, member):
    _upload(client, member, "keep-session", SAMPLE_JSONL)
    shorter = "\n".join(SAMPLE_JSONL.split("\n")[:2])
    resp = _upload(client, member, "keep-session", shorter)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "kept_existing"
    assert body["entries"] == 3


def test_client_role_cannot_upload(client, app_ctx):
    reviewer = team_service.create_member("Reviewer", "r@example.com", "client")
    resp = _upload(client, reviewer, "client-session", SAMPLE_JSONL)
    assert resp.status_code == 403


def test_sessions_list_is_paginated_with_digests(client, member):
    for i in range(3):
        _upload(client, member, f"page-session-{i}", SAMPLE_JSONL)
    first = client.get("/api/decision-log/sessions?per_page=2", headers=_auth_headers(member)).get_json()
    assert first["total"] == 3 and first["pages"] == 2 and len(first["items"]) == 2
    second = client.get("/api/decision-log/sessions?per_page=2&page=2",
                        headers=_auth_headers(member)).get_json()
    assert len(second["items"]) == 1
    item = first["items"][0]
    assert item["entry_count"] == 3
    assert item["verifications"] == 1
    assert len(item["content_sha256"]) == 64
    assert item["content_bytes"] == len(SAMPLE_JSONL.encode())
    bad = client.get("/api/decision-log/sessions?page=x", headers=_auth_headers(member))
    assert bad.status_code == 400


def test_sessions_hidden_from_clients(client, app_ctx):
    reviewer = team_service.create_member("Reviewer", "r@example.com", "client")
    resp = client.get("/api/decision-log/sessions", headers=_auth_headers(reviewer))
    assert resp.status_code == 403


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
        session = db.session.get(DecisionLogSession, "meta-session")
        assert session.model == "claude-opus-4-6"
        assert session.cwd == "/home/dev"
        assert session.git_branch == "main"


# --- red-team finding 5: replacement only by extension; bounded bodies --------------------


def _line(text, index):
    return json.dumps({"type": "user", "timestamp": "2026-03-16T12:00:00Z",
                       "message": {"role": "user", "id": f"m{index}", "content": [{"type": "text", "text": text}]}})


def _jsonl(texts):
    return "\n".join(_line(text, index) for index, text in enumerate(texts))


def test_another_members_forged_transcript_is_rejected(client, app_ctx):
    genuine = team_service.create_member("Agent A", "a@example.com", "agent")
    other = team_service.create_member("Agent B", "b@example.com", "agent")
    assert _upload(client, genuine, "sess-genuine", _jsonl(["genuine decision", "done."])).get_json()["status"] \
        == "created"
    forged = _jsonl(["forged: approve without review", "totally different", "x" * 500])
    resp = _upload(client, other, "sess-genuine", forged)
    assert resp.status_code == 409
    body = resp.get_json()
    assert body["status"] == "rejected" and body["session_id"] == "sess-genuine"
    assert body["error"].startswith("entry 1 differs from the stored transcript")
    db.session.expire_all()
    texts = [e.content_text for e in DecisionLogEntry.query.filter_by(session_id="sess-genuine")]
    assert texts == ["genuine decision", "done."]
    assert db.session.get(DecisionLogSession, "sess-genuine").submitted_by == genuine.id
    (rejected,) = DecisionLogTranscript.query.filter_by(session_id="sess-genuine", status="rejected").all()
    assert rejected.submitted_by == other.id
    assert gzip.decompress(rejected.content_gz) == forged.encode()


def test_an_extension_by_another_member_is_forbidden(client, app_ctx):
    genuine = team_service.create_member("Agent A", "a@example.com", "agent")
    other = team_service.create_member("Agent B", "b@example.com", "agent")
    _upload(client, genuine, "sess-ext", _jsonl(["one", "two"]))
    resp = _upload(client, other, "sess-ext", _jsonl(["one", "two", "three"]))
    assert resp.status_code == 403
    assert resp.get_json()["status"] == "rejected"
    db.session.expire_all()
    assert [e.content_text for e in DecisionLogEntry.query.filter_by(session_id="sess-ext")] == ["one", "two"]
    assert db.session.get(DecisionLogSession, "sess-ext").submitted_by == genuine.id
    versions = {v.status: v for v in DecisionLogTranscript.query.filter_by(session_id="sess-ext")}
    assert set(versions) == {"current", "rejected"}
    assert versions["current"].submitted_by == genuine.id
    assert versions["rejected"].submitted_by == other.id
    assert _upload(client, genuine, "sess-ext", _jsonl(["one", "two", "three"])).get_json()["status"] \
        == "replaced"


def test_longer_garbage_is_kept_existing_not_a_wipe(client, member):
    _upload(client, member, "sess-1", _jsonl(["genuine decision", "done."]))
    resp = _upload(client, member, "sess-1", b"not json\n" * 200)
    assert resp.status_code == 200 and resp.get_json()["status"] == "kept_existing"
    assert DecisionLogEntry.query.filter_by(session_id="sess-1").count() == 2


@pytest.fixture
def small_limit(app_ctx):
    app_ctx.config["MAX_CONTENT_LENGTH"] = 1000
    return 1000


def _post_raw(client, member, body, *, chunked, terminated=True):
    environ = {"wsgi.input_terminated": True} if terminated else {}
    headers = {"X-API-Key": member.issued_api_key}
    if chunked:
        headers["Transfer-Encoding"] = "chunked"
    return client.post("/api/decision-log/upload?session_id=sess-limit", input_stream=io.BytesIO(body),
                       headers=headers, environ_overrides=environ)


def test_declared_body_over_the_limit_is_413(client, member, small_limit):
    resp = _upload(client, member, "sess-limit", "x" * (small_limit + 1))
    assert resp.status_code == 413
    assert DecisionLogSession.query.count() == 0
    at_limit = _jsonl(["y" * 10]).ljust(small_limit)
    assert _upload(client, member, "sess-limit", at_limit).status_code == 200


def test_chunked_body_over_the_limit_is_413_never_truncated(client, member, small_limit):
    line = _jsonl(["z" * 50]) + "\n"
    body = (line * (small_limit // len(line) + 2)).encode()
    assert len(body) > small_limit
    resp = _post_raw(client, member, body, chunked=True)
    assert resp.status_code == 413
    assert "exceeds the 1000 byte limit" in resp.get_json()["error"]
    assert DecisionLogSession.query.count() == 0

    exactly = body[:small_limit]
    resp = _post_raw(client, member, exactly, chunked=True)
    assert resp.status_code == 200
    assert resp.get_json()["content_bytes"] == small_limit


def test_chunked_body_the_server_does_not_delimit_is_411(client, member):
    resp = _post_raw(client, member, _jsonl(["hello"]).encode(), chunked=True, terminated=False)
    assert resp.status_code == 411
    assert DecisionLogSession.query.count() == 0


def test_upload_retries_once_after_a_deadlock(client, member, monkeypatch):
    class DeadlockDetected(Exception):
        pgcode = "40P01"

    real = evidence_import.import_decision_log
    calls = []

    def flaky(*args, **kwargs):
        calls.append(1)
        result = real(*args, **kwargs)
        if len(calls) == 1:
            raise OperationalError("INSERT", {}, DeadlockDetected())
        return result

    monkeypatch.setattr(evidence_import, "import_decision_log", flaky)
    resp = _upload(client, member, "sess-dl", SAMPLE_JSONL)
    assert resp.status_code == 200 and resp.get_json()["status"] == "created"
    assert len(calls) == 2
    assert DecisionLogEntry.query.filter_by(session_id="sess-dl").count() == 3

    def always(*args, **kwargs):
        calls.append(1)
        raise OperationalError("INSERT", {}, DeadlockDetected())

    monkeypatch.setattr(evidence_import, "import_decision_log", always)
    calls.clear()
    with pytest.raises(OperationalError):
        _upload(client, member, "sess-dl-2", SAMPLE_JSONL)
    assert len(calls) == 2
    assert db.session.get(DecisionLogSession, "sess-dl-2") is None
