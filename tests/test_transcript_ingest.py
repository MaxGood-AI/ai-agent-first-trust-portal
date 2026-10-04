"""Tests for transcript ingest: Claude Code, openclaude and Codex formats, and agent labels.

Every transcript here is synthetic, built from the record shapes each agent
CLI writes.
"""

import json

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db, DecisionLogSession, DecisionLogEntry
from app.services import team_service
from app.services import transcript_ingest
from app.services.transcript_ingest import (
    detect_agent_type,
    ingest_all_pending,
    ingest_from_content,
    normalize_agent_type,
)


def _jsonl(records):
    return "\n".join(json.dumps(record) for record in records)


# --- synthetic transcripts ----------------------------------------------------

CLAUDE_CODE_RECORDS = [
    {"type": "permission-mode", "permissionMode": "default", "sessionId": "cc-1"},
    {"type": "file-history-snapshot", "messageId": "snap-1", "snapshot": {}},
    {
        "type": "user", "version": "9.9.9", "cwd": "/work/repo", "gitBranch": "main",
        "timestamp": "2026-01-02T10:00:00.000Z",
        "message": {"role": "user", "content": "Add a widget"},
    },
    {
        "type": "assistant", "version": "9.9.9", "timestamp": "2026-01-02T10:00:02.000Z",
        "message": {"role": "assistant", "id": "msg-a1", "model": "claude-model-x",
                    "content": [{"type": "thinking", "thinking": "private"}]},
    },
    {
        "type": "assistant", "version": "9.9.9", "timestamp": "2026-01-02T10:00:03.000Z",
        "message": {"role": "assistant", "id": "msg-a1", "model": "claude-model-x",
                    "content": [{"type": "text", "text": "Reading the file."}]},
    },
    {
        "type": "assistant", "version": "9.9.9", "timestamp": "2026-01-02T10:00:04.000Z",
        "message": {"role": "assistant", "id": "msg-a1", "model": "claude-model-x",
                    "content": [{"type": "tool_use", "id": "toolu_1", "name": "Read",
                                 "input": {"file_path": "/work/repo/a.py"}}]},
    },
    {
        "type": "user", "timestamp": "2026-01-02T10:00:05.000Z",
        "message": {"role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": "toolu_1",
                                 "content": "file body"}]},
    },
    {"type": "system", "subtype": "info", "content": "note", "timestamp": "2026-01-02T10:00:06.000Z"},
    {
        "type": "user", "timestamp": "2026-01-02T10:00:09.000Z",
        "message": {"role": "user", "content": [{"type": "text", "text": "Done."}]},
    },
]

CODEX_RECORDS = [
    {"timestamp": "2026-01-03T09:00:00.000Z", "type": "session_meta", "ordinal": 0,
     "payload": {"id": "cx-1", "session_id": "cx-1", "cwd": "/work/codex",
                 "originator": "codex_exec", "cli_version": "0.1.0",
                 "git": {"branch": "feature/x", "commit_hash": "abc123"}}},
    {"timestamp": "2026-01-03T09:00:00.100Z", "type": "event_msg", "ordinal": 1,
     "payload": {"type": "task_started", "turn_id": "turn-1"}},
    {"timestamp": "2026-01-03T09:00:00.200Z", "type": "response_item", "ordinal": 2,
     "payload": {"type": "message", "role": "developer", "id": "dev-1",
                 "content": [{"type": "input_text", "text": "sandbox rules"}]}},
    {"timestamp": "2026-01-03T09:00:00.300Z", "type": "turn_context", "ordinal": 3,
     "payload": {"cwd": "/work/codex", "model": "codex-model-y", "approval_policy": "never"}},
    {"timestamp": "2026-01-03T09:00:01.000Z", "type": "response_item", "ordinal": 4,
     "payload": {"type": "message", "role": "user", "id": "u-1",
                 "content": [{"type": "input_text", "text": "Fix the bug"},
                             {"type": "input_image", "image_url": "data:"}]}},
    {"timestamp": "2026-01-03T09:00:01.100Z", "type": "event_msg", "ordinal": 5,
     "payload": {"type": "item_completed",
                 "item": {"type": "UserMessage", "content": [{"type": "text", "text": "Fix the bug"}]}}},
    {"timestamp": "2026-01-03T09:00:02.000Z", "type": "response_item", "ordinal": 6,
     "payload": {"type": "reasoning", "id": "rs-1", "summary": [{"type": "summary_text", "text": "hidden"}],
                 "encrypted_content": "opaque"}},
    {"timestamp": "2026-01-03T09:00:03.000Z", "type": "response_item", "ordinal": 7,
     "payload": {"type": "custom_tool_call", "id": "ctc-1", "call_id": "call_1", "name": "exec",
                 "input": "cat README.md", "status": "completed"}},
    {"timestamp": "2026-01-03T09:00:04.000Z", "type": "response_item", "ordinal": 8,
     "payload": {"type": "custom_tool_call_output", "call_id": "call_1",
                 "output": [{"type": "input_text", "text": "tool output"}]}},
    {"timestamp": "2026-01-03T09:00:05.000Z", "type": "response_item", "ordinal": 9,
     "payload": {"type": "function_call", "id": "fc-1", "call_id": "call_2", "name": "shell",
                 "arguments": "{\"command\": [\"ls\", \"-la\"]}"}},
    {"timestamp": "2026-01-03T09:00:05.500Z", "type": "response_item", "ordinal": 10,
     "payload": {"type": "function_call_output", "call_id": "call_2", "output": "listing"}},
    {"timestamp": "2026-01-03T09:00:06.000Z", "type": "response_item", "ordinal": 11,
     "payload": {"type": "local_shell_call", "call_id": "call_3", "status": "completed",
                 "action": {"type": "exec", "command": ["pwd"]}}},
    {"timestamp": "2026-01-03T09:00:06.500Z", "type": "token_usage_record", "ordinal": 12,
     "payload": {"usage": {"input_tokens": 10}}},
    {"timestamp": "2026-01-03T09:00:07.000Z", "type": "response_item", "ordinal": 13,
     "payload": {"type": "message", "role": "assistant", "id": "a-1", "phase": "commentary",
                 "content": [{"type": "output_text", "text": "Looking around."}]}},
    {"timestamp": "2026-01-03T09:00:08.000Z", "type": "response_item", "ordinal": 14,
     "payload": {"type": "message", "role": "assistant", "id": "a-2", "phase": "final_answer",
                 "content": [{"type": "output_text", "text": "Fixed."},
                             {"type": "output_text", "text": "Tests pass."}]}},
    {"timestamp": "2026-01-03T09:00:20.000Z", "type": "response_item", "ordinal": 15,
     "payload": {"type": "message", "role": "user", "id": "u-2",
                 "content": [{"type": "input_text", "text": "done."}]}},
    {"timestamp": "2026-01-03T09:00:21.000Z", "type": "event_msg", "ordinal": 16,
     "payload": {"type": "task_complete", "turn_id": "turn-1"}},
]

OPENCLAUDE_RECORDS = [
    {"type": "mode", "mode": "default", "sessionId": "oc-1"},
    {
        "type": "user", "version": "unknown", "entrypoint": "cli", "userType": "external",
        "cwd": "/work/oc", "gitBranch": "dev", "isMeta": False,
        "timestamp": "2026-01-04T08:00:00.000Z",
        "message": {"role": "user", "content": "Summarise the repo"},
    },
    {
        "type": "assistant", "version": "unknown", "timestamp": "2026-01-04T08:00:01.000Z",
        "message": {"role": "assistant", "id": "oc-msg-1", "model": "some-model",
                    "content": [{"type": "text", "text": "It is a portal."}]},
    },
]


# --- fixtures -------------------------------------------------------------------

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


def _entries(session_id):
    return (DecisionLogEntry.query.filter_by(session_id=session_id)
            .order_by(DecisionLogEntry.id).all())


# --- agent labels ---------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("claude-code", "claude_code"),
    ("claude_code", "claude_code"),
    ("Codex", "codex"),
    ("  openclaude\n", "openclaude"),
    ("agent-2", "agent_2"),
    ("a" * 50, "a" * 50),
])
def test_normalize_agent_type_accepts_names(raw, expected):
    assert normalize_agent_type(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "   ", "bad agent", "codex!", "a" * 51, 7, ["codex"]])
def test_normalize_agent_type_rejects_unusable_names(raw):
    assert normalize_agent_type(raw) is None


def test_detect_agent_type_by_record_format():
    assert detect_agent_type(CODEX_RECORDS) == "codex"
    assert detect_agent_type(CLAUDE_CODE_RECORDS) == "claude_code"
    assert detect_agent_type(OPENCLAUDE_RECORDS) == "claude_code"
    assert detect_agent_type([]) == "claude_code"
    assert detect_agent_type([{"type": "response_item", "payload": "not-a-dict"}]) == "claude_code"
    assert detect_agent_type([["list"], 3, {"type": "session_meta", "payload": {}}]) == "codex"


# --- Claude Code ------------------------------------------------------------------

def test_claude_code_transcript_parsed(app_ctx):
    session = ingest_from_content(_jsonl(CLAUDE_CODE_RECORDS), "cc-1")

    assert session.agent_type == "claude_code"
    assert session.model == "9.9.9"
    assert session.cwd == "/work/repo"
    assert session.git_branch == "main"
    assert session.started_at.isoformat().startswith("2026-01-02T10:00:00")
    assert session.ended_at.isoformat().startswith("2026-01-02T10:00:09")

    entries = _entries("cc-1")
    assert [(e.role, e.content_text) for e in entries] == [
        ("user", "Add a widget"),
        ("assistant", None),
        ("assistant", "Reading the file."),
        ("assistant", None),
        ("user", None),
        ("user", "Done."),
    ]
    assert entries[1].tool_calls is None
    assert json.loads(entries[3].tool_calls) == [
        {"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {"file_path": "/work/repo/a.py"}},
    ]
    assert [e.message_id for e in entries] == [None, "msg-a1", "msg-a1", "msg-a1", None, None]
    assert [e.is_verification for e in entries] == [False, False, False, False, False, True]


def test_claude_code_model_falls_back_to_message_model(app_ctx):
    records = [
        {"type": "user", "timestamp": "2026-01-02T10:00:00Z",
         "message": {"role": "user", "content": "hi"}},
        {"type": "assistant", "timestamp": "2026-01-02T10:00:01Z",
         "message": {"role": "assistant", "model": "claude-model-x", "content": []}},
    ]
    session = ingest_from_content(_jsonl(records), "cc-2")
    assert session.model == "claude-model-x"


def test_claude_code_ignores_blank_and_invalid_lines(app_ctx):
    content = "\n\nnot json\n" + _jsonl(CLAUDE_CODE_RECORDS[2:3]) + "\n   \n"
    session = ingest_from_content(content, "cc-3")
    assert session.agent_type == "claude_code"
    assert len(_entries("cc-3")) == 1


def test_claude_code_named_agent_label(app_ctx):
    session = ingest_from_content(_jsonl(CLAUDE_CODE_RECORDS), "cc-4", agent_type="claude-code")
    assert session.agent_type == "claude_code"


# --- openclaude ------------------------------------------------------------------

def test_openclaude_transcript_parsed_with_named_label(app_ctx):
    session = ingest_from_content(_jsonl(OPENCLAUDE_RECORDS), "oc-1", agent_type="openclaude")

    assert session.agent_type == "openclaude"
    assert session.model == "unknown"
    assert session.cwd == "/work/oc"
    assert session.git_branch == "dev"
    assert [(e.role, e.content_text, e.message_id) for e in _entries("oc-1")] == [
        ("user", "Summarise the repo", None),
        ("assistant", "It is a portal.", "oc-msg-1"),
    ]


def test_openclaude_transcript_without_named_agent_detected_as_claude_code(app_ctx):
    session = ingest_from_content(_jsonl(OPENCLAUDE_RECORDS), "oc-2")
    assert session.agent_type == "claude_code"
    assert len(_entries("oc-2")) == 2


# --- Codex ----------------------------------------------------------------------

def test_codex_transcript_parsed(app_ctx):
    session = ingest_from_content(_jsonl(CODEX_RECORDS), "cx-1")

    assert session.agent_type == "codex"
    assert session.model == "codex-model-y"
    assert session.cwd == "/work/codex"
    assert session.git_branch == "feature/x"
    assert session.started_at.isoformat().startswith("2026-01-03T09:00:00")
    assert session.ended_at.isoformat().startswith("2026-01-03T09:00:21")

    entries = _entries("cx-1")
    assert [(e.role, e.content_text, e.message_id) for e in entries] == [
        ("user", "Fix the bug", "u-1"),
        ("assistant", None, "ctc-1"),
        ("assistant", None, "fc-1"),
        ("assistant", None, None),
        ("assistant", "Looking around.", "a-1"),
        ("assistant", "Fixed.\nTests pass.", "a-2"),
        ("user", "done.", "u-2"),
    ]
    assert [e.is_verification for e in entries] == [False] * 6 + [True]
    assert entries[0].tool_calls is None
    assert entries[4].tool_calls is None
    assert json.loads(entries[1].tool_calls) == [
        {"type": "tool_use", "id": "call_1", "name": "exec", "input": "cat README.md"},
    ]
    assert json.loads(entries[2].tool_calls) == [
        {"type": "tool_use", "id": "call_2", "name": "shell", "input": {"command": ["ls", "-la"]}},
    ]
    assert json.loads(entries[3].tool_calls) == [
        {"type": "tool_use", "id": "call_3", "name": "local_shell",
         "input": {"type": "exec", "command": ["pwd"]}},
    ]
    assert entries[1].timestamp.isoformat().startswith("2026-01-03T09:00:03")


def test_codex_stores_no_developer_reasoning_or_tool_output(app_ctx):
    ingest_from_content(_jsonl(CODEX_RECORDS), "cx-2")
    texts = [e.content_text for e in _entries("cx-2") if e.content_text]
    for hidden in ("sandbox rules", "hidden", "opaque", "tool output", "listing"):
        assert all(hidden not in text for text in texts)


def test_codex_function_call_with_non_json_arguments_keeps_raw_text(app_ctx):
    records = [
        {"timestamp": "2026-01-03T09:00:00Z", "type": "response_item",
         "payload": {"type": "function_call", "call_id": "call_9", "name": "apply_patch",
                     "arguments": "*** Begin Patch"}},
        {"timestamp": "2026-01-03T09:00:01Z", "type": "response_item",
         "payload": {"type": "web_search_call", "id": "ws_1", "action": {"query": "flask"}}},
    ]
    ingest_from_content(_jsonl(records), "cx-3")
    entries = _entries("cx-3")
    assert json.loads(entries[0].tool_calls) == [
        {"type": "tool_use", "id": "call_9", "name": "apply_patch", "input": "*** Begin Patch"},
    ]
    assert json.loads(entries[1].tool_calls) == [
        {"type": "tool_use", "id": "ws_1", "name": "web_search", "input": {"query": "flask"}},
    ]


def test_codex_message_content_variants(app_ctx):
    records = [
        {"timestamp": "2026-01-03T09:00:00Z", "type": "response_item",
         "payload": {"type": "message", "role": "user", "content": "plain string"}},
        {"timestamp": "2026-01-03T09:00:01Z", "type": "response_item",
         "payload": {"type": "message", "role": "assistant", "content": None}},
        {"timestamp": "2026-01-03T09:00:02Z", "type": "response_item",
         "payload": {"type": "message", "role": "assistant",
                     "content": [{"type": "output_text", "text": None}, "stray", {"type": "text", "text": "ok"}]}},
        {"timestamp": "2026-01-03T09:00:03Z", "type": "response_item", "payload": {"type": None}},
        {"timestamp": "2026-01-03T09:00:04Z", "type": "event_msg", "payload": "not-a-dict"},
        ["not", "a", "record"],
    ]
    session = ingest_from_content(_jsonl(records), "cx-4")
    assert session.agent_type == "codex"
    assert session.model is None
    assert [(e.role, e.content_text) for e in _entries("cx-4")] == [
        ("user", "plain string"),
        ("assistant", None),
        ("assistant", "ok"),
    ]


def test_codex_session_meta_only_is_empty_session(app_ctx):
    session = ingest_from_content(_jsonl(CODEX_RECORDS[:1]), "cx-5")
    assert session.agent_type == "codex"
    assert session.cwd == "/work/codex"
    assert session.started_at is not None
    assert _entries("cx-5") == []


def test_named_agent_overrides_detected_format(app_ctx):
    session = ingest_from_content(_jsonl(CODEX_RECORDS), "cx-6", agent_type="Codex")
    assert session.agent_type == "codex"
    session = ingest_from_content(_jsonl(CLAUDE_CODE_RECORDS), "cc-5", agent_type="openclaude")
    assert session.agent_type == "openclaude"


def test_unusable_named_agent_falls_back_to_detection(app_ctx):
    session = ingest_from_content(_jsonl(CODEX_RECORDS), "cx-7", agent_type="not valid!")
    assert session.agent_type == "codex"


def test_existing_session_is_not_replaced(app_ctx):
    ingest_from_content(_jsonl(CODEX_RECORDS[:1]), "cx-8")
    assert ingest_from_content(_jsonl(CODEX_RECORDS), "cx-8", agent_type="codex") is None
    assert _entries("cx-8") == []


# --- upload endpoint ------------------------------------------------------------

def test_upload_codex_detects_agent(client, member, app_ctx):
    resp = client.post(
        "/api/decision-log/upload?session_id=up-cx-1",
        data=_jsonl(CODEX_RECORDS),
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"session_id": "up-cx-1", "entries": 7, "agent_type": "codex"}


def test_upload_agent_parameter_labels_session(client, member, app_ctx):
    resp = client.post(
        "/api/decision-log/upload?session_id=up-oc-1&agent=openclaude",
        data=_jsonl(OPENCLAUDE_RECORDS),
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    assert resp.status_code == 200
    assert resp.get_json()["agent_type"] == "openclaude"
    assert DecisionLogSession.query.get("up-oc-1").agent_type == "openclaude"


def test_upload_claude_code_agent_parameter_normalised(client, member, app_ctx):
    resp = client.post(
        "/api/decision-log/upload?session_id=up-cc-1&agent=claude-code",
        data=_jsonl(CLAUDE_CODE_RECORDS),
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"session_id": "up-cc-1", "entries": 6, "agent_type": "claude_code"}


def test_upload_invalid_agent_rejected(client, member, app_ctx):
    resp = client.post(
        "/api/decision-log/upload?session_id=up-bad-1&agent=bad%20agent",
        data=_jsonl(CODEX_RECORDS),
        content_type="application/jsonl",
        headers=_auth_headers(member),
    )
    assert resp.status_code == 400
    assert "Invalid agent" in resp.get_json()["error"]
    assert DecisionLogSession.query.get("up-bad-1") is None


def test_sessions_list_reports_agent_type(client, member, app_ctx):
    for sid, records, agent in (("ls-cx", CODEX_RECORDS, ""), ("ls-oc", OPENCLAUDE_RECORDS, "&agent=openclaude"),
                                ("ls-cc", CLAUDE_CODE_RECORDS, "")):
        client.post(f"/api/decision-log/upload?session_id={sid}{agent}", data=_jsonl(records),
                    content_type="application/jsonl", headers=_auth_headers(member))
    resp = client.get("/api/decision-log/sessions", headers=_auth_headers(member))
    labels = {s["id"]: (s["agent_type"], s["entry_count"], s["verifications"]) for s in resp.get_json()}
    assert labels == {"ls-cx": ("codex", 7, 1), "ls-oc": ("openclaude", 2, 0), "ls-cc": ("claude_code", 6, 1)}


# --- batch ingest from decision-logs/ ---------------------------------------------

def _stage(directory, name, records, meta=None):
    (directory / f"{name}.jsonl").write_text(_jsonl(records))
    if meta is not None:
        (directory / f"{name}.meta.json").write_text(json.dumps(meta))


def test_ingest_all_pending_reads_sidecar_agent(app_ctx, tmp_path, monkeypatch):
    monkeypatch.setattr(transcript_ingest, "DECISION_LOGS_DIR", str(tmp_path))
    _stage(tmp_path, "2026-01-03T090000Z_bt-cx", CODEX_RECORDS, {"agent": "codex", "reason": "other"})
    _stage(tmp_path, "2026-01-04T080000Z_bt-oc", OPENCLAUDE_RECORDS, {"agent": "openclaude", "reason": "exit"})
    _stage(tmp_path, "2026-01-02T100000Z_bt-cc", CLAUDE_CODE_RECORDS, {"agent": "claude-code"})
    _stage(tmp_path, "2026-01-05T000000Z_bt-nometa", CODEX_RECORDS)

    assert ingest_all_pending() == 4

    sessions = {s.id: s for s in DecisionLogSession.query.all()}
    assert sessions["bt-cx"].agent_type == "codex"
    assert sessions["bt-cx"].exit_reason == "other"
    assert sessions["bt-oc"].agent_type == "openclaude"
    assert sessions["bt-oc"].exit_reason == "exit"
    assert sessions["bt-cc"].agent_type == "claude_code"
    assert sessions["bt-nometa"].agent_type == "codex"
    assert sessions["bt-cx"].transcript_path.endswith("2026-01-03T090000Z_bt-cx.jsonl")
    assert ingest_all_pending() == 0
