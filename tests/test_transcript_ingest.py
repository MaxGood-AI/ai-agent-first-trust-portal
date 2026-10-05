"""Tests for transcript parsing and the decision-log ingest entry points:
Claude Code, openclaude and Codex formats, and agent labels.

Every transcript here is synthetic, built from the record shapes each agent
CLI writes.
"""

import gzip
import json
from datetime import datetime, timezone

import pytest

from app import create_app
from app.config import TestConfig
from app.models import DecisionLogEntry, DecisionLogSession, db
from app.services import evidence_import_decision_logs as dl
from app.services import team_service, transcript_ingest
from app.services.transcript_ingest import (
    detect_agent_type,
    ingest_all_pending,
    ingest_from_content,
    normalize_agent_type,
    parse_transcript,
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
def client(app):
    return app.test_client()


@pytest.fixture
def member(app):
    return team_service.create_member("Test Agent", "agent@example.com", "agent")


def _auth_headers(member):
    return {"X-API-Key": member.issued_api_key}


def _jsonl(records):
    return "\n".join(json.dumps(record) for record in records)


def _entries(session_id):
    return (DecisionLogEntry.query.filter_by(session_id=session_id)
            .order_by(DecisionLogEntry.id).all())


def record(kind, content, ts="2026-03-16T12:00:00Z", **extra):
    message = {"role": kind, "content": content, "id": f"id-{ts}"}
    message.update(extra.pop("message", {}))
    data = {"type": kind, "message": message, "timestamp": ts}
    data.update(extra)
    return json.dumps(data)


SAMPLE = "\n".join([
    json.dumps({"type": "summary", "summary": "ignored"}),
    record("user", [{"type": "text", "text": "Hello"}], cwd="/home/dev", gitBranch="main"),
    record("assistant", [{"type": "text", "text": "Hi"}, {"type": "tool_use", "name": "Read", "input": {}}],
           ts="2026-03-16T12:00:01Z", message={"model": "model-x"}, cwd="/other"),
    record("user", [{"type": "text", "text": "  Done.  "}], ts="2026-03-16T12:00:05Z"),
    record("assistant", [{"type": "text", "text": "done."}], ts="2026-03-16T12:00:06Z"),
    "",
    "not json",
    "[1, 2]",
])

# --- synthetic transcripts ------------------------------------------------------

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


def _codex_message(role, text, ts="2026-01-03T09:00:01Z", message_id="m-1"):
    return {"timestamp": ts, "type": "response_item",
            "payload": {"type": "message", "role": role, "id": message_id,
                        "content": [{"type": "input_text", "text": text}]}}


# --- parsing --------------------------------------------------------------------

def test_parse_transcript_entries_and_metadata():
    parsed = parse_transcript(SAMPLE.encode())
    assert parsed.agent_type == "claude_code"
    assert [e["role"] for e in parsed.entries] == ["user", "assistant", "user", "assistant"]
    assert parsed.model == "model-x"
    assert parsed.cwd == "/home/dev"
    assert parsed.git_branch == "main"
    assert parsed.started_at == datetime(2026, 3, 16, 12, 0, tzinfo=timezone.utc)
    assert parsed.ended_at == datetime(2026, 3, 16, 12, 0, 6, tzinfo=timezone.utc)
    assert [e["is_verification"] for e in parsed.entries] == [False, False, True, False]
    tool_calls = json.loads(parsed.entries[1]["tool_calls"])
    assert tool_calls[0]["name"] == "Read"
    assert parsed.entries[0]["tool_calls"] is None
    assert parsed.entries[0]["message_id"] == "id-2026-03-16T12:00:00Z"


def test_parse_transcript_tolerates_odd_records():
    lines = [
        json.dumps({"type": "user", "message": "not a dict", "timestamp": 1773662400000}),
        json.dumps({"type": "user", "message": {"content": None}, "timestamp": "garbage"}),
        json.dumps({"type": "assistant", "message": {"content": "plain text"}, "version": "2.0.1"}),
        json.dumps({"type": "user", "message": {"content": [{"type": "text", "text": None},
                                                            {"type": "text", "text": 42}, "raw", {"type": "image"}]}}),
        json.dumps({"type": "user", "message": {"content": {"k": "v"}}, "timestamp": 1e20}),
        json.dumps({"type": "user", "message": {"content": 7}}),
        json.dumps({"type": ["unhashable"], "payload": {}}),
        json.dumps({"type": {"also": "unhashable"}, "payload": {"type": "message"}}),
    ]
    parsed = parse_transcript("\n".join(lines))
    assert parsed.agent_type == "claude_code"
    assert len(parsed.entries) == 6
    assert parsed.entries[0]["timestamp"] == datetime(2026, 3, 16, 12, 0, tzinfo=timezone.utc)
    assert parsed.entries[0]["content_text"] is None
    assert parsed.entries[1]["timestamp"] is None
    assert parsed.entries[2]["content_text"] == "plain text"
    assert parsed.entries[3]["content_text"] == "\n42\nraw"
    assert parsed.entries[4]["content_text"] == "k"
    assert parsed.entries[4]["timestamp"] is None
    assert parsed.entries[5]["content_text"] is None
    assert parsed.model == "2.0.1"


def test_parse_codex_rollout():
    parsed = parse_transcript(_jsonl(CODEX_RECORDS).encode())
    assert parsed.agent_type == "codex"
    assert parsed.model == "codex-model-y"
    assert (parsed.cwd, parsed.git_branch) == ("/work/codex", "feature/x")
    assert parsed.started_at == datetime(2026, 1, 3, 9, 0, tzinfo=timezone.utc)
    assert parsed.ended_at == datetime(2026, 1, 3, 9, 0, 21, tzinfo=timezone.utc)
    assert len(parsed.entries) == 7


def test_codex_rollout_ignores_claude_records_and_their_errors():
    bad_claude = json.dumps({"type": "user", "message": {"role": 7, "content": "x"}})
    codex = [json.dumps(r) for r in CODEX_RECORDS]
    parsed = parse_transcript("\n".join([bad_claude] + codex + [record("user", "late claude record")]))
    assert parsed.agent_type == "codex"
    assert len(parsed.entries) == 7
    with pytest.raises(transcript_ingest.TranscriptError, match="message.role must be a string"):
        parse_transcript(bad_claude)


def test_codex_stored_fields_are_validated():
    long_model = {"timestamp": "2026-01-03T09:00:00Z", "type": "turn_context", "payload": {"model": "m" * 101}}
    with pytest.raises(transcript_ingest.TranscriptError, match="payload.model is longer than 100 characters"):
        parse_transcript(json.dumps(long_model))
    bad_cwd = {"timestamp": "2026-01-03T09:00:00Z", "type": "session_meta", "payload": {"cwd": ["/x"]}}
    with pytest.raises(transcript_ingest.TranscriptError, match="payload.cwd must be a string"):
        parse_transcript(json.dumps(bad_cwd))
    bad_id = _codex_message("user", "hi", message_id="i" * 101)
    with pytest.raises(transcript_ingest.TranscriptError, match="payload.id is longer than 100 characters"):
        parse_transcript(json.dumps(bad_id))


def test_codex_limits_apply(monkeypatch):
    numbers = "[" + ",".join(["9e15"] * (440 * 1024)) + "]"  # 2.2 MB in the line, about 9 MB as stored
    call = {"timestamp": "2026-01-03T09:00:00Z", "type": "response_item",
            "payload": {"type": "function_call", "call_id": "c", "name": "f", "arguments": numbers}}
    with pytest.raises(transcript_ingest.TranscriptToolCallsTooLargeError):
        parse_transcript(json.dumps(call).encode())
    monkeypatch.setattr(transcript_ingest, "MAX_TRANSCRIPT_ENTRIES", 2)
    with pytest.raises(transcript_ingest.TranscriptTooManyEntriesError):
        parse_transcript(_jsonl([_codex_message("user", str(i)) for i in range(3)]))


def test_codex_deeply_nested_arguments_stay_raw_text():
    nested = "[" * 100_000 + "]" * 100_000
    call = {"timestamp": "2026-01-03T09:00:00Z", "type": "response_item",
            "payload": {"type": "function_call", "call_id": "c", "name": "f", "arguments": nested}}
    parsed = parse_transcript(json.dumps(call))
    assert json.loads(parsed.entries[0]["tool_calls"])[0]["input"] == nested


def test_a_line_nested_deeper_than_the_limit_is_refused():
    def line(depth):
        return '{"type":"user","message":{"content":"x"},"n":' + "[" * depth + "]" * depth + "}"

    parse_transcript(line(transcript_ingest.MAX_LINE_DEPTH - 1))
    with pytest.raises(transcript_ingest.TranscriptError, match="nested deeper than 64"):
        parse_transcript(line(transcript_ingest.MAX_LINE_DEPTH))


def test_codex_reconstruction_parses_back_to_the_same_entries(app):
    content = _jsonl(CODEX_RECORDS)
    ingest_from_content(content, "cx-recon")
    session = db.session.get(DecisionLogSession, "cx-recon")
    parsed = parse_transcript(content)
    rebuilt = parse_transcript(gzip.decompress(dl.reconstruct_transcript_gz(session, parsed.entries)))
    assert dl.entries_digest(rebuilt.entries) == dl.entries_digest(parsed.entries)


# --- agent labels -----------------------------------------------------------------

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
    assert detect_agent_type([{"type": ["list"], "payload": {}}]) == "claude_code"
    assert detect_agent_type([["list"], 3, {"type": "session_meta", "payload": {}}]) == "codex"


# --- storing ------------------------------------------------------------------------

def test_ingest_from_content_created_unchanged_replaced(app):
    member = team_service.create_member("Agent", "agent@example.com", "agent")

    session = ingest_from_content(SAMPLE, "sess-1", submitted_by=member.id, exit_reason="clear",
                                  transcript_path="uploads/sess-1.jsonl")
    assert session.id == "sess-1"
    assert session.submitted_by == member.id
    assert session.exit_reason == "clear"
    assert session.transcript_path == "uploads/sess-1.jsonl"
    assert session.interactions.count() == 4
    assert session.content_bytes == len(SAMPLE.encode())

    assert ingest_from_content(SAMPLE, "sess-1") is None

    longer = SAMPLE + "\n" + record("user", [{"type": "text", "text": "more"}], ts="2026-03-16T12:01:00Z")
    replaced = ingest_from_content(longer.encode(), "sess-1")
    assert replaced.interactions.count() == 5
    assert replaced.replaced_at is not None
    assert replaced.submitted_by == member.id


def test_overlong_transcript_fields_are_rejected_and_exit_reason_truncated(app):
    content = record("user", [{"type": "text", "text": "x"}], message={"model": "m" * 300})
    with pytest.raises(transcript_ingest.TranscriptError, match="model is longer than 100 characters"):
        ingest_from_content(content, "sess-long")
    assert db.session.get(DecisionLogSession, "sess-long") is None
    content = record("user", [{"type": "text", "text": "x"}], message={"model": "m" * 100})
    session = ingest_from_content(content, "sess-long", exit_reason="r" * 80)
    assert len(session.model) == 100
    assert len(session.exit_reason) == 50


def test_ingest_all_pending(app, tmp_path, monkeypatch):
    monkeypatch.setattr(transcript_ingest, "DECISION_LOGS_DIR", str(tmp_path / "missing"))
    assert ingest_all_pending() == 0

    monkeypatch.setattr(transcript_ingest, "DECISION_LOGS_DIR", str(tmp_path))
    (tmp_path / "2026-03-16T120000Z_sess-a.jsonl").write_text(SAMPLE)
    (tmp_path / "2026-03-16T120000Z_sess-a.meta.json").write_text(json.dumps({"reason": "logout"}))
    (tmp_path / "2026-03-17T120000Z_sess-b.jsonl").write_text(SAMPLE)
    (tmp_path / "no-session-id.jsonl").write_text(SAMPLE)

    assert ingest_all_pending() == 2
    session = db.session.get(DecisionLogSession, "sess-a")
    assert session.exit_reason == "logout"
    assert session.transcript_path == str(tmp_path / "2026-03-16T120000Z_sess-a.jsonl")
    assert ingest_all_pending() == 0


def _compared(session_id, entries):
    comparison = dl._compare_with_stored(session_id, entries)
    return comparison.stored, comparison.difference


def test_compare_with_stored_reports_count_and_first_difference(app):
    ingest_from_content(SAMPLE, "sess-m")
    parsed = parse_transcript(SAMPLE)
    assert _compared("sess-m", parsed.entries) == (4, None)
    assert _compared("sess-m", parsed.entries[:2]) == (4, None)
    parsed.entries[2] = dict(parsed.entries[2], content_text="changed")
    assert _compared("sess-m", parsed.entries) == (4, 2)
    assert _compared("missing", parsed.entries) == (0, None)
    assert DecisionLogEntry.query.filter_by(session_id="sess-m").count() == 4


def test_ingest_from_content_returns_none_for_a_rejected_transcript(app):
    ingest_from_content(SAMPLE, "sess-r")
    other = record("user", [{"type": "text", "text": "a different first message"}])
    assert ingest_from_content(other + "\n" + SAMPLE, "sess-r") is None
    assert DecisionLogEntry.query.filter_by(session_id="sess-r").count() == 4


def test_time_helpers():
    naive = datetime(2026, 1, 1, 12, 0)
    assert dl._naive_utc(None) is None
    assert dl._naive_utc(naive) is naive
    assert dl._utc(None) is None
    assert dl._utc(naive) == naive.replace(tzinfo=timezone.utc)


# --- Claude Code ------------------------------------------------------------------

def test_claude_code_transcript_parsed(app):
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


def test_claude_code_model_falls_back_to_message_model(app):
    records = [
        {"type": "user", "timestamp": "2026-01-02T10:00:00Z",
         "message": {"role": "user", "content": "hi"}},
        {"type": "assistant", "timestamp": "2026-01-02T10:00:01Z",
         "message": {"role": "assistant", "model": "claude-model-x", "content": []}},
    ]
    session = ingest_from_content(_jsonl(records), "cc-2")
    assert session.model == "claude-model-x"


def test_claude_code_ignores_blank_and_invalid_lines(app):
    content = "\n\nnot json\n" + _jsonl(CLAUDE_CODE_RECORDS[2:3]) + "\n   \n"
    session = ingest_from_content(content, "cc-3")
    assert session.agent_type == "claude_code"
    assert len(_entries("cc-3")) == 1


def test_claude_code_named_agent_label(app):
    session = ingest_from_content(_jsonl(CLAUDE_CODE_RECORDS), "cc-4", agent_type="claude-code")
    assert session.agent_type == "claude_code"


# --- openclaude ------------------------------------------------------------------

def test_openclaude_transcript_parsed_with_named_label(app):
    session = ingest_from_content(_jsonl(OPENCLAUDE_RECORDS), "oc-1", agent_type="openclaude")

    assert session.agent_type == "openclaude"
    assert session.model == "unknown"
    assert session.cwd == "/work/oc"
    assert session.git_branch == "dev"
    assert [(e.role, e.content_text, e.message_id) for e in _entries("oc-1")] == [
        ("user", "Summarise the repo", None),
        ("assistant", "It is a portal.", "oc-msg-1"),
    ]


def test_openclaude_transcript_without_named_agent_detected_as_claude_code(app):
    session = ingest_from_content(_jsonl(OPENCLAUDE_RECORDS), "oc-2")
    assert session.agent_type == "claude_code"
    assert len(_entries("oc-2")) == 2


# --- Codex ----------------------------------------------------------------------

def test_codex_transcript_parsed(app):
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


def test_codex_stores_no_developer_reasoning_or_tool_output(app):
    ingest_from_content(_jsonl(CODEX_RECORDS), "cx-2")
    texts = [e.content_text for e in _entries("cx-2") if e.content_text]
    for hidden in ("sandbox rules", "hidden", "opaque", "tool output", "listing"):
        assert all(hidden not in text for text in texts)


def test_codex_function_call_with_non_json_arguments_keeps_raw_text(app):
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


def test_codex_message_content_variants(app):
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


def test_codex_session_meta_only_is_empty_session(app):
    session = ingest_from_content(_jsonl(CODEX_RECORDS[:1]), "cx-5")
    assert session.agent_type == "codex"
    assert session.cwd == "/work/codex"
    assert session.started_at is not None
    assert _entries("cx-5") == []


def test_named_agent_overrides_detected_format(app):
    session = ingest_from_content(_jsonl(CODEX_RECORDS), "cx-6", agent_type="Codex")
    assert session.agent_type == "codex"
    session = ingest_from_content(_jsonl(CLAUDE_CODE_RECORDS), "cc-5", agent_type="openclaude")
    assert session.agent_type == "openclaude"


def test_unusable_named_agent_falls_back_to_detection(app):
    session = ingest_from_content(_jsonl(CODEX_RECORDS), "cx-7", agent_type="not valid!")
    assert session.agent_type == "codex"


def test_stored_session_keeps_its_agent_label(app):
    ingest_from_content(_jsonl(CODEX_RECORDS[:1]), "cx-8")
    session = ingest_from_content(_jsonl(CODEX_RECORDS), "cx-8", agent_type="openclaude")
    assert session.agent_type == "codex"
    assert len(_entries("cx-8")) == 7


# --- upload endpoint ------------------------------------------------------------

def _upload(client, member, query, records):
    return client.post(f"/api/decision-log/upload?{query}", data=_jsonl(records),
                       content_type="application/jsonl", headers=_auth_headers(member))


def test_upload_codex_detects_agent(client, member):
    resp = _upload(client, member, "session_id=up-cx-1", CODEX_RECORDS)
    assert resp.status_code == 200
    body = resp.get_json()
    assert (body["session_id"], body["entries"], body["status"], body["agent_type"]) == \
        ("up-cx-1", 7, "created", "codex")
    again = _upload(client, member, "session_id=up-cx-1&agent=openclaude", CODEX_RECORDS).get_json()
    assert (again["status"], again["agent_type"]) == ("unchanged", "codex")


def test_upload_agent_parameter_labels_session(client, member):
    resp = _upload(client, member, "session_id=up-oc-1&agent=openclaude", OPENCLAUDE_RECORDS)
    assert resp.status_code == 200
    assert resp.get_json()["agent_type"] == "openclaude"
    assert db.session.get(DecisionLogSession, "up-oc-1").agent_type == "openclaude"


def test_upload_claude_code_agent_parameter_normalised(client, member):
    resp = _upload(client, member, "session_id=up-cc-1&agent=claude-code", CLAUDE_CODE_RECORDS)
    assert resp.status_code == 200
    body = resp.get_json()
    assert (body["session_id"], body["entries"], body["agent_type"]) == ("up-cc-1", 6, "claude_code")


def test_upload_invalid_agent_rejected(client, member):
    resp = _upload(client, member, "session_id=up-bad-1&agent=bad%20agent", CODEX_RECORDS)
    assert resp.status_code == 400
    assert "Invalid agent" in resp.get_json()["error"]
    assert db.session.get(DecisionLogSession, "up-bad-1") is None


def test_sessions_list_reports_agent_type(client, member):
    for sid, records, agent in (("ls-cx", CODEX_RECORDS, ""), ("ls-oc", OPENCLAUDE_RECORDS, "&agent=openclaude"),
                                ("ls-cc", CLAUDE_CODE_RECORDS, "")):
        _upload(client, member, f"session_id={sid}{agent}", records)
    resp = client.get("/api/decision-log/sessions", headers=_auth_headers(member))
    labels = {s["id"]: (s["agent_type"], s["entry_count"], s["verifications"]) for s in resp.get_json()["items"]}
    assert labels == {"ls-cx": ("codex", 7, 1), "ls-oc": ("openclaude", 2, 0), "ls-cc": ("claude_code", 6, 1)}


# --- batch ingest from decision-logs/ ---------------------------------------------

def _stage(directory, name, records, meta=None):
    (directory / f"{name}.jsonl").write_text(_jsonl(records))
    if meta is not None:
        (directory / f"{name}.meta.json").write_text(json.dumps(meta))


def test_ingest_all_pending_reads_sidecar_agent(app, tmp_path, monkeypatch):
    monkeypatch.setattr(transcript_ingest, "DECISION_LOGS_DIR", str(tmp_path))
    _stage(tmp_path, "2026-01-03T090000Z_bt-cx", CODEX_RECORDS, {"agent": "codex", "reason": "other"})
    _stage(tmp_path, "2026-01-04T080000Z_bt-oc", OPENCLAUDE_RECORDS, {"agent": "openclaude", "reason": "exit"})
    _stage(tmp_path, "2026-01-02T100000Z_bt-cc", CLAUDE_CODE_RECORDS, {"agent": "claude-code"})
    _stage(tmp_path, "2026-01-05T000000Z_bt-nometa", CODEX_RECORDS)
    _stage(tmp_path, "2026-01-06T000000Z_bt-odd", CODEX_RECORDS, {"agent": ["codex"], "reason": 3})

    assert ingest_all_pending() == 5

    sessions = {s.id: s for s in DecisionLogSession.query.all()}
    assert sessions["bt-cx"].agent_type == "codex"
    assert sessions["bt-cx"].exit_reason == "other"
    assert sessions["bt-oc"].agent_type == "openclaude"
    assert sessions["bt-oc"].exit_reason == "exit"
    assert sessions["bt-cc"].agent_type == "claude_code"
    assert sessions["bt-nometa"].agent_type == "codex"
    assert (sessions["bt-odd"].agent_type, sessions["bt-odd"].exit_reason) == ("codex", None)
    assert sessions["bt-cx"].transcript_path.endswith("2026-01-03T090000Z_bt-cx.jsonl")
    assert ingest_all_pending() == 0
