"""Ingest AI agent session transcripts into the decision log.

Transcripts arrive as JSONL, uploaded through ``POST /api/decision-log/upload``
or staged in ``decision-logs/`` for ``POST /api/decision-log/ingest``, and
populate the ``decision_log_sessions`` and ``decision_log_entries`` tables.

Two transcript formats are parsed; the format is detected from the records:

* **Claude Code JSONL** (openclaude writes the same format). Each record of
  ``type`` ``user`` or ``assistant`` becomes one entry: its ``text`` content
  blocks become the entry text and its ``tool_use`` blocks the entry's tool
  calls. Thinking blocks are not stored. The session's ``model`` is the first
  of ``message.model`` or the record ``version``, and ``cwd`` / ``git_branch``
  come from the records; ``started_at`` / ``ended_at`` span the user and
  assistant records.
* **Codex rollout JSONL**: ``{"timestamp", "type", "payload"}`` records of
  type ``session_meta``, ``turn_context``, ``response_item`` and
  ``event_msg``. A ``response_item`` message with role ``user`` or
  ``assistant`` becomes one entry with its text. Each ``response_item`` tool
  call (any payload type ending in ``_call``: ``function_call``,
  ``custom_tool_call``, ``local_shell_call``, ``web_search_call``, ...)
  becomes one assistant entry whose tool calls hold a single object shaped
  like a Claude Code ``tool_use`` block (``type``, ``id``, ``name``,
  ``input``). Developer messages, reasoning, tool output and ``event_msg``
  records are not stored. ``session_meta`` supplies ``cwd`` and
  ``git_branch``, the first ``turn_context`` the ``model``, and
  ``started_at`` / ``ended_at`` span every timestamped record.

A user entry whose whole text is ``done.`` is flagged as a verification in
both formats.

Each session's ``agent_type`` is the agent the caller names (the upload's
``agent`` parameter, or the ``agent`` field of a staged transcript's
``.meta.json`` sidecar), normalised by ``normalize_agent_type``
(``claude-code`` is stored as ``claude_code``). Without a named agent it is
the detected format's agent: ``codex`` for a Codex rollout, ``claude_code``
otherwise. openclaude transcripts carry the ``openclaude`` label when the
caller names it, since their records match Claude Code's.
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from glob import glob

from app.models import db, DecisionLogSession, DecisionLogEntry

logger = logging.getLogger(__name__)

DECISION_LOGS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "decision-logs"
)

DONE_PATTERN = re.compile(r"^\s*done\.?\s*$", re.IGNORECASE)

CLAUDE_CODE_AGENT = "claude_code"
CODEX_AGENT = "codex"

# Stored agent labels: lower-case letters, digits and underscores, at most
# the width of decision_log_sessions.agent_type.
AGENT_TYPE_PATTERN = re.compile(r"^[a-z0-9_]{1,50}$")

# Record types of a Codex rollout; no Claude Code record uses them.
CODEX_RECORD_TYPES = frozenset({"session_meta", "turn_context", "response_item", "event_msg"})
CODEX_MESSAGE_ROLES = ("user", "assistant")
CODEX_TEXT_BLOCK_TYPES = ("input_text", "output_text", "text")
CODEX_TOOL_CALL_SUFFIX = "_call"


@dataclass
class ParsedTranscript:
    """Entries and session metadata parsed from one transcript."""

    entries: list = field(default_factory=list)
    model: str = None
    cwd: str = None
    git_branch: str = None
    first_timestamp: datetime = None
    last_timestamp: datetime = None

    def note_timestamp(self, timestamp):
        """Extend the session span to include ``timestamp``."""
        if timestamp:
            if not self.first_timestamp:
                self.first_timestamp = timestamp
            self.last_timestamp = timestamp


def normalize_agent_type(agent):
    """Return the stored label for an agent name, or None when it is unusable.

    The name is trimmed, lower-cased and has hyphens replaced by underscores,
    so the SessionEnd sidecar's ``claude-code`` is stored as ``claude_code``.
    A name that is not a string, is empty, is longer than 50 characters or
    holds characters other than letters, digits, ``-`` and ``_`` returns None.
    """
    if not isinstance(agent, str):
        return None
    label = agent.strip().lower().replace("-", "_")
    return label if AGENT_TYPE_PATTERN.match(label) else None


def detect_agent_type(records):
    """Return the agent whose transcript format ``records`` follow."""
    return CODEX_AGENT if _is_codex_rollout(records) else CLAUDE_CODE_AGENT


def ingest_all_pending():
    """Ingest all transcript files not yet in the database."""
    if not os.path.isdir(DECISION_LOGS_DIR):
        logger.info("No decision-logs directory found")
        return 0

    jsonl_files = glob(os.path.join(DECISION_LOGS_DIR, "*.jsonl"))
    ingested = 0

    for filepath in jsonl_files:
        session_id = _extract_session_id(filepath)
        if not session_id:
            continue

        existing = DecisionLogSession.query.get(session_id)
        if existing:
            continue

        try:
            _ingest_transcript(filepath, session_id)
            ingested += 1
            logger.info("Ingested session %s from %s", session_id, filepath)
        except Exception:
            logger.exception("Failed to ingest %s", filepath)
            db.session.rollback()

    return ingested


def _extract_session_id(filepath):
    """Extract session ID from filename: TIMESTAMP_SESSION-ID.jsonl"""
    basename = os.path.basename(filepath)
    parts = basename.replace(".jsonl", "").split("_", 1)
    return parts[1] if len(parts) == 2 else None


def ingest_from_content(content, session_id, submitted_by=None, exit_reason=None,
                        transcript_path=None, agent_type=None):
    """Parse JSONL content string and store in the database.

    ``agent_type`` names the agent that wrote the transcript; it is stored
    through ``normalize_agent_type``, and when absent or unusable the agent
    is detected from the record format.

    Returns the created DecisionLogSession, or None if session already exists.
    """
    existing = DecisionLogSession.query.get(session_id)
    if existing:
        return None

    records = _load_records(content)
    detected_agent = detect_agent_type(records)
    if detected_agent == CODEX_AGENT:
        parsed = _parse_codex_records(records, session_id)
    else:
        parsed = _parse_claude_records(records, session_id)

    session = DecisionLogSession(
        id=session_id,
        agent_type=normalize_agent_type(agent_type) or detected_agent,
        model=parsed.model,
        cwd=parsed.cwd,
        git_branch=parsed.git_branch,
        started_at=parsed.first_timestamp,
        ended_at=parsed.last_timestamp,
        exit_reason=exit_reason,
        transcript_path=transcript_path,
        submitted_by=submitted_by,
    )

    db.session.add(session)
    for entry in parsed.entries:
        db.session.add(entry)
    db.session.commit()
    return session


def _ingest_transcript(filepath, session_id):
    """Parse a single JSONL transcript file and store in the database."""
    with open(filepath) as f:
        content = f.read()

    # Read sidecar metadata if available
    meta_path = filepath.replace(".jsonl", ".meta.json")
    exit_reason = None
    agent_type = None
    if os.path.exists(meta_path):
        with open(meta_path) as mf:
            meta = json.load(mf)
            exit_reason = meta.get("reason")
            agent_type = meta.get("agent")

    return ingest_from_content(content, session_id, exit_reason=exit_reason,
                               transcript_path=filepath, agent_type=agent_type)


def _load_records(content):
    """Decode each non-blank JSONL line, skipping lines that are not JSON."""
    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _is_codex_rollout(records):
    """True when any record has the ``{"type", "payload"}`` shape of a Codex rollout."""
    return any(
        isinstance(record, dict)
        and record.get("type") in CODEX_RECORD_TYPES
        and isinstance(record.get("payload"), dict)
        for record in records
    )


def _parse_claude_records(records, session_id):
    """Parse Claude Code (and openclaude) records into entries and session metadata."""
    parsed = ParsedTranscript()

    for record in records:
        record_type = record.get("type")
        if record_type not in ("user", "assistant"):
            continue

        message = record.get("message", {})
        role = message.get("role", record_type)
        content_blocks = message.get("content", [])
        timestamp_str = record.get("timestamp")

        if not parsed.model:
            parsed.model = message.get("model") or record.get("version")
        if not parsed.cwd:
            parsed.cwd = record.get("cwd")
        if not parsed.git_branch:
            parsed.git_branch = record.get("gitBranch")

        timestamp = _parse_timestamp(timestamp_str)
        parsed.note_timestamp(timestamp)

        text_content = _extract_text(content_blocks)
        tool_calls_json = _extract_tool_calls(content_blocks)
        is_verification = bool(DONE_PATTERN.match(text_content)) if role == "user" else False

        parsed.entries.append(DecisionLogEntry(
            session_id=session_id,
            role=role,
            content_text=text_content if text_content else None,
            tool_calls=tool_calls_json if tool_calls_json else None,
            timestamp=timestamp,
            message_id=message.get("id"),
            is_verification=is_verification,
        ))

    return parsed


def _parse_codex_records(records, session_id):
    """Parse Codex rollout records into entries and session metadata."""
    parsed = ParsedTranscript()

    for record in records:
        if not isinstance(record, dict):
            continue
        payload = record.get("payload")
        if not isinstance(payload, dict):
            continue

        timestamp = _parse_timestamp(record.get("timestamp"))
        parsed.note_timestamp(timestamp)

        record_type = record.get("type")
        if record_type == "session_meta":
            if not parsed.cwd:
                parsed.cwd = payload.get("cwd")
            git = payload.get("git")
            if not parsed.git_branch and isinstance(git, dict):
                parsed.git_branch = git.get("branch")
        elif record_type == "turn_context":
            if not parsed.model:
                parsed.model = payload.get("model")
            if not parsed.cwd:
                parsed.cwd = payload.get("cwd")
        elif record_type == "response_item":
            entry = _codex_entry(payload, session_id, timestamp)
            if entry is not None:
                parsed.entries.append(entry)

    return parsed


def _codex_entry(payload, session_id, timestamp):
    """Return the entry for a Codex ``response_item`` payload, or None if it is not stored."""
    item_type = payload.get("type")

    if item_type == "message":
        role = payload.get("role")
        if role not in CODEX_MESSAGE_ROLES:
            return None
        text_content = _extract_codex_text(payload.get("content"))
        return DecisionLogEntry(
            session_id=session_id,
            role=role,
            content_text=text_content if text_content else None,
            tool_calls=None,
            timestamp=timestamp,
            message_id=payload.get("id"),
            is_verification=bool(DONE_PATTERN.match(text_content)) if role == "user" else False,
        )

    if isinstance(item_type, str) and item_type.endswith(CODEX_TOOL_CALL_SUFFIX):
        return DecisionLogEntry(
            session_id=session_id,
            role="assistant",
            content_text=None,
            tool_calls=json.dumps([_codex_tool_use(payload)]),
            timestamp=timestamp,
            message_id=payload.get("id"),
            is_verification=False,
        )

    return None


def _codex_tool_use(payload):
    """Describe a Codex tool call in the shape of a Claude Code ``tool_use`` block.

    ``name`` is the call's own name, or its payload type without ``_call``
    (``local_shell_call`` is named ``local_shell``). ``input`` is the decoded
    JSON ``arguments`` of a function call, the raw ``input`` of a custom tool
    call, or the ``action`` of a built-in call.
    """
    item_type = payload["type"]
    name = payload.get("name") or item_type[: -len(CODEX_TOOL_CALL_SUFFIX)]
    if "arguments" in payload:
        tool_input = _decode_json_string(payload.get("arguments"))
    elif "input" in payload:
        tool_input = payload.get("input")
    else:
        tool_input = payload.get("action")
    return {
        "type": "tool_use",
        "id": payload.get("call_id") or payload.get("id"),
        "name": name,
        "input": tool_input,
    }


def _decode_json_string(value):
    """Decode a JSON string, returning the value unchanged when it is not JSON."""
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _extract_codex_text(content):
    """Join the text of a Codex message's ``input_text`` / ``output_text`` blocks."""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    texts = []
    for block in content:
        if isinstance(block, dict) and block.get("type") in CODEX_TEXT_BLOCK_TYPES:
            text = block.get("text")
            if isinstance(text, str):
                texts.append(text)
    return "\n".join(texts)


def _parse_timestamp(ts):
    """Parse ISO 8601 timestamp string or Unix millis."""
    if not ts:
        return None
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _extract_text(content_blocks):
    """Extract concatenated text from content blocks."""
    if isinstance(content_blocks, str):
        return content_blocks
    texts = []
    for block in content_blocks:
        if isinstance(block, str):
            texts.append(block)
        elif isinstance(block, dict) and block.get("type") == "text":
            texts.append(block.get("text", ""))
    return "\n".join(texts)


def _extract_tool_calls(content_blocks):
    """Extract tool_use blocks as JSON string."""
    if isinstance(content_blocks, str):
        return None
    tool_calls = [
        block for block in content_blocks
        if isinstance(block, dict) and block.get("type") == "tool_use"
    ]
    return json.dumps(tool_calls) if tool_calls else None
