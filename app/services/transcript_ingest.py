"""Ingest Claude Code session transcripts into the decision log.

Reads JSONL transcript files from decision-logs/ and populates
the decision_log_sessions and decision_log_entries tables.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from glob import glob

from app.models import db, DecisionLogSession, DecisionLogEntry

logger = logging.getLogger(__name__)

DECISION_LOGS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "decision-logs"
)

DONE_PATTERN = re.compile(r"^\s*done\.?\s*$", re.IGNORECASE)


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
                        transcript_path=None):
    """Parse JSONL content string and store in the database.

    Returns the created DecisionLogSession, or None if session already exists.
    """
    existing = DecisionLogSession.query.get(session_id)
    if existing:
        return None

    entries = []
    first_timestamp = None
    last_timestamp = None
    model = None
    cwd = None
    git_branch = None

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        record_type = record.get("type")
        if record_type not in ("user", "assistant"):
            continue

        message = record.get("message", {})
        role = message.get("role", record_type)
        content_blocks = message.get("content", [])
        timestamp_str = record.get("timestamp")

        if not model:
            model = message.get("model") or record.get("version")
        if not cwd:
            cwd = record.get("cwd")
        if not git_branch:
            git_branch = record.get("gitBranch")

        timestamp = _parse_timestamp(timestamp_str)
        if timestamp:
            if not first_timestamp:
                first_timestamp = timestamp
            last_timestamp = timestamp

        text_content = _extract_text(content_blocks)
        tool_calls_json = _extract_tool_calls(content_blocks)
        is_verification = bool(DONE_PATTERN.match(text_content)) if role == "user" else False

        entries.append(DecisionLogEntry(
            session_id=session_id,
            role=role,
            content_text=text_content if text_content else None,
            tool_calls=tool_calls_json if tool_calls_json else None,
            timestamp=timestamp,
            message_id=message.get("id"),
            is_verification=is_verification,
        ))

    session = DecisionLogSession(
        id=session_id,
        agent_type="claude_code",
        model=model,
        cwd=cwd,
        git_branch=git_branch,
        started_at=first_timestamp,
        ended_at=last_timestamp,
        exit_reason=exit_reason,
        transcript_path=transcript_path,
        submitted_by=submitted_by,
    )

    db.session.add(session)
    for entry in entries:
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
    if os.path.exists(meta_path):
        with open(meta_path) as mf:
            meta = json.load(mf)
            exit_reason = meta.get("reason")

    return ingest_from_content(content, session_id, exit_reason=exit_reason,
                               transcript_path=filepath)


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
