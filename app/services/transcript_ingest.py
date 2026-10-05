"""Parse AI agent session transcripts for the decision log.

A transcript is JSONL: one JSON record per line. Two formats are parsed; the
format is detected from the records (:func:`detect_agent_type`):

* **Claude Code JSONL** (openclaude writes the same format). Each record of
  ``type`` ``user`` or ``assistant`` becomes one entry: its ``text`` content
  blocks become the entry text and its ``tool_use`` blocks the entry's tool
  calls; thinking blocks are not stored. The session's model
  (``message.model``, else ``version``), working directory (``cwd``) and git
  branch (``gitBranch``) come from the first record that carries them, and
  its start and end times from the first and last entry timestamps.
* **Codex rollout JSONL**: ``{"timestamp", "type", "payload"}`` records of
  type ``session_meta``, ``turn_context``, ``response_item`` and
  ``event_msg``. A transcript holding any such record (with an object
  ``payload``) is a Codex rollout, and its ``user`` / ``assistant`` records
  are not stored. A ``response_item`` message with role ``user`` or
  ``assistant`` becomes one entry with its text (``input_text``,
  ``output_text`` and ``text`` blocks). Each ``response_item`` tool call (any
  payload type ending in ``_call``: ``function_call``, ``custom_tool_call``,
  ``local_shell_call``, ``web_search_call``, ...) becomes one assistant entry
  whose tool calls hold a single object shaped like a Claude Code
  ``tool_use`` block (``type``, ``id``, ``name``, ``input``). Developer
  messages, reasoning, tool output and ``event_msg`` records are not stored.
  ``session_meta`` supplies the working directory (``cwd``) and git branch
  (``git.branch``), the first ``turn_context`` the model, and the start and
  end times span every timestamped record.

A user entry whose whole text is ``done.`` is flagged as a verification
acknowledgment in both formats.

Each session's ``agent_type`` is the agent the caller names (the upload's
``agent`` parameter, or the ``agent`` field of a transcript's ``.meta.json``
sidecar), normalised by :func:`normalize_agent_type` (``claude-code`` is
stored as ``claude_code``). Without a usable named agent it is the detected
format's agent (:attr:`ParsedTranscript.agent_type`): ``codex`` for a Codex
rollout, ``claude_code`` otherwise. openclaude transcripts carry the
``openclaude`` label when the caller names it, since their records match
Claude Code's.

Values the decision log stores in fixed-length columns - an entry's role (at
most 20 characters) and message id (``message.id`` / ``payload.id``, 100),
and the session's model (100), working directory (500) and git branch (200)
- must be strings within those lengths; any other value makes the whole
transcript invalid (``TranscriptError``, a ValueError; the upload API answers
400). Malformed lines, records of other types and unparseable timestamps
(including instants outside the representable UTC range) are ignored, the
timestamp being stored as unknown. NUL characters and unpaired surrogates in
stored text are replaced by U+FFFD, so every transcript that parses can be
stored by every supported database.

An entry's tool calls (``tool_calls``) are a JSON array of ``tool_use``
blocks (:func:`tool_calls_json`): non-ASCII characters as themselves,
unpaired surrogates as ``\\uXXXX`` escapes, so the stored text is valid UTF-8
about the size of the blocks in the transcript. Tool calls stored before this
form (every non-ASCII character escaped) compare equal to the same calls in
this form (:func:`same_tool_calls`).

A line nested deeper than :data:`MAX_LINE_DEPTH` (64) arrays and objects
makes the whole transcript invalid (``TranscriptError``): every line is
parsed within that depth, whatever its content.

Limits: a transcript holds at most :data:`MAX_TRANSCRIPT_ENTRIES` (50,000)
entries, each of its lines is at most :data:`MAX_ENTRY_BYTES` (8 MiB), an
entry's tool calls are at most :data:`MAX_TOOL_CALLS_BYTES` (8 MiB) and the
tool calls of all its entries together at most
:data:`MAX_TRANSCRIPT_TOOL_CALLS_BYTES` (32 MiB), measured as stored (UTF-8).
A transcript over a limit raises :class:`TranscriptLimitError` (a ValueError;
the upload API answers 413) and nothing of it is stored. A line over the line
limit stops parsing at once, as does an invalid value or a limit reached in a
Codex rollout; in a transcript with no Codex record so far, the first such
error is raised when parsing ends (a later Codex record would make it a
Codex rollout), and the entries parsed until then are released at once.
Lines are split and decoded one at a time (line boundaries as
``str.splitlines`` draws them on the decoded text), so parsing holds the
submitted bytes and the parsed entries, never a second decoded copy of the
whole transcript.

Storing goes through :func:`app.services.evidence_import.import_decision_log`,
which decides whether a transcript creates, extends, leaves or is rejected
by a stored session (a later export whose entries extend the stored ones
replaces it; an identical or shorter one is a no-op; any other is rejected
and kept for review).
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.models import db

logger = logging.getLogger(__name__)

DECISION_LOGS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "decision-logs"
)

DONE_PATTERN = re.compile(r"^\s*done\.?\s*$", re.IGNORECASE)

MAX_TRANSCRIPT_ENTRIES = 50_000
MAX_ENTRY_BYTES = 8 * 1024 * 1024
MAX_TOOL_CALLS_BYTES = 8 * 1024 * 1024
MAX_TRANSCRIPT_TOOL_CALLS_BYTES = 32 * 1024 * 1024
MAX_LINE_DEPTH = 64

CLAUDE_CODE_AGENT = "claude_code"
CODEX_AGENT = "codex"

# Stored agent labels: lower-case letters, digits and underscores, at most
# the width of decision_log_sessions.agent_type.
AGENT_TYPE_PATTERN = re.compile(r"^[a-z0-9_]{1,50}$")

CLAUDE_RECORD_TYPES = ("user", "assistant")
# Record types of a Codex rollout; no Claude Code record uses them.
CODEX_RECORD_TYPES = frozenset({"session_meta", "turn_context", "response_item", "event_msg"})
CODEX_MESSAGE_ROLES = ("user", "assistant")
CODEX_TEXT_BLOCK_TYPES = ("input_text", "output_text", "text")
CODEX_TOOL_CALL_SUFFIX = "_call"

_SURROGATE = re.compile("[\ud800-\udfff]")

# The boundaries str.splitlines() draws, as UTF-8 bytes: CR LF, the single-byte
# separators, NEL (U+0085), LINE SEPARATOR (U+2028) and PARAGRAPH SEPARATOR
# (U+2029). None of these byte sequences can occur inside another character's
# encoding, and the decoder treats every ASCII byte as a character boundary, so
# splitting the bytes and decoding each line equals decoding and splitting.
_LINE_BREAK = re.compile(rb"\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e]|\xc2\x85|\xe2\x80[\xa8\xa9]")

# Stored field -> (model, column) whose length bounds it.
_FIELD_COLUMNS = {
    "message.role": ("DecisionLogEntry", "role"),
    "message.id": ("DecisionLogEntry", "message_id"),
    "model": ("DecisionLogSession", "model"),
    "cwd": ("DecisionLogSession", "cwd"),
    "gitBranch": ("DecisionLogSession", "git_branch"),
    "payload.id": ("DecisionLogEntry", "message_id"),
    "payload.model": ("DecisionLogSession", "model"),
    "payload.cwd": ("DecisionLogSession", "cwd"),
    "payload.git.branch": ("DecisionLogSession", "git_branch"),
}


class TranscriptError(ValueError):
    """A transcript record carries a value the decision log cannot store."""


class TranscriptLimitError(ValueError):
    """A transcript exceeds a decision-log limit (size, entries or line size).

    ``size`` is the measured value (bytes or entries) and ``limit`` the limit
    it exceeds.
    """

    def __init__(self, message: str, *, size: int, limit: int):
        self.size = size
        self.limit = limit
        super().__init__(message)


class TranscriptTooManyEntriesError(TranscriptLimitError):
    """A transcript has more than :data:`MAX_TRANSCRIPT_ENTRIES` entries."""

    def __init__(self, limit: int = MAX_TRANSCRIPT_ENTRIES):
        super().__init__(f"the transcript has more than {limit} entries; decision-log transcripts are "
                         f"limited to {limit} entries", size=limit + 1, limit=limit)


class TranscriptLineTooLargeError(TranscriptLimitError):
    """A transcript line is longer than :data:`MAX_ENTRY_BYTES`."""

    def __init__(self, line_number: int, size: int, limit: int = MAX_ENTRY_BYTES):
        super().__init__(f"line {line_number} is {size} bytes; each line (entry) of a decision-log "
                         f"transcript is limited to {limit} bytes", size=size, limit=limit)


class TranscriptToolCallsTooLargeError(TranscriptLimitError):
    """An entry's tool calls are longer than :data:`MAX_TOOL_CALLS_BYTES`, or all
    entries' together longer than :data:`MAX_TRANSCRIPT_TOOL_CALLS_BYTES` (as stored)."""

    def __init__(self, line_number: int, size: int, limit: int, *, total: bool = False):
        if total:
            message = (f"line {line_number}: the transcript's tool calls reach {size} bytes as stored; the "
                       f"tool calls of a decision-log transcript are limited to {limit} bytes in total")
        else:
            message = (f"line {line_number}: the entry's tool calls are {size} bytes as stored; each "
                       f"entry's tool calls are limited to {limit} bytes")
        super().__init__(message, size=size, limit=limit)


def _field_limit(name):
    import app.models as models

    model_name, column = _FIELD_COLUMNS[name]
    return getattr(models, model_name).__table__.columns[column].type.length


def clean_text(text):
    """``text`` with NUL characters and unpaired surrogates replaced by U+FFFD."""
    if "\x00" in text:
        text = text.replace("\x00", "�")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = "".join("�" if 0xD800 <= ord(char) <= 0xDFFF else char for char in text)
    return text


def _string_field(value, name, line_number):
    """A stored string field: None, or a string within its column's length."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise TranscriptError(f"line {line_number}: {name} must be a string, not {type(value).__name__}")
    value = clean_text(value)
    limit = _field_limit(name)
    if len(value) > limit:
        raise TranscriptError(f"line {line_number}: {name} is longer than {limit} characters")
    return value


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


def _is_codex_record(record):
    """True when ``record`` has the ``{"type", "payload"}`` shape of a Codex rollout record."""
    if not isinstance(record, dict):
        return False
    record_type = record.get("type")
    return isinstance(record_type, str) and record_type in CODEX_RECORD_TYPES \
        and isinstance(record.get("payload"), dict)


def detect_agent_type(records):
    """Return the agent whose transcript format ``records`` (decoded JSONL records) follow."""
    return CODEX_AGENT if any(_is_codex_record(record) for record in records) else CLAUDE_CODE_AGENT


@dataclass
class ParsedTranscript:
    """Entries and session metadata parsed from a transcript.

    Each entry is a dict with ``role``, ``content_text``, ``tool_calls``,
    ``timestamp`` (aware UTC datetime or None), ``message_id`` and
    ``is_verification`` — the columns of ``DecisionLogEntry``.
    ``agent_type`` is the detected format's agent (``claude_code`` or
    ``codex``).
    """

    entries: list = field(default_factory=list)
    model: str = None
    cwd: str = None
    git_branch: str = None
    started_at: datetime = None
    ended_at: datetime = None
    agent_type: str = CLAUDE_CODE_AGENT

    def note_timestamp(self, timestamp):
        """Extend the session span to include ``timestamp``."""
        if timestamp:
            if not self.started_at:
                self.started_at = timestamp
            self.ended_at = timestamp


class _FormatParse:
    """One format's parse of a transcript: its entries, metadata and tool-call total."""

    def __init__(self, agent_type):
        self.parsed = ParsedTranscript(agent_type=agent_type)
        self.tool_calls_total = 0

    def check_room(self):
        if len(self.parsed.entries) >= MAX_TRANSCRIPT_ENTRIES:
            raise TranscriptTooManyEntriesError()

    def add(self, line_number, entry):
        """Append ``(role, text, tool_calls, timestamp, message_id)``, checking the tool-call limits."""
        role, text, tool_calls, timestamp, message_id = entry
        if tool_calls:
            size = _stored_size(tool_calls)
            if size > MAX_TOOL_CALLS_BYTES:
                raise TranscriptToolCallsTooLargeError(line_number, size, MAX_TOOL_CALLS_BYTES)
            self.tool_calls_total += size
            if self.tool_calls_total > MAX_TRANSCRIPT_TOOL_CALLS_BYTES:
                raise TranscriptToolCallsTooLargeError(line_number, self.tool_calls_total,
                                                       MAX_TRANSCRIPT_TOOL_CALLS_BYTES, total=True)
        self.parsed.entries.append({
            "role": role,
            "content_text": text if text else None,
            "tool_calls": tool_calls if tool_calls else None,
            "timestamp": timestamp,
            "message_id": message_id,
            "is_verification": bool(DONE_PATTERN.match(text)) if role == "user" else False,
        })


def _byte_lines(content):
    """The lines of UTF-8 ``content`` (bytes), one at a time, as bytes."""
    start = 0
    for match in _LINE_BREAK.finditer(content):
        yield content[start:match.start()]
        start = match.end()
    if start < len(content):
        yield content[start:]


def _utf8_length(text: str) -> int:
    if len(text) * 4 <= MAX_ENTRY_BYTES or len(text) > MAX_ENTRY_BYTES:
        return len(text)
    return len(text.encode("utf-8", "surrogatepass"))


def _lines(content):
    """``(line_number, stripped text)`` of every line, checking each line's size."""
    if isinstance(content, (bytes, bytearray)):
        for line_number, raw in enumerate(_byte_lines(content), start=1):
            if len(raw) > MAX_ENTRY_BYTES:
                raise TranscriptLineTooLargeError(line_number, len(raw))
            raw = raw.decode("utf-8", errors="replace").strip()  # the line's bytes are released
            yield line_number, raw
        return
    for line_number, line in enumerate(content.splitlines(), start=1):
        size = _utf8_length(line)
        if size > MAX_ENTRY_BYTES:
            raise TranscriptLineTooLargeError(line_number, len(line.encode("utf-8", "surrogatepass")))
        yield line_number, line.strip()


def _check_line_depth(line: str, line_number: int) -> None:
    """Refuse a line nested deeper than :data:`MAX_LINE_DEPTH` (``TranscriptError``)."""
    if line.count("[") + line.count("{") <= MAX_LINE_DEPTH:
        return  # cannot be nested deeper, whatever the strings hold
    from werkzeug.exceptions import HTTPException

    from app.request_limits import check_json_limits

    try:
        check_json_limits(line, max_depth=MAX_LINE_DEPTH, max_values=None)
    except HTTPException:
        raise TranscriptError(f"line {line_number} is nested deeper than {MAX_LINE_DEPTH} levels") from None


def parse_transcript(content) -> ParsedTranscript:
    """Parse JSONL transcript content (bytes or text) in its detected format.

    Malformed lines are ignored; a stored field with a value of the wrong
    type or length raises :class:`TranscriptError`, and a transcript over
    :data:`MAX_TRANSCRIPT_ENTRIES` entries, with a line over
    :data:`MAX_ENTRY_BYTES` or over a tool-call limit raises
    :class:`TranscriptLimitError` (see the module docstring for when).
    """
    claude = _FormatParse(CLAUDE_CODE_AGENT)
    codex = _FormatParse(CODEX_AGENT)
    claude_error = None

    for line_number, line in _lines(content):
        if not line:
            continue
        if len(line) > MAX_LINE_DEPTH:  # a shorter line cannot be nested deeper
            _check_line_depth(line, line_number)
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        line = None
        if not isinstance(record, dict):
            continue

        codex_entry = claude_entry = None
        payload = record.get("payload")
        if isinstance(payload, dict):
            if claude is not None and _is_codex_record(record):
                claude = claude_error = None  # a Codex rollout: Claude Code records are not stored
            if claude is None:
                codex_entry = _codex_record(codex, record, payload, line_number)
            else:
                # Not (yet) a Codex rollout: only the timestamp counts, should it become one.
                codex.parsed.note_timestamp(_parse_timestamp(record.get("timestamp")))
        if claude is not None and claude_error is None and record.get("type") in CLAUDE_RECORD_TYPES:
            try:
                claude_entry = _claude_record(claude, record, line_number)
            except (TranscriptError, TranscriptLimitError) as exc:
                claude_error, claude.parsed.entries = exc, []
        record = payload = None  # only the stored values stay alive

        if codex_entry is not None:
            codex.add(line_number, codex_entry)
        elif claude_entry is not None:
            try:
                claude.add(line_number, claude_entry)
            except TranscriptLimitError as exc:
                claude_error, claude.parsed.entries = exc, []
        codex_entry = claude_entry = None

    if claude is None:
        return codex.parsed
    if claude_error is not None:
        raise claude_error
    return claude.parsed


def _claude_record(state, record, line_number):
    """The entry of a Claude Code ``user`` / ``assistant`` record; updates the session metadata."""
    parsed = state.parsed
    state.check_room()
    message = record.get("message")
    if not isinstance(message, dict):
        message = {}
    role = _string_field(message.get("role", record.get("type")), "message.role", line_number)
    content_blocks = message.get("content")
    if content_blocks is None:
        content_blocks = []

    if not parsed.model:
        parsed.model = _string_field(message.get("model") or record.get("version"), "model", line_number)
    if not parsed.cwd:
        parsed.cwd = _string_field(record.get("cwd"), "cwd", line_number)
    if not parsed.git_branch:
        parsed.git_branch = _string_field(record.get("gitBranch"), "gitBranch", line_number)

    timestamp = _parse_timestamp(record.get("timestamp"))
    parsed.note_timestamp(timestamp)

    message_id = _string_field(message.get("id"), "message.id", line_number)
    text_content = clean_text(_extract_text(content_blocks))
    return role, text_content, _extract_tool_calls(content_blocks), timestamp, message_id


def _codex_record(state, record, payload, line_number):
    """The entry of a Codex rollout record, or None; updates the session metadata."""
    parsed = state.parsed
    timestamp = _parse_timestamp(record.get("timestamp"))
    parsed.note_timestamp(timestamp)

    record_type = record.get("type")
    if record_type == "session_meta":
        if not parsed.cwd:
            parsed.cwd = _string_field(payload.get("cwd"), "payload.cwd", line_number)
        git = payload.get("git")
        if not parsed.git_branch and isinstance(git, dict):
            parsed.git_branch = _string_field(git.get("branch"), "payload.git.branch", line_number)
    elif record_type == "turn_context":
        if not parsed.model:
            parsed.model = _string_field(payload.get("model"), "payload.model", line_number)
        if not parsed.cwd:
            parsed.cwd = _string_field(payload.get("cwd"), "payload.cwd", line_number)
    elif record_type == "response_item":
        return _codex_item(state, payload, timestamp, line_number)
    return None


def _codex_item(state, payload, timestamp, line_number):
    """The entry of a Codex ``response_item`` payload, or None when it is not stored."""
    item_type = payload.get("type")

    if item_type == "message":
        role = payload.get("role")
        if not isinstance(role, str) or role not in CODEX_MESSAGE_ROLES:
            return None
        state.check_room()
        text_content = clean_text(_extract_codex_text(payload.get("content")))
        return role, text_content, None, timestamp, _string_field(payload.get("id"), "payload.id", line_number)

    if isinstance(item_type, str) and item_type.endswith(CODEX_TOOL_CALL_SUFFIX):
        state.check_room()
        message_id = _string_field(payload.get("id"), "payload.id", line_number)
        return "assistant", "", tool_calls_json([_codex_tool_use(payload)]), timestamp, message_id

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
    except (ValueError, RecursionError):
        return value


def _extract_codex_text(content):
    """Join the text of a Codex message's ``input_text`` / ``output_text`` / ``text`` blocks."""
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


def ingest_all_pending():
    """Import every transcript in ``decision-logs/`` and commit.

    For each session the largest export wins; a ``<stem>.meta.json`` sidecar
    supplies the exit reason (``reason``) and the agent (``agent``). Returns
    the number of sessions created or replaced; rejected transcripts are
    logged as warnings.
    """
    if not os.path.isdir(DECISION_LOGS_DIR):
        logger.info("No decision-logs directory found")
        return 0

    from app.services.evidence_import_decision_logs import import_decision_log_directory

    summary, errors = import_decision_log_directory(DECISION_LOGS_DIR, path_prefix=DECISION_LOGS_DIR)
    for message in errors:
        logger.warning("Decision log ingest: %s", message)
    return summary["created"] + summary["replaced"]


def ingest_from_content(content, session_id, submitted_by=None, exit_reason=None,
                        transcript_path=None, agent_type=None):
    """Store a transcript (text or bytes) for ``session_id`` and commit.

    ``agent_type`` names the agent that wrote the transcript; a new session
    is labelled with it (through :func:`normalize_agent_type`), or, when it
    is absent or unusable, with the detected format's agent. The transcript
    is stored with the system's authority (it may extend any session; see
    :func:`app.services.evidence_import.import_decision_log`). Returns the
    stored DecisionLogSession when the transcript created or replaced it, or
    None when the stored transcript was kept (identical, a prefix of it, or
    rejected because it does not extend it).
    """
    from app.models import DecisionLogSession
    from app.services.evidence_import_decision_logs import import_decision_log

    if isinstance(content, str):
        content = content.encode("utf-8")
    result = import_decision_log(
        content,
        session_id=session_id,
        source_path=transcript_path,
        exit_reason=exit_reason,
        submitted_by=submitted_by,
        agent_type=agent_type,
    )
    db.session.commit()
    if result.status not in ("created", "replaced"):
        return None
    return db.session.get(DecisionLogSession, result.session_id)


def _parse_timestamp(ts):
    """Parse an ISO 8601 timestamp string or Unix millis; None when it is not
    one, or names an instant outside the representable UTC range."""
    if not ts or isinstance(ts, bool):
        return None
    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        value = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if value.tzinfo is not None:
            value.astimezone(timezone.utc)
        return value
    except (ValueError, AttributeError, OverflowError):
        return None


def _extract_text(content_blocks):
    """Extract concatenated text from content blocks."""
    if isinstance(content_blocks, str):
        return content_blocks
    if not isinstance(content_blocks, (list, dict)):
        return ""
    texts = []
    for block in content_blocks:
        if isinstance(block, str):
            texts.append(block)
        elif isinstance(block, dict) and block.get("type") == "text":
            text = block.get("text", "")
            texts.append(text if isinstance(text, str) else ("" if text is None else str(text)))
    return "\n".join(texts)


def _stored_size(text: str) -> int:
    """UTF-8 size of text that holds no surrogates (encoded 1 Mi characters at a time)."""
    if text.isascii():
        return len(text)
    step = 1024 * 1024
    return sum(len(text[start:start + step].encode("utf-8")) for start in range(0, len(text), step))


def escape_surrogates(text: str) -> str:
    """JSON text with each unpaired surrogate written as its ``\\uXXXX`` escape."""
    if text.isascii() or not _SURROGATE.search(text):
        return text
    return _SURROGATE.sub(lambda match: f"\\u{ord(match.group()):04x}", text)


def tool_calls_json(blocks) -> str:
    """The stored form of tool calls: ``blocks`` as JSON, non-ASCII characters as
    themselves and unpaired surrogates escaped (valid UTF-8)."""
    return escape_surrogates(json.dumps(blocks, ensure_ascii=False))


def same_tool_calls(stored, parsed) -> bool:
    """True when ``stored`` tool calls hold the same JSON as ``parsed`` (their
    :func:`tool_calls_json` form): equal text, or ``stored`` in the earlier
    stored form, which escaped every non-ASCII character."""
    if stored == parsed:
        return True
    if not isinstance(stored, str) or not isinstance(parsed, str) or not stored.isascii() \
            or "\\u" not in stored or parsed.isascii():
        return False
    try:
        return tool_calls_json(json.loads(stored)) == parsed
    except ValueError:
        return False


def _extract_tool_calls(content_blocks):
    """Extract tool_use blocks as JSON string (:func:`tool_calls_json`)."""
    if not isinstance(content_blocks, list):
        return None
    tool_calls = [
        block for block in content_blocks
        if isinstance(block, dict) and block.get("type") == "tool_use"
    ]
    return tool_calls_json(tool_calls) if tool_calls else None
