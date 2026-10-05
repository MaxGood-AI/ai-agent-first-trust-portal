"""Decision-log transcripts: create, extend, keep or reject a stored session.

Part of the evidence import engine; the public entry points are re-exported
by :mod:`app.services.evidence_import`.

A session can be exported several times while it is resumed, each export a
longer copy of the same transcript. A new export is accepted only when it
**extends** the stored transcript: the stored entries are an exact prefix of
the new export's parsed entries (role, text, tool calls, timestamp compared
as a UTC instant, message id and verification flag, in order) and the new
export has more entries. ``content_sha256`` and ``content_bytes`` of a
session always describe the transcript its stored entries were parsed from.

Limits
------
A transcript is at most :data:`MAX_TRANSCRIPT_BYTES` (32 MiB) as submitted
or reassembled, holds at most ``MAX_TRANSCRIPT_ENTRIES`` (50,000) entries,
each of its lines is at most ``MAX_ENTRY_BYTES`` (8 MiB), and its tool calls
as stored are at most ``MAX_TOOL_CALLS_BYTES`` (8 MiB) per entry and
``MAX_TRANSCRIPT_TOOL_CALLS_BYTES`` (32 MiB) in all
(:mod:`app.services.transcript_ingest`). A transcript over a limit raises a
:class:`TranscriptLimitError` (:class:`TranscriptTooLargeError` for the size,
checked before it is parsed; the other limits as parsing reaches them) and
nothing of it is stored. One process imports at most
:data:`IMPORT_BYTE_BUDGET` (48 MiB) of transcripts at a time
(:func:`import_slot`): each import takes its transcript's size in bytes of
that budget (at least :data:`MIN_IMPORT_CHARGE`, 1 MiB; the full 32 MiB when
the size is not known before reading, as for a git sync's files or an
upload without Content-Length). An upload through the API that does not fit
is refused before its body is read (:class:`ImportBusyError`; the API
answers 429 with ``Retry-After``); a git sync or directory import waits
until it fits, first come, first served.

Entries are stored and always read in insertion order (``id``), which is
the order of the transcript; their timestamps never reorder them.

Who may extend a session (``authority``)
----------------------------------------
* ``system`` - a git sync of the evidence repository, ``cli import`` and the
  local ``decision-logs/`` ingest: the evidence repository is the source of
  the transcripts, so it may extend any session (and wins the conflicts
  below).
* ``store`` - an evidence-store sync, naming the ``evidence_store_objects``
  record of the object version it read: may create a session and extend any
  session as an exact prefix extension, and nothing else (below).
* ``admin`` - an upload by a compliance admin: may extend any session.
* ``member`` - an upload by any other member: may extend only a session whose
  ``submitted_by`` is that member and that is not flagged as a conflict. A
  session created without a submitter (a scheduled git sync) is extended
  only by the system, the store or an admin.

The evidence store (``store``)
------------------------------
A store export creates a session that does not exist, or extends the stored
entries when they are an exact prefix of its entries and it has more. An
identical export (the same content or the same entries) and an export whose
entries are a prefix of the stored ones change nothing (``unchanged`` /
``kept_existing``). Any other export - one that differs from the stored
entries at any entry - is **rejected** and kept as a ``rejected`` version for
review: a store export never replaces, truncates or supersedes entries,
whether they came through the API or from the evidence repository, and never
wins a conflict. Store exports are held to the same timestamp rule as
repository exports (none: an agent transcript is in write order) and fill
only unset session metadata. A stored session without a current version (a
session restored from an earlier portal) that a store export holds
identically is BASELINED, as a full re-import of the evidence repository
does: the export is recorded as the session's current version (naming its
store object; audited; no entry rows written; ``DecisionLogResult.baselined``),
and the store has supplied its entries from then on.

Once the evidence repository or the evidence store has supplied entries of a
session (``repository_entries`` > 0, counting the entries either supplied),
only they may extend it: an upload by a member or an admin that would add
entries is rejected (409) and kept as a ``rejected`` version (audited).
Stored entries after the ones they supplied are UNCONFIRMED: they never
count as verifications (:func:`confirmed_entry_limit`).

Entries appended through the API (``member`` or ``admin`` authority) must
not be back-dated: every appended entry that carries a timestamp must not be
earlier than the latest timestamp among the stored entries (entries without a
timestamp are allowed anywhere). The rule stops a member from appending an
earlier-dated acknowledgment. It does not apply to the evidence repository
(``system``): a genuine agent transcript is in write order, not timestamp
order (a resumed session, a sub-agent's or side-chain records, compaction
summaries and clock skew all put earlier timestamps after later ones), and a
repository version is held instead to extending the stored entries exactly
(each stored entry, in order, is an exact prefix of the new version) - or,
when it does not, to the conflict rules below.

The evidence repository is authoritative
----------------------------------------
``repository_entries`` counts the leading stored entries that a version from
the evidence repository (``system`` authority) or the evidence store
(``store``) created, extended or replaced; the entries after them came
through the API. (For a session stored before the count was recorded it is
all stored entries when the session has no submitter, else none.) The
repository's version wins - a **conflict** - when a ``system`` version

* differs from the stored entries at an entry the repository has not
  supplied: the stored entries from the first difference on are replaced by
  the repository's; or
* is a strict prefix of the stored entries - an empty or metadata-only
  file included - and holds every entry the repository supplied: the stored
  entries beyond it, which came through the API, are removed.

Either way the stored entries become exactly the repository's version, the
previous version is kept as a ``superseded`` version whose ``reason`` starts
with ``repository conflict:`` (so the API-submitted entries that are not in
the repository's version stay available for review), the new ``current``
version names the repository file (``source_path``) and the repository
import's submitter (NULL for a git sync, ``cli import`` and the local
ingest), the session's ``submitted_by`` becomes that submitter too, and the
session is flagged as a conflict (``conflict_at``, ``conflict_detail``). A
``system`` version that differs at an entry the repository itself supplied
is rejected like any other; one that is a prefix of the entries the
repository supplied (an earlier export arriving late) changes nothing.

Session metadata - ``agent_type``, ``model``, ``cwd``, ``git_branch``,
``started_at``, ``exit_reason``, ``submitted_by`` and ``transcript_path`` -
is fixed by the upload that creates the session. A later version fills a
field that is still unset; only an admin's version, or a repository version
that wins a conflict, replaces a value that is set (with each value it
supplies). ``agent_type`` is the agent the creating version names (the
upload's ``agent`` parameter or the sidecar's ``agent`` field, normalised),
else that transcript's detected format's agent
(:mod:`app.services.transcript_ingest`); it never changes after creation,
and ``submitted_by`` changes only in a conflict.
``ended_at`` follows the latest version's end time (the last entry timestamp
of a Claude Code transcript, the last record timestamp of a Codex rollout).
``decision_log_sessions`` is
an audited table, so every change, an admin's included, has an audit row
attributed to its author.

Outcomes (``DecisionLogResult.status``):

* **created** — no session with this id exists: the session (inserted with
  ``ON CONFLICT DO NOTHING``) and its entries are stored, with a ``current``
  version row.
* **unchanged** — the stored ``content_sha256`` equals the new content's
  digest: no writes at all.
* **replaced** — the new export extends the stored transcript and its
  authority may extend the session: its additional entries are appended
  after the stored ones (which stay as they are), and the digest, size,
  ``ended_at``, ``replaced_at`` and metadata (by the rules above) are
  updated. The previous ``current`` version becomes ``superseded`` and keeps
  its content; the new export is recorded as ``current``. A repository
  version that wins a conflict is also **replaced**, with
  ``DecisionLogResult.conflict`` True.
* **kept_existing** — the new export's entries are a prefix of the stored
  ones (an earlier, shorter export arriving late, the same entries in
  different bytes, or content with no parseable records) and it is not a
  repository version that wins a conflict: no writes.
* **rejected** — the stored transcript is unchanged, and the upload is
  recorded as a ``rejected`` version with its content and the reason, once
  per distinct content, when: an entry differs from the stored one (and the
  repository rule above does not apply); an appended entry is back-dated; or
  the upload would extend the session but its authority may not
  (``DecisionLogResult.forbidden``). The API answers 403 when forbidden and
  409 otherwise; a git sync records the file as an error; ``cli import``
  counts it as a failed file.

The session's ``submitted_by`` names the member who submitted its first
version (after a conflict: the repository import's submitter); every version
row names its own submitter.

Sessions stored before digests were recorded (``content_sha256`` NULL)
follow the same rules; when the new content's entries are exactly the stored
entries and its authority may extend the session, its digest and size are
recorded on the session (a one-time backfill) and the result is
**unchanged**; otherwise the result is **kept_existing**.

Concurrency and write order
---------------------------
On PostgreSQL every store of a session first takes the transaction-scoped
advisory lock ``pg_advisory_xact_lock(SESSION_LOCK_CLASS,
session_lock_key(session_id))`` (:func:`lock_session`), before any other
write of its transaction, so uploads, syncs and imports of one session run
one after another and each sees the entries the previous one committed.

``decision_log_entries`` is not audited row by row. A store writes the
entries first - in batches of 1,000, with the foreign-key check to the
session deferred to commit (``SET CONSTRAINTS
fk_decision_log_entries_session DEFERRED``) - and the audited rows (the
session and its version rows) last, so the audit chain's lock is taken
only for those few rows, however many entries the transcript has. Each
store adds a constant number of audit rows: the session's INSERT or
UPDATE and its version rows.

Version rows (``decision_log_transcripts``)
-------------------------------------------
The table is audited; ``content_gz`` enters the audit log as a digest. Every
version records ``entry_count`` and ``entries_sha256``, the digest of its
entries (:func:`entries_digest`), so the audit log holds, per upload, the
counts and digests the stored entries can be checked against
(:func:`stored_entries_digest` recomputes the digest of a session's stored
entries).

* ``current``: the version the session's entries were parsed from:
  ``content_sha256`` / ``content_bytes`` of the upload, ``entry_count``,
  ``entries_sha256``, ``source_path``, ``submitted_by``; ``content_gz`` is
  NULL (the entries hold the content).
* ``superseded``: a version that a longer export extended, or that a
  repository version replaced in a conflict. ``content_sha256`` and
  ``content_bytes`` still describe the original upload; ``content_gz`` is
  the gzip of a *reconstruction* of the version from its stored entries
  (the original bytes are not kept while a version is current), in the
  format below; ``reason`` says what superseded it (in a conflict it starts
  with ``repository conflict:``).
* ``rejected``: ``content_gz`` is the gzip of the rejected upload's exact
  bytes; ``reason`` says why it was rejected; ``entries_sha256`` is NULL.

Entry digest (``entries_sha256``): SHA-256 over, for each entry in stored
order, the UTF-8 of the compact JSON array ``[role, content_text,
tool_calls, timestamp (ISO 8601 UTC with offset, or null), message_id,
is_verification]`` followed by a newline, each value as stored. A version
that keeps stored entries (an extension, or a conflict before its first
difference) takes their digest from the stored rows, so a digest also holds
for tool calls stored in their earlier form.

Reconstruction format (``decision-log-reconstruction/v1``): JSONL. The first
line is ``{"type": "decision-log-reconstruction", "format":
"decision-log-reconstruction/v1", "session_id", "content_sha256",
"content_bytes", "entries"}`` naming the original upload's digest and size
and the number of entries. Each further line is one entry in stored order,
in the Claude Code transcript shape the parser reads (for a Codex session
too): ``{"type": "assistant" | "user",
"timestamp": <ISO 8601 UTC, omitted when unknown>, "message": {"role",
"id" (omitted when unknown), "content": [{"type": "text", "text": ...}
(omitted when the entry has no text), <each stored tool_use block>]}}``;
the first entry line also carries the session's ``cwd``, ``gitBranch`` and
``message.model`` when known. Parsing a reconstruction yields exactly the
stored entries (tool calls stored in their earlier form: the same calls in
the current form).
"""

import collections
import contextvars
import gzip
import hashlib
import io
import json
import logging
import os
import re
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone

import sqlalchemy as sa

from app.models import DecisionLogEntry, DecisionLogSession, DecisionLogTranscript, db
from app.services import chunked_files
from app.services.transcript_ingest import TranscriptLimitError, clean_text, escape_surrogates, \
    normalize_agent_type, parse_transcript, same_tool_calls

logger = logging.getLogger(__name__)

SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,35}$")
JSONL_SUFFIX = ".jsonl"
META_SUFFIX = ".meta.json"
RECONSTRUCTION_FORMAT = "decision-log-reconstruction/v1"
SUPERSEDED_REASON = "superseded by a longer export that extends it"
REPOSITORY_OWNED_REASON = ("the evidence repository or the evidence store holds this session; only they may "
                           "extend it (the upload is kept as a rejected version)")
FORBIDDEN_REASON = ("only the member who submitted this session or a compliance admin may extend it; "
                    "the stored transcript is unchanged")
MAX_TRANSCRIPT_BYTES = 32 * 1024 * 1024
IMPORT_BYTE_BUDGET = MAX_TRANSCRIPT_BYTES * 3 // 2
MIN_IMPORT_CHARGE = 1024 * 1024
CONFLICT_REASON_PREFIX = "repository conflict: "
ENTRY_FOREIGN_KEY = "fk_decision_log_entries_session"
SESSION_LOCK_CLASS = 0x444C4F47  # first key of the per-session advisory lock ("DLOG")
AUTHORITY_SYSTEM = "system"
AUTHORITY_STORE = "store"
AUTHORITY_ADMIN = "admin"
AUTHORITY_MEMBER = "member"
AUTHORITIES = (AUTHORITY_SYSTEM, AUTHORITY_STORE, AUTHORITY_ADMIN, AUTHORITY_MEMBER)
# The sources of transcripts: their entries count in ``repository_entries``.
SOURCE_AUTHORITIES = (AUTHORITY_SYSTEM, AUTHORITY_STORE)
_INSERT_BATCH = 1000
_INSERT_BATCH_TEXT = 4 * 1024 * 1024
_COMPARE_BATCH = 1000


class ImportBudget:
    """A byte budget shared by the transcript imports of one process.

    ``acquire(charge, timeout)`` takes ``charge`` bytes of it: at once when
    they fit and nobody is waiting, else - unless ``timeout`` is 0 - after
    the imports waiting before it (first come, first served), waiting at most
    ``timeout`` seconds (None: until they fit). ``release(charge)`` returns
    them.
    """

    def __init__(self, capacity: int):
        self.capacity = capacity
        self.used = 0
        self._waiting = collections.deque()
        self._changed = threading.Condition()

    def acquire(self, charge: int, timeout: float | None = None) -> bool:
        with self._changed:
            if not self._waiting and self.used + charge <= self.capacity:
                self.used += charge
                return True
            if timeout is not None and timeout <= 0:
                return False
            ticket = object()
            self._waiting.append(ticket)
            deadline = None if timeout is None else time.monotonic() + timeout
            try:
                while self._waiting[0] is not ticket or self.used + charge > self.capacity:
                    remaining = None if deadline is None else deadline - time.monotonic()
                    if remaining is not None and remaining <= 0:
                        return False
                    self._changed.wait(remaining)
                self.used += charge
                return True
            finally:
                self._waiting.remove(ticket)
                self._changed.notify_all()

    def release(self, charge: int) -> None:
        with self._changed:
            self.used -= charge
            self._changed.notify_all()


_import_slots = ImportBudget(IMPORT_BYTE_BUDGET)
_slot_state = threading.local()


class TranscriptTooLargeError(TranscriptLimitError):
    """A transcript is larger than :data:`MAX_TRANSCRIPT_BYTES`."""

    def __init__(self, size: int, limit: int | None = None):
        limit = MAX_TRANSCRIPT_BYTES if limit is None else limit
        super().__init__(f"the transcript is {size} bytes; decision-log transcripts are limited to "
                         f"{limit} bytes", size=size, limit=limit)


class ImportBusyError(RuntimeError):
    """The transcript import budget of this process had no room in time."""


def import_charge(size: int | None) -> int:
    """Bytes of the import budget a transcript of ``size`` bytes takes
    (unknown size: :data:`MAX_TRANSCRIPT_BYTES`; at least :data:`MIN_IMPORT_CHARGE`)."""
    if size is None:
        return MAX_TRANSCRIPT_BYTES
    return min(max(int(size), MIN_IMPORT_CHARGE), MAX_TRANSCRIPT_BYTES)


@contextmanager
def import_slot(timeout: float | None = None, size: int | None = None):
    """Hold room for one transcript import in this process's import budget.

    The process imports at most :data:`IMPORT_BYTE_BUDGET` bytes of
    transcripts at once; an import takes :func:`import_charge` of ``size``
    (unknown: the full transcript limit). Re-entrant within a thread (a
    nested call takes nothing more). ``timeout`` None waits until the charge
    fits; otherwise :class:`ImportBusyError` is raised when it does not fit
    within ``timeout`` seconds (0: it does not fit now).
    """
    if getattr(_slot_state, "held", 0):
        _slot_state.held += 1
        try:
            yield
        finally:
            _slot_state.held -= 1
        return
    budget = _import_slots
    charge = min(import_charge(size), budget.capacity)
    if not budget.acquire(charge, timeout=timeout):
        raise ImportBusyError(f"the server is already importing its limit of {IMPORT_BYTE_BUDGET} bytes of "
                              "decision-log transcripts; retry shortly")
    _slot_state.held = 1
    try:
        yield
    finally:
        _slot_state.held = 0
        budget.release(charge)


@dataclass
class DecisionLogResult:
    """Outcome of :func:`import_decision_log`.

    ``status`` is ``created``, ``replaced``, ``unchanged``,
    ``kept_existing`` or ``rejected``; ``entries`` is the number of entries
    stored for the session afterwards; the digest and size describe the
    submitted content; ``reason`` explains a rejection; ``forbidden`` is
    True for a rejection because the upload's authority may not extend the
    session; ``conflict`` is True when a repository version replaced
    entries submitted through the API; ``agent_type`` is the session's agent
    label (for a new session, the one it is created with);
    ``submitted_entries`` is the number of entries parsed from the submitted
    content (None when it was not parsed: its digest equals the stored one).
    """

    status: str
    session_id: str
    entries: int
    content_sha256: str
    content_bytes: int
    reason: str | None = None
    forbidden: bool = False
    conflict: bool = False
    baselined: bool = False
    agent_type: str | None = None
    submitted_entries: int | None = None


def session_lock_key(session_id: str) -> int:
    """Stable signed 32-bit key of a session id (second key of the session lock)."""
    return int.from_bytes(hashlib.sha256(session_id.encode("utf-8")).digest()[:4], "big", signed=True)


def _is_postgres() -> bool:
    return db.session.get_bind().dialect.name == "postgresql"


def lock_session(session_id: str) -> None:
    """Take the session's transaction-scoped advisory lock (PostgreSQL only).

    Executed on the session's connection without an autoflush, so a caller
    that locks before its first write holds this lock before the audit
    chain's.
    """
    if _is_postgres():
        db.session.connection().execute(
            sa.text("SELECT pg_advisory_xact_lock(:a, :b)"),
            {"a": SESSION_LOCK_CLASS, "b": session_lock_key(session_id)})


def _defer_entry_checks() -> None:
    """Check the entries' foreign key at commit (PostgreSQL), so entries can be
    written before the audited session row of a new session."""
    if _is_postgres():
        db.session.connection().execute(sa.text(f"SET CONSTRAINTS {ENTRY_FOREIGN_KEY} DEFERRED"))


def _attribute_writes() -> None:
    """Name the audit actor for Core statements, which bypass the before_flush hook."""
    if not _is_postgres():
        return
    from flask import g, has_app_context

    member = getattr(g, "current_team_member", None) if has_app_context() else None
    if member is not None:
        db.session.connection().execute(
            sa.text("SET LOCAL app.current_team_member = :member_id"), {"member_id": member.id})


def describe_exception(exc):
    """Short, parameter-free description of an exception for an error line."""
    source = getattr(exc, "orig", None) or exc
    lines = str(source).strip().splitlines()
    text = lines[0] if lines else ""
    return f"{type(exc).__name__}: {text[:300]}"


def session_id_from_path(path):
    """Session id from ``<timestamp>_<session-id>.jsonl`` (or its ``.manifest.json``)."""
    if not path:
        return None
    base = os.path.basename(str(path).replace("\\", "/"))
    if base.endswith(chunked_files.MANIFEST_SUFFIX):
        base = base[: -len(chunked_files.MANIFEST_SUFFIX)]
    if not base.endswith(JSONL_SUFFIX):
        return None
    parts = base[: -len(JSONL_SUFFIX)].split("_", 1)
    return parts[1] if len(parts) == 2 and parts[1] else None


def _naive_utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def clean_metadata(column, value):
    """Informational session text as its column stores it: NUL characters and
    unpaired surrogates replaced by U+FFFD (``transcript_ingest.clean_text``),
    then cut to the column's length. A value that is not text is returned as
    it is."""
    if not isinstance(value, str):
        return value
    value = clean_text(value)
    length = getattr(DecisionLogSession.__table__.columns[column].type, "length", None)
    return value[:length] if length and len(value) > length else value


def _text(value):
    """A value as the text column stores it."""
    return value if value is None or isinstance(value, str) else str(value)


def _entry_key(role, content_text, tool_calls, timestamp, message_id, is_verification):
    return (_text(role), _text(content_text), _text(tool_calls), _utc(timestamp), _text(message_id),
            bool(is_verification))


def _parsed_key(entry):
    return _entry_key(entry["role"], entry["content_text"], entry["tool_calls"], entry["timestamp"],
                      entry["message_id"], entry["is_verification"])


_ENTRY_COLUMNS = (DecisionLogEntry.role, DecisionLogEntry.content_text, DecisionLogEntry.tool_calls,
                  DecisionLogEntry.timestamp, DecisionLogEntry.message_id, DecisionLogEntry.is_verification)
_ENTRY_FIELDS = ("role", "content_text", "tool_calls", "timestamp", "message_id", "is_verification")


def _canonical_entry(key) -> bytes:
    role, content_text, tool_calls, timestamp, message_id, is_verification = key
    line = json.dumps([role, content_text, tool_calls, timestamp.isoformat() if timestamp else None,
                       message_id, is_verification], ensure_ascii=False, separators=(",", ":"))
    return (line + "\n").encode("utf-8", "surrogatepass")


def entries_digest(entries) -> str:
    """``entries_sha256`` of parsed-entry dicts, in order (see the module docstring)."""
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(_canonical_entry(_parsed_key(entry)))
    return digest.hexdigest()


def _stored_rows(session_id):
    statement = (
        sa.select(*_ENTRY_COLUMNS)
        .where(DecisionLogEntry.session_id == session_id)
        .order_by(DecisionLogEntry.id)
        .execution_options(yield_per=_COMPARE_BATCH)
    )
    return db.session.execute(statement)


def stored_entries_digest(session_id) -> tuple[int, str]:
    """``(count, entries_sha256)`` of a session's stored entries, streamed.

    Equal to the ``entry_count`` and ``entries_sha256`` of the session's
    ``current`` version unless the entries were changed outside the import.
    """
    digest = hashlib.sha256()
    count = 0
    for row in _stored_rows(session_id):
        digest.update(_canonical_entry(_entry_key(*row)))
        count += 1
    return count, digest.hexdigest()


def _stored_entry_count(session_id):
    return db.session.query(sa.func.count(DecisionLogEntry.id)).filter(
        DecisionLogEntry.session_id == session_id).scalar() or 0


def _same_entry(stored_key, parsed_key):
    """A stored entry equals a parsed one (tool calls stored in the earlier form included)."""
    if stored_key == parsed_key:
        return True
    return stored_key[:2] == parsed_key[:2] and stored_key[3:] == parsed_key[3:] \
        and same_tool_calls(stored_key[2], parsed_key[2])


@dataclass
class _Comparison:
    """The stored entries of a session compared with parsed entries, in order.

    ``stored``: the number of stored entries; ``difference``: the index of
    the first position (below both lengths) where they differ, or None when
    the shorter list is a prefix of the other; ``prefix``: a SHA-256 object
    over the canonical form of the stored entries before ``difference``
    (without one: before the shorter length); ``stored_sha256``: the digest
    of all stored entries (:func:`stored_entries_digest`).
    """

    stored: int
    difference: int | None
    prefix: object
    stored_sha256: str

    def digest_with(self, entries) -> str:
        """``entries_sha256`` of the stored prefix followed by parsed ``entries``."""
        digest = self.prefix.copy()
        for entry in entries:
            digest.update(_canonical_entry(_parsed_key(entry)))
        return digest.hexdigest()


def _compare_with_stored(session_id, entries):
    """Compare the stored entries of a session with parsed ``entries`` (a :class:`_Comparison`).

    Stored rows are streamed, never held all at once. Digests are taken over
    the stored rows, so the entries a version keeps are described as stored.
    """
    count = 0
    difference = None
    prefix = None
    digest = hashlib.sha256()
    for row in _stored_rows(session_id):
        key = _entry_key(*row)
        if prefix is None:
            if count == len(entries):
                prefix = digest.copy()
            elif not _same_entry(key, _parsed_key(entries[count])):
                difference = count
                prefix = digest.copy()
        digest.update(_canonical_entry(key))
        count += 1
    return _Comparison(count, difference, digest.copy() if prefix is None else prefix, digest.hexdigest())


def _write_entries(session_id, entries):
    """INSERT parsed entries in order, in batches of at most 1,000 entries and
    about 4 MiB of text (a larger entry goes alone)."""
    rows, text = [], 0
    for entry in entries:
        size = len(entry["content_text"] or "") + len(entry["tool_calls"] or "")
        if rows and (len(rows) >= _INSERT_BATCH or text + size > _INSERT_BATCH_TEXT):
            db.session.execute(sa.insert(DecisionLogEntry), rows)
            rows, text = [], 0
        rows.append(dict(entry, session_id=session_id, timestamp=_naive_utc(entry["timestamp"])))
        text += size
    if rows:
        db.session.execute(sa.insert(DecisionLogEntry), rows)


def _delete_entries_from(session_id, index):
    """Delete a session's stored entries from position ``index`` (0-based) on."""
    cutoff = db.session.execute(
        sa.select(DecisionLogEntry.id).where(DecisionLogEntry.session_id == session_id)
        .order_by(DecisionLogEntry.id).offset(index).limit(1)).scalar()
    if cutoff is not None:
        db.session.execute(
            sa.delete(DecisionLogEntry)
            .where(DecisionLogEntry.session_id == session_id, DecisionLogEntry.id >= cutoff)
            .execution_options(synchronize_session=False))


def _latest_stored_timestamp(session_id):
    latest = db.session.query(sa.func.max(DecisionLogEntry.timestamp)).filter(
        DecisionLogEntry.session_id == session_id).scalar()
    return _utc(latest)


def _first_backdated(entries, start, latest):
    """Index of the first entry from ``start`` timestamped before ``latest``, or None."""
    if latest is None:
        return None
    for index in range(start, len(entries)):
        timestamp = entries[index]["timestamp"]
        if timestamp is not None and _utc(timestamp) < latest:
            return index
    return None


def _metadata(parsed, source_path, exit_reason):
    """The session metadata an upload supplies (None where it supplies none)."""
    return {
        "model": clean_metadata("model", parsed.model),
        "cwd": clean_metadata("cwd", parsed.cwd),
        "git_branch": clean_metadata("git_branch", parsed.git_branch),
        "started_at": _naive_utc(parsed.started_at),
        "exit_reason": clean_metadata("exit_reason", exit_reason),
        "transcript_path": clean_metadata("transcript_path", source_path),
    }


def _apply_session_fields(session, parsed, sha, size, source_path, exit_reason, *, replace):
    """Update a stored session from a version that extends it.

    Metadata fills unset fields; with ``replace`` (an admin's version, or a
    repository version that wins a conflict) each value the version supplies
    replaces the stored one.
    """
    for name, value in _metadata(parsed, source_path, exit_reason).items():
        if value is not None and (replace or getattr(session, name) is None) \
                and getattr(session, name) != value:
            setattr(session, name, value)
    if parsed.ended_at is not None:
        session.ended_at = _naive_utc(parsed.ended_at)
    session.content_sha256 = sha
    session.content_bytes = size


def _insert_session(session_id, parsed, sha, size, source_path, exit_reason, submitted_by,
                    repository_entries, agent_type):
    """INSERT the session ... ON CONFLICT DO NOTHING; True when this call inserted it."""
    values = dict(_metadata(parsed, source_path, exit_reason), id=session_id, agent_type=agent_type,
                  ended_at=_naive_utc(parsed.ended_at), submitted_by=submitted_by,
                  content_sha256=sha, content_bytes=size, repository_entries=repository_entries)
    table = DecisionLogSession.__table__
    dialect = db.session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    _attribute_writes()
    statement = insert(table).values(**values).on_conflict_do_nothing(index_elements=["id"])
    return db.session.execute(statement).rowcount == 1


def _has_current_version(session_id) -> bool:
    return db.session.query(DecisionLogTranscript.id).filter_by(
        session_id=session_id, status="current").first() is not None


def _baseline(session, sha, size, source_path, count, digest):
    """Record the repository's or the store's identical copy of a stored session
    that has no current version (a session restored from an earlier portal) as
    its current version - a repository import with the git sync's commit, or a
    store import naming its store object - writing no entry rows."""
    _attribute_writes()
    session.repository_entries = count
    session.content_sha256 = sha
    session.content_bytes = size
    _version(session.id, "current", sha=sha, size=size, entries=count, source_path=source_path,
             submitted_by=None, digest=digest)
    db.session.flush()


def _repository_entries(session, stored):
    """How many leading stored entries came from the evidence repository."""
    if session.repository_entries is not None:
        return min(session.repository_entries, stored)
    return stored if session.submitted_by is None else 0


def confirmed_entry_limit(session, stored):
    """How many leading stored entries count (as verifications among them):
    the repository-supplied ones once the repository has supplied any, else
    all (``None``)."""
    repository = _repository_entries(session, stored)
    return repository if repository > 0 else None


def _may_extend(session, authority, submitted_by):
    if authority in (AUTHORITY_SYSTEM, AUTHORITY_STORE, AUTHORITY_ADMIN):
        return True
    return (session.submitted_by is not None and session.submitted_by == submitted_by
            and session.conflict_at is None)


# The evidence-repository commit the current import reads (set by a git sync
# through ``import_decision_log(source_commit=...)``); every version the import
# writes records it, so ``decision_log_repo_verify`` can fetch that version
# from the repository.
_SOURCE_COMMIT = contextvars.ContextVar("decision_log_source_commit", default=None)
# The evidence-store object the current import reads (set by an evidence-store
# sync through ``import_decision_log(store_object_id=...)``); every version the
# import writes records it, so ``audit-verify --against-store`` can check that
# version against its object.
_STORE_OBJECT = contextvars.ContextVar("decision_log_store_object", default=None)


def _version(session_id, status, *, sha, size, entries, source_path=None, submitted_by=None,
             content_gz=None, reason=None, received_at=None, digest=None):
    row = DecisionLogTranscript(
        id=str(uuid.uuid4()), session_id=session_id, status=status, content_sha256=sha,
        content_bytes=size, entry_count=entries, entries_sha256=digest, content_gz=content_gz,
        reason=reason, source_path=clean_metadata("transcript_path", source_path), submitted_by=submitted_by,
        source_commit=_SOURCE_COMMIT.get() if status != "superseded" else None,
        store_object_id=_STORE_OBJECT.get() if status != "superseded" else None)
    if received_at is not None:
        row.received_at = received_at
    db.session.add(row)
    return row


def _reconstruction_line(entry, first, session):
    content = []
    if entry["content_text"] is not None:
        content.append({"type": "text", "text": entry["content_text"]})
    if entry["tool_calls"]:
        try:
            blocks = json.loads(entry["tool_calls"])
        except ValueError:
            blocks = []
        if isinstance(blocks, list):
            content.extend(block for block in blocks if isinstance(block, dict))
    message = {"role": entry["role"], "content": content}
    if entry["message_id"] is not None:
        message["id"] = entry["message_id"]
    record = {"type": "assistant" if entry["role"] == "assistant" else "user", "message": message}
    if entry["timestamp"] is not None:
        record["timestamp"] = _utc(entry["timestamp"]).isoformat()
    if first:
        if session.model:
            message["model"] = session.model
        if session.cwd:
            record["cwd"] = session.cwd
        if session.git_branch:
            record["gitBranch"] = session.git_branch
    return record


def _reconstruct(session, entries, count):
    """``(content_gz, entries_sha256)`` of ``session``'s stored version.

    ``entries`` (an iterable of parsed-entry dicts, consumed once) are that
    version's ``count`` entries in stored order; the header names the
    session's stored digest and size.
    """
    buffer = io.BytesIO()
    digest = hashlib.sha256()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as handle:
        header = {"type": "decision-log-reconstruction", "format": RECONSTRUCTION_FORMAT,
                  "session_id": session.id, "content_sha256": session.content_sha256,
                  "content_bytes": session.content_bytes, "entries": count}
        handle.write((json.dumps(header) + "\n").encode("utf-8"))
        for index, entry in enumerate(entries):
            digest.update(_canonical_entry(_parsed_key(entry)))
            line = escape_surrogates(json.dumps(_reconstruction_line(entry, index == 0, session),
                                                ensure_ascii=False))
            handle.write((line + "\n").encode("utf-8"))
    return buffer.getvalue(), digest.hexdigest()


def reconstruct_transcript_gz(session, entries):
    """gzip of the ``decision-log-reconstruction/v1`` JSONL of ``session``'s stored version.

    ``entries`` are that version's entries (parsed-entry dicts) in stored
    order; the header names the session's stored digest and size.
    """
    return _reconstruct(session, entries, len(entries))[0]


def _stored_entry_dicts(session_id):
    for row in _stored_rows(session_id):
        yield dict(zip(_ENTRY_FIELDS, row))


def _supersede_current(session, content_gz, digest, count, reason):
    """Turn the session's current version into a superseded one that keeps its content."""
    current = DecisionLogTranscript.query.filter_by(session_id=session.id, status="current").all()
    for row in current:
        row.status = "superseded"
        row.content_gz = content_gz
        row.reason = reason
        if row.entries_sha256 is None:
            row.entries_sha256 = digest
    if not current:  # a session stored before versions were recorded
        _version(session.id, "superseded", sha=session.content_sha256, size=session.content_bytes,
                 entries=count, source_path=session.transcript_path,
                 submitted_by=session.submitted_by, content_gz=content_gz, reason=reason,
                 received_at=_utc(session.replaced_at or session.imported_at), digest=digest)


def _create(sid, parsed, sha, size, source_path, exit_reason, submitted_by, repository_entries, agent_type):
    """Store a new session labelled ``agent_type``; False (nothing stored) when it exists already.

    On PostgreSQL the entries are written first (their foreign-key check is
    deferred to commit) and the audited session row after them, inside a
    savepoint that is rolled back when the session exists.
    """
    session_args = (sid, parsed, sha, size, source_path, exit_reason, submitted_by, repository_entries,
                    agent_type)
    digest = entries_digest(parsed.entries)
    if _is_postgres():
        savepoint = db.session.begin_nested()
        _write_entries(sid, parsed.entries)
        if not _insert_session(*session_args):
            savepoint.rollback()
            return False
        savepoint.commit()
    else:
        if not _insert_session(*session_args):
            return False
        _write_entries(sid, parsed.entries)
    _version(sid, "current", sha=sha, size=size, entries=len(parsed.entries), source_path=source_path,
             submitted_by=submitted_by, digest=digest)
    db.session.flush()
    return True


def _extend(session, parsed, comparison, sha, size, source_path, exit_reason, submitted_by, authority):
    stored_count = comparison.stored
    repository = _repository_entries(session, stored_count)
    content_gz, _ = _reconstruct(session, parsed.entries[:stored_count], stored_count)
    digest = comparison.digest_with(parsed.entries[stored_count:])
    _write_entries(session.id, parsed.entries[stored_count:])
    # The audited writes come last (the audit chain's lock is held from here to commit).
    _attribute_writes()
    _supersede_current(session, content_gz, comparison.stored_sha256, stored_count, SUPERSEDED_REASON)
    _apply_session_fields(session, parsed, sha, size, source_path, exit_reason,
                          replace=authority == AUTHORITY_ADMIN)
    session.replaced_at = datetime.now(timezone.utc)
    session.repository_entries = len(parsed.entries) if authority in SOURCE_AUTHORITIES else repository
    _version(session.id, "current", sha=sha, size=size, entries=len(parsed.entries),
             source_path=source_path, submitted_by=submitted_by, digest=digest)
    db.session.flush()


def _adopt_repository_version(session, parsed, comparison, sha, size, source_path, exit_reason,
                              submitted_by):
    """The repository's version becomes the session's stored entries (a conflict).

    With a ``comparison.difference`` the stored entries from that entry on
    are replaced by the repository's; without one the repository's version
    is a strict prefix of the stored entries and the stored entries beyond
    it are removed. The previous version is kept as ``superseded`` with a
    reason starting with :data:`CONFLICT_REASON_PREFIX`; the new ``current``
    version and the session name the repository import's path and submitter.
    """
    stored_count, count = comparison.stored, len(parsed.entries)
    where = source_path or "repository import"
    if comparison.difference is not None:
        cut = comparison.difference
        detail = (f"entry {cut + 1} of the {stored_count} stored entries differed from the evidence "
                  f"repository's version ({where}); the repository's {count} entries replaced them, and "
                  f"the previous version, with the {stored_count - cut} entries submitted through the API "
                  f"from entry {cut + 1} on, is kept as a superseded version")
    else:
        cut = count
        detail = (f"the evidence repository's version ({where}) has {count} entries and does not contain "
                  f"stored entries {count + 1} to {stored_count}, which were submitted through the API; they "
                  "were removed from the current version, and the previous version, with them, is kept as a "
                  "superseded version")
    content_gz, _ = _reconstruct(session, _stored_entry_dicts(session.id), stored_count)
    digest = comparison.digest_with(parsed.entries[cut:])
    _delete_entries_from(session.id, cut)
    _write_entries(session.id, parsed.entries[cut:])
    # The audited writes come last (the audit chain's lock is held from here to commit).
    _attribute_writes()
    _supersede_current(session, content_gz, comparison.stored_sha256, stored_count,
                       CONFLICT_REASON_PREFIX + detail)
    _apply_session_fields(session, parsed, sha, size, source_path, exit_reason, replace=True)
    if parsed.ended_at is None:
        session.ended_at = None
    now = datetime.now(timezone.utc)
    session.replaced_at = now
    session.repository_entries = count
    session.submitted_by = submitted_by
    session.conflict_at = now
    session.conflict_detail = detail
    _version(session.id, "current", sha=sha, size=size, entries=count,
             source_path=source_path, submitted_by=submitted_by, digest=digest)
    db.session.flush()
    logger.warning("Decision log %s: conflict - %s", session.id, detail)


def _repository_wins(session, parsed, comparison):
    """A repository version conflicts with entries submitted through the API and replaces them.

    It does when it differs from the stored entries at an entry the
    repository has not supplied, or when it is a strict prefix of the stored
    entries (an empty or metadata-only file included) and holds every entry
    the repository supplied (the stored entries beyond it came through the
    API).
    """
    repository = _repository_entries(session, comparison.stored)
    if session.repository_entries is None and not _has_current_version(session.id):
        repository = 0  # restored and never baselined: nothing proves the stored entries are the repository's
    if comparison.difference is not None:
        return comparison.difference >= repository
    return len(parsed.entries) < comparison.stored and len(parsed.entries) >= repository


def _record_rejected(session_id, content, sha, size, entries, reason, source_path, submitted_by):
    known = db.session.query(DecisionLogTranscript.id).filter_by(
        session_id=session_id, status="rejected", content_sha256=sha).first()
    if known is not None:
        return
    _version(session_id, "rejected", sha=sha, size=size, entries=entries, source_path=source_path,
             submitted_by=submitted_by, content_gz=gzip.compress(content, mtime=0), reason=reason)
    db.session.flush()


def import_decision_log(content, *, session_id=None, source_path=None, exit_reason=None,
                        submitted_by=None, authority=AUTHORITY_SYSTEM,
                        dry_run=False, source_commit=None, agent_type=None,
                        store_object_id=None, parsed=None) -> DecisionLogResult:
    """Store one transcript according to the rules in the module docstring.

    ``content`` is the raw transcript bytes (text is encoded as UTF-8); the
    digest and size are computed over those bytes. The session id is
    ``session_id``, else parsed from ``source_path``'s file name.
    ``agent_type`` names the agent that wrote the transcript; a new session
    is labelled with it (normalised by ``normalize_agent_type``), or, when it
    is absent or unusable, with the transcript's detected format's agent; a
    stored session keeps its label.
    ``submitted_by`` is the member the new version (and a new session) is
    attributed to; ``authority`` (``system``, ``store``, ``admin`` or
    ``member``, which needs ``submitted_by``) decides who may extend a stored
    session. Holds an
    import slot (:func:`import_slot`, waiting for one unless the thread holds
    one), takes the session lock, flushes, does not commit (a rejection's
    version row is part of the flush); ``dry_run`` decides the status
    without writing. Raises ValueError when no valid session id can be
    determined or the transcript is invalid (``TranscriptError``), and a
    :class:`TranscriptLimitError` (a ValueError) for a transcript over a
    limit (:class:`TranscriptTooLargeError` above
    :data:`MAX_TRANSCRIPT_BYTES`). ``source_commit`` (a git sync's commit,
    ``system`` authority only) is recorded on every version the import writes;
    so is ``store_object_id`` (the ``evidence_store_objects`` id of the object
    version an evidence-store sync read; required by, and only accepted with,
    the ``store`` authority; the caller writes that row in the same
    transaction). Either one makes ``source_path`` subject to the path rule:
    it must be the session's own ``<timestamp>_<session id>.jsonl``.
    ``parsed`` is ``content`` already parsed by ``parse_transcript`` (the
    evidence store's content check parses it before its transaction); the
    import then does not parse it again.
    """
    if (authority == AUTHORITY_STORE) != bool(store_object_id):
        raise ValueError("an evidence-store import names its store object, and only the store authority does")
    token = _SOURCE_COMMIT.set(source_commit if authority == AUTHORITY_SYSTEM else None)
    store_token = _STORE_OBJECT.set(store_object_id if authority == AUTHORITY_STORE else None)
    try:
        return _import_decision_log(content, session_id=session_id, source_path=source_path,
                                    exit_reason=exit_reason, submitted_by=submitted_by, authority=authority,
                                    dry_run=dry_run, agent_type=agent_type, parsed=parsed)
    finally:
        _STORE_OBJECT.reset(store_token)
        _SOURCE_COMMIT.reset(token)


def _import_decision_log(content, *, session_id, source_path, exit_reason, submitted_by, authority, dry_run,
                         agent_type, parsed=None):
    if isinstance(content, str):
        content = content.encode("utf-8")
    if not isinstance(content, (bytes, bytearray)):
        raise TypeError("content must be bytes")
    if authority not in AUTHORITIES:
        raise ValueError(f"authority must be one of {', '.join(AUTHORITIES)}")
    if authority == AUTHORITY_MEMBER and not submitted_by:
        raise ValueError("a member's upload must name its submitter")
    sid = session_id or session_id_from_path(source_path)
    bound_to_source = _SOURCE_COMMIT.get() is not None or _STORE_OBJECT.get() is not None
    if authority in SOURCE_AUTHORITIES and bound_to_source and session_id_from_path(source_path) != sid:
        raise ValueError(f"repository path {source_path} is not session {sid}'s file "
                         "(<timestamp>_<session id>.jsonl)")
    if not sid:
        raise ValueError("cannot determine the session id: pass session_id or a "
                         "<timestamp>_<session-id>.jsonl path")
    if not SESSION_ID_RE.match(sid):
        raise ValueError(f"invalid session id {sid[:80]!r}")
    size = len(content)
    if size > MAX_TRANSCRIPT_BYTES:
        raise TranscriptTooLargeError(size)
    with import_slot(size=size):
        return _import(content, sid, hashlib.sha256(content).hexdigest(), size, source_path=source_path,
                       exit_reason=exit_reason, submitted_by=submitted_by, authority=authority,
                       dry_run=dry_run, named_agent=normalize_agent_type(agent_type), preparsed=parsed)


def _import(content, sid, sha, size, *, source_path, exit_reason, submitted_by, authority, dry_run,
            named_agent, preparsed=None):
    new_agent = None  # the label a session this call creates gets

    def result(status, entries, reason=None, forbidden=False, conflict=False, baselined=False):
        return DecisionLogResult(status=status, session_id=sid, entries=entries, content_sha256=sha,
                                 content_bytes=size, reason=reason, forbidden=forbidden, conflict=conflict,
                                 baselined=baselined,
                                 agent_type=session.agent_type if session is not None else new_agent,
                                 submitted_entries=len(parsed.entries) if parsed is not None else None)

    def reject(reason, stored, entries, forbidden=False):
        if not dry_run:
            _record_rejected(sid, content, sha, size, entries, reason, source_path, submitted_by)
        return result("rejected", stored, reason, forbidden)

    if not dry_run:
        lock_session(sid)
        _defer_entry_checks()
    session = db.session.get(DecisionLogSession, sid)
    parsed = preparsed
    if session is None:
        parsed = parsed or parse_transcript(content)
        new_agent = named_agent or parsed.agent_type
        if dry_run:
            return result("created", len(parsed.entries))
        repository = len(parsed.entries) if authority in SOURCE_AUTHORITIES else 0
        if _create(sid, parsed, sha, size, source_path, exit_reason, submitted_by, repository, new_agent):
            return result("created", len(parsed.entries))
        # Another transaction created the session first: store against it.
        session = db.session.get(DecisionLogSession, sid, populate_existing=True)

    unbaselined = authority in SOURCE_AUTHORITIES and not _has_current_version(sid)
    if session.content_sha256 == sha and not unbaselined:
        return result("unchanged", _stored_entry_count(sid))

    parsed = parsed or parse_transcript(content)
    comparison = _compare_with_stored(sid, parsed.entries)
    stored, difference = comparison.stored, comparison.difference
    if authority == AUTHORITY_SYSTEM and _repository_wins(session, parsed, comparison):
        if not dry_run:
            _adopt_repository_version(session, parsed, comparison, sha, size, source_path, exit_reason,
                                      submitted_by)
        return result("replaced", len(parsed.entries), conflict=True)
    if difference is None and unbaselined and len(parsed.entries) == stored:
        # A stored session (restored from an earlier portal) that the repository or the
        # store holds identically: record that copy as its current version (a baseline).
        if not dry_run:
            _baseline(session, sha, size, source_path, stored, comparison.stored_sha256)
        return result("unchanged", stored, baselined=True)
    if difference is not None:  # a store export never replaces stored entries (module docstring)
        return reject(f"entry {difference + 1} differs from the stored transcript of {stored} entries; "
                      "a new export must extend the stored transcript", stored, len(parsed.entries))
    permitted = _may_extend(session, authority, submitted_by)
    if len(parsed.entries) > stored:
        if not permitted:
            return reject(FORBIDDEN_REASON, stored, len(parsed.entries), forbidden=True)
        if authority not in SOURCE_AUTHORITIES and _repository_entries(session, stored) > 0:
            return reject(REPOSITORY_OWNED_REASON, stored, len(parsed.entries))
        latest = _latest_stored_timestamp(sid) if authority not in SOURCE_AUTHORITIES else None
        backdated = _first_backdated(parsed.entries, stored, latest) if latest is not None else None
        if backdated is not None:
            stamp = _utc(parsed.entries[backdated]["timestamp"]).isoformat()
            return reject(f"entry {backdated + 1} is timestamped {stamp}, earlier than the latest "
                          f"stored entry ({latest.isoformat()}); appended entries must not be "
                          "back-dated", stored, len(parsed.entries))
        if not dry_run:
            _extend(session, parsed, comparison, sha, size, source_path, exit_reason, submitted_by, authority)
        return result("replaced", len(parsed.entries))
    if len(parsed.entries) == stored and session.content_sha256 is None and permitted \
            and authority != AUTHORITY_STORE:  # a store export that holds nothing new changes nothing
        if not dry_run:
            if authority == AUTHORITY_SYSTEM:
                session.repository_entries = stored
            session.content_sha256 = sha
            session.content_bytes = size
            db.session.flush()
        return result("unchanged", stored)
    return result("kept_existing", stored)


def sidecar_fields(meta):
    """``(exit_reason, agent)`` of a decoded ``.meta.json`` sidecar: its string
    ``reason`` and ``agent`` fields, None where absent or not a string."""
    if not isinstance(meta, dict):
        return None, None
    reason, agent = meta.get("reason"), meta.get("agent")
    return (reason if isinstance(reason, str) else None), (agent if isinstance(agent, str) else None)


def _read_sidecar(directory, logical_name):
    """``(exit_reason, agent)`` from a transcript's sidecar (None, None without a readable one)."""
    meta_path = os.path.join(directory, logical_name[: -len(JSONL_SUFFIX)] + META_SUFFIX)
    if not os.path.isfile(meta_path):
        return None, None
    try:
        with open(meta_path, "rb") as fh:
            meta = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError):
        return None, None
    return sidecar_fields(meta)


def _scan_directory(directory, path_prefix, summary, errors):
    """Pick the largest export of each session: {session_id: (logical, full_path, kind, size)}."""
    best = {}
    for name in sorted(os.listdir(directory)):
        full = os.path.join(directory, name)
        if not os.path.isfile(full):
            continue
        display = f"{path_prefix}/{name}" if path_prefix else full
        if name.endswith(JSONL_SUFFIX):
            logical, kind, size = name, "plain", os.path.getsize(full)
        elif name.endswith(JSONL_SUFFIX + chunked_files.MANIFEST_SUFFIX):
            logical, kind = chunked_files.logical_path(name), "manifest"
            try:
                manifest = chunked_files.parse_manifest(chunked_files.read_manifest_file(full))
                if manifest.name != logical:
                    raise chunked_files.ChunkedFileError(f"manifest names {manifest.name!r}")
            except (OSError, chunked_files.ChunkedFileError) as exc:
                summary["failed"] += 1
                errors.append(f"{display}: not imported ({describe_exception(exc)})")
                continue
            size = manifest.size
        else:
            continue
        sid = session_id_from_path(logical)
        if not sid or not SESSION_ID_RE.match(sid):
            errors.append(f"{display}: no session id in the file name; skipped")
            continue
        rank = (size, kind == "plain", logical)
        if sid not in best or rank > best[sid][0]:
            best[sid] = (rank, logical, full, kind)
    return {sid: (logical, full, kind, rank[0]) for sid, (rank, logical, full, kind) in best.items()}


def import_decision_log_directory(directory, *, dry_run=False, path_prefix="decision-logs"):
    """Import the transcripts of a ``decision-logs`` directory, committing after each.

    For each session id only the largest export is imported (resumed
    sessions leave several, each longer than the last); chunked transcripts
    (``<name>.jsonl.manifest.json`` + parts) are reassembled and verified,
    reading no part beyond the size its manifest declares; a
    ``<stem>.meta.json`` sidecar supplies the exit reason (``reason``) and
    the agent (``agent``) a new session is labelled with. Transcripts are
    stored with the system's authority, one at a time per import slot
    (:func:`import_slot`). The stored ``transcript_path`` is
    ``<path_prefix>/<file name>`` (the full path when ``path_prefix`` is
    empty). A rejected transcript is recorded (its version row is committed)
    and reported as an error line; a transcript larger than
    :data:`MAX_TRANSCRIPT_BYTES` is reported as failed without being read,
    and one over another limit as failed without anything stored.

    Returns ``(summary, errors)``: counts per status (``created``,
    ``replaced``, ``unchanged``, ``kept_existing``, ``rejected``) plus
    ``failed``, and human-readable error lines.
    """
    summary = {"created": 0, "replaced": 0, "unchanged": 0, "kept_existing": 0, "rejected": 0,
               "failed": 0}
    errors = []
    chosen = _scan_directory(directory, path_prefix, summary, errors)

    for sid, (logical, full, kind, size) in sorted(chosen.items(), key=lambda item: item[1][0]):
        display = f"{path_prefix}/{logical}" if path_prefix else os.path.join(directory, logical)
        if size > MAX_TRANSCRIPT_BYTES:
            summary["failed"] += 1
            errors.append(f"{display}: not imported ({describe_exception(TranscriptTooLargeError(size))})")
            continue
        try:
            with import_slot(size=size):
                if kind == "manifest":
                    content = chunked_files.read_local(full)
                else:
                    with open(full, "rb") as fh:
                        content = fh.read(MAX_TRANSCRIPT_BYTES + 1)
                exit_reason, agent = _read_sidecar(directory, logical)
                result = import_decision_log(
                    content, session_id=sid, source_path=display,
                    exit_reason=exit_reason, agent_type=agent, dry_run=dry_run)
                del content
            if not dry_run:
                db.session.commit()
        except Exception as exc:  # one bad transcript must not stop the import
            db.session.rollback()
            logger.warning("Decision log %s failed", display,
                           exc_info=not isinstance(exc, (ValueError, OSError)))
            summary["failed"] += 1
            errors.append(f"{display}: not imported ({describe_exception(exc)})")
            continue
        summary[result.status] += 1
        if result.status == "rejected":
            errors.append(f"{display}: rejected ({result.reason})")
        elif result.conflict:
            errors.append(f"{display}: conflict - the repository's version replaced entries submitted "
                          "through the API (kept as a superseded version)")
        logger.debug("decision log %s: %s (%d entries)", display, result.status, result.entries)
    return summary, errors
