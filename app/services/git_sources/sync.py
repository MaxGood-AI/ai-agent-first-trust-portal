"""Git source sync: bring the portal to the state of a source's branch head,
reading only what changed and writing only real differences.

One sync (``execute_sync_run``) does:

1. Resolve the branch head. When it equals the last synced commit and no
   file is waiting for a retry, the run ends as ``unchanged``.
2. Work out the candidate files: the provider's diff from the last synced
   commit to head; or, on the first sync (or when the provider cannot diff
   from that commit), the full tree compared blob-by-blob with the files
   already recorded in ``git_source_files``. A last synced commit the
   repository does not contain (the provider raises ``NotFoundError`` for the
   diff or the history: history rewritten, repository switched, mistyped
   cutover commit) fails the run with ``UnknownCommitError``, which tells the
   administrator to run a full re-import. Files that failed last time are
   retried, and so are dataset files that imported only partly (records
   skipped for a missing reference), so they catch up once the file they
   depend on is fixed. Only mapped paths (``app.services.git_sources.mappings``)
   count; a changed chunk part (``<name>.part-NNNN``) makes its stored
   manifest a candidate.
   A full re-import (requested on the run) processes every mapped file at
   head; each import is still diff-only per record.
3. Process candidates in dependency order (evidence datasets in
   ``DATASET_ORDER``, then decision logs, then governance files). Each file
   is first *fetched* - its content, and for a decision log its chunk parts
   and ``.meta.json`` sidecar - with no database transaction open, then
   *written* in its own database transaction, so an interrupted sync resumes
   where it stopped and audited writes elsewhere never wait for the whole
   sync or for the provider. A file whose transaction hits a PostgreSQL
   deadlock (SQLSTATE 40P01) is written again once:

   - ``policy`` / ``governance_document``: store a new ``GitFileVersion``
     (content, SHA-256, commit, blob) and make it current;
   - ``dataset:<name>``: ``evidence_import.import_dataset_file`` (diff-only),
     namespaced by the source id, so pentest findings of two sources never
     replace or delete each other;
   - ``decision_log``: reassemble chunked transcripts (reading no part
     beyond its declared size plus one byte), then
     ``evidence_import.import_decision_log`` with the system's authority (the
     evidence repository is authoritative for the sessions it contains: it
     may extend any session, and its version replaces entries submitted
     through the API that it contradicts, flagging the session as a conflict
     and listing it in the run's ``details.conflicts``). The transcript is
     stored before the file's record, under the session's advisory lock taken
     before any other write of the file's transaction; a transcript that does
     not extend the stored one is rejected (kept for review) and the file is
     recorded as an error. Decision logs are fetched and written holding one
     of the process's transcript import slots (waiting for one);
   - deletions: mark the file deleted (pentest findings of a deleted file
     are removed; other records are kept).

   A file the provider cannot return (``FileTooLargeError``, e.g. over
   CodeCommit's 6 MB API limit), a decision-log transcript larger than
   ``evidence_import_decision_logs.MAX_TRANSCRIPT_BYTES`` (32 MiB; a chunked one is
   recognised from its manifest, before any part is read) or over the entry
   limits (50,000 entries, 8 MiB per line), and a chunked transcript whose
   part is larger than its manifest declares are flagged on the run and
   recorded as ``too_large`` on the file with its blob, and are not read
   again until their blob changes (for a chunked file, in a diff sync, a
   change to one of its parts counts too); the sync continues.
4. When enabled for the source, record the commits between the last synced
   commit and head that touched mapped paths (``git_commits``). The history
   and each commit's changed paths are read before the transaction that
   records them. When the provider returns ``history_limit`` commits the
   history may be cut short, and the run's ``details.history_truncated`` is
   true. A full re-import whose last synced commit is unknown to the
   repository records the history reachable from head instead, as a first
   sync does.
5. Record the run's outcome and counts (created / updated / unchanged /
   deleted / skipped / flagged / incomplete / errors) compare-and-set - only
   while the run is still ``running`` under the executor token it was claimed
   with - and, when that applies, the source's sync status and new last
   synced commit. The last synced commit moves compare-and-set too: only
   while it still holds the value the run started from, so a commit an
   administrator set (or a reset by a repository change) during the run is
   kept. A run with flagged, incomplete or failed files is ``partial``.

The provider is never called while the sync's database session has a
transaction open: the source is read into a ``SourceSnapshot``, and every
read transaction ends before the next provider call.

Every write goes through the audited tables (decision-log entries are
audited per stored transcript version, ``decision_log_transcripts``).
"""

from __future__ import annotations

import copy
import hashlib
import logging
import posixpath
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import case, select, text, update

from app.models import db
from app.models.git_source import GitCommit, GitFileVersion, GitSource, GitSourceFile, GitSyncRun
from app.services.git_sources import mappings as mapping_rules
from app.services.git_sources.providers import (
    Change,
    FileTooLargeError,
    GitSourceError,
    NotFoundError,
)
from app.services.git_sources.service import build_provider_for, effective_options
from app.services.scheduler import LockLostError

logger = logging.getLogger(__name__)

COUNT_KEYS = ("created", "updated", "unchanged", "deleted", "skipped", "flagged", "incomplete", "errors")
RETRY_STATUSES = ("error", "incomplete")
MAX_DETAIL_ITEMS = 200
PROVIDER_LIMIT_REASON = "file exceeds the provider's API size limit"
TRANSCRIPT_LIMIT_REASON = "decision-log transcript exceeds the decision-log size limit"
TRANSCRIPT_CONTENT_LIMIT_REASON = "decision-log transcript exceeds the decision-log entry limits"
CHUNK_PART_LIMIT_REASON = "a chunk part is larger than its manifest declares"
MANIFEST_SUFFIX = ".manifest.json"
_PART_RE = re.compile(r"^(?P<name>.+)\.part-\d{4}$")


def _now():
    return datetime.now(timezone.utc)


@dataclass
class Candidate:
    path: str
    kind: str
    change_type: str          # A, M, D, or R (retry)
    blob_id: str | None
    size: int | None = None   # from the tree listing, when known


@dataclass(frozen=True)
class SourceSnapshot:
    """The configuration of a source as a sync read it when it started."""

    id: str
    name: str
    role: str
    provider: str
    repository: str
    branch: str
    region: str | None
    credential_mode: str
    encrypted_credentials: bytes | None
    options: dict | None
    path_mappings: list | None
    last_synced_commit: str | None

    @classmethod
    def of(cls, source: GitSource) -> "SourceSnapshot":
        return cls(id=source.id, name=source.name, role=source.role, provider=source.provider,
                   repository=source.repository, branch=source.branch, region=source.region,
                   credential_mode=source.credential_mode,
                   encrypted_credentials=source.encrypted_credentials,
                   options=copy.deepcopy(source.options),
                   path_mappings=copy.deepcopy(source.path_mappings),
                   last_synced_commit=source.last_synced_commit)


@dataclass(frozen=True)
class StoredFile:
    """What a sync needs of a ``git_source_files`` row to pick candidates."""

    path: str
    kind: str
    blob_id: str | None
    status: str


@dataclass
class FetchedFile:
    """A candidate's content, read from the provider before its transaction.

    ``too_large`` (``{"size", "limit", "reason", "detail"}``) marks a file
    that is flagged instead of imported. A decision log carries its
    (reassembled) ``transcript``, the ``transcript_path`` it is stored under
    and the ``exit_reason`` and ``agent`` of its sidecar.
    """

    content: bytes | None = None
    blob_id: str | None = None
    size: int | None = None
    too_large: dict | None = None
    transcript: bytes | None = None
    transcript_path: str | None = None
    exit_reason: str | None = None
    agent: str | None = None


@dataclass(frozen=True)
class CommitHistory:
    """What ``record_commits`` did: commits recorded, and whether the history
    read reached ``history_limit`` (and so may be cut short)."""

    recorded: int = 0
    truncated: bool = False


@dataclass
class SyncTally:
    counts: dict = field(default_factory=lambda: {key: 0 for key in COUNT_KEYS})
    by_kind: dict = field(default_factory=dict)
    flagged: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    conflicts: list = field(default_factory=list)
    files_changed: int = 0
    rebuild: dict = field(default_factory=lambda: {"retired": 0, "created": 0})

    def add(self, kind: str, **values) -> None:
        bucket = self.by_kind.setdefault(kind, {key: 0 for key in COUNT_KEYS})
        for key, value in values.items():
            self.counts[key] += value
            bucket[key] += value

    def details(self) -> dict:
        details = {"by_kind": self.by_kind, "flagged": self.flagged[:MAX_DETAIL_ITEMS],
                   "errors": self.errors[:MAX_DETAIL_ITEMS],
                   "conflicts": self.conflicts[:MAX_DETAIL_ITEMS]}
        if self.rebuild.get("baselined"):
            details["decision_logs_baselined"] = self.rebuild["baselined"]
        if self.rebuild["retired"]:
            details["pentest_rebuild"] = dict(
                self.rebuild, note=f"pentest rebuild: {self.rebuild['retired']} retired (old ID scheme, stored "
                                   f"without a git-source namespace), {self.rebuild['created']} created")
        return details

    def snapshot(self) -> tuple:
        """The tallies so far, to restore when a file's transaction is rolled back."""
        return copy.deepcopy((self.counts, self.by_kind, self.flagged, self.errors, self.conflicts, self.rebuild))

    def restore(self, snapshot: tuple) -> None:
        (self.counts, self.by_kind, self.flagged, self.errors, self.conflicts,
         self.rebuild) = copy.deepcopy(snapshot)


class UnknownCommitError(GitSourceError):
    """The source's last synced commit is not in the repository."""


def _unknown_commit(last_synced_commit: str, repository: str, exc: Exception) -> UnknownCommitError:
    return UnknownCommitError(
        f"The last synced commit {last_synced_commit} is not in {repository} "
        f"({exc}); the history was rewritten, the repository changed, or the cutover commit is "
        "wrong. Run a full re-import to resync every mapped file from the branch head.")


def _end_transaction() -> None:
    """End the session's open (read) transaction before the next provider call."""
    if db.session().in_transaction():
        db.session.commit()


# ----------------------------------------------------------------------------
# Ordering
# ----------------------------------------------------------------------------

def _sort_key(candidate: Candidate):
    from app.services.evidence_import import DATASET_ORDER

    kind = candidate.kind
    if kind.startswith("dataset:"):
        name = kind.split(":", 1)[1]
        rank = DATASET_ORDER.index(name) if name in DATASET_ORDER else len(DATASET_ORDER)
        return (0, rank, candidate.path)
    if kind == "decision_log":
        return (1, 0, candidate.path)
    return (2, 0, candidate.path)


# ----------------------------------------------------------------------------
# Candidate discovery
# ----------------------------------------------------------------------------

def _stored_files(source_id: str) -> dict[str, StoredFile]:
    rows = db.session.query(GitSourceFile.path, GitSourceFile.kind, GitSourceFile.blob_id,
                            GitSourceFile.status).filter(GitSourceFile.source_id == source_id)
    return {row.path: StoredFile(row.path, row.kind, row.blob_id, row.status) for row in rows}


def _candidates_from_changes(changes: list[Change], mappings: list[dict],
                             stored: dict[str, StoredFile] | None = None) -> list[Candidate]:
    """Candidates for the changed mapped paths. A changed chunk part
    (``<name>.part-NNNN``) whose manifest is a stored, mapped file that did
    not change itself makes the manifest a candidate too, so a flagged
    chunked file is read again once one of its parts changes."""
    out = []
    listed = set()
    parts_changed = set()
    for change in changes:
        kind = mapping_rules.classify(change.path, mappings)
        if kind:
            out.append(Candidate(change.path, kind, change.change_type, change.blob_id))
            listed.add(change.path)
            continue
        match = _PART_RE.match(change.path)
        if match:
            parts_changed.add(match.group("name") + MANIFEST_SUFFIX)
    for manifest_path in sorted(parts_changed - listed):
        record = (stored or {}).get(manifest_path)
        kind = mapping_rules.classify(manifest_path, mappings)
        if kind and record is not None and record.status != "deleted":
            out.append(Candidate(manifest_path, kind, "M", None))
    return out


def _candidates_from_tree(provider, head: str, mappings: list[dict],
                          stored: dict[str, StoredFile], full: bool = False) -> list[Candidate]:
    out = []
    seen = set()
    for entry in provider.list_tree(head):
        kind = mapping_rules.classify(entry.path, mappings)
        if not kind:
            continue
        seen.add(entry.path)
        record = stored.get(entry.path)
        if (not full and record is not None and record.blob_id == entry.blob_id
                and record.status in ("ok", "too_large")):
            continue
        out.append(Candidate(entry.path, kind, "M" if record else "A", entry.blob_id, entry.size))
    for path, record in stored.items():
        if path not in seen and record.status != "deleted":
            out.append(Candidate(path, record.kind, "D", None))
    return out


def discover_candidates(source, provider, head: str, mappings: list[dict],
                        full: bool = False) -> tuple[list[Candidate], str]:
    """Return (candidates, strategy) where strategy is ``diff``, ``tree`` or ``full``.

    ``source`` is a ``SourceSnapshot`` (or a ``GitSource``). The stored file
    records are read, and the read transaction ended, before the provider is
    called.
    """
    last_synced, repository, name = source.last_synced_commit, source.repository, source.name
    stored = _stored_files(source.id)
    _end_transaction()
    if full:
        candidates = _candidates_from_tree(provider, head, mappings, stored, full=True)
        candidates.sort(key=_sort_key)
        return candidates, "full"
    candidates: list[Candidate] | None = None
    strategy = "tree"
    if last_synced and last_synced != head:
        try:
            candidates = _candidates_from_changes(provider.diff(last_synced, head), mappings, stored)
            strategy = "diff"
        except NotFoundError as exc:
            raise _unknown_commit(last_synced, repository, exc) from None
        except GitSourceError as exc:
            logger.info("Git source %s: diff from %s unavailable (%s); comparing trees",
                        name, last_synced[:12], exc)
    if candidates is None:
        if last_synced == head:
            candidates = []
            strategy = "diff"
        else:
            candidates = _candidates_from_tree(provider, head, mappings, stored)
    listed = {c.path for c in candidates}
    for path, record in stored.items():
        if record.status in RETRY_STATUSES and path not in listed:
            kind = mapping_rules.classify(path, mappings) or record.kind
            candidates.append(Candidate(path, kind, "R", None))
    candidates.sort(key=_sort_key)
    return candidates, strategy


# ----------------------------------------------------------------------------
# Fetching (provider only; no database transaction open)
# ----------------------------------------------------------------------------

def _read(provider, candidate: Candidate, head: str) -> tuple[bytes, str]:
    """Return (content, blob_id) for a candidate at ``head``."""
    if candidate.blob_id:
        return provider.read_blob(candidate.blob_id, path=candidate.path, commit_id=head), candidate.blob_id
    content = provider.read_file(candidate.path, head)
    return content, _blob_from_tree(provider, candidate.path, head, content)


def _blob_from_tree(provider, path: str, head: str, content: bytes) -> str:
    for entry in provider.list_tree(head):
        if entry.path == path:
            return entry.blob_id
    return hashlib.sha256(content).hexdigest()


def _decision_log_content(provider, path: str, content: bytes, head: str) -> tuple[bytes, str]:
    """Return (transcript bytes, logical transcript path) for a mapped decision-log path.

    Raises ``TranscriptTooLargeError`` for a transcript (or a manifest
    describing one) larger than ``MAX_TRANSCRIPT_BYTES``, before any part
    is read.
    """
    from app.services import chunked_files
    from app.services import evidence_import_decision_logs as decision_logs

    if not chunked_files.is_manifest(path):
        if len(content) > decision_logs.MAX_TRANSCRIPT_BYTES:
            raise decision_logs.TranscriptTooLargeError(len(content))
        return content, path
    manifest = chunked_files.parse_manifest(content)
    logical = chunked_files.logical_path(path)
    if manifest.name != posixpath.basename(logical):
        raise chunked_files.ChunkedFileError(
            f"manifest {path} describes {manifest.name!r}, not {posixpath.basename(logical)!r}")
    if manifest.size > decision_logs.MAX_TRANSCRIPT_BYTES:
        raise decision_logs.TranscriptTooLargeError(manifest.size)
    directory = posixpath.dirname(path)

    def read_part(name: str, max_bytes: int) -> bytes:
        return provider.read_file(posixpath.join(directory, name) if directory else name, head,
                                  max_bytes=max_bytes)

    return chunked_files.reassemble(manifest, read_part), logical


def _sidecar(provider, transcript_path: str, head: str) -> tuple[str | None, str | None]:
    """``(exit_reason, agent)`` from a transcript's ``.meta.json`` sidecar at ``head``."""
    import json

    from app.services.evidence_import_decision_logs import sidecar_fields

    stem = transcript_path[: -len(".jsonl")] if transcript_path.endswith(".jsonl") else transcript_path
    try:
        meta = json.loads(provider.read_file(stem + ".meta.json", head))
    except (NotFoundError, ValueError):
        return None, None
    except GitSourceError:
        return None, None
    return sidecar_fields(meta)


def _transcript_too_large(size: int, limit: int, detail: str) -> dict:
    return {"size": size, "limit": limit, "reason": TRANSCRIPT_LIMIT_REASON, "detail": detail}


def fetch_candidate(provider, candidate: Candidate, head: str) -> FetchedFile:
    """Read everything a candidate needs from the provider (no database access).

    Raises ``GitSourceError`` (or another error) when the file cannot be
    read; an oversized file is returned flagged (``too_large``).
    """
    from app.services import chunked_files
    from app.services import evidence_import_decision_logs as decision_logs

    if candidate.change_type == "D":
        return FetchedFile()
    is_log = candidate.kind == "decision_log"
    if (is_log and candidate.size is not None and candidate.size > decision_logs.MAX_TRANSCRIPT_BYTES
            and not chunked_files.is_manifest(candidate.path)):
        error = decision_logs.TranscriptTooLargeError(candidate.size)
        return FetchedFile(blob_id=candidate.blob_id, size=candidate.size,
                           too_large=_transcript_too_large(candidate.size, error.limit, str(error)))
    try:
        content, blob_id = _read(provider, candidate, head)
    except FileTooLargeError as exc:
        return FetchedFile(blob_id=candidate.blob_id, size=exc.size,
                           too_large={"size": exc.size, "limit": exc.limit,
                                      "reason": PROVIDER_LIMIT_REASON, "detail": str(exc)})
    fetched = FetchedFile(content=content, blob_id=blob_id, size=len(content))
    if is_log:
        try:
            fetched.transcript, fetched.transcript_path = _decision_log_content(
                provider, candidate.path, content, head)
        except decision_logs.TranscriptTooLargeError as exc:
            return FetchedFile(blob_id=blob_id, size=exc.size,
                               too_large=_transcript_too_large(exc.size, exc.limit, str(exc)))
        except chunked_files.ChunkedPartTooLargeError as exc:
            return FetchedFile(blob_id=blob_id, size=exc.read,
                               too_large={"size": exc.read, "limit": exc.declared,
                                          "reason": CHUNK_PART_LIMIT_REASON, "detail": str(exc)})
        fetched.exit_reason, fetched.agent = _sidecar(provider, fetched.transcript_path, head)
    return fetched


# ----------------------------------------------------------------------------
# Writing (one database transaction per file)
# ----------------------------------------------------------------------------

def _file_record(source, candidate: Candidate) -> GitSourceFile:
    record = GitSourceFile.query.filter_by(source_id=source.id, path=candidate.path).first()
    if record is None:
        record = GitSourceFile(id=str(uuid.uuid4()), source_id=source.id, path=candidate.path,
                               kind=candidate.kind, status="ok")
        db.session.add(record)
    elif record.kind != candidate.kind:
        record.kind = candidate.kind
    return record


def _store_content_version(record: GitSourceFile, content: bytes, blob_id: str, head: str) -> str:
    """Store governance content; returns created | unchanged."""
    text_content = content.decode("utf-8")
    existing = GitFileVersion.query.filter_by(file_id=record.id, blob_id=blob_id).first()
    if existing is not None:
        if record.current_version_id != existing.id:
            record.current_version_id = existing.id
        return "unchanged"
    version = GitFileVersion(
        id=str(uuid.uuid4()),
        file_id=record.id,
        commit_id=head,
        blob_id=blob_id,
        sha256=hashlib.sha256(content).hexdigest(),
        size=len(content),
        content=text_content,
    )
    record.current_version_id = version.id
    db.session.add(version)
    db.session.flush()
    return "created"


def process_candidate(source, fetched: FetchedFile, candidate: Candidate, head: str,
                      tally: SyncTally, member_id: str | None) -> None:
    """Write one fetched candidate (database only; the caller commits)."""
    from app.services import evidence_import
    from app.services.transcript_ingest import TranscriptLimitError

    kind = candidate.kind
    log_result = None
    if kind == "decision_log" and fetched.transcript is not None and fetched.too_large is None:
        # The transcript is stored before this file's record: its session lock comes before
        # any other write of the transaction, and its entries are written before any audited
        # row, so the audit chain's lock is held only for the audited rows that follow.
        session_id = evidence_import.session_id_from_path(fetched.transcript_path)
        if session_id:
            evidence_import.lock_session(session_id)
        try:
            log_result = evidence_import.import_decision_log(
                fetched.transcript,
                source_path=fetched.transcript_path,
                exit_reason=fetched.exit_reason,
                agent_type=fetched.agent,
                submitted_by=member_id,
                authority=evidence_import.AUTHORITY_SYSTEM,
                source_commit=head,
            )
        except TranscriptLimitError as exc:
            size = len(fetched.transcript)
            fetched = FetchedFile(blob_id=fetched.blob_id, size=size, too_large={
                "size": size, "limit": exc.limit, "reason": TRANSCRIPT_CONTENT_LIMIT_REASON,
                "detail": str(exc)})
    record = _file_record(source, candidate)

    if candidate.change_type == "D":
        if kind.startswith("dataset:"):
            counts = evidence_import.remove_dataset_file(kind.split(":", 1)[1], candidate.path,
                                                         namespace=source.id)
            tally.add(kind, deleted=counts.deleted, skipped=counts.skipped)
        elif kind in mapping_rules.CONTENT_KINDS:
            tally.add(kind, deleted=1)  # the stored versions stay; the file is marked deleted
        else:
            tally.add(kind, skipped=1)
        record.status = "deleted"
        record.status_detail = None
        record.blob_id = None
        record.last_commit_id = head
        return

    if fetched.too_large is not None:
        flag = fetched.too_large
        record.status = "too_large"
        record.status_detail = flag["detail"][:1000]
        record.blob_id = fetched.blob_id
        record.size = flag["size"]
        record.last_commit_id = head
        tally.add(kind, flagged=1)
        tally.flagged.append({"path": candidate.path, "size": flag["size"], "limit": flag["limit"],
                              "reason": flag["reason"]})
        return

    # Record the file's final state before importing a dataset or content file
    # (a decision log was stored above), so a new file row is written once
    # (INSERT) rather than inserted and then updated. A failing import rolls
    # the whole file back.
    content = fetched.content
    record.status = "ok"
    record.status_detail = None
    record.blob_id = fetched.blob_id
    record.size = len(content)
    record.last_commit_id = head

    if kind in mapping_rules.CONTENT_KINDS:
        try:
            outcome = _store_content_version(record, content, fetched.blob_id, head)
        except UnicodeDecodeError:
            raise GitSourceError(f"{candidate.path} is not UTF-8 text") from None
        tally.add(kind, **{outcome: 1})
    elif kind.startswith("dataset:"):
        counts = evidence_import.import_dataset_file(kind.split(":", 1)[1], candidate.path, content,
                                                     namespace=source.id)
        tally.add(kind, created=counts.created, updated=counts.updated, unchanged=counts.unchanged,
                  deleted=counts.deleted, skipped=counts.skipped)
        if counts.retired:
            tally.rebuild["retired"] += counts.retired
            tally.rebuild["created"] += counts.created
        for message in counts.errors[:20]:
            tally.errors.append({"path": candidate.path, "error": message})
        if counts.errors:
            # Some records were skipped (e.g. a reference to a record another file has not
            # provided yet). The file is retried on every sync until it imports completely,
            # so it catches up once the file it depends on is fixed.
            record.status = "incomplete"
            record.status_detail = f"{len(counts.errors)} record(s) skipped: {counts.errors[0]}"[:1000]
            tally.add(kind, incomplete=1)
    elif kind == "decision_log" and log_result is not None:
        result = log_result
        if result.status == "rejected":
            # The rejected version is recorded (decision_log_transcripts) with this file's
            # transaction; the stored transcript is unchanged.
            message = f"transcript rejected: {result.reason}"
            record.status = "error"
            record.status_detail = message[:1000]
            tally.add(kind, errors=1)
            tally.errors.append({"path": candidate.path, "error": message[:500]})
            return
        if result.conflict:
            tally.conflicts.append({"path": candidate.path, "session_id": result.session_id})
        if result.baselined:
            tally.rebuild["baselined"] = tally.rebuild.get("baselined", 0) + 1
        outcome = {"created": "created", "replaced": "updated"}.get(result.status, "unchanged")
        tally.add(kind, **{outcome: 1})
    else:
        tally.add(kind, skipped=1)


# ----------------------------------------------------------------------------
# Change records
# ----------------------------------------------------------------------------

def record_commits(source, provider, head: str, mappings: list[dict], limit: int,
                   *, full: bool = False) -> CommitHistory:
    """Record the commits since the last synced commit that touched mapped paths.

    The commits already recorded are read first; the history and the changed
    paths of each new commit are then read from the provider with no
    transaction open, and the new rows are written in one transaction. A last
    synced commit the provider does not know raises ``UnknownCommitError``,
    except on a full re-import, which records the history reachable from
    ``head`` instead.
    """
    if not provider.supports_history:
        return CommitHistory()
    source_id, name = source.id, source.name
    last_synced, repository = source.last_synced_commit, source.repository
    known = {c for (c,) in db.session.query(GitCommit.commit_id).filter_by(source_id=source_id).all()}
    _end_transaction()
    try:
        commits = provider.commits_between(last_synced, head, limit)
    except NotFoundError as exc:
        if not last_synced:
            raise
        if not full:
            raise _unknown_commit(last_synced, repository, exc) from None
        logger.warning("Git source %s: last synced commit %s is unknown; recording history from %s",
                       name, last_synced[:12], head[:12])
        commits = provider.commits_between(None, head, limit)
    rows = []
    for commit in commits:
        if commit.commit_id in known:
            continue
        paths = [p for p in provider.commit_changed_paths(commit) if mapping_rules.classify(p, mappings)]
        if not paths:
            continue
        rows.append(GitCommit(
            id=str(uuid.uuid4()),
            source_id=source_id,
            commit_id=commit.commit_id,
            parent_ids=list(commit.parent_ids),
            author_name=commit.author_name,
            author_email=commit.author_email,
            authored_at=commit.authored_at,
            committer_name=commit.committer_name,
            committer_email=commit.committer_email,
            committed_at=commit.committed_at,
            message=commit.message,
            paths=paths,
        ))
    db.session.add_all(rows)
    db.session.commit()
    return CommitHistory(recorded=len(rows), truncated=len(commits) >= limit)


# ----------------------------------------------------------------------------
# Run
# ----------------------------------------------------------------------------

def _set_audit_actor(member_id: str | None) -> None:
    """Attribute this sync's audited writes to the member who queued it."""
    from flask import g

    if member_id:
        from app.models import TeamMember
        g.current_team_member = db.session.get(TeamMember, member_id)


def _attribute_writes() -> None:
    """Name the audit actor for Core statements, which bypass the before_flush hook."""
    if db.session.get_bind().dialect.name != "postgresql":
        return
    from flask import g

    member = getattr(g, "current_team_member", None)
    if member is not None:
        db.session.connection().execute(
            text("SET LOCAL app.current_team_member = :member_id"), {"member_id": member.id})


def execute_sync_run(run_id: str) -> GitSyncRun:
    """Execute a claimed (``running``) sync run and record its outcome.

    The outcome is written compare-and-set: only while the run is still
    ``running`` under the executor token it was claimed with, and the
    source's last synced commit moves only when that write applies and the
    commit still holds the value the run started from. A lost run lock
    (``LockLostError``) propagates to the scheduler, which records nothing
    further.
    """
    run = db.session.get(GitSyncRun, run_id)
    source = SourceSnapshot.of(run.source)
    token = run.executor_token
    member_id = run.triggered_by_team_member_id
    full = bool(((run.details or {}).get("requested") or {}).get("full"))
    tally = SyncTally()
    _set_audit_actor(member_id)

    try:
        _end_transaction()
        provider = build_provider_for(source)
        head = provider.resolve_head()
        started = db.session.get(GitSyncRun, run_id)
        started.from_commit = source.last_synced_commit
        started.to_commit = head
        db.session.commit()

        mappings = mapping_rules.effective_mappings(source)
        candidates, strategy = discover_candidates(source, provider, head, mappings, full=full)
        tally.files_changed = len(candidates)

        for candidate in candidates:
            _process_file(source, provider, candidate, head, tally, member_id)

        options = effective_options(source)
        history = CommitHistory()
        if options.get("record_commits") and head != source.last_synced_commit:
            history = record_commits(source, provider, head, mappings, int(options["history_limit"]),
                                     full=full)

        if tally.counts["errors"] or tally.counts["flagged"] or tally.counts["incomplete"]:
            status = "partial"
        elif not candidates and source.last_synced_commit == head:
            status = "unchanged"
        else:
            status = "success"
        details = tally.details()
        details.update({"strategy": strategy, "commits_recorded": history.recorded,
                        "history_truncated": history.truncated, "requested": {"full": full}})
        _finish(run_id, token, source, status, tally, details, head=head)
    except LockLostError:
        raise
    except Exception as exc:  # noqa: BLE001 - record the failure on the run
        logger.exception("Git source %s sync failed", source.name)
        db.session.rollback()
        _finish(run_id, token, source, "failure", tally, tally.details(), error=str(exc)[:2000])
    return db.session.get(GitSyncRun, run_id)


def _process_file(source, provider, candidate: Candidate, head: str, tally: SyncTally,
                  member_id: str | None) -> None:
    """Fetch one file (no transaction open), then write it in its own
    transaction, written again once after a deadlock.

    A decision log is fetched and written while holding one of the process's
    transcript import slots (``evidence_import_decision_logs.import_slot``),
    waiting for one to be free first. A failure to fetch or write records
    the file as a file error (the write rolled back with its tallies); the
    sync continues with the next file.
    """
    if candidate.kind == "decision_log" and candidate.change_type != "D":
        from app.services.evidence_import_decision_logs import import_slot

        _end_transaction()
        with import_slot():
            _fetch_and_write(source, provider, candidate, head, tally, member_id)
        return
    _fetch_and_write(source, provider, candidate, head, tally, member_id)


def _fetch_and_write(source, provider, candidate: Candidate, head: str, tally: SyncTally,
                     member_id: str | None) -> None:
    from app.services.evidence_import import is_deadlock

    _end_transaction()
    try:
        fetched = fetch_candidate(provider, candidate, head)
    except GitSourceError as exc:
        _record_file_error(source, candidate, head, str(exc), tally)
        return
    except Exception as exc:  # noqa: BLE001 - one bad file must not stop the sync
        logger.exception("Git source %s: failed to read %s", source.name, candidate.path)
        _record_file_error(source, candidate, head, f"{type(exc).__name__}: {exc}", tally)
        return

    for attempt in (1, 2):
        before = tally.snapshot()
        try:
            process_candidate(source, fetched, candidate, head, tally, member_id)
            db.session.commit()
            return
        except LockLostError:
            db.session.rollback()
            raise
        except GitSourceError as exc:
            db.session.rollback()
            tally.restore(before)
            _record_file_error(source, candidate, head, str(exc), tally)
            return
        except Exception as exc:  # noqa: BLE001 - one bad file must not stop the sync
            db.session.rollback()
            tally.restore(before)
            if attempt == 1 and is_deadlock(exc):
                logger.warning("Git source %s: deadlock while processing %s; retrying once",
                               source.name, candidate.path)
                continue
            logger.exception("Git source %s: failed to process %s", source.name, candidate.path)
            _record_file_error(source, candidate, head, f"{type(exc).__name__}: {exc}", tally)
            return


def _record_file_error(source, candidate: Candidate, head: str, message: str,
                       tally: SyncTally) -> None:
    record = _file_record(source, candidate)
    record.status = "error"
    record.status_detail = message[:1000]
    record.last_commit_id = head
    db.session.commit()
    tally.add(candidate.kind, errors=1)
    tally.errors.append({"path": candidate.path, "error": message[:500]})


def _finish(run_id: str, token: str | None, source, status: str, tally: SyncTally,
            details: dict, head: str | None = None, error: str | None = None) -> bool:
    """Record the run's outcome compare-and-set; True when it applied.

    The run row is updated only while it is ``running`` under ``token`` (the
    executor token it was claimed with); the source's sync status and last
    synced commit are written only when that update applied, and the last
    synced commit (with ``last_synced_at``) only while it still equals
    ``source.last_synced_commit``, the value the run started from.
    """
    finished = _now()
    started_from = source.last_synced_commit
    _attribute_writes()
    owned = GitSyncRun.executor_token.is_(None) if token is None else GitSyncRun.executor_token == token
    applied = db.session.execute(
        update(GitSyncRun)
        .where(GitSyncRun.id == run_id, GitSyncRun.status == "running", owned)
        .values(status=status, finished_at=finished, files_changed=tally.files_changed,
                counts=dict(tally.counts), details=details, error_message=error)
        .execution_options(synchronize_session=False)
    ).rowcount == 1
    if applied:
        values = {"last_sync_status": status}
        if head is not None:
            unchanged = (GitSource.last_synced_commit.is_(None) if started_from is None
                         else GitSource.last_synced_commit == started_from)
            values["last_synced_commit"] = case((unchanged, head), else_=GitSource.last_synced_commit)
            values["last_synced_at"] = case((unchanged, finished), else_=GitSource.last_synced_at)
        db.session.execute(update(GitSource).where(GitSource.id == source.id).values(**values)
                           .execution_options(synchronize_session=False))
        if head is not None:
            current = db.session.scalar(select(GitSource.last_synced_commit)
                                        .where(GitSource.id == source.id))
            if current != head:
                logger.warning("Git source %s: last synced commit changed during run %s; it stays %s",
                               source.name, run_id, current)
    else:
        logger.warning("Git source %s: run %s is no longer running under this executor; "
                       "its outcome (%s) is not recorded", source.name, run_id, status)
    db.session.commit()
    db.session.expire_all()
    return applied
