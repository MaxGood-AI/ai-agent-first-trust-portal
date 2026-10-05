"""Evidence-store sync: record and import every object version the portal has
not recorded yet, writing only real differences.

One sync (``execute_sync_run``, run by the scheduler under the run's target
lock):

0. Reads the bucket's default Object Lock retention and records its mode and
   period (in days, a year counting 365) on the run (``retention_mode``,
   ``retention_days``; audited, written once), before any version is
   recorded. The bucket's first sync also sets its retention floor
   (``evidence_store_retention_floors``, audited) to that period: the lowest
   default retention verification accepts, changed afterwards only by
   ``python -m cli evidence-store set-retention-floor``.
1. For each store prefix (``PREFIXES``), lists the prefix's object versions a
   page at a time, grouped by key (``store.iter_groups``). A key's first
   write is its version listed last; every later version of the key and
   every delete marker is an ANOMALY: listed in the run's
   ``details.anomalies`` (at most 200, with ``counts.anomalies`` counting
   all), never recorded or imported, and a failure of ``audit-verify
   --evidence-store``. A key holding a control character is recorded
   percent-encoded (``keys.stored_key``, ``key_escaped`` set; always
   ``unmapped``). A listing that fails is an error of the run (its class and
   code), and the sync goes on with the next prefix.
2. Per batch of :data:`BATCH_GROUPS` keys, finds the versions already
   recorded with one query, ends that read transaction, and processes each
   version not recorded yet - and each recorded version a sync reads again
   (:func:`retried`: ``error``, one not read or written yet, and ``rejected``
   after :data:`MAX_ATTEMPTS` failed syncs) - one at a time:

   a. classify its key (``keys.classify``);
   b. ``HeadObject`` (with its checksum): size, ETag, last-modified time,
      content type, metadata (sanitized), Object Lock mode and retain-until
      date, and the stored SHA-256 checksum (``store.stored_checksum``): a
      full-object one, or a COMPOSITE one (a multipart upload with SHA-256
      part checksums), whose string is recorded (``composite_checksum``). A
      version without a SHA-256 checksum (or with a malformed one) is
      ``non_conforming``: within its kind's size limit it is read and the
      SHA-256 of its body recorded, and it is never imported;
   c. an ``unmapped`` version is recorded (``recorded``) and not read; a
      version larger than its kind's limit (:func:`kind_limit`: decision
      logs 32 MiB, sidecars 64 KiB, pentest evidence 16 MiB, evidence
      documents 256 MiB; from the listed and stored size, before any byte is
      read) is recorded ``too_large``;
   d. read the version (streamed and bounded; an evidence document is only
      hashed), compute its SHA-256 and require its size to equal the stored
      size and, for a full-object checksum, its SHA-256 to equal the stored
      checksum (``non_conforming`` otherwise); the record's SHA-256 is the
      body's (for a composite checksum, the full-object SHA-256 S3 does not
      store); a pentest file is parsed
      within :data:`STORE_JSON_DEPTH` levels and its kind's value count
      (:func:`parse_json`);
   e. run the kind's PURE, TOTAL content check (``plans.check_pentest``,
      ``plans.check_decision_log``; no database access): content it refuses
      is recorded ``rejected`` (``too_large`` over a decision-log limit),
      once, and never imported;
   f. write it in its own database transaction (retried once after a
      deadlock): the kind's plan against the database (``plans``), its
      import, then its ``evidence_store_objects`` row (naming the run that
      recorded it) - decision logs through the decision-log import with the
      ``store`` authority (``store_object_id`` on every version it writes;
      agent and exit reason from the ``agent`` / ``exit-reason`` metadata,
      else the FIRST version of the ``.meta.json`` sidecar object, whose
      version id - and whether it was read - is recorded in the transcript
      record's ``import_info``, else the detected format; read while holding
      a transcript import slot), pentest evidence as below, evidence
      documents as an ``evidence_documents`` row (the bytes stay in the
      store).

   No database transaction is open while S3 answers.
3. Re-evaluates the ``duplicate`` pentest records whose counterpart no
   longer holds the file's findings - recomputed from the counterpart's
   content, so a deleted, edited or re-keyed finding counts
   (:func:`stale_duplicates`) - and imports them now.
4. Records the outcome compare-and-set (only while the run is ``running``
   under its executor token): ``unchanged`` (no new version, no anomaly),
   ``success``, ``partial`` (an anomaly, an error - a prefix's listing
   included -, or a version recorded as ``rejected``, ``non_conforming`` or
   ``too_large``) or ``failure`` (no prefix could be listed, or the sync
   itself failed).

Decision logs
-------------
The store's authority (``evidence_import_decision_logs``) creates a session
or extends its stored entries as an exact prefix extension, and nothing
else. An identical export, or one whose entries are a prefix of the stored
ones, is ``unchanged`` (its record's ``import_info.decision_log`` names the
outcome, the export's entry count and the session's current version it
matched). An export identical to a restored session that has no current
version is that session's BASELINE: recorded ``ingested`` (outcome
``baselined``), its copy the session's current version, linked to its
object. An export that differs from the stored entries is a CONFLICT: it
is not imported, its record is ``rejected`` with a detail starting
``conflict:``, the transcript is kept as a ``rejected`` version for review
and the run lists it in ``details.conflicts``; verification counts such
records as ``store_conflicts`` (informational, never a failure).

Pentest evidence
----------------
The store imports a pentest file only into its own namespace
(``evidence_import.STORE_NAMESPACE``), only by inserting rows whose ids
derive from the object's version id (``plans``), and never changes another
namespace's findings, nor its own once stored (``plans.plan_pentest``). A
set of findings is identified by its content (each finding's canonical
SHA-256 and ordinal); what a namespace holds is recomputed from its
findings' content. When another namespace (a git source, or ``cli
import``) holds exactly the file's findings for the same
``layer<N>/<name>.json`` (and the file has findings), the version is
recorded ``duplicate`` (its detail names the holder; ``import_info`` holds
the holder, the count and the identity) and nothing is imported. Otherwise
its findings are inserted into the store's namespace (``ingested``;
``import_info`` holds their count, identity and ``stored``); when another
namespace holds different findings for that path, both are kept and the
run lists a conflict. A file without findings to store, or whose findings
the store's namespace already holds exactly (another store object of the
same path), is ``unchanged``; one whose findings it holds differently, or
whose finding ids a stored row already holds, is ``rejected``
(``conflict:``). Store-namespace findings are immutable: the API answers
409 and migration 021's guard freezes them.

Failures
--------
Only the pure content check and the plan's conflicts refuse a version:
recorded ``rejected`` (``too_large`` over a decision-log limit) with a
detail naming the reason, and re-derived identically by verification from
the body. Any failure after a passing check - an S3 or network error, a
deadlock twice, any database error, a data error included - records the
version as ``error`` with one more ``attempts`` and leaves it for the next
sync: every sync reads it again until it imports, and verification
reports it ``pending`` (unverified, never broken). A version that cannot be
imported for good is settled by an administrator (``python -m cli
evidence-store acknowledge``, once it has failed :data:`MAX_ATTEMPTS`
syncs). Every record carries the S3-stored full-object SHA-256 when the
version has one, and the S3-stored composite checksum when it has that
(with the body's SHA-256 once the body is read). Run details and ``error_message`` name errors by class and code only,
never by their message.

Statuses of a recorded version: ``ingested`` (imported: a decision-log
version stored, pentest findings written, a document created),
``unchanged`` (read and verified; its content was already held, or a pentest
file without findings), ``recorded`` (a sidecar, read and verified, or an
unmapped key, not read), ``duplicate``, ``rejected``, ``non_conforming``,
``too_large``, ``error`` and, by an administrator, ``acknowledged`` and
``erased``. A re-sync of an unchanged bucket writes nothing but its run row.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import text, update

from app.models import db
from app.models.evidence_store import (EvidenceDocument, EvidenceStoreObject, EvidenceStoreRetentionFloor,
                                       EvidenceStoreSyncRun)
from app.services.evidence_store import PREFIXES, keys, store
from app.services.evidence_store.plans import (CONFLICT, Conflict, ContentRejected, PentestPlan,  # noqa: F401
                                               TooLarge, check_decision_log, check_pentest, insert_store_findings,
                                               plan_pentest, store_holder)
from app.services.scheduler import LockLostError

logger = logging.getLogger(__name__)

MiB = 1024 * 1024
SIDECAR_LIMIT = 64 * 1024
PENTEST_LIMIT = 16 * MiB
DOCUMENT_LIMIT = 256 * MiB
BATCH_GROUPS = 1000
MAX_DETAIL_ITEMS = 200
MAX_DETAIL_TEXT = 1000
MAX_ATTEMPTS = 3
REEVALUATE_LIMIT = 100
STORE_JSON_DEPTH = 64
PENTEST_MAX_VALUES = 2_000_000
SIDECAR_MAX_VALUES = 1_000

INGESTED = "ingested"
UNCHANGED = "unchanged"
RECORDED = "recorded"
DUPLICATE = "duplicate"
REJECTED = "rejected"
NON_CONFORMING = "non_conforming"
TOO_LARGE = "too_large"
ERROR = "error"
ERASED = "erased"
COUNT_KEYS = ("listed", "new", INGESTED, UNCHANGED, RECORDED, DUPLICATE, REJECTED, NON_CONFORMING, TOO_LARGE,
              "errors", "anomalies", "reevaluated")
SECOND_VERSION = "a second version of the key (keys are write-once)"
DELETE_MARKER = "a delete marker"
BODY_MISMATCH = "the body's SHA-256 differs from its stored checksum"
STORE_OBJECT_FOREIGN_KEY = "fk_decision_log_transcripts_store_object"


def parse_json(content: bytes, *, max_values: int):
    """``content`` (UTF-8 JSON) parsed within :data:`STORE_JSON_DEPTH` levels and
    ``max_values`` arrays, objects and elements; :class:`ContentRejected` for
    anything else (invalid UTF-8 or JSON, too deep, too many values)."""
    import json

    from werkzeug.exceptions import HTTPException

    from app.request_limits import check_json_limits

    try:
        decoded = content.decode("utf-8-sig")
        check_json_limits(decoded, max_depth=STORE_JSON_DEPTH, max_values=max_values)
        return json.loads(decoded)
    except HTTPException as exc:
        raise ContentRejected(exc.description) from None
    except UnicodeDecodeError:
        raise ContentRejected("not UTF-8 text") from None
    except RecursionError:
        raise ContentRejected(f"nested deeper than {STORE_JSON_DEPTH} levels") from None
    except ValueError as exc:
        raise ContentRejected(f"invalid JSON ({getattr(exc, 'msg', 'unparseable')})") from None


def _limits() -> dict:
    from app.services.evidence_import_decision_logs import MAX_TRANSCRIPT_BYTES

    return {keys.KIND_DECISION_LOG: MAX_TRANSCRIPT_BYTES, keys.KIND_SIDECAR: SIDECAR_LIMIT,
            keys.KIND_PENTEST: PENTEST_LIMIT, keys.KIND_DOCUMENT: DOCUMENT_LIMIT}


def kind_limit(kind: str) -> int | None:
    """The size limit of a kind's versions (None: an unmapped version is never read)."""
    return _limits().get(kind)


def _now():
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Recorded:
    """What the portal recorded of a version: its record id, status and attempts."""

    id: str
    status: str
    attempts: int = 0


@dataclass
class Tally:
    counts: dict = field(default_factory=lambda: {key: 0 for key in COUNT_KEYS})
    by_kind: dict = field(default_factory=dict)
    anomalies: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    conflicts: list = field(default_factory=list)

    def add(self, kind: str, status: str) -> None:
        self.counts[status] += 1
        bucket = self.by_kind.setdefault(kind, {})
        bucket[status] = bucket.get(status, 0) + 1

    def anomaly(self, key: str, version_id: str | None, issue: str, count: int = 1) -> None:
        self.counts["anomalies"] += count
        if len(self.anomalies) < MAX_DETAIL_ITEMS:
            self.anomalies.append({"key": keys.display(key), "version_id": version_id, "issue": issue})

    def error(self, key: str, version_id: str | None, message: str) -> None:
        self.counts["errors"] += 1
        if len(self.errors) < MAX_DETAIL_ITEMS:
            self.errors.append({"key": keys.display(key), "version_id": version_id, "error": message[:500]})

    def details(self) -> dict:
        return {"by_kind": self.by_kind, "anomalies": self.anomalies, "errors": self.errors,
                "conflicts": self.conflicts[:MAX_DETAIL_ITEMS]}

    def status(self) -> str:
        counts = self.counts
        if counts["errors"] or counts["anomalies"] or counts[REJECTED] or counts[NON_CONFORMING] \
                or counts[TOO_LARGE]:
            return "partial"
        return "success" if counts["new"] or counts["reevaluated"] else "unchanged"


@dataclass
class Fetched:
    """A version, read from the store before its transaction.

    ``status`` is set when the outcome is decided before any import
    (``non_conforming``, ``too_large``, ``recorded``, ``rejected``);
    ``content`` holds a decision log's bytes, ``parsed`` a pentest file's
    JSON and ``checked`` what the kind's content check returned
    (``plans.CheckedPentest`` / ``plans.CheckedDecisionLog``). ``record_id`` /
    ``attempts`` name the version's ``error`` record when it has one,
    ``run_id`` the run recording it.
    """

    key: str
    version_id: str
    kind: str
    document_kind: str | None = None
    session_id: str | None = None
    size: int = 0
    etag: str | None = None
    last_modified: object = None
    content_type: str | None = None
    metadata: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    lock_mode: str | None = None
    retain_until: object = None
    sha256: str | None = None
    composite_checksum: str | None = None
    status: str | None = None
    content: bytes | None = None
    parsed: object = None
    exit_reason: str | None = None
    agent: str | None = None
    import_info: dict | None = None
    checked: object = None
    record_id: str | None = None
    attempts: int = 0
    run_id: str | None = None
    reevaluation: bool = False


def new_fetched(version: store.ListedVersion, recorded: Recorded | None = None, run_id: str | None = None) -> Fetched:
    classified = keys.classify(version.key)
    fetched = Fetched(key=version.key, version_id=version.version_id, kind=classified.kind,
                      document_kind=classified.document_kind, session_id=classified.session_id,
                      size=version.size, last_modified=version.last_modified, run_id=run_id,
                      record_id=recorded.id if recorded else None, attempts=recorded.attempts if recorded else 0)
    if classified.detail:
        fetched.notes.append(classified.detail)
    return fetched


def _end_transaction() -> None:
    """End the session's open (read) transaction before the next S3 call."""
    if db.session().in_transaction():
        db.session.commit()


def _is_postgres() -> bool:
    return db.session.get_bind().dialect.name == "postgresql"


def _set_audit_actor(member_id: str | None) -> None:
    """Attribute this sync's audited writes to the member who queued it."""
    from flask import g

    if member_id:
        from app.models import TeamMember

        g.current_team_member = db.session.get(TeamMember, member_id)


def _attribute_writes() -> None:
    """Name the audit actor for Core statements, which bypass the before_flush hook."""
    if not _is_postgres():
        return
    from flask import g

    member = getattr(g, "current_team_member", None)
    if member is not None:
        db.session.connection().execute(
            text("SET LOCAL app.current_team_member = :member_id"), {"member_id": member.id})


def _refusal(exc) -> str:
    return keys.display(str(exc), 300)


def _etag(value) -> str | None:
    return value if isinstance(value, str) and keys.sanitize_content_type(value) else None


def _batches(groups, size: int):
    batch = []
    for group in groups:
        batch.append(group)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


# ----------------------------------------------------------------------------
# Reading (S3 only; no database transaction open)
# ----------------------------------------------------------------------------

def read_sidecar(client, bucket: str, key: str, version_id: str) -> tuple[str | None, str | None]:
    """``(exit_reason, agent)`` of one version of a ``.meta.json`` sidecar, read
    within :data:`SIDECAR_LIMIT` and parsed as the store parses JSON; raises when
    it cannot be read or parsed."""
    from app.services.evidence_import_decision_logs import sidecar_fields

    content = store.read_version(client, bucket, key, version_id, SIDECAR_LIMIT)
    return sidecar_fields(parse_json(content, max_values=SIDECAR_MAX_VALUES))


def _sidecar_fields(client, bucket: str, key: str) -> tuple[str | None, str | None, dict | None]:
    """``(exit_reason, agent, {"key", "version_id", "read"})`` from the FIRST version
    of a transcript's ``.meta.json`` sidecar (``read``: its fields were read). A
    sidecar that is missing, too large or unreadable for any reason supplies
    nothing."""
    sidecar, info = keys.sidecar_key(key), None
    try:
        first = store.first_version(client, bucket, sidecar)
        if first is None:
            return None, None, None
        info = {"key": sidecar, "version_id": first.version_id, "read": False}
        if first.size > SIDECAR_LIMIT:
            return None, None, info
        exit_reason, agent = read_sidecar(client, bucket, sidecar, first.version_id)
        info["read"] = True
        return exit_reason, agent, info
    except Exception as exc:  # noqa: BLE001 - an unreadable sidecar supplies nothing
        logger.info("Evidence store: sidecar of %s unreadable (%s)", keys.display(key), store.describe(exc))
        return None, None, info


def _hash_non_conforming(client, bucket: str, fetched: Fetched, limit: int | None) -> None:
    """Record the SHA-256 of a non-conforming version's body when it is within its kind's limit."""
    if limit is None or fetched.size > limit:
        return
    try:
        fetched.sha256, _ = store.hash_version(client, bucket, fetched.key, fetched.version_id, limit)
        fetched.notes.append("SHA-256 computed from the body")
    except store.BodyTooLarge as exc:
        fetched.notes.append(f"the body is larger than the {fetched.kind} limit of {exc.limit} bytes")


def fetch_version(client, bucket: str, version: store.ListedVersion, fetched: Fetched | None = None) -> Fetched:
    """Read what a version needs from the store (no database access) into ``fetched``.

    Raises the S3 error when the version cannot be read; ``fetched`` then
    holds what was read before it.
    """
    from botocore.exceptions import FlexibleChecksumError

    fetched = fetched or new_fetched(version)
    head = store.head_version(client, bucket, version.key, version.version_id)
    fetched.size = int(head.get("ContentLength", version.size) or 0)
    fetched.etag = _etag(head.get("ETag"))
    fetched.last_modified = head.get("LastModified") or version.last_modified
    fetched.content_type = keys.sanitize_content_type(head.get("ContentType"))
    fetched.metadata, notes = keys.sanitize_metadata(head.get("Metadata"), fetched.session_id)
    fetched.notes += notes
    fetched.lock_mode = head.get("ObjectLockMode")
    fetched.retain_until = head.get("ObjectLockRetainUntilDate")
    checksum = store.stored_checksum(head)
    fetched.sha256, fetched.composite_checksum = checksum.sha256, checksum.composite
    limit = kind_limit(fetched.kind)
    if checksum.problem:
        fetched.status = NON_CONFORMING
        fetched.notes.append(checksum.problem)
        _hash_non_conforming(client, bucket, fetched, limit)
        return fetched
    if fetched.kind == keys.KIND_UNMAPPED:
        fetched.status = RECORDED
        return fetched
    if max(fetched.size, version.size) > limit:
        fetched.status = TOO_LARGE
        fetched.notes.append(f"{max(fetched.size, version.size)} bytes; the {fetched.kind} limit is "
                             f"{limit} bytes (not read)")
        return fetched
    try:
        if fetched.kind == keys.KIND_DOCUMENT:
            digest, size = store.hash_version(client, bucket, version.key, version.version_id, limit)
        else:
            content = store.read_version(client, bucket, version.key, version.version_id, limit)
            digest, size = hashlib.sha256(content).hexdigest(), len(content)
    except store.BodyTooLarge as exc:
        fetched.status = TOO_LARGE
        fetched.notes.append(f"the body is larger than the {fetched.kind} limit of {exc.limit} bytes")
        return fetched
    except FlexibleChecksumError:
        fetched.status = NON_CONFORMING
        fetched.notes.append(BODY_MISMATCH)
        return fetched
    # A composite checksum is of the parts' checksums: the body is held to its stored size, and its
    # SHA-256 becomes the record's.
    full_object = fetched.composite_checksum is None
    if (full_object and digest != fetched.sha256) or size != fetched.size:
        fetched.status = NON_CONFORMING
        fetched.notes.append(BODY_MISMATCH if full_object and digest != fetched.sha256
                             else f"the body is {size} bytes, not the stored {fetched.size}")
        fetched.sha256 = digest
        return fetched
    fetched.sha256 = digest
    if fetched.kind == keys.KIND_SIDECAR:
        fetched.status = RECORDED
    elif fetched.kind == keys.KIND_PENTEST:
        check_pentest_content(fetched, content)
    elif fetched.kind == keys.KIND_DECISION_LOG:
        fetched.content = content
        fetched.exit_reason = fetched.metadata.get("exit-reason")
        fetched.agent = fetched.metadata.get("agent")
        if fetched.exit_reason is None or fetched.agent is None:
            exit_reason, agent, sidecar = _sidecar_fields(client, bucket, version.key)
            fetched.exit_reason = fetched.exit_reason or exit_reason
            fetched.agent = fetched.agent or agent
            if sidecar is not None:
                fetched.import_info = {"sidecar": sidecar}
        check_decision_log_content(fetched)
    return fetched


def check_pentest_content(fetched: Fetched, content: bytes) -> None:
    """Parse a pentest version and run its content check (``plans.check_pentest``):
    ``fetched.checked``, or ``rejected`` with the reason."""
    try:
        fetched.parsed = parse_json(content, max_values=PENTEST_MAX_VALUES)
        fetched.checked = check_pentest(fetched.key, fetched.parsed, fetched.version_id)
    except ContentRejected as exc:
        fetched.status, fetched.parsed = REJECTED, None
        fetched.notes.append(f"not imported: {exc}")


def check_decision_log_content(fetched: Fetched) -> None:
    """Run a transcript's content check (``plans.check_decision_log``):
    ``fetched.checked``, else ``too_large`` or ``rejected`` with the reason."""
    try:
        fetched.checked = check_decision_log(fetched.content, fetched.key, fetched.exit_reason, fetched.agent)
    except TooLarge as exc:
        fetched.status, fetched.content = TOO_LARGE, None
        fetched.notes.append(f"transcript over a decision-log limit: {_refusal(exc)}")
    except ContentRejected as exc:
        fetched.status, fetched.content = REJECTED, None
        fetched.notes.append(f"not imported: {_refusal(exc)}")


# ----------------------------------------------------------------------------
# Writing (one database transaction per version)
# ----------------------------------------------------------------------------

def _detail(fetched: Fetched, extra: list[str], lead: str | None = None) -> str | None:
    parts = [part for part in [lead] + fetched.notes + extra if part]
    return "; ".join(parts)[:MAX_DETAIL_TEXT] if parts else None


# Columns a record takes from what was read; on an existing record a value
# not read this time keeps the recorded one.
_EVIDENCE = ("sha256", "composite_checksum", "size", "etag", "last_modified", "content_type", "object_metadata",
             "lock_mode", "retain_until", "sync_run_id", "import_info")


def _record(bucket: str, fetched: Fetched, object_id: str, status: str, extra=(), attempts: int | None = None,
            lead: str | None = None):
    values = {"sha256": fetched.sha256, "composite_checksum": fetched.composite_checksum,
              "size": fetched.size, "etag": fetched.etag,
              "last_modified": fetched.last_modified, "content_type": fetched.content_type,
              "object_metadata": fetched.metadata or None, "lock_mode": fetched.lock_mode,
              "retain_until": fetched.retain_until, "sync_run_id": fetched.run_id,
              "import_info": fetched.import_info}
    detail = _detail(fetched, list(extra), lead)
    row = db.session.get(EvidenceStoreObject, fetched.record_id) if fetched.record_id else None
    if row is None:
        key, escaped = keys.stored_key(fetched.key)
        row = EvidenceStoreObject(id=object_id, bucket=bucket, key=key, key_escaped=escaped,
                                  version_id=fetched.version_id, kind=fetched.kind, status=status, detail=detail,
                                  attempts=attempts if attempts is not None else fetched.attempts, **values)
        db.session.add(row)
    else:
        for name in _EVIDENCE:
            if values[name] is not None:
                setattr(row, name, values[name])
        row.status, row.detail = status, detail
        row.attempts = attempts if attempts is not None else fetched.attempts
    db.session.flush()
    return row


def _ingest_decision_log(bucket: str, fetched: Fetched, object_id: str, tally: Tally) -> str:
    """Import a transcript with the store's authority (module docstring, "Decision logs")."""
    from app.models import DecisionLogTranscript
    from app.services import evidence_import_decision_logs as decision_logs

    checked = fetched.checked
    decision_logs.lock_session(checked.session_id)  # before any other write of the transaction
    if _is_postgres():
        db.session.connection().execute(text(f"SET CONSTRAINTS {STORE_OBJECT_FOREIGN_KEY} DEFERRED"))
    result = decision_logs.import_decision_log(
        fetched.content, session_id=checked.session_id, source_path=fetched.key,
        exit_reason=checked.exit_reason, agent_type=checked.agent, submitted_by=None,
        authority=decision_logs.AUTHORITY_STORE, store_object_id=object_id, parsed=checked.parsed)
    status = {"created": INGESTED, "replaced": INGESTED, "rejected": REJECTED}.get(result.status, UNCHANGED)
    if result.baselined:
        status = INGESTED  # its copy became the restored session's current version
    outcome = {"session_id": result.session_id, "outcome": "baselined" if result.baselined else result.status,
               "entries": result.submitted_entries}
    extra, lead = [f"decision log {outcome['outcome']}"], None
    if result.status == "rejected":
        outcome["outcome"] = CONFLICT
        lead = (f"{CONFLICT}: {result.reason}; not imported (the transcript is kept as a rejected version for "
                "administrator review)")
        tally.conflicts.append({"key": keys.display(fetched.key), "session_id": result.session_id,
                                "issue": "the export differs from the stored transcript; not imported"})
    elif status == UNCHANGED:
        current = db.session.query(DecisionLogTranscript.id).filter_by(
            session_id=result.session_id, status="current").first()
        outcome["matched_version"] = current.id if current is not None else None
    sidecar = (fetched.import_info or {}).get("sidecar")
    if sidecar:
        extra.append(f"sidecar read at version {sidecar['version_id']}")
    fetched.import_info = dict(fetched.import_info or {}, decision_log=outcome)
    _attribute_writes()
    _record(bucket, fetched, object_id, status, extra, lead=lead)
    return status


def describe_holder(holder: str) -> str:
    """Who holds the findings stored under ``holder`` (a ``source_file``)."""
    if ":" not in holder:
        return "cli import"
    namespace = holder.split(":", 1)[0]
    from app.models.git_source import GitSource

    source = db.session.get(GitSource, namespace)
    return f"git source {source.name} ({namespace})" if source is not None else f"namespace {namespace}"


def _ingest_pentest(bucket: str, fetched: Fetched, object_id: str, tally: Tally) -> str:
    """Plan (``plans.plan_pentest``; a :class:`Conflict` propagates) and insert a
    checked pentest file's findings into the store's namespace."""
    checked = fetched.checked
    plan = plan_pentest(checked)
    if checked.rows is None:
        _record(bucket, fetched, object_id, UNCHANGED, [plan.note])
        return UNCHANGED
    if plan.outcome == DUPLICATE:
        fetched.import_info = dict(checked.info(), duplicate_of=plan.duplicate_of)
        _record(bucket, fetched, object_id, DUPLICATE, [
            f"duplicate: {describe_holder(plan.duplicate_of)} holds the same {checked.count} finding(s) "
            f"for {checked.source_file}; not imported"])
        return DUPLICATE
    fetched.import_info = checked.info()
    extra = []
    if plan.others:
        names = [describe_holder(holder) for holder in plan.others]
        extra.append(f"conflict: {', '.join(names)} hold(s) different findings for {checked.source_file}; both kept")
        tally.conflicts.append({"key": keys.display(fetched.key), "kind": keys.KIND_PENTEST, "holders": names})
    if plan.outcome == UNCHANGED:
        _record(bucket, fetched, object_id, UNCHANGED, [plan.note] + extra)
        return UNCHANGED
    created = insert_store_findings(checked)
    fetched.import_info["stored"] = True
    _record(bucket, fetched, object_id, INGESTED, [f"findings: {created} created in the store's namespace"] + extra)
    return INGESTED


def _ingest_document(bucket: str, fetched: Fetched, object_id: str) -> str:
    row = _record(bucket, fetched, object_id, INGESTED)
    db.session.add(EvidenceDocument(
        id=str(uuid.uuid4()), store_object_id=row.id, kind=fetched.document_kind,
        title=keys.document_title(fetched.key), key=fetched.key, sha256=fetched.sha256, size=fetched.size,
        content_type=fetched.content_type))
    db.session.flush()
    return INGESTED


def write_version(bucket: str, fetched: Fetched, tally: Tally) -> str:
    """Record (and import) one fetched version in the current transaction; returns its status.

    The caller commits. Raises :class:`Conflict` when its plan conflicts with
    what the database holds (nothing written; see :func:`_write`).
    """
    object_id = fetched.record_id or str(uuid.uuid4())
    if fetched.status is not None:
        _record(bucket, fetched, object_id, fetched.status)
        return fetched.status
    if fetched.kind == keys.KIND_DECISION_LOG:
        return _ingest_decision_log(bucket, fetched, object_id, tally)
    if fetched.kind == keys.KIND_PENTEST:
        return _ingest_pentest(bucket, fetched, object_id, tally)
    if fetched.kind == keys.KIND_DOCUMENT:
        return _ingest_document(bucket, fetched, object_id)
    _record(bucket, fetched, object_id, RECORDED)
    return RECORDED


def _record_failure(bucket: str, fetched: Fetched, cause: str, tally: Tally) -> None:
    """A version that could not be read or written: one more attempt on its
    ``error`` record, read again by every sync (never a refusal of its content)."""
    tally.error(fetched.key, fetched.version_id, cause)
    if fetched.reevaluation:
        return  # a duplicate stays one until a sync imports it
    attempts = fetched.attempts + 1
    fetched.content = fetched.parsed = fetched.checked = None
    try:
        _record(bucket, fetched, fetched.record_id or str(uuid.uuid4()), ERROR,
                [f"attempt {attempts} failed ({cause}); read again at every sync"
                 + (f"; an administrator may acknowledge it after {MAX_ATTEMPTS} failed syncs"
                    if attempts >= MAX_ATTEMPTS else "")], attempts=attempts)
        db.session.commit()
    except LockLostError:
        db.session.rollback()
        raise
    except Exception as exc:  # noqa: BLE001 - nothing recorded: the next sync tries again
        db.session.rollback()
        logger.warning("Evidence store: cannot record the failure of %s (%s)", keys.display(fetched.key),
                       store.describe(exc))


def _write(bucket: str, fetched: Fetched, tally: Tally) -> None:
    """Write one fetched version in its own transaction, again once after a deadlock.

    A :class:`Conflict` of its plan is recorded instead, as ``rejected``. Any
    other failure - after the version passed its content check - is recorded
    by :func:`_record_failure` (``error``, read again by every sync), never as
    a refusal of the content.
    """
    from app.services.evidence_import import is_deadlock

    for attempt in (1, 2):
        conflicts = len(tally.conflicts)
        try:
            status = write_version(bucket, fetched, tally)
            db.session.commit()
            tally.add(fetched.kind, status)
            return
        except LockLostError:
            db.session.rollback()
            raise
        except Conflict as exc:
            db.session.rollback()
            del tally.conflicts[conflicts:]
            fetched.status, fetched.attempts = REJECTED, 0
            fetched.notes.append(f"not imported: {_refusal(exc)}")
        except Exception as exc:  # noqa: BLE001 - one version must not stop the sync
            db.session.rollback()
            del tally.conflicts[conflicts:]
            if attempt == 1 and is_deadlock(exc):
                logger.warning("Evidence store: deadlock while writing %s; retrying once", keys.display(fetched.key))
                continue
            logger.warning("Evidence store: failed to write %s (%s)", keys.display(fetched.key), store.describe(exc))
            _record_failure(bucket, fetched, store.describe(exc), tally)
            return
        break
    fetched.content = fetched.parsed = fetched.checked = None
    try:  # the refused content is recorded on its own
        status = write_version(bucket, fetched, tally)
        db.session.commit()
        tally.add(fetched.kind, status)
    except LockLostError:
        db.session.rollback()
        raise
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        logger.warning("Evidence store: failed to record %s (%s)", keys.display(fetched.key), store.describe(exc))
        _record_failure(bucket, fetched, store.describe(exc), tally)


def process_version(client, bucket: str, version: store.ListedVersion, tally: Tally, run_id: str | None = None,
                    recorded: Recorded | None = None) -> None:
    """Fetch one version (no transaction open), then write it.

    A decision log is fetched and written holding a transcript import slot
    sized by its listed size (waiting for one).
    """
    from app.services.evidence_import_decision_logs import MAX_TRANSCRIPT_BYTES, import_slot

    tally.counts["new"] += 1
    fetched = new_fetched(version, recorded, run_id)
    if fetched.kind == keys.KIND_DECISION_LOG and version.size <= MAX_TRANSCRIPT_BYTES:
        _end_transaction()
        with import_slot(size=version.size):
            _fetch_and_write(client, bucket, version, fetched, tally)
        return
    _fetch_and_write(client, bucket, version, fetched, tally)


def _fetch_and_write(client, bucket: str, version: store.ListedVersion, fetched: Fetched, tally: Tally) -> None:
    _end_transaction()
    try:
        fetch_version(client, bucket, version, fetched)
    except Exception as exc:  # noqa: BLE001 - one version must not stop the sync
        cause = ("the version is no longer in the store" if store.is_missing(exc) or store.is_delete_marker(exc)
                 else store.describe(exc))
        logger.warning("Evidence store: cannot read %s (%s)", keys.display(version.key), cause)
        _record_failure(bucket, fetched, cause, tally)
        return
    _write(bucket, fetched, tally)


# ----------------------------------------------------------------------------
# Listing
# ----------------------------------------------------------------------------

def recorded_versions(bucket: str, key_list: list[str]) -> dict:
    """``{(key, version_id): Recorded}`` of the versions of ``key_list`` (S3 keys) already
    recorded (one query; an escaped key is looked up in its recorded form)."""
    if not key_list:
        return {}
    stored = {keys.stored_key(key) for key in key_list}
    rows = db.session.query(EvidenceStoreObject.key, EvidenceStoreObject.key_escaped, EvidenceStoreObject.version_id,
                            EvidenceStoreObject.id, EvidenceStoreObject.status, EvidenceStoreObject.attempts).filter(
        EvidenceStoreObject.bucket == bucket, EvidenceStoreObject.key.in_(sorted({key for key, _ in stored}))).all()
    return {(keys.raw_key(row.key, row.key_escaped), row.version_id): Recorded(row.id, row.status, row.attempts or 0)
            for row in rows if (row.key, bool(row.key_escaped)) in stored}


def note_anomalies(group: store.KeyGroup, tally: Tally) -> None:
    """Count and list a key's later versions and delete markers (module docstring)."""
    for later in group.later:
        tally.anomaly(later.key, later.version_id, SECOND_VERSION)
    if group.later_count > len(group.later):
        tally.anomaly(group.key, None, f"{group.later_count - len(group.later)} more later version(s) of the key",
                      count=group.later_count - len(group.later))
    for marker in group.markers:
        tally.anomaly(marker.key, marker.version_id, DELETE_MARKER)
    if group.marker_count > len(group.markers):
        tally.anomaly(group.key, None, f"{group.marker_count - len(group.markers)} more delete marker(s)",
                      count=group.marker_count - len(group.markers))


def _process_batch(client, bucket: str, batch: list, tally: Tally, run_id: str | None = None) -> None:
    candidates = []
    for group in batch:
        tally.counts["listed"] += (1 if group.first else 0) + group.later_count + group.marker_count
        note_anomalies(group, tally)
        if group.first is not None:
            candidates.append(group.first)
    known = recorded_versions(bucket, [version.key for version in candidates])
    _end_transaction()
    for version in candidates:
        recorded = known.get((version.key, version.version_id))
        if recorded is None or retried(recorded.status, recorded.attempts):
            process_version(client, bucket, version, tally, run_id, recorded)


def retried(status: str, attempts: int = 0) -> bool:  # noqa: ARG001 - every error, whatever its attempts
    """A recorded version every sync reads again: one not read or written yet (``error``)."""
    return status == ERROR


def sync_bucket(client, bucket: str, tally: Tally, run_id: str | None = None) -> int:
    """Steps 1 to 3 of the module docstring; returns the number of prefixes whose listing failed."""
    failed = 0
    for prefix in PREFIXES:
        errors = []
        for batch in _batches(store.iter_groups_safely(client, bucket, prefix, errors), BATCH_GROUPS):
            _process_batch(client, bucket, batch, tally, run_id)
        for exc in errors:  # one prefix's listing never stops the sync
            failed += 1
            logger.warning("Evidence store: the listing of %s failed (%s)", prefix, store.describe(exc))
            tally.error(prefix, None, f"the listing failed ({store.describe(exc)})")
    reevaluate_duplicates(client, bucket, tally)
    return failed


# ----------------------------------------------------------------------------
# Duplicate pentest files
# ----------------------------------------------------------------------------

def stale_duplicates(bucket: str, limit: int = REEVALUATE_LIMIT) -> list:
    """The ``duplicate`` pentest records (at most ``limit``) whose counterpart no
    longer holds exactly the findings they duplicate - their count and identity,
    recomputed from the counterpart's content (``evidence_import.held_findings``),
    so a finding the counterpart deleted, edited or re-keyed makes it stale."""
    from app.services.evidence_import import held_findings

    rows = db.session.query(EvidenceStoreObject.id, EvidenceStoreObject.key, EvidenceStoreObject.version_id,
                            EvidenceStoreObject.sha256, EvidenceStoreObject.size, EvidenceStoreObject.attempts,
                            EvidenceStoreObject.import_info).filter_by(
        bucket=bucket, kind=keys.KIND_PENTEST, status=DUPLICATE).order_by(EvidenceStoreObject.id).all()
    infos = {row.id: (row.import_info if isinstance(row.import_info, dict) else {}) for row in rows}
    held = held_findings(info.get("duplicate_of") for info in infos.values())
    stale = []
    for row in rows:
        info = infos[row.id]
        facts = held.get(info.get("duplicate_of"))
        if facts is None or not facts.consistent \
                or (facts.count, facts.identity) != (info.get("findings"), info.get("identity_sha256")):
            stale.append(row)
            if len(stale) >= limit:
                break
    return stale


def reevaluate_duplicates(client, bucket: str, tally: Tally) -> None:
    """Re-read each stale duplicate (its recorded version, checked against its
    SHA-256) and import it now (it may also become a duplicate of another holder)."""
    rows = stale_duplicates(bucket)
    _end_transaction()
    for row in rows:
        fetched = Fetched(key=row.key, version_id=row.version_id, kind=keys.KIND_PENTEST, size=row.size,
                          record_id=row.id, attempts=row.attempts or 0, reevaluation=True)
        try:
            content = store.read_version(client, bucket, row.key, row.version_id, PENTEST_LIMIT)
            if hashlib.sha256(content).hexdigest() != row.sha256:
                tally.error(row.key, row.version_id, "the stored body's SHA-256 differs from the record")
                continue
        except Exception as exc:  # noqa: BLE001 - tried again at the next sync
            tally.error(row.key, row.version_id, store.describe(exc))
            continue
        check_pentest_content(fetched, content)
        tally.counts["reevaluated"] += 1
        _write(bucket, fetched, tally)


# ----------------------------------------------------------------------------
# Run
# ----------------------------------------------------------------------------

def _owned(token: str | None):
    return (EvidenceStoreSyncRun.executor_token.is_(None) if token is None
            else EvidenceStoreSyncRun.executor_token == token)


def record_retention(client, bucket: str, run_id: str, token: str | None, tally: Tally) -> None:
    """Step 0: the bucket's default retention, on the run (audited)."""
    try:
        settings = store.bucket_settings(client, bucket)
    except Exception as exc:  # noqa: BLE001 - reported on the run
        tally.error("", None, f"the bucket's Object Lock configuration cannot be read ({store.describe(exc)})")
        return
    retention = settings["default_retention"] or {}
    _attribute_writes()
    db.session.execute(
        update(EvidenceStoreSyncRun)
        .where(EvidenceStoreSyncRun.id == run_id, EvidenceStoreSyncRun.status == "running", _owned(token),
               EvidenceStoreSyncRun.retention_mode.is_(None), EvidenceStoreSyncRun.retention_days.is_(None))
        .values(retention_mode=retention.get("mode"), retention_days=retention.get("period_days"))
        .execution_options(synchronize_session=False))
    if retention.get("period_days") and db.session.query(EvidenceStoreRetentionFloor.id).filter_by(
            bucket=bucket).first() is None:
        db.session.add(EvidenceStoreRetentionFloor(
            id=str(uuid.uuid4()), bucket=bucket, days=int(retention["period_days"]),
            reason=f"initialized from the bucket's default retention by sync run {run_id}"))
    db.session.commit()


def execute_sync_run(run_id: str) -> EvidenceStoreSyncRun:
    """Execute a claimed (``running``) sync run and record its outcome
    compare-and-set. A lost run lock (``LockLostError``) propagates to the
    scheduler, which records nothing further."""
    run = db.session.get(EvidenceStoreSyncRun, run_id)
    bucket, token, member_id = run.bucket, run.executor_token, run.triggered_by_team_member_id
    tally = Tally()
    _set_audit_actor(member_id)
    try:
        _end_transaction()
        client = store.s3_client()
        record_retention(client, bucket, run_id, token, tally)
        failed = sync_bucket(client, bucket, tally, run_id)
        if failed == len(PREFIXES):
            _finish(run_id, token, "failure", tally, error=tally.errors[-1]["error"] if tally.errors else None)
        else:
            _finish(run_id, token, tally.status(), tally)
    except LockLostError:
        raise
    except Exception as exc:  # noqa: BLE001 - record the failure on the run
        logger.exception("Evidence store sync of %s failed", bucket)
        db.session.rollback()
        _finish(run_id, token, "failure", tally, error=store.describe(exc))
    db.session.expire_all()
    return db.session.get(EvidenceStoreSyncRun, run_id)


def _finish(run_id: str, token: str | None, status: str, tally: Tally, error: str | None = None) -> bool:
    """Record the run's outcome while it is ``running`` under ``token``; True when it applied."""
    _attribute_writes()
    applied = db.session.execute(
        update(EvidenceStoreSyncRun)
        .where(EvidenceStoreSyncRun.id == run_id, EvidenceStoreSyncRun.status == "running", _owned(token))
        .values(status=status, finished_at=_now(), counts=dict(tally.counts), details=tally.details(),
                error_message=error)
        .execution_options(synchronize_session=False)
    ).rowcount == 1
    if not applied:
        logger.warning("Evidence store sync run %s is no longer running under this executor; its outcome (%s) "
                       "is not recorded", run_id, status)
    db.session.commit()
    return applied
