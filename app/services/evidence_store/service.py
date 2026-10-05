"""Evidence store service: status, serialization, documents and their links,
the records of a documented erasure and of an acknowledgement (a
non-conforming upload, a refusal that no longer re-derives, a persistent
error), and a bucket's retention floor. Shared by the API, the admin UI and
the CLI. Every write goes to an audited table and is attributed to the
member in ``flask.g.current_team_member``.

A document's bytes are read from its exact store version into a spooled
temporary file (in memory up to :data:`SPOOL_MEMORY`, then on disk) and
served only after their SHA-256 equals the record. At most
:data:`READ_SLOTS` document reads run at once per process; another read is
refused (429, retry after :data:`RETRY_AFTER_SECONDS` seconds).
"""

from __future__ import annotations

import tempfile
import threading
import uuid
from datetime import datetime, timezone

from sqlalchemy import and_, func, or_

from app.models import Control, TestRecord, db
from app.models.evidence_store import (EvidenceDocument, EvidenceDocumentLink, EvidenceStoreObject,
                                       EvidenceStoreRetentionFloor, EvidenceStoreSyncRun)
from app.services.evidence_store import keys, store, store_bucket

SERVE_LIMIT = 32 * 1024 * 1024
PREVIEW_LIMIT = 1024 * 1024
SPOOL_MEMORY = 1024 * 1024
READ_SLOTS = 2
RETRY_AFTER_SECONDS = 5
MAX_REASON = 2000
_READ_SLOTS = threading.BoundedSemaphore(READ_SLOTS)


class EvidenceStoreError(ValueError):
    """A request the evidence store service refuses (the message says why)."""


class DocumentUnavailable(RuntimeError):
    """A document's bytes cannot be served (``status`` is the HTTP status to answer)."""

    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


def _iso(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def serialize_run(run: EvidenceStoreSyncRun) -> dict:
    return {
        "id": run.id,
        "bucket": run.bucket,
        "trigger_type": run.trigger_type,
        "triggered_by_team_member_id": run.triggered_by_team_member_id,
        "status": run.status,
        "queued_at": _iso(run.queued_at),
        "started_at": _iso(run.started_at),
        "finished_at": _iso(run.finished_at),
        "counts": run.counts or {},
        "details": run.details or {},
        "error_message": run.error_message,
        "retention_mode": run.retention_mode,
        "retention_days": run.retention_days,
    }


def serialize_object(row: EvidenceStoreObject) -> dict:
    return {
        "id": row.id,
        "bucket": row.bucket,
        "key": row.key,
        "key_escaped": bool(row.key_escaped),
        "version_id": row.version_id,
        "kind": row.kind,
        "status": row.status,
        "sha256": row.sha256,
        "composite_checksum": row.composite_checksum,
        "size": row.size,
        "etag": row.etag,
        "last_modified": _iso(row.last_modified),
        "content_type": row.content_type,
        "metadata": row.object_metadata or {},
        "lock_mode": row.lock_mode,
        "retain_until": _iso(row.retain_until),
        "sync_run_id": row.sync_run_id,
        "attempts": row.attempts,
        "import_info": row.import_info,
        "detail": row.detail,
        "erased_at": _iso(row.erased_at),
        "erased_by": row.erased_by,
        "erasure_reason": row.erasure_reason,
        "acknowledged_at": _iso(row.acknowledged_at),
        "acknowledged_by": row.acknowledged_by,
        "acknowledgement_reason": row.acknowledgement_reason,
        "acknowledged_from": row.acknowledged_from,
        "recorded_at": _iso(row.created_at),
    }


def serialize_link(link: EvidenceDocumentLink) -> dict:
    target = None
    if link.control_id:
        control = db.session.get(Control, link.control_id)
        target = {"type": "control", "id": link.control_id,
                  "name": control.name if control else None,
                  "control_id_short": control.control_id_short if control else None}
    else:
        test = db.session.get(TestRecord, link.test_record_id)
        target = {"type": "test", "id": link.test_record_id, "name": test.name if test else None}
    return {"id": link.id, "document_id": link.document_id, "target": target, "created_by": link.created_by,
            "created_at": _iso(link.created_at)}


def serialize_document(document: EvidenceDocument, *, with_links: bool = False) -> dict:
    row = document.store_object
    body = {
        "id": document.id,
        "kind": document.kind,
        "title": document.title,
        "key": document.key,
        "version_id": row.version_id if row else None,
        "bucket": row.bucket if row else None,
        "sha256": document.sha256,
        "size": document.size,
        "content_type": document.content_type,
        "object_status": row.status if row else None,
        "lock_mode": row.lock_mode if row else None,
        "retain_until": _iso(row.retain_until) if row else None,
        "metadata": (row.object_metadata or {}) if row else {},
        "recorded_at": _iso(document.created_at),
        "content_url": f"/api/evidence-documents/{document.id}/content",
    }
    if with_links:
        body["links"] = [serialize_link(link) for link in document.links]
    return body


def latest_runs(limit: int = 20) -> list[EvidenceStoreSyncRun]:
    return EvidenceStoreSyncRun.query.order_by(EvidenceStoreSyncRun.queued_at.desc()).limit(limit).all()


def status() -> dict:
    """The evidence store's configuration and records at a glance."""
    bucket = store_bucket()
    runs = latest_runs(1)
    by_status = dict(db.session.query(EvidenceStoreObject.status, func.count(EvidenceStoreObject.id))
                     .group_by(EvidenceStoreObject.status).all())
    by_kind = dict(db.session.query(EvidenceStoreObject.kind, func.count(EvidenceStoreObject.id))
                   .group_by(EvidenceStoreObject.kind).all())
    floor = retention_floor(bucket) if bucket is not None else None
    return {
        "configured": bucket is not None,
        "bucket": bucket,
        "retention_floor_days": floor.days if floor is not None else None,
        "objects": sum(by_status.values()),
        "objects_by_status": by_status,
        "objects_by_kind": by_kind,
        "documents": db.session.query(func.count(EvidenceDocument.id)).scalar() or 0,
        "last_run": serialize_run(runs[0]) if runs else None,
    }


def enqueue_sync(trigger_type: str, member_id: str | None = None):
    """Queue a sync of the configured bucket: ``(run, created)``; the active run
    with ``created=False`` when one is queued or running. Raises
    ``StoreNotConfigured`` without a bucket."""
    from app.services.evidence_store import require_bucket
    from app.services.scheduler import enqueue_evidence_store_sync

    return enqueue_evidence_store_sync(require_bucket(), trigger_type, member_id)


def objects_query(kind: str | None = None, status_filter: str | None = None):
    query = EvidenceStoreObject.query
    if kind:
        query = query.filter(EvidenceStoreObject.kind == kind)
    if status_filter:
        query = query.filter(EvidenceStoreObject.status == status_filter)
    return query.order_by(EvidenceStoreObject.created_at.desc(), EvidenceStoreObject.id)


def find_object(key: str, version_id: str, bucket: str | None = None) -> EvidenceStoreObject | None:
    """The one record of ``key`` / ``version_id`` (in ``bucket`` when given), else None.

    ``key`` is the S3 key or, for a key recorded escaped, its recorded
    (percent-encoded) form as reports show it.
    """
    stored, escaped = keys.stored_key(key)
    match = and_(EvidenceStoreObject.key == stored, EvidenceStoreObject.key_escaped.is_(escaped))
    if not escaped:  # the key as given may be a recorded (percent-encoded) form
        match = or_(match, and_(EvidenceStoreObject.key == key, EvidenceStoreObject.key_escaped.is_(True)))
    query = EvidenceStoreObject.query.filter(EvidenceStoreObject.version_id == version_id, match)
    if bucket:
        query = query.filter(EvidenceStoreObject.bucket == bucket)
    rows = query.all()
    return rows[0] if len(rows) == 1 else None


def _reason(reason) -> str:
    reason = (reason or "").strip()
    if not reason:
        raise EvidenceStoreError("a reason is required")
    if len(reason) > MAX_REASON:
        raise EvidenceStoreError(f"the reason is longer than {MAX_REASON} characters")
    return reason


def version_absent(row: EvidenceStoreObject, client=None) -> None:
    """Require ``HeadObject`` of the recorded version to report it absent
    (``NoSuchVersion`` / 404); :class:`EvidenceStoreError` otherwise. No
    transaction is held while S3 answers."""
    bucket, key, version_id = row.bucket, keys.raw_key(row.key, bool(row.key_escaped)), row.version_id
    db.session.commit()
    client = client or store.s3_client()
    try:
        store.head_version(client, bucket, key, version_id)
    except Exception as exc:  # noqa: BLE001 - classified below
        if store.is_missing(exc):
            return
        raise EvidenceStoreError(f"the store cannot confirm the version is gone ({store.describe(exc)})") from None
    raise EvidenceStoreError("the version still exists in the evidence store; erase it there first")


def record_erasure(row: EvidenceStoreObject, reason: str, member_id: str, *, client=None) -> EvidenceStoreObject:
    """Mark ``row`` as erased by a documented erasure (audited); the caller commits.

    ``reason`` is required (at most 2,000 characters); an erased record is
    refused, and so is a version ``HeadObject`` still finds in the store
    (:func:`version_absent`).
    """
    reason = _reason(reason)
    if row.status == "erased":
        raise EvidenceStoreError("this version is already recorded as erased")
    version_absent(row, client)
    row.status = "erased"
    row.erased_at = datetime.now(timezone.utc)
    row.erased_by = member_id
    row.erasure_reason = reason
    db.session.flush()
    return row


def acknowledge(row: EvidenceStoreObject, reason: str, member_id: str, *, client=None) -> EvidenceStoreObject:
    """Settle a record an import cannot settle: mark it ``acknowledged`` (audited,
    ``acknowledged_from`` its status); the caller commits. Accepted for

    - a ``non_conforming`` version (an upload without a SHA-256 checksum, or
      whose body does not match it);
    - a refusal (``rejected`` or ``too_large``) that no longer re-derives from
      its body (verification fails it; ``verify.rederive_issues`` finds issues
      now - the body is read with no transaction open);
    - an ``error`` version that failed at least ``sync.MAX_ATTEMPTS`` syncs
      (a persistent error, which every sync otherwise reads again).

    Verification then lists it apart from the failures (informational) and
    still checks that its version exists with the recorded size and ETag
    (and SHA-256: a non-conforming one ``--full`` only).
    """
    from app.services.evidence_store import sync, verify

    reason = _reason(reason)
    if row.status == "error" and (row.attempts or 0) < sync.MAX_ATTEMPTS:
        raise EvidenceStoreError(f"this version has failed {row.attempts or 0} sync(s); a sync reads it again, and an "
                                 f"error is acknowledged only after {sync.MAX_ATTEMPTS} failed syncs")
    if row.status in ("rejected", "too_large"):
        status, record_id = row.status, row.id
        db.session.commit()  # no transaction is held while S3 answers
        record = verify.record_row(db.session, record_id)
        db.session.rollback()
        issues = verify.rederive_issues(db.session, client or store.s3_client(), record)
        row = db.session.get(EvidenceStoreObject, record_id)
        if not issues:
            raise EvidenceStoreError("its refusal re-derives from its body: it is a refusal, not a failure to "
                                     "acknowledge")
        if row.status != status:
            raise EvidenceStoreError(f"the version changed while it was checked (it is now {row.status})")
    elif row.status not in ("non_conforming", "error"):
        raise EvidenceStoreError("only a non_conforming version, a refusal that no longer re-derives or a "
                                 f"persistent error can be acknowledged (this one is {row.status})")
    row.acknowledged_from = row.status
    row.status = "acknowledged"
    row.acknowledged_at = datetime.now(timezone.utc)
    row.acknowledged_by = member_id
    row.acknowledgement_reason = reason
    db.session.flush()
    return row


def retention_floor(bucket: str) -> EvidenceStoreRetentionFloor | None:
    """The bucket's retention floor: its latest floor row (None before its first sync)."""
    return EvidenceStoreRetentionFloor.query.filter_by(bucket=bucket).order_by(
        EvidenceStoreRetentionFloor.set_at.desc(), EvidenceStoreRetentionFloor.id.desc()).first()


def set_retention_floor(bucket: str, days, reason: str, member_id: str) -> EvidenceStoreRetentionFloor:
    """Set ``bucket``'s retention floor to ``days``: a new floor row (audited,
    attributed to ``member_id``; the database dates it); the caller commits.
    The only way to lower a floor; the bucket's first sync sets its first
    floor, so a bucket without one is refused. The reason is required (at
    most 2,000 characters) and ``days`` a whole number of days of at least 1.
    """
    reason = _reason(reason)
    if isinstance(days, bool) or not isinstance(days, int) or days < 1:
        raise EvidenceStoreError("the floor is a whole number of days, at least 1")
    if retention_floor(bucket) is None:
        raise EvidenceStoreError(f"bucket {bucket} has no retention floor yet; its first sync sets it from the "
                                 "bucket's default retention")
    floor = EvidenceStoreRetentionFloor(id=str(uuid.uuid4()), bucket=bucket, days=days, set_by=member_id,
                                        reason=reason)
    db.session.add(floor)
    db.session.flush()
    return floor


def add_link(document: EvidenceDocument, *, control_id: str | None = None, test_id: str | None = None,
             member_id: str | None = None) -> EvidenceDocumentLink:
    """Link ``document`` to one control or one test (audited); the caller commits."""
    if bool(control_id) == bool(test_id):
        raise EvidenceStoreError("name exactly one of control_id and test_id")
    if control_id and db.session.get(Control, control_id) is None:
        raise EvidenceStoreError(f"no control {control_id!r}")
    if test_id and db.session.get(TestRecord, test_id) is None:
        raise EvidenceStoreError(f"no test {test_id!r}")
    existing = EvidenceDocumentLink.query.filter_by(document_id=document.id, control_id=control_id or None,
                                                    test_record_id=test_id or None).first()
    if existing is not None:
        raise EvidenceStoreError("the document is already linked to it")
    link = EvidenceDocumentLink(id=str(uuid.uuid4()), document_id=document.id, control_id=control_id or None,
                                test_record_id=test_id or None, created_by=member_id)
    db.session.add(link)
    db.session.flush()
    return link


def remove_link(document: EvidenceDocument, link_id: str) -> bool:
    """Remove one of ``document``'s links (audited); False when it has no such link."""
    link = db.session.get(EvidenceDocumentLink, link_id)
    if link is None or link.document_id != document.id:
        return False
    db.session.delete(link)
    db.session.flush()
    return True


def documents_for(*, control_id: str | None = None, test_id: str | None = None) -> list[EvidenceDocument]:
    query = EvidenceDocument.query.join(EvidenceDocumentLink, EvidenceDocumentLink.document_id == EvidenceDocument.id)
    if control_id:
        query = query.filter(EvidenceDocumentLink.control_id == control_id)
    if test_id:
        query = query.filter(EvidenceDocumentLink.test_record_id == test_id)
    return query.order_by(EvidenceDocument.created_at.desc()).all()


def open_document(document: EvidenceDocument, *, limit: int = SERVE_LIMIT, client=None):
    """The document's exact version from the store in a spooled temporary file
    (positioned at its start; the caller closes it), only when its SHA-256
    equals the record.

    Raises :class:`DocumentUnavailable`: 413 over ``limit``, 410 when the
    version was erased, 429 when :data:`READ_SLOTS` reads are running, 502
    when the store cannot be read or holds different bytes, 503 when the
    store is not configured.
    """
    row = document.store_object
    if row is None or row.status == "erased":
        raise DocumentUnavailable("this document's version was erased from the evidence store", 410)
    if store_bucket() is None:
        raise DocumentUnavailable("the evidence store is not configured", 503)
    if document.size > limit:
        raise DocumentUnavailable(f"the document is {document.size} bytes; the portal serves documents of at "
                                  f"most {limit} bytes", 413)
    bucket, key, version_id, expected = row.bucket, row.key, row.version_id, document.sha256
    db.session.commit()  # no transaction is held while S3 answers
    if not _READ_SLOTS.acquire(blocking=False):
        raise DocumentUnavailable("the portal is serving other documents; try again shortly", 429)
    spool = tempfile.SpooledTemporaryFile(max_size=SPOOL_MEMORY)
    try:
        digest, _ = store.copy_version(client or store.s3_client(), bucket, key, version_id, limit, spool)
    except store.BodyTooLarge:
        spool.close()
        raise DocumentUnavailable("the stored version is larger than its record", 502) from None
    except Exception as exc:  # noqa: BLE001 - never echo S3 details to the client
        spool.close()
        raise DocumentUnavailable(f"the evidence store cannot be read ({store.describe(exc)})", 502) from None
    finally:
        _READ_SLOTS.release()
    if digest != expected:
        spool.close()
        raise DocumentUnavailable("the stored version's SHA-256 differs from the record; not served", 502)
    spool.seek(0)
    return spool


def document_bytes(document: EvidenceDocument, *, limit: int = SERVE_LIMIT, client=None) -> bytes:
    """The bytes :func:`open_document` serves (for a preview of at most ``limit`` bytes)."""
    with open_document(document, limit=limit, client=client) as spool:
        return spool.read()


def download_name(document: EvidenceDocument) -> str:
    """A safe file name for ``Content-Disposition`` (ASCII letters, digits, ``.``, ``_`` and ``-``)."""
    import re

    base = document.key.rsplit("/", 1)[-1]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", base).strip("._") or "document"
    return name[:150]


def serve_type(document: EvidenceDocument) -> str:
    return keys.serve_content_type(document.key)
