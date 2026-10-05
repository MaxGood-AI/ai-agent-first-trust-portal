"""Evidence store: the write-once S3 bucket of machine-produced evidence.

The contract is ``docs/evidence-repo-spec.md`` -> "Evidence store". Producers
write each record once (``PutObject`` with ``If-None-Match: *`` and a
full-object SHA-256 checksum, or a multipart upload with SHA-256 part
checksums) under five key prefixes; the bucket has versioning and
Object Lock and nothing deletes or replaces a version. The portal reads the
bucket named by ``EVIDENCE_STORE_BUCKET`` through its runtime role and never
writes to it. Without that variable the evidence store is disabled: a sync or
a verification reports "not configured" and nothing else changes.

Modules
-------
``keys``
    Key rules (clean relative paths, the five prefixes, the strict
    decision-log and pentest key patterns, kinds), the reversible escaping
    of keys holding control characters, metadata sanitization, document
    titles and content types. No I/O.
``store``
    Every S3 call of the package, on a client from the runtime role
    (``aws_session.get_session()``): ``list_object_versions``,
    ``head_object``, ``get_object``, ``get_bucket_versioning``,
    ``get_object_lock_configuration``, ``get_bucket_policy`` and
    ``get_bucket_lifecycle_configuration``. Bodies are streamed and bounded.
``sync``
    A sync run: record the bucket's default retention (and, at the bucket's
    first sync, its retention floor), list every object version under the
    prefixes, page by page, record and import each version the portal has
    not recorded (or has recorded as ``error``), one at a time, each in its
    own database transaction (no transaction is open while S3 answers), and
    re-evaluate duplicate pentest files. Decision logs are imported with the
    ``store`` authority: create, extend exactly or baseline a restored
    session, anything else a conflict kept for review.
``plans``
    What an import does with a version's body: the pure, total content
    check of each kind (refusals decided from the body alone), the plan
    against the database (import, unchanged, duplicate or a conflict), the
    store's insert-only pentest import (finding ids derived from the
    object's version id) and what verification recomputes of the store's
    namespace. The sync and verification call the same functions with the
    same inputs.
``verify``
    ``audit-verify --evidence-store``: the bucket's configuration (against
    its retention floor history), policy and lifecycle, every record against
    its own bucket and its import outcome - the store is the ground truth:
    every outcome that is not a straightforward import is re-derived from the
    version's body on every run (bodies read and checked by the worker
    pool, within a byte budget per API slice) -, the store's pentest
    findings against the records that imported them, the evidence documents
    against their records, the listing against the records, the refusals
    and store conflicts (informational); and ``audit-verify --decision-logs
    --against-store`` (every store-imported version against its object's
    body).
``service``
    Status, serialization, queueing a sync, documents (served spooled,
    under a per-process read limit) and their links, the records of a
    documented erasure and of an acknowledgement (a non-conforming upload, a
    rejection that no longer re-derives, a persistent error), and a bucket's
    retention floor.

Records are evidence: migration 021's guards freeze each
``evidence_store_objects`` row's identity and evidence and allow only the
status changes ``error`` to any recorded status, ``duplicate`` to
``ingested`` / ``unchanged`` / ``duplicate`` / ``rejected``,
``non_conforming``, ``rejected``, ``too_large`` or ``error`` to ``acknowledged`` and any
status to ``erased`` (one way), and date each record by the database clock;
they freeze each ``evidence_documents`` row's identity and refuse DELETE and
TRUNCATE on both tables for every role; a sync run's bucket and queue time
(the database clock's) are frozen and the retention it read is written once,
retention floors
are appended (dated by the database; after the first, only by an
administrator with a reason), and neither is ever changed or deleted; the
pentest findings of the store's namespace never change and are never
deleted.

Syncs run as the scheduler's ``evidence_store_sync`` job kind (advisory lock
class 8152, at most one queued or running run per bucket, reaped like every
run): queued by **Sync now**, ``POST /api/evidence-store/sync``,
``python -m cli evidence-store sync`` and, while a bucket is set, the
leader's periodic task (:func:`register`), which queues a sync when a
process gains leadership and then every hour (:data:`SYNC_INTERVAL_SECONDS`).

Tables (migration 021): ``evidence_store_objects``,
``evidence_store_sync_runs``, ``evidence_store_retention_floors``,
``evidence_documents``, ``evidence_document_links`` (all audited) and
``decision_log_transcripts.store_object_id``.

The portal does not attribute writes to the store: producers write with
their own credentials, and CloudTrail data events on the bucket attribute
each write.
"""

from __future__ import annotations

PREFIXES = ("decision-logs/", "pentest-evidence/", "codex-reviews/", "pentest-reports/", "evidence/artifacts/")
NOT_CONFIGURED = "the evidence store is not configured (EVIDENCE_STORE_BUCKET is not set)"


class StoreNotConfigured(RuntimeError):
    """``EVIDENCE_STORE_BUCKET`` is not set."""

    def __init__(self):
        super().__init__(NOT_CONFIGURED)


def store_bucket() -> str | None:
    """The evidence store's bucket (``EVIDENCE_STORE_BUCKET``, environment or
    portal secret), or None when the evidence store is not configured."""
    from app.runtime_config import env

    return env("EVIDENCE_STORE_BUCKET")


def is_configured() -> bool:
    return store_bucket() is not None


def require_bucket() -> str:
    """The configured bucket; raises :class:`StoreNotConfigured` without one."""
    bucket = store_bucket()
    if bucket is None:
        raise StoreNotConfigured()
    return bucket


SYNC_INTERVAL_SECONDS = 3600


def _periodic_sync(app) -> None:  # noqa: ARG001 - periodic task signature
    """Queue a scheduled sync of the configured bucket (nothing without one)."""
    bucket = store_bucket()
    if bucket is None:
        return
    from app.services.scheduler import ActiveRunConflict, enqueue_evidence_store_sync

    try:
        enqueue_evidence_store_sync(bucket, "scheduled")
    except ActiveRunConflict:
        pass  # coalesced into the active run


def register() -> None:
    """Register the hourly sync with the scheduler leader (it runs only while a bucket is set)."""
    from app.services.scheduler import register_periodic

    register_periodic("evidence_store_sync", SYNC_INTERVAL_SECONDS, _periodic_sync)
