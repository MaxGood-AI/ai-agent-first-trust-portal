"""Evidence store: the portal's record of the write-once S3 evidence bucket.

- ``EvidenceStoreObject``: one object version the portal recorded (key,
  version id, SHA-256, the stored composite checksum of a multipart upload,
  size, ETag, Object Lock state, kind, status, the sync run that recorded it).
  Never deleted; migration 021's guard freezes its identity and evidence and
  allows only the status changes listed in
  ``app.services.evidence_store`` (a documented erasure marks it ``erased``;
  an administrator's acknowledgement of a non-conforming upload, a refusal
  that no longer re-derives or a persistent error ``acknowledged``). The
  database dates it.
- ``EvidenceStoreSyncRun``: one sync of the bucket (``git_sync_runs``
  semantics: queued, running, then success, partial, failure or unchanged),
  with the bucket's default Object Lock retention it read (written once,
  never deleted); the database dates its ``queued_at``, which never changes.
- ``EvidenceStoreRetentionFloor``: the lowest default Object Lock retention
  verification accepts for a bucket, one row per change (append-only; the
  latest row is the floor): the first set from the bucket's default at its
  first sync, each later one by an administrator with a reason (audited; the
  database dates every row).
- ``EvidenceDocument``: a team-only evidence document (code review, pentest
  report or evidence artifact), one per store object version. Its bytes stay
  in the store. Never deleted; its identity is frozen like its object's.
- ``EvidenceDocumentLink``: a document linked to one control or one test.

See ``app.services.evidence_store`` for how they are written and verified.
"""

from datetime import datetime, timezone

from app.models import db


def _now():
    return datetime.now(timezone.utc)


OBJECT_KINDS = ("decision_log", "decision_log_sidecar", "pentest_evidence", "evidence_document", "unmapped")
OBJECT_STATUSES = ("ingested", "unchanged", "recorded", "duplicate", "rejected", "non_conforming", "too_large",
                   "error", "acknowledged", "erased")
DOCUMENT_KINDS = ("code-review", "pentest-report", "evidence-artifact")


class EvidenceStoreObject(db.Model):
    __tablename__ = "evidence_store_objects"

    id = db.Column(db.String(36), primary_key=True)
    bucket = db.Column(db.String(63), nullable=False)
    key = db.Column(db.String(3072), nullable=False,
                    comment="The S3 key; percent-encoded when key_escaped (keys.stored_key)")
    key_escaped = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false(),
                            comment="The key held a control character and is recorded percent-encoded")
    version_id = db.Column(db.String(1024), nullable=False)
    kind = db.Column(db.String(32), nullable=False, comment=" | ".join(OBJECT_KINDS))
    status = db.Column(db.String(16), nullable=False, comment=" | ".join(OBJECT_STATUSES))
    sha256 = db.Column(db.String(64), comment="SHA-256 (hex) of the version's bytes")
    composite_checksum = db.Column(db.String(64), comment="The version's stored SHA-256 COMPOSITE checksum as S3 "
                                                          "reports it (multipart upload); NULL for a full-object one")
    size = db.Column(db.BigInteger, nullable=False)
    etag = db.Column(db.String(255), comment="The version's ETag (set by S3)")
    last_modified = db.Column(db.DateTime(timezone=True))
    content_type = db.Column(db.String(255), comment="Content type the producer set (informational)")
    object_metadata = db.Column(db.JSON, comment="Sanitized x-amz-meta-* values")
    lock_mode = db.Column(db.String(16), comment="Object Lock mode when recorded")
    retain_until = db.Column(db.DateTime(timezone=True), comment="Object Lock retain-until date when recorded")
    sync_run_id = db.Column(db.String(36), db.ForeignKey("evidence_store_sync_runs.id"),
                            comment="The sync run that recorded the version")
    attempts = db.Column(db.Integer, nullable=False, default=0, server_default="0",
                         comment="Consecutive syncs that failed to read or write the version (status error)")
    import_info = db.Column(db.JSON, comment="What the import used: the sidecar version a transcript read, "
                                             "the source holding a duplicate pentest file")
    detail = db.Column(db.Text)
    erased_at = db.Column(db.DateTime(timezone=True))
    erased_by = db.Column(db.String(36), db.ForeignKey("team_members.id"))
    erasure_reason = db.Column(db.Text)
    acknowledged_at = db.Column(db.DateTime(timezone=True))
    acknowledged_by = db.Column(db.String(36), db.ForeignKey("team_members.id"))
    acknowledgement_reason = db.Column(db.Text)
    acknowledged_from = db.Column(db.String(16), comment="The status an acknowledgement settled: non_conforming, "
                                                         "rejected, too_large or error")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now,
                           comment="When the portal recorded the version (the database clock's)")
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)

    __table_args__ = (
        db.UniqueConstraint("bucket", "key", "key_escaped", "version_id", name="uq_evidence_store_objects_version"),
        db.Index("ix_evidence_store_objects_kind_status", "kind", "status"),
    )


class EvidenceStoreSyncRun(db.Model):
    __tablename__ = "evidence_store_sync_runs"

    id = db.Column(db.String(36), primary_key=True)
    bucket = db.Column(db.String(63), nullable=False)
    trigger_type = db.Column(db.String(16), nullable=False, default="manual",
                             comment="scheduled | manual | api")
    triggered_by_team_member_id = db.Column(db.String(36), db.ForeignKey("team_members.id"))
    status = db.Column(db.String(16), nullable=False, default="queued",
                       comment="queued | running | success | partial | failure | unchanged")
    queued_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now)
    started_at = db.Column(db.DateTime(timezone=True))
    finished_at = db.Column(db.DateTime(timezone=True))
    counts = db.Column(db.JSON)
    details = db.Column(db.JSON, comment="Anomalies, errors, conflicts and per-kind counts")
    error_message = db.Column(db.Text, comment="Error class and code of a failed run")
    retention_mode = db.Column(db.String(16), comment="The bucket's default Object Lock mode the run read")
    retention_days = db.Column(db.Integer, comment="The bucket's default Object Lock period the run read, in days")
    heartbeat_at = db.Column(db.DateTime(timezone=True),
                             comment="Refreshed by the executing process while it holds the run's lock")
    executor_token = db.Column(db.String(36), comment="Executor allowed to record this run's result")

    __table_args__ = (
        db.Index("ix_evidence_store_sync_runs_queued", "bucket", "queued_at"),
        db.Index(
            "uq_evidence_store_sync_runs_one_active",
            "bucket",
            unique=True,
            postgresql_where=db.text("status IN ('queued', 'running')"),
            sqlite_where=db.text("status IN ('queued', 'running')"),
        ),
    )


class EvidenceStoreRetentionFloor(db.Model):
    __tablename__ = "evidence_store_retention_floors"

    id = db.Column(db.String(36), primary_key=True)
    bucket = db.Column(db.String(63), nullable=False)
    days = db.Column(db.Integer, nullable=False,
                     comment="The lowest default Object Lock retention verification accepts, in days")
    set_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now,
                       comment="When it was set (the database clock; the latest row of a bucket is its floor)")
    set_by = db.Column(db.String(36), db.ForeignKey("team_members.id"),
                       comment="The compliance admin who set it (NULL: the bucket's first sync)")
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now)

    __table_args__ = (
        db.CheckConstraint("days > 0", name="ck_evidence_store_retention_floors_days"),
        db.Index("ix_evidence_store_retention_floors_bucket", "bucket", "set_at"),
    )


class EvidenceDocument(db.Model):
    __tablename__ = "evidence_documents"

    id = db.Column(db.String(36), primary_key=True)
    store_object_id = db.Column(db.String(36), db.ForeignKey("evidence_store_objects.id"), nullable=False,
                                unique=True)
    kind = db.Column(db.String(32), nullable=False, comment=" | ".join(DOCUMENT_KINDS))
    title = db.Column(db.String(500), nullable=False)
    key = db.Column(db.String(1024), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    size = db.Column(db.BigInteger, nullable=False)
    content_type = db.Column(db.String(255))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now)

    store_object = db.relationship("EvidenceStoreObject")
    links = db.relationship("EvidenceDocumentLink", backref="document", lazy="dynamic",
                            order_by="EvidenceDocumentLink.created_at")

    __table_args__ = (db.Index("ix_evidence_documents_kind", "kind", "created_at"),)


class EvidenceDocumentLink(db.Model):
    __tablename__ = "evidence_document_links"

    id = db.Column(db.String(36), primary_key=True)
    document_id = db.Column(db.String(36), db.ForeignKey("evidence_documents.id"), nullable=False)
    control_id = db.Column(db.String(36), db.ForeignKey("controls.id", ondelete="CASCADE"))
    test_record_id = db.Column(db.String(36), db.ForeignKey("test_records.id", ondelete="CASCADE"))
    created_by = db.Column(db.String(36), db.ForeignKey("team_members.id"))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now)

    __table_args__ = (
        db.CheckConstraint("(control_id IS NULL) <> (test_record_id IS NULL)",
                           name="ck_evidence_document_links_one_target"),
        db.UniqueConstraint("document_id", "control_id", name="uq_evidence_document_links_control"),
        db.UniqueConstraint("document_id", "test_record_id", name="uq_evidence_document_links_test"),
        db.Index("ix_evidence_document_links_control", "control_id"),
        db.Index("ix_evidence_document_links_test", "test_record_id"),
    )
