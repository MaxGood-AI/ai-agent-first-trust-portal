"""Evidence store: the portal's record of every object version in the
write-once S3 evidence bucket (``EVIDENCE_STORE_BUCKET``).

- ``evidence_store_objects`` (audited): one row per object version the
  portal recorded - bucket, key (percent-encoded, with ``key_escaped`` set,
  when it holds a control character), version id, SHA-256, the stored
  SHA-256 composite checksum of a multipart upload (``composite_checksum``), size, ETag,
  last-modified time, content type, sanitized metadata, Object Lock mode and
  retain-until date, kind, status, the sync run that recorded it, the
  attempts of a version not yet read, what its import used, and its
  documented erasure or acknowledgement (``acknowledged_from``: the status it
  was acknowledged from). The application role may insert and update rows,
  never delete them (``cli/db_cmd.py``), and the guard
  ``evidence_store_objects_guard`` (every role) keeps them evidence (below).
- ``evidence_store_sync_runs`` (audited, ``details`` as a digest): one row
  per sync, with the semantics of ``git_sync_runs`` (queued, running,
  success, partial, failure, unchanged; heartbeat and executor token; at most
  one queued or running run per bucket) and the bucket's default Object
  Lock retention the run read (``retention_mode``, ``retention_days``). The
  guard ``evidence_store_sync_runs_guard`` (every role) dates each run's
  ``queued_at`` by the database clock on INSERT (any value the client sends
  is ignored), keeps a run's id, bucket and ``queued_at``, lets each
  retention column be written once (NULL to a value) and refuses DELETE and
  TRUNCATE.
- ``evidence_store_retention_floors`` (audited): per bucket, the lowest
  default Object Lock retention verification accepts (``days``), one row per
  change: the bucket's first row is set from its default at its first sync,
  each later row by an administrator; the latest row is the floor. The guard
  ``evidence_store_retention_floors_guard`` makes the table append-only: an
  INSERT gets ``set_at`` and ``created_at`` from the database clock (any
  value the client sends is ignored), later than every row of its bucket,
  and a row after the bucket's first names ``set_by`` and a reason; UPDATE,
  DELETE and TRUNCATE are refused.
- ``evidence_documents`` (audited): one evidence document (code review,
  pentest report or evidence artifact) per store object version; the guard
  ``evidence_documents_guard`` freezes its identity (object, kind, key,
  SHA-256, size, creation time) and refuses DELETE and TRUNCATE.
- ``evidence_document_links`` (audited): a document linked to exactly one
  control or one test record (deleted with it).
- ``decision_log_transcripts.store_object_id``: the store object a version
  was imported from (NULL for every other version). Its foreign key is
  ``DEFERRABLE INITIALLY IMMEDIATE``, so a store import writes the version
  before the object's audited row; it is added ``NOT VALID`` and validated
  through the partial index over the column's non-null values, built first.
  The version guard of migration 018 is replaced by one that also freezes
  ``store_object_id`` and applies the path rule to store imports (a store
  import names its own session's file).
- ``pentest_findings``: the guard ``pentest_findings_guard`` (every role)
  makes the findings of the evidence store's namespace (``source_file``
  starting ``evidence-store:``) immutable: an UPDATE that changes any column
  of one, or moves a row into or out of the namespace, a DELETE of one and a
  TRUNCATE while one exists are refused (the table has no workflow column, so
  every column is frozen). Every other finding is unaffected.

The record guard (``evidence_store_objects_guard``) dates every INSERT by
the database clock (``created_at``; any value the client sends is ignored)
and refuses, for every role, DELETE, TRUNCATE and every UPDATE except these
status changes:

- ``error`` (a version not yet read or written, which every sync reads
  again) to any status but ``acknowledged`` and ``erased``, filling its
  evidence columns; to ``error`` again only with more ``attempts``;
- ``duplicate`` (a pentest file another source holds identically) to
  ``ingested``, ``unchanged``, ``duplicate`` or ``rejected`` (re-evaluated;
  its import information and detail may change);
- ``non_conforming``, ``rejected``, ``too_large`` or ``error`` to
  ``acknowledged``, with ``acknowledged_from`` the status it leaves and ``acknowledged_at``,
  ``acknowledged_by`` and ``acknowledgement_reason`` set;
- any status but ``erased`` to ``erased``, with ``erased_at``, ``erased_by``
  and ``erasure_reason`` set (one way).

Bucket, key, ``key_escaped``, version id, kind and creation time never change; SHA-256,
composite checksum, size, ETag, last-modified time, content type, metadata, Object Lock mode and
retain-until date and the recording run change only while the version is
read again (``error``). An INSERT never records an erased or acknowledged
version.

Every statement is a catalog change or touches only the new tables,
``decision_log_transcripts`` (a nullable column without a default, a partial
index over its non-null values - the one scan of the table - and its foreign
key, validated through that index) and ``pentest_findings`` (a trigger);
``audit_log`` is untouched.

Revision ID: 021
Revises: 020
Create Date: 2026-10-04
"""

from alembic import op
import sqlalchemy as sa

revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None

AUDITED = {
    "evidence_store_objects": (),
    "evidence_store_sync_runs": ("details",),
    "evidence_store_retention_floors": (),
    "evidence_documents": (),
    "evidence_document_links": (),
}

OBJECT_KINDS = ("decision_log", "decision_log_sidecar", "pentest_evidence", "evidence_document", "unmapped")
OBJECT_STATUSES = ("ingested", "unchanged", "recorded", "duplicate", "rejected", "non_conforming", "too_large",
                   "error", "acknowledged", "erased")
DOCUMENT_KINDS = ("code-review", "pentest-report", "evidence-artifact")
STORE_OBJECT_FOREIGN_KEY = "fk_decision_log_transcripts_store_object"
GUARDED = ("evidence_store_objects", "evidence_documents", "evidence_store_sync_runs",
           "evidence_store_retention_floors", "pentest_findings")

# The records of the evidence store are evidence (module docstring).
OBJECT_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION public.evidence_store_objects_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    identity_kept BOOLEAN;
    evidence_kept BOOLEAN;
    erasure_kept BOOLEAN;
    acknowledgement_kept BOOLEAN;
    record_kept BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status IN ('erased', 'acknowledged') OR NEW.erased_at IS NOT NULL OR NEW.erased_by IS NOT NULL
                OR NEW.erasure_reason IS NOT NULL OR NEW.acknowledged_at IS NOT NULL
                OR NEW.acknowledged_by IS NOT NULL OR NEW.acknowledgement_reason IS NOT NULL
                OR NEW.acknowledged_from IS NOT NULL THEN
            RAISE EXCEPTION 'evidence_store_objects: a version is recorded before it is erased or acknowledged'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        -- The database clock dates every record.
        NEW.created_at := pg_catalog.now();
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        identity_kept := NEW.id = OLD.id AND NEW.bucket = OLD.bucket AND NEW.key = OLD.key
            AND NEW.key_escaped = OLD.key_escaped AND NEW.version_id = OLD.version_id AND NEW.kind = OLD.kind
            AND NEW.created_at = OLD.created_at;
        evidence_kept := NEW.sha256 IS NOT DISTINCT FROM OLD.sha256 AND NEW.size = OLD.size
            AND NEW.composite_checksum IS NOT DISTINCT FROM OLD.composite_checksum
            AND NEW.etag IS NOT DISTINCT FROM OLD.etag
            AND NEW.last_modified IS NOT DISTINCT FROM OLD.last_modified
            AND NEW.content_type IS NOT DISTINCT FROM OLD.content_type
            AND NEW.object_metadata::text IS NOT DISTINCT FROM OLD.object_metadata::text
            AND NEW.lock_mode IS NOT DISTINCT FROM OLD.lock_mode
            AND NEW.retain_until IS NOT DISTINCT FROM OLD.retain_until
            AND NEW.sync_run_id IS NOT DISTINCT FROM OLD.sync_run_id;
        erasure_kept := NEW.erased_at IS NOT DISTINCT FROM OLD.erased_at
            AND NEW.erased_by IS NOT DISTINCT FROM OLD.erased_by
            AND NEW.erasure_reason IS NOT DISTINCT FROM OLD.erasure_reason;
        acknowledgement_kept := NEW.acknowledged_at IS NOT DISTINCT FROM OLD.acknowledged_at
            AND NEW.acknowledged_by IS NOT DISTINCT FROM OLD.acknowledged_by
            AND NEW.acknowledgement_reason IS NOT DISTINCT FROM OLD.acknowledgement_reason
            AND NEW.acknowledged_from IS NOT DISTINCT FROM OLD.acknowledged_from;
        record_kept := NEW.attempts = OLD.attempts AND NEW.detail IS NOT DISTINCT FROM OLD.detail
            AND NEW.import_info::text IS NOT DISTINCT FROM OLD.import_info::text;
        IF identity_kept AND erasure_kept AND acknowledgement_kept THEN
            -- A version read again (not yet read or written) gains its evidence and a status,
            -- or one more attempt.
            IF OLD.status = 'error' AND NEW.status NOT IN ('acknowledged', 'erased')
                    AND (NEW.status <> 'error' OR NEW.attempts > OLD.attempts) THEN
                RETURN NEW;
            END IF;
            -- A duplicate pentest file is re-evaluated.
            IF OLD.status = 'duplicate' AND NEW.status IN ('ingested', 'unchanged', 'duplicate', 'rejected')
                    AND evidence_kept AND NEW.attempts = OLD.attempts THEN
                RETURN NEW;
            END IF;
        END IF;
        -- An administrator settles a non-conforming upload, a refusal that no longer re-derives
        -- or a persistent error.
        IF identity_kept AND evidence_kept AND erasure_kept AND record_kept
                AND OLD.status IN ('non_conforming', 'rejected', 'too_large', 'error') AND NEW.status = 'acknowledged'
                AND NEW.acknowledged_from = OLD.status
                AND NEW.acknowledged_at IS NOT NULL AND NEW.acknowledged_by IS NOT NULL
                AND NEW.acknowledgement_reason IS NOT NULL THEN
            RETURN NEW;
        END IF;
        IF identity_kept AND evidence_kept AND acknowledgement_kept AND record_kept
                AND OLD.status <> 'erased' AND NEW.status = 'erased'
                AND NEW.erased_at IS NOT NULL AND NEW.erased_by IS NOT NULL AND NEW.erasure_reason IS NOT NULL THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION 'evidence_store_objects: the records of the evidence store are evidence (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
"""

DOCUMENT_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION public.evidence_documents_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.id = OLD.id AND NEW.store_object_id = OLD.store_object_id
            AND NEW.kind = OLD.kind AND NEW.key = OLD.key AND NEW.sha256 = OLD.sha256
            AND NEW.size = OLD.size AND NEW.created_at = OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'evidence_documents: evidence documents are evidence (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
"""


SYNC_RUN_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION public.evidence_store_sync_runs_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- The database clock dates every run (the order verification reads runs in).
        NEW.queued_at := pg_catalog.now();
        RETURN NEW;
    END IF;
    -- The retention a run read is written once (NULL to a value); the run's identity and queue time
    -- never change.
    IF TG_OP = 'UPDATE' AND NEW.id = OLD.id AND NEW.bucket = OLD.bucket AND NEW.queued_at = OLD.queued_at
            AND (OLD.retention_mode IS NULL OR NEW.retention_mode IS NOT DISTINCT FROM OLD.retention_mode)
            AND (OLD.retention_days IS NULL OR NEW.retention_days IS NOT DISTINCT FROM OLD.retention_days) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'evidence_store_sync_runs: a run''s bucket, queue time and the retention it read are evidence '
        '(% refused)', TG_OP USING ERRCODE = 'insufficient_privilege';
END;
$$;
"""

RETENTION_FLOOR_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION public.evidence_store_retention_floors_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- The database clock dates every floor; a bucket's floors are appended in time order.
        NEW.set_at := pg_catalog.now();
        NEW.created_at := NEW.set_at;
        IF EXISTS (SELECT 1 FROM public.evidence_store_retention_floors f
                   WHERE f.bucket = NEW.bucket AND f.set_at >= NEW.set_at) THEN
            RAISE EXCEPTION 'evidence_store_retention_floors: a floor is later than every floor of its bucket '
                            '(INSERT refused)' USING ERRCODE = 'insufficient_privilege';
        END IF;
        -- After the bucket's first floor (its first sync's), only an administrator, with a reason.
        IF (NEW.set_by IS NULL OR NEW.reason IS NULL OR pg_catalog.btrim(NEW.reason) = '')
                AND EXISTS (SELECT 1 FROM public.evidence_store_retention_floors f WHERE f.bucket = NEW.bucket) THEN
            RAISE EXCEPTION 'evidence_store_retention_floors: the floor changes only by an administrator with a '
                            'reason (INSERT refused)' USING ERRCODE = 'insufficient_privilege';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'evidence_store_retention_floors: floors are appended, never changed or deleted (% refused)',
        TG_OP USING ERRCODE = 'insufficient_privilege';
END;
$$;
"""


PENTEST_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION public.pentest_findings_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        IF EXISTS (SELECT 1 FROM public.pentest_findings WHERE source_file LIKE 'evidence-store:%') THEN
            RAISE EXCEPTION 'pentest_findings: the evidence store''s findings are evidence (TRUNCATE refused)'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        RETURN NULL;
    END IF;
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        IF OLD.source_file LIKE 'evidence-store:%' THEN
            RAISE EXCEPTION 'pentest_findings: the evidence store''s findings are evidence (DELETE refused)'
                USING ERRCODE = 'insufficient_privilege';
        END IF;
        RETURN OLD;
    END IF;
    IF (OLD.source_file LIKE 'evidence-store:%' OR NEW.source_file LIKE 'evidence-store:%')
            AND ROW(NEW.id, NEW.scan_id, NEW.layer, NEW.repo, NEW.severity, NEW.summary, NEW.description,
                    NEW.remediation, NEW.soc2_controls::text, NEW.file_path, NEW.source_file, NEW."timestamp",
                    NEW.other_data::text, NEW.created_at)
                IS DISTINCT FROM ROW(OLD.id, OLD.scan_id, OLD.layer, OLD.repo, OLD.severity, OLD.summary,
                    OLD.description, OLD.remediation, OLD.soc2_controls::text, OLD.file_path, OLD.source_file,
                    OLD."timestamp", OLD.other_data::text, OLD.created_at) THEN
        RAISE EXCEPTION 'pentest_findings: the evidence store''s findings are evidence (UPDATE refused)'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;
"""


def guard_sql(table: str, function_sql: str) -> list[str]:
    """The guard function of ``table`` and its row and TRUNCATE triggers."""
    return [
        function_sql,
        f"REVOKE EXECUTE ON FUNCTION public.{table}_guard() FROM PUBLIC",
        f"CREATE TRIGGER {table}_guard BEFORE INSERT OR UPDATE OR DELETE ON public.{table} "
        f"FOR EACH ROW EXECUTE FUNCTION public.{table}_guard()",
        f"CREATE TRIGGER {table}_no_truncate BEFORE TRUNCATE ON public.{table} "
        f"FOR EACH STATEMENT EXECUTE FUNCTION public.{table}_guard()",
    ]


def _ts(name, nullable=True, default_now=False):
    kwargs = {"nullable": nullable}
    if default_now:
        kwargs["server_default"] = sa.text("now()")
    return sa.Column(name, sa.DateTime(timezone=True), **kwargs)


def _in(column, values):
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


# The guard of migration 018, plus: a store import (no submitter, a path, a
# store object) names its own session's file like a repository import, and an
# UPDATE keeps store_object_id.
VERSION_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION public.decision_log_transcripts_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    base TEXT;
    cut INTEGER;
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- A repository import (no submitter, a path, a commit) or a store import (no
        -- submitter, a path, a store object) names its own session's file:
        -- <timestamp>_<session id>.jsonl (or its .manifest.json).
        IF NEW.submitted_by IS NULL AND NEW.source_path IS NOT NULL
                AND (NEW.source_commit IS NOT NULL OR NEW.store_object_id IS NOT NULL) THEN
            base := pg_catalog.regexp_replace(NEW.source_path, '^.*/', '');
            base := pg_catalog.regexp_replace(base, '[.]manifest[.]json$', '');
            cut := pg_catalog.strpos(base, '_');
            IF base !~ '[.]jsonl$' OR cut = 0
                    OR pg_catalog.substr(base, cut + 1, pg_catalog.length(base) - cut - 6) <> NEW.session_id THEN
                RAISE EXCEPTION 'decision_log_transcripts: repository path % is not session %''s file',
                    NEW.source_path, NEW.session_id USING ERRCODE = 'insufficient_privilege';
            END IF;
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.status = 'current'
            AND ((NEW.status = 'superseded' AND NEW.reason IS NOT NULL AND NEW.content_gz IS NOT NULL)
                 OR (NEW.status = 'current' AND NEW.reason IS NOT DISTINCT FROM OLD.reason
                     AND NEW.content_gz IS NOT DISTINCT FROM OLD.content_gz))
            AND NEW.id = OLD.id AND NEW.session_id = OLD.session_id
            AND NEW.content_sha256 IS NOT DISTINCT FROM OLD.content_sha256
            AND NEW.content_bytes IS NOT DISTINCT FROM OLD.content_bytes
            AND NEW.entry_count = OLD.entry_count
            AND (OLD.entries_sha256 IS NULL OR NEW.entries_sha256 = OLD.entries_sha256)
            AND NEW.received_at = OLD.received_at
            AND NEW.submitted_by IS NOT DISTINCT FROM OLD.submitted_by
            AND NEW.source_path IS NOT DISTINCT FROM OLD.source_path
            AND NEW.source_commit IS NOT DISTINCT FROM OLD.source_commit
            AND NEW.store_object_id IS NOT DISTINCT FROM OLD.store_object_id THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'decision_log_transcripts: versions are history; only a current version may become '
                    'superseded (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
"""


def upgrade():
    op.create_table(
        "evidence_store_sync_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("bucket", sa.String(63), nullable=False),
        sa.Column("trigger_type", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("triggered_by_team_member_id", sa.String(36), sa.ForeignKey("team_members.id")),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        _ts("queued_at", nullable=False, default_now=True),
        _ts("started_at"),
        _ts("finished_at"),
        sa.Column("counts", sa.JSON),
        sa.Column("details", sa.JSON),
        sa.Column("error_message", sa.Text),
        sa.Column("retention_mode", sa.String(16)),
        sa.Column("retention_days", sa.Integer),
        _ts("heartbeat_at"),
        sa.Column("executor_token", sa.String(36)),
    )
    op.create_index("ix_evidence_store_sync_runs_queued", "evidence_store_sync_runs", ["bucket", "queued_at"])
    op.create_index(
        "uq_evidence_store_sync_runs_one_active", "evidence_store_sync_runs", ["bucket"], unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
        sqlite_where=sa.text("status IN ('queued', 'running')"),
    )

    op.create_table(
        "evidence_store_objects",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("bucket", sa.String(63), nullable=False),
        sa.Column("key", sa.String(3072), nullable=False),
        sa.Column("key_escaped", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("version_id", sa.String(1024), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("sha256", sa.String(64)),
        sa.Column("composite_checksum", sa.String(64)),
        sa.Column("size", sa.BigInteger, nullable=False),
        sa.Column("etag", sa.String(255)),
        _ts("last_modified"),
        sa.Column("content_type", sa.String(255)),
        sa.Column("object_metadata", sa.JSON),
        sa.Column("lock_mode", sa.String(16)),
        _ts("retain_until"),
        sa.Column("sync_run_id", sa.String(36), sa.ForeignKey("evidence_store_sync_runs.id")),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("import_info", sa.JSON),
        sa.Column("detail", sa.Text),
        _ts("erased_at"),
        sa.Column("erased_by", sa.String(36), sa.ForeignKey("team_members.id")),
        sa.Column("erasure_reason", sa.Text),
        _ts("acknowledged_at"),
        sa.Column("acknowledged_by", sa.String(36), sa.ForeignKey("team_members.id")),
        sa.Column("acknowledgement_reason", sa.Text),
        sa.Column("acknowledged_from", sa.String(16)),
        _ts("created_at", nullable=False, default_now=True),
        _ts("updated_at", nullable=False, default_now=True),
        sa.UniqueConstraint("bucket", "key", "key_escaped", "version_id", name="uq_evidence_store_objects_version"),
        sa.CheckConstraint(_in("kind", OBJECT_KINDS), name="ck_evidence_store_objects_kind"),
        sa.CheckConstraint(_in("status", OBJECT_STATUSES), name="ck_evidence_store_objects_status"),
    )
    op.create_index("ix_evidence_store_objects_kind_status", "evidence_store_objects", ["kind", "status"])

    op.create_table(
        "evidence_store_retention_floors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("bucket", sa.String(63), nullable=False),
        sa.Column("days", sa.Integer, nullable=False),
        _ts("set_at", nullable=False, default_now=True),
        sa.Column("set_by", sa.String(36), sa.ForeignKey("team_members.id")),
        sa.Column("reason", sa.Text, nullable=False),
        _ts("created_at", nullable=False, default_now=True),
        sa.CheckConstraint("days > 0", name="ck_evidence_store_retention_floors_days"),
    )
    op.create_index("ix_evidence_store_retention_floors_bucket", "evidence_store_retention_floors",
                    ["bucket", "set_at"])

    op.create_table(
        "evidence_documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("store_object_id", sa.String(36), sa.ForeignKey("evidence_store_objects.id"),
                  nullable=False, unique=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("key", sa.String(1024), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size", sa.BigInteger, nullable=False),
        sa.Column("content_type", sa.String(255)),
        _ts("created_at", nullable=False, default_now=True),
        sa.CheckConstraint(_in("kind", DOCUMENT_KINDS), name="ck_evidence_documents_kind"),
    )
    op.create_index("ix_evidence_documents_kind", "evidence_documents", ["kind", "created_at"])

    op.create_table(
        "evidence_document_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("document_id", sa.String(36), sa.ForeignKey("evidence_documents.id"), nullable=False),
        sa.Column("control_id", sa.String(36), sa.ForeignKey("controls.id", ondelete="CASCADE")),
        sa.Column("test_record_id", sa.String(36), sa.ForeignKey("test_records.id", ondelete="CASCADE")),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("team_members.id")),
        _ts("created_at", nullable=False, default_now=True),
        sa.CheckConstraint("(control_id IS NULL) <> (test_record_id IS NULL)",
                           name="ck_evidence_document_links_one_target"),
        sa.UniqueConstraint("document_id", "control_id", name="uq_evidence_document_links_control"),
        sa.UniqueConstraint("document_id", "test_record_id", name="uq_evidence_document_links_test"),
    )
    op.create_index("ix_evidence_document_links_control", "evidence_document_links", ["control_id"])
    op.create_index("ix_evidence_document_links_test", "evidence_document_links", ["test_record_id"])

    op.add_column("decision_log_transcripts", sa.Column(
        "store_object_id", sa.String(36), nullable=True,
        comment="Evidence-store object version this version was imported from"))
    # The partial index first (the table's one scan), then the foreign key: added NOT VALID (no scan)
    # and validated through that index.
    op.create_index("ix_decision_log_transcripts_store_object", "decision_log_transcripts", ["store_object_id"],
                    postgresql_where=sa.text("store_object_id IS NOT NULL"),
                    sqlite_where=sa.text("store_object_id IS NOT NULL"))
    postgres = op.get_bind().dialect.name == "postgresql"
    if postgres:
        op.execute(
            f"ALTER TABLE public.decision_log_transcripts ADD CONSTRAINT {STORE_OBJECT_FOREIGN_KEY} "
            "FOREIGN KEY (store_object_id) REFERENCES public.evidence_store_objects (id) "
            "DEFERRABLE INITIALLY IMMEDIATE NOT VALID")
        op.execute(f"ALTER TABLE public.decision_log_transcripts VALIDATE CONSTRAINT {STORE_OBJECT_FOREIGN_KEY}")

    if postgres:
        from importlib import import_module

        audit_table_sql = import_module("migrations.versions.016_audit_log_v2").audit_table_sql
        for table, digested in AUDITED.items():
            for statement in audit_table_sql(table, digested):
                op.execute(statement)
        op.execute(VERSION_GUARD_FUNCTION)
        for statement in guard_sql("evidence_store_objects", OBJECT_GUARD_FUNCTION) + \
                guard_sql("evidence_documents", DOCUMENT_GUARD_FUNCTION) + \
                guard_sql("evidence_store_sync_runs", SYNC_RUN_GUARD_FUNCTION) + \
                guard_sql("evidence_store_retention_floors", RETENTION_FLOOR_GUARD_FUNCTION) + \
                guard_sql("pentest_findings", PENTEST_GUARD_FUNCTION):
            op.execute(statement)


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        from importlib import import_module

        op.execute(import_module("migrations.versions.018_async_runs_and_transcripts").VERSION_GUARD_FUNCTION)
        op.execute(f"ALTER TABLE decision_log_transcripts DROP CONSTRAINT IF EXISTS {STORE_OBJECT_FOREIGN_KEY}")
        for table in GUARDED:
            op.execute(f"DROP TRIGGER IF EXISTS {table}_guard ON {table};")
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_truncate ON {table};")
            op.execute(f"DROP FUNCTION IF EXISTS public.{table}_guard();")
    op.drop_index("ix_decision_log_transcripts_store_object", table_name="decision_log_transcripts")
    op.drop_column("decision_log_transcripts", "store_object_id")
    for table in reversed(list(AUDITED)):
        op.execute(f"DROP TRIGGER IF EXISTS audit_{table} ON {table};")
        op.execute(f"DROP TRIGGER IF EXISTS audit_lock_{table} ON {table};")
    op.drop_table("evidence_document_links")
    op.drop_table("evidence_documents")
    op.drop_table("evidence_store_retention_floors")
    op.drop_table("evidence_store_objects")
    op.drop_table("evidence_store_sync_runs")
