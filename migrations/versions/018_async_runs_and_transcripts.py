"""Asynchronous collector runs and replaceable decision-log transcripts.

- Collector runs are queued (``status = 'queued'``) and executed by the
  single scheduler leader. A partial unique index allows at most one queued
  or running run per collector. Runs left in ``running``/``queued`` by a
  previous release are closed as failures first so the index can be built.
- ``decision_log_sessions`` gains ``content_sha256`` and ``content_bytes`` (the
  stored transcript's digest and size) and ``replaced_at``, so a later, longer
  export of a session replaces the stored one and an identical re-upload is
  a no-op. Constant-default columns are metadata-only changes.
- ``pentest_findings.source_file`` is indexed: each pentest evidence file is
  authoritative for its findings, and single-file imports look them up by file.
- ``collector_run.heartbeat_at`` / ``executor_token``: the executing process
  refreshes the heartbeat while it holds the run's lock; the reaper closes a
  run only when its heartbeat is stale and its lock is free, and only the
  owning executor (by token) may record the run's result.
- ``portal_settings.public_sections``: which public trust-portal sections are
  published (NULL = the default set, which leaves the risk register private).
- ``decision_log_transcripts``: every received version of a session's
  transcript (current, superseded by a longer export that extends it or by
  the evidence repository's version in a conflict, or rejected because it
  does not extend the stored one), audited, with each version's entry count
  and entries digest (``entries_sha256``); superseded and rejected versions
  keep their content (gzip) for review.
- ``decision_log_sessions`` gains ``repository_entries`` (the leading
  stored entries the evidence repository supplied) and ``conflict_at`` /
  ``conflict_detail`` (a repository version replaced entries submitted
  through the API): nullable columns without defaults, metadata-only.
- The foreign key from ``decision_log_entries`` to ``decision_log_sessions``
  is named ``fk_decision_log_entries_session`` and made ``DEFERRABLE
  INITIALLY IMMEDIATE`` (a catalog change; no row is read or rewritten), so
  an import writes a new session's entries before its audited session row
  and holds the audit chain's lock only for the audited rows.

Revision ID: 018
Revises: 017
Create Date: 2026-09-28
"""

from alembic import op
import sqlalchemy as sa

revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None

# Name the entries' foreign key (whatever name it was created with) and make it
# deferrable; it stays checked immediately unless a transaction defers it.
ENTRY_FOREIGN_KEY_DEFERRABLE = """
DO $$
DECLARE
    fk_name TEXT;
BEGIN
    SELECT c.conname INTO fk_name FROM pg_catalog.pg_constraint AS c
     WHERE c.conrelid = 'public.decision_log_entries'::regclass AND c.contype = 'f'
       AND c.confrelid = 'public.decision_log_sessions'::regclass;
    IF fk_name IS NULL THEN
        RAISE EXCEPTION 'decision_log_entries has no foreign key to decision_log_sessions';
    END IF;
    IF fk_name <> 'fk_decision_log_entries_session' THEN
        EXECUTE pg_catalog.format(
            'ALTER TABLE public.decision_log_entries RENAME CONSTRAINT %I TO fk_decision_log_entries_session',
            fk_name);
    END IF;
    ALTER TABLE public.decision_log_entries
        ALTER CONSTRAINT fk_decision_log_entries_session DEFERRABLE INITIALLY IMMEDIATE;
END;
$$;
"""

ENTRY_FOREIGN_KEY_IMMEDIATE = """
ALTER TABLE public.decision_log_entries
    ALTER CONSTRAINT fk_decision_log_entries_session NOT DEFERRABLE;
ALTER TABLE public.decision_log_entries
    RENAME CONSTRAINT fk_decision_log_entries_session TO decision_log_entries_session_id_fkey;
"""


def upgrade():
    op.execute(
        "UPDATE collector_run SET status = 'failure', finished_at = now(), "
        "error_message = COALESCE(error_message || ' ', '') || "
        "'Run interrupted before the asynchronous runner was installed.' "
        "WHERE status IN ('running', 'queued')"
    )
    op.create_index(
        "uq_collector_run_one_active",
        "collector_run",
        ["collector_config_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
        sqlite_where=sa.text("status IN ('queued', 'running')"),
    )

    op.add_column("decision_log_sessions", sa.Column(
        "content_sha256", sa.String(64), nullable=True,
        comment="SHA-256 of the stored transcript bytes"))
    op.add_column("decision_log_sessions", sa.Column(
        "content_bytes", sa.BigInteger, nullable=True,
        comment="Size in bytes of the stored transcript"))
    op.add_column("decision_log_sessions", sa.Column(
        "replaced_at", sa.DateTime(timezone=True), nullable=True,
        comment="When a longer export last replaced the stored transcript"))
    op.add_column("decision_log_sessions", sa.Column(
        "repository_entries", sa.Integer, nullable=True,
        comment="Leading stored entries supplied by the evidence repository (NULL: not recorded)"))
    op.add_column("decision_log_sessions", sa.Column(
        "conflict_at", sa.DateTime(timezone=True), nullable=True,
        comment="When a repository version last replaced entries submitted through the API"))
    op.add_column("decision_log_sessions", sa.Column(
        "conflict_detail", sa.Text, nullable=True, comment="What the last conflict replaced"))
    if op.get_bind().dialect.name == "postgresql":
        op.execute(ENTRY_FOREIGN_KEY_DEFERRABLE)

    op.create_index("ix_pentest_findings_source_file", "pentest_findings", ["source_file"])

    op.add_column("portal_settings", sa.Column(
        "public_sections", sa.JSON, nullable=True,
        comment="Enabled public sections; NULL = default (risks private)"))

    op.add_column("collector_run", sa.Column(
        "heartbeat_at", sa.DateTime(timezone=True), nullable=True,
        comment="Refreshed by the executing process while it holds the run's lock"))
    op.add_column("collector_run", sa.Column(
        "executor_token", sa.String(36), nullable=True,
        comment="Identifies the executor allowed to record this run's result"))

    op.create_table(
        "decision_log_transcripts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("decision_log_sessions.id"), nullable=False),
        sa.Column("status", sa.String(16), nullable=False,
                  comment="current | superseded | rejected"),
        sa.Column("content_sha256", sa.String(64), nullable=True),
        sa.Column("content_bytes", sa.BigInteger, nullable=True),
        sa.Column("entry_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("entries_sha256", sa.String(64), nullable=True,
                  comment="Digest of the version's entries"),
        sa.Column("content_gz", sa.LargeBinary, nullable=True,
                  comment="gzip of the version's content (superseded and rejected versions)"),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("source_path", sa.String(500), nullable=True),
        sa.Column("source_commit", sa.String(64), nullable=True,
                  comment="Evidence-repository commit a git sync read it at"),
        sa.Column("submitted_by", sa.String(36), sa.ForeignKey("team_members.id"), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.create_index("ix_decision_log_transcripts_session", "decision_log_transcripts",
                    ["session_id", "received_at"])
    if op.get_bind().dialect.name == "postgresql":
        for statement in _audit_sql("decision_log_transcripts", ("content_gz",)):
            op.execute(statement)
        op.execute(VERSION_GUARD_FUNCTION)
        op.execute("REVOKE EXECUTE ON FUNCTION public.decision_log_transcripts_guard() FROM PUBLIC")
        op.execute("CREATE TRIGGER decision_log_transcripts_guard BEFORE INSERT OR UPDATE OR DELETE "
                   "ON public.decision_log_transcripts FOR EACH ROW "
                   "EXECUTE FUNCTION public.decision_log_transcripts_guard()")
        op.execute("CREATE TRIGGER decision_log_transcripts_no_truncate BEFORE TRUNCATE "
                   "ON public.decision_log_transcripts FOR EACH STATEMENT "
                   "EXECUTE FUNCTION public.decision_log_transcripts_guard()")


# Transcript versions only ever grow into history: the one permitted change is
# a CURRENT version becoming SUPERSEDED (keeping its identity, counts and
# digests; gaining its content and reason, both required), besides filling a
# current version's missing entries digest. A superseded version is frozen
# entirely. Every other UPDATE, every DELETE and TRUNCATE is refused for every
# role.
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
        -- A repository import (no submitter, a path, a commit) names its own session's file:
        -- <timestamp>_<session id>.jsonl (or its .manifest.json).
        IF NEW.submitted_by IS NULL AND NEW.source_path IS NOT NULL AND NEW.source_commit IS NOT NULL THEN
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
            AND NEW.source_commit IS NOT DISTINCT FROM OLD.source_commit THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'decision_log_transcripts: versions are history; only a current version may become '
                    'superseded (% refused)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
"""


def _audit_sql(table, digested):
    from importlib import import_module

    return import_module("migrations.versions.016_audit_log_v2").audit_table_sql(table, digested)


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS decision_log_transcripts_guard ON decision_log_transcripts;")
    op.execute("DROP TRIGGER IF EXISTS decision_log_transcripts_no_truncate ON decision_log_transcripts;")
    op.execute("DROP FUNCTION IF EXISTS decision_log_transcripts_guard();")
    op.execute("DROP TRIGGER IF EXISTS audit_decision_log_transcripts ON decision_log_transcripts;")
    op.execute("DROP TRIGGER IF EXISTS audit_lock_decision_log_transcripts ON decision_log_transcripts;")
    op.drop_table("decision_log_transcripts")
    op.drop_column("portal_settings", "public_sections")
    op.drop_column("collector_run", "executor_token")
    op.drop_column("collector_run", "heartbeat_at")
    op.drop_index("ix_pentest_findings_source_file", table_name="pentest_findings")
    if op.get_bind().dialect.name == "postgresql":
        op.execute(ENTRY_FOREIGN_KEY_IMMEDIATE)
    op.drop_column("decision_log_sessions", "conflict_detail")
    op.drop_column("decision_log_sessions", "conflict_at")
    op.drop_column("decision_log_sessions", "repository_entries")
    op.drop_column("decision_log_sessions", "replaced_at")
    op.drop_column("decision_log_sessions", "content_bytes")
    op.drop_column("decision_log_sessions", "content_sha256")
    op.drop_index("uq_collector_run_one_active", table_name="collector_run")
