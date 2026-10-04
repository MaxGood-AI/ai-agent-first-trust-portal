"""Git sources: governance and evidence repositories pulled by the portal.

Creates ``git_sources``, ``git_source_files``, ``git_file_versions``,
``git_commits`` and ``git_sync_runs`` (all audited; stored credentials and
file content are recorded in the audit log as digests only).

Revision ID: 019
Revises: 018
Create Date: 2026-09-28
"""

from alembic import op
import sqlalchemy as sa

revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None

AUDITED = {
    "git_sources": ("encrypted_credentials",),
    "git_source_files": (),
    "git_file_versions": ("content",),
    "git_commits": (),
    "git_sync_runs": (),
}


def _ts(name, nullable=True, default_now=False):
    kwargs = {"nullable": nullable}
    if default_now:
        kwargs["server_default"] = sa.text("now()")
    return sa.Column(name, sa.DateTime(timezone=True), **kwargs)


def upgrade():
    op.create_table(
        "git_sources",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("repository", sa.String(500), nullable=False),
        sa.Column("branch", sa.String(255), nullable=False, server_default="main"),
        sa.Column("region", sa.String(32)),
        sa.Column("credential_mode", sa.String(32), nullable=False, server_default="runtime_role"),
        sa.Column("encrypted_credentials", sa.LargeBinary),
        sa.Column("path_mappings", sa.JSON),
        sa.Column("options", sa.JSON),
        sa.Column("schedule_cron", sa.String(64)),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("last_synced_commit", sa.String(64)),
        _ts("last_synced_at"),
        sa.Column("last_sync_status", sa.String(16)),
        _ts("created_at", nullable=False, default_now=True),
        _ts("updated_at", nullable=False, default_now=True),
        sa.Column("created_by_id", sa.String(36), sa.ForeignKey("team_members.id")),
        sa.Column("updated_by_id", sa.String(36), sa.ForeignKey("team_members.id")),
        sa.CheckConstraint("role IN ('governance', 'evidence')", name="ck_git_sources_role"),
        sa.CheckConstraint("provider IN ('codecommit', 'github', 'local')", name="ck_git_sources_provider"),
    )

    op.create_table(
        "git_source_files",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("git_sources.id"), nullable=False),
        sa.Column("path", sa.String(1024), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("blob_id", sa.String(64)),
        sa.Column("size", sa.BigInteger),
        sa.Column("status", sa.String(16), nullable=False, server_default="ok"),
        sa.Column("status_detail", sa.Text),
        sa.Column("last_commit_id", sa.String(64)),
        sa.Column("current_version_id", sa.String(36)),
        _ts("updated_at", nullable=False, default_now=True),
        sa.UniqueConstraint("source_id", "path", name="uq_git_source_files_path"),
    )
    op.create_index("ix_git_source_files_kind", "git_source_files", ["source_id", "kind"])

    op.create_table(
        "git_file_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("file_id", sa.String(36), sa.ForeignKey("git_source_files.id"), nullable=False),
        sa.Column("commit_id", sa.String(64), nullable=False),
        sa.Column("blob_id", sa.String(64), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size", sa.BigInteger, nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        _ts("created_at", nullable=False, default_now=True),
        sa.UniqueConstraint("file_id", "blob_id", name="uq_git_file_versions_blob"),
    )

    op.create_table(
        "git_commits",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("git_sources.id"), nullable=False),
        sa.Column("commit_id", sa.String(64), nullable=False),
        sa.Column("parent_ids", sa.JSON),
        sa.Column("author_name", sa.String(255)),
        sa.Column("author_email", sa.String(255)),
        _ts("authored_at"),
        sa.Column("committer_name", sa.String(255)),
        sa.Column("committer_email", sa.String(255)),
        _ts("committed_at"),
        sa.Column("message", sa.Text),
        sa.Column("paths", sa.JSON),
        _ts("recorded_at", nullable=False, default_now=True),
        sa.UniqueConstraint("source_id", "commit_id", name="uq_git_commits_commit"),
    )
    op.create_index("ix_git_commits_committed_at", "git_commits", ["source_id", "committed_at"])

    op.create_table(
        "git_sync_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_id", sa.String(36), sa.ForeignKey("git_sources.id"), nullable=False),
        sa.Column("trigger_type", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("triggered_by_team_member_id", sa.String(36), sa.ForeignKey("team_members.id")),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("from_commit", sa.String(64)),
        sa.Column("to_commit", sa.String(64)),
        _ts("queued_at", nullable=False, default_now=True),
        _ts("started_at"),
        _ts("finished_at"),
        sa.Column("files_changed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("counts", sa.JSON),
        sa.Column("details", sa.JSON),
        sa.Column("error_message", sa.Text),
        _ts("heartbeat_at"),
        sa.Column("executor_token", sa.String(36)),
    )
    op.create_index("ix_git_sync_runs_source", "git_sync_runs", ["source_id", "queued_at"])
    op.create_index(
        "uq_git_sync_runs_one_active", "git_sync_runs", ["source_id"], unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
        sqlite_where=sa.text("status IN ('queued', 'running')"),
    )

    if op.get_bind().dialect.name == "postgresql":
        from importlib import import_module

        audit_table_sql = import_module("migrations.versions.016_audit_log_v2").audit_table_sql
        for table, digested in AUDITED.items():
            for statement in audit_table_sql(table, digested):
                op.execute(statement)


def downgrade():
    for table in reversed(list(AUDITED)):
        op.execute(f"DROP TRIGGER IF EXISTS audit_{table} ON {table};")
        op.execute(f"DROP TRIGGER IF EXISTS audit_lock_{table} ON {table};")
    op.drop_table("git_sync_runs")
    op.drop_table("git_commits")
    op.drop_table("git_file_versions")
    op.drop_table("git_source_files")
    op.drop_table("git_sources")
