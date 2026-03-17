"""Initial schema — all models.

Revision ID: 001
Revises:
Create Date: 2026-03-13
"""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "controls",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("state", sa.String(50), server_default="adopted"),
        sa.Column("trustcloud_id", sa.String(36)),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
    )

    op.create_table(
        "test_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("control_id", sa.String(36), sa.ForeignKey("controls.id"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("question", sa.Text),
        sa.Column("recommendation", sa.Text),
        sa.Column("status", sa.String(50), server_default="pending"),
        sa.Column("evidence_status", sa.String(50), server_default="missing"),
        sa.Column("last_executed_at", sa.DateTime),
        sa.Column("due_at", sa.DateTime),
        sa.Column("trustcloud_id", sa.String(36)),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
    )

    op.create_table(
        "evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("test_record_id", sa.String(36), sa.ForeignKey("test_records.id"), nullable=False),
        sa.Column("evidence_type", sa.String(50), nullable=False),
        sa.Column("url", sa.String(1000)),
        sa.Column("file_path", sa.String(500)),
        sa.Column("description", sa.Text),
        sa.Column("collected_at", sa.DateTime),
        sa.Column("collector_name", sa.String(100)),
        sa.Column("trustcloud_id", sa.String(36)),
        sa.Column("created_at", sa.DateTime),
    )

    op.create_table(
        "policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("version", sa.String(20), server_default="1.0"),
        sa.Column("file_path", sa.String(500)),
        sa.Column("status", sa.String(50), server_default="draft"),
        sa.Column("approved_at", sa.DateTime),
        sa.Column("approved_by", sa.String(255)),
        sa.Column("next_review_at", sa.DateTime),
        sa.Column("trustcloud_id", sa.String(36)),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
    )

    op.create_table(
        "decision_log_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("agent_type", sa.String(50), server_default="claude_code"),
        sa.Column("model", sa.String(100)),
        sa.Column("cwd", sa.String(500)),
        sa.Column("git_branch", sa.String(200)),
        sa.Column("started_at", sa.DateTime),
        sa.Column("ended_at", sa.DateTime),
        sa.Column("exit_reason", sa.String(50)),
        sa.Column("transcript_path", sa.String(500)),
        sa.Column("imported_at", sa.DateTime),
    )

    op.create_table(
        "decision_log_entries",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("session_id", sa.String(36), sa.ForeignKey("decision_log_sessions.id"), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("content_text", sa.Text),
        sa.Column("tool_calls", sa.Text),
        sa.Column("timestamp", sa.DateTime),
        sa.Column("message_id", sa.String(100)),
        sa.Column("is_verification", sa.Boolean, server_default=sa.text("false")),
    )

    op.create_table(
        "policy_versions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("file_path", sa.String(500), nullable=False),
        sa.Column("repo", sa.String(100), nullable=False),
        sa.Column("git_commit", sa.String(40), nullable=False),
        sa.Column("git_author", sa.String(255)),
        sa.Column("commit_message", sa.Text),
        sa.Column("content_hash", sa.String(64)),
        sa.Column("effective_at", sa.DateTime),
        sa.Column("imported_at", sa.DateTime),
    )


def downgrade():
    op.drop_table("policy_versions")
    op.drop_table("decision_log_entries")
    op.drop_table("decision_log_sessions")
    op.drop_table("policies")
    op.drop_table("evidence")
    op.drop_table("test_records")
    op.drop_table("controls")
