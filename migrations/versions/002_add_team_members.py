"""Add team_members table and submitted_by FK on decision_log_sessions.

Revision ID: 002
Revises: 001
Create Date: 2026-03-17
"""
from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "team_members",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("api_key", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("is_active", sa.Boolean, server_default=sa.text("true"), nullable=False),
        sa.Column("is_compliance_admin", sa.Boolean, server_default=sa.text("false"), nullable=False),
        sa.Column("created_at", sa.DateTime),
    )

    op.add_column(
        "decision_log_sessions",
        sa.Column("submitted_by", sa.String(36),
                  sa.ForeignKey("team_members.id"), nullable=True),
    )


def downgrade():
    op.drop_column("decision_log_sessions", "submitted_by")
    op.drop_table("team_members")
