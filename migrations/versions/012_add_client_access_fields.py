"""Add client access fields to team_members for gated compliance reports.

Adds expires_at (optional expiry for client API keys) and company
(client's organization name) columns.

Revision ID: 012
Revises: 011
Create Date: 2026-04-05
"""
from alembic import op
import sqlalchemy as sa

revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("team_members", sa.Column("expires_at", sa.DateTime(timezone=True)))
    op.add_column("team_members", sa.Column("company", sa.String(255)))


def downgrade():
    op.drop_column("team_members", "company")
    op.drop_column("team_members", "expires_at")
