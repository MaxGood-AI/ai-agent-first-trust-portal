"""Add other_data JSON column to core entity tables.

Stores unmapped fields from data imports so no source data is ever discarded.

Revision ID: 003
Revises: 002
Create Date: 2026-04-03
"""
from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("controls", sa.Column("other_data", sa.JSON, server_default="{}"))
    op.add_column("test_records", sa.Column("other_data", sa.JSON, server_default="{}"))
    op.add_column("policies", sa.Column("other_data", sa.JSON, server_default="{}"))
    op.add_column("evidence", sa.Column("other_data", sa.JSON, server_default="{}"))


def downgrade():
    op.drop_column("evidence", "other_data")
    op.drop_column("policies", "other_data")
    op.drop_column("test_records", "other_data")
    op.drop_column("controls", "other_data")
