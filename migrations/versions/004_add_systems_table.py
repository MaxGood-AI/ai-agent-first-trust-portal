"""Add systems table and system_id FK on test_records.

Revision ID: 004
Revises: 003
Create Date: 2026-04-03
"""
from alembic import op
import sqlalchemy as sa

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "systems",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("short_name", sa.String(100)),
        sa.Column("purpose", sa.Text),
        sa.Column("risk_score", sa.Float),
        sa.Column("system_type", sa.JSON),
        sa.Column("provider", sa.String(255)),
        sa.Column("data_classifications", sa.JSON),
        sa.Column("group_name", sa.String(255)),
        sa.Column("trustcloud_id", sa.String(36)),
        sa.Column("other_data", sa.JSON, server_default="{}"),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
    )

    op.add_column(
        "test_records",
        sa.Column("system_id", sa.String(36), sa.ForeignKey("systems.id"), nullable=True),
    )


def downgrade():
    op.drop_column("test_records", "system_id")
    op.drop_table("systems")
