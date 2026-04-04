"""Add vendors table and vendor_systems join table.

Revision ID: 005
Revises: 004
Create Date: 2026-04-03
"""
from alembic import op
import sqlalchemy as sa

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "vendors",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(50), server_default="active"),
        sa.Column("is_subprocessor", sa.Boolean, server_default="false"),
        sa.Column("classification", sa.JSON),
        sa.Column("locations", sa.JSON),
        sa.Column("group_name", sa.String(255)),
        sa.Column("purpose", sa.Text),
        sa.Column("website_url", sa.String(1000)),
        sa.Column("privacy_policy_url", sa.String(1000)),
        sa.Column("security_page_url", sa.String(1000)),
        sa.Column("tos_url", sa.String(1000)),
        sa.Column("certifications", sa.JSON),
        sa.Column("trustcloud_id", sa.String(36)),
        sa.Column("other_data", sa.JSON, server_default="{}"),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
    )

    op.create_table(
        "vendor_systems",
        sa.Column("vendor_id", sa.String(36), sa.ForeignKey("vendors.id"), primary_key=True),
        sa.Column("system_id", sa.String(36), sa.ForeignKey("systems.id"), primary_key=True),
    )


def downgrade():
    op.drop_table("vendor_systems")
    op.drop_table("vendors")
