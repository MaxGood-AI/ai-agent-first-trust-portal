"""Add risk_register table.

Revision ID: 008
Revises: 007
Create Date: 2026-04-04
"""
from alembic import op
import sqlalchemy as sa

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "risk_register",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("likelihood", sa.Integer),
        sa.Column("impact", sa.Integer),
        sa.Column("risk_score", sa.Float),
        sa.Column("treatment", sa.String(50)),
        sa.Column("treatment_plan", sa.Text),
        sa.Column("status", sa.String(50), server_default="open"),
        sa.Column("owner_id", sa.String(36)),
        sa.Column("owner_name", sa.String(255)),
        sa.Column("group_name", sa.String(255)),
        sa.Column("review_date", sa.DateTime),
        sa.Column("trustcloud_id", sa.String(36)),
        sa.Column("other_data", sa.JSON, server_default="{}"),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
    )


def downgrade():
    op.drop_table("risk_register")
