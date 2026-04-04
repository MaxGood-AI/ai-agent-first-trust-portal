"""Add policy_controls join table for Policy-to-Control M2M.

Revision ID: 006
Revises: 005
Create Date: 2026-04-04
"""
from alembic import op
import sqlalchemy as sa

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "policy_controls",
        sa.Column("policy_id", sa.String(36), sa.ForeignKey("policies.id"), primary_key=True),
        sa.Column("control_id", sa.String(36), sa.ForeignKey("controls.id"), primary_key=True),
    )


def downgrade():
    op.drop_table("policy_controls")
