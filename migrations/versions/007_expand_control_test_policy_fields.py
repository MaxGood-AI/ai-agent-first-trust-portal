"""Expand controls, test_records, and policies with missing fields.

Promotes fields from other_data to proper columns. The BaseLoader's
runtime column introspection automatically picks up new columns.

Cards: #621 (controls), #622 (test_records), #623 (policies)

Revision ID: 007
Revises: 006
Create Date: 2026-04-04
"""
from alembic import op
import sqlalchemy as sa

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade():
    # --- Controls (#621) ---
    op.add_column("controls", sa.Column("control_id_short", sa.String(50)))
    op.add_column("controls", sa.Column("frequency", sa.String(50)))
    op.add_column("controls", sa.Column("maturity_level", sa.Integer))
    op.add_column("controls", sa.Column("group_name", sa.String(255)))
    op.add_column("controls", sa.Column("owner_id", sa.String(36)))
    op.add_column("controls", sa.Column("owner_name", sa.String(255)))
    op.add_column("controls", sa.Column("soc2_references", sa.JSON))
    op.add_column("controls", sa.Column("source_category", sa.String(255)))

    # --- TestRecords (#622) --- system_id already exists from migration 004
    op.add_column("test_records", sa.Column("test_type", sa.String(50)))
    op.add_column("test_records", sa.Column("execution_status", sa.String(50)))
    op.add_column("test_records", sa.Column("execution_outcome", sa.String(50)))
    op.add_column("test_records", sa.Column("finding", sa.Text))
    op.add_column("test_records", sa.Column("comment", sa.Text))
    op.add_column("test_records", sa.Column("owner_id", sa.String(36)))
    op.add_column("test_records", sa.Column("owner_name", sa.String(255)))

    # --- Policies (#623) ---
    op.add_column("policies", sa.Column("short_name", sa.String(50)))
    op.add_column("policies", sa.Column("security_group", sa.String(255)))
    op.add_column("policies", sa.Column("effective_date", sa.DateTime))
    op.add_column("policies", sa.Column("group_name", sa.String(255)))
    op.add_column("policies", sa.Column("owner_id", sa.String(36)))
    op.add_column("policies", sa.Column("owner_name", sa.String(255)))
    op.add_column("policies", sa.Column("parent_policy_id", sa.String(36),
                                        sa.ForeignKey("policies.id"), nullable=True))
    op.add_column("policies", sa.Column("notes", sa.Text))


def downgrade():
    # --- Policies ---
    op.drop_column("policies", "notes")
    op.drop_column("policies", "parent_policy_id")
    op.drop_column("policies", "owner_name")
    op.drop_column("policies", "owner_id")
    op.drop_column("policies", "group_name")
    op.drop_column("policies", "effective_date")
    op.drop_column("policies", "security_group")
    op.drop_column("policies", "short_name")

    # --- TestRecords ---
    op.drop_column("test_records", "owner_name")
    op.drop_column("test_records", "owner_id")
    op.drop_column("test_records", "comment")
    op.drop_column("test_records", "finding")
    op.drop_column("test_records", "execution_outcome")
    op.drop_column("test_records", "execution_status")
    op.drop_column("test_records", "test_type")

    # --- Controls ---
    op.drop_column("controls", "source_category")
    op.drop_column("controls", "soc2_references")
    op.drop_column("controls", "owner_name")
    op.drop_column("controls", "owner_id")
    op.drop_column("controls", "group_name")
    op.drop_column("controls", "maturity_level")
    op.drop_column("controls", "frequency")
    op.drop_column("controls", "control_id_short")
