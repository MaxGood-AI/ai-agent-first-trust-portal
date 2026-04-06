"""Add file storage columns to evidence table.

Revision ID: 013
Revises: 012
Create Date: 2026-04-06
"""

from alembic import op
import sqlalchemy as sa

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("evidence", sa.Column("file_data", sa.LargeBinary(), nullable=True))
    op.add_column("evidence", sa.Column("file_name", sa.String(255), nullable=True))
    op.add_column("evidence", sa.Column("file_mime_type", sa.String(100), nullable=True))


def downgrade():
    op.drop_column("evidence", "file_mime_type")
    op.drop_column("evidence", "file_name")
    op.drop_column("evidence", "file_data")
