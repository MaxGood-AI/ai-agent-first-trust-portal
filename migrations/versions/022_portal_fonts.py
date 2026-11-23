"""Portal fonts: a heading font and a text font.

- ``portal_settings.heading_font`` and ``portal_settings.text_font``: a plain
  CSS ``font-family`` list each (validated by the settings service); NULL
  means the default system stack, so existing installations render as before.

Expand-only: two nullable columns that the previous release never reads, so it
runs against the new schema. The audit trigger on ``portal_settings`` records
every column through ``to_jsonb``, so the new columns are audited without a
trigger change (neither is a digested column).
"""

from alembic import op
import sqlalchemy as sa

revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("portal_settings", sa.Column(
        "heading_font", sa.String(300), nullable=True,
        comment="CSS font-family list for headings; NULL = default stack"))
    op.add_column("portal_settings", sa.Column(
        "text_font", sa.String(300), nullable=True,
        comment="CSS font-family list for text; NULL = default stack"))


def downgrade():
    op.drop_column("portal_settings", "text_font")
    op.drop_column("portal_settings", "heading_font")
