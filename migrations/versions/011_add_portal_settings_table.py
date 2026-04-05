"""Add portal_settings table for configurable company data and content.

Includes columns for all Phase 2 cards:
- #646: Company info (legal name, brand, email, address, website)
- #650: SOC 2 journey stage tracking
- #649: Legal page content (privacy policy, terms, accessibility)
- #647: AI transparency statement content

Revision ID: 011
Revises: 010
Create Date: 2026-04-05
"""
from alembic import op
import sqlalchemy as sa

revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "portal_settings",
        sa.Column("id", sa.Integer, primary_key=True),
        # #646: Company info
        sa.Column("company_legal_name", sa.String(255)),
        sa.Column("company_brand_name", sa.String(255)),
        sa.Column("contact_email", sa.String(255)),
        sa.Column("physical_address", sa.Text),
        sa.Column("website_url", sa.String(1000)),
        # #650: SOC 2 journey
        sa.Column("soc2_current_stage", sa.String(50), server_default="not_started"),
        sa.Column("soc2_stage_dates", sa.JSON, server_default="{}"),
        # #649: Legal page
        sa.Column("legal_content_md", sa.Text),
        sa.Column("legal_external_url", sa.String(1000)),
        # #647: AI transparency
        sa.Column("ai_transparency_md", sa.Text),
        # Metadata
        sa.Column("updated_at", sa.DateTime(timezone=True)),
        sa.Column("updated_by", sa.String(36)),
        sa.CheckConstraint("id = 1", name="single_row_portal_settings"),
    )

    # Attach audit trigger (PostgreSQL only)
    op.execute("""
        CREATE TRIGGER audit_portal_settings
        AFTER INSERT OR UPDATE OR DELETE ON portal_settings
        FOR EACH ROW EXECUTE FUNCTION audit_trigger_func();
    """)


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS audit_portal_settings ON portal_settings;")
    op.drop_table("portal_settings")
