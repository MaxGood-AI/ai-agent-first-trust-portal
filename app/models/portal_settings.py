"""Portal settings model — single-row table for configurable portal data."""

from app.models import db


class PortalSettings(db.Model):
    __tablename__ = "portal_settings"

    id = db.Column(db.Integer, primary_key=True, default=1)
    # Company info (#646)
    company_legal_name = db.Column(db.String(255))
    company_brand_name = db.Column(db.String(255))
    contact_email = db.Column(db.String(255))
    physical_address = db.Column(db.Text)
    website_url = db.Column(db.String(1000))
    # SOC 2 journey (#650)
    soc2_current_stage = db.Column(db.String(50), server_default="not_started")
    soc2_stage_dates = db.Column(db.JSON, server_default="{}")
    # Legal page (#649)
    legal_content_md = db.Column(db.Text)
    legal_external_url = db.Column(db.String(1000))
    # AI transparency (#647)
    ai_transparency_md = db.Column(db.Text)
    # Metadata
    updated_at = db.Column(db.DateTime(timezone=True))
    updated_by = db.Column(db.String(36))
