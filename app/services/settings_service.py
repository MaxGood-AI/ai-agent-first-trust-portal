"""Portal settings service — read/write configurable portal data."""

from flask import current_app

from app.models import db
from app.models.portal_settings import PortalSettings

SOC2_STAGES = [
    {"key": "not_started", "label": "Not Started", "has_date": False},
    {"key": "policies_established", "label": "Policies & Controls Established", "has_date": False},
    {"key": "collecting_point_in_time", "label": "Collecting Point-in-Time Evidence", "has_date": False},
    {"key": "auditor_engaged", "label": "Auditor Engaged", "has_date": False},
    {"key": "type_1_completed", "label": "Type 1 Audit Completed", "has_date": True},
    {"key": "collecting_continuous", "label": "Collecting Continuous Evidence", "has_date": False},
    {"key": "type_2_completed", "label": "Type 2 Audit Completed", "has_date": True},
]


def get_portal_settings():
    """Return merged settings: DB overrides > env var defaults."""
    db_settings = db.session.get(PortalSettings, 1)

    company_legal_name = (
        db_settings.company_legal_name if db_settings and db_settings.company_legal_name
        else current_app.config.get("PORTAL_COMPANY_NAME", "Your Company")
    )
    company_brand_name = (
        db_settings.company_brand_name if db_settings and db_settings.company_brand_name
        else current_app.config.get("PORTAL_BRAND_NAME", "Your Brand")
    )
    contact_email = (
        db_settings.contact_email if db_settings and db_settings.contact_email
        else current_app.config.get("PORTAL_CONTACT_EMAIL", "compliance@example.com")
    )
    physical_address = (
        db_settings.physical_address if db_settings and db_settings.physical_address
        else ""
    )
    website_url = (
        db_settings.website_url if db_settings and db_settings.website_url
        else ""
    )

    # SOC 2 journey (#650)
    stage_key = (
        db_settings.soc2_current_stage if db_settings and db_settings.soc2_current_stage
        else "not_started"
    )
    stage_dates = (
        db_settings.soc2_stage_dates if db_settings and db_settings.soc2_stage_dates
        else {}
    )
    current_index = next(
        (i for i, s in enumerate(SOC2_STAGES) if s["key"] == stage_key), 0
    )
    soc2_stages = [
        {
            **stage,
            "status": (
                "completed" if i < current_index
                else "current" if i == current_index
                else "future"
            ),
            "date": stage_dates.get(stage["key"]),
        }
        for i, stage in enumerate(SOC2_STAGES)
    ]

    # Content pages (#649, #647)
    legal_content_md = (
        db_settings.legal_content_md if db_settings and db_settings.legal_content_md
        else None
    )
    legal_external_url = (
        db_settings.legal_external_url if db_settings and db_settings.legal_external_url
        else None
    )
    ai_transparency_md = (
        db_settings.ai_transparency_md if db_settings and db_settings.ai_transparency_md
        else None
    )

    return {
        "company_legal_name": company_legal_name,
        "company_brand_name": company_brand_name,
        "contact_email": contact_email,
        "physical_address": physical_address,
        "website_url": website_url,
        "soc2_current_stage": stage_key,
        "soc2_stage_dates": stage_dates,
        "soc2_stages": soc2_stages,
        "legal_content_md": legal_content_md,
        "legal_external_url": legal_external_url,
        "ai_transparency_md": ai_transparency_md,
    }


def update_portal_settings(data, updated_by=None):
    """Create or update the single portal_settings row."""
    settings = db.session.get(PortalSettings, 1)
    if not settings:
        settings = PortalSettings(id=1)

    allowed_fields = [
        "company_legal_name", "company_brand_name", "contact_email",
        "physical_address", "website_url",
        "soc2_current_stage", "soc2_stage_dates",
        "legal_content_md", "legal_external_url",
        "ai_transparency_md",
    ]
    for key in allowed_fields:
        if key in data:
            setattr(settings, key, data[key])

    if updated_by:
        settings.updated_by = updated_by
    settings.updated_at = db.func.now()
    db.session.merge(settings)
    db.session.commit()
    return settings
