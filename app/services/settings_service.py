"""Portal settings service — read/write configurable portal data.

Public sections
---------------
``public_sections`` lists the public trust-portal sections that are
published, by key (:data:`PUBLIC_SECTIONS`). A stored NULL means
:data:`DEFAULT_PUBLIC_SECTIONS`: every section except ``risks``, so the risk
register is private until an admin publishes it. A section that is not
published answers 404 and is left out of the navigation; control names
appear on other pages (``/status``, policy pages) only while ``controls`` is
published. The list is changed
in Admin > Portal Settings or with ``PUT /api/settings``
(``{"public_sections": [...]}``; ``null`` restores the default); every change
is recorded in the audit log (``portal_settings`` is an audited table).
"""

import re

from flask import current_app
from markupsafe import Markup

from app.models import db
from app.models.portal_settings import PortalSettings

# (key, label, public pages) of every public trust-portal section, in canonical order.
PUBLIC_SECTIONS = (
    ("overview", "Overview", "/"),
    ("status", "Compliance status", "/status"),
    ("controls", "Controls", "/controls, /controls/<id>"),
    ("policies", "Policies (approved only)", "/policies, /policies/<id or slug>"),
    ("systems", "Systems", "/systems"),
    ("vendors", "Vendors", "/vendors"),
    ("risks", "Risk register", "/risks"),
    ("ai_transparency", "AI transparency", "/ai-transparency"),
    ("legal", "Legal (privacy, terms, accessibility)", "/legal"),
)
PUBLIC_SECTION_KEYS = tuple(key for key, _, _ in PUBLIC_SECTIONS)
DEFAULT_PUBLIC_SECTIONS = tuple(key for key in PUBLIC_SECTION_KEYS if key != "risks")

# Fonts
# -----
# ``heading_font`` and ``text_font`` are plain CSS ``font-family`` lists. A stored NULL
# means :data:`DEFAULT_FONT_STACK`. Pages emit them as the custom properties
# ``--heading-font`` and ``--text-font``, so a value is accepted only when it cannot
# carry anything but family names (:func:`validate_font_stack`).
DEFAULT_FONT_STACK = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
FONT_FIELDS = ("heading_font", "text_font")
MAX_FONT_STACK_LENGTH = 300
# A family name is words of letters and digits joined by single spaces; a word starts with
# a letter, optionally after one hyphen, and may contain hyphens (``-apple-system``).
_UNQUOTED_WORD = re.compile(r"-?[^\W\d_](?:[^\W_]|-)*")
_QUOTED_NAME = re.compile(r"[^\W_](?:[^\W_]|[ -])*")
_FORBIDDEN_WORDS = {"url", "expression"}
_CSS_WIDE_KEYWORDS = {"inherit", "initial", "unset", "revert", "revert-layer", "default"}

SOC2_STAGES = [
    {"key": "not_started", "label": "Not Started", "has_date": False},
    {"key": "policies_established", "label": "Policies & Controls Established", "has_date": False},
    {"key": "collecting_point_in_time", "label": "Collecting Point-in-Time Evidence", "has_date": False},
    {"key": "auditor_engaged", "label": "Auditor Engaged", "has_date": False},
    {"key": "type_1_completed", "label": "Type 1 Audit Completed", "has_date": True},
    {"key": "collecting_continuous", "label": "Collecting Continuous Evidence", "has_date": False},
    {"key": "type_2_completed", "label": "Type 2 Audit Completed", "has_date": True},
]


def validate_font_stack(value, field="font"):
    """The canonical stored form of a font setting.

    ``None`` stays None (the default stack). Anything else must be a plain
    ``font-family`` list of at most :data:`MAX_FONT_STACK_LENGTH` characters:
    comma-separated families, each an unquoted name (words of letters, digits
    and hyphens, each starting with a letter), a quoted name (letters, digits,
    spaces and hyphens) or a generic family. Semicolons, braces, angle
    brackets, backslashes, slashes, parentheses, colons, ``@``, ``url``,
    ``expression``, control characters, empty items and the CSS-wide keywords
    are refused with ValueError naming ``field``. The result joins the families
    with ``, ``.
    """
    if value is None:
        return None
    problem = f"{field} must be a plain font-family list (comma-separated family names)"
    if not isinstance(value, str) or not value.strip():
        raise ValueError(problem)
    if len(value) > MAX_FONT_STACK_LENGTH:
        raise ValueError(f"{field} must be at most {MAX_FONT_STACK_LENGTH} characters")
    families = []
    for item in value.split(","):
        item = item.strip(" ")
        quote = item[:1] if item[:1] in ("'", '"') else ""
        if quote:
            name = item[1:-1] if len(item) >= 3 and item.endswith(quote) else None
            valid = name is not None and _QUOTED_NAME.fullmatch(name) is not None
            words = name.lower().split() if valid else []
            valid = valid and not _FORBIDDEN_WORDS.intersection(words)
        else:
            words = item.lower().split(" ")
            valid = bool(item) and all(_UNQUOTED_WORD.fullmatch(word) for word in words)
            valid = valid and not (_FORBIDDEN_WORDS | _CSS_WIDE_KEYWORDS).intersection(words)
        if not valid:
            raise ValueError(problem)
        families.append(item)
    return ", ".join(families)


def effective_font_stack(value):
    """The stack a page uses for a stored font value: the value when it is valid, else the default."""
    try:
        return validate_font_stack(value) or DEFAULT_FONT_STACK
    except ValueError:
        return DEFAULT_FONT_STACK


def safe_font_stack(value):
    """A font stack for a ``<style>`` element (Jinja filter ``font_stack``): re-validated, never escaped.

    A validated stack holds no ``<``, ``&`` or ``;``, so it is safe verbatim
    inside a stylesheet; its quotes stay quotes, which autoescaping would turn into entities
    that CSS does not decode.
    """
    return Markup(effective_font_stack(value))


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
    stored_sections = db_settings.public_sections if db_settings else None
    public_sections = (
        [key for key in PUBLIC_SECTION_KEYS if key in stored_sections]
        if isinstance(stored_sections, list) else list(DEFAULT_PUBLIC_SECTIONS)
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
        "public_sections": public_sections,
        "heading_font": effective_font_stack(db_settings.heading_font if db_settings else None),
        "text_font": effective_font_stack(db_settings.text_font if db_settings else None),
    }


def section_enabled(key):
    """True when the public section ``key`` is published."""
    return key in get_portal_settings()["public_sections"]


def validate_public_sections(value):
    """The canonical stored form of a ``public_sections`` value.

    ``None`` stays None (the default set). A list of known section keys is
    returned de-duplicated in canonical order. Anything else raises
    ValueError naming ``public_sections``.
    """
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("public_sections must be a list of section keys or null")
    unknown = sorted({item for item in value if item not in PUBLIC_SECTION_KEYS})
    if unknown:
        raise ValueError(f"public_sections: unknown section {', '.join(unknown)}; "
                         f"known sections are {', '.join(PUBLIC_SECTION_KEYS)}")
    return [key for key in PUBLIC_SECTION_KEYS if key in value]


URL_FIELDS = ("website_url", "legal_external_url")


def update_portal_settings(data, updated_by=None):
    """Create or update the single portal_settings row.

    Raises ValueError when a URL field is not an http(s) URL, ``public_sections``
    is invalid (see :func:`validate_public_sections`) or a font field is not a
    plain font list (see :func:`validate_font_stack`); nothing is saved then.
    """
    from app.security import is_http_url

    for field in URL_FIELDS:
        if data.get(field) and not is_http_url(data[field]):
            raise ValueError(f"{field} must be an http(s) URL")
    if "public_sections" in data:
        data = dict(data, public_sections=validate_public_sections(data["public_sections"]))
    for field in FONT_FIELDS:
        if field in data:
            data = dict(data, **{field: validate_font_stack(data[field], field)})
    settings = db.session.get(PortalSettings, 1)
    if not settings:
        settings = PortalSettings(id=1)

    allowed_fields = [
        "company_legal_name", "company_brand_name", "contact_email",
        "physical_address", "website_url",
        "soc2_current_stage", "soc2_stage_dates",
        "legal_content_md", "legal_external_url",
        "ai_transparency_md", "public_sections",
        *FONT_FIELDS,
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
