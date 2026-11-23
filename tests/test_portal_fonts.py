"""Portal fonts: the heading and text font settings, their validation (a plain
``font-family`` list, so a stored value cannot inject CSS), their rendering as
CSS custom properties on every page (public, admin, 404) and on /api/docs/."""

import html
import re

import pytest

from app import create_app
from app.config import TestConfig
from app.models import db
from app.models.portal_settings import PortalSettings
from app.security import API_DOCS_CSP
from app.services import team_service
from app.services.settings_service import (
    DEFAULT_FONT_STACK, get_portal_settings, update_portal_settings, validate_font_stack)

HEADING = 'Georgia, "Times New Roman", serif'
TEXT = "Geneva, Verdana, sans-serif"
DEFAULT_STACK = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'


@pytest.fixture
def app_ctx():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app_ctx):
    return app_ctx.test_client()


@pytest.fixture
def headers(app_ctx):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    return {"X-API-Key": admin.issued_api_key}


def _style_attribute(response):
    """The decoded style attribute of the <html> element."""
    match = re.search(r"<html[^>]*\sstyle=\"([^\"]*)\"", response.get_data(as_text=True))
    assert match, "the <html> element carries no style attribute"
    return html.unescape(match.group(1))


# --- the validator ---

@pytest.mark.parametrize("value, stored", [
    (DEFAULT_STACK, DEFAULT_STACK),
    (HEADING, HEADING),
    ("  Georgia ,  'Times New Roman'  ,serif ", "Georgia, 'Times New Roman', serif"),
    ("serif", "serif"),
    ("Helvetica-Neue, Arial, system-ui", "Helvetica-Neue, Arial, system-ui"),
    ('"Source Sans 3", sans-serif', '"Source Sans 3", sans-serif'),
])
def test_validator_accepts_a_plain_font_list(value, stored):
    assert validate_font_stack(value, "heading_font") == stored


@pytest.mark.parametrize("value", [
    "Georgia; color: red",
    "Georgia}",
    "Georgia{",
    "</style><script>alert(1)</script>",
    "Georgia<b>",
    "Georgia>",
    "url(https://example.test/x.woff)",
    '"Georgia", url(x)',
    "expression(alert(1))",
    "Expression",
    "url",
    '"expression"',
    "Georgia\nserif",
    "Georgia\rserif",
    "Georgia\tserif",
    "Georgia\x00serif",
    "Georgia\x1bserif",
    "Geo\\rgia",
    "Georgia / serif",
    "Georgia:serif",
    "@import",
    "Georgia, (serif)",
    "Georgia,",
    ",Georgia",
    "Georgia,,serif",
    "Georgia, ",
    '"Georgia',
    'Georgia"',
    '"Geor"gia"',
    "'Georgia\"",
    '"Geo;rgia"',
    "1Georgia",
    "inherit",
    "Georgia, initial",
    '""',
    "G" * 301,
    ", ".join(["Georgia"] * 40),
    "",
    "   ",
    123,
    ["Georgia"],
    {"a": 1},
    True,
])
def test_validator_rejects_everything_else(value):
    with pytest.raises(ValueError, match="heading_font"):
        validate_font_stack(value, "heading_font")


def test_validator_none_means_the_default():
    assert validate_font_stack(None, "text_font") is None


# --- settings: defaults, API ---

def test_defaults_are_todays_stack(app_ctx):
    settings = get_portal_settings()
    assert DEFAULT_FONT_STACK == DEFAULT_STACK
    assert settings["heading_font"] == DEFAULT_STACK
    assert settings["text_font"] == DEFAULT_STACK


def test_settings_api_saves_and_returns_the_fonts(client, headers):
    resp = client.put("/api/settings", headers=headers, json={"heading_font": HEADING, "text_font": TEXT})
    assert resp.status_code == 200
    assert resp.get_json()["heading_font"] == HEADING
    assert resp.get_json()["text_font"] == TEXT
    got = client.get("/api/settings", headers=headers).get_json()
    assert (got["heading_font"], got["text_font"]) == (HEADING, TEXT)
    stored = db.session.get(PortalSettings, 1)
    assert (stored.heading_font, stored.text_font) == (HEADING, TEXT)


def test_settings_api_null_restores_the_default(client, headers):
    client.put("/api/settings", headers=headers, json={"heading_font": HEADING, "text_font": TEXT})
    resp = client.put("/api/settings", headers=headers, json={"heading_font": None, "text_font": None})
    assert resp.status_code == 200
    assert resp.get_json()["heading_font"] == DEFAULT_STACK
    assert resp.get_json()["text_font"] == DEFAULT_STACK


@pytest.mark.parametrize("field", ["heading_font", "text_font"])
@pytest.mark.parametrize("bad", [
    "Georgia; background: url(//x.test/a)",
    "Georgia}body{display:none",
    "</style><script>alert(1)</script>",
    "url(https://x.test/a.woff)",
    "expression(alert(1))",
    "Georgia,\nserif",
    "G" * 301,
])
def test_settings_api_rejects_injection(client, headers, field, bad):
    client.put("/api/settings", headers=headers, json={"heading_font": HEADING, "text_font": TEXT})
    resp = client.put("/api/settings", headers=headers, json={field: bad})
    assert resp.status_code == 400
    assert field in resp.get_json()["error"]
    got = client.get("/api/settings", headers=headers).get_json()
    assert (got["heading_font"], got["text_font"]) == (HEADING, TEXT)


def test_a_rejected_font_saves_nothing_else(client, headers):
    resp = client.put("/api/settings", headers=headers,
                      json={"company_brand_name": "Changed", "text_font": "a;b"})
    assert resp.status_code == 400
    assert get_portal_settings()["company_brand_name"] != "Changed"


# --- settings: Admin form ---

def test_admin_form_shows_and_saves_the_fonts(app_ctx, client, headers):
    page = client.get("/admin/settings", headers=headers).get_data(as_text=True)
    assert 'name="heading_font"' in page and 'name="text_font"' in page
    resp = client.post("/admin/settings", headers=headers,
                       data={"heading_font": HEADING, "text_font": TEXT})
    assert resp.status_code == 302
    assert get_portal_settings()["heading_font"] == HEADING
    assert get_portal_settings()["text_font"] == TEXT
    page = client.get("/admin/settings", headers=headers).get_data(as_text=True)
    assert f'name="heading_font" maxlength="300" value="{HEADING}"' in html.unescape(page)


def test_admin_form_blank_restores_the_default(client, headers):
    client.put("/api/settings", headers=headers, json={"heading_font": HEADING, "text_font": TEXT})
    client.post("/admin/settings", headers=headers, data={"heading_font": "", "text_font": ""})
    assert get_portal_settings()["heading_font"] == DEFAULT_STACK
    assert get_portal_settings()["text_font"] == DEFAULT_STACK


@pytest.mark.parametrize("bad", [
    "Georgia;}", "</style>", "url(x)", "expression(x)", "Georgia\nserif", "G" * 301,
])
def test_admin_form_rejects_injection(client, headers, bad):
    client.put("/api/settings", headers=headers, json={"heading_font": HEADING})
    resp = client.post("/admin/settings", headers=headers, data={"heading_font": bad, "text_font": TEXT})
    assert resp.status_code == 302
    assert get_portal_settings()["heading_font"] == HEADING
    assert get_portal_settings()["text_font"] != TEXT
    flashed = client.get("/admin/settings", headers=headers).get_data(as_text=True)
    assert "Not saved" in flashed and "heading_font" in flashed


# --- rendering ---

PUBLIC_PAGES = ["/", "/controls", "/policies", "/systems", "/vendors", "/status",
                "/ai-transparency", "/legal", "/admin/login"]


@pytest.mark.parametrize("path", PUBLIC_PAGES)
def test_pages_render_the_default_stack_as_variables(client, path):
    resp = client.get(path, follow_redirects=True)
    style = _style_attribute(resp)
    assert f"--heading-font: {DEFAULT_STACK}" in style
    assert f"--text-font: {DEFAULT_STACK}" in style


@pytest.mark.parametrize("path", PUBLIC_PAGES)
def test_pages_render_the_saved_fonts_as_variables(client, headers, path):
    client.put("/api/settings", headers=headers, json={"heading_font": HEADING, "text_font": TEXT})
    resp = client.get(path, follow_redirects=True)
    style = _style_attribute(resp)
    assert f"--heading-font: {HEADING}" in style
    assert f"--text-font: {TEXT}" in style


def test_admin_pages_render_the_saved_fonts(client, headers):
    client.put("/api/settings", headers=headers, json={"heading_font": HEADING, "text_font": TEXT})
    for path in ("/admin/settings", "/admin/"):
        resp = client.get(path, headers=headers, follow_redirects=True)
        assert resp.status_code == 200
        style = _style_attribute(resp)
        assert f"--heading-font: {HEADING}" in style and f"--text-font: {TEXT}" in style


def test_a_stored_value_that_fails_validation_renders_the_default(app_ctx, client):
    db.session.add(PortalSettings(id=1, heading_font="</style><script>x</script>",
                                  text_font="a; b: url(x)"))
    db.session.commit()
    resp = client.get("/")
    body = resp.get_data(as_text=True)
    assert "<script>x" not in body
    style = _style_attribute(resp)
    assert f"--heading-font: {DEFAULT_STACK}" in style and f"--text-font: {DEFAULT_STACK}" in style
    assert get_portal_settings()["heading_font"] == DEFAULT_STACK


def test_stylesheet_uses_the_variables():
    from pathlib import Path
    css = (Path(__file__).resolve().parent.parent / "app/static/css/portal.css").read_text()
    assert re.search(r"body\s*\{[^}]*font-family:\s*var\(--text-font\)", css)
    assert re.search(r"h1,\s*h2,\s*h3,\s*h4,\s*h5,\s*h6[^{]*\{[^}]*font-family:\s*var\(--heading-font\)", css)
    assert re.search(r"button,\s*input,\s*select,\s*textarea\s*\{[^}]*font:\s*inherit", css)
    assert re.search(r"pre,\s*code[^{]*\{[^}]*font-family:\s*monospace", css)
    # The fallback values keep the pages unchanged when the attribute is absent.
    assert f"--text-font: {DEFAULT_STACK}" in css and f"--heading-font: {DEFAULT_STACK}" in css


# --- 404 ---

def test_unknown_page_is_an_html_404_in_the_portal_layout(client, headers):
    client.put("/api/settings", headers=headers, json={"heading_font": HEADING, "text_font": TEXT})
    resp = client.get("/no-such-page")
    assert resp.status_code == 404
    assert resp.mimetype == "text/html"
    body = resp.get_data(as_text=True)
    assert "portal.css" in body and "<h1>" in body and "Not found" in body
    assert f"--heading-font: {HEADING}" in _style_attribute(resp)
    assert "Content-Security-Policy" in resp.headers


def test_unpublished_section_is_the_html_404(client):
    resp = client.get("/risks")
    assert resp.status_code == 404 and "portal.css" in resp.get_data(as_text=True)


def test_api_errors_stay_json(client):
    resp = client.get("/api/no-such-route")
    assert resp.status_code == 404
    assert resp.mimetype == "application/json"
    assert "error" in resp.get_json()


def test_other_http_errors_are_unchanged(client):
    resp = client.post("/", data={})
    assert resp.status_code == 405 and "portal.css" not in resp.get_data(as_text=True)


# --- /api/docs/ ---

def test_api_docs_carry_the_default_fonts(client):
    resp = client.get("/api/docs/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert f"--heading-font: {DEFAULT_STACK}" in body
    assert f"--text-font: {DEFAULT_STACK}" in body


def test_api_docs_carry_the_saved_fonts_and_stay_csp_compatible(client, headers):
    client.put("/api/settings", headers=headers, json={"heading_font": HEADING, "text_font": TEXT})
    resp = client.get("/api/docs/")
    body = resp.get_data(as_text=True)
    assert f"--heading-font: {HEADING}" in body and f"--text-font: {TEXT}" in body
    assert "var(--text-font)" in body and "var(--heading-font)" in body
    assert resp.headers["Content-Security-Policy"] == API_DOCS_CSP
    # Fonts come from the page's own inline style only: no outside stylesheet or font file.
    assert not re.search(r"""<(?:link|script|img)\b[^>]*(?:href|src)\s*=\s*["']https?://""", body)
    assert "@import" not in body and "@font-face" not in body


def test_api_docs_request_no_outside_font_or_stylesheet(client):
    body = client.get("/api/docs/").get_data(as_text=True)
    assert "fonts.googleapis.com" not in body and "fonts.gstatic.com" not in body
    assert not re.search(r"""<link\b[^>]*href\s*=\s*["']https?://""", body)


def test_api_docs_keep_code_monospace(client):
    body = client.get("/api/docs/").get_data(as_text=True)
    assert re.search(r"\.swagger-ui\s+(?:pre|textarea|code)[^{]*\{[^}]*monospace", body)


def test_api_docs_render_the_default_for_an_invalid_stored_value(app_ctx, client):
    db.session.add(PortalSettings(id=1, heading_font="</style><script>x</script>", text_font="a;b"))
    db.session.commit()
    body = client.get("/api/docs/").get_data(as_text=True)
    assert "<script>x" not in body
    assert f"--heading-font: {DEFAULT_STACK}" in body


def test_update_portal_settings_validates(app_ctx):
    with pytest.raises(ValueError, match="text_font"):
        update_portal_settings({"text_font": "a;b"})
