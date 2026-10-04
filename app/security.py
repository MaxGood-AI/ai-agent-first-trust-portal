"""Web security: proxy trust, security headers, CSRF protection, safe
redirects, URL-field validation and sanitized markdown.

CSRF model
----------
State-changing requests (POST, PUT, PATCH, DELETE) must carry the session's
CSRF token - as the ``csrf_token`` form field or the ``X-CSRF-Token`` header -
unless an API-key header (``X-API-Key`` or ``Authorization: Bearer``)
authenticates an active, unexpired member. A request that carries an API-key
header which does not authenticate is answered 401: it is never exempted and
never falls back to the session cookie. Header-authenticated API calls cannot
be forged by a browser; cookie-authenticated browser requests must present the
token. A view decorated with ``csrf_exempt`` authenticates with its own header
credential and uses no session (the bootstrap endpoint ``POST /api/setup``).
The check runs after the request body limits are in force
(``app.request_limits``): it reads at most 1 MiB of an anonymous request.

Templates emit the token with ``{{ csrf_field() }}``; ``base.html`` exposes it
to scripts through ``<meta name="csrf-token">`` only on pages rendered for a
signed-in member, so public pages set no cookie.

URLs
----
URL columns (``URL_FIELDS``) accept only absolute http(s) URLs when written
through the API or admin UI; templates render stored URLs through the
``safe_url`` filter, which turns anything else into ``#``.
"""

from __future__ import annotations

import hmac
import secrets
from urllib.parse import unquote, urlsplit

import markdown as _markdown
import nh3
from flask import abort, current_app, jsonify, request, session
from markupsafe import Markup
from werkzeug.middleware.proxy_fix import ProxyFix

CSRF_SESSION_KEY = "_csrf_token"
SESSION_MEMBER_KEY = "member_id"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)
# Swagger UI (flasgger) renders an inline bootstrap script.
API_DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)
API_DOCS_PREFIXES = ("/api/docs", "/flasgger_static", "/apispec")

# Columns that hold a URL rendered as a link, by table name.
URL_FIELDS = {
    "evidence": ("url",),
    "vendors": ("website_url", "privacy_policy_url", "security_page_url", "tos_url"),
}

MARKDOWN_EXTENSIONS = ["tables", "fenced_code", "toc"]
ALLOWED_TAGS = {
    "a", "abbr", "b", "blockquote", "br", "code", "dd", "del", "div", "dl", "dt",
    "em", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "li", "ol", "p",
    "pre", "s", "span", "strong", "sub", "sup", "table", "tbody", "td", "th",
    "thead", "tr", "ul",
}
ALLOWED_ATTRIBUTES = {
    "a": {"href", "title"},
    "img": {"src", "alt", "title"},
    "th": {"align"},
    "td": {"align"},
    "h1": {"id"}, "h2": {"id"}, "h3": {"id"}, "h4": {"id"}, "h5": {"id"}, "h6": {"id"},
    "code": {"class"},
    "div": {"class"},
    "span": {"class"},
}


# ----- markdown -----

def render_markdown(text: str | None) -> Markup:
    """Render markdown to HTML with raw HTML and unsafe URLs stripped."""
    if not text:
        return Markup("")
    html = _markdown.markdown(text, extensions=MARKDOWN_EXTENSIONS)
    clean = nh3.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes={"http", "https", "mailto"},
        link_rel="noopener noreferrer",
    )
    return Markup(clean)


# ----- URLs -----

def is_http_url(value: str | None) -> bool:
    """True for an absolute http(s) URL with a host."""
    if not value or not isinstance(value, str):
        return False
    parts = urlsplit(value.strip())
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def safe_url(value) -> str:
    """Jinja filter: ``value`` when it is an http(s) URL, otherwise ``#``."""
    if isinstance(value, str) and is_http_url(value):
        return value.strip()
    return "#"


def invalid_url_fields(table_name: str, values: dict) -> list[str]:
    """Names of the URL columns of ``table_name`` whose value in ``values`` is
    set but is not an http(s) URL."""
    return [
        field for field in URL_FIELDS.get(table_name, ())
        if values.get(field) not in (None, "") and not is_http_url(values.get(field))
    ]


def url_fields_error(table_name: str, values: dict) -> str | None:
    """A validation message for non-http(s) URL columns, or None."""
    bad = invalid_url_fields(table_name, values)
    if not bad:
        return None
    return f"{', '.join(bad)} must be an http(s) URL"


# ----- redirects -----

def _is_plain_path(value: str) -> bool:
    """Visible ASCII only (no whitespace or control characters), no backslash,
    a single leading slash."""
    if not value.startswith("/") or value.startswith("//"):
        return False
    return all(0x21 <= ord(ch) <= 0x7E and ch != "\\" for ch in value)


def safe_next_url(value: str | None, fallback: str) -> str:
    """Return ``value`` only when it is a same-site path; otherwise ``fallback``.

    Accepts ``/admin/...``-style absolute paths made of visible ASCII
    characters. Rejects scheme-relative (``//host``) and absolute URLs,
    backslashes, and whitespace or control characters anywhere - also once
    percent-decoded - so that nothing a browser strips or normalises can turn
    the path into ``//host``.
    """
    if not value or not isinstance(value, str):
        return fallback
    candidate = value
    for _ in range(4):
        if not _is_plain_path(candidate):
            return fallback
        decoded = unquote(candidate)
        if decoded == candidate:
            break
        candidate = decoded
    else:
        return fallback
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return fallback
    return value


# ----- CSRF -----

def csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def csrf_field() -> Markup:
    return Markup(f'<input type="hidden" name="{CSRF_FORM_FIELD}" value="{csrf_token()}">')


def csrf_exempt(view):
    """Mark a view that authenticates with its own header credential and uses
    no session, so the CSRF check does not apply to it."""
    view.csrf_exempt = True
    return view


def _view_is_csrf_exempt() -> bool:
    view = current_app.view_functions.get(request.endpoint) if request.endpoint else None
    return bool(getattr(view, "csrf_exempt", False))


def _csrf_protect():
    if not current_app.config.get("CSRF_ENABLED", True):
        return None
    if request.method not in UNSAFE_METHODS:
        return None
    if _view_is_csrf_exempt():
        return None

    from app.auth import api_key_header, header_member

    if api_key_header() is not None:
        member = header_member()
        if member is None or member.is_expired:
            response = jsonify({"error": "Invalid or inactive API key"})
            response.status_code = 401
            return response
        return None
    expected = session.get(CSRF_SESSION_KEY)
    supplied = request.headers.get(CSRF_HEADER) or request.form.get(CSRF_FORM_FIELD)
    if not expected or not supplied or not hmac.compare_digest(str(expected), str(supplied)):
        abort(400, description=(
            "CSRF token missing or invalid. Browsers: reload the page and try again. "
            "API clients: authenticate with the X-API-Key or Authorization: Bearer header."))
    return None


# ----- headers -----

def _security_headers(response):
    path = request.path or ""
    csp = API_DOCS_CSP if path.startswith(API_DOCS_PREFIXES) else DEFAULT_CSP
    response.headers.setdefault("Content-Security-Policy", csp)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if current_app.config.get("SESSION_COOKIE_SECURE"):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if path.startswith(("/admin", "/setup", "/api/")) and "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store"
    return response


def _api_json_errors(error):
    """HTTP errors on /api/ paths are JSON ({"error": ...}); pages keep HTML."""
    from werkzeug.exceptions import HTTPException

    if not isinstance(error, HTTPException):  # pragma: no cover - registered for HTTPException only
        raise error
    if request.path.startswith("/api/"):
        response = jsonify({"error": error.description or error.name})
        response.status_code = error.code or 500
        return response
    return error


def register_security(app) -> None:
    hops = int(app.config.get("TRUSTED_PROXY_HOPS", 0) or 0)
    if hops > 0:
        # Client address and scheme only: the Host header is never taken from a proxy.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops, x_host=0, x_port=0)

    from werkzeug.exceptions import HTTPException

    app.before_request(_csrf_protect)
    app.after_request(_security_headers)
    app.register_error_handler(HTTPException, _api_json_errors)
    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["csrf_field"] = csrf_field
    app.jinja_env.filters["safe_url"] = safe_url
