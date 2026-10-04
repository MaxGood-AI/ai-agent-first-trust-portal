"""Web security: sessions without keys, CSRF, redirects, rate limiting,
headers, request size, markdown sanitising, role scoping and bootstrap."""

import pytest
from flask import json

from app import create_app
from app.config import TestConfig
from app.models import Control, db
from app.security import render_markdown, safe_next_url
from app.services import team_service
from tests.conftest import login, raw_client


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
def admin(app_ctx):
    return team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)


def _session_data(client, app):
    cookie = client.get_cookie(app.config["SESSION_COOKIE_NAME"])
    assert cookie is not None
    serializer = app.session_interface.get_signing_serializer(app)
    return serializer.loads(cookie.value)


# ----- sessions carry no key -----

def test_login_session_holds_member_id_and_fingerprint_only(app_ctx, client, admin):
    resp = client.post("/admin/login", data={"api_key": admin.issued_api_key})
    assert resp.status_code == 302
    data = _session_data(client, app_ctx)
    assert data["member_id"] == admin.id
    assert data["key_fp"] == admin.key_fingerprint
    assert admin.issued_api_key not in json.dumps(data)
    assert admin.api_key_hash not in json.dumps(data)
    assert client.get("/admin/").status_code == 200


def test_session_cookie_flags(app_ctx, client, admin):
    app_ctx.config["SESSION_COOKIE_SECURE"] = True
    resp = client.post("/admin/login", data={"api_key": admin.issued_api_key})
    header = resp.headers.get("Set-Cookie")
    assert "HttpOnly" in header and "SameSite=Lax" in header and "Secure" in header


def test_regenerating_a_key_ends_existing_sessions(client, admin):
    login(client, admin)
    assert client.get("/admin/", headers={"Accept": "text/html"}).status_code == 200
    team_service.regenerate_key(admin.id)
    resp = client.get("/admin/", headers={"Accept": "text/html"})
    assert resp.status_code == 302 and "/admin/login" in resp.headers["Location"]


def test_deactivation_ends_existing_sessions(client, admin):
    team_service.create_member("Second Admin", "second@example.com", "human", is_compliance_admin=True)
    login(client, admin)
    team_service.deactivate_member(admin.id)
    assert client.get("/admin/", headers={"Accept": "text/html"}).status_code == 302


def test_logout_requires_post(client, admin):
    login(client, admin)
    assert client.get("/admin/logout").status_code == 405
    assert client.post("/admin/logout").status_code == 302
    assert client.get("/admin/", headers={"Accept": "text/html"}).status_code == 302


def test_issued_key_is_shown_once_and_never_flashed(app_ctx, client, admin):
    login(client, admin)
    resp = client.post("/admin/team", data={"name": "New Agent", "email": "n@example.com", "role": "agent"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "shown only once" in body
    data = _session_data(client, app_ctx)
    assert "_flashes" not in data
    listing = client.get("/admin/team").get_data(as_text=True)
    assert "shown only once" not in listing


# ----- open redirect -----

@pytest.mark.parametrize("target,expected", [
    ("/admin/collectors", "/admin/collectors"),
    ("https://evil.example/", "/admin/"),
    ("//evil.example/x", "/admin/"),
    ("/\\evil.example", "/admin/"),
    ("javascript:alert(1)", "/admin/"),
    ("", "/admin/"),
])
def test_safe_next_url(target, expected):
    assert safe_next_url(target, "/admin/") == expected


def test_login_does_not_redirect_off_site(client, admin):
    resp = client.post("/admin/login?next=https://evil.example/steal", data={"api_key": admin.issued_api_key})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/admin/")


# ----- CSRF -----

def test_form_post_without_csrf_token_is_rejected(app_ctx, admin):
    browser = raw_client(app_ctx)
    login(browser, admin)
    resp = browser.post("/admin/team", data={"name": "X", "email": "x@example.com", "role": "agent"})
    assert resp.status_code == 400
    ok = browser.post("/admin/team", data={"name": "X", "email": "x@example.com", "role": "agent",
                                           "csrf_token": "test-csrf-token"})
    assert ok.status_code == 200


def test_login_form_requires_csrf_token(app_ctx, admin):
    browser = raw_client(app_ctx)
    assert browser.post("/admin/login", data={"api_key": admin.issued_api_key}).status_code == 400


def test_cookie_authenticated_json_requires_csrf_header(app_ctx, admin):
    browser = raw_client(app_ctx)
    login(browser, admin)
    resp = browser.post("/api/collectors/policy/configure", json={"credential_mode": "none"})
    assert resp.status_code == 400
    resp = browser.post("/api/collectors/policy/configure", json={"credential_mode": "none"},
                        headers={"X-CSRF-Token": "test-csrf-token"})
    assert resp.status_code == 200


def test_api_key_requests_need_no_csrf_token(app_ctx, admin):
    browser = raw_client(app_ctx)
    resp = browser.post("/api/collectors/policy/configure", json={"credential_mode": "none"},
                        headers={"X-API-Key": admin.issued_api_key})
    assert resp.status_code == 200


def test_pages_expose_csrf_meta_tag_to_signed_in_members_only(client, admin):
    assert b'name="csrf-token"' not in client.get("/").data
    login(client, admin)
    assert b'name="csrf-token"' in client.get("/").data


# ----- rate limiting -----

def test_failed_logins_are_rate_limited(app_ctx, client, admin):
    app_ctx.config["AUTH_RATE_LIMIT_ATTEMPTS"] = 3
    for _ in range(3):
        assert client.post("/admin/login", data={"api_key": "wrong"}).status_code == 401
    limited = client.post("/admin/login", data={"api_key": admin.issued_api_key})
    assert limited.status_code == 429
    for _ in range(3):
        client.post("/admin/client-login", data={"api_key": "wrong"})
    assert client.post("/admin/client-login", data={"api_key": "wrong"}).status_code == 429


def test_successful_login_resets_failures(app_ctx, client, admin):
    app_ctx.config["AUTH_RATE_LIMIT_ATTEMPTS"] = 3
    client.post("/admin/login", data={"api_key": "wrong"})
    client.post("/admin/login", data={"api_key": "wrong"})
    assert client.post("/admin/login", data={"api_key": admin.issued_api_key}).status_code == 302
    from app.models.auth_rate_limit import AuthRateLimitWindow
    assert AuthRateLimitWindow.query.filter_by(bucket="login").count() == 0


def test_rate_limit_prune(app_ctx):
    from datetime import timedelta

    from app.services import rate_limit
    with app_ctx.test_request_context("/"):
        rate_limit.consume("login")
    assert rate_limit.prune(max_age=timedelta(seconds=-1)) == 1


# ----- headers and limits -----

def test_security_headers(client):
    resp = client.get("/")
    csp = resp.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert "frame-ancestors 'none'" in csp
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Strict-Transport-Security" not in resp.headers


def test_hsts_when_cookies_are_secure(app_ctx, client):
    app_ctx.config["SESSION_COOKIE_SECURE"] = True
    assert "max-age=" in client.get("/").headers["Strict-Transport-Security"]


def test_api_docs_get_their_own_csp(client):
    resp = client.get("/api/docs/")
    assert "'unsafe-inline'" in resp.headers["Content-Security-Policy"]


def test_admin_and_api_responses_are_not_cached(client):
    assert client.get("/api/health").headers["Cache-Control"] == "no-store"


def test_oversized_request_is_rejected(client, admin):
    body = b"x" * (32 * 1024 * 1024 + 1)
    resp = client.post("/api/decision-log/upload?session_id=big", data=body,
                       headers={"X-API-Key": admin.issued_api_key, "Content-Type": "application/jsonl"})
    assert resp.status_code == 413


def test_proxy_headers_trusted_only_when_configured(monkeypatch):
    class Proxied(TestConfig):
        TRUSTED_PROXY_HOPS = 1

    app = create_app(Proxied)
    captured = {}

    @app.route("/_probe")
    def probe():
        from flask import request
        captured["addr"] = request.remote_addr
        captured["scheme"] = request.scheme
        return "ok"

    app.test_client().get("/_probe", headers={"X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https"})
    assert captured == {"addr": "203.0.113.9", "scheme": "https"}


# ----- markdown -----

def test_render_markdown_strips_scripts_and_unsafe_links():
    html = str(render_markdown(
        "# Title\n\n<script>alert(1)</script>\n\n[x](javascript:alert(1)) "
        "<img src=x onerror=alert(1)> [ok](https://example.com)"))
    assert "<script" not in html
    assert "javascript:" not in html
    assert "onerror" not in html
    assert 'href="https://example.com"' in html
    assert "<h1" in html
    assert str(render_markdown("")) == ""


def test_admin_markdown_is_sanitised_on_public_pages(client, admin):
    client.put("/api/settings", headers={"X-API-Key": admin.issued_api_key},
               json={"legal_content_md": "Hello <script>alert('x')</script>",
                     "ai_transparency_md": "<iframe src='https://evil.example'></iframe>AI"})
    legal = client.get("/legal").get_data(as_text=True)
    assert "alert('x')" not in legal and "Hello" in legal
    assert "<iframe" not in client.get("/ai-transparency").get_data(as_text=True)


def test_settings_reject_non_http_urls(client, admin):
    resp = client.put("/api/settings", headers={"X-API-Key": admin.issued_api_key},
                      json={"legal_external_url": "javascript:alert(1)"})
    assert resp.status_code == 400
    login(client, admin)
    resp = client.post("/admin/settings", data={"legal_external_url": "ftp://x"})
    assert resp.status_code == 302


# ----- role scoping -----

def test_client_keys_are_read_only(client, app_ctx):
    reviewer = team_service.create_member("Reviewer", "r@example.com", "client")
    headers = {"X-API-Key": reviewer.issued_api_key}
    db.session.add(Control(id="c1", name="MFA", category="security"))
    db.session.commit()
    assert client.get("/api/controls", headers=headers).status_code == 200
    assert client.post("/api/controls", headers=headers, json={"name": "x", "category": "security"}).status_code == 403
    assert client.put("/api/controls/c1", headers=headers, json={"name": "y"}).status_code == 403
    assert client.delete("/api/controls/c1", headers=headers).status_code == 403
    assert client.post("/api/tests/batch-record-execution", headers=headers,
                       json={"executions": []}).status_code == 403
    assert client.post("/api/evidence/batch-submit", headers=headers, json={"evidence": []}).status_code == 403


def test_writers_can_write(client, app_ctx):
    agent = team_service.create_member("Agent", "a@example.com", "agent")
    resp = client.post("/api/controls", headers={"X-API-Key": agent.issued_api_key},
                       json={"name": "x", "category": "security"})
    assert resp.status_code == 201


# ----- first-admin bootstrap -----

def test_setup_disabled_without_token(client):
    resp = client.get("/setup")
    assert resp.status_code == 200
    assert b"Setup is not enabled" in resp.data
    assert client.post("/setup", data={"token": "x", "name": "a", "email": "a@x"}).status_code == 401


def test_setup_creates_first_admin_once(app_ctx, client):
    app_ctx.config["BOOTSTRAP_TOKEN"] = "boot-token-123"
    assert b"Bootstrap token" in client.get("/setup").data
    bad = client.post("/setup", data={"token": "wrong", "name": "A", "email": "a@example.com"})
    assert bad.status_code == 401
    missing = client.post("/setup", data={"token": "boot-token-123", "name": "", "email": ""})
    assert missing.status_code == 400
    ok = client.post("/setup", data={"token": "boot-token-123", "name": "Owner", "email": "o@example.com"})
    assert ok.status_code == 200
    assert b"shown only once" in ok.data
    assert team_service.admin_exists()
    assert client.get("/setup").status_code == 404
    assert client.post("/setup", data={"token": "boot-token-123", "name": "B", "email": "b@x"}).status_code == 404


def test_api_setup_with_bearer_token(app_ctx, client):
    app_ctx.config["BOOTSTRAP_TOKEN"] = "boot-token-456"
    assert client.post("/api/setup", json={"name": "A", "email": "a@x"}).status_code == 401
    wrong = client.post("/api/setup", json={"name": "A", "email": "a@x"},
                        headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 401
    incomplete = client.post("/api/setup", json={"name": "A"},
                             headers={"Authorization": "Bearer boot-token-456"})
    assert incomplete.status_code == 400
    resp = client.post("/api/setup", json={"name": "Owner", "email": "o@example.com"},
                       headers={"Authorization": "Bearer boot-token-456"})
    assert resp.status_code == 201
    key = resp.get_json()["api_key"]
    assert client.get("/api/collectors", headers={"X-API-Key": key}).status_code == 200
    again = client.post("/api/setup", json={"name": "B", "email": "b@x"},
                        headers={"Authorization": "Bearer boot-token-456"})
    assert again.status_code == 404


def test_setup_attempts_are_rate_limited(app_ctx, client):
    app_ctx.config["BOOTSTRAP_TOKEN"] = "boot"
    app_ctx.config["AUTH_RATE_LIMIT_ATTEMPTS"] = 2
    for _ in range(2):
        client.post("/api/setup", json={"name": "A", "email": "a@x"}, headers={"Authorization": "Bearer x"})
    assert client.post("/api/setup", json={"name": "A", "email": "a@x"},
                       headers={"Authorization": "Bearer boot"}).status_code == 429
    assert client.post("/setup", data={"token": "boot", "name": "A", "email": "a@x"}).status_code == 429


def test_api_errors_are_json(app_ctx):
    browser = raw_client(app_ctx)
    resp = browser.post("/api/decision-log/upload", data="x")
    assert resp.status_code == 400
    assert "X-API-Key" in resp.get_json()["error"]
    missing = browser.get("/api/no-such-endpoint")
    assert missing.status_code == 404 and "error" in missing.get_json()
    page = browser.get("/no-such-page")
    assert page.status_code == 404 and page.mimetype == "text/html"
