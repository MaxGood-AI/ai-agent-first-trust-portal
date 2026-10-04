"""Web and authentication hardening: client default-deny, API-key header
precedence over the session, redirects, session lifetime, cookies on public
pages, reflected text, proxy trust, URL fields, bootstrap, keyless members,
and template CSP / CSRF conformance."""

import os
import re
import time
from datetime import datetime, timedelta, timezone

import pytest

from app import auth, create_app, security
from app.config import TestConfig
from app.models import (
    db, Control, Evidence, PentestFinding, Policy, RiskRegister, System, TeamMember,
    TestRecord, Vendor,
)
from app.security import safe_next_url
from app.services import team_service
from tests.conftest import TEST_CSRF_TOKEN, login, raw_client

TEMPLATES_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app", "templates")


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


@pytest.fixture
def reviewer(app_ctx):
    return team_service.create_member("Reviewer", "r@example.com", "client")


@pytest.fixture
def seeded(app_ctx):
    db.session.add(Control(id="c1", name="MFA", category="security"))
    db.session.add(TestRecord(id="t1", name="T", control_id="c1", evidence_status="missing"))
    db.session.add(Evidence(id="e1", test_record_id="t1", evidence_type="file", description="IAM dump",
                            file_data=b"AKIA-secret-config", file_name="iam.json"))
    db.session.add(Policy(id="p1", title="Draft incident plan", category="security", status="draft"))
    db.session.add(Policy(id="p2", title="Access control policy", category="security", status="approved"))
    db.session.add(RiskRegister(id="r1", name="Unpatched VPN"))
    db.session.add(PentestFinding(id="f1", layer=3, severity="CRITICAL", summary="SQLi in /login",
                                  description="payload", other_data={"poc": "curl"}))
    db.session.add(System(id="s1", name="Web app"))
    db.session.add(Vendor(id="v1", name="Cloud host"))
    db.session.commit()


# ----- client keys: default-deny with an allowlist -----

CLIENT_DENIED_GETS = [
    "/api/pentest-findings",
    "/api/pentest-findings/f1",
    "/api/evidence",
    "/api/evidence/e1",
    "/api/evidence/e1/download",
    "/api/tests",
    "/api/tests/t1",
    "/api/tests/t1/execution-history",
    "/api/risks",
    "/api/risks/r1",
    "/api/controls/c1",
    "/api/audit-log",
    "/api/audit-log/verify",
    "/api/decision-log/sessions",
    "/api/decision-log/session/any",
    "/api/collectors",
    "/api/git-sources",
]

CLIENT_ALLOWED_GETS = [
    "/api/compliance-score",
    "/api/compliance-journey",
    "/api/controls",
    "/api/gaps",
    "/api/systems",
    "/api/systems/s1",
    "/api/vendors",
    "/api/vendors/v1",
    "/api/policies",
    "/api/policies/p2",
    "/api/settings",
]


@pytest.mark.parametrize("path", CLIENT_DENIED_GETS)
def test_client_key_is_denied_sensitive_reads(client, reviewer, seeded, path):
    resp = client.get(path, headers={"X-API-Key": reviewer.issued_api_key})
    assert resp.status_code == 403, (path, resp.status_code)
    body = resp.get_data(as_text=True)
    assert "AKIA" not in body and "SQLi" not in body and "Unpatched" not in body


@pytest.mark.parametrize("path", CLIENT_ALLOWED_GETS)
def test_client_key_reads_report_data(client, reviewer, seeded, path):
    assert client.get(path, headers={"X-API-Key": reviewer.issued_api_key}).status_code == 200


def test_client_sees_approved_policies_only(client, reviewer, admin, seeded):
    headers = {"X-API-Key": reviewer.issued_api_key}
    listed = {p["id"] for p in client.get("/api/policies", headers=headers).get_json()}
    assert listed == {"p2"}
    draft = client.get("/api/policies/p1", headers=headers)
    assert draft.status_code == 404
    assert "Draft incident plan" not in draft.get_data(as_text=True)
    team = {"X-API-Key": admin.issued_api_key}
    assert {p["id"] for p in client.get("/api/policies", headers=team).get_json()} == {"p1", "p2"}
    assert client.get("/api/policies/p1", headers=team).status_code == 200


@pytest.mark.parametrize("method,path,body", [
    ("post", "/api/systems", {"name": "x"}),
    ("put", "/api/vendors/v1", {"name": "y"}),
    ("delete", "/api/policies/p2", None),
    ("put", "/api/settings", {"company_brand_name": "x"}),
    ("post", "/api/tests/t1/record-execution", {"outcome": "success"}),
    ("post", "/api/audit-log/verify", {}),
    ("post", "/api/decision-log/ingest", {}),
])
def test_client_key_cannot_write(client, reviewer, seeded, method, path, body):
    resp = getattr(client, method)(path, headers={"X-API-Key": reviewer.issued_api_key}, json=body)
    assert resp.status_code == 403


def test_client_session_is_limited_like_the_key(client, reviewer, seeded):
    login(client, reviewer)
    assert client.get("/admin/report", headers={"Accept": "text/html"}).status_code == 200
    assert client.get("/api/risks").status_code == 403
    assert client.get("/api/controls").status_code == 200
    page = client.get("/admin/", headers={"Accept": "text/html"})
    assert page.status_code == 302


# ----- an API-key header authenticates alone; CSRF exemption only when it does -----

JUNK_KEY_HEADERS = [
    {"X-API-Key": "\xa0"},
    {"Authorization": "Bearer \xa0"},
    {"X-API-Key": "\x0c"},
    {"X-API-Key": ""},
    {"X-API-Key": "   "},
    {"X-API-Key": "not-a-key"},
    {"Authorization": "bearer "},
    {"Authorization": "Bearer"},
]


@pytest.mark.parametrize("headers", JUNK_KEY_HEADERS)
def test_junk_key_header_never_uses_the_session(app_ctx, admin, headers):
    browser = raw_client(app_ctx)
    login(browser, admin)
    resp = browser.post("/admin/team", data={"name": "Planted", "email": "p@example.com", "role": "human",
                                             "is_compliance_admin": "on"}, headers=headers)
    assert resp.status_code == 401
    with_token = browser.post("/admin/team", data={"name": "Planted", "email": "p@example.com",
                                                   "role": "human", "is_compliance_admin": "on",
                                                   "csrf_token": TEST_CSRF_TOKEN}, headers=headers)
    assert with_token.status_code == 401
    assert TeamMember.query.filter_by(email="p@example.com").count() == 0
    assert browser.get("/admin/team", headers=headers).status_code == 401
    assert browser.get("/api/compliance-score", headers=headers).status_code == 401


def test_valid_key_header_is_exempt_from_csrf(app_ctx, admin):
    browser = raw_client(app_ctx)
    resp = browser.post("/admin/team", data={"name": "A", "email": "a@example.com", "role": "agent"},
                        headers={"Authorization": f"bearer {admin.issued_api_key}"})
    assert resp.status_code == 200


def test_expired_key_header_is_not_exempt(app_ctx):
    expired = team_service.create_member("Old", "old@example.com", "human", is_compliance_admin=True,
                                         expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
    browser = raw_client(app_ctx)
    resp = browser.post("/admin/team", data={"name": "A", "email": "a@example.com", "role": "agent"},
                        headers={"X-API-Key": expired.issued_api_key})
    assert resp.status_code == 401


# ----- open redirect -----

@pytest.mark.parametrize("target", [
    "/\t/evil.example", "/%09/evil.example", "/\x0b/evil.example", "/ /evil.example",
    "/\n/evil.example", "/\r/evil.example", "/\x00/evil.example", "/%5C/evil.example",
    "/%2F/evil.example", "/%252F/evil.example", "/%2509/evil.example", "/admin/\\x",
    " /admin/", "/admin/ ", "/admin/　", "/ /evil.example",
])
def test_safe_next_url_rejects_normalisable_paths(target):
    assert safe_next_url(target, "/admin/") == "/admin/"


@pytest.mark.parametrize("target", ["/admin/collectors", "/admin/collectors?page=2", "/admin/git-sources/a%2Db"])
def test_safe_next_url_keeps_plain_paths(target):
    assert safe_next_url(target, "/admin/") == target


def test_login_with_tab_in_next_stays_on_site(client, admin):
    resp = client.post("/admin/login?next=/%09/evil.example/phish", data={"api_key": admin.issued_api_key})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/admin/")


# ----- absolute session lifetime -----

def test_absolute_session_lifetime_default():
    assert TestConfig.SESSION_ABSOLUTE_LIFETIME == timedelta(hours=12)


def _set_login_at(client, value):
    with client.session_transaction() as sess:
        sess[auth.SESSION_LOGIN_AT_KEY] = value


def _login_at(client):
    with client.session_transaction() as sess:
        return sess.get(auth.SESSION_LOGIN_AT_KEY)


def test_session_ends_after_absolute_lifetime_despite_activity(client, admin):
    assert client.post("/admin/login", data={"api_key": admin.issued_api_key}).status_code == 302
    assert isinstance(_login_at(client), int)
    started = int(time.time()) - 11 * 3600
    _set_login_at(client, started)
    assert client.get("/admin/", headers={"Accept": "text/html"}).status_code == 200
    assert client.get("/admin/team", headers={"Accept": "text/html"}).status_code == 200
    assert _login_at(client) == started
    _set_login_at(client, int(time.time()) - 12 * 3600 - 5)
    resp = client.get("/admin/", headers={"Accept": "text/html"})
    assert resp.status_code == 302 and "/admin/login" in resp.headers["Location"]
    assert client.get("/admin/team").status_code == 401


def test_session_without_login_time_is_bounded_from_first_use(client, admin):
    login(client, admin)
    assert _login_at(client) is None
    before = int(time.time())
    assert client.get("/admin/team").status_code == 200
    assert _login_at(client) >= before


def test_session_lifetime_is_configurable(app_ctx, client, admin):
    app_ctx.config["SESSION_ABSOLUTE_LIFETIME"] = timedelta(minutes=5)
    client.post("/admin/login", data={"api_key": admin.issued_api_key})
    _set_login_at(client, int(time.time()) - 301)
    assert client.get("/admin/").status_code == 401


# ----- public pages set no cookie -----

@pytest.mark.parametrize("path,status", [("/", 200), ("/controls", 200), ("/policies", 200),
                                         ("/systems", 200), ("/vendors", 200), ("/risks", 404),
                                         ("/status", 200), ("/legal", 200), ("/ai-transparency", 200)])
def test_public_pages_set_no_cookie(client, path, status):
    resp = client.get(path)
    assert resp.status_code == status
    assert resp.headers.getlist("Set-Cookie") == []
    assert b'name="csrf-token"' not in resp.data


def test_signed_in_pages_expose_csrf_meta_tag(client, admin):
    login(client, admin)
    assert b'name="csrf-token"' in client.get("/admin/team").data


# ----- no reflected text on the client login page -----

def test_client_login_error_is_never_reflected(client):
    resp = client.get("/admin/client-login?error=Call+support+at+evil.example")
    assert resp.status_code == 200
    assert b"evil.example" not in resp.data and b"Call support" not in resp.data
    assert b"has expired" in client.get("/admin/client-login?error=expired").data


# ----- proxy trust -----

def test_proxy_host_and_port_headers_are_ignored():
    class Proxied(TestConfig):
        TRUSTED_PROXY_HOPS = 1

    app = create_app(Proxied)
    seen = {}

    @app.route("/_probe_host")
    def probe_host():
        from flask import request
        seen.update(addr=request.remote_addr, host=request.host, scheme=request.scheme)
        return "ok"

    app.test_client().get("/_probe_host", headers={
        "X-Forwarded-For": "6.6.6.6, 198.51.100.7", "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "evil.example", "X-Forwarded-Port": "8443"})
    assert seen == {"addr": "198.51.100.7", "host": "localhost", "scheme": "https"}


# ----- URL fields accept http(s) only -----

BAD_URLS = ["javascript:alert(1)", " JaVaScRiPt:alert(1)", "data:text/html,<script>x</script>",
            "vbscript:x", "java\tscript:alert(1)", "ftp://example.com/x", "//evil.example/x", "https:no-host"]


@pytest.mark.parametrize("bad", BAD_URLS)
def test_safe_url_filter(bad):
    assert security.safe_url(bad) == "#"


def test_safe_url_filter_keeps_http_urls():
    assert security.safe_url("https://example.com/a?b=c") == "https://example.com/a?b=c"
    assert security.safe_url(None) == "#"


@pytest.mark.parametrize("bad", BAD_URLS)
def test_crud_rejects_non_http_urls(client, admin, seeded, bad):
    headers = {"X-API-Key": admin.issued_api_key}
    assert client.post("/api/evidence", headers=headers, json={
        "test_record_id": "t1", "evidence_type": "link", "url": bad}).status_code == 400
    assert client.put("/api/evidence/e1", headers=headers, json={"url": bad}).status_code == 400
    for field in ("website_url", "privacy_policy_url", "security_page_url", "tos_url"):
        assert client.post("/api/vendors", headers=headers, json={"name": "V", field: bad}).status_code == 400
        assert client.put("/api/vendors/v1", headers=headers, json={field: bad}).status_code == 400
    assert db.session.get(Evidence, "e1").url is None
    assert Vendor.query.count() == 1


def test_crud_accepts_http_urls(client, admin, seeded):
    headers = {"X-API-Key": admin.issued_api_key}
    assert client.post("/api/vendors", headers=headers, json={
        "name": "V", "website_url": "https://v.example", "tos_url": ""}).status_code == 201
    assert client.put("/api/evidence/e1", headers=headers, json={"url": "http://e.example/x"}).status_code == 200


def test_record_execution_rejects_non_http_evidence_url(client, admin, seeded):
    resp = client.post("/api/tests/t1/record-execution", headers={"X-API-Key": admin.issued_api_key},
                       json={"outcome": "success", "evidence": [
                           {"evidence_type": "link", "description": "ok", "url": "https://ok.example"},
                           {"evidence_type": "link", "description": "bad", "url": "javascript:alert(1)"}]})
    assert resp.status_code == 400
    db.session.expire_all()
    assert Evidence.query.count() == 1


def test_batch_endpoints_reject_non_http_evidence_url(client, admin, seeded):
    headers = {"X-API-Key": admin.issued_api_key}
    resp = client.post("/api/evidence/batch-submit", headers=headers, json={"evidence": [
        {"test_record_id": "t1", "evidence_type": "link", "description": "d", "url": "javascript:alert(1)"}]})
    assert resp.get_json()["failed"] == 1
    resp = client.post("/api/tests/batch-record-execution", headers=headers, json={"executions": [
        {"test_id": "t1", "outcome": "success",
         "evidence": [{"evidence_type": "link", "description": "d", "url": "data:text/html,x"}]}]})
    assert resp.get_json()["failed"] == 1
    db.session.expire_all()
    assert Evidence.query.count() == 1


def test_admin_forms_reject_non_http_urls(client, admin, seeded):
    login(client, admin)
    client.post("/admin/evidence/upload", data={"test_record_id": "t1", "description": "link",
                                                "evidence_type": "link", "url": "javascript:alert(1)"})
    client.post("/admin/vendors", data={"name": "Evil vendor", "website_url": "javascript:alert(1)"})
    db.session.expire_all()
    assert Evidence.query.count() == 1
    assert Vendor.query.filter_by(name="Evil vendor").count() == 0
    client.post("/admin/vendors", data={"name": "Good vendor", "website_url": "https://good.example"})
    assert Vendor.query.filter_by(name="Good vendor").count() == 1


def test_stored_non_http_urls_render_as_hash(client, admin, seeded):
    vendor = db.session.get(Vendor, "v1")
    vendor.website_url = "javascript:alert(1)"
    db.session.get(Evidence, "e1").file_data = None
    db.session.get(Evidence, "e1").url = "javascript:alert(2)"
    db.session.commit()
    assert b"javascript:" not in client.get("/vendors").data
    login(client, admin)
    assert b"javascript:" not in client.get("/admin/evidence").data


# ----- bootstrap -----

def _revoke_all_keys():
    for member in TeamMember.query.all():
        member.api_key_hash = None
        member.key_rotation_required = True
    db.session.commit()


def test_api_setup_refuses_token_in_body(app_ctx, client):
    app_ctx.config["BOOTSTRAP_TOKEN"] = "boot-token-body"
    # The header is checked before the body is read: a token only in the body is a 401.
    for headers, status in (({}, 401), ({"Authorization": "Bearer boot-token-body"}, 400)):
        resp = client.post("/api/setup", headers=headers,
                           json={"name": "A", "email": "a@example.com", "token": "boot-token-body"})
        assert resp.status_code == status
        assert "Authorization header" in resp.get_json()["error"]
    assert not team_service.admin_exists()


def test_setup_reopens_when_every_admin_is_keyless(app_ctx, client, admin):
    app_ctx.config["BOOTSTRAP_TOKEN"] = "boot-token-reopen"
    assert client.get("/setup").status_code == 404
    _revoke_all_keys()
    assert client.get("/setup").status_code == 200
    resp = client.post("/api/setup", headers={"Authorization": "Bearer boot-token-reopen"},
                       json={"name": "New Owner", "email": "owner@example.com"})
    assert resp.status_code == 201
    assert client.get("/setup").status_code == 404
    assert client.post("/api/setup", headers={"Authorization": "Bearer boot-token-reopen"},
                       json={"name": "B", "email": "b@example.com"}).status_code == 404


def test_setup_form_reopens_when_every_admin_is_keyless(app_ctx, client, admin):
    app_ctx.config["BOOTSTRAP_TOKEN"] = "boot-token-form"
    _revoke_all_keys()
    resp = client.post("/setup", data={"token": "boot-token-form", "name": "Owner", "email": "o@example.com"})
    assert resp.status_code == 200 and b"shown only once" in resp.data


# ----- keyless members in Admin > Team Members -----

def test_keyless_member_is_flagged_and_can_be_reissued(client, admin):
    agent = team_service.create_member("Revoked Agent", "agent@example.com", "agent")
    agent.api_key_hash = None
    agent.key_rotation_required = True
    db.session.commit()
    login(client, admin)
    page = client.get("/admin/team").get_data(as_text=True)
    row = page[page.index("Revoked Agent"):]
    row = row[:row.index("</tr>")]
    assert "No key &mdash; regenerate" in row
    assert "regenerate-key" in row
    resp = client.post(f"/admin/team/{agent.id}/regenerate-key")
    assert resp.status_code == 200
    key = re.search(r'<code class="issued-key-value">([^<]+)</code>', resp.get_data(as_text=True)).group(1)
    db.session.expire_all()
    refreshed = db.session.get(TeamMember, agent.id)
    assert refreshed.has_usable_key and not refreshed.key_rotation_required
    assert client.get("/api/compliance-score", headers={"X-API-Key": key}).status_code == 200


# ----- templates conform to the CSP and carry CSRF tokens -----

INLINE_SCRIPT = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>", re.I)
EVENT_HANDLER = re.compile(r"<[a-z][^<>]*?\son[a-z]+\s*=", re.I | re.S)
JAVASCRIPT_URL = re.compile(r"javascript\s*:", re.I)
FORM_TAG = re.compile(r"<form\b[^>]*>", re.I | re.S)


def _template_files():
    for dirpath, _, files in os.walk(TEMPLATES_ROOT):
        for name in sorted(files):
            if name.endswith(".html"):
                path = os.path.join(dirpath, name)
                with open(path, encoding="utf-8") as fh:
                    yield os.path.relpath(path, TEMPLATES_ROOT), fh.read()


def _csp_violations(html):
    return (INLINE_SCRIPT.findall(html) + EVENT_HANDLER.findall(html) + JAVASCRIPT_URL.findall(html))


def test_templates_have_no_inline_script_handlers_or_javascript_urls():
    found = {name: _csp_violations(src) for name, src in _template_files()}
    assert found and {name: v for name, v in found.items() if v} == {}


def test_every_post_form_carries_a_csrf_token():
    missing = []
    for name, src in _template_files():
        for match in FORM_TAG.finditer(src):
            method = re.search(r'method\s*=\s*["\']?(\w+)', match.group(0), re.I)
            if not method or method.group(1).lower() != "post":
                continue
            end = src.find("</form>", match.end())
            body = src[match.end():end if end != -1 else len(src)]
            if "csrf_field()" not in body:
                missing.append(f"{name}:{src[:match.start()].count(chr(10)) + 1}")
    assert missing == []


def test_rendered_pages_conform_to_the_csp(client, admin, seeded):
    from app.services.settings_service import PUBLIC_SECTION_KEYS, update_portal_settings

    update_portal_settings({"public_sections": list(PUBLIC_SECTION_KEYS)})
    public = ["/", "/controls", "/controls/c1", "/policies", "/systems", "/vendors", "/risks", "/status",
              "/legal", "/ai-transparency", "/admin/login", "/admin/client-login"]
    for path in public:
        resp = client.get(path)
        assert resp.status_code == 200, path
        assert _csp_violations(resp.get_data(as_text=True)) == [], path
    login(client, admin)
    for path in ["/admin/", "/admin/team", "/admin/evidence", "/admin/settings", "/admin/audit-log",
                 "/admin/controls", "/admin/vendors", "/admin/policies", "/admin/risks", "/admin/systems",
                 "/admin/report", "/admin/collectors", "/admin/setup/collectors"]:
        resp = client.get(path)
        assert resp.status_code == 200, path
        assert _csp_violations(resp.get_data(as_text=True)) == [], path
