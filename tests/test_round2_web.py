"""Web hardening (SQLite): rate-limit call sites consume the budget once per
attempt, configurable public sections, server-side logout, session integrity,
the last-admin guard, outbound-request (SSRF) protection and CRUD input
validation."""

import ipaddress
import socket
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import pytest
import requests
from requests.structures import CaseInsensitiveDict

from app import create_app
from app.config import TestConfig
from app.models import db, Control, PentestFinding, Policy, RiskRegister, TeamMember
from app.services import rate_limit, team_service
from tests.conftest import login

PUBLIC_IP = "93.184.215.14"
DEFAULT_SECTIONS = ["overview", "status", "controls", "policies", "systems", "vendors",
                    "ai_transparency", "legal"]


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


def _key(member):
    return {"X-API-Key": member.issued_api_key}


def _cookie_name(app):
    return app.config["SESSION_COOKIE_NAME"]


def _serializer(app):
    return app.session_interface.get_signing_serializer(app)


def _html(client, path):
    return client.get(path, headers={"Accept": "text/html"})


def _fresh(member_id):
    db.session.expire_all()
    return db.session.get(TeamMember, member_id)


# ----- rate limiting: one atomic consume per attempt -----

@pytest.fixture
def consumed(monkeypatch):
    """Record every ``rate_limit.consume`` call; the read-then-record pattern is refused."""
    calls = []
    real = rate_limit.consume

    def counting(bucket):
        calls.append(bucket)
        return real(bucket)

    def refused(*_args, **_kwargs):
        raise AssertionError("rate limit checked and recorded in separate steps")

    monkeypatch.setattr(rate_limit, "consume", counting)
    monkeypatch.setattr(rate_limit, "is_limited", refused, raising=False)
    monkeypatch.setattr(rate_limit, "record_failure", refused, raising=False)
    return calls


def test_every_login_attempt_consumes_the_budget_once(client, admin, consumed):
    reviewer = team_service.create_member("Reviewer", "r@example.com", "client")
    assert client.post("/admin/login", data={"api_key": "wrong"}).status_code == 401
    assert client.post("/admin/login", data={"api_key": ""}).status_code == 200
    assert client.post("/admin/login", data={"api_key": admin.issued_api_key}).status_code == 302
    assert client.post("/admin/client-login", data={"api_key": "wrong"}).status_code == 401
    assert client.post("/admin/client-login", data={"api_key": reviewer.issued_api_key}).status_code == 302
    assert consumed == ["login"] * 3 + ["client_login"] * 2


def test_every_setup_attempt_consumes_the_budget_once(app_ctx, client, consumed):
    app_ctx.config["BOOTSTRAP_TOKEN"] = "boot-token-consume"
    bearer = {"Authorization": "Bearer boot-token-consume"}
    assert client.post("/setup", data={"token": "wrong", "name": "A", "email": "a@x"}).status_code == 401
    assert client.post("/api/setup", json={"name": "A", "email": "a@x"},
                       headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/api/setup", json={"name": "A"}, headers=bearer).status_code == 400
    assert client.post("/api/setup", json={"name": "A", "email": "a@x"}, headers=bearer).status_code == 201
    assert consumed == ["setup"] * 4


def test_exhausted_budget_refuses_even_a_valid_key(app_ctx, client, admin):
    app_ctx.config["AUTH_RATE_LIMIT_ATTEMPTS"] = 2
    for _ in range(2):
        assert client.post("/admin/login", data={"api_key": "wrong"}).status_code == 401
    assert client.post("/admin/login", data={"api_key": admin.issued_api_key}).status_code == 429
    assert client.get("/admin/", headers={"Accept": "text/html"}).status_code == 302


# ----- public sections -----

@pytest.fixture
def portal_data(app_ctx):
    control = Control(id="c1", name="MFA", category="security")
    approved = Policy(id="p-ok", title="Access control policy", category="security", status="approved")
    draft = Policy(id="p-draft", title="Secret draft plan", category="security", status="draft")
    approved.controls.append(control)
    draft.controls.append(control)
    db.session.add_all([control, approved, draft, RiskRegister(id="r1", name="Unpatched VPN concentrator")])
    db.session.commit()


PUBLIC_PAGES = {
    "overview": ["/"],
    "status": ["/status"],
    "controls": ["/controls", "/controls/c1"],
    "policies": ["/policies", "/policies/p-ok"],
    "systems": ["/systems"],
    "vendors": ["/vendors"],
    "risks": ["/risks"],
    "ai_transparency": ["/ai-transparency"],
    "legal": ["/legal"],
}


def _put_sections(client, admin, sections):
    return client.put("/api/settings", headers=_key(admin), json={"public_sections": sections})


def test_risk_register_is_private_by_default(client, portal_data):
    resp = client.get("/risks")
    assert resp.status_code == 404
    assert b"Unpatched VPN" not in resp.data
    assert b'href="/risks"' not in client.get("/").data


def test_default_sections_are_public(app_ctx, client, portal_data):
    from app.services.settings_service import get_portal_settings

    assert get_portal_settings()["public_sections"] == DEFAULT_SECTIONS
    for section in DEFAULT_SECTIONS:
        for path in PUBLIC_PAGES[section]:
            assert client.get(path).status_code == 200, path
    home = client.get("/").get_data(as_text=True)
    for href in ('href="/controls"', 'href="/policies"', 'href="/systems"', 'href="/vendors"',
                 'href="/status"', 'href="/ai-transparency"', 'href="/legal"'):
        assert href in home, href


def test_admin_can_publish_the_risk_register(client, admin, portal_data):
    resp = _put_sections(client, admin, DEFAULT_SECTIONS + ["risks"])
    assert resp.status_code == 200
    assert "risks" in resp.get_json()["public_sections"]
    page = client.get("/risks")
    assert page.status_code == 200 and b"Unpatched VPN" in page.data
    assert b'href="/risks"' in client.get("/").data


def test_disabling_policies_hides_their_pages_and_links(client, admin, portal_data):
    assert _put_sections(client, admin, [s for s in DEFAULT_SECTIONS if s != "policies"]).status_code == 200
    assert client.get("/policies").status_code == 404
    assert client.get("/policies/p-ok").status_code == 404
    assert b'href="/policies"' not in client.get("/").data
    detail = client.get("/controls/c1")
    assert detail.status_code == 200 and b"/policies/p-ok" not in detail.data


def test_every_section_can_be_disabled(client, admin, portal_data):
    assert _put_sections(client, admin, []).status_code == 200
    for paths in PUBLIC_PAGES.values():
        for path in paths:
            assert client.get(path).status_code == 404, path


def test_null_restores_the_default_sections(client, admin, portal_data):
    assert _put_sections(client, admin, ["overview", "risks"]).status_code == 200
    assert client.get("/risks").status_code == 200
    assert client.get("/controls").status_code == 404
    assert _put_sections(client, admin, None).status_code == 200
    assert client.get("/risks").status_code == 404
    assert client.get("/controls").status_code == 200


@pytest.mark.parametrize("value", [["overview", "nope"], "risks", [1], {"risks": True}, [None], [["risks"]]])
def test_public_sections_are_validated(client, admin, portal_data, value):
    resp = _put_sections(client, admin, value)
    assert resp.status_code == 400
    assert "public_sections" in resp.get_json()["error"]
    assert client.get("/risks").status_code == 404
    assert client.get("/controls").status_code == 200


def test_public_sections_are_stored_in_canonical_order_without_duplicates(client, admin):
    resp = _put_sections(client, admin, ["risks", "overview", "risks"])
    assert resp.status_code == 200
    assert resp.get_json()["public_sections"] == ["overview", "risks"]


def test_only_admins_change_public_sections(client, portal_data):
    agent = team_service.create_member("Agent", "agent@example.com", "agent")
    assert _put_sections(client, agent, DEFAULT_SECTIONS + ["risks"]).status_code == 403
    assert client.get("/risks").status_code == 404


def _settings_form(**extra):
    form = {"company_legal_name": "Example Ltd", "soc2_current_stage": "not_started"}
    form.update(extra)
    return form


def test_admin_settings_page_edits_public_sections(client, admin, portal_data):
    login(client, admin)
    page = client.get("/admin/settings").get_data(as_text=True)
    assert 'name="public_sections"' in page and 'value="risks"' in page
    resp = client.post("/admin/settings", data=_settings_form(
        public_sections_form="1", public_sections=DEFAULT_SECTIONS + ["risks"]))
    assert resp.status_code == 302
    assert client.get("/risks").status_code == 200
    resp = client.post("/admin/settings", data=_settings_form(public_sections_form="1",
                                                              public_sections=["overview"]))
    assert resp.status_code == 302
    assert client.get("/risks").status_code == 404 and client.get("/controls").status_code == 404


def test_admin_settings_page_rejects_unknown_sections(client, admin, portal_data):
    login(client, admin)
    resp = client.post("/admin/settings", data=_settings_form(
        public_sections_form="1", public_sections=["overview", "risks", "bogus"]), follow_redirects=True)
    assert b"public_sections" in resp.data or b"Unknown public section" in resp.data
    assert client.get("/risks").status_code == 404


def test_admin_settings_form_without_sections_keeps_them(client, admin, portal_data):
    assert _put_sections(client, admin, DEFAULT_SECTIONS + ["risks"]).status_code == 200
    login(client, admin)
    assert client.post("/admin/settings", data=_settings_form()).status_code == 302
    assert client.get("/risks").status_code == 200


def test_control_detail_lists_approved_policies_only(client, portal_data):
    body = client.get("/controls/c1").get_data(as_text=True)
    assert "Access control policy" in body
    assert "Secret draft plan" not in body and "p-draft" not in body


# ----- logout revokes the session server-side -----

def _sign_in(app, member):
    browser = app.test_client()
    assert browser.post("/admin/login", data={"api_key": member.issued_api_key}).status_code == 302
    return browser


def _replay(app, cookie_value):
    browser = app.test_client()
    browser.set_cookie(_cookie_name(app), cookie_value)
    return browser


def test_logout_revokes_a_copied_session_cookie(app_ctx, admin):
    browser = _sign_in(app_ctx, admin)
    copied = browser.get_cookie(_cookie_name(app_ctx)).value
    assert _html(_replay(app_ctx, copied), "/admin/").status_code == 200
    assert browser.post("/admin/logout").status_code == 302
    replay = _replay(app_ctx, copied)
    resp = _html(replay, "/admin/")
    assert resp.status_code == 302 and "/admin/login" in resp.headers["Location"]
    assert _replay(app_ctx, copied).get("/api/collectors").status_code == 401
    assert _fresh(admin.id).session_epoch == 1
    assert _html(_sign_in(app_ctx, admin), "/admin/").status_code == 200


def test_logout_ends_every_session_of_the_member(app_ctx, admin):
    first, second = _sign_in(app_ctx, admin), _sign_in(app_ctx, admin)
    assert first.post("/admin/logout").status_code == 302
    assert _html(second, "/admin/").status_code == 302


def test_logout_without_a_session_changes_nothing(app_ctx, client, admin):
    assert client.post("/admin/logout").status_code == 302
    assert _fresh(admin.id).session_epoch == 0


def test_session_of_an_earlier_epoch_is_rejected(app_ctx, admin):
    browser = _sign_in(app_ctx, admin)
    member = _fresh(admin.id)
    member.session_epoch = member.session_epoch + 1
    db.session.commit()
    assert _html(browser, "/admin/").status_code == 302


def test_session_cookie_records_the_epoch(app_ctx, admin):
    browser = _sign_in(app_ctx, admin)
    data = _serializer(app_ctx).loads(browser.get_cookie(_cookie_name(app_ctx)).value)
    assert data.get("epoch") == 0


# ----- session integrity -----

def _forged(app, admin, **fields):
    payload = {"member_id": admin.id, "key_fp": admin.key_fingerprint}
    payload.update(fields)
    return _replay(app, _serializer(app).dumps(payload))


@pytest.mark.parametrize("login_at", ["x", None, [1], True])
def test_session_with_an_invalid_login_time_is_rejected(app_ctx, admin, login_at):
    assert _html(_forged(app_ctx, admin, login_at=login_at), "/admin/").status_code == 302


def test_session_with_a_future_login_time_is_rejected(app_ctx, admin):
    future = int(time.time()) + 3600
    assert _html(_forged(app_ctx, admin, login_at=future), "/admin/").status_code == 302
    assert _html(_forged(app_ctx, admin, login_at=int(time.time())), "/admin/").status_code == 200


def test_legacy_session_key_is_dropped(app_ctx, admin):
    browser = _replay(app_ctx, _serializer(app_ctx).dumps({"api_key": admin.issued_api_key}))
    assert browser.get("/admin/login").status_code == 200
    cookie = browser.get_cookie(_cookie_name(app_ctx))
    assert cookie is None or "api_key" not in _serializer(app_ctx).loads(cookie.value)


# ----- the last usable admin cannot be removed -----

def _deactivate(client, member_id):
    return client.post(f"/admin/team/{member_id}/deactivate", follow_redirects=True)


def test_last_admin_cannot_deactivate_themselves(app_ctx, client, admin):
    app_ctx.config["BOOTSTRAP_TOKEN"] = "boot-token-last-admin"
    login(client, admin)
    resp = _deactivate(client, admin.id)
    assert b"last active compliance admin" in resp.data
    assert _fresh(admin.id).is_active
    assert team_service.admin_exists()
    assert client.get("/setup").status_code == 404


def test_other_admins_can_be_deactivated_but_not_the_last(client, admin):
    other = team_service.create_member("Second", "second@example.com", "human", is_compliance_admin=True)
    login(client, admin)
    _deactivate(client, other.id)
    assert not _fresh(other.id).is_active
    resp = _deactivate(client, admin.id)
    assert b"last active compliance admin" in resp.data
    assert _fresh(admin.id).is_active


def test_keyless_and_expired_admins_do_not_count(client, admin):
    keyless = team_service.create_member("Keyless", "k@example.com", "human", is_compliance_admin=True)
    keyless.api_key_hash = None
    team_service.create_member("Expired", "e@example.com", "human", is_compliance_admin=True,
                               expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    db.session.commit()
    login(client, admin)
    _deactivate(client, admin.id)
    assert _fresh(admin.id).is_active


def test_service_refuses_to_deactivate_the_last_admin(app_ctx, admin):
    with pytest.raises(getattr(team_service, "LastAdminError", ValueError)):
        team_service.deactivate_member(admin.id)
    assert _fresh(admin.id).is_active


def test_members_who_are_not_the_last_admin_can_be_deactivated(client, admin):
    agent = team_service.create_member("Agent", "agent@example.com", "agent")
    login(client, admin)
    _deactivate(client, agent.id)
    assert not _fresh(agent.id).is_active


def test_expired_admin_does_not_keep_setup_closed(app_ctx, client):
    team_service.create_member("Expired", "e@example.com", "human", is_compliance_admin=True,
                               expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    app_ctx.config["BOOTSTRAP_TOKEN"] = "boot-token-expired"
    assert not team_service.admin_exists()
    assert client.get("/setup").status_code == 200


# ----- outbound requests refuse internal addresses (SSRF) -----

def _safe_http():
    from app.services import safe_http
    return safe_http


def _fake_getaddrinfo(mapping):
    def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002 - socket's signature
        addresses = mapping.get(host)
        if addresses is None:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known") from None
            addresses = [host]
        results = []
        for address in addresses:
            if ":" in address:
                results.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (address, port or 0, 0, 0)))
            else:
                results.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port or 0)))
        return results
    return getaddrinfo


DNS = {
    "public.example": [PUBLIC_IP],
    "other.example": ["151.101.1.69"],
    "localhost": ["127.0.0.1", "::1"],
    "internal.example": ["10.0.0.9"],
    "mixed.example": [PUBLIC_IP, "10.0.0.9"],
    "metadata.example": ["169.254.169.254"],
    "ghe.internal.example": ["10.0.0.7"],
    "api.github.com": ["140.82.121.6"],
}


@pytest.fixture
def dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo(DNS))


def _response(status=200, headers=None, url=None):
    response = requests.Response()
    response.status_code = status
    response._content = b"{}"
    response.headers = CaseInsensitiveDict(headers or {})
    response.url = url
    return response


def _session(*responses):
    session = mock.Mock(spec=requests.Session)
    session.get.side_effect = list(responses)
    return session


REFUSED_URLS = [
    "http://127.0.0.1/", "http://localhost:8080/admin", "http://10.1.2.3/x", "http://172.16.0.1/",
    "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data/", "http://169.254.170.2/v2/credentials",
    "http://[::1]/", "http://[fd00:ec2::254]/latest/meta-data/", "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:a9fe:a9fe]/", "http://0.0.0.0/", "http://224.0.0.1/", "http://100.64.0.1/",
    "http://[fe80::1]/", "http://internal.example/", "http://mixed.example/", "http://metadata.example/",
    "http://[64:ff9b::a9fe:a9fe]/", "http://[2002:a9fe:a9fe::1]/", "http://[::]/", "http://192.0.0.192/",
    "http://100.100.100.200/",
]


@pytest.mark.parametrize("url", REFUSED_URLS)
def test_internal_addresses_are_refused(dns, url):
    safe_http = _safe_http()
    session = _session(_response())
    with pytest.raises(safe_http.UnsafeURLError):
        safe_http.safe_get(url, timeout=5, session=session)
    session.get.assert_not_called()


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://public.example/", "gopher://public.example/",
                                 "http://", "//public.example/x", "", "https://user:pw@public.example/",
                                 "http://unknown.example/", None])
def test_invalid_or_unresolvable_urls_are_refused(dns, url):
    safe_http = _safe_http()
    session = _session(_response())
    with pytest.raises(safe_http.UnsafeURLError):
        safe_http.safe_get(url, timeout=5, session=session)
    session.get.assert_not_called()


def test_public_address_is_fetched_without_automatic_redirects(dns):
    safe_http = _safe_http()
    session = _session(_response(200))
    response = safe_http.safe_get("https://public.example/status", timeout=7, session=session)
    assert response.status_code == 200
    args, kwargs = session.get.call_args
    assert args[0] == "https://public.example/status"
    assert kwargs["allow_redirects"] is False and kwargs["timeout"] == 7


def test_redirect_to_an_internal_address_is_refused(dns):
    safe_http = _safe_http()
    session = _session(_response(302, {"Location": "http://169.254.169.254/latest/meta-data/"}), _response())
    with pytest.raises(safe_http.UnsafeURLError):
        safe_http.safe_get("https://public.example/", timeout=5, session=session)
    assert session.get.call_count == 1


def test_public_redirects_are_followed_and_rechecked(dns):
    safe_http = _safe_http()
    session = _session(_response(301, {"Location": "/moved"}),
                       _response(307, {"Location": "https://other.example/final"}), _response(200))
    response = safe_http.safe_get("https://public.example/start", timeout=5, session=session,
                                  headers={"Authorization": "Bearer secret", "Accept": "text/html"})
    assert response.status_code == 200
    urls = [call.args[0] for call in session.get.call_args_list]
    assert urls == ["https://public.example/start", "https://public.example/moved", "https://other.example/final"]
    headers = [call.kwargs["headers"] for call in session.get.call_args_list]
    assert headers[1]["Authorization"] == "Bearer secret"
    assert "Authorization" not in headers[2] and headers[2]["Accept"] == "text/html"


def test_redirect_limit(dns):
    safe_http = _safe_http()
    session = mock.Mock(spec=requests.Session)
    session.get.side_effect = lambda *a, **k: _response(302, {"Location": "https://public.example/loop"})
    with pytest.raises(requests.TooManyRedirects):
        safe_http.safe_get("https://public.example/loop", timeout=5, session=session, max_redirects=3)
    assert session.get.call_count == 4


@pytest.mark.parametrize("url,allowed", [
    ("http://10.0.0.5/health", True), ("http://127.0.0.1:8080/health", True), ("http://internal.example/", True),
    ("http://[fd12:3456::1]/", True), ("http://169.254.169.254/", False), ("http://169.254.1.1/", False),
    ("http://[fd00:ec2::254]/", False), ("http://[fe80::1]/", False), ("http://224.0.0.1/", False),
    ("http://0.0.0.0/", False),
])
def test_allow_private_admits_private_hosts_but_never_metadata(dns, url, allowed):
    safe_http = _safe_http()
    session = _session(_response(200))
    if allowed:
        assert safe_http.safe_get(url, timeout=5, session=session, allow_private=True).status_code == 200
    else:
        with pytest.raises(safe_http.UnsafeURLError):
            safe_http.safe_get(url, timeout=5, session=session, allow_private=True)
        session.get.assert_not_called()


class _FakeSocket:
    def __init__(self, peer):
        self.peer = peer
        self.closed = False

    def getpeername(self):
        return self.peer

    def close(self):
        self.closed = True

    def settimeout(self, _value):
        pass

    def setsockopt(self, *_args):
        pass


def test_connection_to_an_internal_peer_is_refused(monkeypatch):
    """A name that re-resolves to an internal address between the check and
    the connection (DNS rebinding) is refused when the socket connects."""
    import urllib3.connection

    safe_http = _safe_http()
    sock = _FakeSocket(("169.254.169.254", 80))
    monkeypatch.setattr(urllib3.connection.connection, "create_connection", lambda *a, **k: sock)
    connection = safe_http.GuardedHTTPConnection("public.example", 80)
    with pytest.raises(safe_http.UnsafeURLError):
        connection.connect()
    assert sock.closed
    public = _FakeSocket((PUBLIC_IP, 80))
    monkeypatch.setattr(urllib3.connection.connection, "create_connection", lambda *a, **k: public)
    fine = safe_http.GuardedHTTPConnection("public.example", 80)
    fine.connect()
    assert not public.closed


def test_default_session_checks_the_connected_peer(dns, monkeypatch):
    import urllib3.connection

    safe_http = _safe_http()
    monkeypatch.setattr(urllib3.connection.connection, "create_connection",
                        lambda *a, **k: _FakeSocket(("10.0.0.9", 80)))
    with pytest.raises(safe_http.UnsafeURLError):
        safe_http.safe_get("http://public.example/", timeout=5)
    session = safe_http.guarded_session()
    assert isinstance(session.get_adapter("https://public.example/"), safe_http.GuardedAdapter)
    assert isinstance(session.get_adapter("http://public.example/"), safe_http.GuardedAdapter)


def test_vendor_probe_refuses_internal_urls(dns):
    from collectors.vendor_check_collector import _probe_url

    _safe_http()
    with mock.patch("requests.Session.get") as get:
        result = _probe_url("http://169.254.169.254/latest/meta-data/", timeout=3)
        get.assert_not_called()
    assert result["reachable"] is False and "refused" in result["error"]
    with mock.patch("requests.Session.get", return_value=_response(200)) as get:
        assert _probe_url("https://public.example/security", timeout=3)["reachable"] is True
        assert get.call_args.kwargs["allow_redirects"] is False


def _platform(services):
    from collectors.platform_collector import PlatformCollector

    config = SimpleNamespace(config={"services": services}, name="platform", id="cfg",
                             credential_mode="none", encrypted_credentials=None)
    return PlatformCollector(config=config, resolver=None)


def _elapsed_response(status=200):
    response = _response(status)
    response.elapsed = timedelta(milliseconds=5)
    return response


def test_platform_collector_refuses_private_hosts_by_default(app_ctx, dns):
    _safe_http()
    with mock.patch("requests.Session.get", return_value=_elapsed_response()) as get:
        results = _platform([{"name": "internal", "url": "http://10.0.0.8", "health_path": "/health"}]).run()
        get.assert_not_called()
    health = [r for r in results if r.check_name == "platform_health:internal"]
    assert health[0].status == "fail" and "refused" in health[0].message


def test_platform_collector_allow_private_per_service(app_ctx, dns):
    _safe_http()
    services = [
        {"name": "internal", "url": "http://10.0.0.8", "health_path": "/health", "allow_private": True},
        {"name": "metadata", "url": "http://169.254.169.254", "allow_private": True},
        {"name": "truthy", "url": "http://10.0.0.8", "allow_private": "yes"},
    ]
    with mock.patch("requests.Session.get", return_value=_elapsed_response()) as get:
        results = {r.check_name: r for r in _platform(services).run()}
    assert [call.args[0] for call in get.call_args_list] == ["http://10.0.0.8/health"]
    assert results["platform_health:internal"].status == "pass"
    assert results["platform_health:metadata"].status == "fail"
    assert results["platform_health:truthy"].status == "fail"


def test_github_enterprise_on_a_private_address_is_refused(dns):
    from app.services.git_sources.providers import GitHubProvider, GitSourceError

    _safe_http()
    session = _session(_response(200))
    provider = GitHubProvider("acme/policies", "main", api_url="https://ghe.internal.example/api/v3",
                              session=session)
    with pytest.raises(GitSourceError, match="refused"):
        provider.resolve_head()
    session.get.assert_not_called()


def test_github_redirect_to_an_internal_address_is_refused(dns):
    from app.services.git_sources.providers import GitHubProvider, GitSourceError

    _safe_http()
    session = _session(_response(301, {"Location": "http://169.254.169.254/latest/meta-data/"}))
    provider = GitHubProvider("acme/policies", "main", session=session)
    with pytest.raises(GitSourceError, match="refused"):
        provider.resolve_head()
    assert session.get.call_count == 1


def test_github_default_session_checks_the_connected_peer():
    from app.services.git_sources.providers import GitHubProvider

    safe_http = _safe_http()
    provider = GitHubProvider("acme/policies", "main")
    assert isinstance(provider._session.get_adapter("https://api.github.com/"), safe_http.GuardedAdapter)


# ----- CRUD input validation -----

@pytest.mark.parametrize("body", [
    {"id": "x" * 500, "name": "n", "category": "security"},
    {"name": "x" * 256, "category": "security"},
    {"name": {"a": 1}, "category": "security"},
    {"name": ["n"], "category": "security"},
    {"name": 5, "category": "security"},
])
def test_crud_rejects_invalid_strings(client, admin, body):
    resp = client.post("/api/controls", headers=_key(admin), json=body)
    assert resp.status_code == 400
    assert Control.query.count() == 0


def test_crud_rejects_duplicate_ids(client, admin):
    body = {"id": "dup", "name": "n", "category": "security"}
    assert client.post("/api/controls", headers=_key(admin), json=body).status_code == 201
    assert client.post("/api/controls", headers=_key(admin), json=body).status_code == 409
    assert client.get("/api/controls/dup", headers=_key(admin)).status_code == 200


def test_crud_validates_typed_columns(client, admin):
    assert client.post("/api/pentest-findings", headers=_key(admin), json={"layer": "x"}).status_code == 400
    assert client.post("/api/pentest-findings", headers=_key(admin), json={"layer": True}).status_code == 400
    assert client.post("/api/pentest-findings", headers=_key(admin), json={"layer": 3}).status_code == 201
    assert PentestFinding.query.count() == 1


def test_crud_accepts_iso_dates(client, admin):
    created = client.post("/api/policies", headers=_key(admin),
                          json={"id": "pd", "title": "T", "category": "security", "next_review_at": "2026-12-31"})
    assert created.status_code == 201
    assert created.get_json()["next_review_at"].startswith("2026-12-31")
    resp = client.put("/api/policies/pd", headers=_key(admin), json={"next_review_at": "2027-01-15T10:00:00Z"})
    assert resp.status_code == 200 and resp.get_json()["next_review_at"].startswith("2027-01-15")
    assert client.put("/api/policies/pd", headers=_key(admin),
                      json={"next_review_at": "not a date"}).status_code == 400
    assert client.put("/api/policies/pd", headers=_key(admin), json={"title": "x" * 600}).status_code == 400
    assert db.session.get(Policy, "pd").title == "T"


def test_admin_form_rejects_over_long_values(client, admin):
    login(client, admin)
    resp = client.post("/admin/controls", data={"name": "n" * 300, "category": "security"},
                       follow_redirects=True)
    assert b"Not saved" in resp.data
    assert Control.query.count() == 0
