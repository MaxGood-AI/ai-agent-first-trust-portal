"""Round-4 web hardening: request body limits (H1), JSON limits (M1), the
durable-admin guard, proxy-free outbound requests, the client session budget
and control names on public pages."""

import io
import json
import pathlib
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest
import requests

from app import create_app
from app.config import TestConfig
from app.models import db, Control, DecisionLogSession, Evidence, Policy, TeamMember, TestRecord
from app.services import team_service
from app.services.settings_service import update_portal_settings
from tests.conftest import login, raw_client

ROOT = pathlib.Path(__file__).resolve().parents[1]
MiB = 1024 * 1024
PUBLIC_IP = "93.184.215.14"


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
def agent(app_ctx):
    return team_service.create_member("Agent", "agent@example.com", "agent")


def _key(member):
    return {"X-API-Key": member.issued_api_key}


class TrackingStream(io.BytesIO):
    """A request body that records how many bytes the application read."""

    def __init__(self, data):
        super().__init__(data)
        self.bytes_read = 0

    def read(self, size=-1):
        chunk = super().read(size)
        self.bytes_read += len(chunk)
        return chunk

    def readline(self, size=-1):
        chunk = super().readline(size)
        self.bytes_read += len(chunk)
        return chunk


def _chunked(client, path, body, headers=None, content_type="application/x-www-form-urlencoded"):
    """POST ``body`` without a Content-Length, as a server that terminates chunked input delivers it."""
    stream = TrackingStream(body)
    all_headers = {"Transfer-Encoding": "chunked", "Content-Type": content_type, **(headers or {})}
    resp = client.post(path, input_stream=stream, headers=all_headers,
                       environ_overrides={"wsgi.input_terminated": True})
    return resp, stream


# ----- H1: request body limits -----

MEMORY_PROBE = """
import io, json, resource, sys
sys.path.insert(0, {root!r})
from app import create_app
from app.config import TestConfig
from app.models import db

app = create_app(type("Cfg", (TestConfig,), {{"PROPAGATE_EXCEPTIONS": False}}))
with app.app_context():
    db.create_all()


def call(path, body, mode):
    env = {{"REQUEST_METHOD": "POST", "PATH_INFO": path, "QUERY_STRING": "", "SERVER_NAME": "localhost",
           "SERVER_PORT": "80", "SERVER_PROTOCOL": "HTTP/1.1", "wsgi.url_scheme": "http",
           "wsgi.input": io.BytesIO(body), "wsgi.errors": io.StringIO(), "wsgi.version": (1, 0),
           "wsgi.multithread": True, "wsgi.multiprocess": False, "wsgi.run_once": False,
           "CONTENT_TYPE": "application/x-www-form-urlencoded"}}
    if mode == "cl":
        env["CONTENT_LENGTH"] = str(len(body))
    else:
        env["HTTP_TRANSFER_ENCODING"] = "chunked"
        env["wsgi.input_terminated"] = True
    out = {{}}
    b"".join(app(env, lambda status, headers, exc_info=None: out.setdefault("status", status)))
    return out["status"]


path, mode = sys.argv[1], sys.argv[2]
body = b"a&" * ((32 * 1024 * 1024 - 16) // 2)
call(path, b"a=1", mode)
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
status = call(path, body, mode)
after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({{"status": status, "peak_growth_kib": after - before}}))
"""


@pytest.mark.parametrize("path,mode", [("/admin/login", "cl"), ("/admin/login", "chunked"),
                                       ("/api/controls", "chunked")])
def test_h1_anonymous_32mib_urlencoded_post_is_413_with_bounded_memory(tmp_path, path, mode):
    script = tmp_path / "memprobe.py"
    script.write_text(MEMORY_PROBE.format(root=str(ROOT)))
    proc = subprocess.run([sys.executable, str(script), path, mode], cwd=str(ROOT), capture_output=True,
                          text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr[-2000:]
    result = json.loads(proc.stdout.strip().splitlines()[-1])
    assert result["status"].startswith("413") and result["peak_growth_kib"] < 8 * 1024, result


def test_h1_limit_hook_runs_before_every_other_hook(app_ctx):
    from app.request_limits import LimitedRequest, apply_route_body_limit

    assert app_ctx.before_request_funcs[None][0] is apply_route_body_limit
    assert app_ctx.request_class is LimitedRequest


@pytest.mark.parametrize("path", ["/admin/login", "/setup", "/api/controls", "/admin/evidence/upload",
                                  "/api/decision-log/upload", "/no/such/route"])
def test_h1_anonymous_body_over_1mib_is_413_before_any_hook_reads_it(app_ctx, path):
    app_ctx.config["BOOTSTRAP_TOKEN"] = "boot-token-h1"
    client = raw_client(app_ctx)
    body = b"a=" + b"x" * (2 * MiB)
    declared = client.post(path, data=body, content_type="application/x-www-form-urlencoded")
    assert declared.status_code == 413
    multipart = client.post(path, data={"file": (io.BytesIO(b"x" * (2 * MiB)), "f.bin")},
                            content_type="multipart/form-data")
    assert multipart.status_code == 413
    resp, stream = _chunked(client, path, body)
    assert resp.status_code == 413
    assert stream.bytes_read <= 1 * MiB + 1


def test_h1_urlencoded_forms_are_capped_by_form_memory_and_parts(client, admin):
    login(client, admin)
    too_big = client.post("/admin/settings", data={"company_legal_name": "x" * 600_000})
    assert too_big.status_code == 413
    too_many = client.post("/admin/settings", data={f"f{i}": "1" for i in range(1001)})
    assert too_many.status_code == 413
    ok = client.post("/admin/settings", data={"company_legal_name": "Acme", "contact_email": "c@example.com"})
    assert ok.status_code in (200, 302)


def test_h1_default_limit_applies_to_authenticated_json_routes(client, agent):
    body = json.dumps({"name": "C", "category": "security", "description": "x" * (2 * MiB)})
    resp = client.post("/api/controls", data=body, content_type="application/json", headers=_key(agent))
    assert resp.status_code == 413


def test_h1_streamed_json_over_the_limit_is_413_not_truncated(client, agent):
    body = json.dumps({"name": "Padded", "category": "security"}).encode() + b" " * (2 * MiB)
    resp, _ = _chunked(client, "/api/controls", body, headers=_key(agent), content_type="application/json")
    assert resp.status_code == 413
    assert Control.query.filter_by(name="Padded").count() == 0
    at_limit = json.dumps({"name": "AtLimit", "category": "security"}).encode().ljust(1 * MiB)
    resp, _ = _chunked(client, "/api/controls", at_limit, headers=_key(agent), content_type="application/json")
    assert resp.status_code == 201


def test_h1_upload_route_accepts_a_large_legal_transcript(client, agent):
    lines = []
    for i in range(2000):
        lines.append(json.dumps({
            "type": "user" if i % 2 == 0 else "assistant",
            "message": {"role": "user" if i % 2 == 0 else "assistant",
                        "content": [{"type": "text", "text": f"entry {i} " + "y" * 2500}], "id": f"m{i}"},
            "timestamp": f"2026-03-16T12:{i // 60 % 60:02d}:{i % 60:02d}Z",
        }))
    body = ("\n".join(lines) + "\n").encode()
    assert 4 * MiB < len(body) < 32 * MiB
    resp = client.post("/api/decision-log/upload?session_id=big-legal", data=body,
                       headers={**_key(agent), "Content-Type": "application/jsonl"})
    assert resp.status_code == 200, resp.get_data(as_text=True)[:300]
    assert resp.get_json()["content_bytes"] == len(body)
    chunked, _ = _chunked(client, "/api/decision-log/upload?session_id=big-legal-2", body,
                          headers=_key(agent), content_type="application/jsonl")
    assert chunked.status_code == 200, chunked.get_data(as_text=True)[:300]
    assert DecisionLogSession.query.count() == 2


def test_h1_raised_limit_applies_only_to_authenticated_requests(app_ctx, client, admin):
    control = Control(id="c1", name="C1", category="security")
    test = TestRecord(id="t1", name="T1", control_id="c1")
    db.session.add_all([control, test])
    db.session.commit()
    form = {"test_record_id": "t1", "description": "big evidence", "evidence_type": "file"}
    anonymous = raw_client(app_ctx).post(
        "/admin/evidence/upload", content_type="multipart/form-data",
        data={**form, "file": (io.BytesIO(b"z" * (3 * MiB)), "evidence.bin")})
    assert anonymous.status_code == 413
    login(client, admin)
    signed_in = client.post("/admin/evidence/upload", content_type="multipart/form-data",
                            data={**form, "file": (io.BytesIO(b"z" * (3 * MiB)), "evidence.bin")})
    assert signed_in.status_code == 302
    assert len(Evidence.query.one().file_data) == 3 * MiB


def test_h1_verify_route_takes_up_to_8mib_from_an_admin(client, admin):
    padded = json.dumps({"heads": "not-a-list"}).encode() + b" " * (3 * MiB)
    resp = client.post("/api/audit-log/verify", data=padded, content_type="application/json",
                       headers=_key(admin))
    assert resp.status_code != 413
    over = json.dumps({"heads": []}).encode() + b" " * (9 * MiB)
    assert client.post("/api/audit-log/verify", data=over, content_type="application/json",
                       headers=_key(admin)).status_code == 413


def test_h1_route_limit_table_names_only_existing_endpoints(app_ctx, monkeypatch):
    from app import request_limits

    request_limits.check_route_limits(app_ctx)
    monkeypatch.setitem(request_limits.ROUTE_BODY_LIMITS, "api.no_such_endpoint", 2 * MiB)
    with pytest.raises(RuntimeError, match="api.no_such_endpoint"):
        request_limits.check_route_limits(app_ctx)


# ----- M1: JSON depth and size limits -----

def _nested(depth):
    return ("[" * depth + "]" * depth).encode()


def _many_values(count):
    return ('{"name": "A", "email": "a@x", "pad": [' + ",".join(["[]"] * count) + "]}").encode()


def test_m1_api_setup_checks_the_token_before_reading_the_body(app_ctx):
    app_ctx.config["BOOTSTRAP_TOKEN"] = "boot-token-m1"
    client = raw_client(app_ctx)
    body = TrackingStream(b"[" + b"[]," * (300_000) + b"[]]")
    resp = client.post("/api/setup", input_stream=body, content_type="application/json",
                       headers={"Content-Length": str(len(body.getvalue())), "Authorization": "Bearer wrong"})
    assert resp.status_code == 401
    assert body.bytes_read == 0
    assert "Authorization header" in resp.get_json()["error"]


def test_m1_api_setup_refuses_deep_and_oversized_json(app_ctx):
    app_ctx.config["BOOTSTRAP_TOKEN"] = "boot-token-m1b"
    client = raw_client(app_ctx)
    bearer = {"Authorization": "Bearer boot-token-m1b"}
    deep = client.post("/api/setup", data=_nested(5000), content_type="application/json", headers=bearer)
    assert deep.status_code == 400
    assert "nested deeper" in deep.get_json()["error"]
    many = client.post("/api/setup", data=_many_values(250_000), content_type="application/json",
                       headers=bearer)
    assert many.status_code == 413
    assert not team_service.admin_exists()
    ok = client.post("/api/setup", json={"name": "Owner", "email": "o@example.com"}, headers=bearer)
    assert ok.status_code == 201


def test_m1_authenticated_json_route_refuses_deep_and_oversized_json(client, agent):
    deep = client.post("/api/controls", data=_nested(5000), content_type="application/json", headers=_key(agent))
    assert deep.status_code == 400
    assert "nested deeper" in deep.get_json()["error"]
    many = client.post("/api/controls", data=_many_values(250_000), content_type="application/json",
                       headers=_key(agent))
    assert many.status_code == 413
    ok = client.post("/api/controls", json={"name": "C", "category": "security"}, headers=_key(agent))
    assert ok.status_code == 201


def test_m1_json_limits_are_applied_without_parsing():
    from app.request_limits import MAX_JSON_DEPTH, check_json_limits, loads_limited
    from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

    brackets = "[{" * MAX_JSON_DEPTH
    assert loads_limited(json.dumps({"a": brackets, "b": [1, {"c": 2}]}).encode()) == \
        {"a": brackets, "b": [1, {"c": 2}]}
    assert loads_limited(_nested(MAX_JSON_DEPTH)) is not None
    with pytest.raises(BadRequest):
        check_json_limits("[" * (MAX_JSON_DEPTH + 1) + "]" * (MAX_JSON_DEPTH + 1))
    with pytest.raises(RequestEntityTooLarge):
        check_json_limits("]" * 300_000)
    with pytest.raises(ValueError):
        loads_limited(b"{not json")
    assert loads_limited('{"k": "\\"[{"}'.encode("utf-16")) == {"k": '"[{'}


# ----- lows -----

def _deactivate(client, member_id):
    return client.post(f"/admin/team/{member_id}/deactivate", follow_redirects=True)


def test_low_last_admin_guard_ignores_admins_expiring_within_30_days(app_ctx, client, admin):
    soon = team_service.create_member("Soon", "soon@example.com", "human", is_compliance_admin=True,
                                      expires_at=datetime.now(timezone.utc) + timedelta(days=10))
    login(client, soon)
    resp = _deactivate(client, admin.id)
    assert b"last active compliance admin" in resp.data
    db.session.expire_all()
    assert db.session.get(TeamMember, admin.id).is_active
    with pytest.raises(team_service.LastAdminError):
        team_service.deactivate_member(admin.id)

    later = team_service.create_member("Later", "later@example.com", "human", is_compliance_admin=True,
                                       expires_at=datetime.now(timezone.utc) + timedelta(days=40))
    assert team_service.is_durable_admin(later) and not team_service.is_durable_admin(soon)
    assert team_service.deactivate_member(soon.id) is not None
    assert team_service.deactivate_member(admin.id) is not None
    with pytest.raises(team_service.LastAdminError):
        team_service.deactivate_member(later.id)


def test_low_guarded_requests_ignore_proxy_environment(monkeypatch):
    from app.services import safe_http

    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 80))])
    sent = []

    def fake_send(self, request, **kwargs):
        sent.append(kwargs.get("proxies") or {})
        response = requests.Response()
        response.status_code = 200
        response._content = b"ok"
        response.url = request.url
        return response

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", fake_send)
    assert safe_http.guarded_session().trust_env is False
    assert safe_http.safe_get("http://pub.test/", timeout=1).status_code == 200
    assert safe_http.safe_get("https://pub.test/", timeout=1).status_code == 200
    assert safe_http.safe_get("http://pub.test/", timeout=1, session=requests.Session()).status_code == 200
    assert len(sent) == 3
    for proxies in sent:
        assert not any(proxies.get(key) for key in ("http", "https", "all")), proxies


def test_low_client_sessions_are_limited_per_member_whatever_the_ip(app_ctx):
    reviewer = team_service.create_member("Reviewer", "r@example.com", "client")
    limit = app_ctx.config["AUTH_RATE_LIMIT_ATTEMPTS"]
    for i in range(limit):
        c = app_ctx.test_client()
        resp = c.post("/admin/client-login", data={"api_key": reviewer.issued_api_key},
                      environ_overrides={"REMOTE_ADDR": f"198.51.100.{i + 1}"})
        assert resp.status_code == 302
        assert c.post("/admin/logout").status_code == 302
    blocked = app_ctx.test_client().post("/admin/client-login", data={"api_key": reviewer.issued_api_key},
                                         environ_overrides={"REMOTE_ADDR": "203.0.113.200"})
    assert blocked.status_code == 429
    other = team_service.create_member("Other", "o@example.com", "client")
    assert app_ctx.test_client().post("/admin/client-login", data={"api_key": other.issued_api_key},
                                      environ_overrides={"REMOTE_ADDR": "203.0.113.200"}).status_code == 302


def test_low_control_names_hidden_unless_controls_section_is_public(app_ctx, client):
    control = Control(id="c1", name="HiddenControlName", category="security")
    policy = Policy(id="p2", title="Approved", category="security", status="approved")
    policy.controls.append(control)
    db.session.add_all([control, policy])
    db.session.commit()
    update_portal_settings({"public_sections": ["policies", "status"]})
    for url in ("/policies/p2", "/status"):
        resp = client.get(url)
        assert resp.status_code == 200
        assert "HiddenControlName" not in resp.get_data(as_text=True), url
    assert "0/0 tests passing" in client.get("/status").get_data(as_text=True)
    update_portal_settings({"public_sections": ["policies", "status", "controls"]})
    for url in ("/policies/p2", "/status"):
        assert "HiddenControlName" in client.get(url).get_data(as_text=True), url
