"""The git sources API (``/api/git-sources``): admin-only access, creation and
validation, lookup by id or name, updates, queued syncs, run history and the
cutover commit. Stored credentials are never returned."""

import json

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.config import TestConfig
from app.models import db
from app.models.git_source import GitSource, GitSyncRun
from app.services import scheduler, team_service
from app.services.collector_encryption import decrypt_credentials

TOKEN = "ghp_NEVER_ECHO_THIS_TOKEN"


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("COLLECTOR_ENCRYPTION_KEYS", Fernet.generate_key().decode())
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin(app):
    return team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)


@pytest.fixture
def headers(admin):
    return {"X-API-Key": admin.issued_api_key}


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "governance"
    (root / "policies").mkdir(parents=True)
    (root / "policies" / "a.md").write_text("# A\n")
    return root


def create(client, headers, **overrides):
    body = {"name": "governance", "role": "governance", "provider": "local", "repository": "/srv/governance"}
    body.update(overrides)
    return client.post("/api/git-sources", headers=headers, json=body)


ROUTES = [
    ("GET", "/api/git-sources"),
    ("POST", "/api/git-sources"),
    ("GET", "/api/git-sources/governance"),
    ("PUT", "/api/git-sources/governance"),
    ("POST", "/api/git-sources/governance/sync"),
    ("GET", "/api/git-sources/governance/runs"),
    ("GET", "/api/git-sources/governance/runs/some-run"),
    ("POST", "/api/git-sources/governance/last-synced-commit"),
]


@pytest.mark.parametrize("method, path", ROUTES)
def test_routes_require_an_api_key(client, method, path):
    resp = client.open(path, method=method, headers={"X-API-Key": "not-a-key"}, json={})
    assert resp.status_code == 401
    resp = client.open(path, method=method, json={})
    assert resp.status_code == 401


@pytest.mark.parametrize("method, path", ROUTES)
def test_routes_reject_non_admin_members(app, client, method, path):
    human = team_service.create_member("User", "user@example.com", "human")
    reviewer = team_service.create_member("Auditor", "auditor@example.com", "client")
    resp = client.open(path, method=method, headers={"X-API-Key": human.issued_api_key}, json={})
    assert resp.status_code == 403
    assert resp.get_json() == {"error": "Admin access required"}
    # Client keys are denied by the client allowlist before the admin check.
    resp = client.open(path, method=method, headers={"X-API-Key": reviewer.issued_api_key}, json={})
    assert resp.status_code == 403
    assert "error" in resp.get_json()
    assert GitSource.query.count() == 0


def test_get_without_key_is_401(client):
    resp = client.get("/api/git-sources")
    assert resp.status_code == 401
    assert resp.get_json() == {"error": "Missing API key"}


def test_create_and_list(client, headers, admin):
    assert client.get("/api/git-sources", headers=headers).get_json() == []
    resp = create(client, headers, branch="release", schedule_cron="*/30 * * * *")
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["name"] == "governance"
    assert body["branch"] == "release"
    assert body["credential_mode"] == "none"
    assert body["enabled"] is True
    assert body["next_run_at"] is not None
    assert body["effective_path_mappings"][0] == {"pattern": "policies/**/*.md", "kind": "policy"}
    source = db.session.get(GitSource, body["id"])
    assert source.created_by_id == admin.id

    create(client, headers, name="alpha-evidence", role="evidence")
    listing = client.get("/api/git-sources", headers=headers).get_json()
    assert [s["name"] for s in listing] == ["alpha-evidence", "governance"]


def test_create_stored_token_never_echoes_credentials(client, headers):
    resp = create(client, headers, provider="github", repository="octo/governance",
                  credential_mode="stored_token", credentials={"token": TOKEN})
    assert resp.status_code == 201
    body = resp.get_json()
    assert body["has_stored_credentials"] is True
    assert "credentials" not in body and "encrypted_credentials" not in body
    assert TOKEN not in resp.get_data(as_text=True)
    assert decrypt_credentials(db.session.get(GitSource, body["id"]).encrypted_credentials) == {"token": TOKEN}

    for path in ("/api/git-sources", "/api/git-sources/governance", f"/api/git-sources/{body['id']}"):
        assert TOKEN not in client.get(path, headers=headers).get_data(as_text=True)
    updated = client.put("/api/git-sources/governance", headers=headers,
                         json={"credentials": {"token": TOKEN + "2"}})
    assert updated.status_code == 200
    assert TOKEN not in updated.get_data(as_text=True)


@pytest.mark.parametrize("overrides, message", [
    ({"repository": ""}, "repository is required"),
    ({"name": "bad name"}, "name must be"),
    ({"role": "archive"}, "role must be one of"),
    ({"provider": "svn"}, "provider must be one of"),
    ({"credential_mode": "stored_token", "provider": "github", "repository": "o/r"}, "credentials.token"),
    ({"schedule_cron": "every day"}, "invalid cron expression"),
    ({"path_mappings": [{"pattern": "../x", "kind": "policy"}]}, "invalid pattern"),
    ({"options": {"api_url": "http://example.com"}}, "https://"),
    ({"unexpected": 1}, "unknown field"),
])
def test_create_validation_errors(client, headers, overrides, message):
    resp = create(client, headers, **overrides)
    assert resp.status_code == 400
    assert message in resp.get_json()["error"]
    assert GitSource.query.count() == 0


@pytest.mark.parametrize("body", [None, "just text", [1, 2]])
def test_create_requires_a_json_object(client, headers, body):
    if body is None:
        resp = client.post("/api/git-sources", headers=headers, data="not json", content_type="text/plain")
    else:
        resp = client.post("/api/git-sources", headers=headers, json=body)
    assert resp.status_code == 400
    assert resp.get_json() == {"error": "JSON object body required"}


def test_create_duplicate_name(client, headers):
    assert create(client, headers).status_code == 201
    resp = create(client, headers, repository="/srv/other")
    assert resp.status_code == 400
    assert "already exists" in resp.get_json()["error"]
    assert GitSource.query.count() == 1


def test_get_by_id_and_by_name(client, headers):
    source_id = create(client, headers).get_json()["id"]
    by_id = client.get(f"/api/git-sources/{source_id}", headers=headers)
    by_name = client.get("/api/git-sources/governance", headers=headers)
    assert by_id.status_code == by_name.status_code == 200
    assert by_id.get_json() == by_name.get_json()
    missing = client.get("/api/git-sources/nope", headers=headers)
    assert missing.status_code == 404
    assert missing.get_json() == {"error": "No git source 'nope'"}


def test_update(client, headers, admin):
    source_id = create(client, headers).get_json()["id"]
    resp = client.put(f"/api/git-sources/{source_id}", headers=headers,
                      json={"branch": "trunk", "enabled": False, "schedule_cron": "0 2 * * 0",
                            "path_mappings": [{"pattern": "docs/*.md", "kind": "policy"}],
                            "options": {"record_commits": False}})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["branch"] == "trunk"
    assert body["enabled"] is False
    assert body["next_run_at"] is None
    assert body["schedule_cron"] == "0 2 * * 0"
    assert body["path_mappings"] == body["effective_path_mappings"] == [{"pattern": "docs/*.md", "kind": "policy"}]
    assert body["options"] == {"record_commits": False, "history_limit": 500}
    assert db.session.get(GitSource, source_id).updated_by_id == admin.id

    reset = client.put("/api/git-sources/governance", headers=headers, json={"path_mappings": None})
    assert reset.get_json()["path_mappings"] is None


def test_update_errors(client, headers):
    create(client, headers)
    create(client, headers, name="other")
    bad = client.put("/api/git-sources/governance", headers=headers, json={"schedule_cron": "nope"})
    assert bad.status_code == 400 and "invalid cron" in bad.get_json()["error"]
    clash = client.put("/api/git-sources/governance", headers=headers, json={"name": "other"})
    assert clash.status_code == 400 and "already exists" in clash.get_json()["error"]
    not_object = client.put("/api/git-sources/governance", headers=headers, json=["x"])
    assert not_object.status_code == 400
    assert not_object.get_json() == {"error": "JSON object body required"}
    missing = client.put("/api/git-sources/nope", headers=headers, json={"branch": "x"})
    assert missing.status_code == 404
    source = client.get("/api/git-sources/governance", headers=headers).get_json()
    assert source["schedule_cron"] is None and source["name"] == "governance"


def test_sync_queues_once_and_reports_runs(client, headers, admin, repo):
    source_id = create(client, headers, repository=str(repo)).get_json()["id"]
    queued = client.post("/api/git-sources/governance/sync", headers=headers)
    assert queued.status_code == 202
    run = queued.get_json()
    assert run["status"] == "queued"
    assert run["trigger_type"] == "api"
    assert run["triggered_by_team_member_id"] == admin.id
    assert run["poll_url"] == f"/api/git-sources/{source_id}/runs/{run['id']}"

    again = client.post(f"/api/git-sources/{source_id}/sync", headers=headers)
    assert again.status_code == 409
    assert again.get_json()["id"] == run["id"]
    assert GitSyncRun.query.count() == 1

    polled = client.get(run["poll_url"], headers=headers)
    assert polled.status_code == 200
    assert polled.get_json()["status"] == "queued"

    assert scheduler.execute_claimed("git_sync", run["id"]) == "executed"
    done = client.get(run["poll_url"], headers=headers).get_json()
    assert done["status"] == "success"
    assert done["counts"]["created"] == 1
    assert done["to_commit"].startswith("local-")
    assert done["finished_at"] is not None

    second = client.post("/api/git-sources/governance/sync", headers=headers)
    assert second.status_code == 202
    runs = client.get("/api/git-sources/governance/runs", headers=headers)
    assert runs.status_code == 200
    assert [r["id"] for r in runs.get_json()] == [second.get_json()["id"], run["id"]]
    source = client.get("/api/git-sources/governance", headers=headers).get_json()
    assert source["last_sync_status"] == "success"
    assert source["last_synced_commit"] == done["to_commit"]
    assert source["last_synced_at"] is not None


def test_sync_full_reimport_request(client, headers, repo):
    create(client, headers, repository=str(repo))
    queued = client.post("/api/git-sources/governance/sync", headers=headers, json={"full": True})
    assert queued.status_code == 202
    run = queued.get_json()
    assert run["details"] == {"requested": {"full": True}}
    scheduler.execute_claimed("git_sync", run["id"])
    done = client.get(run["poll_url"], headers=headers).get_json()
    assert done["details"]["strategy"] == "full"
    assert done["details"]["requested"] == {"full": True}

    plain = client.post("/api/git-sources/governance/sync", headers=headers, json={"full": False})
    assert plain.status_code == 202 and plain.get_json()["details"] == {}


def test_run_lookup_is_scoped_to_its_source(client, headers):
    create(client, headers)
    create(client, headers, name="other")
    run_id = client.post("/api/git-sources/governance/sync", headers=headers).get_json()["id"]
    assert client.get(f"/api/git-sources/governance/runs/{run_id}", headers=headers).status_code == 200
    wrong = client.get(f"/api/git-sources/other/runs/{run_id}", headers=headers)
    assert wrong.status_code == 404
    assert wrong.get_json() == {"error": "Run not found"}
    assert client.get("/api/git-sources/governance/runs/unknown", headers=headers).status_code == 404
    assert client.get("/api/git-sources/other/runs", headers=headers).get_json() == []


@pytest.mark.parametrize("path", ["/api/git-sources/nope/sync", "/api/git-sources/nope/runs",
                                  "/api/git-sources/nope/runs/x", "/api/git-sources/nope/last-synced-commit"])
def test_unknown_source_is_404(client, headers, path):
    method = "GET" if path.endswith(("/runs", "/runs/x")) else "POST"
    resp = client.open(path, method=method, headers=headers, json={"commit_id": "a" * 40})
    assert resp.status_code == 404


def test_set_last_synced_commit(client, headers, admin):
    source_id = create(client, headers).get_json()["id"]
    commit = "0123456789abcdef0123456789abcdef01234567"
    resp = client.post("/api/git-sources/governance/last-synced-commit", headers=headers,
                       json={"commit_id": commit.upper()})
    assert resp.status_code == 200
    assert resp.get_json()["last_synced_commit"] == commit
    assert db.session.get(GitSource, source_id).updated_by_id == admin.id

    for body in ({"commit_id": "abc"}, {}, None, {"commit_id": "z" * 40}):
        kwargs = {"json": body} if body is not None else {"data": "", "content_type": "application/json"}
        bad = client.post("/api/git-sources/governance/last-synced-commit", headers=headers, **kwargs)
        assert bad.status_code == 400
        assert "full commit SHA" in bad.get_json()["error"]
    assert client.get("/api/git-sources/governance", headers=headers).get_json()["last_synced_commit"] == commit


def test_bearer_token_is_accepted(client, admin):
    resp = client.get("/api/git-sources", headers={"Authorization": f"Bearer {admin.issued_api_key}"})
    assert resp.status_code == 200


def test_flasgger_spec_documents_the_routes(client):
    spec = client.get("/apispec_1.json")
    assert spec.status_code == 200
    paths = json.loads(spec.get_data(as_text=True))["paths"]
    assert {"/git-sources", "/git-sources/{source_ref}", "/git-sources/{source_ref}/sync",
            "/git-sources/{source_ref}/runs", "/git-sources/{source_ref}/runs/{run_id}",
            "/git-sources/{source_ref}/last-synced-commit"} <= set(paths)
    create_doc = paths["/git-sources"]["post"]
    assert create_doc["tags"] == ["Git sources"]
    assert set(create_doc["responses"]) == {"201", "400"}


def test_raw_openapi_spec_is_served(client):
    """``/api/openapi.json`` (documented as the raw spec) serves the same spec
    as the Swagger UI, git-source routes included."""
    spec = client.get("/api/openapi.json")
    assert spec.status_code == 200
    assert "/git-sources" in spec.get_json()["paths"]


def test_disabled_source_cannot_be_synced(client, headers):
    source_id = create(client, headers, enabled=False).get_json()["id"]
    resp = client.post(f"/api/git-sources/{source_id}/sync", headers=headers)
    assert resp.status_code == 400
    assert "disabled" in resp.get_json()["error"]


@pytest.mark.parametrize("overrides, message", [
    ({"provider": "github", "repository": "not-owner-slash-name"}, "GitHub owner/name"),
    ({"provider": "codecommit", "repository": "a/b"}, "CodeCommit repository name"),
    ({"provider": "local", "repository": "relative/dir"}, "absolute directory path"),
    ({"branch": "bad..branch"}, "invalid branch name"),
    ({"provider": "github", "repository": "o/r", "credential_mode": "none",
      "options": {"api_url": "https://user:pw@ghe.example.com/api/v3"}}, "without credentials"),
    ({"provider": "github", "repository": "o/r", "credential_mode": "none",
      "options": {"api_url": "https://ghe.example.com/api/v3?x=1"}}, "without credentials"),
])
def test_create_rejects_invalid_repositories_and_urls(client, headers, overrides, message):
    resp = create(client, headers, **overrides)
    assert resp.status_code == 400
    assert message in resp.get_json()["error"]


def test_options_update_merges_and_null_resets(client, headers):
    source_id = create(client, headers, options={"history_limit": 20, "record_commits": True}).get_json()["id"]
    body = client.put(f"/api/git-sources/{source_id}", headers=headers,
                      json={"options": {"record_commits": False}}).get_json()
    assert body["options"]["history_limit"] == 20 and body["options"]["record_commits"] is False
    body = client.put(f"/api/git-sources/{source_id}", headers=headers,
                      json={"options": {"history_limit": None}}).get_json()
    assert body["options"]["history_limit"] == 500


def test_sync_conflict_that_cannot_be_read_back_is_409(client, headers, monkeypatch):
    from app.routes import git_sources_api

    source_id = create(client, headers).get_json()["id"]

    def conflict(*args, **kwargs):
        raise scheduler.ActiveRunConflict("git_sync", source_id)

    monkeypatch.setattr(git_sources_api, "enqueue_git_sync", conflict)
    resp = client.post("/api/git-sources/governance/sync", headers=headers)
    assert resp.status_code == 409
    assert resp.get_json() == {"error": f"A git_sync run of {source_id} is already queued or running"}


GHE = "https://ghe.example.com/api/v3"


@pytest.mark.parametrize("mode, credentials, allowed", [
    ("portal_secret", None, False),
    ("stored_token", {"token": TOKEN}, True),
    ("none", None, True),
])
def test_api_url_requires_a_mode_that_never_sends_the_portal_token(client, headers, mode, credentials,
                                                                   allowed):
    body = {"provider": "github", "repository": "o/r", "credential_mode": mode, "options": {"api_url": GHE}}
    if credentials:
        body["credentials"] = credentials
    resp = create(client, headers, **body)
    if allowed:
        assert resp.status_code == 201
    else:
        assert resp.status_code == 400
        assert "requires credential_mode stored_token or none" in resp.get_json()["error"]
        assert GitSource.query.count() == 0


def test_api_url_rules_apply_to_updates_and_mode_switches(client, headers):
    assert create(client, headers, provider="github", repository="o/r").status_code == 201  # portal_secret
    resp = client.put("/api/git-sources/governance", headers=headers, json={"options": {"api_url": GHE}})
    assert resp.status_code == 400 and "stored_token or none" in resp.get_json()["error"]
    # the default host is always allowed
    resp = client.put("/api/git-sources/governance", headers=headers,
                      json={"options": {"api_url": "https://api.github.com/"}})
    assert resp.status_code == 200
    resp = client.put("/api/git-sources/governance", headers=headers,
                      json={"credential_mode": "none", "options": {"api_url": GHE}})
    assert resp.status_code == 200 and resp.get_json()["options"]["api_url"] == GHE
    switch = client.put("/api/git-sources/governance", headers=headers, json={"credential_mode": "portal_secret"})
    assert switch.status_code == 400 and "stored_token or none" in switch.get_json()["error"]
    db.session.expire_all()
    assert db.session.get(GitSource, GitSource.query.one().id).credential_mode == "none"


def test_local_sources_are_refused_in_production_without_roots(client, headers, monkeypatch):
    monkeypatch.setenv("PORTAL_ENV", "production")
    monkeypatch.delenv("LOCAL_SOURCE_ROOTS", raising=False)
    resp = create(client, headers, repository="/etc")
    assert resp.status_code == 400
    assert "disabled in production; set LOCAL_SOURCE_ROOTS" in resp.get_json()["error"]
    assert GitSource.query.count() == 0


def test_local_sources_must_be_inside_local_source_roots(client, headers, monkeypatch, tmp_path):
    allowed = tmp_path / "srv"
    (allowed / "x").mkdir(parents=True)
    (allowed / "escape").symlink_to("/etc")
    monkeypatch.setenv("PORTAL_ENV", "production")
    monkeypatch.setenv("LOCAL_SOURCE_ROOTS", str(allowed))
    for path in ("/etc", str(allowed / "escape"), str(tmp_path)):
        resp = create(client, headers, repository=path)
        assert resp.status_code == 400 and "outside LOCAL_SOURCE_ROOTS" in resp.get_json()["error"]
    assert create(client, headers, repository=str(allowed / "x")).status_code == 201
    moved = client.put("/api/git-sources/governance", headers=headers, json={"repository": "/etc"})
    assert moved.status_code == 400 and "outside LOCAL_SOURCE_ROOTS" in moved.get_json()["error"]


def test_branch_whitespace_defaults_to_main(client, headers):
    body = create(client, headers, branch="   ").get_json()
    assert body["branch"] == "main"
