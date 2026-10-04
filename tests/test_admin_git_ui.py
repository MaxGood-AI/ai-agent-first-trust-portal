"""Admin pages for git sources, governance documents and change history
(``app.routes.admin_git``), driven through a logged-in browser session."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.config import TestConfig
from app.models import db
from app.models.git_source import GitCommit, GitFileVersion, GitSource, GitSourceFile, GitSyncRun
from app.services import scheduler, team_service
from app.services.collector_encryption import decrypt_credentials
from app.services.git_sources import service
from tests.conftest import login

HTML = {"Accept": "text/html"}
ROLE_ARN = "arn:aws:iam::123456789012:role/git-reader"


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
def admin(app):
    return team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)


@pytest.fixture
def client(app, admin):
    client = app.test_client()
    login(client, admin)
    return client


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "governance"
    files = {
        "policies/encryption.md": "---\nowner: Security\n---\n# Encryption\n\nEncrypt **everything**.\n",
        "CLAUDE.md": "# Agents\n\nBe careful.\n",
        "infrastructure/network.tf": "resource \"x\" \"y\" {}\n",
    }
    for path, content in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return root


def make_source(name="governance", role="governance", **extra):
    data = {"name": name, "role": role, "provider": "local", "repository": "/srv/" + name}
    data.update(extra)
    return service.create_source(data)


def sync_now(source):
    run, _ = scheduler.enqueue_git_sync(source, "manual")
    assert scheduler.execute_claimed("git_sync", run.id) == "executed"
    db.session.expire_all()
    return db.session.get(GitSyncRun, run.id)


def file_record(source, path):
    return GitSourceFile.query.filter_by(source_id=source.id, path=path).one()


def page(resp):
    assert resp.status_code == 200, resp.status_code
    return resp.get_data(as_text=True)


# --------------------------------------------------------------------------
# Access control
# --------------------------------------------------------------------------

PAGES = ["/admin/git-sources", "/admin/git-sources/governance", "/admin/governance",
         "/admin/governance/files/x", "/admin/governance/changes"]
POSTS = ["/admin/git-sources", "/admin/git-sources/governance", "/admin/git-sources/governance/sync",
         "/admin/git-sources/governance/last-synced-commit"]


@pytest.mark.parametrize("path", PAGES)
def test_pages_redirect_anonymous_browsers_to_login(app, path):
    resp = app.test_client().get(path, headers=HTML)
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


@pytest.mark.parametrize("path", PAGES)
def test_pages_redirect_non_admins(app, path):
    member = team_service.create_member("User", "user@example.com", "human")
    client = app.test_client()
    login(client, member)
    resp = client.get(path, headers=HTML)
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]
    assert "error=forbidden" in resp.headers["Location"]


@pytest.mark.parametrize("path", POSTS)
def test_posts_rejected_for_non_admins(app, path):
    make_source()
    member = team_service.create_member("User", "user@example.com", "human")
    client = app.test_client()
    login(client, member)
    resp = client.post(path, headers=HTML, data={"name": "x", "role": "governance", "provider": "local",
                                                 "repository": "/x", "commit_id": "a" * 40})
    assert resp.status_code == 302
    assert "error=forbidden" in resp.headers["Location"]
    assert GitSource.query.count() == 1
    assert GitSyncRun.query.count() == 0
    assert db.session.get(GitSource, GitSource.query.one().id).last_synced_commit is None


def test_api_clients_without_admin_rights_get_403(app):
    reviewer = team_service.create_member("Auditor", "auditor@example.com", "client")
    resp = app.test_client().get("/admin/git-sources", headers={"X-API-Key": reviewer.issued_api_key})
    assert resp.status_code == 403


# --------------------------------------------------------------------------
# Source list, create, detail, update
# --------------------------------------------------------------------------

def test_list_page(client):
    assert "No git sources yet." in page(client.get("/admin/git-sources"))
    make_source(schedule_cron="*/30 * * * *")
    make_source("evidence", role="evidence", enabled=False)
    html = page(client.get("/admin/git-sources"))
    assert "governance" in html and "evidence" in html
    assert "/srv/governance" in html
    assert "*/30 * * * *" in html and "next " in html
    assert "Sync now" in html


def test_create_via_form(client, admin, repo):
    resp = client.post("/admin/git-sources", data={
        "name": "governance", "role": "governance", "provider": "local", "repository": str(repo),
        "branch": "main", "region": "", "credential_mode": "", "role_arn": "", "external_id": "",
        "token": "", "schedule_cron": "0 * * * *", "enabled": "on", "record_commits": "on",
    })
    source = GitSource.query.one()
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith(f"/admin/git-sources/{source.id}")
    assert source.credential_mode == "none"
    assert source.schedule_cron == "0 * * * *"
    assert source.region is None
    assert source.enabled is True
    assert source.options == {"record_commits": True}
    assert source.created_by_id == admin.id
    html = page(client.get(resp.headers["Location"]))
    assert "Created git source governance." in html
    assert "policies/**/*.md" in html  # effective mappings


def test_create_with_stored_token_and_assume_role(client):
    client.post("/admin/git-sources", data={
        "name": "gh", "role": "evidence", "provider": "github", "repository": "octo/evidence",
        "credential_mode": "stored_token", "token": "ghp_form_token", "history_limit": "20"})
    github = GitSource.query.filter_by(name="gh").one()
    assert decrypt_credentials(github.encrypted_credentials) == {"token": "ghp_form_token"}
    assert github.enabled is False  # an unchecked checkbox is not sent
    assert github.options == {"record_commits": False, "history_limit": 20}
    detail = page(client.get(f"/admin/git-sources/{github.id}"))
    assert "(stored, encrypted)" in detail
    assert "ghp_form_token" not in detail

    client.post("/admin/git-sources", data={
        "name": "cc", "role": "governance", "provider": "codecommit", "repository": "governance",
        "region": "ca-central-1", "credential_mode": "assume_role", "role_arn": ROLE_ARN,
        "external_id": "ext-1", "enabled": "on"})
    codecommit = GitSource.query.filter_by(name="cc").one()
    assert codecommit.region == "ca-central-1"
    assert decrypt_credentials(codecommit.encrypted_credentials) == {"role_arn": ROLE_ARN, "external_id": "ext-1"}


@pytest.mark.parametrize("form, message", [
    ({"name": "bad name"}, "name must be 1-100 letters"),
    ({"repository": ""}, "repository is required"),
    ({"schedule_cron": "whenever"}, "invalid cron expression: whenever"),
    ({"credential_mode": "assume_role", "provider": "codecommit", "repository": "governance"},
     "credentials.role_arn is required"),
    ({"provider": "codecommit", "repository": "a/b"}, "repository must be a CodeCommit repository name"),
    ({"history_limit": "lots"}, "history_limit must be an integer"),
])
def test_create_invalid_form_flashes_and_redirects(client, form, message):
    data = {"name": "governance", "role": "governance", "provider": "local", "repository": "/srv/g"}
    data.update(form)
    resp = client.post("/admin/git-sources", data=data)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/admin/git-sources")
    assert GitSource.query.count() == 0
    assert message in page(client.get("/admin/git-sources"))


def test_detail_page(client, repo):
    source = make_source(repository=str(repo))
    by_id = page(client.get(f"/admin/git-sources/{source.id}"))
    by_name = page(client.get("/admin/git-sources/governance"))
    assert "Git source: governance" in by_id and "Git source: governance" in by_name
    assert "No syncs yet." in by_id
    assert "Files needing attention" not in by_id

    (repo / "policies" / "binary.md").write_bytes(b"\xff\xfe")
    sync_now(source)
    html = page(client.get(f"/admin/git-sources/{source.id}"))
    assert "Files needing attention" in html
    assert "policies/binary.md" in html and "not UTF-8" in html
    assert "partial" in html and "manual" in html
    assert source.last_synced_commit[:8] in html
    assert client.get("/admin/git-sources/nope").status_code == 404


def test_update_via_form(client, admin):
    source = make_source(options={"history_limit": 50, "record_commits": True})
    resp = client.post(f"/admin/git-sources/{source.id}", data={
        "repository": "/srv/moved", "branch": "release", "region": "", "credential_mode": "none",
        "role_arn": "", "external_id": "", "token": "", "schedule_cron": "15 3 * * 1",
        "history_limit": "75"})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith(f"/admin/git-sources/{source.id}")
    db.session.expire_all()
    source = db.session.get(GitSource, source.id)
    assert source.repository == "/srv/moved"
    assert source.branch == "release"
    assert source.schedule_cron == "15 3 * * 1"
    assert source.enabled is False
    assert source.options == {"record_commits": False, "history_limit": 75}
    assert source.updated_by_id == admin.id
    assert "Saved." in page(client.get(resp.headers["Location"]))


def test_update_cannot_change_name_role_or_provider(client):
    source = make_source()
    client.post(f"/admin/git-sources/{source.id}", data={
        "name": "renamed", "role": "evidence", "provider": "github", "repository": "/srv/governance",
        "credential_mode": "none", "enabled": "on"})
    db.session.expire_all()
    source = db.session.get(GitSource, source.id)
    assert (source.name, source.role, source.provider) == ("governance", "governance", "local")
    assert source.enabled is True


def test_update_invalid_form_flashes_error(client):
    source = make_source(schedule_cron="0 * * * *")
    resp = client.post("/admin/git-sources/governance", data={
        "repository": "/srv/governance", "credential_mode": "none", "schedule_cron": "99 * * * *"})
    assert resp.status_code == 302
    html = page(client.get(resp.headers["Location"]))
    assert "invalid cron expression: 99 * * * *" in html
    db.session.expire_all()
    assert db.session.get(GitSource, source.id).schedule_cron == "0 * * * *"
    assert client.post("/admin/git-sources/nope", data={}).status_code == 404


def test_update_form_keeps_stored_credentials_when_left_blank(client):
    """The detail page says "leave blank to keep": saving the form with the
    role ARN / token fields empty must keep the stored credentials."""
    source = make_source("cc", provider="codecommit", repository="governance",
                         credential_mode="assume_role", credentials={"role_arn": ROLE_ARN})
    resp = client.post(f"/admin/git-sources/{source.id}", data={
        "repository": "governance", "branch": "release", "region": "", "credential_mode": "assume_role",
        "role_arn": "", "external_id": "", "token": "", "schedule_cron": "", "history_limit": "500",
        "enabled": "on", "record_commits": "on"})
    html = page(client.get(resp.headers["Location"]))
    assert "credentials.role_arn is required" not in html
    assert "Saved." in html
    db.session.expire_all()
    source = db.session.get(GitSource, source.id)
    assert source.branch == "release"
    assert decrypt_credentials(source.encrypted_credentials) == {"role_arn": ROLE_ARN}


def test_update_form_keeps_the_github_api_url(client):
    """The form has no API URL field: saving it must not drop the GitHub
    Enterprise ``api_url`` option (the next sync would call api.github.com)."""
    source = make_source("ghe", provider="github", repository="octo/governance", credential_mode="none",
                         options={"api_url": "https://ghe.example.com/api/v3"})
    client.post(f"/admin/git-sources/{source.id}", data={
        "repository": "octo/governance", "branch": "main", "region": "", "credential_mode": "none",
        "role_arn": "", "external_id": "", "token": "", "schedule_cron": "", "history_limit": "500",
        "enabled": "on", "record_commits": "on"})
    db.session.expire_all()
    source = db.session.get(GitSource, source.id)
    assert source.options.get("api_url") == "https://ghe.example.com/api/v3"


# --------------------------------------------------------------------------
# Sync now and cutover commit
# --------------------------------------------------------------------------

def test_sync_now(client, admin):
    source = make_source()
    first = client.post(f"/admin/git-sources/{source.id}/sync")
    assert first.status_code == 302
    run = GitSyncRun.query.one()
    assert run.trigger_type == "manual"
    assert run.triggered_by_team_member_id == admin.id
    html = page(client.get(first.headers["Location"]))
    assert f"Sync queued (run {run.id[:8]})." in html
    assert "queued" in html

    again = client.post("/admin/git-sources/governance/sync")
    assert f"A sync is already queued (run {run.id[:8]})." in page(client.get(again.headers["Location"]))
    assert GitSyncRun.query.count() == 1
    assert client.post("/admin/git-sources/nope/sync").status_code == 404


def test_sync_now_reports_an_unreadable_active_run(client, monkeypatch):
    from app.routes import admin_git

    source = make_source()

    def conflict(*args, **kwargs):
        raise scheduler.ActiveRunConflict("git_sync", source.id)

    monkeypatch.setattr(admin_git, "enqueue_git_sync", conflict)
    resp = client.post(f"/admin/git-sources/{source.id}/sync")
    assert resp.status_code == 302
    assert "A sync of this source is already queued or running" in page(client.get(resp.headers["Location"]))
    assert GitSyncRun.query.count() == 0


def test_sync_now_full_reimport(client):
    source = make_source()
    assert "Full re-import" in page(client.get(f"/admin/git-sources/{source.id}"))
    client.post(f"/admin/git-sources/{source.id}/sync", data={"full": "on"})
    run = GitSyncRun.query.one()
    assert run.details == {"requested": {"full": True}}


def test_set_last_synced_commit(client, admin):
    source = make_source()
    commit = "f" * 64
    resp = client.post(f"/admin/git-sources/{source.id}/last-synced-commit", data={"commit_id": commit.upper()})
    assert f"Last synced commit set to {commit}." in page(client.get(resp.headers["Location"]))
    db.session.expire_all()
    assert db.session.get(GitSource, source.id).last_synced_commit == commit
    assert db.session.get(GitSource, source.id).updated_by_id == admin.id

    bad = client.post("/admin/git-sources/governance/last-synced-commit", data={"commit_id": "abc"})
    assert "commit_id must be a full commit SHA" in page(client.get(bad.headers["Location"]))
    db.session.expire_all()
    assert db.session.get(GitSource, source.id).last_synced_commit == commit
    missing = client.post("/admin/git-sources/nope/last-synced-commit", data={"commit_id": "a" * 40})
    assert missing.status_code == 404


# --------------------------------------------------------------------------
# Governance documents
# --------------------------------------------------------------------------

def test_governance_list(client, repo, tmp_path):
    assert "No governance documents yet." in page(client.get("/admin/governance"))
    source = make_source(repository=str(repo))
    run = sync_now(source)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    (evidence_root / "controls.json").write_text("[]")
    sync_now(make_source("evidence", role="evidence", repository=str(evidence_root)))

    html = page(client.get("/admin/governance"))
    for path in ("policies/encryption.md", "CLAUDE.md", "infrastructure/network.tf"):
        assert path in html
    assert "controls.json" not in html
    assert "governance document" in html
    assert run.to_commit[:12] in html


def test_governance_file_and_versions(client, repo):
    source = make_source(repository=str(repo))
    sync_now(source)
    record = file_record(source, "policies/encryption.md")
    old_version = record.current_version_id
    (repo / "policies" / "encryption.md").write_text("# Encryption\n\nEncrypt **everything**, always.\n")
    sync_now(source)
    db.session.expire_all()
    record = file_record(source, "policies/encryption.md")
    assert record.current_version_id != old_version

    html = page(client.get(f"/admin/governance/files/{record.id}"))
    assert "<strong>everything</strong>, always." in html
    assert "owner: Security" not in html
    assert "(not the current version)" not in html
    assert html.count("(current)") == 1

    old = page(client.get(f"/admin/governance/files/{record.id}?version={old_version}"))
    assert "(not the current version)" in old
    assert "<strong>everything</strong>." in old
    assert "owner: Security" not in old  # front matter is not rendered

    other = file_record(source, "CLAUDE.md")
    foreign = client.get(f"/admin/governance/files/{record.id}?version={other.current_version_id}")
    assert foreign.status_code == 404
    assert client.get(f"/admin/governance/files/{record.id}?version=missing").status_code == 200
    assert client.get("/admin/governance/files/nope").status_code == 404


def test_governance_file_non_markdown_and_without_version(client, repo):
    source = make_source(repository=str(repo))
    sync_now(source)
    terraform = file_record(source, "infrastructure/network.tf")
    html = page(client.get(f"/admin/governance/files/{terraform.id}"))
    assert "<pre>resource &#34;x&#34; &#34;y&#34; {}" in html

    flagged = GitSourceFile(id=str(uuid.uuid4()), source_id=source.id, path="policies/huge.md",
                            kind="policy", status="too_large", size=10**9)
    db.session.add(flagged)
    db.session.commit()
    assert "No stored version." in page(client.get(f"/admin/governance/files/{flagged.id}"))


def test_governance_file_of_an_evidence_source_is_404(client, tmp_path):
    root = tmp_path / "evidence"
    (root / "notes").mkdir(parents=True)
    (root / "notes" / "a.md").write_text("# Note\n")
    source = make_source("evidence", role="evidence", repository=str(root),
                         path_mappings=[{"pattern": "notes/*.md", "kind": "governance_document"}])
    sync_now(source)
    record = file_record(source, "notes/a.md")
    assert record.current_version_id is not None
    assert client.get(f"/admin/governance/files/{record.id}").status_code == 404


def test_governance_file_with_a_missing_source_is_404(client, repo):
    source = make_source(repository=str(repo))
    orphan = GitSourceFile(id=str(uuid.uuid4()), source_id=str(uuid.uuid4()), path="x.md", kind="policy")
    db.session.add(orphan)
    db.session.commit()
    assert source is not None
    assert client.get(f"/admin/governance/files/{orphan.id}").status_code == 404


# --------------------------------------------------------------------------
# Change history
# --------------------------------------------------------------------------

def add_commits(source, count, start, prefix="change"):
    for index in range(count):
        db.session.add(GitCommit(
            id=str(uuid.uuid4()), source_id=source.id, commit_id=uuid.uuid4().hex + "abcdefab",
            author_name="Dev", author_email="dev@example.com",
            committed_at=start + timedelta(minutes=index), message=f"{prefix} {index:03d}",
            paths=["policies/encryption.md"]))
    db.session.commit()


def test_change_history(client):
    assert "No change records yet." in page(client.get("/admin/governance/changes"))
    governance = make_source()
    evidence = make_source("evidence", role="evidence")
    start = datetime(2026, 5, 1, tzinfo=timezone.utc)
    add_commits(governance, 51, start)
    add_commits(evidence, 1, start - timedelta(days=1), prefix="evidence")

    first = page(client.get("/admin/governance/changes"))
    assert "change 050" in first and "change 001" in first
    assert "change 000" not in first and "evidence 000" not in first
    assert "dev@example.com" in first and "policies/encryption.md" in first
    assert "Older &rarr;" in first and "&larr; Newer" not in first

    second = page(client.get("/admin/governance/changes?page=2"))
    assert "change 000" in second and "evidence 000" in second
    assert "change 050" not in second
    assert "&larr; Newer" in second and "Older &rarr;" not in second

    filtered = page(client.get(f"/admin/governance/changes?source={evidence.id}"))
    assert "evidence 000" in filtered and "change 0" not in filtered
    assert f'value="{evidence.id}" selected' in filtered

    for bad_page in ("abc", "0", "-3"):
        assert "change 050" in page(client.get(f"/admin/governance/changes?page={bad_page}"))
    assert "No change records yet." in page(client.get("/admin/governance/changes?page=9"))


def test_change_history_records_from_a_sync_version_rows(client, repo):
    """Versions written by a sync appear on the file page with their commit and digest."""
    source = make_source(repository=str(repo))
    run = sync_now(source)
    record = file_record(source, "CLAUDE.md")
    version = db.session.get(GitFileVersion, record.current_version_id)
    html = page(client.get(f"/admin/governance/files/{record.id}"))
    assert version.sha256 in html and run.to_commit in html
