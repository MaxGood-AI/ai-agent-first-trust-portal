"""Git source mappings, configuration service, sync engine and the governance
read side (public policy pages, admin change history).

Syncs run end to end through ``scheduler.enqueue_git_sync`` +
``scheduler.execute_claimed`` against the local-directory provider on
``tmp_path`` repositories, or against ``FakeProvider`` (patched in as
``sync.build_provider_for``) where a behaviour needs a provider with commit
history, a failing diff, oversized files or unreadable files.
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.config import TestConfig
from app.models import (
    Control, DecisionLogEntry, DecisionLogSession, Evidence, PentestFinding, Policy, db,
)
from app.models import TestRecord as ControlTestRow
from app.models.git_source import GitCommit, GitFileVersion, GitSource, GitSourceFile, GitSyncRun
from app.services import chunked_files, governance_docs, scheduler, team_service
from app.services.collector_encryption import decrypt_credentials
from app.services.evidence_import import DEFAULT_EVIDENCE_MAPPINGS
from app.services.git_sources import mappings, service, sync
from app.services.git_sources.providers import (
    Change,
    CodeCommitProvider,
    CommitInfo,
    FileTooLargeError,
    GitHubProvider,
    GitProvider,
    GitSourceError,
    LocalDirectoryProvider,
    NotFoundError,
    TreeEntry,
)

ZERO_COUNTS = {"created": 0, "updated": 0, "unchanged": 0, "deleted": 0, "skipped": 0,
               "flagged": 0, "incomplete": 0, "errors": 0}


def counts(**values):
    return dict(ZERO_COUNTS, **values)


# --------------------------------------------------------------------------
# Fixtures and helpers
# --------------------------------------------------------------------------

@pytest.fixture
def app(monkeypatch):
    for name in ("COLLECTOR_ENCRYPTION_KEYS", "COLLECTOR_ENCRYPTION_KEY", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def encryption_key(monkeypatch):
    monkeypatch.setenv("COLLECTOR_ENCRYPTION_KEYS", Fernet.generate_key().decode())


@pytest.fixture
def admin(app):
    return team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)


def write(root, path, content):
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        content = content.encode("utf-8")
    target.write_bytes(content)
    return content


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def run_sync(source, member_id=None):
    run, created = scheduler.enqueue_git_sync(source, "manual", member_id)
    assert created
    assert scheduler.execute_claimed("git_sync", run.id) == "executed"
    db.session.expire_all()
    return db.session.get(GitSyncRun, run.id)


def files_of(source):
    return {f.path: f for f in GitSourceFile.query.filter_by(source_id=source.id).all()}


def current_version(record):
    return db.session.get(GitFileVersion, record.current_version_id)


ENCRYPTION_MD = (
    "---\n"
    "title: Encryption Policy\n"
    "owner: Security Team\n"
    "---\n"
    "# Encryption Policy\n\n"
    "All customer data is encrypted at rest.\n"
)
ACCESS_MD = "# Access Control Policy\n\nAccess is reviewed quarterly.\n"
CLAUDE_MD = "# Agent instructions\n\nFollow the policies.\n"
NET_MD = "# Network\n\nPrivate subnets only.\n"

GOVERNANCE_FILES = {
    "policies/encryption.md": ENCRYPTION_MD,
    "policies/sub/access.md": ACCESS_MD,
    "CLAUDE.md": CLAUDE_MD,
    "infrastructure/net.md": NET_MD,
    "other.txt": "not mapped\n",
}
MAPPED_GOVERNANCE = {
    "policies/encryption.md": "policy",
    "policies/sub/access.md": "policy",
    "CLAUDE.md": "governance_document",
    "infrastructure/net.md": "governance_document",
}


@pytest.fixture
def gov_repo(tmp_path):
    root = tmp_path / "governance"
    for path, content in GOVERNANCE_FILES.items():
        write(root, path, content)
    return root


@pytest.fixture
def gov_source(app, gov_repo):
    return service.create_source({"name": "governance", "role": "governance", "provider": "local",
                                  "repository": str(gov_repo)})


def local_head(root, role="governance"):
    """The head a sync of a local ``role`` source records: the provider walks only the mapped roots."""
    patterns = [m["pattern"] for m in mappings.default_mappings(role)]
    return LocalDirectoryProvider(root, include=patterns).resolve_head()


# --------------------------------------------------------------------------
# Mappings
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path, pattern, expected", [
    ("policies/a.md", "policies/**/*.md", True),
    ("policies/x/y/a.md", "policies/**/*.md", True),
    ("policies/a.txt", "policies/**/*.md", False),
    ("other/policies/a.md", "policies/**/*.md", False),
    ("infrastructure/net.md", "infrastructure/**", True),
    ("infrastructure/a/b/c.tf", "infrastructure/**", True),
    ("infrastructure", "infrastructure/**", False),
    ("infrastructure-x/a", "infrastructure/**", False),
    ("a.md", "*.md", True),
    ("dir/a.md", "*.md", False),
    ("a.md", "**/*.md", True),
    ("x/y/a.md", "**/*.md", True),
    ("layer1/a.json", "layer?/*.json", True),
    ("layer12/a.json", "layer?/*.json", False),
    ("layer/a.json", "layer?/*.json", False),
    ("a/b", "a?b", False),
    ("CLAUDE.md", "CLAUDE.md", True),
    ("CLAUDExmd", "CLAUDE.md", False),
    ("a+b(c).md", "a+b(c).md", True),
    ("decision-logs/x.jsonl", "decision-logs/*.jsonl", True),
    ("decision-logs/x.jsonl.manifest.json", "decision-logs/*.jsonl", False),
])
def test_glob_semantics(path, pattern, expected):
    assert mappings.matches(path, pattern) is expected


def test_classify_first_match_wins():
    rules = [
        {"pattern": "policies/special.md", "kind": "governance_document"},
        {"pattern": "policies/**/*.md", "kind": "policy"},
        {"pattern": "**", "kind": "dataset:controls"},
    ]
    assert mappings.classify("policies/special.md", rules) == "governance_document"
    assert mappings.classify("policies/a/other.md", rules) == "policy"
    assert mappings.classify("anything/else.bin", rules) == "dataset:controls"
    assert mappings.classify("x", rules[:2]) is None
    assert mappings.classify("x", []) is None


def test_default_mappings_per_role():
    governance = mappings.default_mappings("governance")
    assert governance == mappings.DEFAULT_GOVERNANCE_MAPPINGS
    governance[0]["kind"] = "changed"  # a copy: the module default is untouched
    assert mappings.DEFAULT_GOVERNANCE_MAPPINGS[0]["kind"] == "policy"
    assert mappings.default_mappings("evidence") == DEFAULT_EVIDENCE_MAPPINGS
    with pytest.raises(ValueError, match="unknown git source role"):
        mappings.default_mappings("other")


def test_default_governance_mappings_classify_the_governance_layout():
    rules = mappings.default_mappings("governance")
    assert mappings.classify("policies/encryption.md", rules) == "policy"
    assert mappings.classify("policies/sub/access.md", rules) == "policy"
    assert mappings.classify("CLAUDE.md", rules) == "governance_document"
    assert mappings.classify("AGENTS.md", rules) == "governance_document"
    assert mappings.classify("README.md", rules) == "governance_document"
    assert mappings.classify("infrastructure/net.md", rules) == "governance_document"
    assert mappings.classify("agent-config/hooks/x.json", rules) == "governance_document"
    assert mappings.classify("sub/CLAUDE.md", rules) is None
    assert mappings.classify("other.txt", rules) is None


def test_effective_mappings_uses_custom_list_or_role_defaults():
    custom = [{"pattern": "docs/*.md", "kind": "policy"}]
    assert mappings.effective_mappings(SimpleNamespace(path_mappings=custom, role="governance")) == custom
    assert mappings.effective_mappings(SimpleNamespace(path_mappings=None, role="evidence")) \
        == DEFAULT_EVIDENCE_MAPPINGS


def test_validate_mappings_normalizes():
    assert mappings.validate_mappings(None) is None
    result = mappings.validate_mappings([
        {"pattern": " /policies/**/*.md ", "kind": "policy"},
        {"pattern": "controls.json", "kind": "dataset:controls"},
        {"pattern": "logs/*.jsonl", "kind": "decision_log"},
        {"pattern": "README.md", "kind": "governance_document", "extra": "dropped"},
    ])
    assert result == [
        {"pattern": "policies/**/*.md", "kind": "policy"},
        {"pattern": "controls.json", "kind": "dataset:controls"},
        {"pattern": "logs/*.jsonl", "kind": "decision_log"},
        {"pattern": "README.md", "kind": "governance_document"},
    ]


@pytest.mark.parametrize("value, message", [
    ([], "non-empty list"),
    ({"pattern": "x", "kind": "policy"}, "non-empty list"),
    ("policies/*.md", "non-empty list"),
    (["policies/*.md"], "string 'pattern' and 'kind'"),
    ([{"pattern": "x"}], "string 'pattern' and 'kind'"),
    ([{"pattern": 1, "kind": "policy"}], "string 'pattern' and 'kind'"),
    ([{"pattern": "x", "kind": None}], "string 'pattern' and 'kind'"),
    ([{"pattern": "  ", "kind": "policy"}], "invalid pattern"),
    ([{"pattern": "/", "kind": "policy"}], "invalid pattern"),
    ([{"pattern": "../secrets/*", "kind": "policy"}], "invalid pattern"),
    ([{"pattern": "a/../b", "kind": "policy"}], "invalid pattern"),
    ([{"pattern": "x", "kind": "unknown"}], "invalid kind"),
    ([{"pattern": "x", "kind": "dataset:"}], "invalid kind"),
    ([{"pattern": "x", "kind": "dataset:Controls"}], "invalid kind"),
    ([{"pattern": "x", "kind": "policy "}], "invalid kind"),
])
def test_validate_mappings_errors(value, message):
    with pytest.raises(ValueError, match=message):
        mappings.validate_mappings(value)


# --------------------------------------------------------------------------
# Service: create / update validation
# --------------------------------------------------------------------------

def base(**overrides):
    data = {"name": "gov", "role": "governance", "provider": "local", "repository": "/srv/gov"}
    data.update(overrides)
    return data


def test_create_local_source_defaults(app, admin):
    source = service.create_source(base(), member_id=admin.id)
    assert source.branch == "main"
    assert source.credential_mode == "none"
    assert source.enabled is True
    assert source.encrypted_credentials is None
    assert source.path_mappings is None
    assert source.created_by_id == admin.id and source.updated_by_id == admin.id
    assert db.session.get(GitSource, source.id) is source


def test_create_strips_and_applies_optional_fields(app):
    source = service.create_source(base(
        name=" gov.repo_1 ", repository=" /srv/gov ", branch=" release ", region=" ca-central-1 ",
        schedule_cron=" */30 * * * * ", enabled=False,
        path_mappings=[{"pattern": "/docs/*.md", "kind": "policy"}],
        options={"record_commits": 0, "history_limit": "25"},
    ))
    assert source.name == "gov.repo_1"
    assert source.repository == "/srv/gov"
    assert source.branch == "release"
    assert source.region == "ca-central-1"
    assert source.schedule_cron == "*/30 * * * *"
    assert source.enabled is False
    assert source.path_mappings == [{"pattern": "docs/*.md", "kind": "policy"}]
    assert source.options == {"record_commits": False, "history_limit": 25}


@pytest.mark.parametrize("missing", ["name", "role", "provider", "repository"])
def test_create_requires_fields(app, missing):
    data = base()
    data[missing] = ""
    with pytest.raises(service.GitSourceConfigError, match=f"{missing} is required"):
        service.create_source(data)


@pytest.mark.parametrize("name", ["-bad", ".hidden", "has space", "x" * 101, "slash/name", "semi;colon"])
def test_create_rejects_invalid_names(app, name):
    with pytest.raises(service.GitSourceConfigError, match="name must be"):
        service.create_source(base(name=name))


def test_create_accepts_name_boundaries(app):
    assert service.create_source(base(name="x" * 100)).name == "x" * 100
    assert service.create_source(base(name="A")).name == "A"


def test_create_rejects_duplicate_name(app):
    service.create_source(base())
    with pytest.raises(service.GitSourceConfigError, match="already exists"):
        service.create_source(base())


@pytest.mark.parametrize("field, value, message", [
    ("role", "archive", "role must be one of governance, evidence"),
    ("provider", "gitlab", "provider must be one of codecommit, github, local"),
    ("credential_mode", "runtime_role", "credential_mode for local must be one of none"),
    ("schedule_cron", "not a cron", "invalid cron expression"),
    ("schedule_cron", "61 * * * *", "invalid cron expression"),
    ("path_mappings", [], "non-empty list"),
    ("path_mappings", [{"pattern": "x", "kind": "bogus"}], "invalid kind"),
    ("options", "yes", "options must be an object"),
    ("options", {"history_limit": "many"}, "history_limit must be an integer"),
    ("options", {"colour": None}, "unknown option"),
    ("options", {"history_limit": 0}, "between 1 and 10000"),
    ("options", {"history_limit": 10_001}, "between 1 and 10000"),
    ("options", {"api_url": "http://ghe.example.com/api/v3"}, "https:// URL"),
    ("options", {"api_url": 42}, "https:// URL"),
    ("options", {"colour": "blue"}, "unknown option: colour"),
    ("secret", "x", "unknown field"),
])
def test_create_validation_errors(app, field, value, message):
    with pytest.raises(service.GitSourceConfigError, match=message):
        service.create_source(base(**{field: value}))
    assert GitSource.query.count() == 0


def test_options_validation_normalizes(app):
    source = service.create_source(base(provider="github", repository="octo/repo", credential_mode="none",
                                        options={"record_commits": "yes", "history_limit": 10_000,
                                                 "api_url": "https://ghe.example.com/api/v3/"}))
    assert source.options == {"record_commits": True, "history_limit": 10_000,
                              "api_url": "https://ghe.example.com/api/v3"}
    service.update_source(source, {"options": None})
    assert source.options is None
    assert service.effective_options(source) == {"record_commits": True, "history_limit": 500}


def test_default_and_effective_options_per_role(app):
    assert service.default_options("governance") == {"record_commits": True, "history_limit": 500}
    assert service.default_options("evidence") == {"record_commits": False, "history_limit": 500}
    source = service.create_source(base(role="evidence", options={"history_limit": 7}))
    assert service.effective_options(source) == {"record_commits": False, "history_limit": 7}


def test_region_and_schedule_can_be_cleared(app):
    source = service.create_source(base(region="us-east-1", schedule_cron="0 3 * * 1"))
    service.update_source(source, {"region": "", "schedule_cron": "   "})
    assert source.region is None and source.schedule_cron is None
    service.update_source(source, {"region": None, "schedule_cron": None})
    assert source.region is None and source.schedule_cron is None


def test_codecommit_defaults_to_runtime_role(app):
    source = service.create_source(base(provider="codecommit", repository="governance"))
    assert source.credential_mode == "runtime_role"
    assert source.encrypted_credentials is None


def test_assume_role_requires_role_arn(app, encryption_key):
    with pytest.raises(service.GitSourceConfigError, match="credentials.role_arn is required"):
        service.create_source(base(provider="codecommit", repository="gov", credential_mode="assume_role"))
    with pytest.raises(service.GitSourceConfigError, match="must be an IAM role ARN"):
        service.create_source(base(provider="codecommit", repository="gov", credential_mode="assume_role",
                                   credentials={"role_arn": "reader"}))
    with pytest.raises(service.GitSourceConfigError, match="credentials must be an object"):
        service.create_source(base(provider="codecommit", repository="gov", credential_mode="assume_role",
                                   credentials="arn:aws:iam::123456789012:role/reader"))


def test_assume_role_stores_encrypted_credentials(app, encryption_key):
    role_arn = "arn:aws:iam::123456789012:role/git-reader"
    source = service.create_source(base(provider="codecommit", repository="gov", credential_mode="assume_role",
                                        credentials={"role_arn": f" {role_arn} ", "external_id": "ext-1"}))
    assert role_arn.encode() not in source.encrypted_credentials
    assert decrypt_credentials(source.encrypted_credentials) == {"role_arn": role_arn, "external_id": "ext-1"}

    # Updates that do not mention credentials keep them.
    service.update_source(source, {"branch": "release"})
    assert decrypt_credentials(source.encrypted_credentials)["role_arn"] == role_arn

    # New credentials replace them; no external id is stored when none is given.
    service.update_source(source, {"credentials": {"role_arn": "arn:aws:iam::123456789012:role/other"}})
    assert decrypt_credentials(source.encrypted_credentials) == {
        "role_arn": "arn:aws:iam::123456789012:role/other"}

    # Switching to the runtime role clears them.
    service.update_source(source, {"credential_mode": "runtime_role"})
    assert source.encrypted_credentials is None


def test_stored_token_requires_token_and_encryption_key(app):
    github = base(provider="github", repository="octo/repo", credential_mode="stored_token")
    with pytest.raises(service.GitSourceConfigError, match="credentials.token is required"):
        service.create_source(dict(github))
    with pytest.raises(service.GitSourceConfigError, match="credentials.token is required"):
        service.create_source(dict(github, credentials={"token": "   "}))
    with pytest.raises(service.GitSourceConfigError, match="COLLECTOR_ENCRYPTION_KEY"):
        service.create_source(dict(github, credentials={"token": "ghp_secret"}))
    assert GitSource.query.count() == 0


def test_stored_token_encrypted_and_kept(app, encryption_key):
    source = service.create_source(base(provider="github", repository="octo/repo",
                                        credential_mode="stored_token",
                                        credentials={"token": " ghp_topsecret "}))
    assert decrypt_credentials(source.encrypted_credentials) == {"token": "ghp_topsecret"}
    service.update_source(source, {"schedule_cron": "0 * * * *"})
    assert decrypt_credentials(source.encrypted_credentials) == {"token": "ghp_topsecret"}
    service.update_source(source, {"credential_mode": "none"})
    assert source.encrypted_credentials is None


def test_switching_to_stored_token_requires_a_token(app, encryption_key):
    source = service.create_source(base(provider="github", repository="octo/repo"))
    assert source.credential_mode == "portal_secret"
    with pytest.raises(service.GitSourceConfigError, match="credentials.token is required"):
        service.update_source(source, {"credential_mode": "stored_token"})
    db.session.expire_all()
    assert db.session.get(GitSource, source.id).credential_mode == "portal_secret"


def test_provider_change_revalidates_credential_mode(app):
    source = service.create_source(base())
    service.update_source(source, {"provider": "github", "repository": "octo/repo"})
    assert source.credential_mode == "none"  # still valid for github
    source = service.create_source(base(name="gh", provider="github", repository="octo/repo"))
    with pytest.raises(service.GitSourceConfigError, match="portal_secret is not valid for provider local"):
        service.update_source(source, {"provider": "local", "repository": "/srv/gov"})


def test_update_validation_rolls_back(app):
    source = service.create_source(base())
    other = service.create_source(base(name="other"))
    with pytest.raises(service.GitSourceConfigError, match="already exists"):
        service.update_source(other, {"name": "gov"})
    with pytest.raises(service.GitSourceConfigError, match="repository is required"):
        service.update_source(source, {"repository": "   ", "branch": "dev"})
    db.session.expire_all()
    assert db.session.get(GitSource, source.id).branch == "main"
    assert db.session.get(GitSource, other.id).name == "other"


def test_update_keeps_own_name_and_records_member(app, admin):
    source = service.create_source(base())
    service.update_source(source, {"name": "gov", "enabled": False, "branch": ""}, member_id=admin.id)
    assert source.name == "gov"
    assert source.enabled is False
    assert source.branch == "main"
    assert source.updated_by_id == admin.id and source.created_by_id is None


def test_whitespace_branch_is_rejected_or_defaulted(app):
    """A branch of only whitespace must not be stored as an empty branch name
    (``git_sources.branch`` is NOT NULL, default ``main``; providers refuse an
    empty branch at sync time)."""
    try:
        source = service.create_source(base(branch="   "))
    except service.GitSourceConfigError:
        return
    assert source.branch == "main"


# --------------------------------------------------------------------------
# Service: serialization, cutover commit, lookup
# --------------------------------------------------------------------------

def test_serialize_source_never_includes_secrets(app, encryption_key):
    source = service.create_source(base(provider="github", repository="octo/repo",
                                        credential_mode="stored_token", schedule_cron="*/30 * * * *",
                                        credentials={"token": "ghp_TOPSECRET123"}))
    data = service.serialize_source(source)
    text = json.dumps(data)
    assert "TOPSECRET" not in text
    assert "credentials" not in data and "encrypted_credentials" not in data
    assert data["has_stored_credentials"] is True
    assert data["credential_mode"] == "stored_token"
    assert data["path_mappings"] is None
    assert data["effective_path_mappings"] == mappings.DEFAULT_GOVERNANCE_MAPPINGS
    assert data["options"] == {"record_commits": True, "history_limit": 500}
    assert data["next_run_at"] is not None
    assert data["last_synced_at"] is None and data["last_sync_status"] is None
    assert data["created_at"] and data["updated_at"]
    service.update_source(source, {"enabled": False})
    assert service.serialize_source(source)["next_run_at"] is None


@pytest.mark.parametrize("commit_id, stored", [
    ("a" * 40, "a" * 40),
    ("0123456789abcdef" * 4, "0123456789abcdef" * 4),
    (" " + "ABCDEF0123" * 4 + " ", "abcdef0123" * 4),
    ("local-" + "b" * 40, "local-" + "b" * 40),
])
def test_set_last_synced_commit_accepts_full_ids(app, admin, commit_id, stored):
    source = service.create_source(base())
    service.set_last_synced_commit(source, commit_id, member_id=admin.id)
    db.session.expire_all()
    source = db.session.get(GitSource, source.id)
    assert source.last_synced_commit == stored
    assert source.updated_by_id == admin.id


@pytest.mark.parametrize("commit_id", ["", None, "abc123", "a" * 39, "a" * 41, "g" * 40, "a" * 63,
                                       "a" * 65, "a" * 40 + "\n" + "b", "local-" + "a" * 39])
def test_set_last_synced_commit_rejects_others(app, commit_id):
    source = service.create_source(base())
    with pytest.raises(service.GitSourceConfigError, match="full commit SHA"):
        service.set_last_synced_commit(source, commit_id)
    assert source.last_synced_commit is None


def test_find_source_by_id_and_name(app):
    source = service.create_source(base())
    assert service.find_source(source.id) is source
    assert service.find_source("gov") is source
    assert service.find_source("missing") is None


def test_serialize_run(app):
    source = service.create_source(base())
    run, _ = scheduler.enqueue_git_sync(source, "api")
    data = service.serialize_run(run)
    assert data["id"] == run.id and data["source_id"] == source.id
    assert data["status"] == "queued" and data["trigger_type"] == "api"
    assert data["counts"] == {} and data["details"] == {}
    assert data["queued_at"] and data["started_at"] is None and data["finished_at"] is None


# --------------------------------------------------------------------------
# Service: provider construction
# --------------------------------------------------------------------------

def test_build_provider_for_local(app, tmp_path):
    source = service.create_source(base(repository=str(tmp_path)))
    provider = service.build_provider_for(source)
    assert isinstance(provider, LocalDirectoryProvider)
    assert provider.root == tmp_path.resolve()


def test_build_provider_for_github_portal_secret(app, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", " ghp_from_env ")
    source = service.create_source(base(provider="github", repository="octo/repo", branch="trunk"))
    provider = service.build_provider_for(source)
    assert isinstance(provider, GitHubProvider)
    assert provider._token == "ghp_from_env"
    assert provider.repository == "octo/repo" and provider.branch == "trunk"
    assert provider._api_url == "https://api.github.com"


def test_build_provider_for_github_stored_token_and_api_url(app, encryption_key, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_env")
    source = service.create_source(base(provider="github", repository="octo/repo",
                                        credential_mode="stored_token", credentials={"token": "ghp_stored"},
                                        options={"api_url": "https://ghe.example.com/api/v3"}))
    provider = service.build_provider_for(source)
    assert provider._token == "ghp_stored"
    assert provider._api_url == "https://ghe.example.com/api/v3"


def test_build_provider_for_github_without_credentials(app, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_env")
    source = service.create_source(base(provider="github", repository="octo/public", credential_mode="none"))
    assert service.build_provider_for(source)._token is None


class FakeBotoSession:
    def __init__(self):
        self.clients = []

    def client(self, name, **kwargs):
        self.clients.append((name, kwargs))
        return MagicMock(name=f"{name}-client")


def test_build_provider_for_codecommit_runtime_role(app, monkeypatch):
    from app.services import aws_session

    session = FakeBotoSession()
    requested = []
    monkeypatch.setattr(aws_session, "get_session", lambda region=None: requested.append(region) or session)
    source = service.create_source(base(provider="codecommit", repository="governance", region="ca-central-1"))
    provider = service.build_provider_for(source)
    assert isinstance(provider, CodeCommitProvider)
    assert provider.repository == "governance" and provider.branch == "main"
    assert requested == ["ca-central-1"]
    assert session.clients[0][0] == "codecommit"
    assert session.clients[0][1]["region_name"] == "ca-central-1"


def test_build_provider_for_codecommit_assume_role(app, encryption_key, monkeypatch):
    from app.services import aws_session

    base_session, role_session = FakeBotoSession(), FakeBotoSession()
    calls = []

    def fake_role_session(session, role_arn, external_id=None, session_name=None, region=None):
        calls.append((session, role_arn, external_id, session_name, region))
        return role_session

    monkeypatch.setattr(aws_session, "get_session", lambda region=None: base_session)
    monkeypatch.setattr(aws_session, "session_with_refreshable_role", fake_role_session)
    source = service.create_source(base(
        name="n" * 70, provider="codecommit", repository="governance", region="us-east-1",
        credential_mode="assume_role",
        credentials={"role_arn": "arn:aws:iam::123456789012:role/reader", "external_id": "ext"}))
    provider = service.build_provider_for(source)
    assert isinstance(provider, CodeCommitProvider)
    assert calls == [(base_session, "arn:aws:iam::123456789012:role/reader", "ext",
                      ("trust-portal-git-" + "n" * 70)[:64], "us-east-1")]
    assert base_session.clients == []
    assert role_session.clients[0][0] == "codecommit"


# --------------------------------------------------------------------------
# Sync: governance source on the local provider
# --------------------------------------------------------------------------

def test_first_sync_stores_mapped_files(app, gov_repo, gov_source, admin):
    head = local_head(gov_repo)
    run = run_sync(gov_source, member_id=admin.id)

    assert run.status == "success"
    assert run.error_message is None
    assert run.from_commit is None and run.to_commit == head
    assert run.started_at is not None and run.finished_at is not None
    assert run.files_changed == 4
    assert run.counts == counts(created=4)
    assert run.details["strategy"] == "tree"
    assert run.details["commits_recorded"] == 0  # the local provider has no history
    assert run.details["by_kind"]["policy"]["created"] == 2
    assert run.details["by_kind"]["governance_document"]["created"] == 2
    assert run.details["flagged"] == [] and run.details["errors"] == []

    source = db.session.get(GitSource, gov_source.id)
    assert source.last_synced_commit == head
    assert source.last_sync_status == "success"
    assert source.last_synced_at is not None

    files = files_of(source)
    assert {path: f.kind for path, f in files.items()} == MAPPED_GOVERNANCE
    for path, record in files.items():
        raw = GOVERNANCE_FILES[path].encode()
        assert record.status == "ok"
        assert record.blob_id == sha256(raw)
        assert record.size == len(raw)
        assert record.last_commit_id == head
        version = current_version(record)
        assert version.content == GOVERNANCE_FILES[path]
        assert version.sha256 == sha256(raw)
        assert version.size == len(raw)
        assert version.commit_id == head
    assert GitFileVersion.query.count() == 4
    assert GitCommit.query.count() == 0


def test_second_sync_without_changes_is_unchanged(app, gov_repo, gov_source):
    first = run_sync(gov_source)
    second = run_sync(gov_source)
    assert second.status == "unchanged"
    assert second.from_commit == second.to_commit == first.to_commit
    assert second.counts == ZERO_COUNTS
    assert second.files_changed == 0
    assert second.details["strategy"] == "diff"
    assert GitFileVersion.query.count() == 4
    assert db.session.get(GitSource, gov_source.id).last_sync_status == "unchanged"


def test_modifying_one_file_adds_exactly_one_version(app, gov_repo, gov_source):
    first = run_sync(gov_source)
    before = {path: f.current_version_id for path, f in files_of(gov_source).items()}
    changed = ENCRYPTION_MD.replace("at rest", "at rest and in transit")
    write(gov_repo, "policies/encryption.md", changed)

    run = run_sync(gov_source)
    assert run.status == "success"
    assert run.from_commit == first.to_commit and run.to_commit == local_head(gov_repo)
    assert run.to_commit != first.to_commit
    assert run.counts == counts(created=1)
    assert run.files_changed == 1
    assert GitFileVersion.query.count() == 5

    after = files_of(gov_source)
    for path, version_id in before.items():
        if path == "policies/encryption.md":
            assert after[path].current_version_id != version_id
        else:
            assert after[path].current_version_id == version_id
    record = after["policies/encryption.md"]
    assert current_version(record).content == changed
    assert current_version(record).commit_id == run.to_commit
    assert [v.content for v in governance_docs.file_versions(record.id)][-1] == ENCRYPTION_MD
    assert len(governance_docs.file_versions(record.id)) == 2


def test_deleted_file_is_marked_and_readding_restores_it(app, gov_repo, gov_source):
    run_sync(gov_source)
    (gov_repo / "CLAUDE.md").unlink()

    deleted = run_sync(gov_source)
    assert deleted.status == "success"
    assert deleted.counts == counts(deleted=1)
    record = files_of(gov_source)["CLAUDE.md"]
    assert record.status == "deleted"
    assert record.blob_id is None
    assert record.last_commit_id == deleted.to_commit
    assert GitFileVersion.query.count() == 4  # history is kept

    # Still deleted: a later sync does not report it again.
    write(gov_repo, "policies/notes.txt", "unmapped, inside a mapped root: changes the head\n")
    later = run_sync(gov_source)
    assert later.status == "success" and later.counts == ZERO_COUNTS

    write(gov_repo, "CLAUDE.md", CLAUDE_MD)
    readded = run_sync(gov_source)
    assert readded.status == "success"
    assert readded.counts == counts(unchanged=1)  # same blob: the stored version is reused
    record = files_of(gov_source)["CLAUDE.md"]
    assert record.status == "ok"
    assert record.blob_id == sha256(CLAUDE_MD.encode())
    assert current_version(record).content == CLAUDE_MD
    assert GitFileVersion.query.count() == 4

    write(gov_repo, "CLAUDE.md", CLAUDE_MD + "\nNew rule.\n")
    edited = run_sync(gov_source)
    assert edited.counts == counts(created=1)
    assert GitFileVersion.query.count() == 5


def test_reverting_a_file_reuses_its_earlier_version(app, gov_repo, gov_source):
    run_sync(gov_source)
    original = files_of(gov_source)["policies/encryption.md"].current_version_id
    write(gov_repo, "policies/encryption.md", "# Encryption\n\nDraft rewrite.\n")
    run_sync(gov_source)
    assert files_of(gov_source)["policies/encryption.md"].current_version_id != original

    write(gov_repo, "policies/encryption.md", ENCRYPTION_MD)
    reverted = run_sync(gov_source)
    assert reverted.counts == counts(unchanged=1)
    assert files_of(gov_source)["policies/encryption.md"].current_version_id == original
    assert GitFileVersion.query.count() == 5


def test_changed_mapping_reclassifies_files_on_a_full_reimport(app, gov_repo, gov_source):
    run_sync(gov_source)
    policy = make_policy("policies/encryption.md")
    client = app.test_client()
    assert "encrypted at rest" in client.get(f"/policies/{policy.id}").get_data(as_text=True)

    service.update_source(db.session.get(GitSource, gov_source.id), {"path_mappings": [
        {"pattern": "policies/**/*.md", "kind": "governance_document"},
        {"pattern": "CLAUDE.md", "kind": "governance_document"},
    ]})
    run, _ = scheduler.enqueue_git_sync(gov_source, "manual", full=True)
    scheduler.execute_claimed("git_sync", run.id)
    files = files_of(gov_source)
    assert files["policies/encryption.md"].kind == "governance_document"
    assert files["policies/sub/access.md"].kind == "governance_document"
    assert "not available" in client.get(f"/policies/{policy.id}").get_data(as_text=True)


def test_full_reimport_processes_every_mapped_file(app, gov_repo, gov_source):
    first = run_sync(gov_source)
    assert first.details["requested"] == {"full": False}

    run, created = scheduler.enqueue_git_sync(gov_source, "manual", full=True)
    assert created and run.details == {"requested": {"full": True}}
    scheduler.execute_claimed("git_sync", run.id)
    db.session.expire_all()
    run = db.session.get(GitSyncRun, run.id)
    assert run.status == "success"
    assert run.details["strategy"] == "full"
    assert run.details["requested"] == {"full": True}
    assert run.files_changed == 4
    assert run.counts == counts(unchanged=4)
    assert run.from_commit == run.to_commit == first.to_commit
    assert GitFileVersion.query.count() == 4

    (gov_repo / "CLAUDE.md").unlink()
    run, _ = scheduler.enqueue_git_sync(gov_source, "manual", full=True)
    scheduler.execute_claimed("git_sync", run.id)
    db.session.expire_all()
    run = db.session.get(GitSyncRun, run.id)
    assert run.counts == counts(unchanged=3, deleted=1)
    assert files_of(gov_source)["CLAUDE.md"].status == "deleted"


def test_full_reimport_restores_records_skipped_for_a_missing_dependency(app, ev_repo, ev_source):
    write(ev_repo, "controls.json", "{not json")
    run_sync(ev_source)
    write(ev_repo, "controls.json", json.dumps(EV_CONTROLS))
    run_sync(ev_source)
    run, _ = scheduler.enqueue_git_sync(ev_source, "manual", full=True)
    scheduler.execute_claimed("git_sync", run.id)
    db.session.expire_all()
    assert db.session.get(GitSyncRun, run.id).status == "success"
    assert ControlTestRow.query.count() == 1
    assert Evidence.query.count() == 1


def test_non_utf8_governance_file_is_a_file_error(app, gov_repo, gov_source):
    write(gov_repo, "policies/binary.md", b"\xff\xfe\x00bad")
    run = run_sync(gov_source)
    assert run.status == "partial"
    assert run.counts == counts(created=4, errors=1)
    record = files_of(gov_source)["policies/binary.md"]
    assert record.status == "error"
    assert "not UTF-8" in record.status_detail
    assert record.current_version_id is None
    assert run.details["errors"] == [{"path": "policies/binary.md",
                                      "error": "policies/binary.md is not UTF-8 text"}]


def test_sync_of_missing_local_directory_fails(app, tmp_path):
    source = service.create_source(base(repository=str(tmp_path / "absent")))
    run = run_sync(source)
    assert run.status == "failure"
    assert "not a directory" in run.error_message
    source = db.session.get(GitSource, source.id)
    assert source.last_sync_status == "failure"
    assert source.last_synced_commit is None and source.last_synced_at is None


def test_custom_mappings_and_unknown_kinds(app, tmp_path):
    root = tmp_path / "repo"
    write(root, "docs/guide.md", "# Guide\n")
    write(root, "notes/a.txt", "note\n")
    source = service.create_source(base(repository=str(root),
                                        path_mappings=[{"pattern": "docs/*.md", "kind": "policy"}]))
    # A kind outside the validated set (stored directly) is skipped, not failed.
    source.path_mappings = [{"pattern": "docs/*.md", "kind": "policy"},
                            {"pattern": "notes/*.txt", "kind": "custom"}]
    db.session.commit()
    run = run_sync(source)
    assert run.status == "success"
    assert run.counts == counts(created=1, skipped=1)
    assert files_of(source)["notes/a.txt"].status == "ok"
    assert files_of(source)["notes/a.txt"].current_version_id is None


# --------------------------------------------------------------------------
# Sync: fake provider (history, diff fallback, oversized and unreadable files)
# --------------------------------------------------------------------------

def blob(data):
    return hashlib.sha1(data).hexdigest()


def commit_sha(label):
    return hashlib.sha1(label.encode()).hexdigest()


class FakeProvider(GitProvider):
    """In-memory provider: commits are dicts of path -> bytes."""

    name = "fake"
    supports_history = True

    def __init__(self):
        self.trees = {}
        self.head = None
        self.history = []
        self.changed = {}
        self.too_large = {}
        self.failing = set()
        self.diff_error = None
        self.head_error = None
        self.calls = []
        self.limits = []
        self.when = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def commit(self, label, files, changed=None):
        cid = commit_sha(label)
        self.trees[cid] = {path: (c.encode() if isinstance(c, str) else c) for path, c in files.items()}
        parents = (self.head,) if self.head else ()
        self.when += timedelta(hours=1)
        self.history.insert(0, CommitInfo(
            commit_id=cid, parent_ids=parents, author_name="Dev", author_email="dev@example.com",
            authored_at=self.when, committer_name="Dev", committer_email="dev@example.com",
            committed_at=self.when, message=f"commit {label}"))
        self.changed[cid] = sorted(changed if changed is not None else files)
        self.head = cid
        return cid

    def resolve_head(self):
        if self.head_error:
            raise self.head_error
        return self.head

    def list_tree(self, commit_id):
        return [TreeEntry(path, blob(data), len(data)) for path, data in sorted(self.trees[commit_id].items())]

    def diff(self, from_commit, to_commit):
        self.calls.append(("diff", from_commit, to_commit))
        if self.diff_error:
            raise self.diff_error
        before, after = self.trees[from_commit], self.trees[to_commit]
        changes = []
        for path in sorted(set(before) | set(after)):
            if path not in after:
                changes.append(Change(path, "D", None))
            elif path not in before:
                changes.append(Change(path, "A", blob(after[path])))
            elif before[path] != after[path]:
                changes.append(Change(path, "M", blob(after[path])))
        return changes

    def _content(self, path, commit_id):
        if path in self.too_large:
            raise FileTooLargeError(path, self.too_large[path], 1000)
        if path in self.failing:
            raise GitSourceError(f"cannot read {path}")
        try:
            return self.trees[commit_id][path]
        except KeyError:
            raise NotFoundError(f"{path} does not exist") from None

    def read_blob(self, entry_or_blob_id, *, path=None, commit_id=None, max_bytes=None):
        self.calls.append(("read_blob", path))
        data = self._content(path, commit_id)
        return data if max_bytes is None else data[:max_bytes]

    def read_file(self, path, commit_id, *, max_bytes=None):
        self.calls.append(("read_file", path))
        data = self._content(path, commit_id)
        return data if max_bytes is None else data[:max_bytes]

    def commits_between(self, from_commit, to_commit, limit):
        self.limits.append(limit)
        return self.history[:limit]  # overlaps earlier syncs on purpose

    def commit_changed_paths(self, commit):
        return self.changed[commit.commit_id]


@pytest.fixture
def fake(monkeypatch):
    provider = FakeProvider()
    monkeypatch.setattr(sync, "build_provider_for", lambda source: provider)
    return provider


@pytest.fixture
def fake_source(app):
    return service.create_source(base(name="fake-governance", repository="/unused"))


def test_file_too_large_is_flagged_and_sync_continues(app, fake, fake_source):
    fake.commit("c1", {"policies/a.md": "# A\n", "policies/big.md": "x" * 20})
    fake.too_large["policies/big.md"] = 7_000_000
    run = run_sync(fake_source)

    assert run.status == "partial"
    assert run.counts == counts(created=1, flagged=1)
    assert run.details["flagged"] == [{"path": "policies/big.md", "size": 7_000_000, "limit": 1000,
                                       "reason": "file exceeds the provider's API size limit"}]
    record = files_of(fake_source)["policies/big.md"]
    assert record.status == "too_large"
    assert record.size == 7_000_000
    assert record.blob_id == blob(b"x" * 20)
    assert "exceeds the 1000 byte per-file limit" in record.status_detail
    assert record.current_version_id is None
    assert files_of(fake_source)["policies/a.md"].status == "ok"
    assert db.session.get(GitSource, fake_source.id).last_synced_commit == fake.head

    # An oversized file is not retried while its blob is unchanged.
    again = run_sync(fake_source)
    assert again.status == "unchanged"
    fake.commit("c2", {"policies/a.md": "# A2\n", "policies/big.md": "x" * 20})
    fake.diff_error = GitSourceError("no diff")  # compare trees: the flagged blob is skipped
    later = run_sync(fake_source)
    assert later.status == "success"
    assert later.counts == counts(created=1)
    assert later.details["strategy"] == "tree"


def test_unreadable_file_is_recorded_and_retried(app, fake, fake_source):
    fake.commit("c1", {"policies/a.md": "# A\n", "policies/b.md": "# B\n", "CLAUDE.md": "# C\n"})
    fake.failing.add("policies/b.md")
    run = run_sync(fake_source)

    assert run.status == "partial"
    assert run.counts == counts(created=2, errors=1)
    assert run.details["errors"] == [{"path": "policies/b.md", "error": "cannot read policies/b.md"}]
    files = files_of(fake_source)
    assert files["policies/b.md"].status == "error"
    assert files["policies/b.md"].status_detail == "cannot read policies/b.md"
    assert files["policies/b.md"].last_commit_id == fake.head
    assert files["policies/a.md"].status == "ok" and files["CLAUDE.md"].status == "ok"

    source = db.session.get(GitSource, fake_source.id)
    candidates, strategy = sync.discover_candidates(
        source, fake, fake.head, mappings.effective_mappings(source))
    assert strategy == "diff"
    assert candidates == [sync.Candidate("policies/b.md", "policy", "R", None)]

    fake.failing.clear()
    fake.calls.clear()
    retried = run_sync(fake_source)
    assert retried.status == "success"
    assert retried.counts == counts(created=1)
    assert ("read_file", "policies/b.md") in fake.calls
    record = files_of(fake_source)["policies/b.md"]
    assert record.status == "ok" and record.status_detail is None
    assert record.blob_id == blob(b"# B\n")
    assert current_version(record).content == "# B\n"

    final = run_sync(fake_source)
    assert final.status == "unchanged"


def test_diff_strategy_and_fallback_to_tree(app, fake, fake_source):
    c1 = fake.commit("c1", {"policies/a.md": "# A\n", "policies/b.md": "# B\n", "other.txt": "x"})
    run_sync(fake_source)

    c2 = fake.commit("c2", {"policies/a.md": "# A v2\n", "policies/c.md": "# C\n", "other.txt": "y"})
    diffed = run_sync(fake_source)
    assert ("diff", c1, c2) in fake.calls
    assert diffed.details["strategy"] == "diff"
    assert diffed.counts == counts(created=2, deleted=1)  # a modified, c added, b deleted
    assert diffed.files_changed == 3
    files = files_of(fake_source)
    assert files["policies/b.md"].status == "deleted"
    assert current_version(files["policies/a.md"]).content == "# A v2\n"
    assert files["policies/a.md"].blob_id == blob(b"# A v2\n")

    fake.commit("c3", {"policies/a.md": "# A v3\n", "policies/c.md": "# C\n", "other.txt": "y"})
    fake.diff_error = GitSourceError("commit c2 is not available")
    fallback = run_sync(fake_source)
    assert fallback.details["strategy"] == "tree"
    assert fallback.status == "success"
    assert fallback.counts == counts(created=1)
    assert current_version(files_of(fake_source)["policies/a.md"]).content == "# A v3\n"


def test_cutover_commit_limits_the_first_sync_to_later_changes(app, fake, fake_source):
    c1 = fake.commit("c1", {"policies/a.md": "# A\n", "policies/b.md": "# B\n"})
    service.set_last_synced_commit(fake_source, c1)
    fake.commit("c2", {"policies/a.md": "# A\n", "policies/b.md": "# B v2\n"})
    run = run_sync(fake_source)
    assert run.details["strategy"] == "diff"
    assert run.from_commit == c1
    assert set(files_of(fake_source)) == {"policies/b.md"}


def test_history_records_commits_touching_mapped_paths(app, fake, fake_source):
    c1 = fake.commit("c1", {"policies/a.md": "# A\n"})
    c2 = fake.commit("c2", {"policies/a.md": "# A\n", "other.txt": "x"}, changed=["other.txt"])
    first = run_sync(fake_source)
    assert first.details["commits_recorded"] == 1
    assert fake.limits == [500]
    rows = GitCommit.query.all()
    assert [r.commit_id for r in rows] == [c1]
    row = rows[0]
    assert row.source_id == fake_source.id
    assert row.paths == ["policies/a.md"]
    assert row.parent_ids == []
    assert row.author_name == "Dev" and row.author_email == "dev@example.com"
    assert row.committer_name == "Dev" and row.message == "commit c1"
    assert row.committed_at is not None and row.authored_at is not None

    c3 = fake.commit("c3", {"policies/a.md": "# A\n", "other.txt": "x", "CLAUDE.md": "# C\n"},
                     changed=["CLAUDE.md", "other.txt"])
    second = run_sync(fake_source)
    assert second.details["commits_recorded"] == 1  # c1 is not recorded twice
    assert sorted(r.commit_id for r in GitCommit.query.all()) == sorted([c1, c3])
    assert db.session.query(GitCommit).filter_by(commit_id=c3).one().paths == ["CLAUDE.md"]
    assert db.session.query(GitCommit).filter_by(commit_id=c3).one().parent_ids == [c2]

    # Unchanged head: no history walk at all.
    assert run_sync(fake_source).details["commits_recorded"] == 0
    assert fake.limits == [500, 500]

    service.update_source(db.session.get(GitSource, fake_source.id),
                          {"options": {"record_commits": False}})
    fake.commit("c4", {"policies/a.md": "# A4\n", "other.txt": "x", "CLAUDE.md": "# C\n"})
    disabled = run_sync(fake_source)
    assert disabled.details["commits_recorded"] == 0
    assert GitCommit.query.count() == 2
    assert fake.limits == [500, 500]

    service.update_source(db.session.get(GitSource, fake_source.id),
                          {"options": {"record_commits": True, "history_limit": 1}})
    fake.commit("c5", {"policies/a.md": "# A5\n", "other.txt": "x", "CLAUDE.md": "# C\n"})
    limited = run_sync(fake_source)
    assert fake.limits[-1] == 1
    assert limited.details["commits_recorded"] == 1
    assert GitCommit.query.count() == 3


def test_evidence_sources_do_not_record_history_by_default(app, fake):
    source = service.create_source(base(name="ev", role="evidence", repository="/unused"))
    fake.commit("c1", {"controls.json": "[]"})
    run = run_sync(source)
    assert run.details["commits_recorded"] == 0
    assert fake.limits == []


def test_record_commits_without_provider_history(app, gov_repo, gov_source):
    provider = LocalDirectoryProvider(gov_repo)
    head = provider.resolve_head()
    assert sync.record_commits(gov_source, provider, head, mappings.default_mappings("governance"), 10) \
        == sync.CommitHistory(recorded=0, truncated=False)


def test_resolve_head_failure_marks_run_failed(app, fake, fake_source):
    fake.commit("c1", {"policies/a.md": "# A\n"})
    run_sync(fake_source)
    synced = db.session.get(GitSource, fake_source.id).last_synced_commit
    synced_at = db.session.get(GitSource, fake_source.id).last_synced_at

    fake.head_error = GitSourceError("repository unreachable")
    run = run_sync(fake_source)
    assert run.status == "failure"
    assert run.error_message == "repository unreachable"
    assert run.to_commit is None
    assert run.counts == ZERO_COUNTS
    source = db.session.get(GitSource, fake_source.id)
    assert source.last_synced_commit == synced
    assert source.last_synced_at == synced_at
    assert source.last_sync_status == "failure"


def test_history_failure_after_files_marks_run_failed(app, fake, fake_source, monkeypatch):
    fake.commit("c1", {"policies/a.md": "# A\n"})

    def broken(*args, **kwargs):
        raise GitSourceError("history unavailable")

    monkeypatch.setattr(fake, "commits_between", broken)
    run = run_sync(fake_source)
    assert run.status == "failure"
    assert run.error_message == "history unavailable"
    assert db.session.get(GitSource, fake_source.id).last_synced_commit is None
    # The files themselves were committed and are not re-created next time.
    assert files_of(fake_source)["policies/a.md"].status == "ok"


def test_candidates_are_processed_in_dependency_order(app):
    source = service.create_source(base(name="ev", role="evidence", repository="/unused",
                                        path_mappings=[
                                            {"pattern": "a/*.md", "kind": "policy"},
                                            {"pattern": "*.jsonl", "kind": "decision_log"},
                                            {"pattern": "pentest.json", "kind": "dataset:pentest-findings"},
                                            {"pattern": "tests.json", "kind": "dataset:tests"},
                                            {"pattern": "controls.json", "kind": "dataset:controls"},
                                        ]))
    provider = FakeProvider()
    provider.commit("c1", {"a/z.md": "", "a/b.md": "", "2026_s.jsonl": "", "pentest.json": "{}",
                           "tests.json": "[]", "controls.json": "[]"})
    candidates, strategy = sync.discover_candidates(
        source, provider, provider.head, mappings.effective_mappings(source))
    assert strategy == "tree"
    assert [c.path for c in candidates] == [
        "controls.json", "tests.json", "pentest.json", "2026_s.jsonl", "a/b.md", "a/z.md"]
    assert {c.change_type for c in candidates} == {"A"}


def test_mappings_reject_unknown_datasets(app):
    with pytest.raises(service.GitSourceConfigError, match="unknown dataset"):
        service.create_source(base(name="ev2", role="evidence", path_mappings=[
            {"pattern": "x.json", "kind": "dataset:unlisted"}]))


# --------------------------------------------------------------------------
# Sync: evidence source on the local provider
# --------------------------------------------------------------------------

SESSION_1 = "11111111-1111-4111-8111-111111111111"
SESSION_2 = "22222222-2222-4222-8222-222222222222"
TRANSCRIPT = "\n".join([
    json.dumps({"type": "user", "timestamp": "2026-01-01T00:00:00Z", "cwd": "/work", "gitBranch": "main",
                "message": {"role": "user", "id": "m1", "content": [{"type": "text", "text": "Hello"}]}}),
    json.dumps({"type": "assistant", "timestamp": "2026-01-01T00:00:01Z",
                "message": {"role": "assistant", "id": "m2", "model": "test-model",
                            "content": [{"type": "text", "text": "Hi there"}]}}),
    json.dumps({"type": "user", "timestamp": "2026-01-01T00:00:05Z",
                "message": {"role": "user", "id": "m3", "content": [{"type": "text", "text": "done."}]}}),
]) + "\n"
EV_CONTROLS = [{"id": "c1", "name": "MFA", "tsc_category": "security"},
               {"id": "c2", "name": "Backups", "tsc_category": "availability"}]
EV_TESTS = [{"id": "t1", "control_id": "c1", "name": "MFA test", "status": "success"}]
EV_EVIDENCE = [{"test_name": "MFA test", "evidence_type": "link", "url": "https://example.com/mfa",
                "collected_at": "2026-03-27T00:00:00+00:00", "collector_name": "manual"}]
EV_SCAN = {"repo": "RepoA", "scan_id": "scan-1", "timestamp": "2026-04-16T193413Z",
           "findings": [{"severity": "HIGH", "message": "first"}, {"severity": "LOW", "message": "second"}]}
PENTEST_PATH = "pentest-evidence/layer1/scan-1-repo.json"
LOG_1 = f"decision-logs/2026-01-01T000000Z_{SESSION_1}.jsonl"
LOG_2 = f"decision-logs/2026-01-02T000000Z_{SESSION_2}.jsonl"


def write_chunked(root, logical, data, name=None):
    directory = root / logical.rsplit("/", 1)[0]
    base_name = logical.rsplit("/", 1)[1]
    manifest, parts = chunked_files.split(name or base_name, data, part_size=64)
    write(root, logical + chunked_files.MANIFEST_SUFFIX, manifest)
    for part_name, chunk in parts:
        (directory / part_name).write_bytes(chunk)
    return parts


@pytest.fixture
def ev_repo(tmp_path):
    root = tmp_path / "evidence"
    write(root, "controls.json", json.dumps(EV_CONTROLS))
    write(root, "tests.json", json.dumps(EV_TESTS))
    write(root, "evidence/evidence-index.json", json.dumps(EV_EVIDENCE))
    write(root, PENTEST_PATH, json.dumps(EV_SCAN))
    write(root, LOG_1, TRANSCRIPT)
    write(root, LOG_1.replace(".jsonl", ".meta.json"), json.dumps({"reason": "prompt_input_exit"}))
    parts = write_chunked(root, LOG_2, TRANSCRIPT.encode())
    assert len(parts) > 2
    write(root, "README.md", "# Evidence\n")
    return root


@pytest.fixture
def ev_source(app, ev_repo):
    return service.create_source(base(name="evidence", role="evidence", repository=str(ev_repo)))


def test_evidence_sync_imports_records_and_decision_logs(app, ev_repo, ev_source, admin):
    run = run_sync(ev_source, member_id=admin.id)

    assert run.status == "success", run.details
    # 2 controls + 1 test + 1 evidence + 2 findings + 2 decision logs
    assert run.counts == counts(created=8)
    assert run.files_changed == 6
    assert run.details["by_kind"]["decision_log"]["created"] == 2
    assert run.details["by_kind"]["dataset:pentest-findings"]["created"] == 2
    assert run.details["commits_recorded"] == 0

    assert {c.id for c in Control.query.all()} == {"c1", "c2"}
    assert ControlTestRow.query.count() == 1
    assert Evidence.query.count() == 1
    assert PentestFinding.query.count() == 2

    plain = db.session.get(DecisionLogSession, SESSION_1)
    assert plain.exit_reason == "prompt_input_exit"
    assert plain.transcript_path == LOG_1
    assert plain.submitted_by == admin.id
    assert plain.content_sha256 == sha256(TRANSCRIPT.encode())
    chunked = db.session.get(DecisionLogSession, SESSION_2)
    assert chunked.transcript_path == LOG_2
    assert chunked.content_sha256 == sha256(TRANSCRIPT.encode())
    assert chunked.content_bytes == len(TRANSCRIPT.encode())
    assert chunked.exit_reason is None
    assert DecisionLogEntry.query.filter_by(session_id=SESSION_2).count() == 3

    files = files_of(ev_source)
    assert set(files) == {"controls.json", "tests.json", "evidence/evidence-index.json", PENTEST_PATH,
                          LOG_1, LOG_2 + ".manifest.json"}
    assert all(f.status == "ok" for f in files.values())
    assert all(f.current_version_id is None for f in files.values())
    assert GitFileVersion.query.count() == 0

    unchanged = run_sync(ev_source)
    assert unchanged.status == "unchanged"
    assert unchanged.counts == ZERO_COUNTS

    changed = [dict(EV_CONTROLS[0], name="MFA everywhere"), EV_CONTROLS[1]]
    write(ev_repo, "controls.json", json.dumps(changed))
    updated = run_sync(ev_source)
    assert updated.status == "success"
    assert updated.counts == counts(updated=1, unchanged=1)
    assert db.session.get(Control, "c1").name == "MFA everywhere"

    (ev_repo / PENTEST_PATH).unlink()
    removed = run_sync(ev_source)
    assert removed.status == "success"
    assert removed.counts == counts(deleted=2)
    assert PentestFinding.query.count() == 0
    assert files_of(ev_source)[PENTEST_PATH].status == "deleted"


def test_removed_dataset_file_keeps_its_records(app, ev_repo, ev_source):
    run_sync(ev_source)
    (ev_repo / "tests.json").unlink()
    run = run_sync(ev_source)
    assert run.counts == counts(skipped=1)
    assert ControlTestRow.query.count() == 1
    assert files_of(ev_source)["tests.json"].status == "deleted"


def test_longer_decision_log_export_replaces_the_stored_one(app, ev_repo, ev_source):
    run_sync(ev_source)
    longer = TRANSCRIPT + json.dumps({
        "type": "assistant", "timestamp": "2026-01-01T00:00:09Z",
        "message": {"role": "assistant", "id": "m4", "content": [{"type": "text", "text": "Bye"}]}}) + "\n"
    write(ev_repo, LOG_1, longer)
    run = run_sync(ev_source)
    assert run.counts == counts(updated=1)
    assert DecisionLogEntry.query.filter_by(session_id=SESSION_1).count() == 4


def test_invalid_dataset_and_manifest_are_file_errors(app, ev_repo, ev_source):
    write(ev_repo, "controls.json", "{not json")
    bad_log = "decision-logs/2026-01-03T000000Z_33333333-3333-4333-8333-333333333333.jsonl"
    write_chunked(ev_repo, bad_log, TRANSCRIPT.encode(), name="other.jsonl")
    missing_part = "decision-logs/2026-01-04T000000Z_44444444-4444-4444-8444-444444444444.jsonl"
    parts = write_chunked(ev_repo, missing_part, TRANSCRIPT.encode())
    (ev_repo / "decision-logs" / parts[-1][0]).unlink()

    run = run_sync(ev_source)
    assert run.status == "partial"
    assert run.counts["errors"] == 3
    files = files_of(ev_source)

    manifest = files[bad_log + ".manifest.json"]
    assert manifest.status == "error"
    assert manifest.status_detail.startswith("ChunkedFileError: ")
    assert "'other.jsonl'" in manifest.status_detail

    assert files[missing_part + ".manifest.json"].status == "error"
    assert "is not in local snapshot" in files[missing_part + ".manifest.json"].status_detail

    assert files["controls.json"].status == "error"
    assert files["controls.json"].status_detail.startswith("ValueError: controls.json: invalid JSON")
    assert Control.query.count() == 0
    # tests.json imported only partly (its control is missing): it is retried until complete.
    assert files["tests.json"].status == "incomplete"
    assert run.counts["incomplete"] >= 1
    assert any(e["path"] == "tests.json" for e in run.details["errors"])
    assert DecisionLogSession.query.count() == 2

    errors = {e["path"] for e in run.details["errors"]}
    assert {bad_log + ".manifest.json", missing_part + ".manifest.json", "controls.json"} <= errors

    # Fixed files are retried on the next sync even though nothing else changed.
    write(ev_repo, "controls.json", json.dumps(EV_CONTROLS))
    retried = run_sync(ev_source)
    assert files_of(ev_source)["controls.json"].status == "ok"
    assert Control.query.count() == 2
    assert retried.status == "partial"  # the two broken manifests still fail


def test_dependent_dataset_is_reimported_after_its_dependency_is_fixed(app, ev_repo, ev_source):
    """tests.json references controls.json. While controls.json cannot be
    imported, the tests referencing it are skipped with an error. Once
    controls.json is fixed, the next (incremental) sync must bring the portal
    to the state of the branch head - which includes those tests - even though
    tests.json itself did not change. (Only a manually requested full
    re-import restores them today; the incremental sync reports success.)"""
    write(ev_repo, "controls.json", "{not json")
    first = run_sync(ev_source)
    assert first.status == "partial"
    assert ControlTestRow.query.count() == 0
    assert any(e["path"] == "tests.json" for e in first.details["errors"])

    write(ev_repo, "controls.json", json.dumps(EV_CONTROLS))
    run_sync(ev_source)
    assert Control.query.count() == 2
    assert ControlTestRow.query.count() == 1
    assert Evidence.query.count() == 1


def test_decision_log_exit_reason_ignores_unreadable_sidecars(app, tmp_path):
    root = tmp_path / "ev"
    log = f"decision-logs/2026-01-01T000000Z_{SESSION_1}.jsonl"
    write(root, log, TRANSCRIPT)
    write(root, log.replace(".jsonl", ".meta.json"), "not json")
    other = f"decision-logs/2026-01-02T000000Z_{SESSION_2}.jsonl"
    write(root, other, TRANSCRIPT)
    write(root, other.replace(".jsonl", ".meta.json"), json.dumps(["not", "an", "object"]))
    source = service.create_source(base(name="ev", role="evidence", repository=str(root)))
    run = run_sync(source)
    assert run.status == "success"
    assert db.session.get(DecisionLogSession, SESSION_1).exit_reason is None
    assert db.session.get(DecisionLogSession, SESSION_2).exit_reason is None


def test_sidecar_helper_handles_provider_errors():
    class Broken:
        def read_file(self, path, commit_id):
            raise GitSourceError("denied")

    class Missing:
        def read_file(self, path, commit_id):
            raise NotFoundError("missing")

    class Present:
        def read_file(self, path, commit_id):
            assert path == "logs/x.meta.json"
            return b'{"reason": "clear", "agent": "codex"}'

    class Odd:
        def read_file(self, path, commit_id):
            return b'{"reason": 7, "agent": ["codex"]}'

    assert sync._sidecar(Broken(), "logs/x.jsonl", "h") == (None, None)
    assert sync._sidecar(Missing(), "logs/x.jsonl", "h") == (None, None)
    assert sync._sidecar(Present(), "logs/x.jsonl", "h") == ("clear", "codex")
    assert sync._sidecar(Odd(), "logs/x.jsonl", "h") == (None, None)


def test_decision_log_agent_comes_from_the_sidecar_or_the_format(app, tmp_path):
    root = tmp_path / "ev"
    named = f"decision-logs/2026-01-01T000000Z_{SESSION_1}.jsonl"
    write(root, named, TRANSCRIPT)
    write(root, named.replace(".jsonl", ".meta.json"), json.dumps({"agent": "openclaude", "reason": "exit"}))
    codex = f"decision-logs/2026-01-02T000000Z_{SESSION_2}.jsonl"
    write(root, codex, json.dumps({"timestamp": "2026-01-02T00:00:00Z", "type": "response_item",
                                   "payload": {"type": "message", "role": "user", "id": "u-1",
                                               "content": [{"type": "input_text", "text": "hi"}]}}))
    source = service.create_source(base(name="ev", role="evidence", repository=str(root)))
    run = run_sync(source)
    assert run.status == "success"
    first = db.session.get(DecisionLogSession, SESSION_1)
    assert (first.agent_type, first.exit_reason) == ("openclaude", "exit")
    second = db.session.get(DecisionLogSession, SESSION_2)
    assert second.agent_type == "codex" and second.interactions.count() == 1


# --------------------------------------------------------------------------
# Public policy pages
# --------------------------------------------------------------------------

def make_policy(file_path, status="approved", title="Portal Policy Title"):
    policy = Policy(id=str(uuid.uuid4()), title=title, category="security", status=status,
                    file_path=file_path)
    db.session.add(policy)
    db.session.commit()
    return policy


def test_policy_page_renders_synced_markdown(app, gov_repo, gov_source):
    run = run_sync(gov_source)
    policy = make_policy("../policies/encryption.md")
    html = app.test_client().get(f"/policies/{policy.id}").get_data(as_text=True)

    assert "All customer data is encrypted at rest." in html
    assert "Encryption Policy</h1>" in html
    assert "owner: Security Team" not in html and "title: Encryption Policy" not in html
    assert run.to_commit[:12] in html
    assert sha256(ENCRYPTION_MD.encode())[:12] in html
    assert "policies/encryption.md" in html
    assert "not available for online viewing" not in html


@pytest.mark.parametrize("file_path", ["CLAUDE.md", "../infrastructure/net.md", "policies/missing.md",
                                       "../../", None, "a/../../policies/encryption.md"])
def test_policy_page_without_a_synced_policy_file(app, gov_repo, gov_source, file_path):
    run_sync(gov_source)
    policy = make_policy(file_path)
    resp = app.test_client().get(f"/policies/{policy.id}")
    assert resp.status_code == 200
    assert "Policy document content is not available for online viewing." in resp.get_data(as_text=True)


def test_policy_page_resolves_a_unique_basename(app, gov_repo, gov_source):
    run_sync(gov_source)
    policy = make_policy("old-layout/access.md", title="Access")
    html = app.test_client().get(f"/policies/{policy.id}").get_data(as_text=True)
    assert "Access is reviewed quarterly." in html
    assert "policies/sub/access.md" in html


def test_policy_page_ambiguous_basename_is_not_resolved(app, gov_repo, gov_source):
    write(gov_repo, "policies/archive/encryption.md", "# Old encryption policy\n")
    run_sync(gov_source)
    ambiguous = make_policy("elsewhere/encryption.md")
    html = app.test_client().get(f"/policies/{ambiguous.id}").get_data(as_text=True)
    assert "not available for online viewing" in html
    exact = make_policy("policies/archive/encryption.md")
    html = app.test_client().get(f"/policies/{exact.id}").get_data(as_text=True)
    assert "Old encryption policy" in html


def test_policy_page_ignores_deleted_files_and_disabled_sources(app, gov_repo, gov_source):
    run_sync(gov_source)
    policy = make_policy("policies/encryption.md")
    client = app.test_client()
    service.update_source(db.session.get(GitSource, gov_source.id), {"enabled": False})
    assert "not available" in client.get(f"/policies/{policy.id}").get_data(as_text=True)
    service.update_source(db.session.get(GitSource, gov_source.id), {"enabled": True})
    assert "encrypted at rest" in client.get(f"/policies/{policy.id}").get_data(as_text=True)
    (gov_repo / "policies/encryption.md").unlink()
    run_sync(gov_source)
    html = client.get(f"/policies/{policy.id}").get_data(as_text=True)
    assert "This policy is no longer published in the governance repository." in html
    assert "encrypted at rest" not in html


def test_deleted_policy_file_is_retired_never_replaced_by_same_name(app, tmp_path):
    """Red-team finding 15b: after the synced file is deleted, the policy shows as retired and
    never falls back to another file with the same basename (e.g. an unapproved draft)."""
    root = tmp_path / "gov"
    write(root, "policies/access.md", "# Access\n\nCURRENT APPROVED TEXT\n")
    write(root, "policies/drafts/access.md", "# Access\n\nUNAPPROVED DRAFT TEXT\n")
    source = service.create_source(base(repository=str(root)))
    run_sync(source)
    policy = make_policy("policies/access.md")
    client = app.test_client()
    assert "CURRENT APPROVED TEXT" in client.get(f"/policies/{policy.id}").get_data(as_text=True)

    (root / "policies/access.md").unlink()
    run_sync(source)
    html = client.get(f"/policies/{policy.id}").get_data(as_text=True)
    assert "UNAPPROVED DRAFT TEXT" not in html
    assert "This policy is no longer published in the governance repository." in html
    assert governance_docs.policy_file_state("policies/access.md") == ("retired", None)

    # A file record in another state (e.g. unreadable) is unavailable, also without fallback.
    write(root, "policies/access.md", b"\xff\xfe not utf-8")
    run_sync(source)
    assert files_of(source)["policies/access.md"].status == "error"
    assert governance_docs.policy_file_state("policies/access.md") == ("unavailable", None)
    html = client.get(f"/policies/{policy.id}").get_data(as_text=True)
    assert "UNAPPROVED DRAFT TEXT" not in html and "not available for online viewing" in html

    # With no record at the exact path, a single file of the same name is still used.
    other = make_policy("docs/drafts/access.md")
    assert "UNAPPROVED DRAFT TEXT" in client.get(f"/policies/{other.id}").get_data(as_text=True)


def test_policy_files_of_evidence_sources_are_not_public(app, tmp_path):
    root = tmp_path / "ev"
    write(root, "policies/encryption.md", ENCRYPTION_MD)
    source = service.create_source(base(name="ev", role="evidence", repository=str(root),
                                        path_mappings=[{"pattern": "policies/*.md", "kind": "policy"}]))
    assert run_sync(source).counts == counts(created=1)
    policy = make_policy("policies/encryption.md")
    assert "not available" in app.test_client().get(f"/policies/{policy.id}").get_data(as_text=True)


@pytest.mark.parametrize("status", ["draft", "pending_approval", "retired"])
def test_policy_page_404_unless_approved(app, gov_repo, gov_source, status):
    run_sync(gov_source)
    policy = make_policy("policies/encryption.md", status=status)
    assert app.test_client().get(f"/policies/{policy.id}").status_code == 404
    assert app.test_client().get("/policies/no-such-policy").status_code == 404


def test_policy_document_without_stored_version(app, gov_repo, gov_source):
    run_sync(gov_source)
    record = files_of(gov_source)["policies/encryption.md"]
    record.current_version_id = str(uuid.uuid4())  # dangling reference
    db.session.commit()
    assert governance_docs.policy_document(SimpleNamespace(file_path="policies/encryption.md")) is None


# --------------------------------------------------------------------------
# governance_docs helpers
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value, expected", [
    ("../policies/x.md", "policies/x.md"),
    ("../../policies/./x.md", "policies/x.md"),
    ("./a/b.md", "a/b.md"),
    ("/abs/x.md", "abs/x.md"),
    ("  policies//x.md  ", "policies/x.md"),
    ("policies\\sub\\x.md", "policies/sub/x.md"),
    ("a/../../x", None),
    ("policies/../x.md", None),
    ("../..", None),
    ("./", None),
    ("", None),
    (None, None),
])
def test_normalize_policy_path(value, expected):
    assert governance_docs.normalize_policy_path(value) == expected


def test_split_front_matter():
    metadata, body = governance_docs.split_front_matter(ENCRYPTION_MD)
    assert metadata == {"title": "Encryption Policy", "owner": "Security Team"}
    assert body.startswith("# Encryption Policy")
    assert governance_docs.split_front_matter("# Plain\n") == ({}, "# Plain")
    malformed = "---\ntitle: [unclosed\n---\n# Body\n"
    assert governance_docs.split_front_matter(malformed) == ({}, malformed)


def test_governance_files_lists_only_governance_sources(app, gov_repo, gov_source, ev_repo, ev_source):
    run_sync(gov_source)
    run_sync(ev_source)
    rows = governance_docs.governance_files()
    assert [(f.path, s.name) for f, s, _ in rows] == sorted(
        [(path, "governance") for path in MAPPED_GOVERNANCE])
    assert all(v is not None and v.id == f.current_version_id for f, _, v in rows)


def test_governance_files_empty(app):
    assert governance_docs.governance_files() == []


def add_commit(source, index, committed_at):
    row = GitCommit(id=str(uuid.uuid4()), source_id=source.id, commit_id=f"{index:040x}",
                    committed_at=committed_at, message=f"change {index}", paths=["policies/a.md"])
    db.session.add(row)
    return row


def test_change_history_paging_and_filter(app):
    first = service.create_source(base(name="first"))
    second = service.create_source(base(name="second"))
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for index in range(5):
        add_commit(first, index, start + timedelta(days=index))
    add_commit(first, 99, None)
    add_commit(second, 100, start + timedelta(days=50))
    db.session.commit()

    page1 = governance_docs.change_history(page=1, per_page=3)
    assert page1.total == 7
    assert [c.message for c in page1.items] == ["change 100", "change 4", "change 3"]
    assert page1.has_next and not page1.has_prev
    page3 = governance_docs.change_history(page=3, per_page=3)
    assert [c.message for c in page3.items] == ["change 99"]  # undated commits sort last
    assert governance_docs.change_history(page=9, per_page=3).items == []

    only_first = governance_docs.change_history(source_id=first.id, per_page=10)
    assert only_first.total == 6
    assert {c.source_id for c in only_first.items} == {first.id}
    assert governance_docs.change_history(source_id=second.id).total == 1


# --------------------------------------------------------------------------
# Red-team findings: local roots (4), api_url (8), namespaces and unknown
# commits (15), rejected transcripts (5), deadlock retry (12)
# --------------------------------------------------------------------------

def test_etc_demo_is_refused_in_production(app, admin, monkeypatch):
    """The /etc/passwd demo: a local source at /etc cannot be created in production."""
    monkeypatch.setenv("PORTAL_ENV", "production")
    monkeypatch.delenv("LOCAL_SOURCE_ROOTS", raising=False)
    with pytest.raises(service.GitSourceConfigError, match="disabled in production"):
        service.create_source({"name": "etc", "role": "governance", "provider": "local",
                               "repository": "/etc",
                               "path_mappings": [{"pattern": "passwd", "kind": "policy"}]},
                              member_id=admin.id)
    monkeypatch.setenv("LOCAL_SOURCE_ROOTS", "/srv")
    with pytest.raises(service.GitSourceConfigError, match="outside LOCAL_SOURCE_ROOTS"):
        service.create_source(base(repository="/etc"))
    assert service.create_source(base(repository="/srv/x")).repository == "/srv/x"


def test_sync_enforces_local_roots_when_it_builds_the_provider(app, tmp_path, monkeypatch):
    root = tmp_path / "gov"
    write(root, "policies/a.md", "# A\n")
    source = service.create_source(base(repository=str(root)))  # PORTAL_ENV=test: unrestricted
    monkeypatch.setenv("PORTAL_ENV", "production")
    monkeypatch.delenv("LOCAL_SOURCE_ROOTS", raising=False)
    run = run_sync(source)
    assert run.status == "failure"
    assert "local-directory git sources are disabled in production" in run.error_message
    assert files_of(source) == {}

    monkeypatch.setenv("LOCAL_SOURCE_ROOTS", str(tmp_path / "other"))
    run = run_sync(source)
    assert run.status == "failure" and "outside LOCAL_SOURCE_ROOTS" in run.error_message

    monkeypatch.setenv("LOCAL_SOURCE_ROOTS", str(tmp_path))
    assert run_sync(source).status == "success"


def test_sync_never_sends_the_portal_token_to_another_api_url(app, monkeypatch):
    import requests

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_PORTAL_SECRET")
    calls = []
    monkeypatch.setattr(requests.Session, "get", lambda self, url, **kw: calls.append(url))
    source = service.create_source(base(provider="github", repository="octo/repo"))
    source.options = {"api_url": "https://attacker.example"}  # a row that bypassed validation
    db.session.commit()
    run = run_sync(source)
    assert run.status == "failure"
    assert "requires credential_mode stored_token or none" in run.error_message
    assert calls == []
    with pytest.raises(GitSourceError, match="stored_token or none"):
        service.build_provider_for(db.session.get(GitSource, source.id))


def test_two_evidence_sources_keep_their_own_pentest_findings(app, tmp_path):
    def scan(message):
        return json.dumps({"scan_id": "s", "findings": [{"summary": message, "severity": "HIGH"}]})

    a, b = tmp_path / "a", tmp_path / "b"
    write(a, "pentest-evidence/layer1/scan.json", scan("finding from repo A"))
    write(b, "pentest-evidence/layer1/scan.json", scan("finding from repo B"))
    source_a = service.create_source(base(name="ev-a", role="evidence", repository=str(a)))
    source_b = service.create_source(base(name="ev-b", role="evidence", repository=str(b)))
    run_sync(source_a)
    run_b = run_sync(source_b)
    assert run_b.counts == counts(created=1)
    assert sorted(f.summary for f in PentestFinding.query.all()) == ["finding from repo A",
                                                                     "finding from repo B"]
    assert {f.source_file for f in PentestFinding.query.all()} == {
        f"{source_a.id}:layer1/scan.json", f"{source_b.id}:layer1/scan.json"}

    (b / "pentest-evidence/layer1/scan.json").unlink()
    assert run_sync(source_b).counts == counts(deleted=1)
    assert [f.summary for f in PentestFinding.query.all()] == ["finding from repo A"]


def test_unknown_last_synced_commit_fails_until_a_full_reimport(app, fake, fake_source, monkeypatch):
    fake.commit("c1", {"policies/a.md": "# A\n"})
    assert run_sync(fake_source).status == "success"
    fake.commit("c2", {"policies/a.md": "# A2\n", "policies/b.md": "# B\n"})
    unknown = "b" * 40
    service.set_last_synced_commit(db.session.get(GitSource, fake_source.id), unknown)
    fake.diff_error = NotFoundError("CodeCommit CommitDoesNotExistException")
    requested = []

    def history(from_commit, to_commit, limit):
        requested.append(from_commit)
        if from_commit is not None and from_commit not in fake.trees:
            raise NotFoundError("CodeCommit CommitDoesNotExistException")
        return fake.history[:limit]

    monkeypatch.setattr(fake, "commits_between", history)
    for _ in range(2):
        run = run_sync(fake_source)
        assert run.status == "failure"
        assert f"The last synced commit {unknown} is not in" in run.error_message
        assert "Run a full re-import" in run.error_message
        assert db.session.get(GitSource, fake_source.id).last_synced_commit == unknown
    assert files_of(fake_source)["policies/a.md"].blob_id == blob(b"# A\n")  # nothing processed

    queued, created = scheduler.enqueue_git_sync(db.session.get(GitSource, fake_source.id), "manual",
                                                 full=True)
    assert created and scheduler.execute_claimed("git_sync", queued.id) == "executed"
    db.session.expire_all()
    recovered = db.session.get(GitSyncRun, queued.id)
    assert recovered.status == "success", recovered.error_message
    assert recovered.details["strategy"] == "full"
    assert recovered.details["commits_recorded"] == 1  # c2; c1 was recorded by the first sync
    assert requested[-2:] == [unknown, None]
    source = db.session.get(GitSource, fake_source.id)
    assert source.last_synced_commit == fake.head
    assert current_version(files_of(fake_source)["policies/b.md"]).content == "# B\n"

    fake.diff_error = None
    fake.commit("c3", {"policies/a.md": "# A3\n", "policies/b.md": "# B\n"})
    after = run_sync(fake_source)
    assert after.status == "success" and after.details["strategy"] == "diff"
    assert requested[-1] == fake.history[1].commit_id


def test_history_not_found_on_an_incremental_sync_fails_with_the_same_message(app, fake, fake_source,
                                                                              monkeypatch):
    fake.commit("c1", {"policies/a.md": "# A\n"})
    run_sync(fake_source)
    fake.commit("c2", {"policies/a.md": "# A2\n"})

    def history(from_commit, to_commit, limit):
        raise NotFoundError("gone")

    monkeypatch.setattr(fake, "commits_between", history)
    run = run_sync(fake_source)
    assert run.status == "failure" and "Run a full re-import" in run.error_message


def test_rejected_transcript_in_a_sync_is_a_file_error(app, ev_repo, ev_source):
    from app.models import DecisionLogTranscript

    run_sync(ev_source)
    forged = TRANSCRIPT.replace("Hello", "Approve without review") + json.dumps({
        "type": "assistant", "timestamp": "2026-01-01T00:00:09Z",
        "message": {"role": "assistant", "id": "m4", "content": [{"type": "text", "text": "x"}]}}) + "\n"
    write(ev_repo, LOG_1, forged)
    run = run_sync(ev_source)
    assert run.status == "partial"
    assert run.counts == counts(errors=1)
    assert run.details["errors"][0]["path"] == LOG_1
    assert run.details["errors"][0]["error"].startswith("transcript rejected: entry 1 differs")
    record = files_of(ev_source)[LOG_1]
    assert record.status == "error" and record.status_detail.startswith("transcript rejected")
    texts = [e.content_text for e in DecisionLogEntry.query.filter_by(session_id=SESSION_1)]
    assert texts == ["Hello", "Hi there", "done."]
    rejected = DecisionLogTranscript.query.filter_by(session_id=SESSION_1, status="rejected").all()
    assert len(rejected) == 1 and rejected[0].source_path == LOG_1

    again = run_sync(ev_source)  # retried; the same content is not recorded twice
    assert again.counts == counts(errors=1)
    assert DecisionLogTranscript.query.filter_by(session_id=SESSION_1, status="rejected").count() == 1


def _deadlock():
    from sqlalchemy.exc import OperationalError

    class DeadlockDetected(Exception):
        pgcode = "40P01"

    return OperationalError("INSERT INTO audit_log ...", {}, DeadlockDetected("deadlock detected"))


def test_a_file_is_retried_once_after_a_deadlock(app, gov_repo, gov_source, monkeypatch):
    real = sync.process_candidate
    failures = {"policies/encryption.md": 1}

    def flaky(source, fetched, candidate, head, tally, member_id):
        real(source, fetched, candidate, head, tally, member_id)  # tallies, then fails
        if failures.get(candidate.path):
            failures[candidate.path] -= 1
            raise _deadlock()

    monkeypatch.setattr(sync, "process_candidate", flaky)
    run = run_sync(gov_source)
    assert run.status == "success"
    assert run.counts == counts(created=4)  # the retried file is counted once
    assert files_of(gov_source)["policies/encryption.md"].status == "ok"


def test_outcome_is_not_recorded_for_a_run_taken_from_the_executor(app, gov_repo, gov_source, monkeypatch):
    """Compare-and-set finish: a run reaped (or re-claimed) mid-sync keeps the other writer's
    result, and the source's last synced commit does not move."""
    from sqlalchemy import update

    real = sync.process_candidate

    def reaped_meanwhile(source, fetched, candidate, head, tally, member_id):
        real(source, fetched, candidate, head, tally, member_id)
        db.session.execute(update(GitSyncRun).where(GitSyncRun.source_id == source.id)
                           .values(status="failure", error_message="reaped", executor_token=None))

    monkeypatch.setattr(sync, "process_candidate", reaped_meanwhile)
    run = run_sync(gov_source)
    assert (run.status, run.error_message) == ("failure", "reaped")
    assert run.counts in (None, {})
    source = db.session.get(GitSource, gov_source.id)
    assert source.last_synced_commit is None and source.last_sync_status is None


def test_outcome_is_recorded_only_under_the_claiming_token(app, gov_repo, gov_source):
    run, _ = scheduler.enqueue_git_sync(gov_source, "manual")
    db.session.execute(sa_update_run(run.id, status="running", executor_token="token-a"))
    db.session.commit()
    finished = sync.execute_sync_run(run.id)
    assert finished.status == "success"
    assert db.session.get(GitSource, gov_source.id).last_synced_commit == local_head(gov_repo)

    other, _ = scheduler.enqueue_git_sync(gov_source, "manual")
    db.session.execute(sa_update_run(other.id, status="running", executor_token="token-b"))
    db.session.commit()
    assert sync._finish(other.id, "token-a", db.session.get(GitSource, gov_source.id), "success",
                        sync.SyncTally(), {}, head="f" * 40) is False
    assert db.session.get(GitSyncRun, other.id).status == "running"
    assert db.session.get(GitSource, gov_source.id).last_synced_commit == local_head(gov_repo)


def sa_update_run(run_id, **values):
    from sqlalchemy import update

    return update(GitSyncRun).where(GitSyncRun.id == run_id).values(**values)


def test_lost_lock_propagates_instead_of_becoming_a_file_error(app, gov_repo, gov_source, monkeypatch):
    def lost(*args, **kwargs):
        raise scheduler.LockLostError("the executor lost its target lock")

    monkeypatch.setattr(sync, "process_candidate", lost)
    run = run_sync(gov_source)
    assert run.status == "failure"
    assert run.error_message == "Interrupted: the executor lost its target lock"
    assert files_of(gov_source) == {}
    assert db.session.get(GitSource, gov_source.id).last_synced_commit is None


def test_cli_sync_reports_an_unreadable_active_run(app, monkeypatch):
    import argparse
    import importlib
    import io

    from cli import git_source_cmd

    source = service.create_source(base())
    monkeypatch.setattr(importlib.import_module("app"), "create_app", lambda *args, **kwargs: app)

    def conflict(*args, **kwargs):
        raise scheduler.ActiveRunConflict("git_sync", source.id)

    monkeypatch.setattr(scheduler, "enqueue_git_sync", conflict)
    out = io.StringIO()
    args = argparse.Namespace(action="sync", name="gov", full=False, no_wait=False)
    assert git_source_cmd.run(args, out=out) == 1
    assert out.getvalue() == f"error: A git_sync run of {source.id} is already queued or running\n"


def test_a_second_deadlock_records_a_file_error(app, gov_repo, gov_source, monkeypatch):
    real = sync.process_candidate
    attempts = []

    def always(source, fetched, candidate, head, tally, member_id):
        real(source, fetched, candidate, head, tally, member_id)
        if candidate.path == "CLAUDE.md":
            attempts.append(1)
            raise _deadlock()

    monkeypatch.setattr(sync, "process_candidate", always)
    run = run_sync(gov_source)
    assert len(attempts) == 2
    assert run.status == "partial"
    assert run.counts == counts(created=3, errors=1)
    assert files_of(gov_source)["CLAUDE.md"].status == "error"
    assert "OperationalError" in files_of(gov_source)["CLAUDE.md"].status_detail
