"""Phase 5 tests — Policy, Vendor, Platform, and Git (CodeCommit) collectors."""

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.config import TestConfig
from app.models import (
    CollectorCheckResult,
    CollectorConfig,
    CollectorRun,
    Control,
    Evidence,
    Policy,
    TestRecord,
    Vendor,
    db,
)
from app.services import team_service
from app.services.collector_executor import _resolve_test_record, execute_run
from app.services.permission_prober import AWS_ACTION_PROBES
from collectors.aws.collector import AWS_REQUIRED_PERMISSIONS
from collectors.git import GitCollector, codecommit_checks
from collectors.git.collector import GIT_CODECOMMIT_REQUIRED_PERMISSIONS, parse_form_settings
from collectors.platform_collector import PlatformCollector
from collectors.policy_check_collector import PolicyCollector
from collectors.registry import COLLECTOR_CLASSES, get_collector_class
from collectors.vendor_check_collector import VendorCollector
from tests.conftest import login


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    """Every host name resolves to a public address; no test makes a DNS lookup."""
    import socket

    def getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", port or 443))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


@pytest.fixture
def app_ctx(monkeypatch):
    monkeypatch.setenv("COLLECTOR_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
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
    return team_service.create_member(
        "Admin", "admin@example.com", "human", is_compliance_admin=True
    )


def _make_config(name, **overrides):
    defaults = {
        "id": str(uuid.uuid4()),
        "name": name,
        "enabled": True,
        "credential_mode": "none",
    }
    defaults.update(overrides)
    c = CollectorConfig(**defaults)
    db.session.add(c)
    db.session.commit()
    return c


# ============================================================================
# Registry
# ============================================================================


def test_all_five_collectors_registered():
    assert set(COLLECTOR_CLASSES.keys()) == {"aws", "git", "platform", "policy", "vendor"}
    assert get_collector_class("policy") is PolicyCollector
    assert get_collector_class("vendor") is VendorCollector
    assert get_collector_class("platform") is PlatformCollector
    assert get_collector_class("git") is GitCollector


# ============================================================================
# Policy collector
# ============================================================================


def test_policy_collector_empty_db(app_ctx):
    config = _make_config("policy")
    collector = PolicyCollector(config=config)
    results = collector.run()
    assert any(r.check_name == "policy_inventory" and r.status == "fail" for r in results)


def test_policy_collector_all_approved_and_current(app_ctx):
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=180)
    for i in range(3):
        p = Policy(
            id=str(uuid.uuid4()),
            title=f"Policy {i}",
            category="security",
            status="approved",
            next_review_at=future,
        )
        db.session.add(p)
    db.session.commit()

    config = _make_config("policy")
    collector = PolicyCollector(config=config)
    results = collector.run()

    # Inventory + one per-policy check per policy
    assert any(r.check_name == "policy_inventory" and r.status == "pass" for r in results)
    assert sum(1 for r in results if r.check_name.startswith("policy_next_review:")) == 3
    assert all(
        r.status == "pass"
        for r in results
        if r.check_name.startswith("policy_next_review:")
    )


def test_policy_collector_flags_unapproved(app_ctx):
    p = Policy(
        id=str(uuid.uuid4()),
        title="Draft Policy",
        category="security",
        status="draft",
    )
    db.session.add(p)
    db.session.commit()

    collector = PolicyCollector(config=_make_config("policy"))
    results = collector.run()
    fails = [r for r in results if r.status == "fail"]
    assert any("draft" in (r.message or "") for r in fails)


def test_policy_collector_flags_overdue_review(app_ctx):
    past = datetime.now(timezone.utc) - timedelta(days=30)
    p = Policy(
        id=str(uuid.uuid4()),
        title="Stale Policy",
        category="security",
        status="approved",
        next_review_at=past,
    )
    db.session.add(p)
    db.session.commit()

    collector = PolicyCollector(config=_make_config("policy"))
    results = collector.run()
    overdue = [
        r for r in results
        if r.check_name.startswith("policy_next_review:") and r.status == "fail"
    ]
    assert len(overdue) == 1
    assert "overdue" in overdue[0].message.lower()


def test_policy_collector_flags_missing_next_review(app_ctx):
    p = Policy(
        id=str(uuid.uuid4()),
        title="No Review Date",
        category="security",
        status="approved",
    )
    db.session.add(p)
    db.session.commit()

    collector = PolicyCollector(config=_make_config("policy"))
    results = collector.run()
    missing = [
        r for r in results
        if r.check_name.startswith("policy_next_review:") and r.status == "fail"
    ]
    assert len(missing) == 1


# ============================================================================
# Vendor collector
# ============================================================================


def test_vendor_collector_empty_db(app_ctx):
    config = _make_config("vendor")
    results = VendorCollector(config=config).run()
    assert any(r.check_name == "vendor_inventory" and r.status == "fail" for r in results)


def test_vendor_collector_complete_vendor_passes(app_ctx):
    v = Vendor(
        id=str(uuid.uuid4()),
        name="Stripe",
        status="active",
        security_page_url="https://stripe.com/security",
        privacy_policy_url="https://stripe.com/privacy",
        purpose="Payment processing",
    )
    db.session.add(v)
    db.session.commit()

    results = VendorCollector(config=_make_config("vendor")).run()
    completeness = [
        r for r in results if r.check_name.startswith("vendor_record_completeness:")
    ]
    assert len(completeness) == 1
    assert completeness[0].status == "pass"


def test_vendor_collector_flags_missing_fields(app_ctx):
    v = Vendor(
        id=str(uuid.uuid4()),
        name="IncompleteVendor",
        status="active",
        # no security_page_url, no privacy_policy_url, no purpose
    )
    db.session.add(v)
    db.session.commit()

    results = VendorCollector(config=_make_config("vendor")).run()
    completeness = [
        r for r in results if r.check_name.startswith("vendor_record_completeness:")
    ]
    assert completeness[0].status == "fail"


def test_vendor_collector_skips_inactive(app_ctx):
    db.session.add(Vendor(
        id=str(uuid.uuid4()), name="Active", status="active",
        security_page_url="https://a", privacy_policy_url="https://b", purpose="x",
    ))
    db.session.add(Vendor(
        id=str(uuid.uuid4()), name="Inactive", status="inactive",
        security_page_url="https://a", privacy_policy_url="https://b", purpose="x",
    ))
    db.session.commit()

    results = VendorCollector(config=_make_config("vendor")).run()
    completeness_checks = [
        r for r in results if r.check_name.startswith("vendor_record_completeness:")
    ]
    assert len(completeness_checks) == 1  # only the active vendor


def test_vendor_collector_probes_urls_when_enabled(app_ctx):
    v = Vendor(
        id=str(uuid.uuid4()),
        name="ProbedVendor",
        status="active",
        security_page_url="https://example.com/security",
        privacy_policy_url="https://example.com/privacy",
        purpose="test",
    )
    db.session.add(v)
    db.session.commit()
    config = _make_config("vendor", config={"probe_urls": True})

    with patch("collectors.vendor_check_collector._probe_url") as mock_probe:
        mock_probe.return_value = {
            "reachable": True,
            "status_code": 200,
            "error": None,
        }
        results = VendorCollector(config=config).run()

    mock_probe.assert_called_once_with("https://example.com/security", timeout=5)
    reach_results = [
        r for r in results
        if r.check_name.startswith("vendor_security_page_reachable:")
    ]
    assert len(reach_results) == 1
    assert reach_results[0].status == "pass"


def test_vendor_collector_records_unreachable_probe(app_ctx):
    v = Vendor(
        id=str(uuid.uuid4()),
        name="DownVendor",
        status="active",
        security_page_url="https://down.example/security",
        privacy_policy_url="https://down.example/privacy",
        purpose="test",
    )
    db.session.add(v)
    db.session.commit()
    config = _make_config("vendor", config={"probe_urls": True, "http_timeout_seconds": 2})

    with patch("collectors.vendor_check_collector._probe_url") as mock_probe:
        mock_probe.return_value = {
            "reachable": False,
            "status_code": None,
            "error": "timed out",
        }
        results = VendorCollector(config=config).run()

    reach = [r for r in results if r.check_name.startswith("vendor_security_page_reachable:")]
    assert reach[0].status == "fail"


# ============================================================================
# Platform collector
# ============================================================================


def test_platform_collector_no_services(app_ctx):
    config = _make_config("platform")
    results = PlatformCollector(config=config).run()
    assert any(r.check_name == "platform_inventory" and r.status == "fail" for r in results)


def test_platform_collector_probes_services(app_ctx):
    config = _make_config(
        "platform",
        config={
            "services": [
                {
                    "name": "public-api",
                    "url": "https://api.example.com",
                    "health_path": "/api/health",
                    "auth": "none",
                },
            ],
            "http_timeout_seconds": 5,
        },
    )

    class FakeResponse:
        status_code = 200
        class elapsed:  # noqa: D401
            @staticmethod
            def total_seconds():
                return 0.125

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = FakeResponse()
        results = PlatformCollector(config=config).run()

    mock_get.assert_called_once()
    call_kwargs = mock_get.call_args
    assert call_kwargs.args[0] == "https://api.example.com/api/health"
    assert any(
        r.check_name == "platform_health:public-api" and r.status == "pass"
        for r in results
    )


def test_platform_collector_handles_http_error(app_ctx):
    config = _make_config(
        "platform",
        config={
            "services": [
                {"name": "downservice", "url": "https://down.example", "health_path": "/h"},
            ],
        },
    )
    with patch("requests.Session.get", side_effect=Exception("connection refused")):
        results = PlatformCollector(config=config).run()
    health = [r for r in results if r.check_name.startswith("platform_health:")]
    assert len(health) == 1
    assert health[0].status == "fail"
    assert "connection refused" in (health[0].message or "")


def test_platform_collector_handles_non_2xx(app_ctx):
    config = _make_config(
        "platform",
        config={
            "services": [
                {"name": "unhealthy", "url": "https://svc.example", "health_path": "/h"},
            ],
        },
    )

    class FakeResponse:
        status_code = 503
        class elapsed:
            @staticmethod
            def total_seconds():
                return 0.01

    with patch("requests.Session.get", return_value=FakeResponse()):
        results = PlatformCollector(config=config).run()
    health = [r for r in results if r.check_name.startswith("platform_health:")]
    assert health[0].status == "fail"
    assert "503" in health[0].message


# ============================================================================
# Git collector (CodeCommit)
# ============================================================================

STRUCTURED = "Fix the thing\n\n## Problem\nIt broke.\n\n## Solution\nFixed it.\n\n## Verified\nTests pass.\n"
UNSTRUCTURED = "Fix the thing quickly"


def _commit_date(days_ago):
    moment = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return f"{int(moment.timestamp())} +0000"


def _fake_codecommit_session(repository_names=(), repos=None):
    """Build a MagicMock boto3.Session whose codecommit client serves the
    calls the git collector makes.

    ``repos`` maps a repository name to ``{"branch": name, "head": commit id,
    "commits": [(commit id, parent ids, days ago, message), ...]}``; a
    repository without an entry is empty (no default branch). moto's
    CodeCommit support does not cover these calls, so the client is mocked.
    """
    repos = repos or {}
    cc = MagicMock()
    listing = {
        "repositories": [
            {"repositoryName": name, "repositoryId": f"id-{name}"}
            for name in repository_names
        ]
    }

    paginator = MagicMock()
    paginator.paginate.side_effect = lambda **kwargs: iter([listing])

    def get_paginator(name):
        assert name == "list_repositories", name
        return paginator

    cc.get_paginator.side_effect = get_paginator
    cc.list_repositories.return_value = listing

    def get_repository(repositoryName):
        metadata = {"repositoryName": repositoryName}
        branch = repos.get(repositoryName, {}).get("branch")
        if branch:
            metadata["defaultBranch"] = branch
        return {"repositoryMetadata": metadata}

    def get_branch(repositoryName, branchName):
        spec = repos[repositoryName]
        assert branchName == spec["branch"]
        return {"branch": {"branchName": branchName, "commitId": spec["head"]}}

    def get_commit(repositoryName, commitId):
        for commit_id, parents, days_ago, message in repos[repositoryName]["commits"]:
            if commit_id == commitId:
                date = _commit_date(days_ago)
                return {"commit": {
                    "commitId": commit_id,
                    "parents": list(parents),
                    "message": message,
                    "author": {"name": "Dev", "email": "dev@example.com", "date": date},
                    "committer": {"name": "Dev", "email": "dev@example.com", "date": date},
                }}
        raise AssertionError(f"unexpected commit {commitId}")

    cc.get_repository.side_effect = get_repository
    cc.get_branch.side_effect = get_branch
    cc.get_commit.side_effect = get_commit

    session = MagicMock()
    session.client.return_value = cc
    session.region_name = "us-east-1"
    return session, cc


def _linear(prefix, specs):
    """Commits newest first, each the parent of the one before; ids differ in
    their first seven characters (``<prefix><index:06d>`` padded to 40)."""
    def commit_id(index):
        return f"{prefix}{index:06d}".ljust(40, "f")

    commits = []
    for index, (days_ago, message) in enumerate(specs):
        parents = [commit_id(index + 1)] if index + 1 < len(specs) else []
        commits.append((commit_id(index), parents, days_ago, message))
    return commits


def _repo(commits, branch="main"):
    return {"branch": branch, "head": commits[0][0], "commits": commits}


def _run_git(config_overrides=None, **session_kwargs):
    config = _make_config(
        "git",
        credential_mode="task_role",
        config={"provider": "codecommit", "region": "us-east-1", **(config_overrides or {})},
    )
    session, cc = _fake_codecommit_session(**session_kwargs)
    with patch("boto3.Session", return_value=session):
        results = GitCollector(config=config).run()
    return results, cc


def _change_results(results):
    return {r.check_name: r for r in results if r.check_name.startswith("codecommit_change_management")}


def test_git_collector_required_permissions_read_commits_only():
    assert GIT_CODECOMMIT_REQUIRED_PERMISSIONS == [
        "sts:GetCallerIdentity",
        "codecommit:ListRepositories",
        "codecommit:GetRepository",
        "codecommit:GetBranch",
        "codecommit:GetCommit",
    ]


def test_git_collector_rejects_unknown_provider(app_ctx):
    config = _make_config(
        "git",
        credential_mode="task_role",
        config={"provider": "github"},
    )
    results = GitCollector(config=config).run()
    assert any(
        r.check_name == "git_provider" and r.status == "error"
        for r in results
    )


ALL_SECTIONS = ["Problem", "Solution", "Verified"]


@pytest.mark.parametrize("message, missing", [
    (STRUCTURED, []),
    ("x\n## problem\na\n##   SOLUTION  \nb\n## Verified\nc", []),
    ("x\r\n## Problem\r\na\r\n## Solution\r\nb\r\n## Verified\r\nc\r\n", []),
    ("  ## Problem\n  a\n  ## Solution\n  b\n  ## Verified\n  c", []),
    ("## Problem\na\n### Detail\n## Solution\n### Steps\n## Verified\nc", []),
    ("## Problem\na\n## Solution\nb\n## Verified\nTests pass.\n\nCo-Authored-By: X <x@example.com>", []),
    ("## Problem\na\n## Solution\nb\n## Verified\n\nTests: 1983 passed", []),
    ("## Problem\na\n## Solution\nb\n## Verified\nhttps://board.example/c/1\nCo-Authored-By: X <x@example.com>", []),
    ("## Problem\na\n## Solution\n", ["Solution", "Verified"]),
    ("## Problem\n## Solution\n## Verified", ALL_SECTIONS),
    ("## Problem\n\n   \n## Solution\nb\n## Verified\nc", ["Problem"]),
    ("## Problem\na\n## Solution\nb\n## Verified\n\nCo-Authored-By: X <x@example.com>\nSigned-off-by: Y <y@example.com>",
     ["Verified"]),
    ("## Problem\na\n## Notes\nn\n## Solution\nb\n# Verified\nc", ["Verified"]),
    ("## Problem\n## Problem\na\n## Solution\nb\n## Verified\nc", []),
    ("### Problem\na\n### Solution\nb\n### Verified\nc", ALL_SECTIONS),
    ("See ## Problem, ## Solution and ## Verified", ALL_SECTIONS),
    ("## Problems\na\n## Solution:\nb\n## Verified\nc", ["Problem", "Solution"]),
    ("Co-Authored-By: X <x@example.com>", ALL_SECTIONS),
    ("", ALL_SECTIONS),
])
def test_missing_sections(message, missing):
    assert codecommit_checks.missing_sections(message) == missing


def test_check_names_fit_the_database_column():
    short = codecommit_checks.check_name_for("app")
    assert short == "codecommit_change_management:app"
    long_a = "a" * 100
    long_b = "a" * 99 + "b"
    name_a = codecommit_checks.check_name_for(long_a)
    name_b = codecommit_checks.check_name_for(long_b)
    assert len(name_a) == len(name_b) == 128
    assert name_a != name_b
    assert name_a.startswith("codecommit_change_management:aaaa")
    assert len(codecommit_checks.check_name_for("x" * 99)) == 128


def test_long_repository_name_keeps_its_full_name_in_detail(app_ctx):
    name = "r" * 100
    results, _ = _run_git(repository_names=[name], repos={name: _repo(_linear("a", [(1, STRUCTURED)]))})
    change = [r for r in results if r.check_name.startswith("codecommit_change_management")][0]
    assert len(change.check_name) <= 128
    assert change.detail["repository"] == name
    assert change.status == "pass"


def test_git_collector_empty_codecommit_account(app_ctx):
    results, _ = _run_git(repository_names=[])
    inventory = [r for r in results if r.check_name == "codecommit_inventory"]
    assert len(inventory) == 1
    assert inventory[0].status == "fail"
    change = _change_results(results)["codecommit_change_management"]
    assert change.status == "fail"
    assert change.message == "No repositories in change-management scope"


def test_git_collector_runs_no_pull_request_or_approval_rule_checks(app_ctx):
    commits = _linear("a", [(1, STRUCTURED)])
    results, cc = _run_git(repository_names=["repo-one"], repos={"repo-one": _repo(commits)})

    assert {r.check_name for r in results} == {
        "codecommit_inventory", "codecommit_change_management:repo-one"}
    assert {r.target_test_name for r in results} == {"Change management process"}
    for name in ("list_pull_requests", "get_pull_request", "list_approval_rule_templates",
                 "list_associated_approval_rule_templates_for_repository"):
        assert not getattr(cc, name).called, name


def test_change_management_passes_when_every_commit_is_structured(app_ctx):
    commits = _linear("a", [(1, STRUCTURED), (5, STRUCTURED), (20, STRUCTURED)])
    results, _ = _run_git(repository_names=["repo-one"], repos={"repo-one": _repo(commits)})

    inventory = [r for r in results if r.check_name == "codecommit_inventory"][0]
    assert inventory.status == "pass"
    assert inventory.detail["count"] == 1
    assert inventory.detail["in_scope"] == ["repo-one"]
    change = _change_results(results)["codecommit_change_management:repo-one"]
    assert change.status == "pass"
    assert change.target_test_name == "Change management process"
    assert change.detail["repository"] == "repo-one"
    assert change.detail["branch"] == "main"
    assert change.detail["commits"] == 3
    assert change.detail["compliant"] == 3
    assert change.detail["noncompliant"] == 0
    assert change.detail["failing_commits"] == []
    assert change.detail["incomplete"] is False
    assert change.detail["commits_read"] == 3
    assert "all 3 commits in the last 30 days" in change.message


def test_change_management_fails_and_names_unstructured_commits(app_ctx):
    empty_verified = "Fix\n\n## Problem\na\n\n## Solution\nb\n\n## Verified\n"
    commits = _linear("a", [(1, STRUCTURED), (2, UNSTRUCTURED), (3, empty_verified)])
    results, _ = _run_git(repository_names=["repo-one"], repos={"repo-one": _repo(commits)})

    change = _change_results(results)["codecommit_change_management:repo-one"]
    assert change.status == "fail"
    assert change.detail["commits"] == 3
    assert change.detail["compliant"] == 1
    assert change.detail["noncompliant"] == 2
    short_ids = [commits[1][0][:7], commits[2][0][:7]]
    assert change.detail["failing_commits"] == short_ids
    assert ("2 of 3 commits in the last 30 days lack ## Problem, ## Solution, ## Verified with text"
            in change.message)
    assert all(short_id in change.message for short_id in short_ids)


def test_change_management_reads_past_old_commits_and_judges_by_date(app_ctx):
    commits = _linear("a", [(1, STRUCTURED), (10, STRUCTURED), (45, UNSTRUCTURED), (60, UNSTRUCTURED)])
    results, cc = _run_git(
        {"lookback_days": 30}, repository_names=["repo-one"], repos={"repo-one": _repo(commits)})

    change = _change_results(results)["codecommit_change_management:repo-one"]
    assert change.status == "pass"
    assert change.detail["commits"] == 2
    assert change.detail["commits_read"] == 4
    assert change.detail["lookback_days"] == 30
    assert cc.get_commit.call_count == 4


def test_backdated_commit_hides_neither_itself_nor_its_ancestors(app_ctx):
    commits = _linear("a", [(400, STRUCTURED), (1, UNSTRUCTURED), (2, STRUCTURED), (90, STRUCTURED)])
    results, _ = _run_git(repository_names=["repo-one"], repos={"repo-one": _repo(commits)})

    change = _change_results(results)["codecommit_change_management:repo-one"]
    assert change.status == "fail"
    # The head, dated 400 days ago, has an in-window parent: it is in the window too.
    assert change.detail["commits"] == 3
    assert change.detail["failing_commits"] == [commits[1][0][:7]]


def test_backdated_unstructured_head_is_judged(app_ctx):
    commits = _linear("a", [(400, UNSTRUCTURED), (1, STRUCTURED)])
    results, _ = _run_git(repository_names=["repo-one"], repos={"repo-one": _repo(commits)})

    change = _change_results(results)["codecommit_change_management:repo-one"]
    assert change.status == "fail"
    assert change.detail["failing_commits"] == [commits[0][0][:7]]


def test_change_management_lookback_days_widens_the_window(app_ctx):
    commits = _linear("a", [(1, STRUCTURED), (45, UNSTRUCTURED)])
    results, _ = _run_git(
        {"lookback_days": 60}, repository_names=["repo-one"], repos={"repo-one": _repo(commits)})

    change = _change_results(results)["codecommit_change_management:repo-one"]
    assert change.status == "fail"
    assert change.detail["failing_commits"] == [commits[1][0][:7]]


def test_change_management_repository_without_recent_changes_passes(app_ctx):
    commits = _linear("a", [(40, UNSTRUCTURED)])
    results, _ = _run_git(repository_names=["quiet", "empty"], repos={"quiet": _repo(commits)})

    changes = _change_results(results)
    quiet = changes["codecommit_change_management:quiet"]
    assert quiet.status == "pass"
    assert quiet.detail["commits"] == 0
    assert "no changes in the last 30 days" in quiet.message
    empty = changes["codecommit_change_management:empty"]
    assert empty.status == "pass"
    assert empty.detail["branch"] is None
    assert "no changes" in empty.message


def test_change_management_checks_merged_commits_not_the_merge(app_ctx):
    merge = "m" * 40
    main_parent = "b" * 40
    side = "c" * 40
    base = "d" * 40
    commits = [
        (merge, [main_parent, side], 1, "Merge branch 'main' of origin"),
        (main_parent, [base], 2, STRUCTURED),
        (side, [base], 3, UNSTRUCTURED),
        (base, [], 50, STRUCTURED),
    ]
    results, _ = _run_git(repository_names=["repo-one"], repos={"repo-one": _repo(commits)})

    change = _change_results(results)["codecommit_change_management:repo-one"]
    assert change.status == "fail"
    assert change.detail["commits"] == 2
    assert change.detail["merge_commits"] == 1
    assert change.detail["failing_commits"] == [side[:7]]


def test_change_management_excludes_repositories(app_ctx):
    structured = _repo(_linear("a", [(1, STRUCTURED)]))
    unstructured = _repo(_linear("b", [(1, UNSTRUCTURED)]))
    results, cc = _run_git(
        {"exclude_repositories": ["internal-tools"]},
        repository_names=["app", "internal-tools"],
        repos={"app": structured, "internal-tools": unstructured},
    )

    changes = _change_results(results)
    assert set(changes) == {"codecommit_change_management:app"}
    assert changes["codecommit_change_management:app"].status == "pass"
    inventory = [r for r in results if r.check_name == "codecommit_inventory"][0]
    assert inventory.detail["excluded"] == ["internal-tools"]
    assert inventory.detail["in_scope"] == ["app"]
    assert "excluded: internal-tools" in inventory.evidence_description
    assert all(call.kwargs["repositoryName"] == "app" for call in cc.get_commit.call_args_list)


def test_change_management_everything_excluded_fails(app_ctx):
    results, _ = _run_git(
        {"exclude_repositories": ["only"]},
        repository_names=["only"],
        repos={"only": _repo(_linear("a", [(1, UNSTRUCTURED)]))},
    )
    change = _change_results(results)["codecommit_change_management"]
    assert change.status == "fail"
    assert change.message == "No repositories in change-management scope"
    assert change.detail == {"repository_count": 1, "excluded": ["only"]}


def test_git_collector_respects_repo_filter(app_ctx):
    repos = {name: _repo(_linear(prefix, [(1, STRUCTURED)]))
             for name, prefix in (("alpha", "a"), ("beta", "b"), ("gamma", "c"))}
    results, _ = _run_git(
        {"repositories": ["alpha", "gamma", "missing"]},
        repository_names=["alpha", "beta", "gamma"],
        repos=repos,
    )

    changes = _change_results(results)
    assert {r.detail["repository"] for r in changes.values() if r.status == "pass"} == {"alpha", "gamma"}
    missing = changes["codecommit_change_management:missing"]
    assert missing.status == "error"
    assert "not among the account's CodeCommit repositories" in missing.message


def test_change_management_window_beyond_the_walk_fails_as_incomplete(app_ctx, monkeypatch):
    monkeypatch.setattr(codecommit_checks, "MAX_COMMITS_PER_REPO", 3)
    commits = _linear("a", [(1, STRUCTURED)] * 6)
    results, cc = _run_git(repository_names=["busy"], repos={"busy": _repo(commits)})

    change = _change_results(results)["codecommit_change_management:busy"]
    assert change.status == "fail"
    assert change.detail["commits"] == 3
    assert change.detail["noncompliant"] == 0
    assert change.detail["incomplete"] is True
    assert "the window reaches beyond the 3 commits read" in change.message
    assert cc.get_commit.call_count == 3


def test_change_management_walk_bound_inside_closed_window_passes(app_ctx, monkeypatch):
    monkeypatch.setattr(codecommit_checks, "MAX_COMMITS_PER_REPO", 3)
    commits = _linear("a", [(1, STRUCTURED), (2, STRUCTURED), (40, UNSTRUCTURED), (50, UNSTRUCTURED)])
    results, cc = _run_git(repository_names=["repo"], repos={"repo": _repo(commits)})

    change = _change_results(results)["codecommit_change_management:repo"]
    assert change.status == "pass"
    assert change.detail["incomplete"] is False
    assert change.detail["commits"] == 2
    assert cc.get_commit.call_count == 3


def test_change_management_bounds_repositories(app_ctx, monkeypatch):
    monkeypatch.setattr(codecommit_checks, "MAX_REPOSITORIES", 2)
    results, cc = _run_git(repository_names=["r1", "r2", "r3"])

    changes = _change_results(results)
    assert changes["codecommit_change_management"].status == "error"
    assert changes["codecommit_change_management"].detail["in_scope_count"] == 3
    assert {"codecommit_change_management:r1", "codecommit_change_management:r2"} <= set(changes)
    assert "codecommit_change_management:r3" not in changes
    assert cc.get_repository.call_count == 2


def test_change_management_error_on_one_repository_keeps_the_others(app_ctx):
    good = _repo(_linear("a", [(1, STRUCTURED)]))
    session, cc = _fake_codecommit_session(repository_names=["broken", "good"], repos={"good": good})
    serve = cc.get_repository.side_effect

    def get_repository(repositoryName):
        if repositoryName == "broken":
            raise RuntimeError("throttled")
        return serve(repositoryName=repositoryName)

    cc.get_repository.side_effect = get_repository
    results = codecommit_checks.check_change_management(session)

    by_name = {r.check_name: r for r in results}
    assert by_name["codecommit_change_management:broken"].status == "error"
    assert "throttled" in by_name["codecommit_change_management:broken"].message
    assert by_name["codecommit_change_management:good"].status == "pass"


def test_change_management_listing_failure_is_an_error(app_ctx):
    session, cc = _fake_codecommit_session()
    cc.get_paginator.side_effect = RuntimeError("denied")

    results = codecommit_checks.check_change_management(session)
    assert [(r.check_name, r.status) for r in results] == [("codecommit_change_management", "error")]
    inventory = codecommit_checks.check_repository_inventory(session)
    assert [(r.check_name, r.status) for r in inventory] == [("codecommit_inventory", "error")]


@pytest.mark.parametrize("overrides, problem", [
    ({"lookback_days": 0}, "lookback_days must be a whole number from 1 to 365"),
    ({"lookback_days": 366}, "lookback_days must be a whole number from 1 to 365"),
    ({"lookback_days": "soon"}, "lookback_days must be a whole number from 1 to 365"),
    ({"lookback_days": True}, "lookback_days must be a whole number from 1 to 365"),
    ({"exclude_repositories": {"a": 1}}, "exclude_repositories must be a list of repository names"),
    ({"repositories": [1, 2]}, "repositories must be a list of repository names"),
])
def test_git_collector_rejects_invalid_configuration(app_ctx, overrides, problem):
    results, cc = _run_git(overrides, repository_names=["repo-one"])
    assert [(r.check_name, r.status) for r in results] == [("git_config", "error")]
    assert problem in results[0].message
    assert not cc.get_repository.called


def test_git_collector_accepts_a_single_excluded_name_and_numeric_text(app_ctx):
    results, _ = _run_git(
        {"exclude_repositories": "internal", "lookback_days": "7"},
        repository_names=["internal", "app"],
        repos={"app": _repo(_linear("a", [(3, STRUCTURED)]))},
    )
    changes = _change_results(results)
    assert set(changes) == {"codecommit_change_management:app"}
    assert changes["codecommit_change_management:app"].detail["lookback_days"] == 7


def test_git_form_settings_parse_repository_lists_and_window():
    settings = parse_form_settings({
        "repositories": "alpha\n\n beta \n",
        "exclude_repositories": " internal-tools \n\nsandbox\n",
        "lookback_days": " 14 ",
    })
    assert settings == {
        "repositories": ["alpha", "beta"],
        "exclude_repositories": ["internal-tools", "sandbox"],
        "lookback_days": 14,
    }


def test_git_form_settings_blank_fields():
    assert parse_form_settings({"repositories": "  \n", "exclude_repositories": "", "lookback_days": ""}) == {
        "repositories": None,
        "exclude_repositories": [],
    }
    assert parse_form_settings({}) == {}


@pytest.mark.parametrize("lookback", ["0", "366", "soon", "7.5"])
def test_git_form_settings_reject_lookback_outside_range(lookback):
    with pytest.raises(ValueError, match="lookback_days must be a whole number from 1 to 365"):
        parse_form_settings({"lookback_days": lookback})


# ============================================================================
# Permission probes for CodeCommit
# ============================================================================


def test_codecommit_probes_registered():
    for action in GIT_CODECOMMIT_REQUIRED_PERMISSIONS:
        assert action in AWS_ACTION_PROBES, f"Missing probe for {action}"


def _client_error(code, operation):
    from botocore.exceptions import ClientError

    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


@pytest.mark.parametrize("action, method, not_found", [
    ("codecommit:GetBranch", "get_branch", "BranchDoesNotExistException"),
    ("codecommit:GetCommit", "get_commit", "CommitIdDoesNotExistException"),
])
def test_codecommit_probe_counts_not_found_as_authorized(action, method, not_found):
    session, cc = _fake_codecommit_session(repository_names=["repo-one"])
    getattr(cc, method).side_effect = _client_error(not_found, method)
    AWS_ACTION_PROBES[action](session, {})
    assert getattr(cc, method).call_args.kwargs["repositoryName"] == "repo-one"

    getattr(cc, method).side_effect = _client_error("AccessDeniedException", method)
    with pytest.raises(Exception) as raised:
        AWS_ACTION_PROBES[action](session, {})
    assert raised.value.response["Error"]["Code"] == "AccessDeniedException"


@pytest.mark.parametrize("action, method", [
    ("codecommit:GetRepository", "get_repository"),
    ("codecommit:GetBranch", "get_branch"),
    ("codecommit:GetCommit", "get_commit"),
])
def test_codecommit_probes_without_repositories_in_scope_make_no_repository_call(action, method):
    session, cc = _fake_codecommit_session(repository_names=[])
    AWS_ACTION_PROBES[action](session, {})
    assert not getattr(cc, method).called

    session, cc = _fake_codecommit_session(repository_names=["internal"])
    AWS_ACTION_PROBES[action](session, {"exclude_repositories": ["internal"]})
    assert not getattr(cc, method).called


@pytest.mark.parametrize("action, method", [
    ("codecommit:GetRepository", "get_repository"),
    ("codecommit:GetBranch", "get_branch"),
    ("codecommit:GetCommit", "get_commit"),
])
def test_codecommit_probes_exercise_a_repository_in_scope(action, method):
    session, cc = _fake_codecommit_session(repository_names=["alpha", "beta", "gamma"])
    for call in ("get_branch", "get_commit"):
        getattr(cc, call).side_effect = None
    AWS_ACTION_PROBES[action](session, {"repositories": ["beta", "gamma"], "exclude_repositories": ["beta"]})
    assert getattr(cc, method).call_args.kwargs["repositoryName"] == "gamma"


def test_permission_prober_passes_the_collector_config_to_scoped_probes():
    from app.services.credential_resolver import ResolvedCredentials
    from app.services.permission_prober import PermissionProber

    session, cc = _fake_codecommit_session(repository_names=["alpha", "beta"])
    session.client.side_effect = lambda service, **kwargs: (
        cc if service == "codecommit" else MagicMock(get_caller_identity=MagicMock(
            return_value={"Arn": "arn:aws:iam::123456789012:user/probe", "Account": "123456789012"})))
    resolved = ResolvedCredentials(mode="task_role", boto_session=session)

    result = PermissionProber().probe(
        resolved, required_actions=["codecommit:GetRepository"],
        collector_config={"exclude_repositories": ["alpha"]})

    assert result.all_passed
    cc.get_repository.assert_called_once_with(repositoryName="beta")


# ============================================================================
# Executor integration
# ============================================================================


def test_executor_runs_policy_collector(app_ctx):
    Policy(
        id=str(uuid.uuid4()),
        title="Test Policy",
        category="security",
        status="approved",
        next_review_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    p = Policy(
        id=str(uuid.uuid4()),
        title="Test Policy",
        category="security",
        status="approved",
        next_review_at=datetime.now(timezone.utc) + timedelta(days=90),
    )
    db.session.add(p)
    db.session.commit()

    config = _make_config("policy")
    run = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="manual",
        status="running",
    )
    db.session.add(run)
    db.session.commit()

    execute_run(run)
    assert run.status in ("success", "partial")
    assert run.check_pass_count > 0


def test_executor_runs_vendor_collector(app_ctx):
    v = Vendor(
        id=str(uuid.uuid4()),
        name="Stripe",
        status="active",
        security_page_url="https://stripe.com/security",
        privacy_policy_url="https://stripe.com/privacy",
        purpose="Payments",
    )
    db.session.add(v)
    db.session.commit()

    config = _make_config("vendor")
    run = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="manual",
        status="running",
    )
    db.session.add(run)
    db.session.commit()
    execute_run(run)
    assert run.status in ("success", "partial")


def test_executor_runs_git_collector(app_ctx):
    config = _make_config(
        "git",
        credential_mode="task_role",
        config={"provider": "codecommit", "region": "us-east-1"},
    )
    run = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="manual",
        status="running",
    )
    db.session.add(run)
    db.session.commit()

    session, _ = _fake_codecommit_session(repository_names=["test-repo"])
    with patch("boto3.Session", return_value=session):
        execute_run(run)
    assert run.status == "success"
    assert run.finished_at is not None


def _git_run_with_unreadable(repository_names, readable):
    config = _make_config(
        "git",
        credential_mode="task_role",
        config={"provider": "codecommit", "region": "us-east-1"},
    )
    run = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="manual",
        status="running",
    )
    db.session.add(run)
    db.session.commit()

    session, cc = _fake_codecommit_session(
        repository_names=repository_names,
        repos={name: _repo(_linear(name[0], [(1, STRUCTURED)])) for name in readable},
    )
    serve = cc.get_repository.side_effect

    def get_repository(repositoryName):
        if repositoryName not in readable:
            raise RuntimeError("throttled")
        return serve(repositoryName=repositoryName)

    cc.get_repository.side_effect = get_repository
    with patch("boto3.Session", return_value=session):
        execute_run(run)
    return run


def test_executor_run_with_an_errored_repository_is_partial(app_ctx):
    run = _git_run_with_unreadable(["broken", "good"], readable={"good"})
    assert run.status == "partial"
    statuses = {r.check_name: r.status for r in CollectorCheckResult.query.filter_by(collector_run_id=run.id)}
    assert statuses["codecommit_change_management:broken"] == "error"
    assert statuses["codecommit_change_management:good"] == "pass"


def test_executor_run_whose_checks_pass_or_error_only_is_not_success(app_ctx):
    run = _git_run_with_unreadable(["broken"], readable=set())
    # The inventory passes and the only repository errors: the run is partial, never success.
    assert run.status == "partial"
    assert run.check_pass_count == 1
    assert run.check_fail_count == 0


# ============================================================================
# Linking check results to test records by name
# ============================================================================


def _make_test_record(name, record_id=None):
    control = Control(id=str(uuid.uuid4()), name="CC5.3", category="security")
    db.session.add(control)
    db.session.flush()
    record = TestRecord(id=record_id or str(uuid.uuid4()), control_id=control.id, name=name)
    db.session.add(record)
    db.session.commit()
    return record


def test_resolve_test_record_prefers_exact_match(app_ctx):
    _make_test_record("policy management", record_id="00000000-0000-0000-0000-000000000001")
    exact = _make_test_record("Policy Management", record_id="00000000-0000-0000-0000-000000000002")

    assert _resolve_test_record("Policy Management").id == exact.id


def test_resolve_test_record_ignores_case_and_surrounding_spaces(app_ctx):
    record = _make_test_record("  Policy management ")

    assert _resolve_test_record("Policy Management").id == record.id
    assert _resolve_test_record(" POLICY MANAGEMENT\n").id == record.id


def test_resolve_test_record_relaxed_match_is_deterministic(app_ctx):
    _make_test_record("backup ENABLED", record_id="00000000-0000-0000-0000-00000000000b")
    lowest = _make_test_record("Backup enabled ", record_id="00000000-0000-0000-0000-00000000000a")

    assert _resolve_test_record("Backup Enabled").id == lowest.id


@pytest.mark.parametrize("target", [None, "", "   ", "Policy", "Policy  Management"])
def test_resolve_test_record_without_match_returns_none(app_ctx, target):
    _make_test_record("Policy management")

    assert _resolve_test_record(target) is None


def test_executor_links_evidence_to_test_named_with_different_case(app_ctx):
    db.session.add(Policy(
        id=str(uuid.uuid4()),
        title="Information Security Policy",
        category="security",
        status="approved",
        next_review_at=datetime.now(timezone.utc) + timedelta(days=90),
    ))
    db.session.commit()
    record = _make_test_record("Policy management")

    config = _make_config("policy")
    run = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="manual",
        status="running",
    )
    db.session.add(run)
    db.session.commit()

    execute_run(run)

    results = CollectorCheckResult.query.filter_by(collector_run_id=run.id).all()
    assert results
    assert {r.target_test_id for r in results} == {record.id}
    evidence = Evidence.query.filter_by(collector_name="policy").all()
    assert evidence
    assert {e.test_record_id for e in evidence} == {record.id}
    assert run.evidence_count == len(evidence)


# ============================================================================
# Admin UI form submission for non-AWS collectors
# ============================================================================


def _login_admin(client, admin):
    login(client, admin)


def test_admin_form_submit_policy_config(client, admin):
    _login_admin(client, admin)
    resp = client.post(
        "/admin/collectors/policy",
        data={
            "credential_mode": "none",
            "review_warning_days": "45",
            "enabled": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    config = CollectorConfig.query.filter_by(name="policy").one()
    assert config.credential_mode == "none"
    assert config.config["review_warning_days"] == 45


def test_admin_form_submit_platform_services_json(client, admin):
    _login_admin(client, admin)
    services = [{"name": "api", "url": "https://api.example", "health_path": "/h", "auth": "none"}]
    resp = client.post(
        "/admin/collectors/platform",
        data={
            "credential_mode": "none",
            "services_json": json.dumps(services),
            "http_timeout_seconds": "15",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    config = CollectorConfig.query.filter_by(name="platform").one()
    assert config.config["services"] == services
    assert config.config["http_timeout_seconds"] == 15


def test_admin_form_rejects_invalid_services_json(client, admin):
    _login_admin(client, admin)
    resp = client.post(
        "/admin/collectors/platform",
        data={"credential_mode": "none", "services_json": "not json at all"},
        follow_redirects=False,
    )
    # Should flash an error and redirect, not create the config
    assert resp.status_code == 302
    assert CollectorConfig.query.filter_by(name="platform").count() == 0


def test_admin_form_submit_git_config(client, admin):
    _login_admin(client, admin)
    resp = client.post(
        "/admin/collectors/git",
        data={
            "credential_mode": "task_role",
            "region": "ca-central-1",
            "repositories": "alpha\nbeta\n",
            "lookback_days": "60",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    config = CollectorConfig.query.filter_by(name="git").one()
    assert config.config["region"] == "ca-central-1"
    assert config.config["repositories"] == ["alpha", "beta"]
    assert config.config["lookback_days"] == 60


def test_admin_form_submit_vendor_probe_urls(client, admin):
    _login_admin(client, admin)
    resp = client.post(
        "/admin/collectors/vendor",
        data={
            "credential_mode": "none",
            "probe_urls": "on",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    config = CollectorConfig.query.filter_by(name="vendor").one()
    assert config.config["probe_urls"] is True


def test_admin_form_platform_bearer_token_encrypted(client, admin):
    _login_admin(client, admin)
    resp = client.post(
        "/admin/collectors/platform",
        data={
            "credential_mode": "access_keys",
            "bearer_token": "supersecret",
            "services_json": "[]",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    config = CollectorConfig.query.filter_by(name="platform").one()
    assert config.encrypted_credentials is not None
    assert b"supersecret" not in config.encrypted_credentials


def test_configure_page_renders_for_all_collectors(client, admin):
    _login_admin(client, admin)
    for collector_name in ("aws", "git", "platform", "policy", "vendor"):
        resp = client.get(f"/admin/collectors/{collector_name}")
        assert resp.status_code == 200, f"{collector_name} failed to render"
        body = resp.get_data(as_text=True)
        assert "Configure:" in body
