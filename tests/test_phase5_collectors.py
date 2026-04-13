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
    CollectorConfig,
    CollectorRun,
    Control,
    Policy,
    TestRecord,
    Vendor,
    db,
)
from app.services import team_service
from app.services.collector_executor import execute_run
from app.services.permission_prober import AWS_ACTION_PROBES
from collectors.aws.collector import AWS_REQUIRED_PERMISSIONS
from collectors.git import GitCollector
from collectors.git.collector import GIT_CODECOMMIT_REQUIRED_PERMISSIONS
from collectors.platform_collector import PlatformCollector
from collectors.policy_check_collector import PolicyCollector
from collectors.registry import COLLECTOR_CLASSES, get_collector_class
from collectors.vendor_check_collector import VendorCollector


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
                    "name": "maxgoodai",
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

    with patch("requests.get") as mock_get:
        mock_get.return_value = FakeResponse()
        results = PlatformCollector(config=config).run()

    mock_get.assert_called_once()
    call_kwargs = mock_get.call_args
    assert call_kwargs.args[0] == "https://api.example.com/api/health"
    assert any(
        r.check_name == "platform_health:maxgoodai" and r.status == "pass"
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
    with patch("requests.get", side_effect=Exception("connection refused")):
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

    with patch("requests.get", return_value=FakeResponse()):
        results = PlatformCollector(config=config).run()
    health = [r for r in results if r.check_name.startswith("platform_health:")]
    assert health[0].status == "fail"
    assert "503" in health[0].message


# ============================================================================
# Git collector (CodeCommit)
# ============================================================================


def test_git_collector_required_permissions_include_codecommit():
    assert "codecommit:ListRepositories" in GIT_CODECOMMIT_REQUIRED_PERMISSIONS
    assert "codecommit:ListApprovalRuleTemplates" in GIT_CODECOMMIT_REQUIRED_PERMISSIONS


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


def _fake_codecommit_session(repository_names=(), approval_templates=()):
    """Build a MagicMock boto3.Session whose codecommit client exposes the
    pages/methods the git collector uses.

    moto does not implement CodeCommit's list_repositories, so integration
    testing the collector requires mocking the client directly.
    """
    cc = MagicMock()

    repos_page = {
        "repositories": [
            {"repositoryName": name, "repositoryId": f"id-{name}"}
            for name in repository_names
        ]
    }
    templates_page = {"approvalRuleTemplateNames": list(approval_templates)}
    prs_page = {"pullRequestIds": []}

    def build_paginator(page):
        # Each call to paginate() must return a fresh iterator.
        paginator = MagicMock()
        paginator.paginate.side_effect = lambda **kwargs: iter([page])
        return paginator

    paginators = {
        "list_repositories": build_paginator(repos_page),
        "list_approval_rule_templates": build_paginator(templates_page),
        "list_pull_requests": build_paginator(prs_page),
    }

    def get_paginator(name):
        return paginators[name]

    cc.get_paginator.side_effect = get_paginator
    cc.list_repositories.return_value = {
        "repositories": [
            {"repositoryName": name, "repositoryId": f"id-{name}"}
            for name in repository_names
        ]
    }
    cc.list_associated_approval_rule_templates_for_repository.return_value = {
        "approvalRuleTemplateNames": [],
    }
    cc.list_pull_requests.return_value = {"pullRequestIds": []}

    session = MagicMock()
    session.client.return_value = cc
    session.region_name = "us-east-1"
    return session, cc


def test_git_collector_empty_codecommit_account(app_ctx):
    config = _make_config(
        "git",
        credential_mode="task_role",
        config={"provider": "codecommit", "region": "us-east-1"},
    )
    session, _ = _fake_codecommit_session(repository_names=[])
    with patch("boto3.Session", return_value=session):
        results = GitCollector(config=config).run()
    inventory = [r for r in results if r.check_name == "codecommit_inventory"]
    assert len(inventory) == 1
    assert inventory[0].status == "fail"


def test_git_collector_with_repositories(app_ctx):
    config = _make_config(
        "git",
        credential_mode="task_role",
        config={"provider": "codecommit", "region": "us-east-1"},
    )
    session, _ = _fake_codecommit_session(repository_names=["repo-one", "repo-two"])
    with patch("boto3.Session", return_value=session):
        results = GitCollector(config=config).run()

    inventory = [r for r in results if r.check_name == "codecommit_inventory"][0]
    assert inventory.status == "pass"
    assert inventory.detail["count"] == 2

    # Approval rule templates: none configured, should fail
    templates = [r for r in results if r.check_name == "codecommit_approval_rule_templates"][0]
    assert templates.status == "fail"

    # Per-repo approval: each should fail since no templates attached
    per_repo = [r for r in results if r.check_name.startswith("codecommit_repo_approval:")]
    assert len(per_repo) == 2
    assert all(r.status == "fail" for r in per_repo)


def test_git_collector_approval_templates_pass(app_ctx):
    """When the account has at least one approval rule template defined AND
    a repo has one attached, the relevant checks should pass."""
    config = _make_config(
        "git",
        credential_mode="task_role",
        config={"provider": "codecommit", "region": "us-east-1"},
    )
    session, cc = _fake_codecommit_session(
        repository_names=["repo-one"],
        approval_templates=["default-approval-rule"],
    )
    cc.list_associated_approval_rule_templates_for_repository.return_value = {
        "approvalRuleTemplateNames": ["default-approval-rule"],
    }
    with patch("boto3.Session", return_value=session):
        results = GitCollector(config=config).run()

    templates = [r for r in results if r.check_name == "codecommit_approval_rule_templates"][0]
    assert templates.status == "pass"
    per_repo = [r for r in results if r.check_name.startswith("codecommit_repo_approval:")]
    assert per_repo[0].status == "pass"


def test_git_collector_respects_repo_filter(app_ctx):
    config = _make_config(
        "git",
        credential_mode="task_role",
        config={
            "provider": "codecommit",
            "region": "us-east-1",
            "repositories": ["alpha", "gamma"],
        },
    )
    session, _ = _fake_codecommit_session(
        repository_names=["alpha", "beta", "gamma"]
    )
    with patch("boto3.Session", return_value=session):
        results = GitCollector(config=config).run()

    per_repo = [r for r in results if r.check_name.startswith("codecommit_repo_approval:")]
    repo_names = {r.detail["repository"] for r in per_repo if r.detail}
    assert repo_names == {"alpha", "gamma"}


# ============================================================================
# Permission probes for CodeCommit
# ============================================================================


def test_codecommit_probes_registered():
    for action in GIT_CODECOMMIT_REQUIRED_PERMISSIONS:
        assert action in AWS_ACTION_PROBES, f"Missing probe for {action}"


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
    assert run.status in ("success", "partial", "failure")
    assert run.finished_at is not None


# ============================================================================
# Admin UI form submission for non-AWS collectors
# ============================================================================


def _login_admin(client, admin):
    with client.session_transaction() as sess:
        sess["api_key"] = admin.api_key


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
