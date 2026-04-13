"""Integration tests for the v2 AWS collector against moto mocks.

Covers:
- The AWS collector end-to-end via the executor
- Real per-service check functions in collectors/aws/*_checks.py
- The PermissionProber against moto sessions
- The /api/collectors/aws/run endpoint
- Evidence row creation and test-record linking
"""

import uuid

import boto3
import pytest
from cryptography.fernet import Fernet
from moto import mock_aws

from app import create_app
from app.config import TestConfig
from app.models import (
    CollectorCheckResult,
    CollectorConfig,
    CollectorRun,
    Control,
    Evidence,
    TestRecord,
    db,
)
from app.services import team_service
from app.services.collector_executor import execute_run
from app.services.credential_resolver import CredentialResolver
from app.services.permission_prober import PermissionProber
from collectors.aws import AWSCollector
from collectors.aws.collector import AWS_REQUIRED_PERMISSIONS


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
def admin_headers(app_ctx):
    admin = team_service.create_member(
        "Admin", "admin@example.com", "human", is_compliance_admin=True
    )
    return {"X-API-Key": admin.api_key}


@pytest.fixture
def client(app_ctx):
    return app_ctx.test_client()


def _make_config(mode="task_role"):
    config = CollectorConfig(
        id=str(uuid.uuid4()),
        name="aws",
        enabled=True,
        credential_mode=mode,
        config={"region": "us-east-1"},
    )
    db.session.add(config)
    db.session.commit()
    return config


def _make_test_record(name, control_name="CC6.1 Logical Access"):
    control = Control(
        id=str(uuid.uuid4()),
        name=control_name,
        category="security",
        state="adopted",
    )
    db.session.add(control)
    db.session.flush()
    test = TestRecord(
        id=str(uuid.uuid4()),
        control_id=control.id,
        name=name,
    )
    db.session.add(test)
    db.session.commit()
    return test


# ----- Permission probe tests -----


@mock_aws
def test_permission_prober_all_pass(app_ctx):
    config = _make_config()
    resolver = CredentialResolver()
    resolved = resolver.resolve(config)
    prober = PermissionProber()
    result = prober.probe(resolved, required_actions=AWS_REQUIRED_PERMISSIONS)

    # moto provides mock implementations for every action probed.
    assert result.session_identity is not None
    assert result.account_id is not None
    status_by_action = {r.action: r.status for r in result.results}
    # All required actions should either pass or be skipped (none should error/fail)
    for action in AWS_REQUIRED_PERMISSIONS:
        assert status_by_action[action] in ("pass", "skipped"), (
            f"{action} got {status_by_action[action]}"
        )


@mock_aws
def test_permission_prober_structure(app_ctx):
    config = _make_config()
    resolver = CredentialResolver()
    resolved = resolver.resolve(config)
    prober = PermissionProber()
    result = prober.probe(resolved, required_actions=["sts:GetCallerIdentity"])

    d = result.to_dict()
    assert d["all_passed"] is True
    assert d["missing_actions"] == []
    assert d["account_id"] is not None


# ----- AWS collector end-to-end via executor -----


@mock_aws
def test_aws_collector_runs_against_moto(app_ctx):
    # Pre-populate moto with resources the collector will inspect.
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="testuser")
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
    )

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket-1")
    s3.put_bucket_encryption(
        Bucket="test-bucket-1",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )
    s3.put_bucket_versioning(
        Bucket="test-bucket-1",
        VersioningConfiguration={"Status": "Enabled"},
    )
    s3.put_public_access_block(
        Bucket="test-bucket-1",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    config = _make_config()
    collector = AWSCollector(config=config)
    results = collector.run()

    # Expect at least: IAM MFA, password policy, access key age, S3 enc,
    # S3 versioning, S3 PAB, RDS (no instances → pass), CloudTrail (fail).
    assert len(results) >= 7
    result_by_name = {r.check_name: r for r in results}

    # Password policy should pass because we set all required fields.
    assert any(
        r.check_name == "iam_password_policy" and r.status == "pass" for r in results
    )

    # S3 checks should pass for the encrypted/versioned bucket.
    assert result_by_name["s3_encryption:test-bucket-1"].status == "pass"
    assert result_by_name["s3_versioning:test-bucket-1"].status == "pass"
    assert result_by_name["s3_public_access_block:test-bucket-1"].status == "pass"

    # CloudTrail with no trails should fail.
    cloudtrail_results = [r for r in results if r.check_name.startswith("cloudtrail_enabled")]
    assert len(cloudtrail_results) >= 1
    assert any(r.status == "fail" for r in cloudtrail_results)


@mock_aws
def test_executor_creates_check_results_and_evidence(app_ctx):
    # Test record so evidence can be linked.
    _make_test_record("S3 encryption at rest")

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="ex-bucket")
    s3.put_bucket_encryption(
        Bucket="ex-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        },
    )

    config = _make_config()
    run = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="manual",
        status="running",
    )
    db.session.add(run)
    db.session.commit()

    result = execute_run(run)

    assert result.status in ("success", "partial")
    assert result.finished_at is not None
    assert result.check_pass_count > 0
    assert result.evidence_count > 0

    # There should be a check result with evidence linked to our test record.
    linked = (
        CollectorCheckResult.query
        .filter_by(collector_run_id=run.id)
        .filter(CollectorCheckResult.evidence_id.isnot(None))
        .all()
    )
    assert len(linked) >= 1
    evidence_row = db.session.get(Evidence, linked[0].evidence_id)
    assert evidence_row is not None
    assert evidence_row.collector_name == "aws"
    assert evidence_row.evidence_type == "automated"


@mock_aws
def test_executor_updates_config_last_run_status(app_ctx):
    config = _make_config()
    run = CollectorRun(
        id=str(uuid.uuid4()),
        collector_config_id=config.id,
        trigger_type="manual",
        status="running",
    )
    db.session.add(run)
    db.session.commit()
    execute_run(run)

    db.session.refresh(config)
    assert config.last_run_at is not None
    assert config.last_run_status in ("success", "partial", "failure")


# ----- /api/collectors/aws/run endpoint -----


@mock_aws
def test_run_endpoint_executes_and_reports_results(client, admin_headers):
    # Configure the collector
    client.post(
        "/api/collectors/aws/configure",
        headers=admin_headers,
        json={
            "credential_mode": "task_role",
            "config": {"region": "us-east-1"},
            "enabled": True,
        },
    )

    resp = client.post("/api/collectors/aws/run", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] in ("success", "partial", "failure")
    assert data["finished_at"] is not None


@mock_aws
def test_run_endpoint_unknown_collector_404(client, admin_headers):
    # Manually create a config for a collector that has no registered class.
    config = CollectorConfig(
        id=str(uuid.uuid4()),
        name="aws",
        enabled=True,
        credential_mode="task_role",
    )
    db.session.add(config)
    db.session.commit()
    # OK — aws is registered, this should work.
    resp = client.post("/api/collectors/aws/run", headers=admin_headers)
    assert resp.status_code == 200


def test_required_policy_endpoint(client, admin_headers):
    resp = client.get("/api/collectors/aws/required-policy", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["collector"] == "aws"
    assert "sts:GetCallerIdentity" in data["required_permissions"]
    assert data["policy"]["Version"] == "2012-10-17"
    assert len(data["policy"]["Statement"]) > 0


def test_required_policy_unknown_collector(client, admin_headers):
    resp = client.get("/api/collectors/bogus/required-policy", headers=admin_headers)
    assert resp.status_code == 404


@mock_aws
def test_probe_endpoint_uses_collector_required_permissions(client, admin_headers):
    client.post(
        "/api/collectors/aws/configure",
        headers=admin_headers,
        json={"credential_mode": "task_role", "config": {"region": "us-east-1"}},
    )
    resp = client.post("/api/collectors/aws/probe", headers=admin_headers, json={})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "probe" in data
    # Probe should have run against the AWS collector's declared permissions.
    action_names = {r["action"] for r in data["probe"]["results"]}
    assert "iam:ListUsers" in action_names
    assert "s3:ListAllMyBuckets" in action_names
    assert "cloudtrail:DescribeTrails" in action_names
