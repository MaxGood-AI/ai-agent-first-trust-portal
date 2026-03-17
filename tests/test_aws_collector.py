"""Tests for AWS infrastructure evidence collector.

Uses moto to mock all AWS services. Each test verifies that the collector
produces correct evidence items for a given AWS state.
"""

import json
import os
from unittest.mock import patch

import boto3
import moto
import pytest

from collectors.aws_collector import AWSCollector


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    """Set dummy AWS credentials for all tests."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_REGION", "us-east-1")


@pytest.fixture
def collector():
    return AWSCollector(region="us-east-1")


# --- IAM: MFA ---

@moto.mock_aws
def test_iam_mfa_enabled(collector):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="alice")
    iam.create_virtual_mfa_device(VirtualMFADeviceName="alice-mfa")
    iam.enable_mfa_device(
        UserName="alice",
        SerialNumber=f"arn:aws:iam::mfa/alice-mfa",
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )
    results = collector._collect_iam_mfa()
    assert len(results) == 1
    assert "MFA enabled" in results[0]["description"]


@moto.mock_aws
def test_iam_mfa_not_enabled(collector):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="bob")
    results = collector._collect_iam_mfa()
    assert len(results) == 1
    assert "MFA NOT enabled" in results[0]["description"]


# --- IAM: Password Policy ---

@moto.mock_aws
def test_iam_password_policy_exists(collector):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        RequireNumbers=True,
        RequireSymbols=True,
        MaxPasswordAge=90,
    )
    results = collector._collect_iam_password_policy()
    assert len(results) == 1
    assert "MinLength=14" in results[0]["description"]
    assert "MaxAge=90" in results[0]["description"]


@moto.mock_aws
def test_iam_password_policy_missing(collector):
    results = collector._collect_iam_password_policy()
    assert len(results) == 1
    assert "No account password policy" in results[0]["description"]


# --- IAM: Access Key Age ---

@moto.mock_aws
def test_iam_access_key_age(collector):
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="svc-account")
    iam.create_access_key(UserName="svc-account")
    results = collector._collect_iam_access_key_age()
    assert len(results) == 1
    assert "age 0 days" in results[0]["description"]
    assert "[STALE]" not in results[0]["description"]


# --- RDS ---

@moto.mock_aws
def test_rds_encryption_enabled(collector):
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="prod-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="secret123",
        StorageEncrypted=True,
    )
    results = collector._collect_rds_encryption()
    assert len(results) == 1
    assert "encryption enabled" in results[0]["description"]


@moto.mock_aws
def test_rds_encryption_disabled(collector):
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="dev-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="secret123",
        StorageEncrypted=False,
    )
    results = collector._collect_rds_encryption()
    assert len(results) == 1
    assert "encryption NOT enabled" in results[0]["description"]


@moto.mock_aws
def test_rds_backup_retention(collector):
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="prod-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="secret123",
        BackupRetentionPeriod=7,
    )
    results = collector._collect_rds_backups()
    assert len(results) == 1
    assert "retention 7 days" in results[0]["description"]


# --- EC2: Security Groups ---

@moto.mock_aws
def test_security_group_open_ingress(collector):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    sg = ec2.create_security_group(
        GroupName="wide-open",
        Description="test",
        VpcId=vpc["Vpc"]["VpcId"],
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    results = collector._collect_security_groups()
    matching = [r for r in results if sg["GroupId"] in r["description"]]
    assert len(matching) == 1
    assert "open to 0.0.0.0/0" in matching[0]["description"]


@moto.mock_aws
def test_security_group_no_open_ingress(collector):
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    ec2.create_security_group(
        GroupName="locked-down",
        Description="test",
        VpcId=vpc["Vpc"]["VpcId"],
    )
    results = collector._collect_security_groups()
    locked = [r for r in results if "locked-down" in r["description"]]
    assert len(locked) == 0


# --- S3 ---

@moto.mock_aws
def test_s3_public_access_blocked(collector):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="secure-bucket")
    s3.put_public_access_block(
        Bucket="secure-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    results = collector._collect_s3_public_access()
    matching = [r for r in results if "secure-bucket" in r["description"]]
    assert len(matching) == 1
    assert "all public access blocked" in matching[0]["description"]


@moto.mock_aws
def test_s3_versioning_enabled(collector):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="versioned-bucket")
    s3.put_bucket_versioning(
        Bucket="versioned-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )
    results = collector._collect_s3_versioning()
    matching = [r for r in results if "versioned-bucket" in r["description"]]
    assert len(matching) == 1
    assert "Enabled" in matching[0]["description"]


@moto.mock_aws
def test_s3_encryption(collector):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="encrypted-bucket")
    s3.put_bucket_encryption(
        Bucket="encrypted-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                },
            }],
        },
    )
    results = collector._collect_s3_encryption()
    matching = [r for r in results if "encrypted-bucket" in r["description"]]
    assert len(matching) == 1
    assert "aws:kms" in matching[0]["description"]


# --- CloudTrail ---

@moto.mock_aws
def test_cloudtrail_enabled(collector):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="trail-logs")
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(
        Name="main-trail",
        S3BucketName="trail-logs",
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
    )
    ct.start_logging(Name="main-trail")
    results = collector._collect_cloudtrail()
    assert any("multi-region=yes" in r["description"] for r in results)
    assert any("log-validation=yes" in r["description"] for r in results)


@moto.mock_aws
def test_cloudtrail_not_configured(collector):
    results = collector._collect_cloudtrail()
    assert len(results) == 1
    assert "No CloudTrail" in results[0]["description"]


# --- CloudWatch Logs ---

@moto.mock_aws
def test_cloudwatch_log_retention(collector):
    logs = boto3.client("logs", region_name="us-east-1")
    logs.create_log_group(logGroupName="/app/production")
    logs.put_retention_policy(logGroupName="/app/production", retentionInDays=90)
    results = collector._collect_cloudwatch_log_retention()
    matching = [r for r in results if "/app/production" in r["description"]]
    assert len(matching) == 1
    assert "90 days" in matching[0]["description"]


@moto.mock_aws
def test_cloudwatch_log_no_retention(collector):
    logs = boto3.client("logs", region_name="us-east-1")
    logs.create_log_group(logGroupName="/app/dev")
    results = collector._collect_cloudwatch_log_retention()
    matching = [r for r in results if "/app/dev" in r["description"]]
    assert len(matching) == 1
    assert "never expires" in matching[0]["description"]


# --- CloudWatch Alarms ---

@moto.mock_aws
def test_cloudwatch_alarms(collector):
    cw = boto3.client("cloudwatch", region_name="us-east-1")
    cw.put_metric_alarm(
        AlarmName="high-cpu",
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        ComparisonOperator="GreaterThanThreshold",
        Threshold=80.0,
        EvaluationPeriods=1,
        Period=300,
        Statistic="Average",
    )
    results = collector._collect_cloudwatch_alarms()
    assert len(results) == 1
    assert "1 CloudWatch alarm" in results[0]["description"]


@moto.mock_aws
def test_cloudwatch_no_alarms(collector):
    results = collector._collect_cloudwatch_alarms()
    assert len(results) == 1
    assert "No CloudWatch alarms" in results[0]["description"]


# --- Lambda ---

@moto.mock_aws
def test_lambda_function_evidence(collector):
    iam = boto3.client("iam", region_name="us-east-1")
    role = iam.create_role(
        RoleName="lambda-role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
    )
    lam = boto3.client("lambda", region_name="us-east-1")
    lam.create_function(
        FunctionName="my-handler",
        Runtime="python3.12",
        Role=role["Role"]["Arn"],
        Handler="index.handler",
        Code={"ZipFile": b"fake"},
    )
    results = collector._collect_lambda_functions()
    assert len(results) == 1
    assert "runtime=python3.12" in results[0]["description"]
    assert "my-handler" in results[0]["description"]


# --- KMS ---

@moto.mock_aws
def test_kms_key_rotation(collector):
    kms = boto3.client("kms", region_name="us-east-1")
    key = kms.create_key(Description="app-key")
    key_id = key["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=key_id)
    results = collector._collect_kms_key_rotation()
    matching = [r for r in results if "app-key" in r["description"]]
    assert len(matching) == 1
    assert "auto-rotation=yes" in matching[0]["description"]


# --- GuardDuty ---

@moto.mock_aws
def test_guardduty_enabled(collector):
    gd = boto3.client("guardduty", region_name="us-east-1")
    gd.create_detector(Enable=True)
    results = collector._collect_guardduty()
    assert len(results) == 1
    assert "ENABLED" in results[0]["description"]


@moto.mock_aws
def test_guardduty_no_detector(collector):
    results = collector._collect_guardduty()
    assert len(results) == 1
    assert "no detectors" in results[0]["description"]


# --- AWS Config ---

@moto.mock_aws
def test_config_recorder(collector):
    config = boto3.client("config", region_name="us-east-1")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::role/config-role",
        }
    )
    results = collector._collect_config_recorder()
    assert len(results) >= 1


@moto.mock_aws
def test_config_no_recorder(collector):
    results = collector._collect_config_recorder()
    assert len(results) == 1
    assert "no configuration recorders" in results[0]["description"]


# --- EventBridge ---

@moto.mock_aws
def test_eventbridge_rules(collector):
    eb = boto3.client("events", region_name="us-east-1")
    eb.put_rule(Name="daily-check", ScheduleExpression="rate(1 day)", State="ENABLED")
    eb.put_rule(Name="disabled-rule", ScheduleExpression="rate(1 hour)", State="DISABLED")
    results = collector._collect_eventbridge_rules()
    assert len(results) == 1
    assert "2 rule(s)" in results[0]["description"]
    assert "1 enabled" in results[0]["description"]


@moto.mock_aws
def test_eventbridge_no_rules(collector):
    results = collector._collect_eventbridge_rules()
    assert len(results) == 1
    assert "no rules" in results[0]["description"]


# --- SNS ---

@moto.mock_aws
def test_sns_topic_encrypted(collector):
    kms = boto3.client("kms", region_name="us-east-1")
    key = kms.create_key()
    key_id = key["KeyMetadata"]["KeyId"]
    sns = boto3.client("sns", region_name="us-east-1")
    topic = sns.create_topic(
        Name="alerts",
        Attributes={"KmsMasterKeyId": key_id},
    )
    results = collector._collect_sns_topic_encryption()
    assert len(results) == 1
    assert "encrypted" in results[0]["description"]


@moto.mock_aws
def test_sns_topic_not_encrypted(collector):
    sns = boto3.client("sns", region_name="us-east-1")
    sns.create_topic(Name="unencrypted-topic")
    results = collector._collect_sns_topic_encryption()
    assert len(results) == 1
    assert "NOT encrypted" in results[0]["description"]


# --- CodePipeline ---

@moto.mock_aws
def test_codepipeline_exists(collector):
    iam = boto3.client("iam", region_name="us-east-1")
    role = iam.create_role(
        RoleName="pipeline-role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
    )
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="artifact-store")
    cp = boto3.client("codepipeline", region_name="us-east-1")
    cp.create_pipeline(pipeline={
        "name": "deploy-prod",
        "roleArn": role["Role"]["Arn"],
        "artifactStore": {"type": "S3", "location": "artifact-store"},
        "stages": [
            {
                "name": "Source",
                "actions": [{
                    "name": "Source",
                    "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                    "configuration": {"S3Bucket": "artifact-store", "S3ObjectKey": "source.zip"},
                }],
            },
            {
                "name": "Deploy",
                "actions": [{
                    "name": "Deploy",
                    "actionTypeId": {"category": "Deploy", "owner": "AWS", "provider": "S3", "version": "1"},
                    "inputArtifacts": [{"name": "SourceOutput"}],
                    "configuration": {"BucketName": "artifact-store", "Extract": "true"},
                }],
            },
        ],
    })
    results = collector._collect_codepipeline()
    assert len(results) == 1
    assert "deploy-prod" in results[0]["description"]


@moto.mock_aws
def test_codepipeline_none(collector):
    results = collector._collect_codepipeline()
    assert len(results) == 1
    assert "no pipelines" in results[0]["description"]


# --- CodeBuild ---

@moto.mock_aws
def test_codebuild_project(collector):
    iam = boto3.client("iam", region_name="us-east-1")
    role = iam.create_role(
        RoleName="build-role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }),
    )
    cb = boto3.client("codebuild", region_name="us-east-1")
    cb.create_project(
        name="build-app",
        source={"type": "GITHUB", "location": "https://github.com/example/repo.git"},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "computeType": "BUILD_GENERAL1_SMALL",
            "image": "aws/codebuild/standard:7.0",
        },
        serviceRole=role["Role"]["Arn"],
    )
    results = collector._collect_codebuild()
    assert len(results) == 1
    assert "build-app" in results[0]["description"]


@moto.mock_aws
def test_codebuild_none(collector):
    results = collector._collect_codebuild()
    assert len(results) == 1
    assert "no projects" in results[0]["description"]


# --- Full Collection ---

@moto.mock_aws
def test_full_collect_returns_evidence(collector):
    """Full collect run against empty AWS — should return summary items, no crashes."""
    results = collector.collect()
    assert isinstance(results, list)
    for item in results:
        assert "test_name" in item
        assert "description" in item
        assert item["evidence_type"] == "automated"


@moto.mock_aws
def test_collect_skips_without_credentials(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    collector = AWSCollector(region="us-east-1")
    results = collector.collect()
    assert results == []
