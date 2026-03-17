"""AWS infrastructure evidence collector.

Gathers compliance evidence from AWS services: IAM, S3, RDS, EC2, Lambda,
CloudTrail, CloudWatch, KMS, GuardDuty, Config, EventBridge, and SNS.
Requires boto3 and valid AWS credentials. If credentials are not configured,
the collector logs a warning and returns no evidence.

Each collection method is isolated — if one service fails (e.g., due to
missing IAM permissions), the others continue collecting.
"""

import logging
import os
from datetime import datetime, timezone

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    logger.info("boto3 not installed — AWS evidence collection disabled")


def _evidence(test_name, description):
    return {
        "test_name": test_name,
        "evidence_type": "automated",
        "description": description,
        "url": None,
        "file_path": None,
    }


class AWSCollector(BaseCollector):
    """Collects evidence from AWS infrastructure."""

    def __init__(self, region=None):
        super().__init__("aws")
        self.region = region or os.environ.get("AWS_REGION", "us-east-1")

    def _client(self, service):
        return boto3.client(service, region_name=self.region)

    def collect(self):
        if not BOTO3_AVAILABLE:
            logger.warning("boto3 not available — skipping AWS evidence collection")
            return []

        if not os.environ.get("AWS_ACCESS_KEY_ID"):
            logger.warning("AWS_ACCESS_KEY_ID not set — skipping AWS evidence collection")
            return []

        evidence = []
        collectors = [
            self._collect_iam_mfa,
            self._collect_iam_password_policy,
            self._collect_iam_access_key_age,
            self._collect_rds_encryption,
            self._collect_rds_backups,
            self._collect_security_groups,
            self._collect_s3_public_access,
            self._collect_s3_versioning,
            self._collect_s3_encryption,
            self._collect_cloudtrail,
            self._collect_cloudwatch_log_retention,
            self._collect_cloudwatch_alarms,
            self._collect_lambda_functions,
            self._collect_kms_key_rotation,
            self._collect_guardduty,
            self._collect_config_recorder,
            self._collect_eventbridge_rules,
            self._collect_sns_topic_encryption,
            self._collect_codepipeline,
            self._collect_codebuild,
        ]
        for collector_fn in collectors:
            try:
                evidence.extend(collector_fn())
            except Exception:
                logger.exception("Failed in %s", collector_fn.__name__)
        return evidence

    # --- IAM ---

    def _collect_iam_mfa(self):
        """Check MFA enforcement for IAM users."""
        results = []
        iam = self._client("iam")
        users = iam.list_users()["Users"]
        for user in users:
            mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
            status = "enabled" if mfa_devices else "NOT enabled"
            results.append(_evidence(
                "Multi-factor authentication enabled for all users",
                f"IAM user {user['UserName']}: MFA {status}",
            ))
        return results

    def _collect_iam_password_policy(self):
        """Check account password policy settings."""
        iam = self._client("iam")
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return [_evidence(
                    "Password policy configured",
                    "No account password policy is configured",
                )]
            raise
        parts = [
            f"MinLength={policy.get('MinimumPasswordLength', 'unset')}",
            f"RequireUpper={policy.get('RequireUppercaseCharacters', False)}",
            f"RequireLower={policy.get('RequireLowercaseCharacters', False)}",
            f"RequireNumbers={policy.get('RequireNumbers', False)}",
            f"RequireSymbols={policy.get('RequireSymbols', False)}",
            f"MaxAge={policy.get('MaxPasswordAge', 'unset')}days",
        ]
        return [_evidence(
            "Password policy configured",
            f"Account password policy: {', '.join(parts)}",
        )]

    def _collect_iam_access_key_age(self):
        """Flag IAM access keys older than 90 days."""
        results = []
        iam = self._client("iam")
        now = datetime.now(timezone.utc)
        users = iam.list_users()["Users"]
        for user in users:
            keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
            for key in keys:
                age_days = (now - key["CreateDate"]).days
                status = key["Status"]
                flag = " [STALE]" if age_days > 90 and status == "Active" else ""
                results.append(_evidence(
                    "Access key rotation",
                    f"IAM user {user['UserName']} key {key['AccessKeyId']}: "
                    f"{status}, age {age_days} days{flag}",
                ))
        return results

    # --- RDS ---

    def _collect_rds_encryption(self):
        """Check encryption-at-rest for RDS instances."""
        results = []
        rds = self._client("rds")
        instances = rds.describe_db_instances()["DBInstances"]
        for inst in instances:
            encrypted = inst.get("StorageEncrypted", False)
            results.append(_evidence(
                "Data encryption at rest",
                f"RDS {inst['DBInstanceIdentifier']}: "
                f"encryption {'enabled' if encrypted else 'NOT enabled'}",
            ))
        return results

    def _collect_rds_backups(self):
        """Check backup configuration for RDS instances."""
        results = []
        rds = self._client("rds")
        instances = rds.describe_db_instances()["DBInstances"]
        for inst in instances:
            retention = inst.get("BackupRetentionPeriod", 0)
            results.append(_evidence(
                "Backup enabled",
                f"RDS {inst['DBInstanceIdentifier']}: backup retention {retention} days",
            ))
        return results

    # --- EC2 ---

    def _collect_security_groups(self):
        """Check for overly permissive security groups (0.0.0.0/0 ingress)."""
        results = []
        ec2 = self._client("ec2")
        groups = ec2.describe_security_groups()["SecurityGroups"]
        for sg in groups:
            open_ingress = [
                rule for rule in sg.get("IpPermissions", [])
                if any(ip.get("CidrIp") == "0.0.0.0/0" for ip in rule.get("IpRanges", []))
            ]
            if open_ingress:
                results.append(_evidence(
                    "Network security review",
                    f"Security group {sg['GroupId']} ({sg.get('GroupName', '')}): "
                    f"{len(open_ingress)} rule(s) open to 0.0.0.0/0",
                ))
        return results

    # --- S3 ---

    def _collect_s3_public_access(self):
        """Check S3 bucket public access block settings."""
        results = []
        s3 = self._client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        s3control = self._client("s3control")
        for bucket in buckets:
            name = bucket["Name"]
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                all_blocked = all([
                    pab.get("BlockPublicAcls", False),
                    pab.get("IgnorePublicAcls", False),
                    pab.get("BlockPublicPolicy", False),
                    pab.get("RestrictPublicBuckets", False),
                ])
                status = "all public access blocked" if all_blocked else f"partial: {pab}"
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    status = "NO public access block configured"
                else:
                    status = f"error checking: {e.response['Error']['Code']}"
            results.append(_evidence(
                "S3 public access controls",
                f"Bucket {name}: {status}",
            ))
        return results

    def _collect_s3_versioning(self):
        """Check S3 bucket versioning status."""
        results = []
        s3 = self._client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                v = s3.get_bucket_versioning(Bucket=name)
                status = v.get("Status", "Disabled")
            except ClientError:
                status = "error checking"
            results.append(_evidence(
                "S3 versioning",
                f"Bucket {name}: versioning {status}",
            ))
        return results

    def _collect_s3_encryption(self):
        """Check S3 bucket default encryption."""
        results = []
        s3 = self._client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
                algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                status = f"encrypted ({algo})"
            except ClientError as e:
                if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    status = "NO default encryption"
                else:
                    status = f"error checking: {e.response['Error']['Code']}"
            results.append(_evidence(
                "S3 encryption at rest",
                f"Bucket {name}: {status}",
            ))
        return results

    # --- CloudTrail ---

    def _collect_cloudtrail(self):
        """Check CloudTrail status: enabled, multi-region, log validation."""
        results = []
        ct = self._client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        if not trails:
            return [_evidence("CloudTrail enabled", "No CloudTrail trails configured")]
        for trail in trails:
            name = trail["Name"]
            multi = "yes" if trail.get("IsMultiRegionTrail") else "no"
            validation = "yes" if trail.get("LogFileValidationEnabled") else "no"
            results.append(_evidence(
                "CloudTrail enabled",
                f"Trail {name}: multi-region={multi}, log-validation={validation}",
            ))
            try:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                logging_on = "yes" if status.get("IsLogging") else "no"
                results.append(_evidence(
                    "CloudTrail logging active",
                    f"Trail {name}: currently logging={logging_on}",
                ))
            except ClientError:
                logger.exception("Failed to get trail status for %s", name)
        return results

    # --- CloudWatch ---

    def _collect_cloudwatch_log_retention(self):
        """Check CloudWatch log group retention policies."""
        results = []
        logs = self._client("logs")
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page["logGroups"]:
                name = lg["logGroupName"]
                retention = lg.get("retentionInDays")
                status = f"{retention} days" if retention else "never expires"
                results.append(_evidence(
                    "Log retention policy",
                    f"Log group {name}: retention {status}",
                ))
        return results

    def _collect_cloudwatch_alarms(self):
        """Inventory CloudWatch alarms and their states."""
        results = []
        cw = self._client("cloudwatch")
        paginator = cw.get_paginator("describe_alarms")
        alarm_count = 0
        alarm_states = {"OK": 0, "ALARM": 0, "INSUFFICIENT_DATA": 0}
        for page in paginator.paginate():
            for alarm in page.get("MetricAlarms", []):
                alarm_count += 1
                state = alarm.get("StateValue", "UNKNOWN")
                alarm_states[state] = alarm_states.get(state, 0) + 1
            for alarm in page.get("CompositeAlarms", []):
                alarm_count += 1
                state = alarm.get("StateValue", "UNKNOWN")
                alarm_states[state] = alarm_states.get(state, 0) + 1
        state_summary = ", ".join(f"{k}={v}" for k, v in sorted(alarm_states.items()) if v)
        results.append(_evidence(
            "Monitoring and alerting",
            f"{alarm_count} CloudWatch alarm(s) configured: {state_summary}" if alarm_count
            else "No CloudWatch alarms configured",
        ))
        return results

    # --- Lambda ---

    def _collect_lambda_functions(self):
        """Check Lambda function runtimes, VPC config, and env var encryption."""
        results = []
        lam = self._client("lambda")
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page["Functions"]:
                name = fn["FunctionName"]
                runtime = fn.get("Runtime", "container/custom")
                vpc = "yes" if fn.get("VpcConfig", {}).get("VpcId") else "no"
                kms = "yes" if fn.get("KMSKeyArn") else "default"
                results.append(_evidence(
                    "Lambda function security",
                    f"Lambda {name}: runtime={runtime}, VPC={vpc}, "
                    f"env-encryption={kms}",
                ))
        return results

    # --- KMS ---

    def _collect_kms_key_rotation(self):
        """Check KMS key rotation status for customer-managed keys."""
        results = []
        kms = self._client("kms")
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key_entry in page["Keys"]:
                key_id = key_entry["KeyId"]
                try:
                    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    if meta.get("KeyManager") != "CUSTOMER":
                        continue
                    desc = meta.get("Description", "")
                    try:
                        rotation = kms.get_key_rotation_status(KeyId=key_id)
                        rotating = "yes" if rotation.get("KeyRotationEnabled") else "no"
                    except ClientError:
                        rotating = "unable to check"
                    label = f"{key_id[:8]}..."
                    if desc:
                        label = f"{desc} ({key_id[:8]}...)"
                    results.append(_evidence(
                        "Encryption key rotation",
                        f"KMS key {label}: auto-rotation={rotating}",
                    ))
                except ClientError:
                    logger.exception("Failed to describe KMS key %s", key_id)
        return results

    # --- GuardDuty ---

    def _collect_guardduty(self):
        """Check if GuardDuty threat detection is enabled."""
        gd = self._client("guardduty")
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            return [_evidence("Threat detection", "GuardDuty: no detectors enabled")]
        results = []
        for det_id in detectors:
            detail = gd.get_detector(DetectorId=det_id)
            status = detail.get("Status", "UNKNOWN")
            results.append(_evidence(
                "Threat detection",
                f"GuardDuty detector {det_id[:8]}...: status={status}",
            ))
        return results

    # --- AWS Config ---

    def _collect_config_recorder(self):
        """Check if AWS Config recorder is active."""
        config = self._client("config")
        recorders = config.describe_configuration_recorder_status() \
            .get("ConfigurationRecordersStatus", [])
        if not recorders:
            return [_evidence(
                "Configuration monitoring",
                "AWS Config: no configuration recorders found",
            )]
        results = []
        for rec in recorders:
            name = rec.get("name", "default")
            recording = "yes" if rec.get("recording") else "no"
            results.append(_evidence(
                "Configuration monitoring",
                f"AWS Config recorder {name}: recording={recording}",
            ))
        return results

    # --- EventBridge ---

    def _collect_eventbridge_rules(self):
        """Inventory EventBridge rules."""
        eb = self._client("events")
        rules = eb.list_rules().get("Rules", [])
        if not rules:
            return [_evidence(
                "Event-driven automation",
                "EventBridge: no rules configured",
            )]
        enabled = sum(1 for r in rules if r.get("State") == "ENABLED")
        disabled = len(rules) - enabled
        return [_evidence(
            "Event-driven automation",
            f"EventBridge: {len(rules)} rule(s) ({enabled} enabled, {disabled} disabled)",
        )]

    # --- SNS ---

    def _collect_sns_topic_encryption(self):
        """Check SNS topic encryption settings."""
        results = []
        sns = self._client("sns")
        topics = sns.list_topics().get("Topics", [])
        for topic in topics:
            arn = topic["TopicArn"]
            name = arn.split(":")[-1]
            attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
            kms_key = attrs.get("KmsMasterKeyId")
            status = f"encrypted (key={kms_key})" if kms_key else "NOT encrypted"
            results.append(_evidence(
                "SNS topic encryption",
                f"SNS topic {name}: {status}",
            ))
        return results

    # --- CodePipeline ---

    def _collect_codepipeline(self):
        """Inventory CodePipeline pipelines and their last execution status."""
        results = []
        cp = self._client("codepipeline")
        pipelines = cp.list_pipelines().get("pipelines", [])
        if not pipelines:
            return [_evidence("CI/CD pipelines", "CodePipeline: no pipelines configured")]
        for p in pipelines:
            name = p["name"]
            try:
                state = cp.get_pipeline_state(name=name)
                stages = state.get("stageStates", [])
                failed_stages = [
                    s["stageName"] for s in stages
                    if s.get("latestExecution", {}).get("status") == "Failed"
                ]
                last_status = "all stages passed"
                if failed_stages:
                    last_status = f"FAILED stages: {', '.join(failed_stages)}"
                results.append(_evidence(
                    "CI/CD pipelines",
                    f"Pipeline {name}: {len(stages)} stage(s), {last_status}",
                ))
            except Exception:
                results.append(_evidence(
                    "CI/CD pipelines",
                    f"Pipeline {name}: present (state unavailable)",
                ))
        return results

    # --- CodeBuild ---

    def _collect_codebuild(self):
        """Inventory CodeBuild projects and their encryption/logging config."""
        results = []
        cb = self._client("codebuild")
        project_names = cb.list_projects().get("projects", [])
        if not project_names:
            return [_evidence("CI/CD build projects", "CodeBuild: no projects configured")]
        projects = cb.batch_get_projects(names=project_names).get("projects", [])
        for proj in projects:
            name = proj["name"]
            encrypted = "yes" if proj.get("encryptionKey") else "default"
            logs = proj.get("logsConfig", {})
            cw_logs = "yes" if logs.get("cloudWatchLogs", {}).get("status") == "ENABLED" else "no"
            s3_logs = "yes" if logs.get("s3Logs", {}).get("status") == "ENABLED" else "no"
            results.append(_evidence(
                "CI/CD build projects",
                f"CodeBuild {name}: encryption={encrypted}, "
                f"CloudWatch-logs={cw_logs}, S3-logs={s3_logs}",
            ))
        return results
