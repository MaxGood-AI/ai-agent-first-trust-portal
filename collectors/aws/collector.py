"""AWS v2 collector — dispatches to per-service check modules.

This is a thin dispatcher. All SOC 2 evidence-producing logic lives in the
per-service modules (iam_checks, s3_checks, rds_checks, cloudtrail_checks).
Add a new module and include its functions in ``CHECK_FUNCTIONS`` to extend
coverage.
"""

import logging

from collectors.aws import cloudtrail_checks, iam_checks, rds_checks, s3_checks
from collectors.base import BaseCollector, CheckResult

logger = logging.getLogger(__name__)


# The complete IAM action list that this collector exercises. The
# PermissionProber uses these to tell the admin exactly which policy
# statements the collector role must grant.
AWS_REQUIRED_PERMISSIONS = [
    "sts:GetCallerIdentity",
    # IAM
    "iam:ListUsers",
    "iam:ListMFADevices",
    "iam:ListAccessKeys",
    "iam:GetAccountPasswordPolicy",
    # S3
    "s3:ListAllMyBuckets",
    "s3:GetBucketEncryption",
    "s3:GetBucketVersioning",
    "s3:GetBucketPublicAccessBlock",
    # RDS
    "rds:DescribeDBInstances",
    # CloudTrail
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetTrailStatus",
]


CHECK_FUNCTIONS = [
    iam_checks.check_iam_mfa,
    iam_checks.check_password_policy,
    iam_checks.check_access_key_age,
    s3_checks.check_s3_encryption,
    s3_checks.check_s3_versioning,
    s3_checks.check_s3_public_access_block,
    rds_checks.check_rds_encryption,
    rds_checks.check_rds_backups,
    cloudtrail_checks.check_cloudtrail_enabled,
]


class AWSCollector(BaseCollector):
    """Dispatches evidence collection across AWS services."""

    name = "aws"
    required_permissions = AWS_REQUIRED_PERMISSIONS

    def run(self) -> list[CheckResult]:
        resolved = self.resolved
        session = resolved.boto_session
        if session is None:
            return [
                CheckResult(
                    check_name="aws_run",
                    status="error",
                    message="No boto3 session available for AWS collector",
                )
            ]

        results: list[CheckResult] = []
        for fn in CHECK_FUNCTIONS:
            try:
                results.extend(fn(session))
            except Exception as exc:  # noqa: BLE001
                logger.exception("Check function %s raised", fn.__name__)
                results.append(
                    CheckResult(
                        check_name=fn.__name__,
                        status="error",
                        message=str(exc),
                    )
                )
        return results
