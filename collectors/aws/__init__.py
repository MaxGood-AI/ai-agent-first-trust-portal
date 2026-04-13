"""AWS v2 collector package.

Exports ``AWSCollector`` which implements the ``collectors.base.BaseCollector``
interface using a boto3 session resolved from a ``CollectorConfig``.

Per-service checks live in sibling modules (iam_checks, s3_checks, rds_checks,
ec2_checks, cloudtrail_checks, kms_checks). Each module is a collection of
functions that accept a boto3 session and return ``list[CheckResult]``.
"""

from collectors.aws.collector import AWSCollector

__all__ = ["AWSCollector"]
