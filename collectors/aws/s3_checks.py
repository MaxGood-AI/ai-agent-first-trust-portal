"""AWS S3 permission checks for the v2 collector."""

import logging
from typing import Any

from collectors.base import CheckResult

logger = logging.getLogger(__name__)


def check_s3_encryption(session: Any) -> list[CheckResult]:
    """Verify every S3 bucket has default server-side encryption configured."""
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        results: list[CheckResult] = []
        for bucket in buckets:
            name = bucket["Name"]
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
                algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
                results.append(
                    CheckResult(
                        check_name=f"s3_encryption:{name}",
                        status="pass",
                        target_test_name="S3 encryption at rest",
                        message=f"Bucket {name}: encrypted ({algo})",
                        detail={"bucket": name, "algorithm": algo},
                        evidence_description=f"S3 bucket {name} uses {algo} encryption",
                    )
                )
            except Exception as exc:  # botocore.exceptions.ClientError etc.
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    results.append(
                        CheckResult(
                            check_name=f"s3_encryption:{name}",
                            status="fail",
                            target_test_name="S3 encryption at rest",
                            message=f"Bucket {name}: NO default encryption",
                            detail={"bucket": name},
                            evidence_description=(
                                f"S3 bucket {name} has no default encryption configuration"
                            ),
                        )
                    )
                else:
                    results.append(
                        CheckResult(
                            check_name=f"s3_encryption:{name}",
                            status="error",
                            target_test_name="S3 encryption at rest",
                            message=f"Error on {name}: {exc}",
                        )
                    )
        if not results:
            results.append(
                CheckResult(
                    check_name="s3_encryption",
                    status="pass",
                    target_test_name="S3 encryption at rest",
                    message="No S3 buckets in account",
                    evidence_description="No S3 buckets present",
                )
            )
        return results
    except Exception as exc:  # noqa: BLE001
        logger.exception("s3_encryption check failed")
        return [
            CheckResult(
                check_name="s3_encryption",
                status="error",
                target_test_name="S3 encryption at rest",
                message=str(exc),
            )
        ]


def check_s3_versioning(session: Any) -> list[CheckResult]:
    """Verify S3 bucket versioning is enabled."""
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        results: list[CheckResult] = []
        for bucket in buckets:
            name = bucket["Name"]
            try:
                v = s3.get_bucket_versioning(Bucket=name)
                status = v.get("Status", "Disabled") or "Disabled"
                passed = status == "Enabled"
                results.append(
                    CheckResult(
                        check_name=f"s3_versioning:{name}",
                        status="pass" if passed else "fail",
                        target_test_name="S3 versioning",
                        message=f"Bucket {name}: versioning {status}",
                        detail={"bucket": name, "versioning": status},
                        evidence_description=f"S3 bucket {name} versioning: {status}",
                    )
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    CheckResult(
                        check_name=f"s3_versioning:{name}",
                        status="error",
                        target_test_name="S3 versioning",
                        message=f"Error on {name}: {exc}",
                    )
                )
        if not results:
            results.append(
                CheckResult(
                    check_name="s3_versioning",
                    status="pass",
                    target_test_name="S3 versioning",
                    message="No S3 buckets in account",
                )
            )
        return results
    except Exception as exc:  # noqa: BLE001
        logger.exception("s3_versioning check failed")
        return [
            CheckResult(
                check_name="s3_versioning",
                status="error",
                target_test_name="S3 versioning",
                message=str(exc),
            )
        ]


def check_s3_public_access_block(session: Any) -> list[CheckResult]:
    """Verify every bucket has a fully restrictive Public Access Block."""
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        results: list[CheckResult] = []
        for bucket in buckets:
            name = bucket["Name"]
            try:
                pab = s3.get_public_access_block(Bucket=name).get(
                    "PublicAccessBlockConfiguration", {}
                )
                all_blocked = all(
                    [
                        pab.get("BlockPublicAcls", False),
                        pab.get("IgnorePublicAcls", False),
                        pab.get("BlockPublicPolicy", False),
                        pab.get("RestrictPublicBuckets", False),
                    ]
                )
                results.append(
                    CheckResult(
                        check_name=f"s3_public_access_block:{name}",
                        status="pass" if all_blocked else "fail",
                        target_test_name="S3 public access controls",
                        message=(
                            f"Bucket {name}: "
                            f"{'all public access blocked' if all_blocked else 'partial'}"
                        ),
                        detail={"bucket": name, "public_access_block": pab},
                        evidence_description=(
                            f"S3 bucket {name} public access block: "
                            f"{'fully blocked' if all_blocked else 'partial'}"
                        ),
                    )
                )
            except Exception as exc:  # noqa: BLE001
                code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if code == "NoSuchPublicAccessBlockConfiguration":
                    results.append(
                        CheckResult(
                            check_name=f"s3_public_access_block:{name}",
                            status="fail",
                            target_test_name="S3 public access controls",
                            message=f"Bucket {name}: no Public Access Block configured",
                            detail={"bucket": name},
                            evidence_description=(
                                f"S3 bucket {name} has no Public Access Block"
                            ),
                        )
                    )
                else:
                    results.append(
                        CheckResult(
                            check_name=f"s3_public_access_block:{name}",
                            status="error",
                            target_test_name="S3 public access controls",
                            message=f"Error on {name}: {exc}",
                        )
                    )
        if not results:
            results.append(
                CheckResult(
                    check_name="s3_public_access_block",
                    status="pass",
                    target_test_name="S3 public access controls",
                    message="No S3 buckets in account",
                )
            )
        return results
    except Exception as exc:  # noqa: BLE001
        logger.exception("s3_public_access_block check failed")
        return [
            CheckResult(
                check_name="s3_public_access_block",
                status="error",
                target_test_name="S3 public access controls",
                message=str(exc),
            )
        ]
