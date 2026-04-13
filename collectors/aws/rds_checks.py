"""AWS RDS permission checks for the v2 collector."""

import logging
from typing import Any

from collectors.base import CheckResult

logger = logging.getLogger(__name__)


def check_rds_encryption(session: Any) -> list[CheckResult]:
    """Verify every RDS instance has storage encryption enabled."""
    try:
        rds = session.client("rds")
        instances = rds.describe_db_instances().get("DBInstances", [])
        results: list[CheckResult] = []
        for inst in instances:
            instance_id = inst["DBInstanceIdentifier"]
            encrypted = bool(inst.get("StorageEncrypted", False))
            results.append(
                CheckResult(
                    check_name=f"rds_encryption:{instance_id}",
                    status="pass" if encrypted else "fail",
                    target_test_name="Data encryption at rest",
                    message=(
                        f"RDS {instance_id}: "
                        f"encryption {'enabled' if encrypted else 'NOT enabled'}"
                    ),
                    detail={"db_instance": instance_id, "encrypted": encrypted},
                    evidence_description=(
                        f"RDS instance {instance_id} storage encryption: "
                        f"{'enabled' if encrypted else 'disabled'}"
                    ),
                )
            )
        if not results:
            results.append(
                CheckResult(
                    check_name="rds_encryption",
                    status="pass",
                    target_test_name="Data encryption at rest",
                    message="No RDS instances in account",
                    evidence_description="No RDS instances present",
                )
            )
        return results
    except Exception as exc:  # noqa: BLE001
        logger.exception("rds_encryption check failed")
        return [
            CheckResult(
                check_name="rds_encryption",
                status="error",
                target_test_name="Data encryption at rest",
                message=str(exc),
            )
        ]


def check_rds_backups(session: Any, min_retention_days: int = 7) -> list[CheckResult]:
    """Verify RDS automated backup retention meets minimum."""
    try:
        rds = session.client("rds")
        instances = rds.describe_db_instances().get("DBInstances", [])
        results: list[CheckResult] = []
        for inst in instances:
            instance_id = inst["DBInstanceIdentifier"]
            retention = int(inst.get("BackupRetentionPeriod", 0))
            passed = retention >= min_retention_days
            results.append(
                CheckResult(
                    check_name=f"rds_backups:{instance_id}",
                    status="pass" if passed else "fail",
                    target_test_name="Backup enabled",
                    message=(
                        f"RDS {instance_id}: backup retention {retention} days "
                        f"(minimum {min_retention_days})"
                    ),
                    detail={
                        "db_instance": instance_id,
                        "retention_days": retention,
                        "minimum_days": min_retention_days,
                    },
                    evidence_description=(
                        f"RDS instance {instance_id} backup retention: {retention} days"
                    ),
                )
            )
        if not results:
            results.append(
                CheckResult(
                    check_name="rds_backups",
                    status="pass",
                    target_test_name="Backup enabled",
                    message="No RDS instances in account",
                )
            )
        return results
    except Exception as exc:  # noqa: BLE001
        logger.exception("rds_backups check failed")
        return [
            CheckResult(
                check_name="rds_backups",
                status="error",
                target_test_name="Backup enabled",
                message=str(exc),
            )
        ]
