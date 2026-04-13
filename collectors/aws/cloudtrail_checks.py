"""AWS CloudTrail permission checks for the v2 collector."""

import logging
from typing import Any

from collectors.base import CheckResult

logger = logging.getLogger(__name__)


def check_cloudtrail_enabled(session: Any) -> list[CheckResult]:
    """Verify at least one multi-region trail is configured and logging."""
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        if not trails:
            return [
                CheckResult(
                    check_name="cloudtrail_enabled",
                    status="fail",
                    target_test_name="CloudTrail enabled",
                    message="No CloudTrail trails configured",
                    evidence_description="No CloudTrail trails in account",
                )
            ]
        results: list[CheckResult] = []
        for trail in trails:
            name = trail.get("Name")
            multi = bool(trail.get("IsMultiRegionTrail"))
            validation = bool(trail.get("LogFileValidationEnabled"))
            trail_arn = trail.get("TrailARN") or name
            logging_on = False
            try:
                status = ct.get_trail_status(Name=trail_arn)
                logging_on = bool(status.get("IsLogging"))
            except Exception:  # noqa: BLE001
                logger.exception("Failed to get trail status for %s", name)
            passed = multi and logging_on
            results.append(
                CheckResult(
                    check_name=f"cloudtrail_enabled:{name}",
                    status="pass" if passed else "fail",
                    target_test_name="CloudTrail enabled",
                    message=(
                        f"Trail {name}: multi_region={multi}, "
                        f"log_validation={validation}, logging={logging_on}"
                    ),
                    detail={
                        "trail": name,
                        "multi_region": multi,
                        "log_file_validation": validation,
                        "is_logging": logging_on,
                    },
                    evidence_description=(
                        f"CloudTrail trail {name}: multi_region={multi}, logging={logging_on}"
                    ),
                )
            )
        return results
    except Exception as exc:  # noqa: BLE001
        logger.exception("cloudtrail_enabled check failed")
        return [
            CheckResult(
                check_name="cloudtrail_enabled",
                status="error",
                target_test_name="CloudTrail enabled",
                message=str(exc),
            )
        ]
