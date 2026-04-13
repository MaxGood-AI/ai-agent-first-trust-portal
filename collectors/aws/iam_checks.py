"""AWS IAM permission checks for the v2 collector.

Each function takes a boto3 session and returns a list of CheckResult.
Functions must not raise; any exception is captured as ``status="error"``.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from collectors.base import CheckResult

logger = logging.getLogger(__name__)


def check_iam_mfa(session: Any) -> list[CheckResult]:
    """Verify MFA is enabled for every IAM user."""
    try:
        iam = session.client("iam")
        users = iam.list_users().get("Users", [])
        results: list[CheckResult] = []
        for user in users:
            username = user["UserName"]
            devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            enabled = len(devices) > 0
            results.append(
                CheckResult(
                    check_name=f"iam_mfa:{username}",
                    status="pass" if enabled else "fail",
                    target_test_name="Multi-factor authentication enabled for all users",
                    message=(
                        f"IAM user {username}: MFA {'enabled' if enabled else 'NOT enabled'}"
                    ),
                    detail={"user": username, "mfa_device_count": len(devices)},
                    evidence_description=(
                        f"IAM user {username} MFA check: "
                        f"{len(devices)} device(s) registered"
                    ),
                )
            )
        if not results:
            # No users — record a neutral pass so auditors see the check ran.
            results.append(
                CheckResult(
                    check_name="iam_mfa",
                    status="pass",
                    target_test_name="Multi-factor authentication enabled for all users",
                    message="No IAM users present",
                    detail={"user_count": 0},
                    evidence_description="No IAM users in account; MFA check vacuously passes",
                )
            )
        return results
    except Exception as exc:  # noqa: BLE001
        logger.exception("iam_mfa check failed")
        return [
            CheckResult(
                check_name="iam_mfa",
                status="error",
                target_test_name="Multi-factor authentication enabled for all users",
                message=str(exc),
            )
        ]


def check_password_policy(session: Any) -> list[CheckResult]:
    """Verify an account password policy exists and meets minimum requirements."""
    try:
        iam = session.client("iam")
        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
        except iam.exceptions.NoSuchEntityException:
            return [
                CheckResult(
                    check_name="iam_password_policy",
                    status="fail",
                    target_test_name="Password policy configured",
                    message="No account password policy configured",
                    evidence_description="AWS account has no password policy set",
                )
            ]
        min_length = policy.get("MinimumPasswordLength", 0)
        requires_symbols = policy.get("RequireSymbols", False)
        requires_numbers = policy.get("RequireNumbers", False)
        requires_upper = policy.get("RequireUppercaseCharacters", False)
        requires_lower = policy.get("RequireLowercaseCharacters", False)
        passed = (
            min_length >= 12
            and requires_symbols
            and requires_numbers
            and requires_upper
            and requires_lower
        )
        return [
            CheckResult(
                check_name="iam_password_policy",
                status="pass" if passed else "fail",
                target_test_name="Password policy configured",
                message=(
                    f"Password policy: min_length={min_length}, "
                    f"symbols={requires_symbols}, numbers={requires_numbers}, "
                    f"upper={requires_upper}, lower={requires_lower}"
                ),
                detail=policy,
                evidence_description="Account password policy configuration",
            )
        ]
    except Exception as exc:  # noqa: BLE001
        logger.exception("iam_password_policy check failed")
        return [
            CheckResult(
                check_name="iam_password_policy",
                status="error",
                target_test_name="Password policy configured",
                message=str(exc),
            )
        ]


def check_access_key_age(session: Any, max_age_days: int = 90) -> list[CheckResult]:
    """Flag IAM access keys older than ``max_age_days``."""
    try:
        iam = session.client("iam")
        users = iam.list_users().get("Users", [])
        now = datetime.now(timezone.utc)
        results: list[CheckResult] = []
        for user in users:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                create_date = key["CreateDate"]
                if create_date.tzinfo is None:
                    create_date = create_date.replace(tzinfo=timezone.utc)
                age_days = (now - create_date).days
                status_active = key.get("Status") == "Active"
                passed = not (status_active and age_days > max_age_days)
                results.append(
                    CheckResult(
                        check_name=f"iam_access_key_age:{key['AccessKeyId']}",
                        status="pass" if passed else "fail",
                        target_test_name="Access key rotation",
                        message=(
                            f"Key {key['AccessKeyId']} for {username}: "
                            f"age {age_days}d, status {key.get('Status')}"
                        ),
                        detail={
                            "user": username,
                            "key_id": key["AccessKeyId"],
                            "age_days": age_days,
                            "status": key.get("Status"),
                        },
                        evidence_description=(
                            f"IAM access key {key['AccessKeyId']} for {username}: "
                            f"{age_days} days old"
                        ),
                    )
                )
        if not results:
            results.append(
                CheckResult(
                    check_name="iam_access_key_age",
                    status="pass",
                    target_test_name="Access key rotation",
                    message="No IAM access keys in account",
                    evidence_description="No IAM access keys present",
                )
            )
        return results
    except Exception as exc:  # noqa: BLE001
        logger.exception("iam_access_key_age check failed")
        return [
            CheckResult(
                check_name="iam_access_key_age",
                status="error",
                target_test_name="Access key rotation",
                message=str(exc),
            )
        ]
