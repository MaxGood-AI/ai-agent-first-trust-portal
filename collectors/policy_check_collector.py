"""Policy v2 collector — checks policy currency and approval status.

Reads policies directly from the portal database. No external credentials
required. Configuration: optional ``review_warning_days`` to flag policies
whose ``next_review_at`` is within that many days.
"""

import logging
from datetime import datetime, timedelta, timezone

from app.models import Policy
from collectors.base import BaseCollector, CheckResult

logger = logging.getLogger(__name__)


POLICY_REQUIRED_PERMISSIONS: list[str] = []


class PolicyCollector(BaseCollector):
    """Verifies all portal policies are approved, current, and have a
    valid next-review date."""

    name = "policy"
    required_permissions = POLICY_REQUIRED_PERMISSIONS
    credential_modes_supported = ["none", "task_role"]

    def run(self) -> list[CheckResult]:
        config_dict = self.config.config or {}
        review_warning_days = int(config_dict.get("review_warning_days", 30))

        results: list[CheckResult] = []
        now = datetime.now(timezone.utc)
        warn_threshold = now + timedelta(days=review_warning_days)

        try:
            policies = Policy.query.order_by(Policy.title).all()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to query policies")
            return [
                CheckResult(
                    check_name="policy_query",
                    status="error",
                    message=str(exc),
                )
            ]

        if not policies:
            return [
                CheckResult(
                    check_name="policy_inventory",
                    status="fail",
                    target_test_name="Policy Management",
                    message="No policies found in portal database",
                    evidence_description="Portal policy inventory is empty",
                )
            ]

        # Overall inventory check
        total = len(policies)
        approved = sum(1 for p in policies if (p.status or "").lower() == "approved")
        draft = sum(1 for p in policies if (p.status or "").lower() == "draft")
        retired = sum(1 for p in policies if (p.status or "").lower() == "retired")

        results.append(
            CheckResult(
                check_name="policy_inventory",
                status="pass" if approved > 0 else "fail",
                target_test_name="Policy Management",
                message=(
                    f"Portal has {total} policies: {approved} approved, "
                    f"{draft} draft, {retired} retired"
                ),
                detail={
                    "total": total,
                    "approved": approved,
                    "draft": draft,
                    "retired": retired,
                },
                evidence_description=(
                    f"Portal policy inventory: {total} policies ({approved} approved)"
                ),
            )
        )

        # Per-policy approval and review-date checks
        for policy in policies:
            policy_label = policy.short_name or policy.title
            status_val = (policy.status or "").lower()

            if status_val == "retired":
                continue  # retired policies aren't expected to be current

            if status_val != "approved":
                results.append(
                    CheckResult(
                        check_name=f"policy_approved:{policy.id}",
                        status="fail",
                        target_test_name="Policy Management",
                        message=f"Policy '{policy_label}' has status '{status_val}'",
                        detail={"policy_id": policy.id, "status": status_val},
                        evidence_description=(
                            f"Policy {policy_label} status: {status_val}"
                        ),
                    )
                )
                continue  # no point checking review date of unapproved policy

            # Approved policy: check review date
            next_review = policy.next_review_at
            if next_review is None:
                results.append(
                    CheckResult(
                        check_name=f"policy_next_review:{policy.id}",
                        status="fail",
                        target_test_name="Policy Management",
                        message=f"Policy '{policy_label}' has no next review date",
                        detail={"policy_id": policy.id},
                        evidence_description=(
                            f"Policy {policy_label} missing next_review_at"
                        ),
                    )
                )
                continue

            if next_review.tzinfo is None:
                next_review_aware = next_review.replace(tzinfo=timezone.utc)
            else:
                next_review_aware = next_review

            if next_review_aware < now:
                results.append(
                    CheckResult(
                        check_name=f"policy_next_review:{policy.id}",
                        status="fail",
                        target_test_name="Policy Management",
                        message=(
                            f"Policy '{policy_label}' review overdue "
                            f"(was due {next_review_aware.date()})"
                        ),
                        detail={
                            "policy_id": policy.id,
                            "next_review_at": next_review_aware.isoformat(),
                            "overdue": True,
                        },
                        evidence_description=(
                            f"Policy {policy_label} overdue for review since "
                            f"{next_review_aware.date()}"
                        ),
                    )
                )
            elif next_review_aware < warn_threshold:
                results.append(
                    CheckResult(
                        check_name=f"policy_next_review:{policy.id}",
                        status="pass",
                        target_test_name="Policy Management",
                        message=(
                            f"Policy '{policy_label}' review due soon "
                            f"({next_review_aware.date()})"
                        ),
                        detail={
                            "policy_id": policy.id,
                            "next_review_at": next_review_aware.isoformat(),
                            "warn_only": True,
                        },
                        evidence_description=(
                            f"Policy {policy_label} review due {next_review_aware.date()}"
                        ),
                    )
                )
            else:
                results.append(
                    CheckResult(
                        check_name=f"policy_next_review:{policy.id}",
                        status="pass",
                        target_test_name="Policy Management",
                        message=(
                            f"Policy '{policy_label}' next review "
                            f"{next_review_aware.date()}"
                        ),
                        detail={
                            "policy_id": policy.id,
                            "next_review_at": next_review_aware.isoformat(),
                        },
                        evidence_description=(
                            f"Policy {policy_label} approved, next review "
                            f"{next_review_aware.date()}"
                        ),
                    )
                )

        return results
