"""AWS CodeCommit checks for the git collector.

Each function takes a boto3 session and returns ``list[CheckResult]``.
Functions must not raise; any exception is captured as ``status="error"``.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from collectors.base import CheckResult

logger = logging.getLogger(__name__)


def check_repository_inventory(session: Any) -> list[CheckResult]:
    """Verify the account has at least one CodeCommit repository."""
    try:
        cc = session.client("codecommit")
        paginator = cc.get_paginator("list_repositories")
        repos: list[str] = []
        for page in paginator.paginate():
            for r in page.get("repositories", []):
                repos.append(r["repositoryName"])

        if not repos:
            return [
                CheckResult(
                    check_name="codecommit_inventory",
                    status="fail",
                    target_test_name="Change management process",
                    message="No CodeCommit repositories found",
                    evidence_description="No CodeCommit repositories in the account",
                )
            ]
        return [
            CheckResult(
                check_name="codecommit_inventory",
                status="pass",
                target_test_name="Change management process",
                message=f"{len(repos)} CodeCommit repositories found",
                detail={"count": len(repos), "names": repos[:50]},
                evidence_description=(
                    f"{len(repos)} CodeCommit repositories in account"
                ),
            )
        ]
    except Exception as exc:  # noqa: BLE001
        logger.exception("codecommit_inventory check failed")
        return [
            CheckResult(
                check_name="codecommit_inventory",
                status="error",
                target_test_name="Change management process",
                message=str(exc),
            )
        ]


def check_approval_rule_templates(session: Any) -> list[CheckResult]:
    """Verify at least one approval rule template exists.

    SOC 2 change management requires code changes to be reviewed before
    merging. CodeCommit enforces this through approval rule templates that
    can be associated with repositories. Having at least one template is
    the baseline signal that PR review is being enforced.
    """
    try:
        cc = session.client("codecommit")
        templates: list[str] = []
        paginator = cc.get_paginator("list_approval_rule_templates")
        for page in paginator.paginate():
            templates.extend(page.get("approvalRuleTemplateNames", []))

        if not templates:
            return [
                CheckResult(
                    check_name="codecommit_approval_rule_templates",
                    status="fail",
                    target_test_name="PR review requirements",
                    message="No approval rule templates defined",
                    evidence_description=(
                        "No CodeCommit approval rule templates exist; PR reviews "
                        "are not enforced by template"
                    ),
                )
            ]
        return [
            CheckResult(
                check_name="codecommit_approval_rule_templates",
                status="pass",
                target_test_name="PR review requirements",
                message=f"{len(templates)} approval rule templates defined",
                detail={"count": len(templates), "names": templates},
                evidence_description=(
                    f"{len(templates)} CodeCommit approval rule templates define "
                    "review requirements"
                ),
            )
        ]
    except Exception as exc:  # noqa: BLE001
        logger.exception("codecommit_approval_rule_templates check failed")
        return [
            CheckResult(
                check_name="codecommit_approval_rule_templates",
                status="error",
                target_test_name="PR review requirements",
                message=str(exc),
            )
        ]


def check_approval_rules_attached_to_repos(
    session: Any, repo_filter: list[str] | None = None
) -> list[CheckResult]:
    """For each repository, verify at least one approval rule template is
    associated. A repo without an associated rule has no enforced review
    policy even if templates exist globally.
    """
    try:
        cc = session.client("codecommit")
        repos: list[str] = []
        paginator = cc.get_paginator("list_repositories")
        for page in paginator.paginate():
            for r in page.get("repositories", []):
                name = r["repositoryName"]
                if repo_filter and name not in repo_filter:
                    continue
                repos.append(name)

        results: list[CheckResult] = []
        for repo_name in repos:
            try:
                response = cc.list_associated_approval_rule_templates_for_repository(
                    repositoryName=repo_name,
                )
                templates = response.get("approvalRuleTemplateNames", [])
                attached = len(templates) > 0
                results.append(
                    CheckResult(
                        check_name=f"codecommit_repo_approval:{repo_name}",
                        status="pass" if attached else "fail",
                        target_test_name="PR review requirements",
                        message=(
                            f"Repo {repo_name}: "
                            f"{len(templates)} approval rule template(s) attached"
                        ),
                        detail={
                            "repository": repo_name,
                            "approval_rule_templates": templates,
                        },
                        evidence_description=(
                            f"CodeCommit repo {repo_name} approval rule templates: "
                            f"{templates or 'none'}"
                        ),
                    )
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    CheckResult(
                        check_name=f"codecommit_repo_approval:{repo_name}",
                        status="error",
                        target_test_name="PR review requirements",
                        message=f"Error on {repo_name}: {exc}",
                    )
                )

        if not results:
            results.append(
                CheckResult(
                    check_name="codecommit_repo_approval",
                    status="pass",
                    target_test_name="PR review requirements",
                    message="No repositories to check",
                )
            )
        return results
    except Exception as exc:  # noqa: BLE001
        logger.exception("codecommit_repo_approval check failed")
        return [
            CheckResult(
                check_name="codecommit_repo_approval",
                status="error",
                target_test_name="PR review requirements",
                message=str(exc),
            )
        ]


def check_recent_merged_pull_requests(
    session: Any,
    repo_filter: list[str] | None = None,
    lookback_days: int = 30,
) -> list[CheckResult]:
    """For each repository, count recently-merged pull requests as positive
    evidence that change management is operating."""
    try:
        cc = session.client("codecommit")
        repos: list[str] = []
        paginator = cc.get_paginator("list_repositories")
        for page in paginator.paginate():
            for r in page.get("repositories", []):
                name = r["repositoryName"]
                if repo_filter and name not in repo_filter:
                    continue
                repos.append(name)

        cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        results: list[CheckResult] = []

        for repo_name in repos:
            try:
                pr_ids: list[str] = []
                pr_paginator = cc.get_paginator("list_pull_requests")
                for page in pr_paginator.paginate(
                    repositoryName=repo_name,
                    pullRequestStatus="CLOSED",
                ):
                    pr_ids.extend(page.get("pullRequestIds", []))

                merged_count = 0
                for pr_id in pr_ids[:100]:  # cap to avoid runaway cost
                    try:
                        pr = cc.get_pull_request(pullRequestId=pr_id).get(
                            "pullRequest", {}
                        )
                    except Exception:  # noqa: BLE001
                        continue
                    targets = pr.get("pullRequestTargets", [])
                    merged = any(t.get("mergeMetadata", {}).get("isMerged") for t in targets)
                    if not merged:
                        continue
                    last_activity = pr.get("lastActivityDate")
                    if last_activity is None:
                        continue
                    if last_activity.tzinfo is None:
                        last_activity = last_activity.replace(tzinfo=timezone.utc)
                    if last_activity >= cutoff:
                        merged_count += 1

                results.append(
                    CheckResult(
                        check_name=f"codecommit_recent_merged_prs:{repo_name}",
                        status="pass" if merged_count > 0 else "pass",
                        target_test_name="Change management process",
                        message=(
                            f"Repo {repo_name}: {merged_count} PRs merged "
                            f"in last {lookback_days} days"
                        ),
                        detail={
                            "repository": repo_name,
                            "merged_count": merged_count,
                            "lookback_days": lookback_days,
                        },
                        evidence_description=(
                            f"CodeCommit repo {repo_name}: {merged_count} merged "
                            f"PRs in last {lookback_days} days"
                        ),
                    )
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    CheckResult(
                        check_name=f"codecommit_recent_merged_prs:{repo_name}",
                        status="error",
                        target_test_name="Change management process",
                        message=f"Error on {repo_name}: {exc}",
                    )
                )

        if not results:
            results.append(
                CheckResult(
                    check_name="codecommit_recent_merged_prs",
                    status="pass",
                    target_test_name="Change management process",
                    message="No repositories to check",
                )
            )
        return results
    except Exception as exc:  # noqa: BLE001
        logger.exception("codecommit_recent_merged_prs check failed")
        return [
            CheckResult(
                check_name="codecommit_recent_merged_prs",
                status="error",
                target_test_name="Change management process",
                message=str(exc),
            )
        ]
