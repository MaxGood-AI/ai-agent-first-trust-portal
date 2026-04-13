"""Git v2 collector — dispatches to per-provider check modules.

v1 supports AWS CodeCommit. The provider is selected via
``config.config.provider`` (default: ``codecommit``). A future release will
add ``github`` as a second backend using a PAT stored in the
``access_keys`` credential mode under key ``github_token``.
"""

import logging

from collectors.base import BaseCollector, CheckResult
from collectors.git import codecommit_checks

logger = logging.getLogger(__name__)


GIT_CODECOMMIT_REQUIRED_PERMISSIONS = [
    "sts:GetCallerIdentity",
    "codecommit:ListRepositories",
    "codecommit:ListApprovalRuleTemplates",
    "codecommit:ListAssociatedApprovalRuleTemplatesForRepository",
    "codecommit:ListPullRequests",
    "codecommit:GetPullRequest",
]


class GitCollector(BaseCollector):
    """Change-management evidence from source control."""

    name = "git"
    required_permissions = GIT_CODECOMMIT_REQUIRED_PERMISSIONS
    credential_modes_supported = [
        "task_role",
        "task_role_assume",
        "access_keys",
    ]

    def run(self) -> list[CheckResult]:
        config_dict = self.config.config or {}
        provider = (config_dict.get("provider") or "codecommit").lower()
        if provider != "codecommit":
            return [
                CheckResult(
                    check_name="git_provider",
                    status="error",
                    message=(
                        f"Unsupported git provider '{provider}'. "
                        "v1 supports only 'codecommit'."
                    ),
                )
            ]

        resolved = self.resolved
        session = resolved.boto_session
        if session is None:
            return [
                CheckResult(
                    check_name="git_run",
                    status="error",
                    message="No boto3 session available for CodeCommit access",
                )
            ]

        repo_filter = config_dict.get("repositories") or None
        lookback_days = int(config_dict.get("lookback_days", 30))

        results: list[CheckResult] = []
        results.extend(codecommit_checks.check_repository_inventory(session))
        results.extend(codecommit_checks.check_approval_rule_templates(session))
        results.extend(
            codecommit_checks.check_approval_rules_attached_to_repos(
                session, repo_filter=repo_filter
            )
        )
        results.extend(
            codecommit_checks.check_recent_merged_pull_requests(
                session, repo_filter=repo_filter, lookback_days=lookback_days
            )
        )
        return results
