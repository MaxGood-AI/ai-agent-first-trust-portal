"""Git collector: change-management evidence from AWS CodeCommit.

Configuration (``config.config``, every key optional):

``provider``
    ``codecommit`` (the default and the only provider).
``repositories``
    Repository names to check; empty or absent checks every repository in
    the account.
``exclude_repositories``
    Repository names left out of the change-management scope: the
    repositories the risk register designates as neither customer-facing
    nor processing customer data.
``lookback_days``
    The window of default-branch commits checked, 1 to 365 days (default 30).

The checks are in ``collectors.git.codecommit_checks``.
"""

import logging
from collections.abc import Mapping

from collectors.base import BaseCollector, CheckResult
from collectors.git import codecommit_checks

logger = logging.getLogger(__name__)


GIT_CODECOMMIT_REQUIRED_PERMISSIONS = [
    "sts:GetCallerIdentity",
    "codecommit:ListRepositories",
    "codecommit:GetRepository",
    "codecommit:GetBranch",
    "codecommit:GetCommit",
]

DEFAULT_LOOKBACK_DAYS = 30
MAX_LOOKBACK_DAYS = 365


def name_list(value) -> list[str] | None:
    """Return a list of repository names, or ``None`` when ``value`` is not one."""
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return [item.strip() for item in value if item.strip()]


def _lines(text: str | None) -> list[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def parse_form_settings(form: Mapping[str, str]) -> dict:
    """Return the configuration settings of the admin form's git fields.

    ``repositories`` and ``exclude_repositories`` are one name per line;
    each is set only when its field is present, a blank ``repositories``
    becoming ``None`` (every repository). A blank ``lookback_days`` leaves the
    setting as it is. Raises ``ValueError`` with an administrator-facing
    message for a ``lookback_days`` that is not a whole number from 1 to 365.
    """
    settings: dict = {}
    if "repositories" in form:
        settings["repositories"] = _lines(form.get("repositories")) or None
    if "exclude_repositories" in form:
        settings["exclude_repositories"] = _lines(form.get("exclude_repositories"))
    lookback = (form.get("lookback_days") or "").strip()
    if lookback:
        days = _lookback_days(lookback)
        if days is None:
            raise ValueError(f"lookback_days must be a whole number from 1 to {MAX_LOOKBACK_DAYS}")
        settings["lookback_days"] = days
    return settings


def _lookback_days(value) -> int | None:
    if value is None:
        return DEFAULT_LOOKBACK_DAYS
    if isinstance(value, bool):
        return None
    try:
        days = int(value)
    except (TypeError, ValueError):
        return None
    return days if 1 <= days <= MAX_LOOKBACK_DAYS else None


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
                        "The git collector reads 'codecommit'."
                    ),
                )
            ]

        repositories = name_list(config_dict.get("repositories"))
        exclude_repositories = name_list(config_dict.get("exclude_repositories"))
        lookback_days = _lookback_days(config_dict.get("lookback_days"))
        problems = []
        if repositories is None:
            problems.append("repositories must be a list of repository names")
        if exclude_repositories is None:
            problems.append("exclude_repositories must be a list of repository names")
        if lookback_days is None:
            problems.append(f"lookback_days must be a whole number from 1 to {MAX_LOOKBACK_DAYS}")
        if problems:
            return [
                CheckResult(
                    check_name="git_config",
                    status="error",
                    target_test_name=codecommit_checks.CHANGE_MANAGEMENT_TEST,
                    message="; ".join(problems),
                )
            ]

        session = self.resolved.boto_session
        if session is None:
            return [
                CheckResult(
                    check_name="git_run",
                    status="error",
                    message="No boto3 session available for CodeCommit access",
                )
            ]

        results: list[CheckResult] = []
        results.extend(
            codecommit_checks.check_repository_inventory(
                session,
                repositories=repositories,
                exclude_repositories=exclude_repositories,
            )
        )
        results.extend(
            codecommit_checks.check_change_management(
                session,
                repositories=repositories,
                exclude_repositories=exclude_repositories,
                lookback_days=lookback_days,
            )
        )
        return results
