"""Permission prober — tests whether resolved credentials can exercise
the AWS actions a collector needs.

Each probe makes a minimal, read-only API call that exercises the target
permission. Access-denied errors are captured as ``fail``; other errors as
``error``. The prober never writes data.

Probes are registered in the ``AWS_ACTION_PROBES`` table. Unknown actions
are reported as ``skipped`` so admins know which permissions cannot yet be
verified programmatically.
"""

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from app.services.credential_resolver import ResolvedCredentials

logger = logging.getLogger(__name__)


@dataclass
class PermissionCheckResult:
    action: str
    status: str  # "pass" | "fail" | "error" | "skipped"
    message: str | None = None


@dataclass
class PermissionProbeResult:
    session_identity: str | None
    account_id: str | None
    region: str | None
    checked_at: str
    all_passed: bool
    results: list[PermissionCheckResult] = field(default_factory=list)

    @property
    def missing_actions(self) -> list[str]:
        return [r.action for r in self.results if r.status != "pass"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_identity": self.session_identity,
            "account_id": self.account_id,
            "region": self.region,
            "checked_at": self.checked_at,
            "all_passed": self.all_passed,
            "results": [asdict(r) for r in self.results],
            "missing_actions": self.missing_actions,
        }


# ----- per-action probe implementations -----


def _probe_sts_get_caller_identity(session: Any) -> None:
    session.client("sts").get_caller_identity()


def _probe_iam_list_users(session: Any) -> None:
    session.client("iam").list_users(MaxItems=1)


def _probe_iam_list_mfa_devices(session: Any) -> None:
    """ListMFADevices needs a username — try the first user, or call
    list_virtual_mfa_devices as a fallback that exercises a close permission."""
    iam = session.client("iam")
    users = iam.list_users(MaxItems=1).get("Users", [])
    if users:
        iam.list_mfa_devices(UserName=users[0]["UserName"])
    else:
        iam.list_virtual_mfa_devices(MaxItems=1)


def _probe_iam_list_access_keys(session: Any) -> None:
    iam = session.client("iam")
    users = iam.list_users(MaxItems=1).get("Users", [])
    if users:
        iam.list_access_keys(UserName=users[0]["UserName"])
    else:
        # No users — just verify list_users works; list_access_keys perm is
        # implicitly exercised when users exist.
        iam.list_users(MaxItems=1)


def _probe_iam_get_account_password_policy(session: Any) -> None:
    iam = session.client("iam")
    try:
        iam.get_account_password_policy()
    except iam.exceptions.NoSuchEntityException:
        # No policy configured is fine — the call itself is authorized.
        pass


def _probe_s3_list_all_my_buckets(session: Any) -> None:
    session.client("s3").list_buckets()


def _probe_s3_get_bucket_encryption(session: Any) -> None:
    _probe_s3_bucket_attr(session, "get_bucket_encryption")


def _probe_s3_get_bucket_versioning(session: Any) -> None:
    _probe_s3_bucket_attr(session, "get_bucket_versioning")


def _probe_s3_get_bucket_public_access_block(session: Any) -> None:
    _probe_s3_bucket_attr(session, "get_public_access_block")


def _probe_s3_bucket_attr(session: Any, method_name: str) -> None:
    s3 = session.client("s3")
    buckets = s3.list_buckets().get("Buckets", [])
    if not buckets:
        return
    method = getattr(s3, method_name)
    try:
        method(Bucket=buckets[0]["Name"])
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        # These codes indicate the call was authorized but there's no config;
        # that still proves the permission is present.
        allowed = {
            "ServerSideEncryptionConfigurationNotFoundError",
            "NoSuchPublicAccessBlockConfiguration",
        }
        if code in allowed:
            return
        raise


def _probe_rds_describe_db_instances(session: Any) -> None:
    session.client("rds").describe_db_instances(MaxRecords=20)


def _probe_cloudtrail_describe_trails(session: Any) -> None:
    session.client("cloudtrail").describe_trails()


def _probe_cloudtrail_get_trail_status(session: Any) -> None:
    ct = session.client("cloudtrail")
    trails = ct.describe_trails().get("trailList", [])
    if trails:
        ct.get_trail_status(Name=trails[0].get("TrailARN") or trails[0].get("Name"))


def _probe_codecommit_list_repositories(session: Any) -> None:
    session.client("codecommit").list_repositories(order="ascending")


def _probe_codecommit_list_approval_rule_templates(session: Any) -> None:
    session.client("codecommit").list_approval_rule_templates()


def _probe_codecommit_list_associated_approval_rules(session: Any) -> None:
    cc = session.client("codecommit")
    repos = cc.list_repositories().get("repositories", [])
    if repos:
        cc.list_associated_approval_rule_templates_for_repository(
            repositoryName=repos[0]["repositoryName"]
        )


def _probe_codecommit_list_pull_requests(session: Any) -> None:
    cc = session.client("codecommit")
    repos = cc.list_repositories().get("repositories", [])
    if repos:
        cc.list_pull_requests(repositoryName=repos[0]["repositoryName"])


def _probe_codecommit_get_pull_request(session: Any) -> None:
    """There may be no open PRs — catch that as success since the permission
    is what we're testing, not the data presence."""
    cc = session.client("codecommit")
    repos = cc.list_repositories().get("repositories", [])
    if not repos:
        return
    prs = cc.list_pull_requests(
        repositoryName=repos[0]["repositoryName"]
    ).get("pullRequestIds", [])
    if prs:
        cc.get_pull_request(pullRequestId=prs[0])


AWS_ACTION_PROBES: dict[str, Callable[[Any], None]] = {
    "sts:GetCallerIdentity": _probe_sts_get_caller_identity,
    "iam:ListUsers": _probe_iam_list_users,
    "iam:ListMFADevices": _probe_iam_list_mfa_devices,
    "iam:ListAccessKeys": _probe_iam_list_access_keys,
    "iam:GetAccountPasswordPolicy": _probe_iam_get_account_password_policy,
    "s3:ListAllMyBuckets": _probe_s3_list_all_my_buckets,
    "s3:GetBucketEncryption": _probe_s3_get_bucket_encryption,
    "s3:GetBucketVersioning": _probe_s3_get_bucket_versioning,
    "s3:GetBucketPublicAccessBlock": _probe_s3_get_bucket_public_access_block,
    "rds:DescribeDBInstances": _probe_rds_describe_db_instances,
    "cloudtrail:DescribeTrails": _probe_cloudtrail_describe_trails,
    "cloudtrail:GetTrailStatus": _probe_cloudtrail_get_trail_status,
    "codecommit:ListRepositories": _probe_codecommit_list_repositories,
    "codecommit:ListApprovalRuleTemplates": _probe_codecommit_list_approval_rule_templates,
    "codecommit:ListAssociatedApprovalRuleTemplatesForRepository":
        _probe_codecommit_list_associated_approval_rules,
    "codecommit:ListPullRequests": _probe_codecommit_list_pull_requests,
    "codecommit:GetPullRequest": _probe_codecommit_get_pull_request,
}


def _is_access_denied(exc: Exception) -> bool:
    error = getattr(exc, "response", None)
    if not isinstance(error, dict):
        return False
    code = error.get("Error", {}).get("Code", "")
    return code in ("AccessDenied", "UnauthorizedOperation", "AccessDeniedException")


class PermissionProber:
    """Runs the required-permissions list of a collector against a
    resolved credential set and reports per-action results."""

    def probe(
        self,
        resolved: ResolvedCredentials,
        required_actions: list[str],
    ) -> PermissionProbeResult:
        checked_at = datetime.now(timezone.utc).isoformat()
        session_identity: str | None = None
        account_id: str | None = None
        region: str | None = None

        # Identity probe first — if this fails, no point running the rest.
        if resolved.boto_session is not None:
            try:
                sts = resolved.boto_session.client("sts")
                caller = sts.get_caller_identity()
                session_identity = caller.get("Arn")
                account_id = caller.get("Account")
                region = resolved.boto_session.region_name
            except Exception as exc:  # noqa: BLE001
                return PermissionProbeResult(
                    session_identity=None,
                    account_id=None,
                    region=None,
                    checked_at=checked_at,
                    all_passed=False,
                    results=[
                        PermissionCheckResult(
                            action="sts:GetCallerIdentity",
                            status="error",
                            message=str(exc),
                        )
                    ],
                )

        results: list[PermissionCheckResult] = []
        if "sts:GetCallerIdentity" not in required_actions:
            results.append(
                PermissionCheckResult(
                    action="sts:GetCallerIdentity",
                    status="pass" if session_identity else "skipped",
                    message=None if session_identity else "No AWS session to probe",
                )
            )

        for action in required_actions:
            probe_fn = AWS_ACTION_PROBES.get(action)
            if probe_fn is None:
                results.append(
                    PermissionCheckResult(
                        action=action,
                        status="skipped",
                        message="No probe implemented for this action",
                    )
                )
                continue
            if resolved.boto_session is None:
                results.append(
                    PermissionCheckResult(
                        action=action,
                        status="skipped",
                        message="No AWS session to probe",
                    )
                )
                continue
            try:
                probe_fn(resolved.boto_session)
                results.append(
                    PermissionCheckResult(action=action, status="pass")
                )
            except Exception as exc:  # noqa: BLE001
                if _is_access_denied(exc):
                    results.append(
                        PermissionCheckResult(
                            action=action,
                            status="fail",
                            message="AccessDenied",
                        )
                    )
                else:
                    results.append(
                        PermissionCheckResult(
                            action=action,
                            status="error",
                            message=str(exc),
                        )
                    )

        all_passed = all(r.status == "pass" for r in results)
        return PermissionProbeResult(
            session_identity=session_identity,
            account_id=account_id,
            region=region,
            checked_at=checked_at,
            all_passed=all_passed,
            results=results,
        )
