"""AWS CodeCommit checks for the git collector.

The change-approval control the portal recognises is an independent AI
red-team review (an AI agent on a different model from the one that made
the change), an automated security scan and the accountable human's "done."
verification, with each change pushed directly to the repository's default
branch. The review and the verification live in the decision log; on the
branch, every change carries a structured commit message with ``## Problem``,
``## Solution`` and ``## Verified`` sections. These checks read that record:

``check_repository_inventory``
    The account's CodeCommit repositories, and which of them are in the
    change-management scope.
``check_change_management``
    For each repository in scope, every commit on the default branch within
    the lookback window passes only when its message carries the three
    sections, each a ``##`` heading line (any case) followed by text before
    the next ``#`` or ``##`` heading; a closing paragraph of git trailers
    (``Co-Authored-By:``, ``Signed-off-by:``) is not section text. A merge commit (more than one
    parent) records no change of its own; the commits it brings in are
    checked one by one. A repository with no commit in the window passes
    with "no changes".

The walk: the newest ``MAX_COMMITS_PER_REPO`` commits of the default branch,
read breadth-first from its head through every parent, whatever their dates.
A commit's date is its committer date (the author date when there is none),
raised to the latest date among its ancestors read, since a commit cannot
predate its parents; a commit is in the window when that date is at most
``lookback_days`` old. A commit dated before the window therefore neither
ends the walk nor leaves the window itself while a parent is in it. When an
in-window commit has a parent beyond the commits read, the window reaches
past the walk: the result is ``incomplete`` and fails.

Scope: every repository in the account, or those named in ``repositories``,
less those named in ``exclude_repositories`` (the repositories the risk
register designates as neither customer-facing nor processing customer
data). An empty scope fails.

Bounds: at most ``MAX_REPOSITORIES`` repositories per run and
``MAX_COMMITS_PER_REPO`` GetCommit calls per repository. Check names are at
most ``MAX_CHECK_NAME_LENGTH`` characters (the database column): a longer
repository name is shortened and suffixed with a hash of the full name, and
the full name is in the result's ``detail``.

Each function takes a boto3 session and returns ``list[CheckResult]``. The
functions never raise; any exception becomes a ``status="error"`` result,
which makes the collector run partial or failed.
"""

import hashlib
import logging
import re
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

from app.services.git_sources.providers import _parse_codecommit_date
from collectors.base import CheckResult

logger = logging.getLogger(__name__)

CHANGE_MANAGEMENT_TEST = "Change management process"
CHECK_PREFIX = "codecommit_change_management"

REQUIRED_SECTIONS = ("Problem", "Solution", "Verified")
_HEADING = re.compile(r"^[ \t]*(#{1,2})[ \t]+(.*?)[ \t]*$")
_TRAILER = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):[ \t]")

MAX_REPOSITORIES = 200
MAX_COMMITS_PER_REPO = 500
MAX_CHECK_NAME_LENGTH = 128
SHORT_ID_LENGTH = 7
MESSAGE_ID_LIMIT = 10


def _is_trailer_block(lines: list[str]) -> bool:
    """A closing paragraph of git trailers: every line ``Key: value`` and at
    least one key a standard attribution trailer (``*-by``, ``Change-Id``)."""
    keys = [_TRAILER.match(line.strip()) for line in lines]
    if not lines or not all(keys):
        return False
    return any(k.group(1).lower().endswith("-by") or k.group(1).lower() == "change-id" for k in keys)


def _section_lines(message: str) -> list[str]:
    """The message's lines without its closing git trailer paragraph."""
    lines = (message or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    end = len(lines)
    while end and not lines[end - 1].strip():
        end -= 1
    start = end
    while start and lines[start - 1].strip():
        start -= 1
    if _is_trailer_block(lines[start:end]):
        return lines[:start]
    return lines[:end]


def missing_sections(message: str) -> list[str]:
    """Return the required sections a commit message lacks or leaves empty, in order."""
    wanted = {name.lower() for name in REQUIRED_SECTIONS}
    has_text: dict[str, bool] = {}
    current = None
    for line in _section_lines(message):
        heading = _HEADING.match(line)
        if heading:
            title = heading.group(2).lower()
            current = title if len(heading.group(1)) == 2 and title in wanted else None
            if current is not None:
                has_text.setdefault(current, False)
            continue
        if current is not None and line.strip():
            has_text[current] = True
    return [name for name in REQUIRED_SECTIONS if not has_text.get(name.lower())]


def check_name_for(repository: str) -> str:
    """The per-repository check name, at most ``MAX_CHECK_NAME_LENGTH`` characters."""
    name = f"{CHECK_PREFIX}:{repository}"
    if len(name) <= MAX_CHECK_NAME_LENGTH:
        return name
    digest = hashlib.sha256(repository.encode("utf-8")).hexdigest()[:8]
    keep = MAX_CHECK_NAME_LENGTH - len(CHECK_PREFIX) - len(digest) - 2
    return f"{CHECK_PREFIX}:{repository[:keep]}~{digest}"


def _list_repository_names(cc: Any) -> list[str]:
    names: list[str] = []
    for page in cc.get_paginator("list_repositories").paginate():
        for repository in page.get("repositories", []):
            names.append(repository["repositoryName"])
    return sorted(names)


def repositories_in_scope(
    names: list[str],
    repositories: list[str] | None,
    exclude_repositories: list[str] | None,
) -> tuple[list[str], list[str]]:
    """Return ``(in_scope, excluded)`` from the account's repository names."""
    include = set(repositories or [])
    exclude = set(exclude_repositories or [])
    candidates = [name for name in names if not include or name in include]
    excluded = [name for name in candidates if name in exclude]
    return [name for name in candidates if name not in exclude], excluded


def check_repository_inventory(
    session: Any,
    repositories: list[str] | None = None,
    exclude_repositories: list[str] | None = None,
) -> list[CheckResult]:
    """Verify the account has at least one CodeCommit repository and record
    which repositories the change-management check covers."""
    try:
        cc = session.client("codecommit")
        names = _list_repository_names(cc)

        if not names:
            return [
                CheckResult(
                    check_name="codecommit_inventory",
                    status="fail",
                    target_test_name=CHANGE_MANAGEMENT_TEST,
                    message="No CodeCommit repositories found",
                    evidence_description="No CodeCommit repositories in the account",
                )
            ]
        in_scope, excluded = repositories_in_scope(names, repositories, exclude_repositories)
        return [
            CheckResult(
                check_name="codecommit_inventory",
                status="pass",
                target_test_name=CHANGE_MANAGEMENT_TEST,
                message=(
                    f"{len(names)} CodeCommit repositories found, "
                    f"{len(in_scope)} in change-management scope"
                ),
                detail={
                    "count": len(names),
                    "names": names[:50],
                    "in_scope": in_scope[:50],
                    "in_scope_count": len(in_scope),
                    "excluded": excluded,
                },
                evidence_description=(
                    f"{len(names)} CodeCommit repositories in account; "
                    f"{len(in_scope)} in change-management scope"
                    + (f", excluded: {', '.join(excluded)}" if excluded else "")
                ),
            )
        ]
    except Exception as exc:  # noqa: BLE001
        logger.exception("codecommit_inventory check failed")
        return [
            CheckResult(
                check_name="codecommit_inventory",
                status="error",
                target_test_name=CHANGE_MANAGEMENT_TEST,
                message=str(exc),
            )
        ]


def _fetch_commit(cc: Any, repository: str, commit_id: str, now: datetime) -> dict:
    commit = cc.get_commit(repositoryName=repository, commitId=commit_id).get("commit") or {}
    committer = commit.get("committer") or {}
    author = commit.get("author") or {}
    moment = (_parse_codecommit_date(committer.get("date"))
              or _parse_codecommit_date(author.get("date"))
              or now)
    return {
        "commit_id": commit_id,
        "parents": list(commit.get("parents") or []),
        "message": commit.get("message") or "",
        "dated": moment,
    }


def _read_commits(cc: Any, repository: str, head_commit_id: str, now: datetime) -> tuple[dict, set]:
    """Read the newest ``MAX_COMMITS_PER_REPO`` commits breadth-first from the
    head through every parent. Returns ``(commits by id, ids left unread)``."""
    commits: dict[str, dict] = {}
    queue = deque([head_commit_id])
    queued = {head_commit_id}
    while queue and len(commits) < MAX_COMMITS_PER_REPO:
        commit_id = queue.popleft()
        commit = _fetch_commit(cc, repository, commit_id, now)
        commits[commit_id] = commit
        for parent_id in commit["parents"]:
            if parent_id not in queued:
                queued.add(parent_id)
                queue.append(parent_id)
    return commits, set(queue)


def _effective_dates(commits: dict[str, dict]) -> dict[str, datetime]:
    """Each commit's date raised to the latest date among its ancestors read."""
    effective: dict[str, datetime] = {}
    for start in commits:
        stack = [(start, False)]
        while stack:
            commit_id, parents_done = stack.pop()
            if commit_id in effective:
                continue
            parents = [p for p in commits[commit_id]["parents"] if p in commits]
            if not parents_done:
                stack.append((commit_id, True))
                stack.extend((p, False) for p in parents if p not in effective)
                continue
            effective[commit_id] = max([commits[commit_id]["dated"]] + [effective[p] for p in parents])
    return effective


def _short(commit_id: str) -> str:
    return commit_id[:SHORT_ID_LENGTH]


def _check_repository(
    cc: Any, repository: str, lookback_days: int, cutoff: datetime, now: datetime
) -> CheckResult:
    check_name = check_name_for(repository)
    try:
        metadata = cc.get_repository(repositoryName=repository).get("repositoryMetadata") or {}
        branch = metadata.get("defaultBranch")
        head = None
        if branch:
            head = (cc.get_branch(repositoryName=repository, branchName=branch)
                    .get("branch") or {}).get("commitId")
        commits, unread = _read_commits(cc, repository, head, now) if head else ({}, set())
    except Exception as exc:  # noqa: BLE001
        logger.warning("codecommit_change_management failed on %s: %s", repository, exc)
        return CheckResult(
            check_name=check_name,
            status="error",
            target_test_name=CHANGE_MANAGEMENT_TEST,
            message=f"Error on {repository}: {exc}",
            detail={"repository": repository},
        )

    effective = _effective_dates(commits)
    in_window = [commit for commit_id, commit in commits.items() if effective[commit_id] >= cutoff]
    incomplete = any(parent in unread for commit in in_window for parent in commit["parents"])
    changes = [commit for commit in in_window if len(commit["parents"]) < 2]
    failing = [commit for commit in changes if missing_sections(commit["message"])]
    failing_ids = [_short(commit["commit_id"]) for commit in failing]
    window = f"in the last {lookback_days} days"
    sections = ", ".join(f"## {name}" for name in REQUIRED_SECTIONS)
    detail = {
        "repository": repository,
        "branch": branch,
        "lookback_days": lookback_days,
        "window_start": cutoff.isoformat(),
        "commits": len(changes),
        "compliant": len(changes) - len(failing),
        "noncompliant": len(failing),
        "merge_commits": len(in_window) - len(changes),
        "failing_commits": failing_ids,
        "commits_read": len(commits),
        "incomplete": incomplete,
        "max_commits": MAX_COMMITS_PER_REPO,
    }
    label = f"Repo {repository} ({branch})" if branch else f"Repo {repository}"
    beyond = (
        f"; the window reaches beyond the {len(commits)} commits read, so older commits "
        "in it are unchecked (shorten lookback_days)"
    ) if incomplete else ""

    if failing:
        listed = ", ".join(failing_ids[:MESSAGE_ID_LIMIT])
        more = f" and {len(failing_ids) - MESSAGE_ID_LIMIT} more" if len(failing_ids) > MESSAGE_ID_LIMIT else ""
        return CheckResult(
            check_name=check_name,
            status="fail",
            target_test_name=CHANGE_MANAGEMENT_TEST,
            message=(
                f"{label}: {len(failing)} of {len(changes)} commits {window} lack "
                f"{sections} with text: {listed}{more}{beyond}"
            ),
            detail=detail,
            evidence_description=(
                f"CodeCommit repo {repository}: {len(failing)} of {len(changes)} commits "
                f"{window} lack a structured {sections} message"
            ),
        )
    if incomplete:
        return CheckResult(
            check_name=check_name,
            status="fail",
            target_test_name=CHANGE_MANAGEMENT_TEST,
            message=f"{label}: the {len(changes)} commits {window} among those read carry {sections}{beyond}",
            detail=detail,
            evidence_description=(
                f"CodeCommit repo {repository}: the {window} window reaches beyond the "
                f"{len(commits)} commits read; the change record is verified only for those"
            ),
        )
    if not changes:
        return CheckResult(
            check_name=check_name,
            status="pass",
            target_test_name=CHANGE_MANAGEMENT_TEST,
            message=f"{label}: no changes {window}",
            detail=detail,
            evidence_description=f"CodeCommit repo {repository}: no changes {window}",
        )
    return CheckResult(
        check_name=check_name,
        status="pass",
        target_test_name=CHANGE_MANAGEMENT_TEST,
        message=f"{label}: all {len(changes)} commits {window} carry {sections}",
        detail=detail,
        evidence_description=(
            f"CodeCommit repo {repository}: all {len(changes)} commits {window} "
            f"carry a structured {sections} message"
        ),
    )


def check_change_management(
    session: Any,
    repositories: list[str] | None = None,
    exclude_repositories: list[str] | None = None,
    lookback_days: int = 30,
    now: datetime | None = None,
) -> list[CheckResult]:
    """Check every commit on each in-scope repository's default branch within
    ``lookback_days`` for the structured change record (one result per
    repository)."""
    try:
        cc = session.client("codecommit")
        names = _list_repository_names(cc)
        in_scope, excluded = repositories_in_scope(names, repositories, exclude_repositories)
        now = now or datetime.now(timezone.utc)
        cutoff = now - timedelta(days=lookback_days)

        results: list[CheckResult] = []
        known = set(names)
        for name in sorted(set(repositories or []) - known - set(exclude_repositories or [])):
            results.append(
                CheckResult(
                    check_name=check_name_for(name),
                    status="error",
                    target_test_name=CHANGE_MANAGEMENT_TEST,
                    message=f"Repository {name} is not among the account's CodeCommit repositories",
                    detail={"repository": name},
                )
            )

        if not in_scope:
            results.append(
                CheckResult(
                    check_name=CHECK_PREFIX,
                    status="fail",
                    target_test_name=CHANGE_MANAGEMENT_TEST,
                    message="No repositories in change-management scope",
                    detail={"repository_count": len(names), "excluded": excluded},
                    evidence_description="No CodeCommit repository is in change-management scope",
                )
            )
            return results

        if len(in_scope) > MAX_REPOSITORIES:
            results.append(
                CheckResult(
                    check_name=CHECK_PREFIX,
                    status="error",
                    target_test_name=CHANGE_MANAGEMENT_TEST,
                    message=(
                        f"{len(in_scope)} repositories in scope; the first {MAX_REPOSITORIES} "
                        "are checked. Narrow the scope with repositories or exclude_repositories."
                    ),
                    detail={"in_scope_count": len(in_scope), "max_repositories": MAX_REPOSITORIES},
                )
            )
            in_scope = in_scope[:MAX_REPOSITORIES]

        for repository in in_scope:
            results.append(_check_repository(cc, repository, lookback_days, cutoff, now))
        return results
    except Exception as exc:  # noqa: BLE001
        logger.exception("codecommit_change_management check failed")
        return [
            CheckResult(
                check_name=CHECK_PREFIX,
                status="error",
                target_test_name=CHANGE_MANAGEMENT_TEST,
                message=str(exc),
            )
        ]
