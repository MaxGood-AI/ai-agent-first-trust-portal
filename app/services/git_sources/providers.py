"""Git source providers: read one branch of a repository through an API.

The portal reads its governance and evidence repositories without a git
binary and without any credential helper. A provider exposes one branch of
one repository through the contract below; the sync layer builds on it.

Contract
--------
``resolve_head()``
    The commit id the configured branch points at.
``list_tree(commit_id)``
    Every file (blob) in the commit's tree, recursively, as ``TreeEntry``
    objects sorted by path. Paths are repository-relative, use forward
    slashes and have no leading slash. Submodule entries are not files and
    are omitted.
``diff(from_commit, to_commit)``
    The files that differ between two commits, as ``Change`` objects sorted by
    path: ``A`` added, ``M`` modified, ``D`` deleted. A rename is reported as
    ``D`` for the old path plus ``A`` for the new path.
``read_blob(entry_or_blob_id, path=..., commit_id=..., max_bytes=None)`` /
``read_file(path, commit_id, max_bytes=None)``
    File content as bytes. ``read_blob`` accepts a ``TreeEntry`` (or a
    ``Change``) as well as a bare blob id; ``path`` names the file in error
    messages and lets the local provider find it. With ``max_bytes``, at
    most that many bytes are returned (the file's first ``max_bytes`` when it
    is longer) and no more are read where the API streams: GitHub and local
    reads stop there; CodeCommit returns whole files (at most 6 MB).
``commits_between(from_commit, to_commit, limit)``
    Commits reachable from ``to_commit`` and not from ``from_commit`` (every
    ancestor when ``from_commit`` is ``None``), newest first, each commit once,
    at most ``limit``. All parents of a merge are followed.
``commit_changed_paths(commit)``
    The paths a commit changed relative to its first parent (every path of
    the tree for a root commit), sorted.

Failures raise ``GitSourceError`` or one of its subclasses:
``NotFoundError`` (repository, branch, commit or path missing),
``FileTooLargeError`` (the API cannot return the file) and ``RateLimitError``
(the API asked the caller to back off). Messages are safe to show to
administrators and never contain an access token. A provider instance is
used by one thread at a time.

Providers
---------
``codecommit`` - ``CodeCommitProvider``
    AWS CodeCommit through a boto3 client, calling only GetBranch, GetCommit,
    GetDifferences, GetFile and GetBlob. ``list_tree`` calls GetDifferences
    with only ``afterCommitSpecifier``, which returns every file of the tree
    as an addition together with its blob id, so a listing costs one call per
    page of files whatever the directory layout. History is walked with GetCommit in commit-date order from
    ``to_commit`` (interesting) and ``from_commit`` (uninteresting) together,
    the way ``git log from..to`` walks it; with clock skew between committers
    a commit can be classified out of order.
``github`` - ``GitHubProvider``
    The GitHub REST API (github.com or GitHub Enterprise Server) with an
    optional bearer token. Error messages quote the API's error message only
    for ``https://api.github.com``; for any other ``api_url`` they carry the
    HTTP status code and reason phrase, never the response body. Every
    request goes through ``app.services.safe_http.safe_get``: the API host
    and every redirect hop must resolve to public addresses (the default
    session also checks the address each connection reaches), and the token
    is sent only to the ``api_url`` origin. ``api.github.com`` resolves to
    public addresses; a GitHub Enterprise Server ``api_url`` whose host
    resolves to a private, loopback, link-local or other internal address is
    refused with ``GitSourceError``.
    ``diff`` uses the compare API when ``from_commit``
    is an ancestor of ``to_commit`` and the comparison lists fewer than 300
    files; otherwise it diffs the two recursive trees by blob sha, which is
    exact. ``commits_between`` uses the compare API when the range holds at
    most 250 commits (exact). A larger range is read from the commit list of
    ``to_commit`` (commit-date order, all parents) until ``from_commit``
    appears; commits of a side branch dated before ``from_commit`` are then
    missed, and ancestors of ``from_commit`` dated after it are included.
    ``commit_changed_paths`` returns at most 3,000 paths, the GitHub limit
    for one commit.
``local`` - ``LocalDirectoryProvider``
    A directory on disk, for development, tests and adopters without a hosted
    repository. It reads no git metadata: the ``.git`` directory and every
    path component starting with ``.git`` are skipped. Blob ids are sha256
    digests of file content and the head is derived from the file manifest,
    so an unchanged directory keeps its head. It has no history.
    ``build_provider`` applies the portal's local-source policy
    (:func:`local_source_roots`): with ``LOCAL_SOURCE_ROOTS`` set, the
    directory (resolved, symbolic links followed) must be one of those roots
    or inside one; without it, local sources are refused in production
    (``PORTAL_ENV=production``) and unrestricted in development and tests.

Size limits
-----------
- CodeCommit: 6 MB for any individual file through the API, GetFile and
  GetBlob alike (``max_file_bytes``); a larger file raises
  ``FileTooLargeError``.
- GitHub: blobs (``/git/blobs``) and file contents (``/contents``) are read
  with the raw media type, which returns files up to 100 MB
  (``max_file_bytes``); the JSON contents representation, limited to 1 MB, is
  not used. A recursive tree listing is limited to 100,000 entries or 7 MB; a
  truncated listing raises ``GitSourceError``. The compare API lists at most
  300 files and 250 commits.
- Local: no limit.
"""

from __future__ import annotations

import abc
import hashlib
import heapq
import itertools
import os
import re
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import requests
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from app.services.safe_http import UnsafeURLError, guarded_session, release, safe_get

DEFAULT_GITHUB_API_URL = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_JSON_MEDIA_TYPE = "application/vnd.github+json"
GITHUB_RAW_MEDIA_TYPE = "application/vnd.github.raw+json"

CODECOMMIT_MAX_FILE_BYTES = 6 * 1024 * 1024
GITHUB_MAX_FILE_BYTES = 100 * 1024 * 1024

_GITLINK_MODE = "160000"
_HEX_ID = re.compile(r"^[0-9a-fA-F]{4,64}$")
_CODECOMMIT_REPOSITORY = re.compile(r"^[\w.-]{1,100}$")
_GITHUB_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_BRANCH_FORBIDDEN = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]")
_CODECOMMIT_DATE = re.compile(r"^(\d+)(?:\s+[+-]\d{4})?$")


class GitSourceError(Exception):
    """A git source provider failed. The message is safe to show to administrators."""


class NotFoundError(GitSourceError):
    """The repository, branch, commit or path does not exist."""


class FileTooLargeError(GitSourceError):
    """The provider cannot return this file through its API.

    ``path`` is the repository path when known, ``size`` the file size in
    bytes when known, ``limit`` the provider's per-file limit in bytes.
    """

    def __init__(self, path: str | None, size: int | None, limit: int, message: str = ""):
        self.path = path
        self.size = size
        self.limit = limit
        if not message:
            subject = path or "file"
            size_text = f" ({size} bytes)" if size is not None else ""
            message = f"{subject}{size_text} exceeds the {limit} byte per-file limit of the provider API"
        super().__init__(message)


class RateLimitError(GitSourceError):
    """The provider API rate limit is exhausted; ``retry_after`` is in seconds when known."""

    def __init__(self, message: str, retry_after: int | None = None):
        self.retry_after = retry_after
        super().__init__(message)


@dataclass(frozen=True)
class TreeEntry:
    """One file of a tree."""

    path: str
    blob_id: str
    size: int | None


@dataclass(frozen=True)
class Change:
    """One file changed between two commits; ``blob_id`` is ``None`` for a deletion."""

    path: str
    change_type: str
    blob_id: str | None


@dataclass(frozen=True)
class CommitInfo:
    """Commit metadata; datetimes are timezone-aware UTC."""

    commit_id: str
    parent_ids: tuple[str, ...]
    author_name: str | None
    author_email: str | None
    authored_at: datetime | None
    committer_name: str | None
    committer_email: str | None
    committed_at: datetime | None
    message: str


class GitProvider(abc.ABC):
    """Read access to one branch of one repository (see the module docstring)."""

    name: str = ""
    max_file_bytes: int | None = None
    supports_history: bool = True

    @abc.abstractmethod
    def resolve_head(self) -> str:
        """Return the commit id at the configured branch."""

    @abc.abstractmethod
    def list_tree(self, commit_id: str) -> list[TreeEntry]:
        """Return every file in the commit's tree, sorted by path."""

    @abc.abstractmethod
    def diff(self, from_commit: str, to_commit: str) -> list[Change]:
        """Return the files changed between two commits, sorted by path."""

    @abc.abstractmethod
    def read_blob(self, entry_or_blob_id: str | TreeEntry | Change, *, path: str | None = None,
                  commit_id: str | None = None, max_bytes: int | None = None) -> bytes:
        """Return the content of a blob (at most ``max_bytes`` of it)."""

    @abc.abstractmethod
    def read_file(self, path: str, commit_id: str, *, max_bytes: int | None = None) -> bytes:
        """Return the content of ``path`` at ``commit_id`` (at most ``max_bytes`` of it)."""

    @abc.abstractmethod
    def commits_between(self, from_commit: str | None, to_commit: str, limit: int) -> list[CommitInfo]:
        """Return commits in ``to_commit`` and not in ``from_commit``, newest first."""

    @abc.abstractmethod
    def commit_changed_paths(self, commit: CommitInfo) -> list[str]:
        """Return the paths ``commit`` changed relative to its first parent."""

    def _ensure_within_limit(self, path: str | None, size: int | None) -> None:
        if self.max_file_bytes is not None and size is not None and size > self.max_file_bytes:
            raise FileTooLargeError(path, size, self.max_file_bytes)


# --- shared helpers ---------------------------------------------------------


def _blob_target(entry_or_blob_id: str | TreeEntry | Change,
                 path: str | None) -> tuple[str, str | None, int | None]:
    """Return ``(blob_id, path, size)`` for a ``read_blob`` argument."""
    if isinstance(entry_or_blob_id, TreeEntry):
        return entry_or_blob_id.blob_id, path or entry_or_blob_id.path, entry_or_blob_id.size
    if isinstance(entry_or_blob_id, Change):
        if entry_or_blob_id.blob_id is None:
            raise GitSourceError(f"{entry_or_blob_id.path} was deleted and has no content to read")
        return entry_or_blob_id.blob_id, path or entry_or_blob_id.path, None
    if not isinstance(entry_or_blob_id, str) or not entry_or_blob_id:
        raise GitSourceError("a blob id is required")
    return entry_or_blob_id, path, None


def _prefix(data: bytes, max_bytes: int | None) -> bytes:
    """``data``, cut to its first ``max_bytes`` bytes when a limit is given."""
    return data if max_bytes is None or len(data) <= max_bytes else data[:max_bytes]


def _validate_repo_path(path: str) -> str:
    """Return ``path`` if it is a plain repository-relative path, else raise."""
    if not isinstance(path, str) or not path or "\x00" in path or path.startswith("/"):
        raise GitSourceError(f"invalid repository path: {path!r}")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise GitSourceError(f"invalid repository path: {path!r}")
    return path


def _validate_branch(branch: str) -> str:
    if not isinstance(branch, str) or not branch.strip():
        raise GitSourceError("a branch name is required")
    if (_BRANCH_FORBIDDEN.search(branch) or ".." in branch or "@{" in branch
            or branch.startswith(("/", "-", ".")) or branch.endswith(("/", ".", ".lock"))
            or "//" in branch):
        raise GitSourceError(f"invalid branch name: {branch!r}")
    return branch


def _is_git_component(name: str) -> bool:
    return name.startswith(".git")


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _parse_codecommit_date(value: Any) -> datetime | None:
    """Parse a CodeCommit ``"<epoch seconds> <+hhmm>"`` date (ISO 8601 also accepted)."""
    if isinstance(value, str):
        match = _CODECOMMIT_DATE.match(value.strip())
        if match:
            return datetime.fromtimestamp(int(match.group(1)), tz=timezone.utc)
    return _parse_iso(value)


def _commit_timestamp(commit: CommitInfo) -> float:
    moment = commit.committed_at or commit.authored_at
    return moment.timestamp() if moment else 0.0


def _normalize_changes(changes: list[Change]) -> list[Change]:
    """Merge a deletion and an addition of the same path into a modification; sort by path."""
    merged: dict[str, Change] = {}
    for change in changes:
        existing = merged.get(change.path)
        if existing is not None and {existing.change_type, change.change_type} == {"A", "D"}:
            added = change if change.change_type == "A" else existing
            merged[change.path] = Change(change.path, "M", added.blob_id)
        else:
            merged[change.path] = change
    return [merged[path] for path in sorted(merged)]


def _diff_manifests(before: Mapping[str, str], after: Mapping[str, str]) -> list[Change]:
    """Diff two ``{path: blob_id}`` manifests exactly."""
    changes = []
    for path in sorted(before.keys() | after.keys()):
        old, new = before.get(path), after.get(path)
        if old is None:
            changes.append(Change(path, "A", new))
        elif new is None:
            changes.append(Change(path, "D", None))
        elif old != new:
            changes.append(Change(path, "M", new))
    return changes


# --- AWS CodeCommit -----------------------------------------------------------


class CodeCommitProvider(GitProvider):
    """AWS CodeCommit through a boto3 ``codecommit`` client."""

    name = "codecommit"
    max_file_bytes = CODECOMMIT_MAX_FILE_BYTES
    supports_history = True

    _NOT_FOUND_CODES = frozenset({
        "RepositoryDoesNotExistException",
        "BranchDoesNotExistException",
        "CommitDoesNotExistException",
        "CommitIdDoesNotExistException",
        "FileDoesNotExistException",
        "FolderDoesNotExistException",
        "BlobIdDoesNotExistException",
        "PathDoesNotExistException",
    })

    def __init__(self, repository: str, branch: str, client: Any):
        if not isinstance(repository, str) or not _CODECOMMIT_REPOSITORY.match(repository):
            raise GitSourceError(f"invalid CodeCommit repository name: {repository!r}")
        self.repository = repository
        self.branch = _validate_branch(branch)
        self._client = client

    def _call(self, operation: str, *, path: str | None = None, **params: Any) -> dict:
        try:
            return getattr(self._client, operation)(repositoryName=self.repository, **params)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code") or "UnknownError"
            message = error.get("Message") or ""
            text = f"CodeCommit {code}: {message}" if message else f"CodeCommit {code}"
            if code == "FileTooLargeException":
                raise FileTooLargeError(
                    path, None, CODECOMMIT_MAX_FILE_BYTES,
                    f"{path or 'blob'} exceeds the CodeCommit API limit of 6 MB per file ({code})",
                ) from exc
            if code in self._NOT_FOUND_CODES:
                raise NotFoundError(text) from exc
            raise GitSourceError(text) from exc
        except BotoCoreError as exc:
            raise GitSourceError(f"CodeCommit request failed: {exc}") from exc

    def _differences(self, before: str | None, after: str) -> Iterator[dict]:
        params: dict[str, Any] = {"afterCommitSpecifier": after}
        if before:
            params["beforeCommitSpecifier"] = before
        while True:
            response = self._call("get_differences", **params)
            yield from response.get("differences") or []
            token = response.get("NextToken")
            if not token:
                return
            params["NextToken"] = token

    @staticmethod
    def _file_blob(blob: dict | None) -> dict | None:
        """Return the blob metadata when it describes a file (not a submodule)."""
        if not blob or not blob.get("path") or not blob.get("blobId"):
            return None
        if blob.get("mode") == _GITLINK_MODE:
            return None
        return blob

    def resolve_head(self) -> str:
        response = self._call("get_branch", branchName=self.branch)
        commit_id = (response.get("branch") or {}).get("commitId")
        if not commit_id:
            raise GitSourceError(f"CodeCommit branch {self.branch} has no commit")
        return commit_id

    def list_tree(self, commit_id: str) -> list[TreeEntry]:
        entries = []
        for difference in self._differences(None, commit_id):
            blob = self._file_blob(difference.get("afterBlob"))
            if blob is not None:
                entries.append(TreeEntry(blob["path"].lstrip("/"), blob["blobId"], None))
        return sorted(entries, key=lambda entry: entry.path)

    def diff(self, from_commit: str, to_commit: str) -> list[Change]:
        if from_commit == to_commit:
            return []
        changes = []
        for difference in self._differences(from_commit, to_commit):
            before = self._file_blob(difference.get("beforeBlob"))
            after = self._file_blob(difference.get("afterBlob"))
            if before is not None and after is not None and before["path"] == after["path"]:
                changes.append(Change(after["path"].lstrip("/"), "M", after["blobId"]))
                continue
            if before is not None:
                changes.append(Change(before["path"].lstrip("/"), "D", None))
            if after is not None:
                changes.append(Change(after["path"].lstrip("/"), "A", after["blobId"]))
        return _normalize_changes(changes)

    def read_blob(self, entry_or_blob_id: str | TreeEntry | Change, *, path: str | None = None,
                  commit_id: str | None = None, max_bytes: int | None = None) -> bytes:
        blob_id, path, size = _blob_target(entry_or_blob_id, path)
        self._ensure_within_limit(path, size)
        return _prefix(self._call("get_blob", path=path, blobId=blob_id)["content"], max_bytes)

    def read_file(self, path: str, commit_id: str, *, max_bytes: int | None = None) -> bytes:
        path = _validate_repo_path(path)
        response = self._call("get_file", path=path, commitSpecifier=commit_id, filePath=path)
        return _prefix(response["fileContent"], max_bytes)

    def _get_commit(self, commit_id: str) -> CommitInfo:
        commit = self._call("get_commit", commitId=commit_id).get("commit") or {}
        author = commit.get("author") or {}
        committer = commit.get("committer") or {}
        return CommitInfo(
            commit_id=commit.get("commitId") or commit_id,
            parent_ids=tuple(commit.get("parents") or ()),
            author_name=author.get("name"),
            author_email=author.get("email"),
            authored_at=_parse_codecommit_date(author.get("date")),
            committer_name=committer.get("name"),
            committer_email=committer.get("email"),
            committed_at=_parse_codecommit_date(committer.get("date")),
            message=commit.get("message") or "",
        )

    def commits_between(self, from_commit: str | None, to_commit: str, limit: int) -> list[CommitInfo]:
        if limit <= 0 or from_commit == to_commit:
            return []
        walk = _HistoryWalk(self._get_commit)
        walk.push(to_commit, uninteresting=False)
        if from_commit:
            walk.push(from_commit, uninteresting=True)
        return walk.run(limit)

    def commit_changed_paths(self, commit: CommitInfo) -> list[str]:
        parent = commit.parent_ids[0] if commit.parent_ids else None
        paths: set[str] = set()
        for difference in self._differences(parent, commit.commit_id):
            for side in ("beforeBlob", "afterBlob"):
                blob = difference.get(side) or {}
                if blob.get("path"):
                    paths.add(blob["path"].lstrip("/"))
        return sorted(paths)


class _HistoryWalk:
    """Commit-date ordered walk of ``to`` minus ``from`` (``git log from..to``).

    Commits reachable from an uninteresting commit are uninteresting. The walk
    stops when every queued commit is uninteresting or ``limit`` interesting
    commits have been emitted. Each commit is fetched once.
    """

    def __init__(self, fetch: Callable[[str], CommitInfo]):
        self._fetch = fetch
        self._commits: dict[str, CommitInfo] = {}
        self._uninteresting: dict[str, bool] = {}
        self._queued: set[str] = set()
        self._heap: list[tuple[float, int, str]] = []
        self._order = itertools.count()
        self._pending_interesting = 0
        self._emitted: list[CommitInfo] = []

    def push(self, commit_id: str, *, uninteresting: bool) -> None:
        commit = self._fetch(commit_id)
        self._commits[commit_id] = commit
        self._uninteresting[commit_id] = uninteresting
        self._queued.add(commit_id)
        heapq.heappush(self._heap, (-_commit_timestamp(commit), next(self._order), commit_id))
        if not uninteresting:
            self._pending_interesting += 1

    def _mark_uninteresting(self, commit_id: str) -> None:
        stack = [commit_id]
        while stack:
            current = stack.pop()
            if self._uninteresting.get(current, True):
                continue
            self._uninteresting[current] = True
            if current in self._queued:
                self._pending_interesting -= 1
                continue
            commit = self._commits[current]
            self._emitted = [item for item in self._emitted if item.commit_id != current]
            stack.extend(commit.parent_ids)

    def run(self, limit: int) -> list[CommitInfo]:
        while self._heap and self._pending_interesting > 0:
            _, _, commit_id = heapq.heappop(self._heap)
            self._queued.discard(commit_id)
            uninteresting = self._uninteresting[commit_id]
            commit = self._commits[commit_id]
            if not uninteresting:
                self._pending_interesting -= 1
                self._emitted.append(commit)
                if len(self._emitted) >= limit:
                    break
            for parent_id in commit.parent_ids:
                if parent_id not in self._uninteresting:
                    self.push(parent_id, uninteresting=uninteresting)
                elif uninteresting:
                    self._mark_uninteresting(parent_id)
        return self._emitted[:limit]


# --- GitHub -------------------------------------------------------------------


def _split_github_repository(repository: str) -> tuple[str, str]:
    parts = repository.split("/") if isinstance(repository, str) else []
    if (len(parts) != 2 or not all(_GITHUB_NAME.match(part) for part in parts)
            or any(part in (".", "..") for part in parts)):
        raise GitSourceError(f"GitHub repository must be 'owner/name', got {repository!r}")
    return parts[0], parts[1]


def _validate_api_url(api_url: str) -> str:
    parts = urlsplit(api_url) if isinstance(api_url, str) else None
    if (parts is None or parts.scheme != "https" or not parts.hostname or parts.username
            or parts.password or parts.query or parts.fragment):
        raise GitSourceError(f"GitHub API URL must be an https:// URL, got {api_url!r}")
    return api_url.rstrip("/")


def _validate_object_id(object_id: str) -> str:
    if not isinstance(object_id, str) or not _HEX_ID.match(object_id):
        raise GitSourceError(f"invalid git object id: {object_id!r}")
    return object_id


def is_default_github_api_url(api_url: str | None) -> bool:
    """True when ``api_url`` is unset or names ``https://api.github.com``."""
    return not api_url or api_url.strip().rstrip("/").lower() == DEFAULT_GITHUB_API_URL


def _reason_phrase(response: requests.Response) -> str:
    reason = response.reason if isinstance(response.reason, str) else ""
    return "".join(ch for ch in reason if ch.isprintable())[:100].strip()


class GitHubProvider(GitProvider):
    """The GitHub REST API (``api_url`` points at github.com or GitHub Enterprise Server)."""

    name = "github"
    max_file_bytes = GITHUB_MAX_FILE_BYTES
    supports_history = True

    COMPARE_FILE_LIMIT = 300
    PAGE_SIZE = 100
    MAX_COMMIT_FILE_PAGES = 30

    def __init__(self, repository: str, branch: str, token: str | None = None,
                 api_url: str = DEFAULT_GITHUB_API_URL, session: requests.Session | None = None,
                 request_timeout: float = 30.0):
        owner, name = _split_github_repository(repository)
        self.repository = f"{owner}/{name}"
        self.branch = _validate_branch(branch)
        self._repo_path = f"/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
        self._api_url = _validate_api_url(api_url or DEFAULT_GITHUB_API_URL)
        # Response bodies are quoted in errors only when they come from github.com.
        self._quote_error_bodies = is_default_github_api_url(self._api_url)
        self._token = token or None
        self._session = session if session is not None else guarded_session()
        self._timeout = request_timeout

    def _redact(self, text: str) -> str:
        return text.replace(self._token, "***") if self._token else text

    def _get(self, path: str, *, params: dict | None = None, raw: bool = False,
             file_path: str | None = None, stream: bool = False) -> requests.Response:
        headers = {
            "Accept": GITHUB_RAW_MEDIA_TYPE if raw else GITHUB_JSON_MEDIA_TYPE,
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            response = safe_get(self._api_url + self._repo_path + path, headers=headers,
                                params=params, timeout=self._timeout, session=self._session,
                                stream=stream)
        except (requests.RequestException, UnsafeURLError) as exc:
            raise GitSourceError(self._redact(
                f"GitHub request for {self.repository} failed: {type(exc).__name__}: {exc}")) from None
        if 200 <= response.status_code < 300:
            return response
        try:
            error = self._error_for(response, path, file_path)
        finally:
            if stream:
                release(response)
        raise error

    def _read_raw(self, path: str, *, file_path: str | None, params: dict | None = None,
                  max_bytes: int | None = None) -> bytes:
        """Raw file content; with ``max_bytes``, read no more than that many bytes."""
        if max_bytes is None:
            return self._get(path, params=params, raw=True, file_path=file_path).content
        response = self._get(path, params=params, raw=True, file_path=file_path, stream=True)
        data = bytearray()
        try:
            while len(data) < max_bytes:
                chunk = response.raw.read(min(64 * 1024, max_bytes - len(data)), decode_content=True)
                if not chunk:
                    break
                data += chunk
        except (requests.RequestException, OSError) as exc:
            raise GitSourceError(self._redact(
                f"GitHub read of {file_path or path} failed: {type(exc).__name__}: {exc}")) from None
        finally:
            release(response)
        return bytes(data[:max_bytes])

    @staticmethod
    def _error_details(response: requests.Response) -> tuple[str, list[str]]:
        try:
            body = response.json()
        except ValueError:
            return (response.text or "").strip()[:200], []
        if not isinstance(body, dict):
            return "", []
        codes = [str(item.get("code")) for item in body.get("errors") or [] if isinstance(item, dict)]
        return str(body.get("message") or ""), codes

    def _error_for(self, response: requests.Response, path: str, file_path: str | None) -> GitSourceError:
        status = response.status_code
        message, codes = self._error_details(response)
        shown = message if self._quote_error_bodies else _reason_phrase(response)
        where = f"{self.repository} {path}"
        headers = response.headers or {}
        retry_after = headers.get("Retry-After")
        if status == 429 or (status == 403 and (headers.get("X-RateLimit-Remaining") == "0"
                                                or retry_after is not None)):
            wait = self._retry_seconds(retry_after, headers.get("X-RateLimit-Reset"))
            text = "GitHub API rate limit exceeded"
            if wait is not None:
                text += f"; retry after {wait} seconds"
            return RateLimitError(self._redact(f"{text} ({where})"), retry_after=wait)
        if status == 404:
            return NotFoundError(self._redact(f"GitHub resource not found: {where}"))
        if status in (403, 422) and ("too_large" in codes or "too large" in message.lower()):
            detail = f": {shown}" if shown else ""
            return FileTooLargeError(file_path, None, GITHUB_MAX_FILE_BYTES, self._redact(
                f"{file_path or where} is too large for the GitHub API (limit 100 MB){detail}"))
        if status == 401:
            return GitSourceError(self._redact(f"GitHub rejected the credentials (401) for {where}"))
        detail = f": {shown}" if shown else ""
        return GitSourceError(self._redact(f"GitHub API error {status} for {where}{detail}"))

    @staticmethod
    def _retry_seconds(retry_after: str | None, reset: str | None) -> int | None:
        if retry_after is not None and retry_after.strip().isdigit():
            return int(retry_after.strip())
        if reset is not None and reset.strip().isdigit():
            return max(0, int(reset.strip()) - int(time.time()))
        return None

    @staticmethod
    def _json(response: requests.Response, what: str, expected: type = dict) -> Any:
        try:
            data = response.json()
        except ValueError:
            data = None
        if not isinstance(data, expected):
            raise GitSourceError(f"GitHub returned an invalid response for the {what}")
        return data

    def resolve_head(self) -> str:
        data = self._json(self._get(f"/branches/{quote(self.branch, safe='/')}"), "branch")
        sha = (data.get("commit") or {}).get("sha")
        if not sha:
            raise GitSourceError(f"GitHub branch {self.branch} has no commit")
        return sha

    def list_tree(self, commit_id: str) -> list[TreeEntry]:
        commit_id = _validate_object_id(commit_id)
        data = self._json(self._get(f"/git/trees/{commit_id}", params={"recursive": "1"}), "tree")
        if data.get("truncated"):
            raise GitSourceError(
                f"GitHub truncated the tree of {self.repository}@{commit_id}: a recursive tree "
                "listing is limited to 100,000 entries or 7 MB")
        entries = [
            TreeEntry(item["path"], item["sha"], item.get("size"))
            for item in data.get("tree") or []
            if item.get("type") == "blob" and item.get("path") and item.get("sha")
        ]
        return sorted(entries, key=lambda entry: entry.path)

    def diff(self, from_commit: str, to_commit: str) -> list[Change]:
        from_commit = _validate_object_id(from_commit)
        to_commit = _validate_object_id(to_commit)
        if from_commit == to_commit:
            return []
        try:
            data = self._json(self._get(f"/compare/{from_commit}...{to_commit}"), "comparison")
        except (NotFoundError, RateLimitError):
            raise
        except GitSourceError:
            return self._tree_diff(from_commit, to_commit)
        changes = self._changes_from_compare(data)
        if changes is None:
            return self._tree_diff(from_commit, to_commit)
        return changes

    def _changes_from_compare(self, data: Any) -> list[Change] | None:
        """Return the comparison's changes, or ``None`` when it is not a complete direct diff."""
        if not isinstance(data, dict) or data.get("status") not in ("ahead", "identical"):
            return None
        files = data.get("files")
        if not isinstance(files, list) or len(files) >= self.COMPARE_FILE_LIMIT:
            return None
        changes = []
        for item in files:
            status, filename, sha = item.get("status"), item.get("filename"), item.get("sha")
            if not filename:
                return None
            if status == "removed":
                changes.append(Change(filename, "D", None))
                continue
            if status == "unchanged":
                continue
            if not sha or status not in ("added", "copied", "modified", "changed", "renamed"):
                return None
            if status == "renamed":
                if not item.get("previous_filename"):
                    return None
                changes.append(Change(item["previous_filename"], "D", None))
            kind = "A" if status in ("added", "copied", "renamed") else "M"
            changes.append(Change(filename, kind, sha))
        return _normalize_changes(changes)

    def _tree_diff(self, from_commit: str, to_commit: str) -> list[Change]:
        before = {entry.path: entry.blob_id for entry in self.list_tree(from_commit)}
        after = {entry.path: entry.blob_id for entry in self.list_tree(to_commit)}
        return _diff_manifests(before, after)

    def read_blob(self, entry_or_blob_id: str | TreeEntry | Change, *, path: str | None = None,
                  commit_id: str | None = None, max_bytes: int | None = None) -> bytes:
        blob_id, path, size = _blob_target(entry_or_blob_id, path)
        self._ensure_within_limit(path, size)
        blob_id = _validate_object_id(blob_id)
        return self._read_raw(f"/git/blobs/{blob_id}", file_path=path, max_bytes=max_bytes)

    def read_file(self, path: str, commit_id: str, *, max_bytes: int | None = None) -> bytes:
        path = _validate_repo_path(path)
        commit_id = _validate_object_id(commit_id)
        return self._read_raw(f"/contents/{quote(path, safe='/')}", params={"ref": commit_id},
                              file_path=path, max_bytes=max_bytes)

    @staticmethod
    def _commit_info(item: dict) -> CommitInfo:
        commit = item.get("commit") or {}
        author = commit.get("author") or {}
        committer = commit.get("committer") or {}
        return CommitInfo(
            commit_id=item["sha"],
            parent_ids=tuple(parent["sha"] for parent in item.get("parents") or [] if parent.get("sha")),
            author_name=author.get("name"),
            author_email=author.get("email"),
            authored_at=_parse_iso(author.get("date")),
            committer_name=committer.get("name"),
            committer_email=committer.get("email"),
            committed_at=_parse_iso(committer.get("date")),
            message=commit.get("message") or "",
        )

    def commits_between(self, from_commit: str | None, to_commit: str, limit: int) -> list[CommitInfo]:
        to_commit = _validate_object_id(to_commit)
        if limit <= 0 or from_commit == to_commit:
            return []
        if from_commit:
            from_commit = _validate_object_id(from_commit)
            data = self._json(self._get(f"/compare/{from_commit}...{to_commit}"), "comparison")
            commits = data.get("commits") or []
            total = data.get("total_commits")
            if isinstance(total, int) and total <= len(commits):
                return [self._commit_info(item) for item in list(reversed(commits))[:limit]]
        return self._walk_commit_list(from_commit, to_commit, limit)

    def _walk_commit_list(self, from_commit: str | None, to_commit: str, limit: int) -> list[CommitInfo]:
        result: list[CommitInfo] = []
        seen: set[str] = set()
        page = 1
        while True:
            items = self._json(self._get("/commits", params={
                "sha": to_commit, "per_page": self.PAGE_SIZE, "page": page}), "commit list", list)
            for item in items:
                sha = item.get("sha")
                if not sha or sha in seen:
                    continue
                if sha == from_commit:
                    return result
                seen.add(sha)
                result.append(self._commit_info(item))
                if len(result) >= limit:
                    return result
            if len(items) < self.PAGE_SIZE:
                return result
            page += 1

    def commit_changed_paths(self, commit: CommitInfo) -> list[str]:
        commit_id = _validate_object_id(commit.commit_id)
        paths: set[str] = set()
        for page in range(1, self.MAX_COMMIT_FILE_PAGES + 1):
            data = self._json(self._get(f"/commits/{commit_id}", params={
                "per_page": self.PAGE_SIZE, "page": page}), "commit")
            files = data.get("files") or []
            for item in files:
                for key in ("filename", "previous_filename"):
                    if item.get(key):
                        paths.add(item[key])
            if len(files) < self.PAGE_SIZE:
                break
        return sorted(paths)


# --- local directory ------------------------------------------------------------


class LocalDirectoryProvider(GitProvider):
    """A directory on disk, read without any git metadata.

    Symbolic links to files inside the root are read as the file they point
    to; symbolic links resolving outside the root or into a ``.git`` path,
    and symbolic links to directories, are skipped by ``list_tree`` and
    refused by the read methods. The provider remembers the manifests of the
    ``SNAPSHOT_LIMIT`` most recent heads it computed; ``diff``, ``list_tree``
    and ``read_file`` accept a remembered head or the current head and raise
    ``GitSourceError("unknown local snapshot ...")`` for any other.

    ``allowed_roots`` (resolved directories) confines the provider: its root,
    resolved once at construction, must be one of them or inside one, and
    every file it reads resolves inside that root. ``None`` places no
    restriction on the root.

    ``include`` (the source's mapping patterns) limits what is walked and
    hashed to the directories those patterns can match: each pattern's
    leading literal directories (``policies/**/*.md`` -> ``policies/``), a
    literal file as itself, and the root's own files for a pattern without a
    directory (``*.json``); a pattern starting with a wildcard directory walks
    the whole root. Directories named in :data:`SKIP_DIRECTORIES` (``.git``,
    ``node_modules`` and the like) are never walked. Every file under a
    walked directory is listed (chunked-file parts sit beside their
    manifests). ``None`` walks the whole root.
    """

    name = "local"
    max_file_bytes = None
    supports_history = False

    SNAPSHOT_LIMIT = 32
    _CHUNK_BYTES = 1024 * 1024
    SKIP_DIRECTORIES = frozenset({"node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache",
                                  ".pytest_cache", ".ruff_cache", ".cache", ".terraform", ".next"})

    def __init__(self, root: str | os.PathLike, allowed_roots: list[str] | None = None,
                 include: list[str] | None = None):
        root_path = Path(root).expanduser()
        if not root_path.is_dir():
            raise GitSourceError(f"local git source root is not a directory: {root}")
        self.root = root_path.resolve()
        check_local_root(self.root, allowed_roots)
        self._hash_cache: dict[str, tuple[int, int, str]] = {}
        self._snapshots: OrderedDict[str, dict[str, tuple[str, int]]] = OrderedDict()
        self._walk_plan = self.walk_plan(include)

    @staticmethod
    def walk_plan(patterns: list[str] | None) -> list[tuple[str, bool]]:
        """``[(relative path, recursive)]`` to walk for ``patterns`` (class docstring)."""
        if patterns is None:
            return [("", True)]
        plan = set()
        for pattern in patterns:
            parts = [part for part in pattern.strip("/").split("/") if part]
            literal = []
            for part in parts:
                if any(char in part for char in "*?["):
                    break
                literal.append(part)
            if len(literal) == len(parts):
                plan.add(("/".join(literal), False))       # a literal file (or directory entry)
            elif literal:
                plan.add(("/".join(literal), True))
            elif len(parts) == 1:
                plan.add(("", False))                      # the root's own files
            else:
                return [("", True)]                        # a wildcard directory: walk everything
        return sorted(plan)

    # path safety

    def _safe_path(self, rel_path: str) -> Path:
        rel = _validate_repo_path(rel_path)
        if any(_is_git_component(part) for part in rel.split("/")):
            raise GitSourceError(f"{rel} is inside a .git path and is not readable")
        try:
            resolved = (self.root / rel).resolve(strict=True)
        except FileNotFoundError:
            raise NotFoundError(f"{rel} does not exist in the local source") from None
        except (OSError, RuntimeError) as exc:
            raise GitSourceError(f"cannot resolve {rel}: {exc}") from None
        if not resolved.is_relative_to(self.root):
            raise GitSourceError(f"{rel} resolves outside the local source root")
        if any(_is_git_component(part) for part in resolved.relative_to(self.root).parts):
            raise GitSourceError(f"{rel} resolves into a .git path and is not readable")
        if not resolved.is_file():
            raise NotFoundError(f"{rel} is not a file")
        return resolved

    # manifests

    def _hash(self, rel: str, target: Path, stat: os.stat_result) -> str:
        cached = self._hash_cache.get(rel)
        if cached is not None and cached[0] == stat.st_size and cached[1] == stat.st_mtime_ns:
            return cached[2]
        digest = hashlib.sha256()
        try:
            with target.open("rb") as handle:
                for chunk in iter(lambda: handle.read(self._CHUNK_BYTES), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise GitSourceError(f"cannot read {rel}: {exc.strerror or exc}") from None
        value = digest.hexdigest()
        self._hash_cache[rel] = (stat.st_size, stat.st_mtime_ns, value)
        return value

    def _add(self, manifest: dict, rel: str) -> None:
        try:
            target = self._safe_path(rel)
            stat = target.stat()
        except (GitSourceError, OSError):
            return
        manifest[rel] = (self._hash(rel, target, stat), stat.st_size)

    def _skip(self, name: str) -> bool:
        return _is_git_component(name) or name in self.SKIP_DIRECTORIES

    def _scan(self) -> dict[str, tuple[str, int]]:
        manifest: dict[str, tuple[str, int]] = {}
        for start, recursive in self._walk_plan:
            base = self.root / start if start else self.root
            if any(self._skip(part) for part in Path(start).parts):
                continue
            if base.is_file() or (start and not base.is_dir()):
                self._add(manifest, start)                 # a literal file (absent ones are skipped)
                continue
            for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
                dirnames[:] = sorted(name for name in dirnames if not self._skip(name)) if recursive else []
                for filename in sorted(filenames):
                    if not _is_git_component(filename):
                        self._add(manifest, (Path(dirpath) / filename).relative_to(self.root).as_posix())
        for stale in self._hash_cache.keys() - manifest.keys():
            del self._hash_cache[stale]
        return manifest

    @staticmethod
    def _head_for(manifest: Mapping[str, tuple[str, int]]) -> str:
        digest = hashlib.sha256()
        for path in sorted(manifest):
            digest.update(f"{path}\0{manifest[path][0]}\n".encode("utf-8", "surrogateescape"))
        return "local-" + digest.hexdigest()[:40]

    def _remember(self, head: str, manifest: dict[str, tuple[str, int]]) -> None:
        self._snapshots[head] = manifest
        self._snapshots.move_to_end(head)
        while len(self._snapshots) > self.SNAPSHOT_LIMIT:
            self._snapshots.popitem(last=False)

    def _manifest_for(self, commit_id: str) -> dict[str, tuple[str, int]]:
        if commit_id in self._snapshots:
            self._snapshots.move_to_end(commit_id)
            return self._snapshots[commit_id]
        manifest = self._scan()
        head = self._head_for(manifest)
        self._remember(head, manifest)
        if head == commit_id:
            return manifest
        raise GitSourceError(
            f"unknown local snapshot {commit_id!r}: the directory no longer matches it; "
            "list the current tree instead")

    def _read_verified(self, rel: str, blob_id: str, max_bytes: int | None = None) -> bytes:
        """The file's content, verified against ``blob_id``; with ``max_bytes``, a file
        longer than that returns its first ``max_bytes`` bytes, unverified."""
        target = self._safe_path(rel)
        try:
            if max_bytes is None:
                data = target.read_bytes()
            else:
                with target.open("rb") as handle:
                    if os.fstat(handle.fileno()).st_size > max_bytes:
                        return handle.read(max_bytes)
                    data = handle.read(max_bytes)
        except OSError as exc:
            raise GitSourceError(f"cannot read {rel}: {exc.strerror or exc}") from None
        if hashlib.sha256(data).hexdigest() != blob_id:
            raise GitSourceError(f"{rel} changed after the local tree was listed; list the tree again")
        return data

    # contract

    def resolve_head(self) -> str:
        manifest = self._scan()
        head = self._head_for(manifest)
        self._remember(head, manifest)
        return head

    def list_tree(self, commit_id: str) -> list[TreeEntry]:
        manifest = self._manifest_for(commit_id)
        return [TreeEntry(path, blob_id, size) for path, (blob_id, size) in sorted(manifest.items())]

    def diff(self, from_commit: str, to_commit: str) -> list[Change]:
        after = self._manifest_for(to_commit)
        before = self._manifest_for(from_commit)
        return _diff_manifests({path: item[0] for path, item in before.items()},
                               {path: item[0] for path, item in after.items()})

    def read_blob(self, entry_or_blob_id: str | TreeEntry | Change, *, path: str | None = None,
                  commit_id: str | None = None, max_bytes: int | None = None) -> bytes:
        blob_id, path, _ = _blob_target(entry_or_blob_id, path)
        if path is None:
            path = self._path_for_blob(blob_id, commit_id)
        return self._read_verified(path, blob_id, max_bytes)

    def _path_for_blob(self, blob_id: str, commit_id: str | None) -> str:
        if commit_id is not None and commit_id in self._snapshots:
            candidates = [self._snapshots[commit_id]]
        else:
            candidates = list(reversed(self._snapshots.values()))
        for manifest in candidates:
            for path, (candidate, _) in sorted(manifest.items()):
                if candidate == blob_id:
                    return path
        raise NotFoundError(f"blob {blob_id} is not in any listed local snapshot")

    def read_file(self, path: str, commit_id: str, *, max_bytes: int | None = None) -> bytes:
        rel = _validate_repo_path(path)
        entry = self._manifest_for(commit_id).get(rel)
        if entry is None:
            raise NotFoundError(f"{rel} is not in local snapshot {commit_id}")
        return self._read_verified(rel, entry[0], max_bytes)

    def commits_between(self, from_commit: str | None, to_commit: str, limit: int) -> list[CommitInfo]:
        return []

    def commit_changed_paths(self, commit: CommitInfo) -> list[str]:
        return []


LOCAL_SOURCES_DISABLED = (
    "local-directory git sources are disabled in production; set LOCAL_SOURCE_ROOTS to the "
    "directories they may read")


def local_source_roots() -> list[str] | None:
    """The directories local-directory sources may read, per the portal's configuration.

    Returns the resolved ``LOCAL_SOURCE_ROOTS`` directories, or ``None`` (no
    restriction) when it is unset outside production. Raises
    ``GitSourceError`` when it is unset in production, where local sources
    are disabled.
    """
    from app import runtime_config

    roots = runtime_config.local_source_roots()
    if roots is None and runtime_config.is_production():
        raise GitSourceError(LOCAL_SOURCES_DISABLED)
    return roots


def check_local_root(path: str | os.PathLike, allowed_roots: list[str] | None) -> str:
    """Return ``path`` resolved (symbolic links followed); raise ``GitSourceError``
    when ``allowed_roots`` is not ``None`` and the resolved path is neither one
    of them nor inside one."""
    real = os.path.realpath(os.path.expanduser(os.fspath(path)))
    if allowed_roots is None:
        return real
    for root in allowed_roots:
        root_real = os.path.realpath(root)
        if os.path.commonpath([real, root_real]) == root_real:
            return real
    listed = ", ".join(allowed_roots) if allowed_roots else "none"
    raise GitSourceError(
        f"local git source {os.fspath(path)} resolves to {real}, outside LOCAL_SOURCE_ROOTS ({listed})")


# --- factory ------------------------------------------------------------------------


def build_provider(provider: str, *, repository: str, branch: str, region: str | None = None,
                   boto_session=None, token: str | None = None, api_url: str | None = None,
                   request_timeout: float = 30.0, include: list[str] | None = None) -> GitProvider:
    """Build the provider named ``provider`` (``codecommit``, ``github`` or ``local``).

    - ``codecommit``: ``repository`` is the CodeCommit repository name. The
      client comes from ``boto_session`` (the portal session from
      ``app.services.aws_session.get_session`` when omitted) in ``region``.
    - ``github``: ``repository`` is ``owner/name``; ``token`` is optional for
      public repositories; ``api_url`` defaults to ``https://api.github.com``.
    - ``local``: ``repository`` is the path of an existing directory, allowed
      by :func:`local_source_roots`; ``branch`` is not used.

    Invalid input raises ``GitSourceError`` naming the problem.
    """
    kind = provider.strip().lower() if isinstance(provider, str) else ""
    if request_timeout is None or request_timeout <= 0:
        raise GitSourceError("request_timeout must be a positive number of seconds")
    if kind == "codecommit":
        if not isinstance(repository, str) or not _CODECOMMIT_REPOSITORY.match(repository):
            raise GitSourceError(f"invalid CodeCommit repository name: {repository!r}")
        _validate_branch(branch)
        if boto_session is None:
            from app.services.aws_session import get_session
            boto_session = get_session(region)
        client = boto_session.client("codecommit", region_name=region, config=BotoConfig(
            connect_timeout=request_timeout, read_timeout=request_timeout,
            retries={"mode": "standard", "max_attempts": 5}))
        return CodeCommitProvider(repository, branch, client)
    if kind == "github":
        return GitHubProvider(repository, branch, token=token, api_url=api_url or DEFAULT_GITHUB_API_URL,
                              request_timeout=request_timeout)
    if kind == "local":
        if not isinstance(repository, str) or not repository.strip():
            raise GitSourceError("a local git source needs the path of a directory")
        return LocalDirectoryProvider(repository, allowed_roots=local_source_roots(), include=include)
    raise GitSourceError(f"unsupported git provider {provider!r}; expected codecommit, github or local")
