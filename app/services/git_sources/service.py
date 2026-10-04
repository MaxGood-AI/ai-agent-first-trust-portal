"""Git source configuration: validation, persistence, serialization and
provider construction. Shared by the API, the admin UI and the CLI.

Credential modes
----------------
codecommit
    ``runtime_role`` (default): the portal's runtime AWS session.
    ``assume_role``: assume ``credentials.role_arn`` (optional
    ``credentials.external_id``) from the runtime session.
github
    ``portal_secret`` (default): ``GITHUB_TOKEN`` from the environment or
    the portal secret, sent only to ``https://api.github.com``.
    ``stored_token``: ``credentials.token``, stored Fernet-encrypted
    (requires ``COLLECTOR_ENCRYPTION_KEYS``). ``none``: public repository.
    ``options.api_url`` (GitHub Enterprise Server) other than
    ``https://api.github.com`` requires ``stored_token`` or ``none``.
local
    ``none``. The directory must be allowed by ``LOCAL_SOURCE_ROOTS``
    (``providers.local_source_roots``); in production local sources need it.

The local-directory and ``api_url`` rules are checked when a source is
created or updated (``GitSourceConfigError``) and again when a sync builds
its provider (``GitSourceError``, which fails the run).

An update that changes which repository a source reads - its provider,
repository, branch, CodeCommit region or GitHub ``api_url`` - or which of
its files it reads and as what - its ``role`` or its effective
``path_mappings`` - clears ``last_synced_commit``, so the next sync
compares the branch head's tree with the stored files (importing files
that became mapped, marking deleted those no longer mapped) instead of
diffing from a commit of another repository or only reading files that
changed since. ``git_sources`` is audited, so the reset is recorded with
the update and attributed to its author.

Stored credentials are never returned by any serializer.
"""

from __future__ import annotations

import re
import uuid
from urllib.parse import urlsplit

from app.models import db
from app.models.git_source import CREDENTIAL_MODES, PROVIDERS, ROLES, GitSource
from app.services.git_sources import mappings as mapping_rules

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
CODECOMMIT_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
GITHUB_REPO_RE = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$|^local-[0-9a-f]{40}$")
DEFAULT_HISTORY_LIMIT = 500
FIELDS = ("name", "role", "provider", "repository", "branch", "region", "credential_mode",
          "credentials", "schedule_cron", "enabled", "path_mappings", "options")


class GitSourceConfigError(ValueError):
    pass


API_URL_MODE_MESSAGE = (
    "options.api_url other than https://api.github.com requires credential_mode stored_token "
    "or none; the portal's GITHUB_TOKEN is only sent to https://api.github.com")


def _check_local_directory(repository: str) -> None:
    from app.services.git_sources.providers import GitSourceError, check_local_root, local_source_roots

    try:
        check_local_root(repository, local_source_roots())
    except GitSourceError as exc:
        raise GitSourceConfigError(str(exc)) from None


def _check_github_api_url(source: GitSource) -> None:
    from app.services.git_sources.providers import is_default_github_api_url

    api_url = (source.options or {}).get("api_url")
    if (source.provider == "github" and not is_default_github_api_url(api_url)
            and source.credential_mode not in ("stored_token", "none")):
        raise GitSourceConfigError(API_URL_MODE_MESSAGE)


def default_credential_mode(provider: str) -> str:
    return CREDENTIAL_MODES[provider][0]


def default_options(role: str) -> dict:
    return {"record_commits": role == "governance", "history_limit": DEFAULT_HISTORY_LIMIT}


def effective_options(source: GitSource) -> dict:
    options = default_options(source.role)
    options.update(source.options or {})
    return options


def find_source(identifier: str) -> GitSource | None:
    """Look a source up by id or by unique name."""
    source = db.session.get(GitSource, identifier)
    if source is None:
        source = GitSource.query.filter_by(name=identifier).first()
    return source


def _validate_repository(provider: str, repository: str) -> None:
    if provider == "codecommit":
        if not CODECOMMIT_REPO_RE.match(repository) or repository.endswith(".git"):
            raise GitSourceConfigError("repository must be a CodeCommit repository name")
    elif provider == "github":
        if not GITHUB_REPO_RE.match(repository) or repository.split("/")[1] in (".", ".."):
            raise GitSourceConfigError("repository must be a GitHub owner/name")
    elif provider == "local":
        if not repository.startswith("/"):
            raise GitSourceConfigError("repository must be an absolute directory path")


def _validate_options(options) -> dict | None:
    if options is None:
        return None
    if not isinstance(options, dict):
        raise GitSourceConfigError("options must be an object")
    clean = {}
    for key, value in options.items():
        if value is None:
            clean[key] = None  # remove the option (back to its default)
            if key not in ("record_commits", "history_limit", "api_url"):
                raise GitSourceConfigError(f"unknown option: {key}")
        elif key == "record_commits":
            clean[key] = bool(value)
        elif key == "history_limit":
            try:
                limit = int(value)
            except (TypeError, ValueError) as exc:
                raise GitSourceConfigError("options.history_limit must be an integer") from exc
            if not 1 <= limit <= 10_000:
                raise GitSourceConfigError("options.history_limit must be between 1 and 10000")
            clean[key] = limit
        elif key == "api_url":
            parts = urlsplit(value) if isinstance(value, str) else None
            if (parts is None or parts.scheme != "https" or not parts.hostname
                    or parts.username or parts.password or parts.query or parts.fragment):
                raise GitSourceConfigError(
                    "options.api_url must be an https:// URL without credentials, query or fragment")
            clean[key] = value.rstrip("/")
        else:
            raise GitSourceConfigError(f"unknown option: {key}")
    return clean


def repository_identity(source) -> tuple:
    """What decides which repository and branch a source reads."""
    from app.services.git_sources.providers import is_default_github_api_url

    api_url = (source.options or {}).get("api_url")
    return (
        source.provider,
        source.repository,
        source.branch,
        source.region if source.provider == "codecommit" else None,
        None if source.provider != "github" or is_default_github_api_url(api_url) else api_url,
    )


def reading_identity(source) -> tuple:
    """What decides which files of the repository a source reads, and as what."""
    return (source.role, mapping_rules.effective_mappings(source))


def apply_config(source: GitSource, data: dict, *, creating: bool, member_id: str | None = None) -> GitSource:
    """Validate ``data`` (a subset of FIELDS) and apply it to ``source``.

    Clears ``last_synced_commit`` when the update changes the source's
    ``repository_identity`` or ``reading_identity``.
    """
    from app.services.scheduler import parse_cron

    identity_before = None if creating else repository_identity(source)
    reading_before = None if creating else reading_identity(source)
    unknown = set(data) - set(FIELDS)
    if unknown:
        raise GitSourceConfigError(f"unknown field(s): {', '.join(sorted(unknown))}")
    if creating:
        for required in ("name", "role", "provider", "repository"):
            if not data.get(required):
                raise GitSourceConfigError(f"{required} is required")

    if "name" in data:
        name = str(data["name"]).strip()
        if not NAME_RE.match(name):
            raise GitSourceConfigError("name must be 1-100 letters, digits, '.', '_' or '-'")
        clash = GitSource.query.filter(GitSource.name == name, GitSource.id != source.id).first()
        if clash:
            raise GitSourceConfigError(f"a git source named {name!r} already exists")
        source.name = name
    if "role" in data:
        if data["role"] not in ROLES:
            raise GitSourceConfigError(f"role must be one of {', '.join(ROLES)}")
        source.role = data["role"]
    if "provider" in data:
        if data["provider"] not in PROVIDERS:
            raise GitSourceConfigError(f"provider must be one of {', '.join(PROVIDERS)}")
        source.provider = data["provider"]
    if "repository" in data:
        repository = str(data["repository"]).strip()
        if not repository:
            raise GitSourceConfigError("repository is required")
        source.repository = repository
    if "repository" in data or "provider" in data:
        _validate_repository(source.provider, source.repository)
    if "branch" in data or creating:
        branch = str(data.get("branch") or "").strip() or "main"
        if not BRANCH_RE.match(branch) or ".." in branch or branch.endswith((".", "/", ".lock")):
            raise GitSourceConfigError(f"invalid branch name: {branch!r}")
        source.branch = branch
    if "region" in data:
        source.region = (str(data["region"]).strip() or None) if data["region"] else None
    previous_mode = None if creating else source.credential_mode
    if "credential_mode" in data or creating:
        mode = data.get("credential_mode") or default_credential_mode(source.provider)
        if mode not in CREDENTIAL_MODES[source.provider]:
            raise GitSourceConfigError(
                f"credential_mode for {source.provider} must be one of "
                f"{', '.join(CREDENTIAL_MODES[source.provider])}")
        source.credential_mode = mode
    elif source.credential_mode not in CREDENTIAL_MODES.get(source.provider, ()):
        raise GitSourceConfigError(
            f"credential_mode {source.credential_mode} is not valid for provider {source.provider}")
    if "schedule_cron" in data:
        cron = (data["schedule_cron"] or "").strip() or None
        if cron and parse_cron(cron) is None:
            raise GitSourceConfigError(f"invalid cron expression: {cron}")
        source.schedule_cron = cron
    if "enabled" in data:
        source.enabled = bool(data["enabled"])
    elif creating:
        source.enabled = True
    if "path_mappings" in data:
        try:
            source.path_mappings = mapping_rules.validate_mappings(data["path_mappings"])
        except ValueError as exc:
            raise GitSourceConfigError(str(exc)) from exc
    if "options" in data:
        changes = _validate_options(data["options"])
        if changes is None:
            source.options = None
        else:
            merged = dict(source.options or {})
            for key, value in changes.items():
                if value is None:
                    merged.pop(key, None)
                else:
                    merged[key] = value
            source.options = merged or None

    _check_github_api_url(source)
    if source.provider == "local" and (creating or "repository" in data or "provider" in data
                                       or data.get("enabled")):
        _check_local_directory(source.repository)

    _apply_credentials(source, data.get("credentials"),
                       mode_changed=creating or source.credential_mode != previous_mode)

    if identity_before is not None and source.last_synced_commit is not None and (
            repository_identity(source) != identity_before or reading_identity(source) != reading_before):
        source.last_synced_commit = None

    if member_id:
        if creating:
            source.created_by_id = member_id
        source.updated_by_id = member_id
    return source


def _apply_credentials(source: GitSource, credentials, *, mode_changed: bool) -> None:
    from app.services.collector_encryption import CollectorEncryptionError, encrypt_credentials

    mode = source.credential_mode
    if mode in ("runtime_role", "portal_secret", "none"):
        source.encrypted_credentials = None
        return
    if credentials is None:
        if mode_changed or source.encrypted_credentials is None:
            needed = "credentials.role_arn" if mode == "assume_role" else "credentials.token"
            raise GitSourceConfigError(f"{needed} is required for credential_mode {mode}")
        return
    if not isinstance(credentials, dict):
        raise GitSourceConfigError("credentials must be an object")
    if mode == "assume_role":
        role_arn = str(credentials.get("role_arn", "")).strip()
        if not role_arn.startswith("arn:"):
            raise GitSourceConfigError("credentials.role_arn must be an IAM role ARN")
        payload = {"role_arn": role_arn}
        if credentials.get("external_id"):
            payload["external_id"] = str(credentials["external_id"])
    else:  # stored_token
        token = str(credentials.get("token", "")).strip()
        if not token:
            raise GitSourceConfigError("credentials.token is required")
        payload = {"token": token}
    try:
        source.encrypted_credentials = encrypt_credentials(payload)
    except CollectorEncryptionError as exc:
        raise GitSourceConfigError(str(exc)) from exc


def create_source(data: dict, member_id: str | None = None) -> GitSource:
    source = GitSource(id=str(uuid.uuid4()))
    apply_config(source, data, creating=True, member_id=member_id)
    db.session.add(source)
    db.session.commit()
    return source


def update_source(source: GitSource, data: dict, member_id: str | None = None) -> GitSource:
    try:
        apply_config(source, data, creating=False, member_id=member_id)
    except GitSourceConfigError:
        db.session.rollback()
        raise
    db.session.commit()
    return source


def set_last_synced_commit(source: GitSource, commit_id: str, member_id: str | None = None) -> GitSource:
    """Cutover support: the next sync diffs from ``commit_id``.

    A sync already running when this is set finishes without moving the
    value (its outcome is recorded compare-and-set on the commit it started
    from).
    """
    commit_id = (commit_id or "").strip().lower()
    if not COMMIT_RE.match(commit_id):
        raise GitSourceConfigError("commit_id must be a full commit SHA (40 or 64 hex characters)")
    source.last_synced_commit = commit_id
    if member_id:
        source.updated_by_id = member_id
    db.session.commit()
    return source


def serialize_source(source: GitSource) -> dict:
    from app.services.scheduler import next_run_time

    upcoming = next_run_time(source.schedule_cron) if source.enabled else None
    return {
        "id": source.id,
        "name": source.name,
        "role": source.role,
        "provider": source.provider,
        "repository": source.repository,
        "branch": source.branch,
        "region": source.region,
        "credential_mode": source.credential_mode,
        "has_stored_credentials": source.encrypted_credentials is not None,
        "path_mappings": source.path_mappings,
        "effective_path_mappings": mapping_rules.effective_mappings(source),
        "options": effective_options(source),
        "schedule_cron": source.schedule_cron,
        "next_run_at": upcoming.isoformat() if upcoming else None,
        "enabled": source.enabled,
        "last_synced_commit": source.last_synced_commit,
        "last_synced_at": source.last_synced_at.isoformat() if source.last_synced_at else None,
        "last_sync_status": source.last_sync_status,
        "created_at": source.created_at.isoformat() if source.created_at else None,
        "updated_at": source.updated_at.isoformat() if source.updated_at else None,
    }


def serialize_run(run) -> dict:
    return {
        "id": run.id,
        "source_id": run.source_id,
        "trigger_type": run.trigger_type,
        "triggered_by_team_member_id": run.triggered_by_team_member_id,
        "status": run.status,
        "from_commit": run.from_commit,
        "to_commit": run.to_commit,
        "queued_at": run.queued_at.isoformat() if run.queued_at else None,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "files_changed": run.files_changed,
        "counts": run.counts or {},
        "details": run.details or {},
        "error_message": run.error_message,
    }


def build_provider_for(source: GitSource):
    """Construct the provider for ``source`` with its resolved credentials.

    Raises ``GitSourceError`` when the source breaks the local-directory or
    ``api_url`` rules (see the module docstring).
    """
    from app.runtime_config import env
    from app.services.collector_encryption import decrypt_credentials
    from app.services.git_sources.providers import GitSourceError, build_provider, is_default_github_api_url

    options = effective_options(source)
    if source.provider == "codecommit":
        from app.services.aws_session import get_session, session_with_refreshable_role

        session = get_session(source.region)
        if source.credential_mode == "assume_role":
            creds = decrypt_credentials(source.encrypted_credentials)
            session = session_with_refreshable_role(
                session, creds["role_arn"], external_id=creds.get("external_id"),
                session_name=f"trust-portal-git-{source.name}"[:64], region=source.region)
        return build_provider("codecommit", repository=source.repository, branch=source.branch,
                              region=source.region, boto_session=session)
    if source.provider == "github":
        token = None
        if source.credential_mode == "portal_secret":
            if not is_default_github_api_url(options.get("api_url")):
                raise GitSourceError(API_URL_MODE_MESSAGE)
            token = env("GITHUB_TOKEN")
        elif source.credential_mode == "stored_token":
            token = decrypt_credentials(source.encrypted_credentials).get("token")
        return build_provider("github", repository=source.repository, branch=source.branch,
                              token=token, api_url=options.get("api_url"))
    from app.services.git_sources.mappings import effective_mappings

    return build_provider("local", repository=source.repository, branch=source.branch,
                          include=[mapping["pattern"] for mapping in effective_mappings(source)])
