"""Read side of governance git sources: policy documents for the public
policy pages, and governance documents / change history for admins.

``Policy.file_path`` is resolved only against policy files synced from
governance sources (``git_source_files`` of kind ``policy``) - never against
the server's filesystem. A file is *served* when its source is enabled, its
status is ``ok`` and it has a current version. A disabled source's files are
never served, and they keep their paths and names: no other file is shown
in their place. Resolution: normalise the path (strip ``./`` and leading
``../`` segments, e.g. ``../policies/encryption.md`` ->
``policies/encryption.md``), then:

1. file records at exactly that path (in any governance source, enabled or
   disabled): the first served one, taking sources in the order they were
   created; when none is served, no document - ``retired`` when every such
   record is deleted from the repository, ``unavailable`` otherwise
   (disabled source, unreadable, too large, not UTF-8). A different file is
   never shown in its place;
2. no file record at that path: the policy files with the same file name
   that are ``ok`` with a current version, in any governance source. When
   there is exactly one, it is shown if its source is enabled
   (``unavailable`` when disabled); none, or more than one, is ``missing``.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass

from app.models import db
from app.models.git_source import GitCommit, GitFileVersion, GitSource, GitSourceFile


@dataclass
class PolicyDocument:
    path: str
    source_name: str
    commit_id: str
    sha256: str
    body: str
    metadata: dict


def normalize_policy_path(file_path: str | None) -> str | None:
    if not file_path:
        return None
    path = file_path.strip().replace("\\", "/")
    parts = [p for p in path.split("/") if p not in ("", ".")]
    while parts and parts[0] == "..":
        parts.pop(0)
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def _policy_records():
    """Policy file records of every governance source, enabled or disabled."""
    return (
        db.session.query(GitSourceFile, GitSource)
        .join(GitSource, GitSource.id == GitSourceFile.source_id)
        .filter(GitSource.role == "governance")
        .filter(GitSourceFile.kind == "policy")
        .order_by(GitSource.created_at, GitSource.name, GitSourceFile.path)
    )


def _is_served(record: GitSourceFile, source: GitSource) -> bool:
    return bool(source.enabled) and record.status == "ok" and record.current_version_id is not None


def policy_file_state(file_path: str | None):
    """Resolve a policy's file_path (see the module docstring).

    Returns ``(state, row)``: ``("published", (GitSourceFile, GitSource))``,
    ``("retired", None)``, ``("unavailable", None)`` or ``("missing", None)``
    (no path, or no synced file matches).
    """
    path = normalize_policy_path(file_path)
    if not path:
        return "missing", None
    records = _policy_records().filter(GitSourceFile.path == path).all()
    if records:
        for record, source in records:
            if _is_served(record, source):
                return "published", (record, source)
        retired = all(record.status == "deleted" for record, _ in records)
        return ("retired" if retired else "unavailable"), None
    name = posixpath.basename(path)
    matches = [
        (record, source)
        for record, source in (_policy_records().filter(GitSourceFile.status == "ok")
                               .filter(GitSourceFile.current_version_id.isnot(None)).all())
        if posixpath.basename(record.path) == name
    ]
    if len(matches) != 1:
        return "missing", None
    record, source = matches[0]
    return ("published", matches[0]) if _is_served(record, source) else ("unavailable", None)


def resolve_policy_file(file_path: str | None):
    """Return (GitSourceFile, GitSource) for a policy's file_path, or None."""
    state, row = policy_file_state(file_path)
    return row if state == "published" else None


def split_front_matter(text: str) -> tuple[dict, str]:
    import frontmatter

    try:
        post = frontmatter.loads(text)
        return dict(post.metadata), post.content
    except Exception:  # noqa: BLE001 - malformed front matter renders as plain markdown
        return {}, text


def policy_document(policy) -> PolicyDocument | None:
    resolved = resolve_policy_file(policy.file_path)
    if resolved is None:
        return None
    return _document(*resolved)


def policy_document_state(policy) -> tuple[str, PolicyDocument | None]:
    """``(state, document)`` for a policy: ``published`` with its document, or
    ``retired`` / ``unavailable`` / ``missing`` without one."""
    state, row = policy_file_state(policy.file_path)
    if state != "published":
        return state, None
    document = _document(*row)
    return ("published", document) if document else ("missing", None)


def _document(record, source) -> PolicyDocument | None:
    version = db.session.get(GitFileVersion, record.current_version_id)
    if version is None:
        return None
    metadata, body = split_front_matter(version.content)
    return PolicyDocument(path=record.path, source_name=source.name, commit_id=version.commit_id,
                          sha256=version.sha256, body=body, metadata=metadata)


def governance_files():
    """Current governance-source files (policies and documents), grouped by source."""
    rows = (
        db.session.query(GitSourceFile, GitSource)
        .join(GitSource, GitSource.id == GitSourceFile.source_id)
        .filter(GitSource.role == "governance")
        .filter(GitSourceFile.kind.in_(("policy", "governance_document")))
        .order_by(GitSource.name, GitSourceFile.path)
        .all()
    )
    versions = {}
    ids = [f.current_version_id for f, _ in rows if f.current_version_id]
    if ids:
        for version in GitFileVersion.query.filter(GitFileVersion.id.in_(ids)).all():
            versions[version.id] = version
    return [(f, s, versions.get(f.current_version_id)) for f, s in rows]


def file_versions(file_id: str):
    return (GitFileVersion.query.filter_by(file_id=file_id)
            .order_by(GitFileVersion.created_at.desc()).all())


def change_history(source_id: str | None = None, page: int = 1, per_page: int = 50):
    query = GitCommit.query
    if source_id:
        query = query.filter_by(source_id=source_id)
    return query.order_by(GitCommit.committed_at.desc().nullslast()).paginate(
        page=page, per_page=per_page, error_out=False)
