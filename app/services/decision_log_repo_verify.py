"""Check decision-log versions against the evidence repository itself
(``python -m cli audit-verify --decision-logs --against-repo``,
``GET /api/decision-log/verify?against_repo=true``).

The audit log shows what the portal recorded; it cannot show that a version
the portal recorded as a repository import really came from the repository,
because the application role that performs imports could also forge one. The
evidence repository is controlled independently of the portal, so it is the
ground truth for imported transcripts: every version recorded as a repository
import (``submitted_by`` NULL, ``source_path`` set; a superseded one only with a
recorded commit: git-sync imports and the
successors of ``repository conflict:`` steps alike) is fetched from the
configured evidence git source at the commit the version records
(``source_commit``), through the source's provider (chunked transcripts
reassembled), and must match the version exactly:

- the file's SHA-256 is the version's ``content_sha256``;
- its entries (parsed as an import parses them) number ``entry_count`` and
  hash to ``entries_sha256`` - so the stored entries, which the base
  verifier checks against ``entries_sha256``, are the repository's.

The version's path must also be ITS OWN session's file - the importer's
derivation (``<timestamp>_<session id>.jsonl``) gives the version's session
id - and lie under the source's decision-log mapping (a chunked transcript
through its manifest), so a forged import cannot borrow another session's
genuine file (the importer and migration 018's guard refuse such a version
at write time too).

Findings, each reported individually and each making the result ``broken``:
``mismatches`` (the repository holds something else, or the path is not the
session's decision-log file), ``missing`` (the commit or path is not in the
repository), ``unreadable`` (the provider could not read or parse it) and
``missing_commit`` (a version recorded after a CodeCommit or GitHub evidence
source was configured that names no commit). The legitimately unverifiable cases are listed
separately - ``no_commit`` (``cli import``, the local ingest, or a version
recorded before the evidence source was configured or while it is a local
directory) and ``local_history`` (a commit a local-directory source no
longer holds: it keeps no history) - and make the result ``unverified``. A
SOC 2 evidence run requires both to be 0 (status ``valid``). A stored session
with no repository-import version at all - never imported from the
repository, so not in it (an API-only session, or one restored from an
earlier portal that a full re-import did not find) - is listed separately as
``not_in_repository`` (informational).

A full re-import of the evidence source (``python -m cli git-source sync
--name <source> --full``, or "Full re-import" in the admin UI) baselines the
sessions the repository holds identically (a repository-import version with
the commit, no entry rows written) and applies the conflict rules to the
others, so that every session in the repository is covered.

Each (commit, path) is fetched once (cached), by at most ``workers`` threads
at a time; sessions are checked in id order, and ``after_session`` /
``max_sessions`` bound and resume a run (``next_after_session``).
"""

from __future__ import annotations

import hashlib
import posixpath
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import text

MAX_REPORTED = 100
DEFAULT_WORKERS = 2


def evidence_source(name: str | None = None):
    """The evidence git source to check against (``name``, or the only evidence source)."""
    from app.models.git_source import GitSource

    query = GitSource.query.filter_by(role="evidence")
    if name:
        query = query.filter((GitSource.name == name) | (GitSource.id == name))
    sources = query.all()
    if len(sources) != 1:
        raise LookupError("name the evidence git source to check against (--source)" if sources
                          else "no evidence git source is configured")
    return sources[0]


def _read(provider, commit: str, path: str) -> bytes:
    """The transcript at ``path`` in ``commit``: the file, or its reassembled chunks."""
    from app.services import chunked_files
    from app.services.git_sources.providers import NotFoundError

    try:
        return provider.read_file(path, commit)
    except NotFoundError:
        manifest_path = path + chunked_files.MANIFEST_SUFFIX
        manifest = chunked_files.parse_manifest(provider.read_file(manifest_path, commit))
        directory = posixpath.dirname(path)

        def read_part(name: str, max_bytes: int) -> bytes:
            return provider.read_file(posixpath.join(directory, name) if directory else name, commit,
                                      max_bytes=max_bytes)

        return chunked_files.reassemble(manifest, read_part)


def _fingerprint(provider, commit: str, path: str) -> dict:
    """``{"sha256", "entries", "entries_sha256"}`` of the repository's transcript, or ``{"error", "kind"}``."""
    from app.services.evidence_import_decision_logs import entries_digest
    from app.services.git_sources.providers import GitSourceError, NotFoundError
    from app.services.transcript_ingest import parse_transcript

    try:
        content = _read(provider, commit, path)
    except NotFoundError as exc:
        return {"kind": "missing", "error": str(exc)[:300]}
    except GitSourceError as exc:
        kind = "unverifiable" if "unknown local snapshot" in str(exc) else "unreadable"
        return {"kind": kind, "error": str(exc)[:300]}
    except Exception as exc:  # noqa: BLE001 - reported per version, never a crash
        return {"kind": "unreadable", "error": f"{type(exc).__name__}: {str(exc)[:300]}"}
    try:
        parsed = parse_transcript(content)
    except Exception as exc:  # noqa: BLE001
        return {"kind": "unreadable", "error": f"not a readable transcript: {type(exc).__name__}"}
    return {"sha256": hashlib.sha256(content).hexdigest(), "entries": len(parsed.entries),
            "entries_sha256": entries_digest(parsed.entries)}


def verify_against_repo(session, provider, *, source=None, after_session: str | None = None,
                        max_sessions: int | None = None, workers: int = DEFAULT_WORKERS) -> dict:
    """Check every repository-import version (module docstring). ``source`` (the
    evidence ``GitSource``) supplies the decision-log mapping and when and as what
    the source was configured."""
    from app.services import chunked_files
    from app.services.evidence_import_decision_logs import session_id_from_path
    from app.services.git_sources.mappings import classify, effective_mappings

    patterns = effective_mappings(source) if source is not None else None
    strict_since = source.created_at if source is not None and source.provider != "local" else None

    def belongs(version) -> str | None:
        if session_id_from_path(version.source_path) != version.session_id:
            return "the path is not this session's file (it names another session)"
        if patterns is not None and "decision_log" not in (
                classify(version.source_path, patterns),
                classify(version.source_path + chunked_files.MANIFEST_SUFFIX, patterns)):
            return "the path is not under the evidence source's decision-log mapping"
        return None
    window = session.execute(text(
        "SELECT id, transcript_path FROM decision_log_sessions WHERE id > :after ORDER BY id"
        + (" LIMIT :limit" if max_sessions is not None else "")),
        {"after": after_session or "", "limit": max_sessions}).all()
    ids = [row.id for row in window]
    versions = session.execute(text(
        "SELECT id, session_id, status, content_sha256, entry_count, entries_sha256, source_path, source_commit, "
        "received_at "
        "FROM decision_log_transcripts WHERE status IN ('current', 'superseded') AND submitted_by IS NULL "
        "AND source_path IS NOT NULL AND (source_commit IS NOT NULL OR status = 'current') "
        "AND session_id = ANY(:ids) ORDER BY session_id, received_at, id"),
        {"ids": ids}).all() if ids else []
    imported = {v.session_id for v in versions}
    not_in_repository = [{"session_id": row.id, "transcript_path": row.transcript_path} for row in window
                         if row.id not in imported]
    session.rollback()  # no snapshot is held while the repository answers

    targets = sorted({(v.source_commit, v.source_path) for v in versions if v.source_commit and not belongs(v)})
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        fingerprints = dict(zip(targets, pool.map(lambda t: _fingerprint(provider, *t), targets)))

    found = {"mismatches": [], "missing": [], "unreadable": [], "missing_commit": [], "no_commit": [],
             "local_history": []}
    for version in versions:
        item = {"session_id": version.session_id, "version_id": version.id, "status": version.status,
                "path": version.source_path, "commit": version.source_commit}
        wrong_path = belongs(version)
        if wrong_path:
            found["mismatches"].append(dict(item, issue=wrong_path))
            continue
        if not version.source_commit:
            received = version.received_at
            if strict_since is not None and received is not None and \
                    (received if received.tzinfo else received.replace(tzinfo=strict_since.tzinfo)) >= strict_since:
                found["missing_commit"].append(dict(item, issue="a repository import recorded after the evidence "
                                                                "source was configured names no commit"))
            else:
                found["no_commit"].append(dict(item, issue="the version records no repository commit"))
            continue
        fingerprint = fingerprints[(version.source_commit, version.source_path)]
        if "kind" in fingerprint:
            kind = "local_history" if fingerprint["kind"] == "unverifiable" else fingerprint["kind"]
            found[kind].append(dict(item, issue=fingerprint["error"]))
            continue
        differences = [name for name, stored in (("sha256", version.content_sha256),
                                                 ("entries", version.entry_count),
                                                 ("entries_sha256", version.entries_sha256))
                       if fingerprint[name] != stored]
        if differences:
            found["mismatches"].append(dict(item, issue="the repository holds a different transcript "
                                                        f"({', '.join(differences)} differ)"))
    broken = found["mismatches"] or found["missing"] or found["unreadable"] or found["missing_commit"]
    unverifiable = len(found["no_commit"]) + len(found["local_history"])
    status = "broken" if broken else ("unverified" if unverifiable else "valid")
    result = {"status": status, "sessions": len(ids), "versions_checked": len(versions),
              "unverifiable_count": unverifiable,
              "blobs_fetched": len(targets),
              "not_in_repository": not_in_repository[:MAX_REPORTED], "not_in_repository_count": len(not_in_repository),
              "next_after_session": ids[-1] if max_sessions is not None and len(ids) >= max_sessions else None}
    for name, items in found.items():
        result[name] = items[:MAX_REPORTED]
        result[f"{name}_count"] = len(items)
    return result
