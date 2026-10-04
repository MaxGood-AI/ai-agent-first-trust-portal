"""Verify stored decision-log entries against their audited version history.

``decision_log_entries`` is not audited row by row. Each stored transcript
version (``decision_log_transcripts``, audited) records ``entry_count`` and
``entries_sha256``, the digest of its entries
(``evidence_import_decision_logs.entries_digest``). A session's versions
(``current`` and ``superseded``; ``rejected`` uploads are not part of its
history), in the order received, must form a history that only grows:

1. exactly one version is ``current``, and the stored entries hash to its
   ``entry_count`` and ``entries_sha256``;
2. every superseded version since the last repository-conflict replacement
   is a PREFIX of the current entries: its digest equals the digest of the
   first ``entry_count`` stored entries, and entry counts never decrease
   along the history. The one permitted non-prefix step is a genuine
   repository conflict: a version superseded with a reason starting
   ``repository conflict:`` whose successor is a repository import
   (``source_path`` set, ``submitted_by`` NULL) and - on PostgreSQL - whose
   supersession, the successor's creation and the session's ``conflict_at``
   were recorded by the audit log in one transaction. Any other step with
   that reason is reported and treated as an ordinary step;
3. a superseded version carries its content (``content_gz``) and reason;
4. on PostgreSQL, each version's history in the audit log is: created
   (INSERT) with the digest and count it still has, then at most one change,
   ``current`` to ``superseded``; nothing else (superseded versions are
   immutable - migration 018's guard refuses any other change, for every
   role), and the stored ``content_gz`` of a superseded version is the one
   the audit log recorded when it was superseded. A version created directly
   as ``superseded`` is accepted only as a session's first version (a
   session stored before versions were recorded).

A version without a recorded digest (a session stored before digests
existed) is counted as ``unrecorded`` and its prefix check is skipped.

``python -m cli audit-verify --decision-logs`` runs it (a mismatch makes the
status ``broken``).
"""

from __future__ import annotations

import hashlib

from sqlalchemy import text

MAX_REPORTED = 100
CONFLICT_PREFIX = "repository conflict:"


def _history(session, version_ids: list[str]) -> dict[str, list]:
    rows = session.execute(text(
        "SELECT record_id, action, new_values->>'status' AS status, "
        "new_values->>'entries_sha256' AS digest, new_values->>'entry_count' AS count, "
        "new_values->>'content_gz' AS content, changed_at FROM audit_log "
        "WHERE table_name = 'decision_log_transcripts' AND record_id = ANY(:ids) ORDER BY id"),
        {"ids": version_ids}).all()
    history: dict[str, list] = {}
    for row in rows:
        history.setdefault(row.record_id, []).append(row)
    return history


def _check_history(version, first: bool, events: list, issue) -> None:
    if not events or events[0].action != "INSERT":
        issue(version, "the audit log has no record of this version's creation")
        return
    created = events[0]
    digests = [e.digest for e in events if e.digest]
    if version.entries_sha256 and (not digests or digests[0] != version.entries_sha256):
        issue(version, "the version's digest is not the one the audit log recorded")
    if created.count is not None and str(version.entry_count) != created.count:
        issue(version, "the version's entry count is not the one the audit log recorded")
    changes = events[1:]
    if created.status == "current":
        allowed = len(changes) <= 1 and all(e.action == "UPDATE" and e.status == "superseded" for e in changes)
        superseded_by = changes[-1] if changes else None
    else:
        allowed = created.status == "superseded" and first and not changes
        superseded_by = created
    if not allowed:
        issue(version, "the version changed after it was recorded (versions are history)")
        return
    if version.status == "superseded":
        if superseded_by is None:
            issue(version, "the version is superseded but the audit log never recorded it so")
        elif version.content_gz is not None and superseded_by.content != \
                "sha256:" + hashlib.sha256(bytes(version.content_gz)).hexdigest():
            issue(version, "the superseded version's content is not the one the audit log recorded")


def _conflict_times(session, session_id: str) -> set:
    """When the audit log recorded the session's ``conflict_at`` being set."""
    return {row[0] for row in session.execute(text(
        "SELECT changed_at FROM audit_log WHERE table_name = 'decision_log_sessions' AND record_id = :s "
        "AND new_values->>'conflict_at' IS NOT NULL "
        "AND (old_values IS NULL OR old_values->>'conflict_at' IS DISTINCT FROM new_values->>'conflict_at')"),
        {"s": session_id})}


def _conflict_step(version, successor, history, conflict_times, postgres: bool, issue) -> bool:
    """True when ``version`` -> ``successor`` is a genuine repository conflict (module docstring)."""
    if version.status != "superseded" or not (version.reason or "").startswith(CONFLICT_PREFIX):
        return False
    if not successor.source_path or successor.submitted_by is not None:
        issue(version, "a repository-conflict step whose successor is not a repository import")
        return False
    if postgres:
        superseded = [e.changed_at for e in history.get(version.id, [])[1:] if e.status == "superseded"]
        created = [e.changed_at for e in history.get(successor.id, [])[:1] if e.action == "INSERT"]
        if not superseded or not created or superseded[-1] != created[0] or created[0] not in conflict_times:
            issue(version, "a repository-conflict step not recorded as one repository import "
                           "(supersession, successor and session conflict in one transaction)")
            return False
    return True


def _check_session(session, session_id: str, postgres: bool, issue) -> int:
    """Check one session; returns the number of versions without a recorded digest."""
    from app.services.evidence_import_decision_logs import _canonical_entry, _entry_key, _stored_rows

    versions = session.execute(text(
        "SELECT id, status, entry_count, entries_sha256, content_gz, reason, source_path, submitted_by "
        "FROM decision_log_transcripts "
        "WHERE session_id = :s AND status IN ('current', 'superseded') ORDER BY received_at, id"),
        {"s": session_id}).all()
    unrecorded = sum(1 for v in versions if v.entries_sha256 is None)
    current = [v for v in versions if v.status == "current"]
    if len(current) != 1:
        issue(versions[-1], f"the session has {len(current)} current versions (exactly one expected)")
    history = _history(session, [v.id for v in versions]) if postgres else {}
    for index, version in enumerate(versions):
        if postgres:
            _check_history(version, index == 0, history.get(version.id, []), issue)
    conflict_times = _conflict_times(session, session_id) if postgres else set()
    genuine = {index for index, version in enumerate(versions[:-1])
               if _conflict_step(version, versions[index + 1], history, conflict_times, postgres, issue)}
    for version in versions:
        if version.status == "superseded" and (version.content_gz is None or not version.reason):
            issue(version, "the superseded version has no content or reason")

    last_conflict = max(genuine, default=-1)
    for index, (earlier, later) in enumerate(zip(versions, versions[1:])):
        if index not in genuine and later.entry_count < earlier.entry_count:
            issue(later, "the entry count decreased along the version history")
    if len(current) != 1 or versions[-1].status != "current":
        return unrecorded
    wanted: dict[int, list] = {}
    for version in versions[last_conflict + 1:-1]:
        if version.status == "superseded" and version.entries_sha256:
            wanted.setdefault(version.entry_count, []).append(version)
    digest, count = hashlib.sha256(), 0

    def compare_prefix():
        for version in wanted.pop(count, []):
            if digest.hexdigest() != version.entries_sha256:
                issue(version, "the superseded version is not a prefix of the current entries")

    compare_prefix()
    for row in _stored_rows(session_id):
        digest.update(_canonical_entry(_entry_key(*row)))
        count += 1
        if count in wanted:
            compare_prefix()
    for missing in wanted.values():
        for version in missing:
            issue(version, "the superseded version is longer than the current entries")
    head = versions[-1]
    if head.entries_sha256 and (count, digest.hexdigest()) != (head.entry_count, head.entries_sha256):
        issue(head, "stored entries differ from the version's recorded digest")
    return unrecorded


def verify_decision_logs(session, *, progress=None, after_session: str | None = None,
                         max_sessions: int | None = None) -> dict:
    """Check every session's version history and stored entries (module docstring);
    ``after_session`` / ``max_sessions`` bound and resume a run (``next_after_session``)."""
    postgres = session.get_bind().dialect.name == "postgresql"
    session_ids = session.execute(text(
        "SELECT DISTINCT session_id FROM decision_log_transcripts WHERE status IN ('current', 'superseded') "
        "AND session_id > :after ORDER BY session_id" + (" LIMIT :limit" if max_sessions is not None else "")),
        {"after": after_session or "", "limit": max_sessions}).scalars().all()
    mismatches, unrecorded = [], 0
    for done, session_id in enumerate(session_ids, 1):
        def issue(version, message, session_id=session_id):
            mismatches.append({"session_id": session_id, "version_id": version.id, "status": version.status,
                               "entry_count": version.entry_count, "issue": message})

        unrecorded += _check_session(session, session_id, postgres, issue)
        if progress:
            progress(done)
    return {"sessions_checked": len(session_ids), "unrecorded": unrecorded, "mismatch_count": len(mismatches),
            "mismatches": mismatches[:MAX_REPORTED],
            "next_after_session": session_ids[-1] if max_sessions is not None and len(session_ids) >= max_sessions
            else None}
