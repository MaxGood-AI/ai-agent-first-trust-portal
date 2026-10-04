"""Cutover coverage: sessions restored from an earlier portal (entries, no versions) are
baselined by a full re-import of the evidence source, then covered by --against-repo."""

import json

import pytest
from sqlalchemy import create_engine, text

from app.models import DecisionLogSession, db
from app.services import scheduler
from app.services.decision_log_repo_verify import verify_against_repo
from app.services.decision_log_verify import verify_decision_logs
from app.services.evidence_import import import_decision_log
from app.services.git_sources import service
from app.services.git_sources.providers import LocalDirectoryProvider
from app.services.git_sources.service import build_provider_for
from app.services.git_sources import mappings


def _rec(role, text_value, ts, msg_id):
    return json.dumps({"type": role, "timestamp": ts,
                       "message": {"role": role, "id": msg_id, "content": [{"type": "text", "text": text_value}]}})


GENUINE = "\n".join([_rec("user", "please deploy", "2026-03-16T12:00:00Z", "u1"),
                     _rec("assistant", "Please verify, then reply done.", "2026-03-16T12:05:00Z", "a1"),
                     _rec("user", "it is broken, do not ship", "2026-03-16T12:30:00Z", "u2")]) + "\n"


def _path(sid):
    return f"decision-logs/2026-03-16T120000Z_{sid}.jsonl"


def _restored(owner_url, sid):
    """A session as restored from an earlier portal: entries and session row, no versions,
    no repository_entries or content digest (those columns are new)."""
    import_decision_log(GENUINE.encode(), session_id=sid, source_path=_path(sid))
    db.session.commit()
    engine = create_engine(owner_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE decision_log_transcripts DISABLE TRIGGER USER"))
            conn.execute(text("DELETE FROM decision_log_transcripts WHERE session_id = :s"), {"s": sid})
            conn.execute(text("ALTER TABLE decision_log_transcripts ENABLE TRIGGER USER"))
            conn.execute(text("UPDATE decision_log_sessions SET repository_entries = NULL, content_sha256 = NULL, "
                              "content_bytes = NULL WHERE id = :s"), {"s": sid})
    finally:
        engine.dispose()
    db.session.expire_all()


def _entry_ids(sid):
    return [row[0] for row in db.session.execute(
        text("SELECT id FROM decision_log_entries WHERE session_id = :s ORDER BY id"), {"s": sid})]


@pytest.fixture
def cutover(pg_app, migrated_pg_url, tmp_path):
    """Restored sessions, an evidence repository and a source that starts at the freeze commit."""
    root = tmp_path / "evidence"
    (root / "decision-logs").mkdir(parents=True)
    for sid in ("same", "tampered"):
        (root / _path(sid)).write_text(GENUINE)
        _restored(migrated_pg_url, sid)
    _restored(migrated_pg_url, "orphan")            # no repository file
    source = service.create_source({"name": "evidence", "role": "evidence", "provider": "local",
                                    "repository": str(root)})
    freeze = LocalDirectoryProvider(root, include=[m["pattern"] for m in mappings.default_mappings("evidence")])
    service.set_last_synced_commit(source, freeze.resolve_head())
    db.session.commit()
    return {"source": source, "owner_url": migrated_pg_url}


def _sync(source, full):
    run, created = scheduler.enqueue_git_sync(source, "manual", None, full=full)
    assert created and scheduler.execute_claimed("git_sync", run.id) == "executed"
    db.session.expire_all()
    from app.models.git_source import GitSyncRun
    return db.session.get(GitSyncRun, run.id)


def test_baseline_restored_sessions_then_verify_against_the_repository(cutover):
    before = _entry_ids("same")
    assert _sync(cutover["source"], full=False).status == "unchanged"   # diff from the freeze: nothing
    assert verify_against_repo(db.session, build_provider_for(cutover["source"]))["versions_checked"] == 0

    run = _sync(cutover["source"], full=True)                            # the baseline
    assert run.details["decision_logs_baselined"] == 2
    assert _entry_ids("same") == before                                  # no entry rows written
    current = db.session.execute(text("SELECT source_commit, submitted_by, entry_count FROM decision_log_transcripts "
                                      "WHERE session_id = 'same' AND status = 'current'")).first()
    assert current.source_commit and current.submitted_by is None and current.entry_count == 3
    audited = db.session.execute(text("SELECT count(*) FROM audit_log WHERE table_name = 'decision_log_transcripts' "
                                      "AND action = 'INSERT'")).scalar()
    assert audited >= 2
    result = verify_against_repo(db.session, build_provider_for(cutover["source"]))
    assert result["status"] == "valid" and result["versions_checked"] == 2
    assert verify_decision_logs(db.session)["mismatches"] == []


def test_tampered_restored_session_is_a_conflict_not_a_baseline(cutover):
    engine = create_engine(cutover["owner_url"], isolation_level="AUTOCOMMIT")
    try:
        with engine.begin() as conn:
            conn.execute(text("UPDATE decision_log_entries SET content_text = 'done.', is_verification = true "
                              "WHERE id = (SELECT max(id) FROM decision_log_entries WHERE session_id = 'tampered')"))
    finally:
        engine.dispose()
    run = _sync(cutover["source"], full=True)
    assert run.details["decision_logs_baselined"] == 1                  # only the identical one
    assert {c["session_id"] for c in run.details["conflicts"]} == {"tampered"}
    session = db.session.get(DecisionLogSession, "tampered")
    assert session.conflict_at is not None
    texts = [row[0] for row in db.session.execute(
        text("SELECT content_text FROM decision_log_entries WHERE session_id = 'tampered' ORDER BY id"))]
    assert texts[-1] == "it is broken, do not ship"                     # the repository's version won
    assert verify_against_repo(db.session, build_provider_for(cutover["source"]))["status"] == "valid"


def test_session_without_a_repository_file_is_listed(cutover):
    _sync(cutover["source"], full=True)
    result = verify_against_repo(db.session, build_provider_for(cutover["source"]))
    assert result["not_in_repository_count"] == 1
    assert result["not_in_repository"][0]["session_id"] == "orphan"
    assert result["status"] == "valid"   # informational: listed, not a finding
