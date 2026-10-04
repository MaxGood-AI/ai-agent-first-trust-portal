"""Round 4 fixes (data stream) on PostgreSQL: decision-log entries are written
before the audited rows and audited per upload (H2), at most the slot limit of
transcripts import at once (H2), the evidence repository's conflict with an
API-squatted session is audited (M2), and a role or path-mapping change that
resets the last synced commit is audited (low).
"""

import json
import threading
import time

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from app.models import DecisionLogSession, DecisionLogTranscript, db
from app.models.git_source import GitSource
from app.services import team_service
from app.services import evidence_import_decision_logs as dl
from app.services.audit_chain import verify_chain
from app.services.evidence_import import import_decision_log
from app.services.git_sources import service

AUDIT_CHAIN_LOCK_KEY = 815000001


def _autocommit(pg_app):
    return create_engine(pg_app.config["SQLALCHEMY_DATABASE_URI"], isolation_level="AUTOCOMMIT",
                         poolclass=NullPool)


def _line(index, text_value, ts="2026-03-16T12:00:00Z"):
    return json.dumps({"type": "user", "timestamp": ts,
                       "message": {"role": "user", "id": f"m{index}",
                                   "content": [{"type": "text", "text": text_value}]}})


def _transcript(count, start=0):
    return "\n".join(_line(i, f"entry {i}") for i in range(start, start + count))


def _audit_count(engine, table=None):
    with engine.connect() as conn:
        if table is None:
            return conn.execute(text("SELECT count(*) FROM audit_log")).scalar()
        return conn.execute(text("SELECT count(*) FROM audit_log WHERE table_name = :t"), {"t": table}).scalar()


def _chain_lock_held(engine):
    with engine.connect() as conn:
        return bool(conn.execute(text(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted AND objid = :k AND objsubid = 1 "
            "AND database = (SELECT oid FROM pg_database WHERE datname = current_database())"),
            {"k": AUDIT_CHAIN_LOCK_KEY}).scalar())


def test_h2_entries_are_written_without_the_chain_lock_and_audited_per_upload(pg_app, monkeypatch):
    agent = team_service.create_member("Agent A", "a@example.com", "agent")
    db.session.remove()
    observer = _autocommit(pg_app)
    held_during_entry_batches = []
    real_write = dl._write_entries

    def observed_write(session_id, entries):
        real_write(session_id, entries)
        held_during_entry_batches.append(_chain_lock_held(observer))

    monkeypatch.setattr(dl, "_write_entries", observed_write)
    client = pg_app.test_client()
    try:
        before = _audit_count(observer)
        resp = client.post("/api/decision-log/upload?session_id=big", data=_transcript(5000),
                           headers={"X-API-Key": agent.issued_api_key})
        assert resp.status_code == 200 and resp.get_json()["status"] == "created"
        created_rows = _audit_count(observer) - before

        before = _audit_count(observer)
        resp = client.post("/api/decision-log/upload?session_id=big",
                           data=_transcript(5000) + "\n" + _transcript(3000, start=5000),
                           headers={"X-API-Key": agent.issued_api_key})
        assert resp.status_code == 200 and resp.get_json()["status"] == "replaced"
        extended_rows = _audit_count(observer) - before
    finally:
        observer.dispose()
    assert held_during_entry_batches == [False, False]
    # created: the session INSERT and its current version; replaced: the superseded version
    # UPDATE, the session UPDATE and the new current version - whatever the entry count.
    assert created_rows == 2 and extended_rows == 3
    assert _audit_count(db.engine, "decision_log_entries") == 0
    current = DecisionLogTranscript.query.filter_by(session_id="big", status="current").one()
    assert (current.entry_count, current.entries_sha256) == dl.stored_entries_digest("big")
    assert current.entry_count == 8000
    assert verify_chain(db.session)["status"] == "valid"


def test_h2_the_entries_foreign_key_is_deferrable_and_still_enforced(pg_app):
    with db.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT conname, condeferrable, condeferred FROM pg_constraint "
            "WHERE conrelid = 'public.decision_log_entries'::regclass AND contype = 'f'")).one()
    assert tuple(row) == ("fk_decision_log_entries_session", True, False)
    # A new session's entries are stored before its session row, in one transaction.
    result = import_decision_log(_transcript(3).encode(), session_id="fk", source_path=None)
    db.session.commit()
    assert result.status == "created"
    # An entry without its session still fails (at commit when deferred).
    engine = _autocommit(pg_app)
    try:
        with engine.connect() as conn:
            failed = False
            try:
                with conn.begin():
                    conn.execute(text("SET CONSTRAINTS fk_decision_log_entries_session DEFERRED"))
                    conn.execute(text("INSERT INTO decision_log_entries (session_id, role) VALUES ('nope', 'user')"))
            except Exception:  # noqa: BLE001 - the foreign-key violation at commit
                failed = True
            assert failed
    finally:
        engine.dispose()


def test_h2_uploads_over_the_slot_limit_get_429_while_others_proceed(pg_app, monkeypatch):
    keys = [team_service.create_member(f"A{i}", f"a{i}@example.com", "agent").issued_api_key for i in range(3)]
    db.session.remove()
    real_parse = dl.parse_transcript
    entered = threading.Semaphore(0)
    release = threading.Event()

    def slow_parse(content):
        entered.release()
        release.wait(10)
        return real_parse(content)

    monkeypatch.setattr(dl, "parse_transcript", slow_parse)
    monkeypatch.setattr(dl, "_import_slots", dl.ImportBudget(2 * dl.MIN_IMPORT_CHARGE))  # room for two small uploads
    results = {}

    def upload(index):
        client = pg_app.test_client()
        resp = client.post(f"/api/decision-log/upload?session_id=s{index}", data=_transcript(3),
                           headers={"X-API-Key": keys[index]})
        results[index] = (resp.status_code, resp.headers.get("Retry-After"))

    threads = [threading.Thread(target=upload, args=(i,)) for i in range(2)]
    for thread in threads:
        thread.start()
    assert entered.acquire(timeout=10) and entered.acquire(timeout=10)  # both hold a slot
    upload(2)  # a third upload while both slots are taken
    release.set()
    for thread in threads:
        thread.join(30)
    assert results[2] == (429, "5")
    assert results[0][0] == 200 and results[1][0] == 200
    db.session.remove()
    assert db.session.get(DecisionLogSession, "s2") is None


def test_m2_a_repository_conflict_is_audited(pg_app):
    squatter = team_service.create_member("Agent B", "b@example.com", "agent")
    db.session.remove()
    client = pg_app.test_client()
    genuine = _transcript(3)
    forged = _transcript(2) + "\n" + _line(9, "done.", "2026-03-16T12:06:00Z")
    resp = client.post("/api/decision-log/upload?session_id=squat", data=forged,
                       headers={"X-API-Key": squatter.issued_api_key})
    assert resp.status_code == 200
    result = import_decision_log(genuine.encode(), session_id="squat",
                                 source_path="decision-logs/2026-03-16T120000Z_squat.jsonl")
    db.session.commit()
    assert result.status == "replaced" and result.conflict
    with db.engine.connect() as conn:
        session_rows = conn.execute(text(
            "SELECT action, old_values, new_values FROM audit_log "
            "WHERE table_name = 'decision_log_sessions' AND record_id = 'squat' ORDER BY id")).all()
        version_rows = conn.execute(text(
            "SELECT action, new_values FROM audit_log WHERE table_name = 'decision_log_transcripts' "
            "ORDER BY id")).all()
    action, old, new = session_rows[-1]
    assert action == "UPDATE" and old["conflict_at"] is None and new["conflict_at"] is not None
    assert new["repository_entries"] == 3 and "entry 3" in new["conflict_detail"]
    superseded = [values for act, values in version_rows
                  if act == "UPDATE" and values["status"] == "superseded"]
    assert superseded and superseded[-1]["content_gz"].startswith("sha256:")
    assert "conflict" in superseded[-1]["reason"]
    current = [values for act, values in version_rows if act == "INSERT" and values["status"] == "current"]
    assert current[-1]["entries_sha256"] == dl.stored_entries_digest("squat")[1]
    assert verify_chain(db.session)["status"] == "valid"


def test_low_role_change_reset_of_the_last_synced_commit_is_audited(pg_app):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    admin_id = admin.id
    source = service.create_source({"name": "ev", "role": "evidence", "provider": "local",
                                    "repository": "/srv/ev"})
    source_id = source.id
    service.set_last_synced_commit(source, "a" * 40)
    headers = {"X-API-Key": admin.issued_api_key}
    resp = pg_app.test_client().put(f"/api/git-sources/{source_id}", json={"role": "governance"},
                                    headers=headers)
    assert resp.status_code == 200 and resp.get_json()["last_synced_commit"] is None
    db.session.remove()
    assert db.session.get(GitSource, source_id).last_synced_commit is None
    with db.engine.connect() as conn:
        action, changed_by, old, new = conn.execute(text(
            "SELECT action, changed_by, old_values, new_values FROM audit_log "
            "WHERE table_name = 'git_sources' AND record_id = :s ORDER BY id DESC LIMIT 1"),
            {"s": source_id}).one()
    assert action == "UPDATE" and changed_by == admin_id
    assert (old["last_synced_commit"], new["last_synced_commit"]) == ("a" * 40, None)
    assert (old["role"], new["role"]) == ("evidence", "governance")


def test_h2_import_of_a_maximal_entry_count_holds_the_chain_lock_briefly(pg_app):
    """A 50,000-entry transcript: an audited write by another connection never waits long."""
    body = "\n".join(_line(i, "x") for i in range(50_000)).encode()
    engine = _autocommit(pg_app)
    waits = []
    stop = threading.Event()

    def audited_writer():
        index = 0
        with engine.connect() as conn:
            while not stop.is_set():
                start = time.monotonic()
                conn.execute(text("INSERT INTO controls (id, name, category) VALUES (:i, 'C', 'security')"),
                             {"i": f"probe-{index}"})
                waits.append(time.monotonic() - start)
                index += 1
                time.sleep(0.01)

    writer = threading.Thread(target=audited_writer)
    writer.start()
    try:
        started = time.monotonic()
        result = import_decision_log(body, session_id="max")
        db.session.commit()
        elapsed = time.monotonic() - started
    finally:
        stop.set()
        writer.join(30)
        engine.dispose()
    assert result.status == "created" and result.entries == 50_000
    assert waits, "the audited writer made no write"
    # The import takes seconds; the chain lock is held only for its last audited rows.
    assert max(waits) < max(0.5, elapsed / 4), (max(waits), elapsed)
