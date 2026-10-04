"""Red-team round 2, git sources and decision logs, on PostgreSQL: concurrent
uploads of one session (per-session advisory lock, ON CONFLICT insert),
audited metadata and source changes, 400 (not 500) for unstorable transcript
values, no idle-in-transaction connection while the provider is called, and
the last-synced-commit compare-and-set against a concurrent writer."""

import json
import threading
import time

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from app.models import DecisionLogEntry, DecisionLogSession, DecisionLogTranscript, db
from app.models.git_source import GitSource
from app.services import chunked_files, team_service
from app.services import evidence_import_decision_logs as dl
from app.services.audit_chain import verify_chain
from app.services.git_sources import service, sync

from tests.test_round2_git import GENUINE, LOG_OK, TransactionCheckingProvider, rec


def _rec(index, text_value, ts="2026-03-16T12:00:00Z"):
    return rec("user", text_value, ts, f"m{index}")


def _autocommit(pg_app):
    return create_engine(pg_app.config["SQLALCHEMY_DATABASE_URI"], isolation_level="AUTOCOMMIT",
                         poolclass=NullPool)


class Rendezvous:
    """Lets the first of two threads wait inside a critical step until the
    other thread reaches the same step, or is seen waiting for an advisory
    lock (the step is serialised), or a timeout passes."""

    def __init__(self, engine, timeout=5.0):
        self.engine = engine
        self.timeout = timeout
        self.arrived = 0
        self.lock_waits = 0
        self.guard = threading.Lock()

    def _someone_waits_for_an_advisory_lock(self):
        with self.engine.connect() as conn:
            return bool(conn.execute(text(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted "
                "AND database = (SELECT oid FROM pg_database WHERE datname = current_database())"
            )).scalar())

    def meet(self):
        with self.guard:
            self.arrived += 1
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self.arrived >= 2:
                return
            if self._someone_waits_for_an_advisory_lock():
                with self.guard:
                    self.lock_waits += 1
                return
            time.sleep(0.02)


def _race(pg_app, bodies, session_id, key):
    results = {}

    def upload(name, body):
        client = pg_app.test_client()
        try:
            resp = client.post(f"/api/decision-log/upload?session_id={session_id}", data=body,
                               headers={"X-API-Key": key})
            results[name] = (resp.status_code, (resp.get_json(silent=True) or {}).get("status"))
        except Exception as exc:  # noqa: BLE001 - an escaped error is the finding
            results[name] = ("EXC", f"{type(exc).__name__}: {str(exc)[:200]}")

    threads = [threading.Thread(target=upload, args=(name, body)) for name, body in bodies.items()]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    return results


def _texts(session_id):
    db.session.remove()
    return [e.content_text for e in DecisionLogEntry.query.filter_by(session_id=session_id)
            .order_by(DecisionLogEntry.id)]


def test_concurrent_first_uploads_never_fail_or_duplicate(pg_app, monkeypatch):
    agent = team_service.create_member("Agent A", "a@example.com", "agent")
    engine = _autocommit(pg_app)
    rendezvous = Rendezvous(engine)
    real_parse = dl.parse_transcript

    def meeting_parse(content):
        parsed = real_parse(content)
        rendezvous.meet()
        return parsed

    monkeypatch.setattr(dl, "parse_transcript", meeting_parse)
    try:
        results = _race(pg_app, {"short": _rec(0, "first"), "long": _rec(0, "first") + "\n" + _rec(1, "second")},
                        "newrace", agent.issued_api_key)
    finally:
        engine.dispose()
    assert all(code in (200, 409) for code, _ in results.values()), results
    assert rendezvous.lock_waits == 1  # the second upload waited for the session lock
    assert sorted(status for _, status in results.values()) in (
        ["created", "replaced"], ["created", "kept_existing"]), results
    assert _texts("newrace") == ["first", "second"]
    assert DecisionLogSession.query.filter_by(id="newrace").count() == 1
    assert DecisionLogTranscript.query.filter_by(session_id="newrace", status="current").count() == 1


def test_concurrent_extensions_append_each_entry_once(pg_app, monkeypatch):
    agent = team_service.create_member("Agent A", "a@example.com", "agent")
    key = agent.issued_api_key
    base = "\n".join(_rec(i, f"t{i}") for i in range(3))
    client = pg_app.test_client()
    assert client.post("/api/decision-log/upload?session_id=race", data=base,
                       headers={"X-API-Key": key}).status_code == 200
    engine = _autocommit(pg_app)
    rendezvous = Rendezvous(engine)
    real_compare = dl._compare_with_stored

    def meeting_compare(session_id, entries):
        result = real_compare(session_id, entries)
        rendezvous.meet()
        return result

    monkeypatch.setattr(dl, "_compare_with_stored", meeting_compare)
    try:
        results = _race(pg_app, {"ext1": base + "\n" + _rec(3, "t3"),
                                 "ext2": base + "\n" + _rec(3, "t3") + "\n" + _rec(4, "t4")},
                        "race", key)
    finally:
        engine.dispose()
    monkeypatch.setattr(dl, "_compare_with_stored", real_compare)
    assert all(code == 200 for code, _ in results.values()), results
    assert _texts("race") == ["t0", "t1", "t2", "t3", "t4"]
    assert rendezvous.lock_waits == 1  # the second upload waited for the session lock
    later = base + "\n" + "\n".join(_rec(i, f"t{i}") for i in range(3, 6))
    resp = pg_app.test_client().post("/api/decision-log/upload?session_id=race", data=later,
                                     headers={"X-API-Key": key})
    assert resp.status_code == 200 and resp.get_json()["status"] == "replaced"


def _audit_rows(table, record_id):
    return db.session.execute(text(
        "SELECT action, changed_by, old_values, new_values FROM audit_log "
        "WHERE table_name = :t AND record_id = :r ORDER BY id"), {"t": table, "r": record_id}).mappings().all()


def test_session_metadata_changes_only_by_an_admin_and_audited(pg_app):
    agent = team_service.create_member("Agent A", "a@example.com", "agent")
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    ids = {"agent": agent.id, "admin": admin.id}
    keys = {"agent": agent.issued_api_key, "admin": admin.issued_api_key}
    client = pg_app.test_client()

    def upload(who, lines):
        return client.post("/api/decision-log/upload?session_id=meta", data="\n".join(lines),
                           headers={"X-API-Key": keys[who]})

    first = rec("user", "hi", "2026-03-16T12:00:00Z", "u1", cwd="/genuine")
    assert upload("agent", [first]).status_code == 200
    moved = rec("user", "hi", "2026-03-16T12:00:00Z", "u1", cwd="/forged")
    assert upload("agent", [moved, _rec(2, "x", "2026-03-16T12:01:00Z")]).status_code == 200
    db.session.remove()
    assert db.session.get(DecisionLogSession, "meta").cwd == "/genuine"
    assert all((row["new_values"] or {}).get("cwd") == "/genuine"
               for row in _audit_rows("decision_log_sessions", "meta"))

    admin_move = rec("user", "hi", "2026-03-16T12:00:00Z", "u1", cwd="/admin")
    assert upload("admin", [admin_move, _rec(2, "x", "2026-03-16T12:01:00Z"),
                            _rec(3, "y", "2026-03-16T12:02:00Z")]).status_code == 200
    db.session.remove()
    assert db.session.get(DecisionLogSession, "meta").cwd == "/admin"
    last = _audit_rows("decision_log_sessions", "meta")[-1]
    assert last["action"] == "UPDATE" and last["changed_by"] == ids["admin"]
    assert (last["old_values"]["cwd"], last["new_values"]["cwd"]) == ("/genuine", "/admin")
    assert last["new_values"]["submitted_by"] == ids["agent"]
    assert verify_chain(db.session)["status"] == "valid"


def test_unstorable_transcript_values_answer_400_not_500(pg_app):
    agent = team_service.create_member("Agent A", "a@example.com", "agent")
    pg_app.config["PROPAGATE_EXCEPTIONS"] = False
    pg_app.testing = False
    client = pg_app.test_client()
    headers = {"X-API-Key": agent.issued_api_key}
    rejected = {
        "long-role": {"type": "user", "message": {"role": "r" * 50, "content": "x"}},
        "dict-role": {"type": "user", "message": {"role": {"a": 1}, "content": "x"}},
        "dict-cwd": {"type": "user", "cwd": {"a": 1}, "message": {"role": "user", "content": "x"}},
        "long-msgid": {"type": "user", "message": {"role": "user", "id": "i" * 300, "content": "x"}},
    }
    for name, record in rejected.items():
        resp = client.post(f"/api/decision-log/upload?session_id=w-{name}", data=json.dumps(record),
                           headers=headers)
        assert resp.status_code == 400, (name, resp.get_data(as_text=True))
    stored = {
        "ts-overflow": ({"type": "user", "timestamp": "0001-01-01T00:00:00+14:00",
                         "message": {"role": "user", "content": "x"}}, "x"),
        "nul": ({"type": "user", "message": {"role": "user", "content": "a\u0000b"}}, "a�b"),
    }
    for name, (record, expected) in stored.items():
        resp = client.post(f"/api/decision-log/upload?session_id=w-{name}", data=json.dumps(record),
                           headers=headers)
        assert resp.status_code == 200, (name, resp.get_data(as_text=True))
        assert _texts(f"w-{name}") == [expected]


class IdleInTransactionProvider(TransactionCheckingProvider):
    """Also records any connection of the database left idle in a transaction."""

    def __init__(self, engine):
        super().__init__()
        self.engine = engine

    def _check(self, name):
        super()._check(name)
        with self.engine.connect() as conn:
            idle = conn.execute(text(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                "AND state LIKE 'idle in transaction%' AND pid <> pg_backend_pid()")).scalar()
        if idle:
            self.inside.append(f"{name}: {idle} connection(s) idle in transaction")


def _sync(source):
    from app.models.git_source import GitSyncRun
    from app.services import scheduler

    run, created = scheduler.enqueue_git_sync(source, "manual")
    assert created and scheduler.execute_claimed("git_sync", run.id) == "executed"
    db.session.expire_all()
    return db.session.get(GitSyncRun, run.id)


def test_no_connection_is_idle_in_transaction_while_the_provider_is_called(pg_app, monkeypatch):
    engine = _autocommit(pg_app)
    provider = IdleInTransactionProvider(engine)
    monkeypatch.setattr(sync, "build_provider_for", lambda source: provider)
    source = service.create_source({"name": "ev", "role": "evidence", "provider": "local",
                                    "repository": "/unused", "options": {"record_commits": True}})
    chunked = "decision-logs/2026-01-02T000000Z_sess-chunked.jsonl"
    manifest, parts = chunked_files.split(chunked.rsplit("/", 1)[1], "\n".join(GENUINE).encode(), part_size=100)
    files = {"controls.json": json.dumps([{"id": "c1", "name": "MFA", "tsc_category": "security"}]),
             LOG_OK: GENUINE[0], LOG_OK.replace(".jsonl", ".meta.json"): json.dumps({"reason": "clear"}),
             chunked + chunked_files.MANIFEST_SUFFIX: manifest}
    files.update({f"decision-logs/{name}": data for name, data in parts})
    provider.commit("c1", files)
    try:
        first = _sync(source)
        files[LOG_OK] = "\n".join(GENUINE[:2])
        files.pop("controls.json")
        provider.commit("c2", files)
        second = _sync(db.session.get(GitSource, source.id))
    finally:
        engine.dispose()
    assert first.status == "success" and second.status == "success", (first.details, second.details)
    assert provider.inside == []


def test_repository_change_resets_the_last_synced_commit_audited(pg_app):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    admin_id = admin.id
    source_id = service.create_source({"name": "gov", "role": "governance", "provider": "local",
                                       "repository": "/srv/gov"}, member_id=admin_id).id
    client = pg_app.test_client()
    headers = {"X-API-Key": admin.issued_api_key}
    assert client.post(f"/api/git-sources/{source_id}/last-synced-commit", json={"commit_id": "a" * 40},
                       headers=headers).status_code == 200
    assert client.put(f"/api/git-sources/{source_id}", json={"branch": "main", "schedule_cron": "0 * * * *"},
                      headers=headers).get_json()["last_synced_commit"] == "a" * 40
    resp = client.put(f"/api/git-sources/{source_id}", json={"branch": "release"}, headers=headers)
    assert resp.status_code == 200 and resp.get_json()["last_synced_commit"] is None
    db.session.remove()
    assert db.session.get(GitSource, source_id).last_synced_commit is None
    last = _audit_rows("git_sources", source_id)[-1]
    assert last["action"] == "UPDATE" and last["changed_by"] == admin_id
    assert (last["old_values"]["last_synced_commit"], last["new_values"]["last_synced_commit"]) == ("a" * 40, None)
    assert (last["old_values"]["branch"], last["new_values"]["branch"]) == ("main", "release")


def test_a_finishing_sync_keeps_a_commit_set_by_another_connection(pg_app, tmp_path, monkeypatch):
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "a.md").write_text("# A\n")
    source = service.create_source({"name": "gov", "role": "governance", "provider": "local",
                                    "repository": str(tmp_path)})
    first = _sync(source)
    (tmp_path / "policies" / "a.md").write_text("# A2\n")
    other = _autocommit(pg_app)
    cutover = "c" * 40
    real = sync.process_candidate

    def admin_sets_commit(src, fetched, candidate, head, tally, member_id):
        with other.connect() as conn:  # committed before this file's audited writes begin
            conn.execute(text("UPDATE git_sources SET last_synced_commit = :c WHERE id = :s"),
                         {"c": cutover, "s": src.id})
        real(src, fetched, candidate, head, tally, member_id)

    monkeypatch.setattr(sync, "process_candidate", admin_sets_commit)
    try:
        second = _sync(db.session.get(GitSource, source.id))
    finally:
        other.dispose()
    assert second.status == "success" and second.from_commit == first.to_commit
    stored = db.session.get(GitSource, source.id)
    assert stored.last_synced_commit == cutover and stored.last_sync_status == "success"
