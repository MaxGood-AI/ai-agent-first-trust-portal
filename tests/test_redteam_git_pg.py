"""Red-team fixes on PostgreSQL: decision-log versions under the audit
triggers, namespaced pentest findings, the compare-and-set sync outcome under
the scheduler's run guard, and the deadlock retry with the real driver error
(SQLSTATE 40P01)."""

import gzip
import hashlib
import json

from sqlalchemy import text

from app.models import DecisionLogEntry, DecisionLogSession, DecisionLogTranscript, PentestFinding, db
from app.services import evidence_import, team_service
from app.services.audit_chain import verify_chain
from app.services.evidence_import import import_dataset_file, import_decision_log, is_deadlock


def _jsonl(texts):
    return ("\n".join(json.dumps({
        "type": "user", "timestamp": "2026-03-16T12:00:00Z",
        "message": {"role": "user", "id": f"m{index}", "content": [{"type": "text", "text": text}]},
    }) for index, text in enumerate(texts)) + "\n").encode()


def _audit(table):
    return db.session.execute(text(
        "SELECT action, old_values, new_values FROM audit_log WHERE table_name = :t ORDER BY id"),
        {"t": table}).mappings().all()


def test_upload_versions_are_audited_with_content_digests(pg_app):
    genuine = team_service.create_member("Agent A", "a@example.com", "agent")
    other = team_service.create_member("Agent B", "b@example.com", "agent")
    client = pg_app.test_client()

    def upload(member, body):
        return client.post("/api/decision-log/upload?session_id=sess-pg", data=body,
                           headers={"X-API-Key": member.issued_api_key})

    assert upload(genuine, _jsonl(["genuine", "done."])).get_json()["status"] == "created"
    assert upload(genuine, _jsonl(["genuine", "done.", "more"])).get_json()["status"] == "replaced"
    forged = _jsonl(["forged", "x", "y", "z"])
    rejected = upload(other, forged)
    assert rejected.status_code == 409 and rejected.get_json()["status"] == "rejected"
    assert upload(other, forged).status_code == 409  # recorded once

    db.session.expire_all()
    assert [e.content_text for e in DecisionLogEntry.query.filter_by(session_id="sess-pg")
            .order_by(DecisionLogEntry.id)] == ["genuine", "done.", "more"]
    assert db.session.get(DecisionLogSession, "sess-pg").submitted_by == genuine.id
    versions = {v.status: v for v in DecisionLogTranscript.query.filter_by(session_id="sess-pg")}
    assert set(versions) == {"superseded", "current", "rejected"}
    assert gzip.decompress(versions["rejected"].content_gz) == forged

    rows = _audit("decision_log_transcripts")
    assert [r["action"] for r in rows] == ["INSERT", "UPDATE", "INSERT", "INSERT"]
    for row in rows:
        for values in (row["old_values"], row["new_values"]):
            if values and values.get("content_gz") is not None:
                assert values["content_gz"].startswith("sha256:")
    assert verify_chain(db.session)["status"] == "valid"


def test_namespaced_pentest_findings_on_postgresql(pg_app):
    scan = {"scan_id": "s", "findings": [{"summary": "same finding", "severity": "HIGH"}]}
    path = "pentest-evidence/layer1/scan.json"
    import_dataset_file("pentest-findings", path, scan, namespace="source-a")
    db.session.commit()
    import_dataset_file("pentest-findings", path, scan, namespace="source-b")
    db.session.commit()
    assert sorted(f.source_file for f in PentestFinding.query.all()) == [
        "source-a:layer1/scan.json", "source-b:layer1/scan.json"]
    import_dataset_file("pentest-findings", path, dict(scan, findings=[]), namespace="source-b")
    db.session.commit()
    assert [f.source_file for f in PentestFinding.query.all()] == ["source-a:layer1/scan.json"]


def _sync(source):
    from app.models.git_source import GitSyncRun
    from app.services import scheduler

    run, created = scheduler.enqueue_git_sync(source, "manual")
    assert created and scheduler.execute_claimed("git_sync", run.id) == "executed"
    db.session.expire_all()
    return db.session.get(GitSyncRun, run.id)


def test_sync_outcome_is_compare_and_set_under_the_run_guard(pg_app, tmp_path, monkeypatch):
    from sqlalchemy import create_engine

    from app.models.git_source import GitSource, GitSourceFile
    from app.services.git_sources import service, sync

    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "a.md").write_text("# A\n")
    (tmp_path / "policies" / "b.md").write_text("# B\n")
    source = service.create_source({"name": "gov", "role": "governance", "provider": "local",
                                    "repository": str(tmp_path)})
    first = _sync(source)
    assert first.status == "success" and first.executor_token
    assert db.session.get(GitSource, source.id).last_synced_commit == first.to_commit

    (tmp_path / "policies" / "a.md").write_text("# A2\n")
    other = create_engine(pg_app.config["SQLALCHEMY_DATABASE_URI"], isolation_level="AUTOCOMMIT")
    real = sync.process_candidate

    def taken_over(src, fetched, candidate, head, tally, member_id):
        # Another writer takes the run between two files (before this file's audited writes,
        # whose transaction holds the audit-chain lock the other writer's audit row needs).
        with other.connect() as conn:
            conn.execute(text("UPDATE git_sync_runs SET executor_token = 'someone-else' "
                              "WHERE source_id = :s AND status = 'running'"), {"s": src.id})
        real(src, fetched, candidate, head, tally, member_id)

    monkeypatch.setattr(sync, "process_candidate", taken_over)
    try:
        second = _sync(db.session.get(GitSource, source.id))
    finally:
        other.dispose()
    assert (second.status, second.executor_token) == ("running", "someone-else")
    assert db.session.get(GitSource, source.id).last_synced_commit == first.to_commit
    record = GitSourceFile.query.filter_by(source_id=source.id, path="policies/a.md").one()
    assert record.blob_id == hashlib.sha256(b"# A\n").hexdigest()  # the changed file was not written


def test_real_deadlock_error_is_detected_and_the_upload_retried(pg_app, monkeypatch):
    member = team_service.create_member("Agent", "ag@example.com", "agent")
    real = evidence_import.import_decision_log
    seen = []

    def deadlock_once(*args, **kwargs):
        if not seen:
            try:
                db.session.execute(text(
                    "DO $$ BEGIN RAISE EXCEPTION 'deadlock detected' USING ERRCODE = '40P01'; END $$"))
            except Exception as exc:  # noqa: BLE001 - the driver's real error, as the app sees it
                seen.append(exc)
                raise
        return real(*args, **kwargs)

    monkeypatch.setattr(evidence_import, "import_decision_log", deadlock_once)
    resp = pg_app.test_client().post("/api/decision-log/upload?session_id=sess-dl", data=_jsonl(["a"]),
                                     headers={"X-API-Key": member.issued_api_key})
    assert resp.status_code == 200 and resp.get_json()["status"] == "created"
    assert is_deadlock(seen[0]) and type(seen[0]).__name__ == "OperationalError"
    assert not is_deadlock(Exception())
    assert import_decision_log(_jsonl(["a"]), session_id="sess-dl").status == "unchanged"
