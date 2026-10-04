"""audit-verify --decision-logs --against-repo: the evidence repository is ground truth
for imported transcripts, so an import forged with the application role is caught."""

import io
import json
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app import runtime_config
from app.models import db
from app.services import scheduler
from app.services.decision_log_repo_verify import verify_against_repo
from app.services.decision_log_verify import verify_decision_logs
from app.services.evidence_import_decision_logs import entries_digest
from app.services.git_sources import service
from app.services.git_sources.service import build_provider_for
from app.services.transcript_ingest import parse_transcript


def _rec(role, text_value, ts, msg_id):
    return json.dumps({"type": role, "timestamp": ts,
                       "message": {"role": role, "id": msg_id, "content": [{"type": "text", "text": text_value}]}})


GENUINE = "\n".join([_rec("user", "please deploy", "2026-03-16T12:00:00Z", "u1"),
                     _rec("assistant", "Please verify, then reply done.", "2026-03-16T12:05:00Z", "a1"),
                     _rec("user", "it is broken, do not ship", "2026-03-16T12:30:00Z", "u2")]) + "\n"
DONE = _rec("user", "done.", "2026-03-16T12:31:00Z", "u-forged")
PATH = "decision-logs/2026-03-16T120000Z_s1.jsonl"


@pytest.fixture
def app_url(migrated_pg_url):
    from cli.db_cmd import provision_app_role

    role = f"tpa_{uuid.uuid4().hex[:8]}"
    url = make_url(migrated_pg_url).set(username=role, password="app-" + uuid.uuid4().hex)
    rendered = url.render_as_string(hide_password=False)
    assert provision_app_role(migrated_pg_url, rendered) is True
    return rendered


@pytest.fixture
def evidence(pg_app, tmp_path):
    root = tmp_path / "evidence"
    (root / "decision-logs").mkdir(parents=True)
    (root / PATH).write_text(GENUINE)
    source = service.create_source({"name": "evidence", "role": "evidence", "provider": "local",
                                    "repository": str(root)})
    run, created = scheduler.enqueue_git_sync(source, "manual", None)
    assert created and scheduler.execute_claimed("git_sync", run.id) == "executed"
    db.session.expire_all()
    current = db.session.execute(text("SELECT source_commit, content_sha256 FROM decision_log_transcripts "
                                      "WHERE session_id = 's1' AND status = 'current'")).first()
    assert current.source_commit and current.source_commit.startswith("local-")
    return {"source": service.find_source("evidence"), "commit": current.source_commit, "sha": current.content_sha256}


def _run(url, *statements):
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with engine.begin() as conn:  # one transaction
            for statement in statements:
                conn.execute(text(statement))
    finally:
        engine.dispose()


def _repo_check(state):
    db.session.expire_all()
    return verify_against_repo(db.session, build_provider_for(state["source"]))


def _digest(lines):
    return entries_digest(parse_transcript("\n".join(lines).encode()).entries)


def test_repo_happy_path(evidence, migrated_pg_url, monkeypatch):
    result = _repo_check(evidence)
    assert (result["status"], result["versions_checked"], result["blobs_fetched"]) == ("valid", 1, 1)
    from cli import admin_cmd
    from cli.__main__ import build_parser

    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", migrated_pg_url)
    runtime_config._reset_for_tests()
    out = io.StringIO()
    code = admin_cmd.run(build_parser().parse_args(["audit-verify", "--decision-logs", "--against-repo"]), out=out)
    assert code == 0, out.getvalue()
    assert "against_repo: status=valid versions=1 mismatches=0 missing=0 unreadable=0" in out.getvalue()


def test_repo_forged_import_in_one_transaction_is_caught(evidence, app_url):
    """The app role appends a forged entry and records a new 'repository import' version for it,
    consistent with the audit log and the version history - only the repository can refute it."""
    lines = GENUINE.strip().split("\n")
    _run(app_url, "INSERT INTO decision_log_entries (session_id, role, content_text, is_verification, message_id, "
                  "timestamp) VALUES ('s1', 'user', 'done.', true, 'u-forged', '2026-03-16T12:31:00Z')")
    _run(app_url,
         "UPDATE decision_log_transcripts SET status = 'superseded', reason = 'superseded by a longer export', "
         "content_gz = '\\x00' WHERE session_id = 's1' AND status = 'current'",
         "INSERT INTO decision_log_transcripts (id, session_id, status, content_sha256, entry_count, entries_sha256, "
         f"source_path, source_commit, received_at) VALUES ('{uuid.uuid4()}', 's1', 'current', '{evidence['sha']}', "
         f"4, '{_digest(lines + [DONE])}', '{PATH}', '{evidence['commit']}', now() + interval '1 second')")
    assert verify_decision_logs(db.session)["mismatches"] == []    # the residual: history alone accepts it
    result = _repo_check(evidence)
    assert result["status"] == "broken" and result["mismatches_count"] == 1
    assert "entries, entries_sha256 differ" in result["mismatches"][0]["issue"]


def test_repo_forged_conflict_import_is_caught(evidence, app_url):
    lines = GENUINE.strip().split("\n")
    forged = lines[:2] + [_rec("user", "done.", "2026-03-16T12:30:00Z", "u2")]
    _run(app_url,
         "UPDATE decision_log_entries SET content_text = 'done.', is_verification = true "
         "WHERE id = (SELECT max(id) FROM decision_log_entries WHERE session_id = 's1')",
         "UPDATE decision_log_transcripts SET status = 'superseded', reason = 'repository conflict: forged', "
         "content_gz = '\\x00' WHERE session_id = 's1' AND status = 'current'",
         "INSERT INTO decision_log_transcripts (id, session_id, status, content_sha256, entry_count, entries_sha256, "
         f"source_path, source_commit, received_at) VALUES ('{uuid.uuid4()}', 's1', 'current', '{evidence['sha']}', "
         f"3, '{_digest(forged)}', '{PATH}', '{evidence['commit']}', now() + interval '1 second')",
         "UPDATE decision_log_sessions SET conflict_at = now() WHERE id = 's1'")
    result = _repo_check(evidence)
    assert result["status"] == "broken"
    assert "entries_sha256 differ" in result["mismatches"][0]["issue"]


def test_repo_missing_blob_is_broken(evidence, app_url):
    _run(app_url,
         "UPDATE decision_log_transcripts SET status = 'superseded', reason = 'x', content_gz = '\\x00' "
         "WHERE session_id = 's1' AND status = 'current'",
         "INSERT INTO decision_log_transcripts (id, session_id, status, content_sha256, entry_count, entries_sha256, "
         f"source_path, source_commit, received_at) VALUES ('{uuid.uuid4()}', 's1', 'current', '{evidence['sha']}', "
         f"3, repeat('0', 64), 'decision-logs/2026-03-17T000000Z_s1.jsonl', '{evidence['commit']}', "
         "now() + interval '1 second')")
    result = _repo_check(evidence)
    assert result["status"] == "broken" and result["missing_count"] == 1
    assert result["missing"][0]["path"] == "decision-logs/2026-03-17T000000Z_s1.jsonl"


def test_repo_import_without_a_commit_is_unverifiable_and_runs_resume(evidence, pg_app):
    from app.services.evidence_import import import_decision_log

    import_decision_log(GENUINE.encode(), session_id="cli-import",
                        source_path="decision-logs/2026-03-16T120000Z_cli-import.jsonl")  # no commit
    db.session.commit()
    result = _repo_check(evidence)
    assert result["status"] == "unverified" and result["unverifiable_count"] == 1
    first = verify_against_repo(db.session, build_provider_for(evidence["source"]), max_sessions=1)
    assert first["versions_checked"] == 1 and first["next_after_session"] == "cli-import"
    rest = verify_against_repo(db.session, build_provider_for(evidence["source"]), after_session="cli-import",
                               max_sessions=1)
    assert rest["versions_checked"] == 1 and rest["status"] == "valid"


def test_repo_check_through_the_admin_api(evidence, pg_app):
    from app.services import team_service

    admin = team_service.create_member("Admin", "a@example.com", "human", is_compliance_admin=True)
    body = pg_app.test_client().get("/api/decision-log/verify?against_repo=true&max_sessions=10",
                                    headers={"X-API-Key": admin.issued_api_key}).get_json()
    assert body["status"] == "valid" and body["decision_logs"]["against_repo"]["versions_checked"] == 1
