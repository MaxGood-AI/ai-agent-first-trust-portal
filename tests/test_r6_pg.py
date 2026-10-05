"""Round 6 (PostgreSQL): the repository-owned append window (N-B), the forged
conflict step (N-C), empty repository files, and audit-verify-archive's
unchecked verdict."""

import io
import json
import os
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app import runtime_config
from app.models import DecisionLogEntry, db
from app.services import team_service
from app.services.decision_log_verify import verify_decision_logs
from app.services.evidence_import import import_decision_log


def _rec(role, text_value, ts, msg_id):
    return json.dumps({"type": role, "timestamp": ts,
                       "message": {"role": role, "id": msg_id, "content": [{"type": "text", "text": text_value}]}})


GENUINE = [_rec("user", "please deploy", "2026-03-16T12:00:00Z", "u1"),
           _rec("assistant", "Please verify, then reply done.", "2026-03-16T12:05:00Z", "a1"),
           _rec("user", "it is broken, do not ship", "2026-03-16T12:30:00Z", "u2")]
DONE = _rec("user", "done.", "2026-03-16T12:31:00Z", "u-forged")


@pytest.fixture
def app_url(migrated_pg_url):
    from cli.db_cmd import provision_app_role

    role = f"tpa_{uuid.uuid4().hex[:8]}"
    url = make_url(migrated_pg_url).set(username=role, password="app-" + uuid.uuid4().hex)
    rendered = url.render_as_string(hide_password=False)
    assert provision_app_role(migrated_pg_url, rendered) is True
    return rendered


def _upload(client, member, sid, lines):
    return client.post(f"/api/decision-log/upload?session_id={sid}", data="\n".join(lines).encode(),
                       headers={"X-API-Key": member.issued_api_key})


def _repo(sid, lines):
    result = import_decision_log("\n".join(lines).encode(), session_id=sid,
                                 source_path=f"decision-logs/2026-03-16T120000Z_{sid}.jsonl")
    db.session.commit()
    return result


def _run(url, *statements):
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with engine.begin() as conn:  # one transaction
            for statement in statements:
                conn.execute(text(statement))
    finally:
        engine.dispose()


def _listing(client, member, sid):
    items = client.get("/api/decision-log/sessions?per_page=100",
                       headers={"X-API-Key": member.issued_api_key}).get_json()["items"]
    return next(item for item in items if item["id"] == sid)


# --------------------------------------------------------------------------
# N-B: once the repository has imported a session, only the repository extends it
# --------------------------------------------------------------------------

def test_nb_member_append_after_the_repository_import_is_refused(pg_app):
    client = pg_app.test_client()
    member = team_service.create_member("Member B", "b@example.com", "agent")
    admin = team_service.create_member("Admin", "a@example.com", "human", is_compliance_admin=True)
    assert _upload(client, member, "window", GENUINE[:1]).status_code in (200, 201)
    assert _repo("window", GENUINE).status == "replaced"           # the repository extends it
    before = db.session.execute(text("SELECT count(*) FROM audit_log")).scalar()

    response = _upload(client, member, "window", GENUINE + [DONE])   # the append window
    assert response.status_code == 409, response.get_json()
    assert "the evidence repository or the evidence store holds this session; only they may extend it" \
        in response.get_json()["error"]
    admin_done = _rec("user", "done. (admin)", "2026-03-16T12:32:00Z", "u-admin")
    assert _upload(client, admin, "window", GENUINE + [admin_done]).status_code == 409
    db.session.expire_all()
    rejected = db.session.execute(text("SELECT count(*) FROM decision_log_transcripts "
                                       "WHERE session_id = 'window' AND status = 'rejected'")).scalar()
    assert rejected == 2
    assert db.session.execute(text("SELECT count(*) FROM audit_log")).scalar() > before  # audited
    item = _listing(client, member, "window")
    assert item["entry_count"] == 3 and item["verifications"] == 0 and item["conflict"] is False
    assert _repo("window", GENUINE + [DONE]).status == "replaced"   # the repository still may


def test_nb_entries_after_the_repository_supplied_ones_never_count(pg_app):
    client = pg_app.test_client()
    member = team_service.create_member("Member B", "b@example.com", "agent")
    _repo("legacy", GENUINE)
    # An entry stored after the repository's (e.g. before this rule existed).
    db.session.add(DecisionLogEntry(session_id="legacy", role="user", content_text="done.", is_verification=True))
    db.session.commit()
    item = _listing(client, member, "legacy")
    assert item["entry_count"] == 4 and item["verifications"] == 0
    detail = client.get("/api/decision-log/session/legacy", headers={"X-API-Key": member.issued_api_key}).get_json()
    assert [(e["unconfirmed"], e["is_verification"]) for e in detail["entries"]] == [
        (False, False), (False, False), (False, False), (True, False)]


def test_low_empty_repository_file_for_a_squatted_session_is_a_conflict(pg_app):
    client = pg_app.test_client()
    member = team_service.create_member("Member B", "b@example.com", "agent")
    assert _upload(client, member, "empty", GENUINE + [DONE]).status_code in (200, 201)
    result = _repo("empty", [json.dumps({"type": "summary", "summary": "metadata only"})])
    assert (result.status, result.conflict) == ("replaced", True)
    item = _listing(client, member, "empty")
    assert item["conflict"] is True and item["entry_count"] == 0 and item["verifications"] == 0
    assert verify_decision_logs(db.session)["mismatches"] == []


# --------------------------------------------------------------------------
# N-C: a forged "repository conflict" step
# --------------------------------------------------------------------------

def _forge(app_url, sid, *, source_path=None, conflict=False):
    """Tamper an entry, supersede the current version with a conflict reason, insert a matching current one."""
    from app.services.evidence_import_decision_logs import stored_entries_digest

    _run(app_url, "UPDATE decision_log_entries SET content_text = 'done.', is_verification = true "
                  f"WHERE id = (SELECT max(id) FROM decision_log_entries WHERE session_id = '{sid}')")
    count, digest = stored_entries_digest(sid)
    db.session.rollback()
    path = f"'{source_path}'" if source_path else "NULL"
    statements = [
        "UPDATE decision_log_transcripts SET status = 'superseded', reason = 'repository conflict: forged', "
        f"content_gz = '\\x00' WHERE session_id = '{sid}' AND status = 'current'",
        "INSERT INTO decision_log_transcripts (id, session_id, status, entry_count, entries_sha256, source_path, "
        f"received_at) VALUES ('{uuid.uuid4()}', '{sid}', 'current', {count}, '{digest}', {path}, "
        "now() + interval '1 second')"]
    if conflict:
        statements.append(f"UPDATE decision_log_sessions SET conflict_at = now() WHERE id = '{sid}'")
    _run(app_url, *statements)
    db.session.expire_all()


@pytest.mark.parametrize("variant", ["bare", "as_repository_import"])
def test_nc_forged_conflict_step_is_detected(pg_app, app_url, variant):
    _repo(f"forged-{variant}", GENUINE)
    if variant == "bare":
        _forge(app_url, "forged-bare")
        expected = "a repository-conflict step whose successor is not a repository import"
    else:  # even with a repository-looking successor, without the session's conflict in that transaction
        _forge(app_url, "forged-as_repository_import", source_path="decision-logs/x.jsonl")
        expected = ("a repository-conflict step not recorded as one repository import "
                    "(supersession, successor and session conflict in one transaction)")
    issues = [m["issue"] for m in verify_decision_logs(db.session)["mismatches"]]
    assert expected in issues
    assert "the superseded version is not a prefix of the current entries" in issues


def test_nc_genuine_repository_conflict_verifies(pg_app):
    client = pg_app.test_client()
    member = team_service.create_member("Member B", "b@example.com", "agent")
    assert _upload(client, member, "real", GENUINE[:2] + [DONE]).status_code in (200, 201)
    result = _repo("real", GENUINE)
    assert (result.status, result.conflict) == ("replaced", True)
    assert verify_decision_logs(db.session)["mismatches"] == []


def test_nc_current_and_superseded_versions_are_frozen(pg_app, app_url, migrated_pg_url):
    _repo("frozen", GENUINE)
    for url in (app_url, migrated_pg_url):
        for statement in (
                "UPDATE decision_log_transcripts SET reason = 'repository conflict: x' WHERE session_id = 'frozen'",
                "UPDATE decision_log_transcripts SET content_gz = '\\x00' WHERE session_id = 'frozen'",
                "UPDATE decision_log_transcripts SET status = 'superseded' WHERE session_id = 'frozen'"):
            with pytest.raises(Exception, match="versions are history"):
                _run(url, statement)


# --------------------------------------------------------------------------
# audit-verify-archive without the witness or a manifest is not "verified"
# --------------------------------------------------------------------------

def test_low_archive_check_without_witness_or_manifest_is_not_verified(migrated_pg_url, monkeypatch):
    from cli import admin_cmd
    from cli.__main__ import build_parser

    monkeypatch.delenv("AUDIT_WITNESS_BUCKET", raising=False)
    runtime_config._reset_for_tests()
    dump = os.path.join(os.path.dirname(__file__), "fixtures", "audit_archive", "portal.dump")
    out = io.StringIO()
    code = admin_cmd.run(build_parser().parse_args(
        ["audit-verify-archive", "--dump", dump, "--scratch-url", migrated_pg_url]), out=out)
    assert code == 4
    text_out = out.getvalue()
    assert text_out.startswith("NOT VERIFIED") and "not checked against the witness" in text_out
    assert "not checked against an archive manifest" in text_out
