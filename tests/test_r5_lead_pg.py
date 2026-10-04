"""Round 5 (PostgreSQL): the decision-log verifier cannot be re-baselined (N-C),
and the serving-role / provisioning lows."""

import io
import json
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app import runtime_config
from app.models import db
from app.services import transcript_ingest
from app.services.decision_log_verify import verify_decision_logs


@pytest.fixture
def app_url(migrated_pg_url):
    from cli.db_cmd import provision_app_role

    role = f"tpa_{uuid.uuid4().hex[:8]}"
    url = make_url(migrated_pg_url).set(username=role, password="app-" + uuid.uuid4().hex)
    rendered = url.render_as_string(hide_password=False)
    assert provision_app_role(migrated_pg_url, rendered) is True
    return rendered


def _line(index, text_value):
    return json.dumps({"type": "user", "timestamp": "2026-03-16T12:00:00Z",
                       "message": {"role": "user", "id": f"m{index}",
                                   "content": [{"type": "text", "text": text_value}]}})


def _store(session_id, count):
    transcript_ingest.ingest_from_content("\n".join(_line(i, f"entry {i}") for i in range(count)), session_id)
    db.session.expire_all()


def _run(url, *statements):
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            for statement in statements:
                conn.execute(text(statement))
    finally:
        engine.dispose()


def _issues(result):
    return [m["issue"] for m in result["mismatches"]]


def _cli(monkeypatch, url, argv):
    from cli import admin_cmd
    from cli.__main__ import build_parser

    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", url)
    runtime_config._reset_for_tests()
    out = io.StringIO()
    return admin_cmd.run(build_parser().parse_args(argv), out=out), out.getvalue()


def test_nc_honest_growth_verifies(pg_app):
    _store("s1", 3)
    _store("s1", 5)   # a longer export extends it
    _store("s1", 8)
    versions = db.session.execute(text("SELECT status, entry_count FROM decision_log_transcripts "
                                       "WHERE session_id = 's1' ORDER BY received_at, id")).all()
    assert [tuple(v) for v in versions] == [("superseded", 3), ("superseded", 5), ("current", 8)]
    assert verify_decision_logs(db.session)["mismatches"] == []


def test_nc_rebaselining_by_a_version_swap_is_detected(pg_app, migrated_pg_url, app_url, monkeypatch):
    """The red team's two app-role writes: tamper an entry, then supersede the current version
    and add a new current one whose digest matches the tampered entries."""
    from app.services.evidence_import_decision_logs import stored_entries_digest

    _store("n1", 4)
    _run(app_url, "UPDATE decision_log_entries SET content_text = 'done.', is_verification = true "
                  "WHERE id = (SELECT max(id) FROM decision_log_entries WHERE session_id = 'n1')")
    count, digest = stored_entries_digest("n1")
    db.session.rollback()
    _run(app_url,
         "UPDATE decision_log_transcripts SET status = 'superseded', reason = 'x', content_gz = '\\x00' "
         "WHERE session_id = 'n1' AND status = 'current'",
         "INSERT INTO decision_log_transcripts (id, session_id, status, entry_count, entries_sha256, received_at) "
         f"VALUES ('{uuid.uuid4()}', 'n1', 'current', {count}, '{digest}', now() + interval '1 second')")
    db.session.expire_all()
    issues = _issues(verify_decision_logs(db.session))
    assert "the superseded version is not a prefix of the current entries" in issues
    # Superseding without content or reason is refused by the guard (round 6), so the attacker supplies both.
    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-verify", "--decision-logs"])
    assert code == 1 and out.startswith("status=broken")


def test_nc_shortening_the_history_is_detected(pg_app, app_url):
    from app.services.evidence_import_decision_logs import stored_entries_digest

    _store("n2", 3)
    _store("n2", 6)
    _run(app_url, "DELETE FROM decision_log_entries WHERE session_id = 'n2' AND id IN "
                  "(SELECT id FROM decision_log_entries WHERE session_id = 'n2' ORDER BY id DESC LIMIT 2)")
    count, digest = stored_entries_digest("n2")
    db.session.rollback()
    _run(app_url,
         "UPDATE decision_log_transcripts SET status = 'superseded', reason = 'x', content_gz = '\\x00' "
         "WHERE session_id = 'n2' AND status = 'current'",
         "INSERT INTO decision_log_transcripts (id, session_id, status, entry_count, entries_sha256, received_at) "
         f"VALUES ('{uuid.uuid4()}', 'n2', 'current', {count}, '{digest}', now() + interval '1 second')")
    db.session.expire_all()
    issues = _issues(verify_decision_logs(db.session))
    assert "the entry count decreased along the version history" in issues
    assert "the superseded version is longer than the current entries" in issues


def test_nc_versions_are_history_for_every_role(pg_app, migrated_pg_url, app_url):
    _store("n3", 3)
    _store("n3", 5)
    for url in (app_url, migrated_pg_url):   # the application role and the owner alike
        for statement in (
                "UPDATE decision_log_transcripts SET entry_count = 1 WHERE session_id = 'n3' AND status = 'superseded'",
                "UPDATE decision_log_transcripts SET content_gz = '\\x00' WHERE status = 'superseded'",
                "UPDATE decision_log_transcripts SET entries_sha256 = repeat('0', 64) WHERE status = 'current'",
                "UPDATE decision_log_transcripts SET status = 'current' WHERE status = 'superseded'",
                "DELETE FROM decision_log_transcripts WHERE session_id = 'n3'",
                "TRUNCATE decision_log_transcripts CASCADE"):
            with pytest.raises(Exception, match="versions are history|permission denied"):
                _run(url, statement)


def test_nc_owner_rewriting_a_digest_behind_the_triggers_is_detected(pg_app, migrated_pg_url):
    from app.services.evidence_import_decision_logs import stored_entries_digest

    _store("n4", 3)
    _run(migrated_pg_url, "UPDATE decision_log_entries SET content_text = 'forged' "
                          "WHERE id = (SELECT min(id) FROM decision_log_entries WHERE session_id = 'n4')")
    count, digest = stored_entries_digest("n4")
    db.session.rollback()
    _run(migrated_pg_url,
         "ALTER TABLE decision_log_transcripts DISABLE TRIGGER USER",
         f"UPDATE decision_log_transcripts SET entries_sha256 = '{digest}' WHERE session_id = 'n4'",
         "ALTER TABLE decision_log_transcripts ENABLE TRIGGER USER")
    db.session.expire_all()
    assert _issues(verify_decision_logs(db.session)) == ["the version's digest is not the one the audit log recorded"]


# --------------------------------------------------------------------------
# Lows
# --------------------------------------------------------------------------

@pytest.mark.parametrize("grantee", ["app", "PUBLIC"])
def test_low_serving_role_refuses_execute_on_owner_security_definer_functions(migrated_pg_url, app_url, grantee):
    from cli.db_cmd import serving_role_problems

    assert serving_role_problems(app_url) == []
    target = f'"{make_url(app_url).username}"' if grantee == "app" else "PUBLIC"
    _run(migrated_pg_url, f"GRANT EXECUTE ON FUNCTION public.audit_witness_arm(TEXT) TO {target}")
    problems = serving_role_problems(app_url)
    assert any("may execute SECURITY DEFINER function(s) it does not own: audit_witness_arm" in p
               for p in problems), problems


def test_low_witness_publications_are_append_only_for_the_app_role(migrated_pg_url, app_url):
    _run(app_url, "INSERT INTO audit_witness_publications (published_at, head_id, row_hash, object_key, outcome) "
                  "VALUES (now(), 1, repeat('a', 64), 'chain-heads/x', 'published')")
    for statement in ("UPDATE audit_witness_publications SET outcome = 'already'",
                      "DELETE FROM audit_witness_publications",
                      "TRUNCATE audit_witness_publications"):
        with pytest.raises(Exception, match="permission denied"):
            _run(app_url, statement)


def test_low_provisioning_log_says_altered(migrated_pg_url, app_url, caplog):
    import logging

    from cli.db_cmd import provision_app_role

    with caplog.at_level(logging.INFO, logger="cli.db_cmd"):
        assert provision_app_role(migrated_pg_url, app_url) is True
    assert f"Provisioned application role {make_url(app_url).username} (altered)" in caplog.text
    assert "alterd" not in caplog.text
