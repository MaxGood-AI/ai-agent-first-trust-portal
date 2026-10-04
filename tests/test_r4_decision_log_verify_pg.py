"""Decision-log entries are no longer audited row by row (H2); their integrity
is checked against the digest each audited transcript version recorded."""

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


def _store(session_id, count=3):
    transcript_ingest.ingest_from_content("\n".join(_line(i, f"entry {i}") for i in range(count)), session_id)


def _as_app_role(app_url, *statements):
    engine = create_engine(app_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            for statement in statements:
                conn.execute(text(statement))
    finally:
        engine.dispose()


def _cli(monkeypatch, url, argv):
    from cli import admin_cmd
    from cli.__main__ import build_parser

    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", url)
    runtime_config._reset_for_tests()
    out = io.StringIO()
    return admin_cmd.run(build_parser().parse_args(argv), out=out), out.getvalue()


def test_h2_stored_entries_verify_against_their_audited_digest(pg_app):
    _store("s-clean")
    _store("s-other", count=5)
    result = verify_decision_logs(db.session)
    assert result == {"sessions_checked": 2, "unrecorded": 0, "mismatch_count": 0, "mismatches": [],
                      "next_after_session": None}


def test_h2_entry_changed_by_the_app_role_is_detected(pg_app, migrated_pg_url, app_url, monkeypatch):
    _store("s-tampered")
    before = db.session.execute(text("SELECT count(*) FROM audit_log")).scalar()
    _as_app_role(app_url, "UPDATE decision_log_entries SET content_text = 'forged' "
                          "WHERE id = (SELECT min(id) FROM decision_log_entries)")
    db.session.expire_all()
    assert db.session.execute(text("SELECT count(*) FROM audit_log")).scalar() == before  # not audited per row
    result = verify_decision_logs(db.session)
    assert result["mismatch_count"] == 1
    assert result["mismatches"][0]["issue"] == "stored entries differ from the version's recorded digest"
    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-verify", "--decision-logs"])
    assert code == 1 and out.startswith("status=broken")
    assert "decision_logs: checked=1 unrecorded=0 mismatches=1" in out


def test_h2_digest_rewritten_to_cover_changed_entries_is_detected(pg_app, app_url):
    from app.services.evidence_import_decision_logs import stored_entries_digest

    _store("s-covered")
    _as_app_role(app_url, "DELETE FROM decision_log_entries WHERE id = (SELECT max(id) FROM decision_log_entries)")
    count, digest = stored_entries_digest("s-covered")
    db.session.rollback()
    # Rewriting the version's digest to cover the change is refused (versions are history, migration 018)...
    with pytest.raises(Exception, match="versions are history"):
        _as_app_role(app_url, f"UPDATE decision_log_transcripts SET entry_count = {count}, "
                              f"entries_sha256 = '{digest}' WHERE session_id = 's-covered' AND status = 'current'")
    db.session.expire_all()
    # ...so the removed entry is still detected.
    result = verify_decision_logs(db.session)
    assert [m["issue"] for m in result["mismatches"]] == [
        "stored entries differ from the version's recorded digest"]
