"""Red-team final check: a transplanted repository file, a commit-less import on a
CodeCommit/GitHub source, and the listing's owner of a repository-held session."""

import json
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.models import db
from app.services import scheduler, team_service
from app.services.decision_log_repo_verify import verify_against_repo
from app.services.evidence_import import import_decision_log
from app.services.git_sources import service
from app.services.git_sources.service import build_provider_for


def _rec(role, text_value, ts, msg_id):
    return json.dumps({"type": role, "timestamp": ts,
                       "message": {"role": role, "id": msg_id, "content": [{"type": "text", "text": text_value}]}})


GENUINE = [_rec("user", "please deploy", "2026-03-16T12:00:00Z", "u1"),
           _rec("assistant", "Please verify, then reply done.", "2026-03-16T12:05:00Z", "a1"),
           _rec("user", "it is broken, do not ship", "2026-03-16T12:30:00Z", "u2")]
OTHER = [_rec("user", "done.", "2026-03-16T12:00:00Z", "v1")]


def _path(sid):
    return f"decision-logs/2026-03-16T120000Z_{sid}.jsonl"


@pytest.fixture
def app_url(migrated_pg_url):
    from cli.db_cmd import provision_app_role

    role = f"tpa_{uuid.uuid4().hex[:8]}"
    url = make_url(migrated_pg_url).set(username=role, password="app-" + uuid.uuid4().hex)
    rendered = url.render_as_string(hide_password=False)
    assert provision_app_role(migrated_pg_url, rendered) is True
    return rendered


@pytest.fixture
def synced(pg_app, tmp_path):
    root = tmp_path / "evidence"
    (root / "decision-logs").mkdir(parents=True)
    (root / _path("x")).write_text("\n".join(GENUINE) + "\n")
    (root / _path("y")).write_text("\n".join(OTHER) + "\n")
    source = service.create_source({"name": "evidence", "role": "evidence", "provider": "local",
                                    "repository": str(root)})
    run, created = scheduler.enqueue_git_sync(source, "manual", None)
    assert created and scheduler.execute_claimed("git_sync", run.id) == "executed"
    db.session.expire_all()
    y = db.session.execute(text("SELECT content_sha256, entry_count, entries_sha256, source_commit "
                                "FROM decision_log_transcripts WHERE session_id = 'y' AND status = 'current'")).first()
    return {"source": service.find_source("evidence"), "y": y}


def _run(url, *statements):
    engine = create_engine(url, isolation_level="AUTOCOMMIT")
    try:
        with engine.begin() as conn:
            for statement in statements:
                conn.execute(text(statement))
    finally:
        engine.dispose()


def _transplant_statements(y, path):
    return ["UPDATE decision_log_transcripts SET status = 'superseded', reason = 'x', content_gz = '\\x00' "
            "WHERE session_id = 'x' AND status = 'current'",
            "INSERT INTO decision_log_transcripts (id, session_id, status, content_sha256, entry_count, "
            "entries_sha256, "
            f"source_path, source_commit, received_at) VALUES ('{uuid.uuid4()}', 'x', 'current', '{y.content_sha256}', "
            f"{y.entry_count}, '{y.entries_sha256}', '{path}', '{y.source_commit}', now() + interval '1 second')"]


def test_transplant_of_another_sessions_file_is_refused_and_detected(synced, app_url, migrated_pg_url):
    y = synced["y"]
    # Write time: the guard refuses it for every role, the importer refuses it too.
    with pytest.raises(Exception, match="is not session x's file"):
        _run(app_url, *_transplant_statements(y, _path("y")))
    with pytest.raises(ValueError, match="is not session x's file"):
        import_decision_log("\n".join(OTHER).encode(), session_id="x", source_path=_path("y"), source_commit="c1")
    db.session.rollback()
    # Behind the triggers (the owner), the repository check still refuses to be fooled.
    _run(migrated_pg_url, "ALTER TABLE decision_log_transcripts DISABLE TRIGGER USER",
         *_transplant_statements(y, _path("y")), "ALTER TABLE decision_log_transcripts ENABLE TRIGGER USER")
    db.session.expire_all()
    result = verify_against_repo(db.session, build_provider_for(synced["source"]), source=synced["source"])
    assert result["status"] == "broken"
    assert result["mismatches"][0]["issue"] == "the path is not this session's file (it names another session)"


def test_path_outside_the_decision_log_mapping_is_broken(synced, migrated_pg_url):
    y = synced["y"]
    outside = "evidence/2026-03-16T120000Z_x.jsonl"   # x's name, but not a decision-log path
    _run(migrated_pg_url, *_transplant_statements(y, outside))
    db.session.expire_all()
    result = verify_against_repo(db.session, build_provider_for(synced["source"]), source=synced["source"])
    assert result["mismatches"][0]["issue"] == "the path is not under the evidence source's decision-log mapping"


def test_commit_less_import_on_a_codecommit_source_is_broken(pg_app, tmp_path):
    import_decision_log("\n".join(GENUINE).encode(), session_id="before", source_path=_path("before"))
    db.session.commit()
    source = service.create_source({"name": "evidence", "role": "evidence", "provider": "codecommit",
                                    "repository": "evidence-repo", "region": "us-east-1"})
    import_decision_log("\n".join(GENUINE).encode(), session_id="after", source_path=_path("after"))
    db.session.commit()

    class NoRepository:   # nothing is fetched: neither version records a commit
        def read_file(self, *args, **kwargs):
            raise AssertionError("not reached")

    result = verify_against_repo(db.session, NoRepository(), source=source)
    assert result["status"] == "broken"
    assert [f["session_id"] for f in result["missing_commit"]] == ["after"]
    assert [f["session_id"] for f in result["no_commit"]] == ["before"]   # before the source existed: listed


def test_listing_shows_the_repository_import_for_a_repository_held_session(pg_app):
    member = team_service.create_member("Member B", "b@example.com", "agent")
    client = pg_app.test_client()
    headers = {"X-API-Key": member.issued_api_key}
    assert client.post("/api/decision-log/upload?session_id=psq", data=GENUINE[0].encode(),
                       headers=headers).status_code in (200, 201)
    import_decision_log("\n".join(GENUINE).encode(), session_id="psq", source_path=_path("psq"))
    db.session.commit()
    items = client.get("/api/decision-log/sessions", headers=headers).get_json()["items"]
    item = next(i for i in items if i["id"] == "psq")
    assert (item["submitted_by"], item["created_by"], item["repository_held"]) == (None, member.id, True)
    detail = client.get("/api/decision-log/session/psq", headers=headers).get_json()["session"]
    assert (detail["submitted_by"], detail["created_by"], detail["repository_held"]) == (None, member.id, True)
