"""Round 5 fixes (data stream), on PostgreSQL: the emoji transcript probe's
memory (N-A) and the audit trail of a prefix-squat conflict (N-B).
"""

import gc
import json
import tracemalloc

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from app.models import DecisionLogEntry, db
from app.services import team_service
from app.services.evidence_import import import_decision_log

MIB = 1024 * 1024


def _rec(role, text_value, ts, msg_id):
    return json.dumps({"type": role, "timestamp": ts,
                       "message": {"role": role, "id": msg_id, "content": [{"type": "text", "text": text_value}]}})


GENUINE = [_rec("user", "please deploy", "2026-03-16T12:00:00Z", "u1"),
           _rec("assistant", "Please verify, then reply done.", "2026-03-16T12:05:00Z", "a1"),
           _rec("user", "it is broken, do not ship", "2026-03-16T12:30:00Z", "u2")]
FORGED_DONE = _rec("user", "done.", "2026-03-16T12:31:00Z", "u-forged")


def _emoji_probe():
    """The red team's probe: four tool_use lines of 4-byte characters, each under 8 MiB (~32 MiB)."""
    chars = (8 * MIB - 400) // 4
    lines = [json.dumps({"type": "assistant", "timestamp": "2026-03-16T12:00:01Z",
                         "message": {"role": "assistant", "id": f"E{i}",
                                     "content": [{"type": "tool_use", "id": f"t{i}", "name": "x",
                                                  "input": {"s": "\U0001F600" * chars}}]}}, ensure_ascii=False)
             for i in range(4)]
    return ("\n".join(lines) + "\n").encode()


def test_na_emoji_probe_upload_peak_memory_is_bounded(pg_app):
    key = team_service.create_member("Agent A", "a@example.com", "agent").issued_api_key
    db.session.remove()
    body = _emoji_probe()
    client = pg_app.test_client()
    gc.collect()
    tracemalloc.start()
    try:
        resp = client.post("/api/decision-log/upload?session_id=emoji", data=body, headers={"X-API-Key": key})
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert resp.status_code == 200 and resp.get_json()["entries"] == 4
    # Everything the upload allocates (request copy, body, parsed entries, SQL) stays within a few
    # times the body; the ASCII-escaped tool calls took over ten times.
    assert peak < 5 * len(body), peak / len(body)
    stored = db.session.query(db.func.sum(db.func.octet_length(DecisionLogEntry.tool_calls))).scalar()
    assert stored < len(body)


def test_na_an_unpaired_surrogate_in_a_tool_call_is_stored(pg_app):
    key = team_service.create_member("Agent A", "a@example.com", "agent").issued_api_key
    db.session.remove()
    line = ('{"type":"assistant","message":{"role":"assistant","id":"s1","content":'
            '[{"type":"tool_use","id":"t","name":"x","input":{"s":"\\ud800 café"}}]}}')
    resp = pg_app.test_client().post("/api/decision-log/upload?session_id=sur", data=line.encode(),
                                     headers={"X-API-Key": key})
    assert resp.status_code == 200
    stored = DecisionLogEntry.query.filter_by(session_id="sur").one().tool_calls
    assert "\\ud800 café" in stored


def test_nb_prefix_squat_conflict_is_audited(pg_app):
    squatter = team_service.create_member("Agent B", "b@example.com", "agent")
    key, squatter_id = squatter.issued_api_key, squatter.id
    db.session.remove()
    client = pg_app.test_client()
    resp = client.post("/api/decision-log/upload?session_id=sq", data="\n".join(GENUINE + [FORGED_DONE]),
                       headers={"X-API-Key": key})
    assert resp.status_code == 200
    engine = create_engine(pg_app.config["SQLALCHEMY_DATABASE_URI"], poolclass=NullPool)
    try:
        with engine.connect() as conn:
            before = conn.execute(text("SELECT max(id) FROM audit_log")).scalar()

        path = "decision-logs/2026-03-16T120000Z_sq.jsonl"
        result = import_decision_log("\n".join(GENUINE).encode(), source_path=path)
        db.session.commit()
        assert (result.status, result.conflict) == ("replaced", True)

        with engine.connect() as conn:
            rows = conn.execute(text(
                "SELECT table_name, action, old_values, new_values FROM audit_log WHERE id > :id ORDER BY id"),
                {"id": before}).all()
            entries = conn.execute(text(
                "SELECT count(*), count(*) FILTER (WHERE is_verification) FROM decision_log_entries "
                "WHERE session_id = 'sq'")).one()
    finally:
        engine.dispose()
    assert tuple(entries) == (3, 0)
    session_rows = [(action, old, new) for table, action, old, new in rows if table == "decision_log_sessions"]
    assert len(session_rows) == 1
    action, old, new = session_rows[0]
    assert action == "UPDATE" and old["conflict_at"] is None and new["conflict_at"] is not None
    assert old["submitted_by"] == squatter_id and new["submitted_by"] is None
    assert "stored entries 4 to 4" in new["conflict_detail"] and new["repository_entries"] == 3
    versions = [(action, new) for table, action, _, new in rows if table == "decision_log_transcripts"]
    assert [(action, new["status"]) for action, new in versions] == [("UPDATE", "superseded"), ("INSERT", "current")]
    superseded, current = versions[0][1], versions[1][1]
    assert superseded["reason"].startswith("repository conflict: ") and superseded["entry_count"] == 4
    assert superseded["submitted_by"] == squatter_id and superseded["content_gz"].startswith("sha256:")
    assert (current["entry_count"], current["submitted_by"], current["source_path"]) == (3, None, path)
