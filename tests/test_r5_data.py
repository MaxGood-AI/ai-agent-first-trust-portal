"""Round 5 fixes (data stream), on SQLite: transcript memory amplification
(N-A: tool calls stored at their size, tool-call limits, a byte-weighted
import budget) and the evidence repository's authority over a session whose
API version continues the repository's (N-B: prefix squat).
"""

import gzip
import json
import threading
import time
import tracemalloc

import pytest

from app import create_app
from app.config import TestConfig
from app.models import DecisionLogEntry, DecisionLogSession, DecisionLogTranscript, db
from app.services import evidence_import_decision_logs as dl
from app.services import team_service, transcript_ingest
from app.services.evidence_import import import_decision_log

MIB = 1024 * 1024
REPO_PATH = "decision-logs/2026-03-16T120000Z_{}.jsonl"


@pytest.fixture
def app(monkeypatch):
    for name in ("COLLECTOR_ENCRYPTION_KEYS", "COLLECTOR_ENCRYPTION_KEY", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def rec(role, text, ts, msg_id, **extra):
    record = {"type": role, "message": {"role": role, "id": msg_id,
                                        "content": [{"type": "text", "text": text}]}}
    if ts is not None:
        record["timestamp"] = ts
    record.update(extra)
    return json.dumps(record)


def tool_rec(msg_id, tool_input, ts="2026-03-16T12:00:01Z", ensure_ascii=False):
    return json.dumps({"type": "assistant", "timestamp": ts,
                       "message": {"role": "assistant", "id": msg_id,
                                   "content": [{"type": "tool_use", "id": f"t-{msg_id}", "name": "x",
                                                "input": tool_input}]}}, ensure_ascii=ensure_ascii)


GENUINE = [
    rec("user", "please deploy", "2026-03-16T12:00:00Z", "u1", cwd="/genuine", gitBranch="main"),
    rec("assistant", "Please verify, then reply done.", "2026-03-16T12:05:00Z", "a1"),
    rec("user", "it is broken, do not ship", "2026-03-16T12:30:00Z", "u2"),
]
FORGED_DONE = rec("user", "done.", "2026-03-16T12:31:00Z", "u-forged")


def member(name, admin_member=False):
    return team_service.create_member(name, f"{name.lower().replace(' ', '.')}@example.com", "agent",
                                      is_compliance_admin=admin_member)


def up(client, who, sid, lines):
    body = "\n".join(lines) if isinstance(lines, list) else lines
    resp = client.post(f"/api/decision-log/upload?session_id={sid}", data=body,
                       headers={"X-API-Key": who.issued_api_key})
    return resp.status_code, (resp.get_json(silent=True) or {})


def repo_import(lines, sid, name=None):
    result = import_decision_log("\n".join(lines).encode(), session_id=sid,
                                 source_path=REPO_PATH.format(name or sid))
    db.session.commit()
    return result


def texts(sid):
    return [e.content_text for e in DecisionLogEntry.query.filter_by(session_id=sid).order_by(DecisionLogEntry.id)]


def versions(sid):
    return DecisionLogTranscript.query.filter_by(session_id=sid).order_by(DecisionLogTranscript.received_at).all()


def emoji_transcript(lines=4, line_bytes=8 * MIB - 400):
    """The red team's emoji probe: tool_use inputs of 4-byte characters, each line under 8 MiB."""
    chars = line_bytes // 4
    body = "\n".join(tool_rec(f"E{i}", {"s": "\U0001F600" * chars}) for i in range(lines)) + "\n"
    return body.encode()


# --------------------------------------------------------------------------
# N-A: tool calls are stored at their size, within limits
# --------------------------------------------------------------------------

def test_na_tool_calls_are_stored_as_utf8_not_ascii_escapes():
    blocks_input = {"s": "\U0001F600 café —", "n": [1, 2.5], "lone": "\ud800"}
    parsed = transcript_ingest.parse_transcript(tool_rec("a1", blocks_input, ensure_ascii=True).encode())
    stored = parsed.entries[0]["tool_calls"]
    assert "\U0001F600" in stored and "\\ud83d" not in stored  # characters as themselves
    assert "\\ud800" in stored  # an unpaired surrogate stays an escape, so the text is valid UTF-8
    stored.encode("utf-8")
    assert json.loads(stored)[0]["input"] == blocks_input


def test_na_emoji_probe_parses_within_its_own_size():
    body = emoji_transcript()
    assert 31 * MIB < len(body) <= 32 * MIB
    tracemalloc.start()
    try:
        parsed = transcript_ingest.parse_transcript(body)
        digest = dl.entries_digest(parsed.entries)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    stored = sum(len(e["tool_calls"].encode()) for e in parsed.entries)
    assert len(parsed.entries) == 4 and digest
    assert stored < len(body)  # the ASCII-escaped form was three times the body
    # The entries (about the body's size) plus one line's transient decoding; the escaped form
    # peaked above five times the body.
    assert peak < 3 * len(body), peak / len(body)


def numbers_rec(msg_id, count):
    """A tool_use whose input is ``count`` numbers written ``9e15``: 5 bytes each in the
    transcript, 20 as stored (``9000000000000000.0, ``)."""
    return tool_rec(msg_id, [0]).replace('"input": [0]', '"input": [' + ",".join(["9e15"] * count) + "]")


def test_na_an_entry_over_the_tool_call_limit_answers_413(app):
    agent = member("Agent A")
    client = app.test_client()
    one = numbers_rec("n0", 400 * 1024)  # 2 MiB in the transcript, 7.8 MiB as stored
    assert len(one.encode()) < transcript_ingest.MAX_ENTRY_BYTES
    code, body = up(client, agent, "big-entry", [numbers_rec("n1", 440 * 1024)])
    assert code == 413 and "each entry's tool calls are limited to 8388608 bytes" in body["error"]
    assert db.session.get(DecisionLogSession, "big-entry") is None

    code, body = up(client, agent, "big-total", [numbers_rec(f"n{i}", 400 * 1024) for i in range(5)])
    assert code == 413 and "limited to 33554432 bytes in total" in body["error"]
    assert db.session.get(DecisionLogSession, "big-total") is None

    code, body = up(client, agent, "fits", [one])
    assert code == 200 and body["status"] == "created"


# --------------------------------------------------------------------------
# N-A: the import budget is weighted by bytes
# --------------------------------------------------------------------------

class Holder:
    """Hold ``size`` bytes of the import budget in another thread until released."""

    def __init__(self, size):
        self.size = size
        self.held = threading.Event()
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.run)

    def run(self):
        with dl.import_slot(size=self.size):
            self.held.set()
            self.done.wait(10)

    def __enter__(self):
        self.thread.start()
        assert self.held.wait(5)
        return self

    def __exit__(self, *exc):
        self.done.set()
        self.thread.join(5)


def test_na_budget_admits_one_big_and_small_uploads_but_not_two_big(app):
    agent = member("Agent A")
    client = app.test_client()
    big = b"x" * (20 * MIB)
    with Holder(32 * MIB):
        resp = client.post("/api/decision-log/upload?session_id=big2", data=big,
                           headers={"X-API-Key": agent.issued_api_key})
        assert resp.status_code == 429 and resp.get_json()["status"] == "busy"
        assert resp.headers["Retry-After"] == "5"
        assert up(client, agent, "small", GENUINE)[0] == 200
        assert db.session.get(DecisionLogSession, "small") is not None
        with Holder(8 * MIB):  # small ones fit beside the big one
            assert up(client, agent, "small2", GENUINE)[0] == 200
    assert db.session.get(DecisionLogSession, "big2") is None
    assert dl._import_slots.used == 0


def test_na_budget_charges_and_waits():
    assert dl.import_charge(10) == dl.MIN_IMPORT_CHARGE
    assert dl.import_charge(None) == dl.MAX_TRANSCRIPT_BYTES
    assert dl.import_charge(20 * MIB) == 20 * MIB
    budget = dl.ImportBudget(48 * MIB)
    assert budget.acquire(32 * MIB, timeout=0)
    assert not budget.acquire(32 * MIB, timeout=0)  # two big ones never run together
    assert budget.acquire(16 * MIB, timeout=0)
    budget.release(16 * MIB)

    order = []

    def sync_import():  # a git sync waits (no timeout) until its charge fits
        assert budget.acquire(32 * MIB)
        order.append("sync")

    waiter = threading.Thread(target=sync_import)
    waiter.start()
    time.sleep(0.2)
    assert order == []
    assert not budget.acquire(MIB, timeout=0)  # nobody overtakes a waiting import
    budget.release(32 * MIB)
    waiter.join(5)
    assert order == ["sync"] and budget.used == 32 * MIB
    assert not budget.acquire(32 * MIB, timeout=0.05)


def test_na_import_slot_is_reentrant_and_bounded(monkeypatch):
    monkeypatch.setattr(dl, "_import_slots", dl.ImportBudget(dl.MAX_TRANSCRIPT_BYTES))
    with dl.import_slot(timeout=0, size=MIB):
        with dl.import_slot(timeout=0, size=32 * MIB):  # the same thread takes nothing more
            assert dl._import_slots.used == MIB
        outcome = []
        thread = threading.Thread(target=lambda: outcome.append(_try_slot(32 * MIB)))
        thread.start()
        thread.join(5)
        assert isinstance(outcome[0], dl.ImportBusyError)
        assert "bytes of decision-log transcripts" in str(outcome[0])
    assert dl._import_slots.used == 0
    assert _try_slot(32 * MIB) is None


def _try_slot(size):
    try:
        with dl.import_slot(timeout=0, size=size):
            return None
    except dl.ImportBusyError as exc:
        return exc


# --------------------------------------------------------------------------
# N-B: a repository version that the API continued is a conflict
# --------------------------------------------------------------------------

def test_nb_repository_prefix_of_an_api_upload_removes_the_forged_tail(app):
    a, b = member("Agent A"), member("Agent B")
    client = app.test_client()
    assert up(client, b, "sq", GENUINE + [FORGED_DONE])[1]["status"] == "created"

    result = repo_import(GENUINE, "sq")
    assert (result.status, result.conflict, result.entries) == ("replaced", True, 3)
    assert texts("sq") == ["please deploy", "Please verify, then reply done.", "it is broken, do not ship"]
    session = db.session.get(DecisionLogSession, "sq")
    assert session.conflict_at is not None and "stored entries 4 to 4" in session.conflict_detail
    assert session.submitted_by is None and session.repository_entries == 3
    assert session.content_sha256 == result.content_sha256
    superseded, current = versions("sq")
    assert (superseded.status, superseded.entry_count, superseded.submitted_by) == ("superseded", 4, b.id)
    assert superseded.reason.startswith("repository conflict: ")
    assert "u-forged" in gzip.decompress(superseded.content_gz).decode()
    assert (current.status, current.entry_count, current.submitted_by) == ("current", 3, None)
    assert current.source_path == REPO_PATH.format("sq")
    assert current.entries_sha256 == dl.stored_entries_digest("sq")[1]

    # The squatter can no longer extend it, and nothing counts as verified.
    code, body = up(client, b, "sq", GENUINE + [FORGED_DONE])
    assert code == 403 and body["status"] == "rejected"
    listing = client.get("/api/decision-log/sessions", headers={"X-API-Key": a.issued_api_key}).get_json()
    item = next(i for i in listing["items"] if i["id"] == "sq")
    assert item["conflict"] is True and item["verifications"] == 0 and item["submitted_by"] is None


def test_nb_honest_repository_extension_still_works(app):
    b = member("Agent B")
    client = app.test_client()
    assert up(client, b, "hx", GENUINE + [FORGED_DONE])[1]["status"] == "created"
    assert repo_import(GENUINE, "hx").conflict
    later = GENUINE + [rec("user", "done.", "2026-03-16T12:40:00Z", "u3")]
    result = repo_import(later, "hx", "hx-later")
    assert (result.status, result.conflict) == ("replaced", False)
    assert texts("hx")[-1] == "done." and len(texts("hx")) == 4
    assert [v.status for v in versions("hx")] == ["superseded", "superseded", "current"]
    assert versions("hx")[1].reason == dl.SUPERSEDED_REASON
    # An earlier, shorter repository export arriving late changes nothing.
    assert repo_import(GENUINE[:2], "hx", "hx-early").status == "kept_existing"
    assert repo_import(GENUINE, "hx").status == "kept_existing"
    assert len(texts("hx")) == 4 and len(versions("hx")) == 3


def test_nb_repository_prefix_of_its_own_entries_or_with_no_entries_is_kept(app):
    b = member("Agent B")
    client = app.test_client()
    assert repo_import(GENUINE, "own").status == "created"
    assert repo_import(GENUINE[:2], "own").status == "kept_existing"
    assert up(client, b, "garbage", GENUINE)[0] == 200
    dry = import_decision_log("\n".join(GENUINE[:2]).encode(), session_id="garbage", dry_run=True)
    assert (dry.status, dry.conflict) == ("replaced", True)
    # A repository file without entries for a squatted session is a conflict too (round 6).
    result = repo_import(["not json"], "garbage")
    assert (result.status, result.conflict) == ("replaced", True)
    assert db.session.get(DecisionLogSession, "garbage").conflict_at is not None
    assert texts("garbage") == []


def test_nb_m2_conflict_names_the_repository_version(app):
    b = member("Agent B")
    client = app.test_client()
    assert up(client, b, "m2", GENUINE[:2] + [FORGED_DONE])[0] == 200
    result = repo_import(GENUINE, "m2")
    assert result.conflict
    superseded, current = versions("m2")
    assert superseded.reason.startswith("repository conflict: entry 3 of the 3 stored entries")
    assert (current.source_path, current.submitted_by) == (REPO_PATH.format("m2"), None)
    assert db.session.get(DecisionLogSession, "m2").submitted_by is None


def test_na_tool_calls_stored_in_the_escaped_form_still_compare_equal(app):
    lines = [tool_rec("t1", {"s": "café \U0001F600"}), tool_rec("t2", {"s": "plain"})]
    assert repo_import(lines, "legacy").status == "created"
    for entry in DecisionLogEntry.query.filter_by(session_id="legacy"):
        entry.tool_calls = json.dumps(json.loads(entry.tool_calls))  # the earlier stored form
    current = versions("legacy")[0]
    current.entries_sha256 = dl.stored_entries_digest("legacy")[1]
    db.session.commit()
    legacy_digest = current.entries_sha256

    result = repo_import(lines + [tool_rec("t3", {"s": "—"}, "2026-03-16T12:00:02Z")], "legacy", "legacy-2")
    assert (result.status, result.conflict) == ("replaced", False)
    superseded, current = versions("legacy")
    assert superseded.entries_sha256 == legacy_digest
    assert current.entries_sha256 == dl.stored_entries_digest("legacy")[1]
    assert repo_import(lines, "legacy", "legacy-1").status == "kept_existing"
