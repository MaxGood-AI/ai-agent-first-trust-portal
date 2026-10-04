"""Round 4 fixes (data stream), on SQLite: decision-log transcript limits and
import slots (H2), the evidence repository's authority over sessions squatted
through the API (M2), chunk parts that lie about their size (N5), cron ranges
ending at 7 and the reset of the last synced commit when a source's role or
path mappings change (lows).
"""

import gzip
import hashlib
import io
import json
import random
import time
import tracemalloc
from datetime import datetime, timezone

import pytest
import requests

from app import create_app
from app.config import TestConfig
from app.models import DecisionLogEntry, DecisionLogSession, DecisionLogTranscript, db
from app.models.git_source import GitSource, GitSourceFile
from app.services import chunked_files, scheduler, team_service
from app.services import evidence_import_decision_logs as dl
from app.services import transcript_ingest
from app.services.evidence_import import import_decision_log
from app.services.git_sources import service, sync
from app.services.git_sources.providers import GitHubProvider, LocalDirectoryProvider

from tests.test_git_sync import FakeProvider, base, counts, run_sync

MIB = 1024 * 1024


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


@pytest.fixture
def fake(monkeypatch):
    provider = FakeProvider()
    monkeypatch.setattr(sync, "build_provider_for", lambda source: provider)
    return provider


def rec(role, text, ts, msg_id, **extra):
    record = {"type": role, "message": {"role": role, "id": msg_id,
                                        "content": [{"type": "text", "text": text}]}}
    if ts is not None:
        record["timestamp"] = ts
    record.update(extra)
    return json.dumps(record)


GENUINE = [
    rec("user", "please deploy", "2026-03-16T12:00:00Z", "u1", cwd="/genuine", gitBranch="main"),
    rec("assistant", "Please verify, then reply done.", "2026-03-16T12:05:00Z", "a1"),
    rec("user", "it is broken, do not ship", "2026-03-16T12:30:00Z", "u2"),
]
FORGED_DONE = rec("user", "done.", "2026-03-16T12:06:00Z", "u-forged")


def member(name, admin_member=False):
    return team_service.create_member(name, f"{name.lower().replace(' ', '.')}@example.com", "agent",
                                      is_compliance_admin=admin_member)


def up(client, who, sid, lines, query=""):
    body = "\n".join(lines) if isinstance(lines, list) else lines
    resp = client.post(f"/api/decision-log/upload?session_id={sid}{query}", data=body,
                       headers={"X-API-Key": who.issued_api_key})
    return resp.status_code, (resp.get_json(silent=True) or {})


def texts(sid):
    return [e.content_text for e in DecisionLogEntry.query.filter_by(session_id=sid)
            .order_by(DecisionLogEntry.id)]


def tiny_transcript(target, tag="x"):
    """The red team's probe: minimal records up to ``target`` bytes (the most entries)."""
    line = ('{"type":"user","message":{"content":"%s"}}\n' % tag).encode()
    count = target // len(line)
    return line * count, count


def repo_import(lines, sid, source_path=None):
    result = import_decision_log("\n".join(lines).encode(), session_id=sid, source_path=source_path)
    db.session.commit()
    return result


# --------------------------------------------------------------------------
# H2: entry limits, bounded parsing, import slots
# --------------------------------------------------------------------------

def test_h2_780k_entry_transcript_is_refused_quickly(app):
    agent = member("Agent A")
    body, entries = tiny_transcript(32 * MIB - 16)
    assert entries > 700_000
    start = time.monotonic()
    resp = app.test_client().post("/api/decision-log/upload?session_id=m0", data=body,
                                  headers={"X-API-Key": agent.issued_api_key})
    elapsed = time.monotonic() - start
    assert resp.status_code == 413, resp.get_json()
    assert "limited to 50000 entries" in resp.get_json()["error"]
    assert elapsed < 10
    db.session.remove()
    assert db.session.get(DecisionLogSession, "m0") is None
    assert DecisionLogEntry.query.count() == 0


def test_h2_a_line_over_the_entry_size_limit_is_refused(app):
    agent = member("Agent A")
    body = GENUINE[0] + "\n" + rec("assistant", "y" * (9 * MIB), "2026-03-16T12:01:00Z", "a1")
    code, data = up(app.test_client(), agent, "fat", body)
    assert code == 413
    assert data["error"].startswith("line 2 is ") and "limited to 8388608 bytes" in data["error"]
    assert db.session.get(DecisionLogSession, "fat") is None


def test_h2_a_transcript_at_the_entry_limit_is_stored(app):
    body = b'{"type":"user","message":{"content":"x"}}\n' * 50_000
    result = import_decision_log(body, session_id="edge")
    db.session.commit()
    assert result.status == "created" and result.entries == 50_000
    with pytest.raises(transcript_ingest.TranscriptTooManyEntriesError):
        import_decision_log(body + b'{"type":"user","message":{"content":"y"}}\n', session_id="edge")


def test_h2_byte_level_line_split_matches_decode_then_splitlines():
    alphabet = [b"a", b"{", b" ", b"\n", b"\r", b"\r\n", b"\x0b", b"\x0c", b"\x1c", b"\x1d", b"\x1e",
                b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9", "—".encode(), "\U0001F600".encode(),
                b"\xc2", b"\xe2", b"\xe2\x80", b"\x80", b"\xa8", b"\xff", b"\xf0\x9f", b"\xed\xa0\x80"]
    rng = random.Random(4)
    for _ in range(3000):
        data = b"".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        expected = [line.strip() for line in data.decode("utf-8", errors="replace").splitlines()]
        assert [line for _, line in transcript_ingest._lines(data)] == expected, data


def test_h2_parsing_a_maximal_transcript_holds_no_second_copy_of_it():
    # 32 MiB of ~4 KiB assistant records, one of them with a non-ASCII character: decoding the
    # whole transcript at once would need twice its size again for that one character.
    records = [rec("assistant", ("q" * 4000) if i else ("—" + "q" * 3999), "2026-03-16T12:00:01Z",
                   f"a{i}") for i in range(8000)]
    body = ("\n".join(records)).encode()
    assert 31 * MIB < len(body) < 32 * MIB
    tracemalloc.start()
    try:
        parsed = transcript_ingest.parse_transcript(body)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(parsed.entries) == 8000
    # The parsed entries hold the text once (about the transcript's size); nothing else of
    # transcript size may be alive at the same time.
    assert peak < 1.5 * len(body), peak


def test_h2_uploads_refuse_and_syncs_wait_when_no_import_slot_is_free(app, fake, monkeypatch):
    class RecordingSlots:
        capacity = dl.IMPORT_BYTE_BUDGET

        def __init__(self, free):
            self.free = free
            self.timeouts = []

        def acquire(self, charge, timeout=None):
            self.timeouts.append(timeout)
            return self.free

        def release(self, charge):
            pass

    agent = member("Agent A")
    busy = RecordingSlots(free=False)
    monkeypatch.setattr(dl, "_import_slots", busy)
    resp = app.test_client().post("/api/decision-log/upload?session_id=busy", data="\n".join(GENUINE),
                                  headers={"X-API-Key": agent.issued_api_key})
    assert resp.status_code == 429
    assert resp.headers["Retry-After"] == "5"
    assert resp.get_json()["status"] == "busy"
    assert busy.timeouts == [0]  # an upload never waits for a slot
    assert db.session.get(DecisionLogSession, "busy") is None

    free = RecordingSlots(free=True)
    monkeypatch.setattr(dl, "_import_slots", free)
    fake.commit("c1", {"decision-logs/2026-03-16T120000Z_s-sync.jsonl": "\n".join(GENUINE)})
    source = service.create_source(base(name="ev", role="evidence", repository="/unused"))
    assert run_sync(source).counts == counts(created=1)
    assert free.timeouts == [None]  # a sync waits for one (one slot for fetch and write)


def test_h2_import_slot_is_reentrant_and_bounded(monkeypatch):
    import threading

    monkeypatch.setattr(dl, "_import_slots", dl.ImportBudget(dl.MIN_IMPORT_CHARGE))  # room for one import
    with dl.import_slot(timeout=0):
        with dl.import_slot(timeout=0):  # the same thread holds it already
            pass
        errors = []

        def other():
            try:
                with dl.import_slot(timeout=0):
                    pass
            except dl.ImportBusyError as exc:
                errors.append(exc)

        thread = threading.Thread(target=other)
        thread.start()
        thread.join(5)
        assert len(errors) == 1
    with dl.import_slot(timeout=0):
        pass


def test_h2_git_sync_flags_a_transcript_over_the_entry_limit_and_does_not_reread_it(app, fake):
    path = "decision-logs/2026-03-16T120000Z_many.jsonl"
    many = b'{"type":"user","message":{"content":"x"}}\n' * 50_001
    fake.commit("c0", {"README.md": "x", path: many})
    source = service.create_source(base(name="ev", role="evidence", repository="/unused"))
    run = run_sync(source)
    assert run.status == "partial" and run.counts == counts(flagged=1)
    assert run.details["flagged"][0]["reason"] == sync.TRANSCRIPT_CONTENT_LIMIT_REASON
    record = GitSourceFile.query.filter_by(source_id=source.id, path=path).one()
    assert record.status == "too_large" and "limited to 50000 entries" in record.status_detail
    assert DecisionLogEntry.query.count() == 0

    fake.commit("c1", {"README.md": "y", path: many})
    fake.calls.clear()
    run = run_sync(db.session.get(GitSource, source.id))
    assert not [call for call in fake.calls if call[0] in ("read_blob", "read_file") and call[1] == path]


# --------------------------------------------------------------------------
# M2: the evidence repository is authoritative for the sessions it contains
# --------------------------------------------------------------------------

def test_m2_repository_version_wins_over_a_session_squatted_through_the_api(app):
    a, b = member("Agent A"), member("Agent B")
    client = app.test_client()
    forged = GENUINE[:2] + [FORGED_DONE]
    assert up(client, b, "sess-genuine", forged)[1]["status"] == "created"

    result = repo_import(GENUINE, "sess-genuine", "decision-logs/2026-03-16T120000Z_sess-genuine.jsonl")
    assert result.status == "replaced" and result.conflict

    assert texts("sess-genuine") == ["please deploy", "Please verify, then reply done.",
                                     "it is broken, do not ship"]
    session = db.session.get(DecisionLogSession, "sess-genuine")
    assert session.conflict_at is not None and "entry 3" in session.conflict_detail
    assert session.content_sha256 == hashlib.sha256("\n".join(GENUINE).encode()).hexdigest()
    assert session.repository_entries == 3
    versions = {v.status: v for v in DecisionLogTranscript.query.filter_by(session_id="sess-genuine")}
    assert versions["current"].entry_count == 3
    assert versions["current"].entries_sha256 == dl.stored_entries_digest("sess-genuine")[1]
    kept = gzip.decompress(versions["superseded"].content_gz).decode()
    assert "u-forged" in kept and "conflict" in versions["superseded"].reason

    # The squatter may no longer extend the session; the listing flags the conflict.
    code, body = up(client, b, "sess-genuine", GENUINE + [rec("user", "done.", "2026-03-16T12:40:00Z", "u9")])
    assert code == 403 and body["status"] == "rejected"
    listing = client.get("/api/decision-log/sessions", headers={"X-API-Key": a.issued_api_key}).get_json()
    item = next(i for i in listing["items"] if i["id"] == "sess-genuine")
    assert item["conflict"] is True and item["conflict_at"] and item["verifications"] == 0
    detail = client.get("/api/decision-log/session/sess-genuine",
                        headers={"X-API-Key": a.issued_api_key}).get_json()["session"]
    assert detail["conflict"] is True and "entry 3" in detail["conflict_detail"]


def test_m2_a_forged_append_after_a_prefix_squat_is_replaced_by_the_repository(app):
    b = member("Agent B")
    client = app.test_client()
    assert up(client, b, "sess-x", GENUINE[:1])[1]["status"] == "created"
    assert repo_import(GENUINE, "sess-x").status == "replaced"
    forged = GENUINE + [rec("user", "done.", "2026-03-16T12:31:00Z", "u-forged")]
    assert up(client, b, "sess-x", forged)[0] == 409  # the repository holds the session now (round 6)

    later = GENUINE + [rec("user", "fixed now, still testing", "2026-03-16T12:45:00Z", "u3")]
    result = repo_import(later, "sess-x")
    assert result.status == "replaced" and not result.conflict
    assert texts("sess-x")[-1] == "fixed now, still testing"
    assert not DecisionLogEntry.query.filter_by(session_id="sess-x", is_verification=True).count()
    rejected = DecisionLogTranscript.query.filter_by(session_id="sess-x", status="rejected").all()
    assert any("u-forged" in gzip.decompress(v.content_gz).decode() for v in rejected)


def test_m2_the_repository_cannot_rewrite_entries_it_supplied(app):
    assert repo_import(GENUINE, "own").status == "created"
    rewritten = GENUINE[:2] + [FORGED_DONE]
    result = repo_import(rewritten, "own")
    assert result.status == "rejected" and not result.conflict
    assert texts("own")[-1] == "it is broken, do not ship"
    assert db.session.get(DecisionLogSession, "own").conflict_at is None


def test_m2_git_sync_reports_the_conflict(app, fake):
    b = member("Agent B")
    path = "decision-logs/2026-03-16T120000Z_sess-g.jsonl"
    up(app.test_client(), b, "sess-g", GENUINE[:2] + [FORGED_DONE])
    fake.commit("c0", {path: "\n".join(GENUINE)})
    source = service.create_source(base(name="ev", role="evidence", repository="/unused"))
    run = run_sync(source)
    assert run.status == "success" and run.counts == counts(updated=1)
    assert run.details["conflicts"] == [{"path": path, "session_id": "sess-g"}]
    assert texts("sess-g")[-1] == "it is broken, do not ship"
    assert db.session.get(DecisionLogSession, "sess-g").conflict_at is not None


# --------------------------------------------------------------------------
# N5: a chunk part that lies about its size
# --------------------------------------------------------------------------

class BoundedFake(FakeProvider):
    """FakeProvider that records the byte limit and the bytes returned of each read."""

    def __init__(self):
        super().__init__()
        self.reads = []

    def read_file(self, path, commit_id, *, max_bytes=None):
        data = super().read_file(path, commit_id, max_bytes=max_bytes)
        self.reads.append((path, max_bytes, len(data)))
        return data


def _lying_manifest(name, small):
    return json.dumps({"format": "chunked-file/v1", "name": name, "size": len(small),
                       "sha256": hashlib.sha256(small).hexdigest(),
                       "parts": [{"name": f"{name}.part-0001", "size": len(small),
                                  "sha256": hashlib.sha256(small).hexdigest()}]}).encode()


def test_n5_a_lying_part_is_read_only_to_its_declared_size_and_flagged_until_it_changes(app, monkeypatch):
    provider = BoundedFake()
    monkeypatch.setattr(sync, "build_provider_for", lambda source: provider)
    name = "2026-03-16T120000Z_lie.jsonl"
    manifest_path, part_path = f"decision-logs/{name}.manifest.json", f"decision-logs/{name}.part-0001"
    small = "\n".join(GENUINE).encode()
    provider.commit("c0", {"README.md": "x", manifest_path: _lying_manifest(name, small),
                           part_path: b"A" * (5 * MIB)})
    source = service.create_source(base(name="ev", role="evidence", repository="/unused"))
    run = run_sync(source)
    assert run.status == "partial" and run.counts == counts(flagged=1)
    assert run.details["flagged"][0]["reason"] == sync.CHUNK_PART_LIMIT_REASON
    part_reads = [read for read in provider.reads if read[0] == part_path]
    assert part_reads == [(part_path, len(small) + 1, len(small) + 1)]
    record = GitSourceFile.query.filter_by(source_id=source.id, path=manifest_path).one()
    assert record.status == "too_large" and "larger than the" in record.status_detail

    # Not read again while nothing of it changes ...
    provider.commit("c1", {"README.md": "y", manifest_path: _lying_manifest(name, small),
                           part_path: b"A" * (5 * MIB)})
    provider.reads.clear()
    assert run_sync(db.session.get(GitSource, source.id)).counts == counts()
    assert not [read for read in provider.reads if read[0] == part_path]

    # ... and imported once its part is corrected.
    provider.commit("c2", {"README.md": "y", manifest_path: _lying_manifest(name, small), part_path: small})
    run = run_sync(db.session.get(GitSource, source.id))
    assert run.counts == counts(created=1), run.details
    assert texts("lie")[-1] == "it is broken, do not ship"


def test_n5_reassemble_asks_for_the_declared_size_plus_one():
    small = b"0123456789"
    manifest = chunked_files.parse_manifest(_lying_manifest("x.jsonl", small))
    asked = []

    def read_part(name, max_bytes):
        asked.append(max_bytes)
        return (b"B" * (10 * MIB))[:max_bytes]

    with pytest.raises(chunked_files.ChunkedPartTooLargeError, match="larger than the 10 bytes"):
        chunked_files.reassemble(manifest, read_part)
    assert asked == [11]


def test_n5_local_reads_stop_at_the_limit(tmp_path):
    (tmp_path / "logs").mkdir()
    name = "2026-03-16T120000Z_loc.jsonl"
    small = b"0123456789"
    (tmp_path / "logs" / (name + ".manifest.json")).write_bytes(_lying_manifest(name, small))
    (tmp_path / "logs" / (name + ".part-0001")).write_bytes(b"C" * MIB)
    with pytest.raises(chunked_files.ChunkedPartTooLargeError):
        chunked_files.read_local(str(tmp_path / "logs" / (name + ".manifest.json")))
    provider = LocalDirectoryProvider(tmp_path)
    head = provider.resolve_head()
    assert provider.read_file(f"logs/{name}.part-0001", head, max_bytes=11) == b"C" * 11
    assert len(provider.read_file(f"logs/{name}.part-0001", head)) == MIB


def test_n5_github_reads_stop_at_the_limit(monkeypatch):
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", lambda host, port, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.121.6", port or 443))])

    class CountingRaw(io.BytesIO):
        consumed = 0

        def read(self, amt=-1, decode_content=True):
            data = super().read(amt)
            CountingRaw.consumed += len(data)
            return data

    class Session:
        def get(self, url, **kwargs):
            response = requests.Response()
            response.status_code = 200
            response.raw = CountingRaw(b"D" * (4 * MIB))
            return response

    provider = GitHubProvider("acme/evidence", "main", token="t", session=Session())
    data = provider.read_file("logs/x.jsonl.part-0001", "a" * 40, max_bytes=1001)
    assert data == b"D" * 1001
    assert CountingRaw.consumed == 1001


# --------------------------------------------------------------------------
# Lows
# --------------------------------------------------------------------------

def test_low_cron_range_7_7_is_sunday_only():
    assert scheduler.crontab_day_of_week("7-7") == "sun"
    assert scheduler.crontab_day_of_week("7-7/2") == "sun"
    assert scheduler.crontab_day_of_week("6-7") == "sun,sat"
    assert scheduler.crontab_day_of_week("0-7/2") == "sun,tue,thu,sat"
    trigger = scheduler.parse_cron("0 0 * * 7-7")
    now = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)  # a Monday
    fires = []
    previous = None
    for _ in range(3):
        previous = trigger.get_next_fire_time(previous, previous or now)
        fires.append(previous.weekday())
    assert fires == [6, 6, 6]


@pytest.mark.parametrize("change", [
    {"role": "governance"},
    {"path_mappings": [{"pattern": "decision-logs/*.jsonl", "kind": "decision_log"}]},
])
def test_low_changing_role_or_path_mappings_resets_the_last_synced_commit(app, change):
    source = service.create_source(base(name="ev", role="evidence", repository="/srv/ev"))
    service.set_last_synced_commit(source, "a" * 40)
    service.update_source(source, change)
    assert db.session.get(GitSource, source.id).last_synced_commit is None


def test_low_an_update_that_keeps_role_and_mappings_keeps_the_last_synced_commit(app):
    mappings = [{"pattern": "decision-logs/*.jsonl", "kind": "decision_log"}]
    source = service.create_source(base(name="ev", role="evidence", repository="/srv/ev",
                                        path_mappings=mappings))
    service.set_last_synced_commit(source, "a" * 40)
    service.update_source(source, {"role": "evidence", "path_mappings": mappings, "schedule_cron": "0 * * * *"})
    assert db.session.get(GitSource, source.id).last_synced_commit == "a" * 40
