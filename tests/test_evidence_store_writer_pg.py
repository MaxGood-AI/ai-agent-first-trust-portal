"""Evidence store: a writer's content never produces a verification failure that
only an erasure could clear.

Every store import first runs a pure, total content check that refuses (or
cleans) everything the database could refuse, and verification re-derives
with the same functions and inputs; a failure while writing stays ``error``
(pending, retried, settled by an administrator's acknowledgement). Store
pentest finding ids derive from the object's version id and the API assigns
pentest finding ids, so no writer squats them; store-namespace findings no
store object imported fail verification and never suppress an import;
verification re-derives through the worker pool within per-slice budgets;
sync runs and records are dated by the database clock and a first retention
floor below the earliest recorded object's retention fails."""

import collections
import json
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.models import DecisionLogSession, PentestFinding, db
from app.models.evidence_store import EvidenceStoreRetentionFloor, EvidenceStoreSyncRun
from app.routes import evidence_store_api
from app.services import team_service
from app.services.evidence_store import plans, store, sync
from app.services.evidence_store import verify as store_verify
from tests.store_fakes import BUCKET
from tests.test_evidence_store_hardening_pg import _failures, _refused, _verify
from tests.test_evidence_store_pg import (LONGER, PENTEST, PENTEST_KEY, TRANSCRIPT, _cli, record,  # noqa: F401
                                          run_sync, s3, tamper)

HOSTILE_KEY = "pentest-evidence/layer3/hostile.json"
STORE_HOLDER = "evidence-store:layer2/scan-1.json"


def _admin():
    return team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)


def _settled(s3, key, rounds=3):
    """Sync ``rounds`` times; the record of ``key`` and the last run."""
    run = None
    for _ in range(rounds):
        run = run_sync()
    return record(key), run


# --------------------------------------------------------------------------
# N1: content the database could refuse is refused (or cleaned) by the pure check
# --------------------------------------------------------------------------

@pytest.mark.parametrize("stamp", ["0001-01-01T00:00:00+05:00", "9999-12-31T23:59:59-05:00"],
                         ids=["year-1-east", "year-9999-west"])
def test_a_timestamp_outside_the_utc_range_is_refused_once(pg_app, s3, stamp):
    s3.put(PENTEST_KEY, PENTEST)
    s3.put(HOSTILE_KEY, json.dumps({"timestamp": stamp, "findings": [{"severity": "LOW", "summary": "x"}]}).encode())
    row, run = _settled(s3, HOSTILE_KEY)
    assert (row.status, row.attempts) == ("rejected", 0) and "timestamp is outside" in row.detail
    assert run.counts["errors"] == 0 and run.status == "unchanged"
    assert record(PENTEST_KEY).status == "ingested"
    result = _verify(s3)
    assert result["status"] == "valid", _failures(result)
    assert result["records"]["refusals_count"] == 1


SURROGATES = {
    "summary": rb'{"findings": [{"severity": "LOW", "summary": "a\ud800b"}]}',
    "other_data-value": rb'{"findings": [{"severity": "LOW", "summary": "ok", "extra": "\udc00"}]}',
    "other_data-key": rb'{"findings": [{"severity": "LOW", "summary": "ok", "\ud800": 1}]}',
    "repo": rb'{"repo": "\ud800", "findings": [{"severity": "LOW", "summary": "ok"}]}',
    "remediation-struct": rb'{"findings": [{"severity": "LOW", "summary": "ok", "remediation": {"a": "\ud800"}}]}',
    "nul-in-json": rb'{"findings": [{"severity": "LOW", "summary": "ok", "soc2_controls": ["CC\u00007.1"]}]}',
    "nul-in-key": rb'{"findings": [{"severity": "LOW", "summary": "ok", "a\u0000b": 1}]}',
}


@pytest.mark.parametrize("body", list(SURROGATES.values()), ids=list(SURROGATES))
def test_unstorable_text_anywhere_in_a_pentest_file_is_refused_once(pg_app, s3, body):
    s3.put(HOSTILE_KEY, body)
    row, run = _settled(s3, HOSTILE_KEY)
    assert (row.status, row.attempts) == ("rejected", 0), row.detail
    assert "unpaired surrogate" in row.detail or "NUL character" in row.detail
    assert run.counts["errors"] == 0
    assert PentestFinding.query.count() == 0
    result = _verify(s3, full=True)
    assert result["status"] == "valid", _failures(result)
    assert result["records"]["refusals_count"] == 1


@pytest.mark.parametrize("sidecar", [rb'{"reason": "a\u0000b"}', rb'{"reason": "a\ud800b"}',
                                     json.dumps({"reason": "r" * 500, "agent": "codex"}).encode()],
                         ids=["nul", "surrogate", "over-length"])
def test_a_sidecar_exit_reason_is_cleaned_and_the_transcript_imported(pg_app, s3, sidecar):
    key = "decision-logs/2026-10-01T000000Z_sess-side.jsonl"
    s3.put("decision-logs/2026-10-01T000000Z_sess-side.meta.json", sidecar)
    s3.put(key, TRANSCRIPT)
    row, run = _settled(s3, key)
    assert row.status == "ingested" and run.counts["errors"] == 0, row.detail
    reason = db.session.get(DecisionLogSession, "sess-side").exit_reason
    assert "\x00" not in reason and reason.encode("utf-8") and len(reason) <= 50
    later, later_sidecar = ("decision-logs/2026-10-02T000000Z_sess-side.jsonl",
                            "decision-logs/2026-10-02T000000Z_sess-side.meta.json")
    s3.put(later_sidecar, sidecar)
    s3.put(later, TRANSCRIPT)  # unchanged: re-derived with the same sidecar-supplied inputs
    run_sync()
    assert record(later).status == "unchanged" and record(later).import_info["sidecar"]["read"] is True
    reads = s3.reads(later_sidecar)
    result = _verify(s3)
    assert result["status"] == "valid", _failures(result)
    assert s3.reads(later_sidecar) == reads + 1  # verification re-read the sidecar version the sync read


def test_verification_rederives_with_the_sidecar_inputs_the_sync_used(pg_app, s3, monkeypatch):
    key = "decision-logs/2026-10-01T000000Z_sess-in.jsonl"
    sidecar = "decision-logs/2026-10-01T000000Z_sess-in.meta.json"
    s3.put(sidecar, json.dumps({"reason": "clear", "agent": "codex"}).encode())
    s3.put(key, TRANSCRIPT)
    run_sync()
    later = "decision-logs/2026-10-03T000000Z_sess-in.jsonl"
    s3.put(later, TRANSCRIPT)
    run_sync()
    seen = []
    real = plans.check_decision_log

    def spy(content, key, exit_reason=None, agent=None):
        seen.append((key, exit_reason, agent))
        return real(content, key, exit_reason, agent)

    monkeypatch.setattr(plans, "check_decision_log", spy)
    assert _verify(s3)["status"] == "valid"
    assert (later, None, None) in seen  # its own sidecar does not exist: nothing supplied, as at the sync
    original = s3.get_object

    def unreadable(**kwargs):
        if kwargs["Key"] == "decision-logs/2026-10-03T000000Z_sess-in.meta.json":
            raise RuntimeError("never read")
        return original(**kwargs)

    monkeypatch.setattr(s3, "get_object", unreadable)
    assert _verify(s3)["status"] == "valid"


def test_the_pure_checks_raise_only_their_refusals():
    with pytest.raises(plans.ContentRejected, match="cannot be checked"):
        plans.check_pentest(PENTEST_KEY, {"findings": [{"summary": object()}]}, "v1")
    with pytest.raises(plans.ContentRejected, match="version id"):
        plans.check_pentest(PENTEST_KEY, {"findings": []}, "")
    with pytest.raises(plans.ContentRejected, match="not a"):
        plans.check_pentest("pentest-evidence/bad.json", {"findings": []}, "v1")
    with pytest.raises(plans.ContentRejected, match="invalid session id"):
        plans.check_decision_log(TRANSCRIPT, "decision-logs/2026-10-01T000000Z_-bad.jsonl")
    checked = plans.check_decision_log(TRANSCRIPT, "decision-logs/2026-10-01T000000Z_sess.jsonl", "a\x00\ud800",
                                       ["not", "text"])
    assert checked.exit_reason == "a��" and checked.agent is None and checked.session_id == "sess"


# --------------------------------------------------------------------------
# N1 (b): a failure while writing stays an error, settled by an administrator
# --------------------------------------------------------------------------

def test_a_write_failure_stays_an_error_until_an_admin_acknowledges_it(pg_app, s3, migrated_pg_url, monkeypatch):
    s3.put(PENTEST_KEY, PENTEST)

    class Refused(Exception):
        pgcode = "22P02"

    def failing(checked):
        raise Refused("the database refused a value")

    monkeypatch.setattr(sync, "insert_store_findings", failing)
    run_sync()
    row = record(PENTEST_KEY)
    assert (row.status, row.attempts) == ("error", 1) and "22P02" in row.detail
    admin = _admin()
    args = ("evidence-store", "acknowledge", "--key", PENTEST_KEY, "--version-id", row.version_id, "--reason",
            "the import cannot be repeated", "--admin", admin.email)
    code, out = _cli(migrated_pg_url, monkeypatch, *args)
    assert code == 2 and "after 3 failed syncs" in out
    for _ in range(2):
        run_sync()
    row = record(PENTEST_KEY)
    assert (row.status, row.attempts) == ("error", 3)
    pending = _verify(s3)
    assert pending["status"] == "unverified" and pending["failure_count"] == 0
    code, out = _cli(migrated_pg_url, monkeypatch, *args)
    assert code == 0, out
    row = record(PENTEST_KEY)
    assert (row.status, row.acknowledged_from, row.acknowledged_by) == ("acknowledged", "error", admin.id)
    result = _verify(s3)
    assert result["status"] == "valid", _failures(result)
    assert result["records"]["acknowledged"][0]["acknowledged_from"] == "error"
    assert run_sync().counts["new"] == 0  # settled: no sync reads it again


def test_a_rejection_is_acknowledged_only_when_it_no_longer_rederives(pg_app, s3, migrated_pg_url, monkeypatch):
    version = s3.put(PENTEST_KEY, PENTEST)
    checked = plans.check_pentest(PENTEST_KEY, json.loads(PENTEST), version)
    # The database role puts a git-source finding under one of the ids the store's import takes.
    first = dict(checked.rows[0], source_file="git-src:layer2/scan-1.json")
    db.session.add(PentestFinding(**first))
    db.session.commit()
    run_sync()
    row = record(PENTEST_KEY)
    assert row.status == "rejected" and "the store never takes over a finding" in row.detail
    assert db.session.get(PentestFinding, first["id"]).source_file == "git-src:layer2/scan-1.json"
    assert _verify(s3)["status"] == "valid"  # the refusal re-derives while the row holds the id
    admin = _admin()
    args = ("evidence-store", "acknowledge", "--key", PENTEST_KEY, "--version-id", version, "--reason",
            "the conflicting finding was removed", "--admin", admin.email)
    code, out = _cli(migrated_pg_url, monkeypatch, *args)
    assert code == 2 and "re-derives" in out
    db.session.execute(text("DELETE FROM pentest_findings WHERE id = :i"), {"i": first["id"]})
    db.session.commit()
    stale = _verify(s3)
    assert stale["status"] == "broken"
    assert any(k == PENTEST_KEY and "acknowledges a refusal that no longer re-derives" in i
               for k, i in _failures(stale))
    code, out = _cli(migrated_pg_url, monkeypatch, *args)
    assert code == 0, out
    assert (record(PENTEST_KEY).status, record(PENTEST_KEY).acknowledged_from) == ("acknowledged", "rejected")
    assert _verify(s3)["status"] == "valid"


def test_a_too_large_refusal_that_no_longer_rederives_is_acknowledged(pg_app, s3, migrated_pg_url, monkeypatch):
    from app.services import transcript_ingest

    key = "decision-logs/2026-10-01T000000Z_sess-many.jsonl"
    monkeypatch.setattr(transcript_ingest, "MAX_TRANSCRIPT_ENTRIES", 2)
    version = s3.put(key, LONGER)
    run_sync()
    assert record(key).status == "too_large" and _verify(s3)["status"] == "valid"
    admin = _admin()
    args = ("evidence-store", "acknowledge", "--key", key, "--version-id", version, "--reason",
            "the transcript limit was raised", "--admin", admin.email)
    code, out = _cli(migrated_pg_url, monkeypatch, *args)
    assert code == 2 and "re-derives" in out
    monkeypatch.setattr(transcript_ingest, "MAX_TRANSCRIPT_ENTRIES", 50_000)  # a later release raises the limit
    stale = _verify(s3)
    assert (key, "recorded too_large, but its body is within the decision-log limits") in _failures(stale)
    code, out = _cli(migrated_pg_url, monkeypatch, *args)
    assert code == 0, out
    assert (record(key).status, record(key).acknowledged_from) == ("acknowledged", "too_large")
    assert _verify(s3)["status"] == "valid"


def test_the_guard_admits_only_the_documented_acknowledgements(pg_app, s3):
    admin = _admin()
    s3.put(HOSTILE_KEY, b"not json")
    run_sync()
    row = record(HOSTILE_KEY)
    base = ("UPDATE evidence_store_objects SET status = 'acknowledged', acknowledged_at = now(), "
            "acknowledged_by = :m, acknowledgement_reason = 'r'")
    _refused(base + " WHERE id = :i", {"m": admin.id, "i": row.id})  # no acknowledged_from
    _refused(base + ", acknowledged_from = 'error' WHERE id = :i", {"m": admin.id, "i": row.id})
    db.session.execute(text(base + ", acknowledged_from = 'rejected' WHERE id = :i"), {"m": admin.id, "i": row.id})
    db.session.commit()
    _refused("UPDATE evidence_store_objects SET status = 'rejected', acknowledged_from = NULL WHERE id = :i",
             {"i": row.id})
    with pytest.raises(Exception, match="recorded before it is erased or acknowledged"):
        db.session.execute(text("INSERT INTO evidence_store_objects (id, bucket, key, version_id, kind, status, size, "
                                "acknowledged_from) VALUES ('x', :b, 'k', 'v', 'unmapped', 'recorded', 1, 'error')"),
                           {"b": BUCKET})
    db.session.rollback()


# --------------------------------------------------------------------------
# N2: no writer squats an id the store's import takes
# --------------------------------------------------------------------------

def test_the_api_assigns_pentest_finding_ids(pg_app, s3):
    member = team_service.create_member("Member", "member@example.com", "human")
    client, headers = pg_app.test_client(), {"X-API-Key": member.issued_api_key}
    squat = str(uuid.uuid4())
    refused = client.post("/api/pentest-findings", json={"id": squat, "layer": 2, "source_file": "layer2/decoy.json",
                                                         "summary": "decoy"}, headers=headers)
    assert refused.status_code == 400 and "assigned by the server" in refused.get_json()["error"]
    created = client.post("/api/pentest-findings", json={"layer": 2, "source_file": "layer2/decoy.json",
                                                         "summary": "decoy"}, headers=headers)
    assert created.status_code == 201 and created.get_json()["id"] != squat
    assert db.session.get(PentestFinding, squat) is None
    spec = client.get("/apispec_1.json").get_json()
    assert "assigns the finding's id" in json.dumps(spec["paths"]["/pentest-findings"]["post"])


def test_store_finding_ids_derive_from_the_version_and_are_never_taken_over(pg_app, s3):
    from cli.loaders.pentest_findings import finding_id

    first = json.loads(PENTEST)["findings"][0]
    squat = finding_id(STORE_HOLDER, first, collections.Counter())  # the formula an attacker could predict
    db.session.add(PentestFinding(id=squat, layer=2, source_file="layer2/decoy.json", summary="decoy"))
    db.session.commit()
    version = s3.put(PENTEST_KEY, PENTEST)
    run = run_sync()
    assert record(PENTEST_KEY).status == "ingested" and run.counts["errors"] == 0
    ids = {f.id for f in PentestFinding.query.filter_by(source_file=STORE_HOLDER)}
    expected = {row["id"] for row in plans.check_pentest(PENTEST_KEY, json.loads(PENTEST), version).rows}
    assert ids == expected and squat not in ids and len(ids) == 2
    assert db.session.get(PentestFinding, squat).source_file == "layer2/decoy.json"  # never moved
    assert plans.check_pentest(PENTEST_KEY, json.loads(PENTEST), "another-version").rows[0]["id"] not in ids
    assert _verify(s3, full=True)["status"] == "valid"


# --------------------------------------------------------------------------
# N3: store-namespace findings no store object imported
# --------------------------------------------------------------------------

def _forge(source_file, summary):
    db.session.add(PentestFinding(id=str(uuid.uuid4()), layer=2, severity="CRITICAL", summary=summary,
                                  source_file=source_file, other_data={"severity": "CRITICAL", "summary": summary}))
    db.session.commit()


def test_a_forged_store_finding_fails_verification(pg_app, s3):
    s3.put("decision-logs/2026-10-01T000000Z_sess-p4.jsonl", TRANSCRIPT)
    run_sync()
    assert _verify(s3)["status"] == "valid"
    _forge("evidence-store:layer2/forged.json", "forged from nowhere")
    result = _verify(s3)
    assert result["status"] == "broken" and result["store_findings"]["failure_count"] == 1
    assert "no store object imported" in result["store_findings"]["failures"][0]["issue"]


def test_a_forged_store_finding_never_suppresses_the_real_import(pg_app, s3):
    _forge(STORE_HOLDER, "pre-empted")
    s3.put(PENTEST_KEY, PENTEST)
    run = run_sync()
    row = record(PENTEST_KEY)
    assert row.status == "ingested" and run.counts["errors"] == 0 and run.counts["rejected"] == 0
    assert PentestFinding.query.filter_by(source_file=STORE_HOLDER).count() == 3
    result = _verify(s3)
    assert result["status"] == "broken"
    assert (PENTEST_KEY, "the store's namespace holds 1 finding(s) for its file that this version did not "
                         "import") in _failures(result)
    tamper("DELETE FROM pentest_findings WHERE summary = 'pre-empted'", table="pentest_findings")
    assert _verify(s3)["status"] == "valid"


# --------------------------------------------------------------------------
# N4: verification cost is bounded and parallel
# --------------------------------------------------------------------------

def _flood(s3, count=12):
    s3.put("decision-logs/2026-10-01T000000Z_sess-flood.jsonl", LONGER)
    run_sync()
    for index in range(1, count + 1):
        s3.put(f"decision-logs/2026-10-01T{index:06d}Z_sess-flood.jsonl", TRANSCRIPT)  # unchanged
        s3.put(f"pentest-evidence/layer4/junk-{index}.json", b"not json")  # rejected
    run_sync()


def test_rederivation_reads_bodies_in_the_worker_pool(pg_app, s3, monkeypatch):
    _flood(s3)
    threads, real = set(), store.read_version

    def slow(client, bucket, key, version_id, limit):
        threads.add(threading.get_ident())
        time.sleep(0.02)
        return real(client, bucket, key, version_id, limit)

    monkeypatch.setattr(store, "read_version", slow)
    db.session.commit()
    result = store_verify.verify_store(db.session, s3, BUCKET, workers=4)
    assert result["status"] == "valid", _failures(result)
    assert result["records"]["rederived"] == 24 and result["bytes_read"] > 0
    assert threading.get_ident() not in threads and len(threads) > 1


def test_api_slices_stop_at_their_byte_budget_and_sum_to_the_whole_run(pg_app, s3, migrated_pg_url, monkeypatch):
    _flood(s3)
    admin = _admin()
    budget = len(TRANSCRIPT) * 3
    monkeypatch.setattr(evidence_store_api, "VERIFY_SLICE_BYTES", budget)
    client, headers = pg_app.test_client(), {"X-API-Key": admin.issued_api_key}
    cursor, slices, checked, exhausted = None, 0, 0, 0
    while True:
        body = client.get("/api/evidence-store/verify" + (f"?cursor={cursor}" if cursor else ""),
                          headers=headers).get_json()
        assert body["status"] == "valid" and body["max_bytes"] == budget
        assert body["bytes_read"] <= budget or (body["records"] or {}).get("checked") == 1
        slices += 1
        checked += (body["records"] or {}).get("checked", 0)
        exhausted += bool(body["budget_exhausted"])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    whole = _verify(s3)
    assert checked == whole["records"]["checked"] and exhausted >= 3 and slices > exhausted
    code, out = _cli(migrated_pg_url, monkeypatch, "audit-verify", "--evidence-store")
    assert f"rederived={whole['records']['rederived']}" in out and "bytes_read=" in out, out
    assert "evidence_store: status=valid" in out


# --------------------------------------------------------------------------
# N5: runs and records are dated by the database; the first floor is checked against the store
# --------------------------------------------------------------------------

def test_sync_runs_are_dated_by_the_database_and_never_redated(pg_app, s3):
    before = db.session.execute(text("SELECT now()")).scalar()
    db.session.commit()
    run_id = str(uuid.uuid4())
    db.session.add(EvidenceStoreSyncRun(id=run_id, bucket=BUCKET, trigger_type="manual", status="success",
                                        queued_at=datetime(2000, 1, 1, tzinfo=timezone.utc)))
    db.session.commit()
    queued = db.session.execute(text("SELECT queued_at FROM evidence_store_sync_runs WHERE id = :i"),
                                {"i": run_id}).scalar()
    assert queued >= before
    _refused("UPDATE evidence_store_sync_runs SET queued_at = now() - interval '30 days' WHERE id = :i",
             {"i": run_id})
    s3.put(PENTEST_KEY, PENTEST)
    run_sync()
    created = db.session.execute(text("SELECT created_at FROM evidence_store_objects")).scalar()
    assert created >= before
    db.session.execute(text("INSERT INTO evidence_store_objects (id, bucket, key, version_id, kind, status, size, "
                            "created_at) VALUES ('early', :b, 'decision-logs/x.txt', 'v', 'unmapped', 'recorded', 1, "
                            "'2000-01-01')"), {"b": BUCKET})
    db.session.commit()
    assert db.session.execute(text("SELECT created_at FROM evidence_store_objects WHERE id = 'early'")).scalar() \
        >= before


def test_a_first_floor_seeded_with_a_forged_run_fails(pg_app, s3):
    db.session.add(EvidenceStoreSyncRun(id=str(uuid.uuid4()), bucket=BUCKET, trigger_type="manual", status="success",
                                        queued_at=datetime(2000, 1, 1, tzinfo=timezone.utc),
                                        retention_mode="GOVERNANCE", retention_days=1))
    db.session.add(EvidenceStoreRetentionFloor(id=str(uuid.uuid4()), bucket=BUCKET, days=1, reason="seed"))
    db.session.commit()
    s3.put(PENTEST_KEY, PENTEST)
    run_sync()
    result = _verify(s3)
    assert result["status"] == "broken"
    assert any("first retention floor (1 days) is below the Object Lock retention" in issue
               for issue in result["bucket_check"]["issues"]), result["bucket_check"]["issues"]


def test_a_genuine_first_floor_passes_the_earliest_object_check(pg_app, s3):
    s3.put(PENTEST_KEY, PENTEST)
    run_sync()
    result = _verify(s3)
    assert result["status"] == "valid", result["bucket_check"]["issues"]
    head = s3.head_object(Bucket=BUCKET, Key=PENTEST_KEY, VersionId=record(PENTEST_KEY).version_id)
    retention = head["ObjectLockRetainUntilDate"] - head["LastModified"]
    assert abs(retention - timedelta(days=7 * 365)) < timedelta(days=3)
