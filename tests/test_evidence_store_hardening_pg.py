"""Evidence store hardening: the store's decision-log authority, body checks
against the store, write-once sync runs and the retention floor, the bucket
policy's resources, import outcomes, escaped keys and listing errors, bulk
acknowledgement and the records of a former bucket."""

import hashlib
import importlib.util
import json
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from app.models import DecisionLogSession, DecisionLogTranscript, db
from app.models.evidence_store import EvidenceStoreObject, EvidenceStoreRetentionFloor
from app.services import evidence_import, scheduler, team_service
from app.services import evidence_import_decision_logs as dl
from app.services.decision_log_verify import verify_decision_logs
from app.services.evidence_store import keys, service, store, sync
from app.services.evidence_store import verify as store_verify
from tests.store_fakes import BUCKET, ChecksummingS3, b64_sha256, bucket_policy, make_bucket
from tests.test_evidence_store_pg import (LOG_KEY, LONGER, PENTEST, PENTEST_KEY, REVIEW, REVIEW_KEY,  # noqa: F401
                                          TRANSCRIPT, _cli, _client_error, populate, record, run_sync, s3, tamper)
from tests.test_round2_git import rec

REPO = Path(__file__).resolve().parent.parent
OTHER_PENTEST = json.dumps({"scan_id": "s2", "findings": [{"severity": "LOW", "summary": "other"}]}).encode()


def _verify(s3, **kwargs):
    db.session.commit()
    return store_verify.verify_store(db.session, s3, BUCKET, **kwargs)


def _failures(result):
    return [(f["key"], f["issue"]) for part in ("records", "listing") for f in (result[part] or {}).get("failures", [])]


def _upload(client, member, session_id, body):
    return client.post(f"/api/decision-log/upload?session_id={session_id}", data=body,
                       headers={"X-API-Key": member.issued_api_key})


def _refused(statement, params=None):
    with pytest.raises(Exception, match="refused|insufficient|permission"):
        db.session.execute(text(statement), params or {})
        db.session.commit()
    db.session.rollback()


# --------------------------------------------------------------------------
# N1: the store's authority creates or extends exactly, nothing else
# --------------------------------------------------------------------------

def test_a_store_export_never_replaces_entries_submitted_through_the_api(pg_app, s3):
    member = team_service.create_member("Member", "member@example.com", "human")
    assert _upload(pg_app.test_client(), member, "sess-api", LONGER).status_code < 300
    forged = (rec("user", "ship it now", "2026-03-16T12:00:00Z", "zz1") + "\n").encode()
    key = "decision-logs/2026-01-01T000000Z_sess-api.jsonl"
    s3.put(key, forged)
    run = run_sync()
    row = record(key)
    assert row.status == "rejected" and row.detail.startswith("conflict: ")
    assert row.import_info["decision_log"]["outcome"] == "conflict"
    assert run.details["conflicts"][0]["key"] == key and run.status == "partial"
    current = DecisionLogTranscript.query.filter_by(session_id="sess-api", status="current").one()
    assert (current.entry_count, current.content_sha256) == (3, hashlib.sha256(LONGER).hexdigest())
    assert DecisionLogTranscript.query.filter_by(session_id="sess-api", status="superseded").count() == 0
    kept = DecisionLogTranscript.query.filter_by(session_id="sess-api", status="rejected").one()
    assert kept.store_object_id == row.id  # kept for administrator review
    session = db.session.get(DecisionLogSession, "sess-api")
    assert session.conflict_at is None and session.submitted_by == member.id and session.repository_entries == 0
    db.session.commit()
    assert verify_decision_logs(db.session)["mismatch_count"] == 0
    result = _verify(s3)
    assert result["status"] == "valid" and result["store_conflicts_count"] == 1  # informational, never a failure
    assert result["store_conflicts"][0]["key"] == key


def test_a_store_prefix_export_never_truncates_a_session(pg_app, s3):
    member = team_service.create_member("Member", "member@example.com", "human")
    assert _upload(pg_app.test_client(), member, "sess-api2", LONGER).status_code < 300
    key = "decision-logs/2026-01-01T000000Z_sess-api2.jsonl"
    s3.put(key, TRANSCRIPT)  # a strict prefix of the stored entries
    run_sync()
    current = DecisionLogTranscript.query.filter_by(session_id="sess-api2", status="current").one()
    assert current.entry_count == 3
    row = record(key)
    assert row.status == "unchanged"
    assert row.import_info["decision_log"] == {"session_id": "sess-api2", "outcome": "kept_existing", "entries": 2,
                                               "matched_version": current.id}
    assert _verify(s3, full=True)["status"] == "valid"


def test_the_store_extends_an_api_session_exactly_and_then_holds_it(pg_app, s3):
    member = team_service.create_member("Member", "member@example.com", "human")
    client = pg_app.test_client()
    assert _upload(client, member, "sess-ext", TRANSCRIPT).status_code < 300
    s3.put("decision-logs/2026-01-02T000000Z_sess-ext.jsonl", LONGER)
    run_sync()
    assert record("decision-logs/2026-01-02T000000Z_sess-ext.jsonl").status == "ingested"
    session = db.session.get(DecisionLogSession, "sess-ext")
    assert session.repository_entries == 3 and session.conflict_at is None
    extended = LONGER + (rec("user", "done.", "2026-03-16T13:00:00Z", "u9") + "\n").encode()
    refused = _upload(client, member, "sess-ext", extended)
    assert refused.status_code == 409 and "evidence store" in refused.get_json()["error"]


def test_the_store_authority_is_bound_to_its_object():
    with pytest.raises(ValueError, match="store object"):
        dl.import_decision_log(TRANSCRIPT, session_id="sess-x", authority=dl.AUTHORITY_STORE)
    with pytest.raises(ValueError, match="store object"):
        dl.import_decision_log(TRANSCRIPT, session_id="sess-x", authority=dl.AUTHORITY_SYSTEM, store_object_id="o1")


# --------------------------------------------------------------------------
# N2: --against-store reads the object's body
# --------------------------------------------------------------------------

def test_against_store_reads_and_parses_each_object(pg_app, s3, monkeypatch):
    s3.put(LOG_KEY, TRANSCRIPT)
    run_sync()
    obj = record(LOG_KEY)
    assert store_verify.verify_decision_logs_against_store(db.session, s3)["status"] == "valid"
    # The application role un-pins the session and imports LONGER under the genuine object's id and digest.
    db.session.execute(text("UPDATE decision_log_sessions SET content_sha256 = 'x' WHERE id = 'sess-store'"))
    token = dl._STORE_OBJECT.set(obj.id)
    try:
        dl._import(LONGER, "sess-store", obj.sha256, len(TRANSCRIPT), source_path=LOG_KEY, exit_reason=None,
                   submitted_by=None, authority=dl.AUTHORITY_SYSTEM, dry_run=False, named_agent=None)
    finally:
        dl._STORE_OBJECT.reset(token)
    db.session.commit()
    forged = store_verify.verify_decision_logs_against_store(db.session, s3)
    assert forged["status"] == "broken" and forged["mismatches_count"] == 1
    assert "entries" in forged["mismatches"][0]["issue"] and forged["objects_checked"] == 1
    assert s3.reads(LOG_KEY) == 3  # the sync, then each verification read the body once

    def unreadable(*args, **kwargs):
        raise _client_error("GetObject", "SlowDown")

    monkeypatch.setattr(store, "read_version", unreadable)
    result = store_verify.verify_decision_logs_against_store(db.session, s3, max_sessions=10)
    assert result["status"] == "broken" and result["unreadable_count"] == 2
    assert "ClientError SlowDown" in result["unreadable"][0]["issue"]


def test_against_store_refuses_an_object_of_another_session(pg_app, s3):
    s3.put(LOG_KEY, TRANSCRIPT)
    other = "decision-logs/2026-10-02T000000Z_sess-other.jsonl"
    s3.put(other, TRANSCRIPT)
    run_sync()
    tamper("UPDATE decision_log_transcripts SET store_object_id = :o WHERE session_id = 'sess-store'",
           {"o": record(other).id}, table="decision_log_transcripts")
    result = store_verify.verify_decision_logs_against_store(db.session, s3)
    assert result["status"] == "broken"
    assert any("not a decision log of this session" in m["issue"] for m in result["mismatches"])


# --------------------------------------------------------------------------
# N3 + N7: sync runs are write-once; the retention floor
# --------------------------------------------------------------------------

def test_sync_run_retention_is_written_once_and_runs_are_never_deleted(pg_app, s3):
    run = run_sync()
    assert (run.retention_mode, run.retention_days) == ("GOVERNANCE", 7 * 365)
    _refused("UPDATE evidence_store_sync_runs SET retention_days = 1")
    _refused("UPDATE evidence_store_sync_runs SET retention_days = NULL")
    _refused("UPDATE evidence_store_sync_runs SET retention_mode = 'COMPLIANCE'")
    _refused("UPDATE evidence_store_sync_runs SET bucket = 'other'")
    _refused("DELETE FROM evidence_store_sync_runs")
    _refused("TRUNCATE evidence_store_sync_runs CASCADE")
    db.session.execute(text("UPDATE evidence_store_sync_runs SET status = 'success', counts = NULL"))
    db.session.commit()  # a run's progress still changes


def test_the_retention_floor_is_set_at_the_first_sync_and_guarded(pg_app, s3):
    run_sync()
    floor = EvidenceStoreRetentionFloor.query.filter_by(bucket=BUCKET).one()
    assert floor.days == 7 * 365 and floor.set_by is None and "initialized" in floor.reason
    s3.set_default_retention(BUCKET, {"Mode": "GOVERNANCE", "Years": 10})
    run_sync()
    assert db.session.get(EvidenceStoreRetentionFloor, floor.id).days == 7 * 365  # raising never moves it
    audited = db.session.execute(text("SELECT count(*) FROM audit_log WHERE table_name = "
                                      "'evidence_store_retention_floors'")).scalar()
    assert audited == 1
    _refused("UPDATE evidence_store_retention_floors SET days = 1")
    _refused("DELETE FROM evidence_store_retention_floors")
    _refused("TRUNCATE evidence_store_retention_floors")


def test_a_lowered_default_fails_until_restored_above_the_floor(pg_app, s3):
    populate(s3)
    run_sync()
    assert _verify(s3)["status"] == "valid"
    s3.set_default_retention(BUCKET, {"Mode": "GOVERNANCE", "Days": 1})
    lowered = _verify(s3)
    assert lowered["status"] == "broken" and lowered["bucket_check"]["retention_floor_days"] == 7 * 365
    assert any("below the retention floor" in issue for issue in lowered["bucket_check"]["issues"])
    assert run_sync().retention_days == 1
    s3.set_default_retention(BUCKET, {"Mode": "GOVERNANCE", "Years": 7})
    assert _verify(s3)["status"] == "valid"  # restored at the floor: the history does not keep the failure
    s3.set_default_retention(BUCKET, {"Mode": "COMPLIANCE", "Years": 9})
    assert _verify(s3)["status"] == "valid"


def test_a_short_retained_upload_fails_until_an_admin_lowers_the_floor(pg_app, s3, migrated_pg_url, monkeypatch):
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    s3.set_default_retention(BUCKET, {"Mode": "GOVERNANCE", "Days": 1})
    key = "codex-reviews/2026/review-short.md"
    version = s3.put(key, b"# short\n")
    head = s3.head_object(Bucket=BUCKET, Key=key, VersionId=version)
    s3.head_overrides[(key, version)] = {"ObjectLockRetainUntilDate": head["LastModified"] + timedelta(days=1)}
    run_sync()
    _refused("UPDATE evidence_store_sync_runs SET retention_days = 1")
    s3.set_default_retention(BUCKET, {"Mode": "GOVERNANCE", "Years": 7})
    restored = _verify(s3)
    assert restored["status"] == "broken"
    assert any(k == key and "retention floor" in issue for k, issue in _failures(restored))
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    agent = team_service.create_member("Agent", "agent@example.com", "agent")
    args = ("evidence-store", "set-retention-floor", "--days")
    code, out = _cli(migrated_pg_url, monkeypatch, *args, "1", "--reason", "x", "--admin", agent.email)
    assert code == 2 and "not an active compliance admin" in out
    code, out = _cli(migrated_pg_url, monkeypatch, *args, "0", "--reason", "x", "--admin", admin.email)
    assert code == 2 and "at least 1" in out
    code, out = _cli(migrated_pg_url, monkeypatch, *args, "1", "--reason", "  ", "--admin", admin.email)
    assert code == 2 and "reason is required" in out
    code, out = _cli(migrated_pg_url, monkeypatch, *args, "1", "--reason", "a one-day test object, documented",
                     "--admin", admin.email)
    assert code == 0, out
    audit = db.session.execute(text(
        "SELECT changed_by, new_values->>'days' AS days FROM audit_log "
        "WHERE table_name = 'evidence_store_retention_floors' AND action = 'INSERT' AND changed_by IS NOT NULL")).one()
    assert (audit.changed_by, audit.days) == (admin.id, "1")
    assert _verify(s3)["status"] == "valid"
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "status")
    assert "retention floor: 1 days" in out


def test_the_retention_from_upload_uses_the_stores_last_modified(pg_app, s3):
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    review = record(REVIEW_KEY)
    head = s3.head_object(Bucket=BUCKET, Key=REVIEW_KEY, VersionId=review.version_id)
    short = head["LastModified"] + timedelta(days=2)
    s3.head_overrides[(REVIEW_KEY, review.version_id)] = {"ObjectLockRetainUntilDate": short}
    tamper("UPDATE evidence_store_objects SET retain_until = :t, last_modified = :m WHERE id = :i",
           {"t": short, "m": short - timedelta(days=8 * 365), "i": review.id})
    result = _verify(s3)
    assert result["status"] == "broken"
    assert any(k == REVIEW_KEY and "2 days from its upload" in issue for k, issue in _failures(result))


# --------------------------------------------------------------------------
# N4 + N9: the bucket policy's resources, effects, principals and keys
# --------------------------------------------------------------------------

def _deploy_module():
    spec = importlib.util.spec_from_file_location(
        "hardening_deploy_store", REPO / "deploy" / "aws" / "tests" / "test_evidence_store.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_stacks_policy_passes_the_verifier():
    deploy = _deploy_module()
    assert store_verify.check_policy(json.dumps(deploy.rendered_bucket_policy()), deploy.FAKE_BUCKET) == ([], [])
    assert store_verify.check_policy(json.dumps(deploy.rendered_bucket_policy(deploy.ERASER)),
                                     deploy.FAKE_BUCKET) == ([], [deploy.ERASER])


@pytest.mark.parametrize("suffix", ["*object", "*/object", "*t", "decision-logs/object*", "decision-logs/*",
                                    "d?cision-logs/*", "evidence/artifacts/x*", "**"])
def test_resources_that_protect_less_than_every_store_prefix_fail(suffix):
    policy = bucket_policy("b")
    for statement in policy["Statement"]:
        if statement["Sid"] in ("DenyDeletesAndRetentionChanges", "DenyWriteWithoutIfNoneMatch"):
            statement["Resource"] = f"arn:aws:s3:::b/{suffix}"
    issues, _ = store_verify.check_policy(json.dumps(policy), "b")
    assert len(issues) == 5, issues


def test_literal_prefix_resources_covering_every_store_prefix_pass():
    policy = bucket_policy("b")
    resources = ["arn:aws:s3:::b/decision-logs/*", "arn:aws:s3:::b/pentest-*", "arn:aws:s3:::b/codex-reviews/*",
                 "arn:aws:s3:::b/evidence/*"]
    for statement in policy["Statement"]:
        if statement["Sid"] in ("DenyDeletesAndRetentionChanges", "DenyWriteWithoutIfNoneMatch"):
            statement["Resource"] = resources
    assert store_verify.check_policy(json.dumps(policy), "b") == ([], [])
    assert store_verify.resource_prefixes("arn:aws:s3:::b/evidence/*", "b") == {"evidence/artifacts/"}
    assert store_verify.resource_prefixes("*", "b") == set()
    assert store_verify.resource_prefixes("arn:aws:s3:::bb/*", "b") == set()


def test_effects_principals_actions_and_conditions_are_exact():
    base = bucket_policy("b")

    def check(change):
        policy = json.loads(json.dumps(base))
        change(policy["Statement"][-1])
        return store_verify.check_policy(json.dumps(policy), "b")

    assert check(lambda s: s.update(Effect="deny"))[0]
    assert check(lambda s: s.update(Principal={"AWS": "arn:aws:iam::111122223333:root"}))[0]
    assert check(lambda s: s.update(Principal={"AWS": "*"})) == ([], [])
    assert check(lambda s: s.update(Action=["s3:Delete*", "s3:PutObjectRetention",
                                            "s3:BypassGovernanceRetention"])) == ([], [])
    narrowed = check(lambda s: s.update(Action=["s3:*Object", "s3:PutObjectRetention",
                                                "s3:BypassGovernanceRetention"]))[0]
    assert len(narrowed) == 1 and "s3:DeleteObjectVersion" in narrowed[0]
    assert check(lambda s: s.update(Condition={"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::1:role/x"}}))[0]
    wildcard = check(lambda s: s.update(Condition={"ArnNotEquals": {"aws:PrincipalArn": "arn:aws:iam::*:role/*"}}))
    assert any("wildcard principal" in issue for issue in wildcard[0])


def test_a_policy_with_a_repeated_key_fails():
    raw = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:DeleteObject",'
           '"s3:DeleteObjectVersion","s3:BypassGovernanceRetention","s3:PutObjectRetention","s3:PutObject"],'
           '"Resource":"arn:aws:s3:::b/*","Effect":"Deny"}]}')
    issues, _ = store_verify.check_policy(raw, "b")
    assert issues == ["the bucket policy repeats the key 'Effect' in an object"]


# --------------------------------------------------------------------------
# N5: verification cross-checks import outcomes
# --------------------------------------------------------------------------

def _insert_record(key, version, kind, status, s3, import_info=None):
    head = s3.head_object(Bucket=BUCKET, Key=key, VersionId=version, ChecksumMode="ENABLED")
    sha = store.stored_checksum(head).sha256
    db.session.execute(text(
        "INSERT INTO evidence_store_objects (id, bucket, key, version_id, kind, status, sha256, size, etag, "
        "last_modified, lock_mode, retain_until, attempts, import_info) VALUES (:id, :b, :k, :v, :kind, :status, :s, "
        ":z, :e, :lm, :mode, :ru, 0, :info)"),
        {"id": str(uuid.uuid4()), "b": BUCKET, "k": key, "v": version, "kind": kind, "status": status, "s": sha,
         "z": head["ContentLength"], "e": head["ETag"], "lm": head["LastModified"], "mode": head.get("ObjectLockMode"),
         "ru": head.get("ObjectLockRetainUntilDate"), "info": json.dumps(import_info) if import_info else None})
    db.session.commit()


def test_an_inserted_outcome_does_not_suppress_an_import(pg_app, s3):
    run_sync()
    version = s3.put(LOG_KEY, TRANSCRIPT)
    _insert_record(LOG_KEY, version, "decision_log", "unchanged", s3)
    assert run_sync().status == "unchanged" and db.session.get(DecisionLogSession, "sess-store") is None
    result = _verify(s3)
    assert result["status"] == "broken"
    assert any(k == LOG_KEY and "recorded unchanged" in issue for k, issue in _failures(result))


@pytest.mark.parametrize("key,kind,status,issue", [
    (LOG_KEY, "decision_log", "ingested", "recorded ingested"),
    (PENTEST_KEY, "pentest_evidence", "ingested", "store's namespace holds no findings"),
    (PENTEST_KEY, "pentest_evidence", "duplicate", "counterpart does not hold"),
    (LOG_KEY, "unmapped", "recorded", "is not its key's"),
    (REVIEW_KEY, "evidence_document", "recorded", "no sync records"),
])
def test_impossible_outcomes_fail_verification(pg_app, s3, key, kind, status, issue):
    run_sync()
    version = s3.put(key, {LOG_KEY: TRANSCRIPT, PENTEST_KEY: PENTEST, REVIEW_KEY: REVIEW}[key])
    _insert_record(key, version, kind, status, s3)
    result = _verify(s3)
    assert result["status"] == "broken" and any(k == key and issue in i for k, i in _failures(result)), result


def test_a_duplicate_holds_only_while_its_counterpart_does(pg_app, s3):
    evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, PENTEST, namespace="git-src")
    db.session.commit()
    s3.put(PENTEST_KEY, PENTEST)
    run_sync()
    assert record(PENTEST_KEY).status == "duplicate" and _verify(s3, full=True)["status"] == "valid"
    evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, OTHER_PENTEST, namespace="git-src")
    db.session.commit()
    stale = _verify(s3)
    assert stale["status"] == "broken" and any("counterpart" in issue for _, issue in _failures(stale))
    run_sync()  # the stale duplicate is imported into the store's namespace
    assert record(PENTEST_KEY).status == "ingested" and _verify(s3)["status"] == "valid"


def test_outcomes_are_rederived_from_bodies_on_every_run(pg_app, s3):
    evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, OTHER_PENTEST, namespace="git-src")
    db.session.commit()
    holder = "git-src:layer2/scan-1.json"
    held = evidence_import.held_findings([holder])[holder]
    version = s3.put(PENTEST_KEY, PENTEST)
    # The database role records the file as a duplicate of the git source's (different) findings, with the
    # counterpart's own count and identity, so the per-sync re-evaluation sees nothing stale.
    _insert_record(PENTEST_KEY, version, "pentest_evidence", "duplicate", s3, {
        "duplicate_of": holder, "identity_sha256": held.identity, "findings": held.count})
    s3.put(LOG_KEY, TRANSCRIPT)
    run_sync()
    current = DecisionLogTranscript.query.filter_by(session_id="sess-store", status="current").one()
    other_key = "decision-logs/2026-10-05T000000Z_sess-store.jsonl"
    other = s3.put(other_key, (rec("user", "something else", "2026-03-16T12:00:00Z", "zz") + "\n").encode())
    _insert_record(other_key, other, "decision_log", "unchanged", s3, {
        "decision_log": {"session_id": "sess-store", "outcome": "kept_existing", "entries": 1,
                         "matched_version": current.id}})
    for result in (_verify(s3), _verify(s3, full=True)):  # the recorded facts agree with the database: not enough
        issues = _failures(result)
        assert result["status"] == "broken"
        assert (PENTEST_KEY, "recorded duplicate, but its counterpart does not hold exactly the findings of its "
                             "body") in issues
        assert (other_key, "recorded unchanged, but its entries are not identical to, or a prefix of, its session's "
                           "stored entries") in issues


# --------------------------------------------------------------------------
# N6: keys with control characters; listing errors
# --------------------------------------------------------------------------

def test_escaped_keys_round_trip():
    for key in ("codex-reviews/a\x00b", "codex-reviews/50%\tdone.md", "x\x7f\x9f%25"):
        stored, escaped = keys.stored_key(key)
        assert escaped and keys.raw_key(stored, True) == key
        assert not any(keys._control(ch) for ch in stored)
    assert keys.stored_key("codex-reviews/50%.md") == ("codex-reviews/50%.md", False)
    assert keys.raw_key("codex-reviews/50%25.md", False) == "codex-reviews/50%25.md"
    assert keys.stored_key("a\x00b") == ("a%00b", True) and keys.stored_key("%\t") == ("%25%09", True)


def test_keys_with_control_characters_are_recorded_escaped(pg_app, s3, migrated_pg_url, monkeypatch):
    key = "codex-reviews/50%\tdone.md"
    version = s3.put(key, REVIEW, checksum=None)
    run = run_sync()
    row = EvidenceStoreObject.query.filter_by(key="codex-reviews/50%25%09done.md").one()
    assert (row.key_escaped, row.kind, row.status, row.version_id) == (True, "unmapped", "non_conforming", version)
    assert run.counts["anomalies"] == 0 and run_sync().status == "unchanged"
    broken = _verify(s3)
    assert broken["listing"]["unrecorded_count"] == 0 and broken["records"]["failure_count"] == 1
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "acknowledge", "--key", row.key, "--version-id",
                     version, "--reason", "a test upload without a checksum", "--admin", admin.email)
    assert code == 0, out
    assert _verify(s3)["status"] == "valid"  # HeadObject of the raw key, the listing matched to the record


def test_a_nul_key_is_recorded_escaped(pg_app, s3, monkeypatch):
    key = "codex-reviews/a\x00b"
    group = store.KeyGroup(key)
    group.add(store.ListedVersion(key, "v1", len(REVIEW), None))
    heads = []

    def head_version(client, bucket, head_key, version_id):
        heads.append(head_key)
        return {"ContentLength": len(REVIEW), "ETag": '"e"', "ObjectLockMode": "GOVERNANCE",
                "ChecksumSHA256": b64_sha256(REVIEW),
                "ChecksumType": "FULL_OBJECT"}

    monkeypatch.setattr(store, "head_version", head_version)
    tally = sync.Tally()
    sync._process_batch(s3, BUCKET, [group], tally)
    row = EvidenceStoreObject.query.filter_by(key="codex-reviews/a%00b").one()
    assert (row.key_escaped, row.kind, row.status) == (True, "unmapped", "recorded") and heads == [key]
    assert tally.counts["anomalies"] == 0 and service.find_object(key, "v1").id == row.id
    assert service.find_object("codex-reviews/a%00b", "v1").id == row.id

    def groups(client, bucket, prefix, start_after=None):
        return iter([group] if prefix == "codex-reviews/" else [])

    monkeypatch.setattr(store, "iter_groups", groups)
    listing = store_verify.verify_listing(db.session, s3, BUCKET)
    assert (listing["failure_count"], listing["unrecorded_count"]) == (0, 0)


def test_listing_errors_are_reported_never_raised(pg_app, s3, monkeypatch):
    s3.put(REVIEW_KEY, REVIEW)
    original = s3.list_object_versions

    def refuse_decision_logs(**kwargs):
        if kwargs.get("Prefix") == "decision-logs/":
            raise _client_error("ListObjectVersions", "InternalError")
        return original(**kwargs)

    monkeypatch.setattr(s3, "list_object_versions", refuse_decision_logs)
    run = run_sync()
    assert run.status == "partial" and record(REVIEW_KEY).status == "ingested"
    assert run.details["errors"] == [{"key": "decision-logs/", "version_id": None,
                                      "error": "the listing failed (ClientError InternalError)"}]
    result = _verify(s3)
    assert result["status"] == "broken"
    assert ("decision-logs/", "the listing cannot be read (ClientError InternalError)") in _failures(result)


# --------------------------------------------------------------------------
# N8 + N13: bulk acknowledgement; the records of a former bucket
# --------------------------------------------------------------------------

def test_acknowledge_a_file_of_versions(pg_app, s3, migrated_pg_url, monkeypatch, tmp_path):
    first = s3.put("codex-reviews/a.md", REVIEW, checksum=None)
    second = s3.put("codex-reviews/b.md", REVIEW, checksum=None)
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    lines = [json.dumps({"key": "codex-reviews/a.md", "version_id": first}), "",
             json.dumps({"key": "codex-reviews/b.md", "version_id": second}), "not json",
             json.dumps({"key": REVIEW_KEY, "version_id": record(REVIEW_KEY).version_id}),
             json.dumps({"key": "codex-reviews/none.md", "version_id": "v"}), json.dumps(["x"])]
    path = tmp_path / "acknowledge.jsonl"
    path.write_text("\n".join(lines) + "\n")
    base = ("evidence-store", "acknowledge", "--reason", "uploaded before checksums were required", "--admin",
            admin.email)
    code, out = _cli(migrated_pg_url, monkeypatch, *base, "--file", str(path), "--key", "x")
    assert code == 2 and "replaces --key" in out
    code, out = _cli(migrated_pg_url, monkeypatch, *base, "--file", str(path))
    assert code == 2 and "Acknowledged 2 version(s); refused 4." in out
    assert "line 4: refused: not a JSON object" in out and "line 5: refused: only a non_conforming" in out
    assert {record("codex-reviews/a.md").status, record("codex-reviews/b.md").status} == {"acknowledged"}
    rows = db.session.execute(text("SELECT count(*) FROM audit_log WHERE table_name = 'evidence_store_objects' "
                                   "AND new_values->>'status' = 'acknowledged'")).scalar()
    assert rows == 2
    code, out = _cli(migrated_pg_url, monkeypatch, *base, "--file", str(tmp_path / "missing.jsonl"))
    assert code == 2 and "cannot read" in out
    code, out = _cli(migrated_pg_url, monkeypatch, *base)
    assert code == 2 and "--key and --version-id" in out


def test_records_of_a_former_bucket_are_handled_by_naming_it(pg_app, s3, migrated_pg_url, monkeypatch):
    former = "evidence-former-test"
    make_bucket(s3, former)
    old = ChecksummingS3(s3.client, former)
    old.checksums, old.head_overrides, old.policies = s3.checksums, s3.head_overrides, s3.policies
    version = old.put("codex-reviews/old.md", REVIEW, checksum=None)
    review = old.put(REVIEW_KEY, REVIEW)
    run, created = scheduler.enqueue_evidence_store_sync(former, "manual")
    assert created and scheduler.execute_claimed("evidence_store_sync", run.id) == "executed"
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    base = ("evidence-store", "acknowledge", "--key", "codex-reviews/old.md", "--version-id", version, "--reason",
            "uploaded by an early producer", "--admin", admin.email)
    code, out = _cli(migrated_pg_url, monkeypatch, *base)
    assert code == 2 and f"in bucket {BUCKET}" in out
    code, out = _cli(migrated_pg_url, monkeypatch, *base, "--bucket", former)
    assert code == 0, out
    s3.client.delete_object(Bucket=former, Key=REVIEW_KEY, VersionId=review, BypassGovernanceRetention=True)
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "record-erasure", "--key", REVIEW_KEY,
                     "--version-id", review, "--reason", "data-subject erasure request", "--admin", admin.email,
                     "--bucket", former)
    assert code == 0, out
    assert EvidenceStoreObject.query.filter_by(bucket=former, key=REVIEW_KEY).one().status == "erased"


def test_cli_help_states_the_operator_trust_boundary():
    from cli import evidence_store_cmd

    assert "Trust boundary" in evidence_store_cmd.__doc__
    assert "asserted by the operator" in evidence_store_cmd.ADMIN_HELP
