"""Evidence store integrity on PostgreSQL: pentest files held by several
sources, writer-caused failures, the bucket's protection, the guard on the
store's records, erasure and acknowledgement, every record against its own
bucket, pinned sidecars, document serving and sanitized run errors."""

import hashlib
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.models import DecisionLogSession, PentestFinding, db
from app.models.evidence_store import EvidenceDocument, EvidenceStoreObject, EvidenceStoreSyncRun
from app.services import evidence_import, team_service
from app.services.evidence_store import service, store, sync
from app.services.evidence_store import verify as store_verify
from tests.store_fakes import BUCKET, b64_sha256, bucket_policy
from tests.test_evidence_store_pg import (LOG_KEY, PENTEST, PENTEST_KEY, REVIEW, REVIEW_KEY, SIDECAR_KEY,  # noqa: F401
                                          TRANSCRIPT, _cli, _client_error, populate, record, run_sync, s3, tamper)

OTHER_PENTEST = json.dumps({"scan_id": "s2", "findings": [{"severity": "LOW", "summary": "other"}]}).encode()
EMPTY_PENTEST = json.dumps({"scan_id": "s3", "findings": []}).encode()


def _verify(s3, **kwargs):
    db.session.commit()
    return store_verify.verify_store(db.session, s3, BUCKET, **kwargs)


def _issues(result):
    return {(f["key"], f["issue"]) for part in ("records", "listing") for f in (result[part] or {}).get("failures", [])}


def _sources(path="layer2/scan-1.json"):
    return {f.source_file for f in PentestFinding.query.filter(PentestFinding.source_file.endswith(path))}


# --------------------------------------------------------------------------
# H1: a store upload never takes over another source's pentest findings
# --------------------------------------------------------------------------

def test_an_empty_store_file_leaves_repository_findings_intact(pg_app, s3):
    evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, PENTEST, namespace="git-src")
    evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, OTHER_PENTEST)  # cli import
    db.session.commit()
    s3.put(PENTEST_KEY, EMPTY_PENTEST)
    run = run_sync()
    assert PentestFinding.query.filter_by(source_file="git-src:layer2/scan-1.json").count() == 2
    assert PentestFinding.query.filter_by(source_file="layer2/scan-1.json").count() == 1
    assert record(PENTEST_KEY).status in ("unchanged", "ingested")
    assert [c["key"] for c in run.details["conflicts"]] == [PENTEST_KEY]
    # Later imports of the path still apply: nothing is skipped because the store holds the file.
    changed = evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, OTHER_PENTEST, namespace="git-src")
    db.session.commit()
    # The git source's own two findings are replaced; it also retires the cli import's copy (the cutover rule).
    assert (changed.skipped, changed.created, changed.deleted, changed.retired) == (0, 1, 3, 1)
    again = evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, PENTEST)
    db.session.commit()
    assert again.skipped == 0 and PentestFinding.query.filter_by(source_file="layer2/scan-1.json").count() == 2


def test_a_store_file_held_identically_elsewhere_is_a_duplicate(pg_app, s3):
    evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, PENTEST, namespace="git-src")
    db.session.commit()
    s3.put(PENTEST_KEY, PENTEST)
    run = run_sync()
    row = record(PENTEST_KEY)
    assert row.status == "duplicate" and "git-src" in row.detail and row.sha256 == hashlib.sha256(PENTEST).hexdigest()
    assert run.status == "success" and run.counts["duplicate"] == 1
    assert PentestFinding.query.count() == 2 and _sources() == {"git-src:layer2/scan-1.json"}
    assert run_sync().status == "unchanged"  # the duplicate is not re-imported while its counterpart holds it
    assert PentestFinding.query.count() == 2


def test_a_duplicate_is_imported_once_its_counterpart_no_longer_holds_the_findings(pg_app, s3):
    evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, PENTEST, namespace="git-src")
    db.session.commit()
    s3.put(PENTEST_KEY, PENTEST)
    run_sync()
    assert record(PENTEST_KEY).status == "duplicate"
    evidence_import.remove_dataset_file("pentest-findings", PENTEST_KEY, namespace="git-src")
    db.session.commit()
    assert PentestFinding.query.count() == 0
    run = run_sync()
    row = record(PENTEST_KEY)
    assert row.status == "ingested" and run.counts["reevaluated"] == 1
    assert _sources() == {"evidence-store:layer2/scan-1.json"} and PentestFinding.query.count() == 2


def test_a_cli_import_copy_is_never_taken_over_by_the_store(pg_app, s3):
    evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, OTHER_PENTEST)
    db.session.commit()
    s3.put(PENTEST_KEY, PENTEST)
    run_sync()
    assert _sources() == {"layer2/scan-1.json", "evidence-store:layer2/scan-1.json"}
    assert record(PENTEST_KEY).status == "ingested" and "conflict" in record(PENTEST_KEY).detail


# --------------------------------------------------------------------------
# H2: writer-caused failures are recorded once, deterministically
# --------------------------------------------------------------------------

def test_deeply_nested_json_is_rejected_once(pg_app, s3):
    deep = b"[" * 100_000 + b"]" * 100_000
    s3.put(PENTEST_KEY, deep)
    nested_line = (b'{"type": "user", "message": ' + b"[" * 50_000 + b"]" * 50_000 + b"}\n")
    s3.put(LOG_KEY, TRANSCRIPT + nested_line)
    s3.put("decision-logs/2026-10-02T000000Z_sess-side.jsonl", TRANSCRIPT)
    s3.put("decision-logs/2026-10-02T000000Z_sess-side.meta.json", b'{"agent": ' + b"[" * 20_000 + b"]" * 20_000 + b"}")
    run = run_sync()
    assert record(PENTEST_KEY).status == "rejected" and "nested" in record(PENTEST_KEY).detail
    assert record(LOG_KEY).status == "rejected" and "nested" in record(LOG_KEY).detail
    assert record("decision-logs/2026-10-02T000000Z_sess-side.jsonl").status == "ingested"
    assert run.counts["errors"] == 0
    assert run_sync().status == "unchanged"


def test_an_unreadable_sidecar_supplies_nothing(pg_app, s3, monkeypatch):
    s3.put(LOG_KEY, TRANSCRIPT)
    s3.put(SIDECAR_KEY, json.dumps({"agent": "codex"}).encode())

    real = store.read_version

    def broken(client, bucket, key, version_id, limit):
        if key == SIDECAR_KEY:
            raise RuntimeError("anything at all")
        return real(client, bucket, key, version_id, limit)

    monkeypatch.setattr(store, "read_version", broken)
    run = run_sync()
    assert record(LOG_KEY).status == "ingested"
    assert db.session.get(DecisionLogSession, "sess-store").agent_type == "claude_code"
    # The sidecar's own record is a version not read yet, tried again at the next sync.
    assert record(SIDECAR_KEY).status == "error" and run.counts["errors"] == 1


def test_a_version_failing_every_sync_stays_an_error_and_is_pending(pg_app, s3, monkeypatch):
    s3.put(REVIEW_KEY, REVIEW)
    original = s3.get_object

    def refuse(**kwargs):
        raise _client_error("GetObject", "SlowDown")

    monkeypatch.setattr(s3, "get_object", refuse)
    first = run_sync()
    row = record(REVIEW_KEY)
    assert (row.status, row.attempts) == ("error", 1) and first.status == "partial"
    assert row.sha256 == hashlib.sha256(REVIEW).hexdigest()  # the stored checksum, from HeadObject
    for attempts in (2, 3, 4):
        run = run_sync()
        row = record(REVIEW_KEY)
        assert (row.status, row.attempts) == ("error", attempts) and run.counts["rejected"] == 0
    assert "SlowDown" in row.detail and "read again at every sync" in row.detail
    monkeypatch.setattr(s3, "get_object", original)
    # A failure to read is never a refusal of the content: pending (unverified), never broken.
    pending = _verify(s3)
    assert pending["status"] == "unverified" and pending["failure_count"] == 0
    assert pending["records"]["pending_count"] == 1 and pending["records"]["refusals_count"] == 0
    recovered = run_sync()  # every later sync reads it again, and imports it once it can
    assert recovered.status == "success" and EvidenceDocument.query.count() == 1
    assert (record(REVIEW_KEY).id, record(REVIEW_KEY).status) == (row.id, "ingested")
    assert _verify(s3)["status"] == "valid"


def test_a_failed_version_recovers_on_its_record(pg_app, s3, monkeypatch):
    s3.put(REVIEW_KEY, REVIEW)
    original = s3.head_object

    def refuse(**kwargs):
        raise _client_error("HeadObject", "InternalError")

    monkeypatch.setattr(s3, "head_object", refuse)
    run_sync()
    failed = record(REVIEW_KEY)
    assert failed.status == "error" and failed.sha256 is None
    monkeypatch.setattr(s3, "head_object", original)
    run_sync()
    recovered = record(REVIEW_KEY)
    assert recovered.id == failed.id and recovered.status == "ingested"
    assert recovered.sha256 == hashlib.sha256(REVIEW).hexdigest() and EvidenceDocument.query.count() == 1


def test_database_data_errors_while_writing_stay_errors(pg_app, s3, monkeypatch):
    class DataError(Exception):
        pgcode = "22001"

    s3.put(REVIEW_KEY, REVIEW)
    real = sync.write_version

    def failing(bucket, fetched, tally, **kwargs):
        if fetched.status is None:
            raise DataError("value too long for type character varying(500) with secret arn:aws:iam::123:role/x")
        return real(bucket, fetched, tally, **kwargs)

    monkeypatch.setattr(sync, "write_version", failing)
    run = run_sync()
    row = record(REVIEW_KEY)
    # A write failure after a passing content check is never a refusal of the content: an error, retried.
    assert (row.status, row.attempts) == ("error", 1) and "DataError 22001" in row.detail and "arn:" not in row.detail
    assert "arn:" not in json.dumps(run.details) and run.counts["rejected"] == 0
    assert _verify(s3)["status"] == "unverified"
    monkeypatch.setattr(sync, "write_version", real)
    run_sync()
    assert record(REVIEW_KEY).status == "ingested" and _verify(s3)["status"] == "valid"


@pytest.mark.parametrize("key", [
    "decision-logs/yesterday_sess.jsonl",
    "decision-logs/2026-13-01T000000Z_sess.jsonl",
    "decision-logs/2026-10-01T000000Z_" + "s" * 101 + ".jsonl",
    "pentest-evidence/layer0/scan.json",
    "pentest-evidence/layer12/scan.json",
    "pentest-evidence/layer1/" + "n" * 201 + ".json",
])
def test_keys_outside_the_strict_patterns_are_unmapped_and_never_read(pg_app, s3, key):
    s3.put(key, b"{}")
    run_sync()
    row = record(key)
    assert row.kind == "unmapped" and row.status == "recorded" and s3.reads(key) == 0


# --------------------------------------------------------------------------
# H3: the bucket's protection is verified
# --------------------------------------------------------------------------

def test_each_sync_records_the_default_retention(pg_app, s3):
    run = run_sync()
    assert (run.retention_mode, run.retention_days) == ("GOVERNANCE", 7 * 365)
    audited = db.session.execute(text(
        "SELECT new_values->>'retention_days' FROM audit_log WHERE table_name = 'evidence_store_sync_runs' "
        "AND new_values->>'retention_days' IS NOT NULL")).scalars().all()
    assert audited and audited[-1] == str(7 * 365)


def test_lowered_default_retention_fails_verification(pg_app, s3):
    populate(s3)
    run_sync()
    assert _verify(s3)["status"] == "valid"
    s3.set_default_retention(BUCKET, {"Mode": "GOVERNANCE", "Days": 1})
    result = _verify(s3)
    assert result["status"] == "broken"
    assert any("below the retention floor" in issue for issue in result["bucket_check"]["issues"])
    assert run_sync().retention_days == 1  # each sync records what it read
    s3.set_default_retention(BUCKET, {"Mode": "NONE", "Years": 7})
    assert any("not GOVERNANCE or COMPLIANCE" in i for i in _verify(s3)["bucket_check"]["issues"])
    tamper("DELETE FROM evidence_store_retention_floors", table="evidence_store_retention_floors")
    s3.set_default_retention(BUCKET, {"Mode": "GOVERNANCE", "Years": 7})
    assert any("no retention floor" in i for i in _verify(s3)["bucket_check"]["issues"])


def test_short_object_retention_fails_and_expired_retention_is_informational(pg_app, s3):
    populate(s3)
    run_sync()
    review = record(REVIEW_KEY)
    tamper("UPDATE evidence_store_objects SET retain_until = last_modified + interval '2 days' WHERE id = :i",
           {"i": review.id})
    s3.head_overrides[(review.key, review.version_id)] = {
        "ObjectLockRetainUntilDate": review.last_modified + timedelta(days=2)}
    result = _verify(s3)
    assert result["status"] == "broken" and any(
        key == REVIEW_KEY and "shorter than" in issue for key, issue in _issues(result))
    pentest = record(PENTEST_KEY)
    s3.head_overrides[(review.key, review.version_id)] = {}
    tamper("UPDATE evidence_store_objects SET retain_until = :t WHERE id = :i",
           {"t": datetime.now(timezone.utc) - timedelta(days=1), "i": review.id})
    tamper("UPDATE evidence_store_objects SET last_modified = :t WHERE id = :i",
           {"t": datetime.now(timezone.utc) - timedelta(days=7 * 365 + 2), "i": review.id})
    s3.head_overrides[(review.key, review.version_id)] = {
        "ObjectLockRetainUntilDate": datetime.now(timezone.utc) - timedelta(days=1),
        "LastModified": datetime.now(timezone.utc) - timedelta(days=7 * 365 + 2)}
    expired = _verify(s3)
    assert expired["records"]["retention_expired_count"] == 1, expired
    assert expired["records"]["retention_expired"][0]["key"] == REVIEW_KEY
    assert not any(key == REVIEW_KEY for key, _ in _issues(expired))
    assert pentest.key not in {k for k, _ in _issues(expired)}


@pytest.mark.parametrize("policy,issue", [
    (None, "no bucket policy"),
    (bucket_policy(actions=["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention"]),
     "s3:BypassGovernanceRetention"),
    (bucket_policy(if_none_match=False), "If-None-Match"),
    (bucket_policy(delete_condition={"StringEquals": {"aws:PrincipalAccount": "000000000000"}}), "s3:DeleteObject"),
])
def test_a_weakened_bucket_policy_fails_verification(pg_app, s3, policy, issue):
    if policy is None:
        s3.delete_bucket_policy(Bucket=BUCKET)
    else:
        s3.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(policy))
    result = _verify(s3)
    assert result["status"] == "broken" and any(issue in i for i in result["bucket_check"]["issues"]), result


def test_an_erasure_principal_makes_verification_unverified(pg_app, s3):
    principal = "arn:aws:iam::111122223333:role/evidence-erasure"
    s3.put_bucket_policy(Bucket=BUCKET, Policy=json.dumps(bucket_policy(erasure_principal=principal)))
    result = _verify(s3)
    assert result["status"] == "unverified" and result["bucket_check"]["erasure_principals"] == [principal]


def test_expiring_lifecycle_rules_fail_verification(pg_app, s3):
    s3.client.put_bucket_lifecycle_configuration(Bucket=BUCKET, LifecycleConfiguration={"Rules": [
        {"ID": "abort", "Status": "Enabled", "Filter": {"Prefix": ""},
         "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}}]})
    assert _verify(s3)["status"] == "valid"
    s3.client.put_bucket_lifecycle_configuration(Bucket=BUCKET, LifecycleConfiguration={"Rules": [
        {"ID": "expire", "Status": "Enabled", "Filter": {"Prefix": "codex-reviews/"},
         "NoncurrentVersionExpiration": {"NoncurrentDays": 30}}]})
    result = _verify(s3)
    assert result["status"] == "broken" and any("expire" in i for i in result["bucket_check"]["issues"])


# --------------------------------------------------------------------------
# M1: the records are evidence
# --------------------------------------------------------------------------

def _pg_error(statement, params=None):
    with pytest.raises(Exception, match="refused|recorded before"):
        db.session.execute(text(statement), params or {})
        db.session.commit()
    db.session.rollback()


def test_the_guard_freezes_records_and_documents(pg_app, s3):
    populate(s3)
    run_sync()
    log, review = record(LOG_KEY), record(REVIEW_KEY)
    _pg_error("UPDATE evidence_store_objects SET sha256 = :s WHERE id = :i", {"s": "1" * 64, "i": log.id})
    _pg_error("UPDATE evidence_store_objects SET key = 'x' WHERE id = :i", {"i": log.id})
    _pg_error("UPDATE evidence_store_objects SET status = 'rejected' WHERE id = :i", {"i": log.id})
    _pg_error("UPDATE evidence_store_objects SET status = 'acknowledged' WHERE id = :i", {"i": log.id})
    _pg_error("UPDATE evidence_store_objects SET status = 'erased' WHERE id = :i", {"i": log.id})
    _pg_error("DELETE FROM evidence_store_objects WHERE id = :i", {"i": log.id})
    _pg_error("TRUNCATE evidence_store_objects CASCADE")
    _pg_error("INSERT INTO evidence_store_objects (id, bucket, key, version_id, kind, status, size, attempts) "
              "VALUES ('x', 'b', 'k', 'v', 'unmapped', 'erased', 0, 0)")
    document = EvidenceDocument.query.one()
    _pg_error("UPDATE evidence_documents SET sha256 = :s", {"s": "0" * 64})
    _pg_error("UPDATE evidence_documents SET kind = 'pentest-report'")
    _pg_error("DELETE FROM evidence_documents")
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    db.session.execute(text(
        "UPDATE evidence_store_objects SET status = 'erased', erased_at = now(), erased_by = :a, "
        "erasure_reason = 'documented' WHERE id = :i"), {"a": admin.id, "i": review.id})
    db.session.commit()
    _pg_error("UPDATE evidence_store_objects SET status = 'ingested' WHERE id = :i", {"i": review.id})
    assert db.session.get(EvidenceDocument, document.id) is not None


def test_record_erasure_requires_the_version_to_be_gone(pg_app, s3, migrated_pg_url, monkeypatch):
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    review = record(REVIEW_KEY)
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "record-erasure", "--key", REVIEW_KEY,
                     "--version-id", review.version_id, "--reason", "purge", "--admin", admin.email)
    assert code == 2 and "still exists" in out and record(REVIEW_KEY).status == "ingested"


def test_verify_fails_an_erased_record_whose_version_exists(pg_app, s3):
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    tamper("UPDATE evidence_store_objects SET status = 'erased', erased_at = now(), erased_by = :a, "
           "erasure_reason = 'claimed' WHERE key = :k", {"a": admin.id, "k": REVIEW_KEY})
    result = _verify(s3)
    assert result["status"] == "broken" and any("still exists" in issue for _, issue in _issues(result))


def test_verify_cross_checks_documents_against_their_records(pg_app, s3):
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    assert _verify(s3)["documents"]["failure_count"] == 0
    tamper("UPDATE evidence_documents SET sha256 = :s", {"s": "0" * 64}, table="evidence_documents")
    result = _verify(s3)
    assert result["status"] == "broken" and result["documents"]["failure_count"] == 1


# --------------------------------------------------------------------------
# M2: every record against its own bucket
# --------------------------------------------------------------------------

def test_records_of_another_bucket_are_verified_there(pg_app, s3):
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    db.session.add(EvidenceStoreObject(id=str(uuid.uuid4()), bucket="elsewhere-bucket", key=REVIEW_KEY,
                                       version_id="v-elsewhere", kind="evidence_document", status="recorded",
                                       sha256="a" * 64, size=1, attempts=0))
    db.session.commit()
    result = _verify(s3)
    assert result["status"] == "broken" and result["records"]["checked"] == 2
    assert any(f.get("bucket") == "elsewhere-bucket" for f in result["records"]["failures"])


# --------------------------------------------------------------------------
# M3: sidecars are pinned to their first version
# --------------------------------------------------------------------------

def test_the_sidecar_is_read_at_its_first_version(pg_app, s3):
    first = s3.put(SIDECAR_KEY, json.dumps({"agent": "openclaude"}).encode())
    s3.put(SIDECAR_KEY, json.dumps({"agent": "codex"}).encode())  # a second write of a write-once key
    s3.put(LOG_KEY, TRANSCRIPT)
    run_sync()
    assert db.session.get(DecisionLogSession, "sess-store").agent_type == "openclaude"
    assert record(LOG_KEY).import_info["sidecar"] == {"key": SIDECAR_KEY, "version_id": first, "read": True}


# --------------------------------------------------------------------------
# M4: a non-conforming upload is read, recorded and can be acknowledged
# --------------------------------------------------------------------------

def test_non_conforming_objects_are_hashed_and_can_be_acknowledged(pg_app, s3, migrated_pg_url, monkeypatch):
    key = "codex-reviews/plain.md"
    s3.put(key, REVIEW, checksum=None)
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    row = record(key)
    assert row.status == "non_conforming" and row.sha256 == hashlib.sha256(REVIEW).hexdigest() and row.etag
    assert _verify(s3)["status"] == "broken"
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    agent = team_service.create_member("Agent", "agent@example.com", "agent")
    args = ("evidence-store", "acknowledge", "--key", key, "--version-id", row.version_id, "--reason")
    code, out = _cli(migrated_pg_url, monkeypatch, *args, "uploaded without a checksum", "--admin", agent.email)
    assert code == 2 and "not an active compliance admin" in out
    code, out = _cli(migrated_pg_url, monkeypatch, *args, "uploaded without a checksum", "--admin", admin.email)
    assert code == 0, out
    acknowledged = record(key)
    assert (acknowledged.status, acknowledged.acknowledged_by) == ("acknowledged", admin.id)
    audit = db.session.execute(text("SELECT changed_by FROM audit_log WHERE table_name = 'evidence_store_objects' "
                                    "AND new_values->>'status' = 'acknowledged'")).scalar()
    assert audit == admin.id
    result = _verify(s3, full=True)
    assert result["status"] == "valid", result
    assert result["records"]["acknowledged_count"] == 1
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "acknowledge", "--key", REVIEW_KEY,
                     "--version-id", record(REVIEW_KEY).version_id, "--reason", "x", "--admin", admin.email)
    assert code == 2 and "non_conforming" in out
    s3.head_overrides[(key, row.version_id)] = {"ETag": '"0000"'}
    assert _verify(s3)["status"] == "broken"


# --------------------------------------------------------------------------
# Low: documents, the verify API, capped lists, sanitized errors, admin filter, migration
# --------------------------------------------------------------------------

def test_document_reads_are_bounded_per_process(pg_app, s3, monkeypatch):
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    document = EvidenceDocument.query.one()
    agent = team_service.create_member("Agent", "agent@example.com", "agent")
    client = pg_app.test_client()
    url = f"/api/evidence-documents/{document.id}/content"
    monkeypatch.setattr(service, "_READ_SLOTS", threading.BoundedSemaphore(1))
    assert service._READ_SLOTS.acquire(blocking=False)
    try:
        busy = client.get(url, headers={"X-API-Key": agent.issued_api_key})
        assert busy.status_code == 429 and busy.headers["Retry-After"]
    finally:
        service._READ_SLOTS.release()
    served = client.get(url, headers={"X-API-Key": agent.issued_api_key})
    assert served.status_code == 200 and served.data == REVIEW and served.headers["Content-Length"] == str(len(REVIEW))


def test_full_verification_through_the_api_is_a_small_page(pg_app, s3, monkeypatch):
    from app.routes import evidence_store_api

    populate(s3)
    run_sync()
    monkeypatch.setattr(evidence_store_api, "MAX_FULL_VERIFY_ITEMS", 2)
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    body = pg_app.test_client().get("/api/evidence-store/verify?full=true&max_items=500",
                                    headers={"X-API-Key": admin.issued_api_key}).get_json()
    assert body["records"]["checked"] == 2 and body["next_cursor"] and body["max_items"] == 2


def test_failure_lists_are_capped_with_exact_counts(pg_app, s3, monkeypatch):
    monkeypatch.setattr(store_verify, "MAX_KEPT", 2)
    for index in range(5):
        s3.put(f"codex-reviews/r{index}.md", REVIEW, checksum=None)
    run_sync()
    result = _verify(s3)
    assert result["records"]["failure_count"] == 5 and len(result["records"]["failures"]) == 2


def test_run_errors_are_sanitized(pg_app, s3, monkeypatch):
    from botocore.exceptions import ClientError

    s3.put(REVIEW_KEY, REVIEW)
    secret = "arn:aws:iam::123456789012:role/secret-role on evidence-store-test/codex-reviews/x"

    def refuse(**kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": secret}}, "HeadObject")

    monkeypatch.setattr(s3, "head_object", refuse)
    run = run_sync()
    assert run.details["errors"][0]["error"] == "ClientError AccessDenied"
    assert secret not in json.dumps(run.details) and "123456789012" not in (record(REVIEW_KEY).detail or "")

    def refuse_listing(**kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": secret}}, "ListObjectVersions")

    monkeypatch.setattr(s3, "list_object_versions", refuse_listing)
    failed = run_sync()
    assert failed.status == "failure" and failed.error_message == "the listing failed (ClientError AccessDenied)"
    assert secret not in json.dumps(failed.details)


def test_audit_log_filter_lists_the_evidence_store_tables(pg_app):
    from tests.conftest import login

    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    client = pg_app.test_client()
    login(client, admin)
    page = client.get("/admin/audit-log").data
    for table in ("evidence_store_objects", "evidence_store_sync_runs", "evidence_store_retention_floors",
                  "evidence_documents", "evidence_document_links"):
        assert table.encode() in page, table


def test_migration_021_validates_the_store_object_foreign_key(pg_app):
    validated = db.session.execute(text(
        "SELECT convalidated FROM pg_constraint WHERE conname = 'fk_decision_log_transcripts_store_object'")).scalar()
    assert validated is True
    guards = set(db.session.execute(text(
        "SELECT tgname FROM pg_trigger WHERE tgname LIKE 'evidence_%guard' OR tgname LIKE 'evidence_%no_truncate'"
    )).scalars())
    assert {"evidence_store_objects_guard", "evidence_store_objects_no_truncate", "evidence_documents_guard",
            "evidence_documents_no_truncate", "evidence_store_sync_runs_guard", "evidence_store_sync_runs_no_truncate",
            "evidence_store_retention_floors_guard", "evidence_store_retention_floors_no_truncate"} <= guards


def test_store_sync_run_model_has_retention_columns():
    assert {"retention_mode", "retention_days"} <= set(EvidenceStoreSyncRun.__table__.columns.keys())
    assert {"etag", "attempts", "sync_run_id", "import_info", "acknowledged_at", "acknowledged_by",
            "acknowledgement_reason", "key_escaped"} <= set(EvidenceStoreObject.__table__.columns.keys())
    assert b64_sha256(b"") and sync.MAX_ATTEMPTS == 3
