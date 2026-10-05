"""Evidence store on PostgreSQL: sync (diff-only, anomalies, checksums, size
limits, decision logs, pentest findings, documents), verification of the
store and of decision logs against it, documented erasure, document links
and content, the scheduler kind and migration 021."""

import io
import json
import uuid
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app import runtime_config
from app.models import Control, DecisionLogSession, DecisionLogTranscript, PentestFinding, TestRecord, db
from app.models.evidence_store import EvidenceDocument, EvidenceStoreObject, EvidenceStoreSyncRun
from app.services import evidence_import, scheduler, team_service
from app.services.evidence_store import service, store, sync
from app.services.evidence_store import verify as store_verify
from tests.store_fakes import BUCKET, ChecksummingS3, b64_sha256, make_bucket
from tests.test_round2_git import GENUINE, rec

LOG_KEY = "decision-logs/2026-10-01T000000Z_sess-store.jsonl"
SIDECAR_KEY = "decision-logs/2026-10-01T000000Z_sess-store.meta.json"
TRANSCRIPT = ("\n".join(GENUINE[:2]) + "\n").encode()
LONGER = ("\n".join(GENUINE) + "\n").encode()
PENTEST_KEY = "pentest-evidence/layer2/scan-1.json"
PENTEST = json.dumps({"scan_id": "s1", "repo": "portal", "timestamp": "2026-04-16T193413Z",
                      "findings": [{"severity": "HIGH", "summary": "first"},
                                   {"severity": "LOW", "summary": "second"}]}).encode()
REVIEW_KEY = "codex-reviews/2026/review-1.md"
REVIEW = b"# Review\n\nNo findings.\n"
UNMAPPED_KEY = "decision-logs/notes.txt"


@pytest.fixture
def s3(monkeypatch):
    with mock_aws():
        for name, value in (("AWS_ACCESS_KEY_ID", "testing"), ("AWS_SECRET_ACCESS_KEY", "testing"),
                            ("AWS_REGION", "us-east-1"), ("EVIDENCE_STORE_BUCKET", BUCKET)):
            monkeypatch.setenv(name, value)
        for name in ("AWS_RUNTIME_ROLE_ARN", "PORTAL_SECRET_ID"):
            monkeypatch.delenv(name, raising=False)
        client = boto3.client("s3", region_name="us-east-1")
        fake = ChecksummingS3(client)
        make_bucket(fake)
        monkeypatch.setattr(store, "s3_client", lambda: fake)
        yield fake


def run_sync(member_id=None):
    run, created = scheduler.enqueue_evidence_store_sync(BUCKET, "manual", member_id)
    assert created
    assert scheduler.execute_claimed("evidence_store_sync", run.id) == "executed"
    db.session.expire_all()
    return db.session.get(EvidenceStoreSyncRun, run.id)


def audit_count(exclude=("evidence_store_sync_runs",)):
    return db.session.execute(text("SELECT count(*) FROM audit_log WHERE table_name <> ALL(:x)"),
                              {"x": list(exclude)}).scalar()


def record(key):
    return EvidenceStoreObject.query.filter_by(key=key).one()


def tamper(statement, params=None, table="evidence_store_objects"):
    """Change a record as only the database owner can: with the table's guard disabled."""
    db.session.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER {table}_guard"))
    db.session.execute(text(statement), params or {})
    db.session.execute(text(f"ALTER TABLE {table} ENABLE TRIGGER {table}_guard"))
    db.session.commit()


def populate(s3):
    versions = {
        LOG_KEY: s3.put(LOG_KEY, TRANSCRIPT, metadata={"producer": "session-end", "agent": "codex",
                                                       "session-id": "sess-store", "redaction": "rules-1"},
                        content_type="application/x-ndjson"),
        SIDECAR_KEY: s3.put(SIDECAR_KEY, json.dumps({"reason": "clear", "agent": "openclaude"}).encode()),
        PENTEST_KEY: s3.put(PENTEST_KEY, PENTEST, metadata={"producer": "security-scan"}),
        REVIEW_KEY: s3.put(REVIEW_KEY, REVIEW, metadata={"producer": "code-review"}, content_type="text/markdown"),
        UNMAPPED_KEY: s3.put(UNMAPPED_KEY, b"free text"),
    }
    return versions


def _cli(migrated_pg_url, monkeypatch, *argv):
    from cli.__main__ import build_parser, main  # noqa: F401

    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", migrated_pg_url)
    runtime_config._reset_for_tests()
    out = io.StringIO()
    args = build_parser().parse_args(list(argv))
    if args.command == "evidence-store":
        from cli import evidence_store_cmd
        code = evidence_store_cmd.run(args, out=out)
    else:
        from cli import admin_cmd
        code = admin_cmd.run(args, out=out)
    db.session.expire_all()
    return code, out.getvalue()


# --------------------------------------------------------------------------
# Sync
# --------------------------------------------------------------------------

def test_sync_records_and_imports_every_kind(pg_app, s3):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    versions = populate(s3)
    run = run_sync(admin.id)
    assert run.status == "success", run.details
    assert run.counts["listed"] == 5 and run.counts["new"] == 5
    assert (run.counts["ingested"], run.counts["recorded"], run.counts["anomalies"]) == (3, 2, 0)

    log = record(LOG_KEY)
    assert (log.kind, log.status, log.version_id) == ("decision_log", "ingested", versions[LOG_KEY])
    assert log.sha256 == __import__("hashlib").sha256(TRANSCRIPT).hexdigest() and log.size == len(TRANSCRIPT)
    assert log.lock_mode == "GOVERNANCE" and log.retain_until > datetime.now(timezone.utc) + timedelta(days=365 * 6)
    assert log.object_metadata == {"producer": "session-end", "agent": "codex", "session-id": "sess-store",
                                   "redaction": "rules-1"}
    assert log.content_type == "application/x-ndjson"
    version = DecisionLogTranscript.query.filter_by(session_id="sess-store", status="current").one()
    assert version.store_object_id == log.id and version.source_path == LOG_KEY
    assert version.submitted_by is None and version.source_commit is None
    session = db.session.get(DecisionLogSession, "sess-store")
    assert session.agent_type == "codex"  # metadata wins over the sidecar's openclaude
    assert session.exit_reason == "clear"  # no exit-reason metadata: the sidecar's reason
    assert session.repository_entries == 2

    assert (record(SIDECAR_KEY).kind, record(SIDECAR_KEY).status) == ("decision_log_sidecar", "recorded")
    assert (record(UNMAPPED_KEY).kind, record(UNMAPPED_KEY).status) == ("unmapped", "recorded")
    assert s3.reads(UNMAPPED_KEY) == 0  # an unmapped object is never read
    findings = PentestFinding.query.all()
    assert len(findings) == 2 and {f.source_file for f in findings} == {"evidence-store:layer2/scan-1.json"}
    document = EvidenceDocument.query.one()
    assert (document.kind, document.title) == ("code-review", "2026/review-1.md")
    assert document.store_object_id == record(REVIEW_KEY).id

    rows = db.session.execute(text(
        "SELECT changed_by FROM audit_log WHERE table_name = 'evidence_store_objects'")).all()
    assert len(rows) == 5 and {row.changed_by for row in rows} == {admin.id}


def test_resync_writes_nothing_and_adds_no_audit_rows(pg_app, s3):
    populate(s3)
    assert run_sync().status == "success"
    before = audit_count()
    again = run_sync()
    assert again.status == "unchanged" and again.counts["new"] == 0 and again.counts["listed"] == 5
    assert audit_count() == before
    assert s3.reads(LOG_KEY) == 1


def test_anomalies_are_listed_counted_and_never_recorded(pg_app, s3):
    first = s3.put(REVIEW_KEY, REVIEW)
    second = s3.put(REVIEW_KEY, b"# Replaced\n")
    s3.put("codex-reviews/gone.md", b"gone")
    s3.client.delete_object(Bucket=BUCKET, Key="codex-reviews/gone.md")
    run = run_sync()
    assert run.status == "partial" and run.counts["anomalies"] == 2
    issues = {(a["key"], a["version_id"], a["issue"]) for a in run.details["anomalies"]}
    assert (REVIEW_KEY, second, sync.SECOND_VERSION) in issues
    assert any(a["key"] == "codex-reviews/gone.md" and a["issue"] == sync.DELETE_MARKER
               for a in run.details["anomalies"])
    assert [r.version_id for r in EvidenceStoreObject.query.filter_by(key=REVIEW_KEY)] == [first]
    assert EvidenceDocument.query.count() == 2  # the first version of each key
    assert run_sync().status == "partial"  # anomalies stay visible on every sync
    from tests.conftest import login

    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    client = pg_app.test_client()
    login(client, admin)
    page = client.get("/admin/evidence-store")
    assert page.status_code == 200 and sync.SECOND_VERSION.encode() in page.data and b"partial" in page.data


def test_non_conforming_objects_are_recorded_and_not_imported(pg_app, s3):
    s3.put("decision-logs/2026-10-01T000000Z_no-checksum.jsonl", TRANSCRIPT, checksum=None)
    s3.put("decision-logs/2026-10-01T000000Z_multipart.jsonl", TRANSCRIPT, checksum=b64_sha256(TRANSCRIPT) + "-0")
    s3.put("decision-logs/2026-10-01T000000Z_mismatch.jsonl", TRANSCRIPT, checksum=b64_sha256(b"other"))
    run = run_sync()
    assert run.status == "partial" and run.counts["non_conforming"] == 3
    missing = record("decision-logs/2026-10-01T000000Z_no-checksum.jsonl")
    assert missing.status == "non_conforming" and "no SHA-256" in missing.detail
    assert missing.sha256 == __import__("hashlib").sha256(TRANSCRIPT).hexdigest()  # hashed, never imported
    assert s3.reads(missing.key) == 1 and missing.etag
    malformed = record("decision-logs/2026-10-01T000000Z_multipart.jsonl")  # a composite checksum of 0 parts
    assert malformed.status == "non_conforming" and "malformed" in malformed.detail
    assert malformed.composite_checksum is None
    mismatch = record("decision-logs/2026-10-01T000000Z_mismatch.jsonl")
    assert mismatch.sha256 == __import__("hashlib").sha256(TRANSCRIPT).hexdigest()
    assert sync.BODY_MISMATCH in mismatch.detail
    assert DecisionLogSession.query.count() == 0


def test_size_limits_apply_before_any_byte_is_read(pg_app, s3, monkeypatch):
    from app.services import evidence_import_decision_logs as decision_logs

    monkeypatch.setattr(sync, "PENTEST_LIMIT", 10)
    monkeypatch.setattr(sync, "DOCUMENT_LIMIT", 10)
    monkeypatch.setattr(decision_logs, "MAX_TRANSCRIPT_BYTES", 10)
    s3.put(PENTEST_KEY, PENTEST)
    s3.put(REVIEW_KEY, REVIEW)
    s3.put(LOG_KEY, TRANSCRIPT)
    run = run_sync()
    assert run.counts["too_large"] == 3 and run.status == "partial"
    for key in (PENTEST_KEY, REVIEW_KEY, LOG_KEY):
        row = record(key)
        assert row.status == "too_large" and "not read" in row.detail
        assert row.sha256 == __import__("hashlib").sha256({PENTEST_KEY: PENTEST, REVIEW_KEY: REVIEW,
                                                           LOG_KEY: TRANSCRIPT}[key]).hexdigest()
        assert s3.reads(key) == 0
    assert PentestFinding.query.count() == 0 and EvidenceDocument.query.count() == 0


def test_invalid_keys_and_metadata_are_recorded_safely(pg_app, s3):
    s3.put("decision-logs/no-session.jsonl", TRANSCRIPT)
    s3.put("codex-reviews/a//b.md", REVIEW)
    s3.put("codex-reviews/a\\b.md", REVIEW)
    s3.put(LOG_KEY, TRANSCRIPT, metadata={"agent": "bad agent!", "session-id": "someone-else", "x-extra": "1",
                                          "producer": "Session End"})
    run = run_sync()
    assert record("decision-logs/no-session.jsonl").kind == "unmapped"
    assert "session id" in record("decision-logs/no-session.jsonl").detail
    empty_segment = record("codex-reviews/a//b.md")
    assert empty_segment.kind == "unmapped" and ". or .." in empty_segment.detail
    assert "backslash" in record("codex-reviews/a\\b.md").detail
    assert EvidenceDocument.query.count() == 0 and s3.reads("codex-reviews/a//b.md") == 0
    log = record(LOG_KEY)
    assert log.object_metadata is None
    assert "metadata agent: invalid value dropped" in log.detail
    assert "session-id differs" in log.detail and "1 unknown metadata name(s) dropped" in log.detail
    assert "bad agent" not in log.detail
    assert db.session.get(DecisionLogSession, "sess-store").agent_type == "claude_code"  # detected format
    assert run.counts["ingested"] == 1


def test_sidecar_supplies_agent_and_reason_when_metadata_lacks_them(pg_app, s3):
    s3.put(LOG_KEY, TRANSCRIPT)
    s3.put(SIDECAR_KEY, json.dumps({"reason": "prompt_input_exit", "agent": "openclaude"}).encode())
    other = "decision-logs/2026-10-02T000000Z_sess-meta.jsonl"
    s3.put(other, TRANSCRIPT, metadata={"exit-reason": "logout"})
    s3.put("decision-logs/2026-10-02T000000Z_sess-meta.meta.json",
           json.dumps({"reason": "other", "agent": "codex"}).encode())
    run_sync()
    first = db.session.get(DecisionLogSession, "sess-store")
    assert (first.agent_type, first.exit_reason) == ("openclaude", "prompt_input_exit")
    second = db.session.get(DecisionLogSession, "sess-meta")
    assert (second.agent_type, second.exit_reason) == ("codex", "logout")


def test_store_exports_extend_sessions_and_members_cannot_extend_them(pg_app, s3):
    s3.put(LOG_KEY, TRANSCRIPT)
    run_sync()
    s3.put("decision-logs/2026-10-02T000000Z_sess-store.jsonl", LONGER)
    s3.put("decision-logs/2026-10-03T000000Z_sess-store.jsonl", TRANSCRIPT)  # an earlier export, late
    run = run_sync()
    assert record("decision-logs/2026-10-02T000000Z_sess-store.jsonl").status == "ingested"
    assert record("decision-logs/2026-10-03T000000Z_sess-store.jsonl").status == "unchanged"
    assert run.counts["ingested"] == 1 and run.counts["unchanged"] == 1
    versions = DecisionLogTranscript.query.filter_by(session_id="sess-store").order_by(
        DecisionLogTranscript.received_at).all()
    assert [v.status for v in versions] == ["superseded", "current"]
    assert versions[0].store_object_id == record(LOG_KEY).id

    member = team_service.create_member("Agent", "agent@example.com", "agent")
    extended = LONGER + (rec("user", "done.", "2026-03-16T13:00:00Z", "u9") + "\n").encode()
    response = pg_app.test_client().post("/api/decision-log/upload?session_id=sess-store", data=extended,
                                         headers={"X-API-Key": member.issued_api_key})
    assert response.status_code in (403, 409) and response.get_json()["status"] == "rejected"
    assert DecisionLogTranscript.query.filter_by(session_id="sess-store", status="current").one().entry_count == 3


def test_store_export_conflicting_with_api_entries_is_kept_for_review(pg_app, s3):
    from app.services.decision_log_verify import verify_decision_logs

    member = team_service.create_member("Agent", "agent@example.com", "agent")
    squatted = ("\n".join([GENUINE[0], rec("assistant", "squatted", "2026-03-16T12:06:00Z", "a9")]) + "\n").encode()
    response = pg_app.test_client().post("/api/decision-log/upload?session_id=sess-store", data=squatted,
                                         headers={"X-API-Key": member.issued_api_key})
    assert response.status_code < 300
    s3.put(LOG_KEY, LONGER)
    run = run_sync()
    assert [(c["key"], c["session_id"]) for c in run.details["conflicts"]] == [(LOG_KEY, "sess-store")]
    assert record(LOG_KEY).status == "rejected" and record(LOG_KEY).detail.startswith("conflict: entry 2 differs")
    session = db.session.get(DecisionLogSession, "sess-store")
    assert session.conflict_at is None and session.submitted_by == member.id and session.repository_entries == 0
    assert DecisionLogTranscript.query.filter_by(session_id="sess-store", status="current").one().entry_count == 2
    db.session.commit()
    checked = verify_decision_logs(db.session)
    assert checked["mismatch_count"] == 0, checked["mismatches"]


def test_rejected_store_export_is_kept_for_review(pg_app, s3):
    s3.put(LOG_KEY, TRANSCRIPT)
    run_sync()
    diverging = (rec("user", "something else", "2026-03-16T12:00:00Z", "u1") + "\n").encode() + LONGER
    s3.put("decision-logs/2026-10-04T000000Z_sess-store.jsonl", diverging)
    run = run_sync()
    row = record("decision-logs/2026-10-04T000000Z_sess-store.jsonl")
    assert row.status == "rejected" and row.detail.startswith("conflict: ") and run.status == "partial"
    rejected = DecisionLogTranscript.query.filter_by(session_id="sess-store", status="rejected").one()
    assert rejected.store_object_id == row.id


def test_pentest_file_in_a_repository_and_the_store_is_never_duplicated(pg_app, s3):
    counts = evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, PENTEST, namespace="git-src")
    db.session.commit()
    assert counts.created == 2
    s3.put(PENTEST_KEY, PENTEST)
    run_sync()
    findings = PentestFinding.query.all()
    assert len(findings) == 2 and {f.source_file for f in findings} == {"git-src:layer2/scan-1.json"}
    row = record(PENTEST_KEY)
    assert row.status == "duplicate" and row.import_info["duplicate_of"] == "git-src:layer2/scan-1.json"
    again = evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, PENTEST, namespace="git-src")
    db.session.commit()
    assert (again.created, again.skipped, again.unchanged, again.errors) == (0, 0, 2, [])


# --------------------------------------------------------------------------
# Documents
# --------------------------------------------------------------------------

def test_document_links_are_admin_only_and_audited(pg_app, s3):
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    document = EvidenceDocument.query.one()
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    agent = team_service.create_member("Agent", "agent@example.com", "agent")
    db.session.add(Control(id="c1", name="MFA", category="security"))
    db.session.add(TestRecord(id="t1", control_id="c1", name="MFA enforced"))
    db.session.commit()
    client = pg_app.test_client()
    url = f"/api/evidence-documents/{document.id}/links"
    assert client.post(url, json={"control_id": "c1"}, headers={"X-API-Key": agent.issued_api_key}).status_code == 403
    assert client.post(url, json={"control_id": "c1", "test_id": "t1"},
                       headers={"X-API-Key": admin.issued_api_key}).status_code == 400
    assert client.post(url, json={"control_id": "nope"}, headers={"X-API-Key": admin.issued_api_key}).status_code == 400
    created = client.post(url, json={"control_id": "c1"}, headers={"X-API-Key": admin.issued_api_key})
    assert created.status_code == 201
    link_id = created.get_json()["id"]
    assert client.post(url, json={"control_id": "c1"}, headers={"X-API-Key": admin.issued_api_key}).status_code == 400
    assert client.post(url, json={"test_id": "t1"}, headers={"X-API-Key": admin.issued_api_key}).status_code == 201
    listed = client.get("/api/evidence-documents?control_id=c1", headers={"X-API-Key": agent.issued_api_key}).get_json()
    assert [item["id"] for item in listed["items"]] == [document.id]
    detail = client.get(f"/api/evidence-documents/{document.id}",
                        headers={"X-API-Key": agent.issued_api_key}).get_json()
    assert {link["target"]["type"] for link in detail["links"]} == {"control", "test"}
    assert client.delete(f"{url}/{link_id}", headers={"X-API-Key": admin.issued_api_key}).status_code == 200
    assert client.delete(f"{url}/{link_id}", headers={"X-API-Key": admin.issued_api_key}).status_code == 404
    rows = db.session.execute(text(
        "SELECT action, changed_by FROM audit_log WHERE table_name = 'evidence_document_links' ORDER BY id")).all()
    assert [(r.action, r.changed_by) for r in rows] == [("INSERT", admin.id), ("INSERT", admin.id),
                                                        ("DELETE", admin.id)]
    # Deleting the test removes its link (audited) instead of failing.
    db.session.delete(db.session.get(TestRecord, "t1"))
    db.session.commit()
    assert document.links.count() == 0


def test_document_content_is_served_only_when_its_sha256_matches(pg_app, s3):
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    document = EvidenceDocument.query.one()
    agent = team_service.create_member("Agent", "agent@example.com", "agent")
    client = pg_app.test_client()
    response = client.get(f"/api/evidence-documents/{document.id}/content", headers={"X-API-Key": agent.issued_api_key})
    assert response.status_code == 200 and response.data == REVIEW
    assert response.headers["Content-Disposition"] == 'attachment; filename="review-1.md"'
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.mimetype == "text/markdown"
    tamper("UPDATE evidence_documents SET sha256 = :s", {"s": "0" * 64}, table="evidence_documents")
    tampered = client.get(f"/api/evidence-documents/{document.id}/content", headers={"X-API-Key": agent.issued_api_key})
    assert tampered.status_code == 502 and REVIEW not in tampered.data


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------

def _verify(s3, **kwargs):
    db.session.commit()
    return store_verify.verify_store(db.session, s3, BUCKET, **kwargs)


def test_verify_valid_after_sync_and_unrecorded_before(pg_app, s3):
    populate(s3)
    before = _verify(s3)
    assert before["status"] == "unverified" and before["unrecorded_count"] == 5
    run_sync()
    result = _verify(s3, full=True)
    assert result["status"] == "valid", result
    assert result["records"]["checked"] == 5 and result["listing"]["listed"] == 5
    assert result["bucket_check"]["default_retention"] == {
        "mode": "GOVERNANCE", "days": None, "years": 7, "period_days": 7 * 365}
    s3.put("codex-reviews/new.md", b"new")
    later = _verify(s3)
    assert later["status"] == "unverified" and later["listing"]["unrecorded"][0]["key"] == "codex-reviews/new.md"


def test_verify_failure_modes(pg_app, s3, monkeypatch):
    populate(s3)
    run_sync()
    log, review, pentest = record(LOG_KEY), record(REVIEW_KEY), record(PENTEST_KEY)
    # tampered record
    tamper("UPDATE evidence_store_objects SET sha256 = :s WHERE id = :i", {"s": "1" * 64, "i": log.id})
    # retention removed / shortened
    s3.head_overrides[(review.key, review.version_id)] = {"ObjectLockMode": None}
    s3.head_overrides[(pentest.key, pentest.version_id)] = {
        "ObjectLockRetainUntilDate": pentest.retain_until - timedelta(days=1)}
    # missing version
    sidecar = record(SIDECAR_KEY)
    s3.client.delete_object(Bucket=BUCKET, Key=SIDECAR_KEY, VersionId=sidecar.version_id,
                            BypassGovernanceRetention=True)
    # delete marker and a second version
    s3.client.delete_object(Bucket=BUCKET, Key=UNMAPPED_KEY)
    s3.put(REVIEW_KEY, b"# Replaced\n")
    result = _verify(s3)
    assert result["status"] == "broken"
    issues = {(f["key"], f["issue"]) for f in result["records"]["failures"] + result["listing"]["failures"]}
    assert (LOG_KEY, "the stored SHA-256 checksum differs from the record") in issues
    assert (REVIEW_KEY, "the version is not under Object Lock retention") in issues
    assert (PENTEST_KEY, "its retain-until date is earlier than the recorded one") in issues
    assert (SIDECAR_KEY, store_verify.MISSING) in issues
    assert (UNMAPPED_KEY, store_verify.DELETE_MARKER) in issues
    assert (REVIEW_KEY, store_verify.SECOND_VERSION) in issues


def test_verify_full_rereads_bodies_and_non_conforming_records_fail(pg_app, s3, monkeypatch):
    s3.put(REVIEW_KEY, REVIEW)
    s3.put("codex-reviews/plain.md", REVIEW, checksum=None)
    run_sync()
    quick = _verify(s3)
    assert quick["status"] == "broken"
    assert [f["key"] for f in quick["records"]["failures"]] == ["codex-reviews/plain.md"]
    monkeypatch.setattr(store, "hash_version", lambda *args, **kwargs: ("2" * 64, len(REVIEW)))
    full = _verify(s3, full=True)
    assert any(f["key"] == REVIEW_KEY and f["issue"] == "the body's SHA-256 differs from the record"
               for f in full["records"]["failures"])


def test_verify_bucket_configuration(pg_app, s3):
    plain = "evidence-plain-test"
    s3.client.create_bucket(Bucket=plain)
    check = store_verify.check_bucket(s3, plain)
    assert "versioning is not enabled" in check["issues"] and "Object Lock is not enabled" in check["issues"]
    unlocked = "evidence-unlocked-test"
    make_bucket(s3, unlocked, retention=False)
    assert store_verify.check_bucket(s3, unlocked)["issues"] == ["Object Lock has no default retention"]


def test_bounded_verify_slices_cover_everything(pg_app, s3):
    populate(s3)
    run_sync()
    cursor, slices, checked, listed = None, 0, 0, 0
    while True:
        result = _verify(s3, cursor=cursor, max_items=2)
        slices += 1
        checked += (result["records"] or {}).get("checked", 0)
        listed += (result["listing"] or {}).get("listed", 0)
        assert result["status"] == "valid"
        cursor = result["next_cursor"]
        if cursor is None:
            break
        assert slices < 20
    assert (checked, listed) == (5, 5) and slices > 2
    with pytest.raises(ValueError):
        store_verify.decode_cursor("not-a-cursor")


def test_verify_api_is_admin_only_and_bounded(pg_app, s3):
    populate(s3)
    run_sync()
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    agent = team_service.create_member("Agent", "agent@example.com", "agent")
    client = pg_app.test_client()
    assert client.get("/api/evidence-store/verify", headers={"X-API-Key": agent.issued_api_key}).status_code == 403
    body = client.get("/api/evidence-store/verify?max_items=3", headers={"X-API-Key": admin.issued_api_key}).get_json()
    assert body["status"] == "valid" and body["records"]["checked"] == 3 and body["next_cursor"]
    assert client.get("/api/evidence-store/verify?cursor=bogus",
                      headers={"X-API-Key": admin.issued_api_key}).status_code == 400


def test_erased_versions_are_listed_separately(pg_app, s3, migrated_pg_url, monkeypatch):
    populate(s3)
    run_sync()
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    agent = team_service.create_member("Agent", "agent@example.com", "agent")
    review = record(REVIEW_KEY)
    s3.client.delete_object(Bucket=BUCKET, Key=REVIEW_KEY, VersionId=review.version_id,
                            BypassGovernanceRetention=True)
    assert _verify(s3)["status"] == "broken"
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "record-erasure", "--key", REVIEW_KEY,
                     "--version-id", review.version_id, "--reason", "  ", "--admin", admin.email)
    assert code == 2 and "reason is required" in out
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "record-erasure", "--key", REVIEW_KEY,
                     "--version-id", review.version_id, "--reason", "leaked secret purge", "--admin", agent.email)
    assert code == 2 and "not an active compliance admin" in out
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "record-erasure", "--key", REVIEW_KEY,
                     "--version-id", review.version_id, "--reason", "leaked secret purge", "--admin", admin.email)
    assert code == 0, out
    row = db.session.get(EvidenceStoreObject, review.id)
    assert (row.status, row.erased_by, row.erasure_reason) == ("erased", admin.id, "leaked secret purge")
    audit = db.session.execute(text("SELECT changed_by, new_values->>'status' AS status FROM audit_log "
                                    "WHERE table_name = 'evidence_store_objects' AND action = 'UPDATE'")).one()
    assert (audit.changed_by, audit.status) == (admin.id, "erased")
    result = _verify(s3)
    assert result["status"] == "valid" and result["records"]["erased_count"] == 1
    document = EvidenceDocument.query.one()
    gone = pg_app.test_client().get(f"/api/evidence-documents/{document.id}/content",
                                    headers={"X-API-Key": agent.issued_api_key})
    assert gone.status_code == 410
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "record-erasure", "--key", REVIEW_KEY,
                     "--version-id", review.version_id, "--reason", "again", "--admin", admin.email)
    assert code == 2 and "already" in out


def test_decision_logs_against_the_store(pg_app, s3, migrated_pg_url, monkeypatch):
    populate(s3)
    run_sync()
    checked = store_verify.verify_decision_logs_against_store(db.session, s3)
    assert (checked["status"], checked["versions_checked"], checked["objects_checked"]) == ("valid", 1, 1)
    code, out = _cli(migrated_pg_url, monkeypatch, "audit-verify", "--decision-logs", "--against-repo",
                     "--against-store", "--evidence-store")
    assert code == 0, out
    assert "against_repo: status=valid versions=0" in out
    assert "against_store: status=valid versions=1 objects=1 mismatches=0 missing=0" in out
    assert "evidence_store: status=valid" in out
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    api = pg_app.test_client().get("/api/decision-log/verify?against_repo=true&against_store=true",
                                   headers={"X-API-Key": admin.issued_api_key}).get_json()
    assert api["status"] == "valid" and api["decision_logs"]["against_store"]["versions_checked"] == 1
    assert api["decision_logs"]["against_repo"]["repository_configured"] is False
    tamper("UPDATE evidence_store_objects SET sha256 = :s WHERE kind = 'decision_log'", {"s": "f" * 64})
    broken_api = pg_app.test_client().get("/api/decision-log/verify?against_store=true",
                                          headers={"X-API-Key": admin.issued_api_key}).get_json()
    assert broken_api["status"] == "broken"
    broken = store_verify.verify_decision_logs_against_store(db.session, s3)
    assert broken["status"] == "broken" and broken["mismatches_count"] == 1
    code, out = _cli(migrated_pg_url, monkeypatch, "audit-verify", "--decision-logs", "--against-store")
    assert code == 1 and "against the evidence store" in out


def test_against_repo_ignores_store_versions(pg_app, s3):
    from app.services.decision_log_repo_verify import NoEvidenceSourceError, evidence_source, verify_against_repo

    s3.put(LOG_KEY, TRANSCRIPT)
    run_sync()
    with pytest.raises(NoEvidenceSourceError):
        evidence_source()
    with pytest.raises(LookupError):
        evidence_source("named")
    result = verify_against_repo(db.session, None)
    assert (result["status"], result["versions_checked"], result["not_in_repository_count"],
            result["in_store_count"]) == ("valid", 0, 0, 1)


def test_cli_usage_and_not_configured(pg_app, s3, migrated_pg_url, monkeypatch):
    code, out = _cli(migrated_pg_url, monkeypatch, "audit-verify", "--against-store")
    assert code == 2 and "need --decision-logs" in out
    code, out = _cli(migrated_pg_url, monkeypatch, "audit-verify", "--full")
    assert code == 2 and "--full needs --evidence-store" in out
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "status")
    assert code == 0 and f"bucket: {BUCKET}" in out
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "sync")
    assert code == 0 and "Queued sync run" in out
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "sync", "--wait")
    assert code == 1 and "already queued" in out
    db.session.execute(text("UPDATE evidence_store_sync_runs SET status = 'failure'"))
    db.session.commit()
    populate(s3)
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "sync", "--wait")
    assert code == 0 and json.loads(out)["status"] == "success"
    monkeypatch.delenv("EVIDENCE_STORE_BUCKET")
    for argv in (("evidence-store", "sync"), ("audit-verify", "--evidence-store"),
                 ("audit-verify", "--decision-logs", "--against-store")):
        code, out = _cli(migrated_pg_url, monkeypatch, *argv)
        assert code == 2 and "not configured" in out, argv
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "status", "--json")
    assert code == 0 and json.loads(out)["configured"] is False


# --------------------------------------------------------------------------
# Failure paths
# --------------------------------------------------------------------------

def _client_error(operation, code="AccessDenied"):
    from botocore.exceptions import ClientError

    return ClientError({"Error": {"Code": code, "Message": "refused"}}, operation)


def test_refused_content_is_recorded_and_unreadable_versions_are_retried(pg_app, s3, monkeypatch):
    from app.services import transcript_ingest

    monkeypatch.setattr(transcript_ingest, "MAX_TRANSCRIPT_ENTRIES", 2)
    bad_id = "decision-logs/2026-10-01T000000Z_sess-bad.jsonl"
    many = "decision-logs/2026-10-01T000000Z_sess-many.jsonl"
    s3.put(PENTEST_KEY, b"not json")
    s3.put(bad_id, (rec("user", "x", "2026-03-16T12:00:00Z", "m" * 200) + "\n").encode())
    s3.put(many, LONGER)
    s3.put("decision-logs/2026-10-01T000000Z_sess-many.meta.json", b"{not json")
    s3.put(REVIEW_KEY, REVIEW)
    original = s3.head_object

    def refuse_review(**kwargs):
        if kwargs["Key"] == REVIEW_KEY:
            raise _client_error("HeadObject")
        return original(**kwargs)

    monkeypatch.setattr(s3, "head_object", refuse_review)
    run = run_sync()
    assert record(PENTEST_KEY).status == "rejected" and "invalid JSON" in record(PENTEST_KEY).detail
    assert record(bad_id).status == "rejected" and "longer than" in record(bad_id).detail
    assert record(many).status == "too_large" and "decision-log limit" in record(many).detail
    assert db.session.get(DecisionLogSession, "sess-many") is None
    assert (record(REVIEW_KEY).status, record(REVIEW_KEY).attempts) == ("error", 1)
    assert run.status == "partial" and run.counts["errors"] == 1
    assert run.details["errors"][0]["key"] == REVIEW_KEY and "AccessDenied" in run.details["errors"][0]["error"]
    monkeypatch.setattr(s3, "head_object", original)
    again = run_sync()
    assert again.counts["new"] == 1 and record(REVIEW_KEY).status == "ingested"


def test_write_failures_are_retried_after_a_deadlock_and_reported(pg_app, s3, monkeypatch):
    class Deadlock(Exception):
        pgcode = "40P01"

    s3.put(REVIEW_KEY, REVIEW)
    calls, real = [], sync.write_version

    def flaky(bucket, fetched, tally):
        calls.append(fetched.key)
        if len(calls) == 1:
            raise Deadlock("deadlock detected")
        return real(bucket, fetched, tally)

    monkeypatch.setattr(sync, "write_version", flaky)
    run = run_sync()
    assert calls == [REVIEW_KEY, REVIEW_KEY] and run.counts["errors"] == 0 and record(REVIEW_KEY).status == "ingested"

    def broken(bucket, fetched, tally):
        raise RuntimeError("database gone")

    s3.put("codex-reviews/b.md", b"b")
    monkeypatch.setattr(sync, "write_version", broken)
    failed = run_sync()
    assert failed.counts["errors"] == 1 and failed.details["errors"][0]["error"] == "RuntimeError"
    assert record("codex-reviews/b.md").status == "error" and "RuntimeError" in record("codex-reviews/b.md").detail


def test_listing_failure_fails_the_run(pg_app, s3, monkeypatch):
    def refuse(**kwargs):
        raise _client_error("ListObjectVersions")

    monkeypatch.setattr(s3, "list_object_versions", refuse)
    run = run_sync()
    assert run.status == "failure" and "AccessDenied" in run.error_message


def test_fetch_checks_the_body_against_the_checksum(s3, monkeypatch):
    import hashlib

    from botocore.exceptions import FlexibleChecksumError

    version = store.ListedVersion(REVIEW_KEY, s3.put(REVIEW_KEY, REVIEW), len(REVIEW), None)

    def raising(exc):
        def hash_version(*args, **kwargs):
            raise exc
        return hash_version

    monkeypatch.setattr(store, "hash_version", raising(FlexibleChecksumError(error_msg="mismatch")))
    assert sync.fetch_version(s3, BUCKET, version).status == "non_conforming"
    monkeypatch.setattr(store, "hash_version", raising(store.BodyTooLarge(11, 10)))
    assert sync.fetch_version(s3, BUCKET, version).status == "too_large"
    monkeypatch.setattr(store, "hash_version", lambda *args: (hashlib.sha256(REVIEW).hexdigest(), len(REVIEW) + 1))
    longer = sync.fetch_version(s3, BUCKET, version)
    assert longer.status == "non_conforming" and "bytes, not the stored" in longer.notes[-1]
    assert store.first_version(s3, BUCKET, "codex-reviews/none.md") is None
    first = s3.put("codex-reviews/big.md", b"x" * 20)
    s3.put("codex-reviews/big.md", b"y")
    s3.put("codex-reviews/big.md.later", b"z")
    assert store.first_version(s3, BUCKET, "codex-reviews/big.md").version_id == first


def test_verify_reports_unreadable_versions_and_buckets(pg_app, s3, monkeypatch):
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    original = s3.head_object

    def refuse(**kwargs):
        raise _client_error("HeadObject")

    monkeypatch.setattr(s3, "head_object", refuse)
    assert "cannot be read" in _verify(s3)["records"]["failures"][0]["issue"]
    monkeypatch.setattr(s3, "head_object", original)

    def refuse_body(*args, **kwargs):
        raise _client_error("GetObject")

    monkeypatch.setattr(store, "hash_version", refuse_body)
    assert "body cannot be read" in _verify(s3, full=True)["records"]["failures"][0]["issue"]
    monkeypatch.setattr(store, "bucket_settings", refuse_body)
    assert "cannot be read" in store_verify.check_bucket(s3, BUCKET)["issues"][0]


def test_against_store_reports_missing_objects_and_skips_erased_ones(pg_app, s3):
    s3.put(LOG_KEY, TRANSCRIPT)
    run_sync()
    log = record(LOG_KEY)
    s3.client.delete_object(Bucket=BUCKET, Key=LOG_KEY, VersionId=log.version_id, BypassGovernanceRetention=True)
    missing = store_verify.verify_decision_logs_against_store(db.session, s3, max_sessions=10)
    assert missing["status"] == "broken" and missing["missing_count"] == 1
    assert missing["missing"][0]["issue"] == store_verify.MISSING
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    service.record_erasure(db.session.get(EvidenceStoreObject, log.id), "data-subject erasure request", admin.id)
    db.session.commit()
    erased = store_verify.verify_decision_logs_against_store(db.session, s3)
    assert erased["status"] == "valid" and erased["erased_count"] == 1
    with pytest.raises(service.EvidenceStoreError):
        service.record_erasure(db.session.get(EvidenceStoreObject, log.id), "x" * 3000, admin.id)


# --------------------------------------------------------------------------
# Scheduler
# --------------------------------------------------------------------------

def test_one_active_run_single_runner_and_reaper(pg_app, s3):
    from app.services.evidence_store import _periodic_sync

    run, created = scheduler.enqueue_evidence_store_sync(BUCKET, "manual")
    again, created_again = scheduler.enqueue_evidence_store_sync(BUCKET, "api")
    assert created and not created_again and again.id == run.id
    _periodic_sync(pg_app)  # coalesces into the active run
    assert EvidenceStoreSyncRun.query.count() == 1
    held = scheduler.TargetLock(db.engine, scheduler.KINDS["evidence_store_sync"].lock_class, BUCKET)
    assert held.acquire()
    try:
        assert scheduler.execute_claimed("evidence_store_sync", run.id) == "busy"
    finally:
        held.release()
    assert scheduler.KINDS["evidence_store_sync"].lock_class not in {
        kind.lock_class for name, kind in scheduler.KINDS.items() if name != "evidence_store_sync"}
    db.session.execute(text(
        "UPDATE evidence_store_sync_runs SET status = 'running', started_at = :t, heartbeat_at = :t"),
                       {"t": datetime.now(timezone.utc) - timedelta(hours=1)})
    db.session.commit()
    assert scheduler.reap_once() == 1
    db.session.expire_all()
    assert db.session.get(EvidenceStoreSyncRun, run.id).status == "failure"
    _periodic_sync(pg_app)
    queued = EvidenceStoreSyncRun.query.filter_by(status="queued").one()
    assert queued.trigger_type == "scheduled"
    assert scheduler.dispatch_once() >= 1
    db.session.expire_all()
    assert db.session.get(EvidenceStoreSyncRun, queued.id).status in ("unchanged", "success")


def test_sync_api_queues_and_polls(pg_app, s3):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    client = pg_app.test_client()
    headers = {"X-API-Key": admin.issued_api_key}
    queued = client.post("/api/evidence-store/sync", headers=headers)
    assert queued.status_code == 202
    body = queued.get_json()
    assert body["poll_url"] == f"/api/evidence-store/runs/{body['id']}" and body["status"] == "queued"
    assert client.post("/api/evidence-store/sync", headers=headers).status_code == 409
    assert client.get(body["poll_url"], headers=headers).get_json()["status"] == "queued"
    assert client.get("/api/evidence-store", headers=headers).get_json()["bucket"] == BUCKET


# --------------------------------------------------------------------------
# Migration 021
# --------------------------------------------------------------------------

def test_migration_021_upgrades_locks_and_grants(pg_url):
    from alembic import command

    import ast
    from pathlib import Path

    from cli import db_cmd

    tree = ast.parse((Path(db_cmd.ROOT) / "migrations" / "env.py").read_text())
    assigned = {node.targets[0].id: node.value for node in tree.body
                if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}
    WRITER_ORDER = ast.literal_eval(assigned["WRITER_ORDER"])
    locks = assigned["REVISION_LOCKS"]
    REVISION_LOCKS = {ast.literal_eval(k): v for k, v in zip(locks.keys, locks.values)}
    assert ast.literal_eval(REVISION_LOCKS["021"]) == (
        ("controls", "test_records", "pentest_findings", "team_members", "decision_log_transcripts"), False)
    for table in ("evidence_store_objects", "evidence_documents", "evidence_document_links",
                  "evidence_store_sync_runs", "evidence_store_retention_floors"):
        assert WRITER_ORDER.index(table) < WRITER_ORDER.index("audit_log")
    from tests.test_migrations_pg import _alembic_config

    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "020")
    command.upgrade(cfg, "head")
    role = f"tpa_{uuid.uuid4().hex[:8]}"
    app_url = make_url(pg_url).set(username=role, password="app-" + uuid.uuid4().hex).render_as_string(
        hide_password=False)
    assert db_cmd.provision_app_role(pg_url, app_url) is True
    engine = create_engine(pg_url)
    try:
        with engine.connect() as conn:
            def allowed(table, privilege):
                return conn.execute(text("SELECT has_table_privilege(:r, :t, :p)"),
                                    {"r": role, "t": f"public.{table}", "p": privilege}).scalar()

            for table in ("evidence_store_objects", "evidence_documents", "evidence_store_sync_runs",
                          "evidence_store_retention_floors"):
                assert allowed(table, "SELECT, INSERT, UPDATE") and not allowed(table, "DELETE")
            assert allowed("evidence_document_links", "DELETE")
            triggers = set(conn.execute(text(
                "SELECT tgname FROM pg_trigger WHERE tgname LIKE 'audit_%evidence%'")).scalars())
            assert {"audit_evidence_store_objects", "audit_evidence_documents", "audit_evidence_document_links",
                    "audit_evidence_store_sync_runs", "audit_evidence_store_retention_floors"} <= triggers
            deferrable = conn.execute(text(
                "SELECT condeferrable FROM pg_constraint WHERE conname = 'fk_decision_log_transcripts_store_object'"
            )).scalar()
            assert deferrable is True
    finally:
        engine.dispose()
    assert db_cmd.serving_role_problems(app_url) == []


def test_version_guard_covers_store_imports(pg_app):
    db.session.add(DecisionLogSession(id="sess-g", agent_type="claude_code"))
    db.session.add(EvidenceStoreObject(id="obj-1", bucket=BUCKET, key="decision-logs/x_sess-g.jsonl",
                                       version_id="v1", kind="decision_log", status="ingested", size=1))
    db.session.commit()

    def insert(path):
        db.session.execute(text(
            "INSERT INTO decision_log_transcripts (id, session_id, status, entry_count, source_path, store_object_id, "
            "received_at) VALUES (:id, 'sess-g', 'current', 0, :p, 'obj-1', now())"),
            {"id": str(uuid.uuid4()), "p": path})
        db.session.commit()

    with pytest.raises(Exception, match="is not session"):
        insert("decision-logs/x_other.jsonl")
    db.session.rollback()
    insert("decision-logs/x_sess-g.jsonl")
    with pytest.raises(Exception, match="versions are history"):
        db.session.execute(text("UPDATE decision_log_transcripts SET store_object_id = NULL"))
        db.session.commit()
    db.session.rollback()
