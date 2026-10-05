"""Evidence store: SHA-256 COMPOSITE checksums (multipart uploads with SHA-256
part checksums) conform; the record holds the body's full-object SHA-256 and
the composite checksum S3 reports, verification holds HeadObject's composite
checksum, size and ETag to the record on every run and ``--full`` recomputes
the body's SHA-256. Objects without a SHA-256 checksum stay non-conforming.
Bulk-copy metadata is kept on every kind of object."""

import hashlib
import json

import pytest
from sqlalchemy import text

from app.models import DecisionLogSession, DecisionLogTranscript, PentestFinding, db
from app.models.evidence_store import EvidenceDocument
from app.services import team_service
from app.services.evidence_store import service, store
from app.services.evidence_store import verify as store_verify
from tests.store_fakes import b64_sha256, composite_sha256
from tests.test_evidence_store_hardening_pg import _failures, _verify
from tests.test_evidence_store_pg import (LOG_KEY, PENTEST, PENTEST_KEY, REVIEW, REVIEW_KEY,  # noqa: F401
                                          SIDECAR_KEY, TRANSCRIPT, record, run_sync, s3, tamper)

DIFFERS = store_verify.CHECKSUM_DIFFERS
BULK = {"producer": "backfill", "source-repo": "evidence-repo", "source-commit": "c" * 40}


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _upload_multipart(s3):
    """Every kind uploaded as a multipart upload with SHA-256 part checksums."""
    return {key: s3.put(key, body, checksum="composite")
            for key, body in ((LOG_KEY, TRANSCRIPT), (PENTEST_KEY, PENTEST), (REVIEW_KEY, REVIEW))}


def test_composite_checksums_conform_and_record_the_full_object_sha256(pg_app, s3):
    _upload_multipart(s3)
    run = run_sync()
    assert run.status == "success", run.details
    assert (run.counts["ingested"], run.counts["non_conforming"]) == (3, 0)
    for key, body in ((LOG_KEY, TRANSCRIPT), (PENTEST_KEY, PENTEST), (REVIEW_KEY, REVIEW)):
        row = record(key)
        assert row.status == "ingested", row.detail
        assert row.sha256 == _sha(body)  # the full-object SHA-256, computed from the body
        assert row.composite_checksum == composite_sha256(body) and row.composite_checksum.endswith("-2")
        assert row.etag and row.size == len(body)
        assert row.composite_checksum != b64_sha256(body)
    version = DecisionLogTranscript.query.filter_by(session_id="sess-store", status="current").one()
    assert version.content_sha256 == _sha(TRANSCRIPT) and version.store_object_id == record(LOG_KEY).id
    assert PentestFinding.query.count() == 2
    assert EvidenceDocument.query.one().sha256 == _sha(REVIEW)

    quick = _verify(s3)
    assert quick["status"] == "valid", quick
    full = _verify(s3, full=True)
    assert full["status"] == "valid", full
    against = store_verify.verify_decision_logs_against_store(db.session, s3)
    assert (against["status"], against["versions_checked"]) == ("valid", 1)

    client = pg_app.test_client()
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    listed = client.get("/api/evidence-store/objects", headers={"X-API-Key": admin.issued_api_key}).get_json()
    composite = {item["key"]: item["composite_checksum"] for item in listed["items"]}
    assert composite[LOG_KEY] == composite_sha256(TRANSCRIPT)


def test_a_full_object_upload_records_no_composite_checksum(pg_app, s3):
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    row = record(REVIEW_KEY)
    assert (row.status, row.sha256, row.composite_checksum) == ("ingested", _sha(REVIEW), None)
    # A full-object record whose version now reports a composite checksum fails.
    s3.head_overrides[(REVIEW_KEY, row.version_id)] = {"ChecksumSHA256": composite_sha256(REVIEW),
                                                       "ChecksumType": "COMPOSITE"}
    assert (REVIEW_KEY, DIFFERS) in _failures(_verify(s3))


@pytest.mark.parametrize("override,issue", [
    ({"ChecksumSHA256": composite_sha256(REVIEW, parts=3), "ChecksumType": "COMPOSITE"}, DIFFERS),
    ({"ChecksumSHA256": b64_sha256(REVIEW), "ChecksumType": "FULL_OBJECT"}, DIFFERS),
    ({"ChecksumSHA256": None}, "the object has no SHA-256 checksum"),
    ({"ChecksumSHA256": composite_sha256(REVIEW) + "-2"}, "the object's SHA-256 checksum is malformed"),
    ({"ContentLength": len(REVIEW) + 1}, f"the stored size ({len(REVIEW) + 1}) differs from the record "
                                         f"({len(REVIEW)})"),
    ({"ETag": '"0123456789abcdef0123456789abcdef-2"'}, "the stored ETag differs from the record"),
])
def test_a_tampered_composite_version_is_broken_on_every_run(pg_app, s3, override, issue):
    version = s3.put(REVIEW_KEY, REVIEW, checksum="composite")
    run_sync()
    assert _verify(s3)["status"] == "valid"
    s3.head_overrides[(REVIEW_KEY, version)] = override
    result = _verify(s3)
    assert result["status"] == "broken"
    assert (REVIEW_KEY, issue) in _failures(result)


def test_a_tampered_composite_record_is_broken_and_full_rehashes_the_body(pg_app, s3, monkeypatch):
    _upload_multipart(s3)
    run_sync()
    log, review = record(LOG_KEY), record(REVIEW_KEY)
    tamper("UPDATE evidence_store_objects SET composite_checksum = :c WHERE id = :i",
           {"c": composite_sha256(b"other"), "i": log.id})
    result = _verify(s3)
    assert result["status"] == "broken" and (LOG_KEY, DIFFERS) in _failures(result)
    tamper("UPDATE evidence_store_objects SET composite_checksum = :c WHERE id = :i",
           {"c": composite_sha256(TRANSCRIPT), "i": log.id})
    assert _verify(s3)["status"] == "valid"

    # The record's full-object SHA-256 rewritten consistently with the document: only --full re-reads the body.
    tamper("UPDATE evidence_store_objects SET sha256 = :s WHERE id = :i", {"s": "1" * 64, "i": review.id})
    tamper("UPDATE evidence_documents SET sha256 = :s WHERE store_object_id = :i", {"s": "1" * 64, "i": review.id},
           table="evidence_documents")
    assert (REVIEW_KEY, "the body's SHA-256 differs from the record") not in _failures(_verify(s3))
    full = _verify(s3, full=True)
    assert full["status"] == "broken"
    assert (REVIEW_KEY, "the body's SHA-256 differs from the record") in _failures(full)


def test_the_guard_freezes_the_composite_checksum(pg_app, s3):
    _upload_multipart(s3)
    run_sync()
    with pytest.raises(Exception, match="refused"):
        db.session.execute(text("UPDATE evidence_store_objects SET composite_checksum = NULL WHERE key = :k"),
                           {"k": REVIEW_KEY})
        db.session.commit()
    db.session.rollback()
    assert record(REVIEW_KEY).composite_checksum == composite_sha256(REVIEW)


def test_a_composite_version_whose_body_has_another_size_is_non_conforming(pg_app, s3):
    version = s3.put(LOG_KEY, TRANSCRIPT, checksum="composite")
    s3.head_overrides[(LOG_KEY, version)] = {"ContentLength": len(TRANSCRIPT) + 5}
    run = run_sync()
    assert run.counts["non_conforming"] == 1
    row = record(LOG_KEY)
    assert row.status == "non_conforming"
    assert f"the body is {len(TRANSCRIPT)} bytes, not the stored {len(TRANSCRIPT) + 5}" in row.detail
    assert row.sha256 == _sha(TRANSCRIPT) and row.composite_checksum == composite_sha256(TRANSCRIPT)
    assert db.session.get(DecisionLogSession, "sess-store") is None


@pytest.mark.parametrize("checksum,head,problem", [
    (None, {}, "no SHA-256 checksum"),
    (None, {"ChecksumCRC32": "AAAAAA==", "ChecksumType": "FULL_OBJECT"}, "no SHA-256 checksum"),
    (b64_sha256(REVIEW) + "-0", {}, "malformed"),
    (b64_sha256(REVIEW) + "-2", {"ChecksumType": "FULL_OBJECT"}, "malformed"),
    ("bm90IGEgZGlnZXN0-2", {}, "malformed"),
])
def test_objects_without_a_sha256_checksum_stay_non_conforming(pg_app, s3, checksum, head, problem):
    version = s3.put(REVIEW_KEY, REVIEW, checksum=checksum)
    if head:
        s3.head_overrides[(REVIEW_KEY, version)] = head
    run = run_sync()
    assert run.status == "partial" and run.counts["non_conforming"] == 1
    row = record(REVIEW_KEY)
    assert row.status == "non_conforming" and problem in row.detail
    assert row.sha256 == _sha(REVIEW) and row.composite_checksum is None  # hashed from the body, never imported
    assert EvidenceDocument.query.count() == 0
    result = _verify(s3)
    assert result["status"] == "broken"
    assert any(key == REVIEW_KEY and "non_conforming" in issue for key, issue in _failures(result))


def test_an_acknowledged_non_conforming_version_that_now_has_a_composite_checksum_fails(pg_app, s3):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    version = s3.put(REVIEW_KEY, REVIEW, checksum=None)
    run_sync()
    service.acknowledge(record(REVIEW_KEY), "uploaded before the checksum rule", admin.id)
    db.session.commit()
    assert _verify(s3)["status"] == "valid"
    s3.checksums[(REVIEW_KEY, version)] = composite_sha256(REVIEW)
    result = _verify(s3)
    assert result["status"] == "broken"
    assert (REVIEW_KEY, "recorded as non-conforming, but the version has a composite SHA-256 checksum its body "
                        "matches") in _failures(result)


def test_bulk_copy_metadata_is_kept_on_transcripts_and_sidecars(pg_app, s3):
    s3.put(LOG_KEY, TRANSCRIPT, checksum="composite", metadata=dict(BULK, redaction="rules-1"))
    s3.put(SIDECAR_KEY, json.dumps({"reason": "clear"}).encode(), metadata=dict(BULK, redaction="rules-1"))
    s3.put(PENTEST_KEY, PENTEST, metadata=dict(BULK, **{"source-blob": "b" * 40}))
    run = run_sync()
    assert run.status == "success", run.details
    for key in (LOG_KEY, SIDECAR_KEY):
        row = record(key)
        assert row.object_metadata == dict(BULK, redaction="rules-1")
        assert not row.detail or "metadata" not in row.detail  # nothing dropped, no unknown name
    assert record(PENTEST_KEY).object_metadata == dict(BULK, **{"source-blob": "b" * 40})
    s3.put("codex-reviews/bad-repo.md", REVIEW, metadata=dict(BULK, **{"source-repo": "repo/with/slashes"}))
    run_sync()
    bad = record("codex-reviews/bad-repo.md")
    assert bad.object_metadata == {"producer": "backfill", "source-commit": "c" * 40}
    assert "metadata source-repo: invalid value dropped" in bad.detail
    assert _verify(s3)["status"] == "valid"
    assert len(composite_sha256(REVIEW, parts=10000)) <= store.MAX_COMPOSITE_CHECKSUM
