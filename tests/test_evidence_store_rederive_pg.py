"""Evidence store: the store is the ground truth for every import outcome.

Every outcome that is not a straightforward ingested-and-linked version is
re-derived from the store body on every verification run (no ``--full``
needed): a restored session's exports, refusals inserted by the database
role, a replayed repository conflict naming a store object, store-namespace
pentest findings deleted or edited, a counterpart edited under a duplicate,
the append-only retention floor, the bucket policy's partition and erasure
principals, and bulk acknowledgement of unparseable lines."""

import json
import types
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from app.models import DecisionLogEntry, DecisionLogSession, DecisionLogTranscript, PentestFinding, db
from app.models.evidence_store import EvidenceStoreObject, EvidenceStoreRetentionFloor
from app.services import evidence_import, scheduler, team_service
from app.services import evidence_import_decision_logs as dl
from app.services.decision_log_verify import verify_decision_logs
from app.services.evidence_store import service
from app.services.evidence_store import verify as store_verify
from tests.store_fakes import BUCKET, WRITER_ROLE, ChecksummingS3, bucket_policy, make_bucket
from tests.test_evidence_store_hardening_pg import (OTHER_PENTEST, _failures, _insert_record, _refused, _upload,
                                                    _verify)
from tests.test_evidence_store_pg import (LOG_KEY, LONGER, PENTEST, PENTEST_KEY, REVIEW, REVIEW_KEY,  # noqa: F401
                                          TRANSCRIPT, _cli, record, run_sync, s3, tamper)
from tests.test_round2_git import rec

STORE_HOLDER = "evidence-store:layer2/scan-1.json"
ERASER = "arn:aws:iam::111122223333:role/evidence-erasure"


def _entries(session_id):
    return DecisionLogEntry.query.filter_by(session_id=session_id).count()


def _restored(session_id):
    """Make a stored session look restored from an earlier portal: no versions, no repository count."""
    tamper("DELETE FROM decision_log_transcripts WHERE session_id = :s", {"s": session_id},
           table="decision_log_transcripts")
    db.session.execute(text("UPDATE decision_log_sessions SET repository_entries = NULL WHERE id = :s"),
                       {"s": session_id})
    db.session.commit()


def _store_findings():
    return PentestFinding.query.filter(PentestFinding.source_file == STORE_HOLDER)


# --------------------------------------------------------------------------
# F1: a restored session's exports
# --------------------------------------------------------------------------

def test_prefix_and_metadata_only_exports_of_a_restored_session_verify(pg_app, s3):
    dl.import_decision_log(LONGER, session_id="sess-old", authority=dl.AUTHORITY_SYSTEM)
    db.session.commit()
    _restored("sess-old")
    prefix = "decision-logs/2026-01-01T000000Z_sess-old.jsonl"
    empty = "decision-logs/2026-01-02T000000Z_sess-old.jsonl"
    s3.put(prefix, TRANSCRIPT)
    s3.put(empty, b'{"type": "summary", "summary": "nothing"}\n')
    run_sync()
    assert record(prefix).status == "unchanged"
    assert record(prefix).import_info["decision_log"]["matched_version"] is None
    assert record(empty).status == "unchanged" and record(empty).import_info["decision_log"]["entries"] == 0
    result = _verify(s3)
    assert result["status"] == "valid", _failures(result)
    run_sync()
    assert _verify(s3)["status"] == "valid"


def test_an_identical_export_baselines_a_restored_session(pg_app, s3):
    member = team_service.create_member("Member", "member@example.com", "human")
    client = pg_app.test_client()
    assert _upload(client, member, "sess-base", LONGER).status_code < 300
    _restored("sess-base")
    entries = _entries("sess-base")
    key = "decision-logs/2026-01-01T000000Z_sess-base.jsonl"
    s3.put(key, LONGER)
    run_sync()
    row = record(key)
    assert row.status == "ingested" and row.import_info["decision_log"]["outcome"] == "baselined"
    current = DecisionLogTranscript.query.filter_by(session_id="sess-base", status="current").one()
    assert (current.store_object_id, current.content_sha256, current.entry_count) == (row.id, row.sha256, 3)
    assert current.submitted_by is None and current.source_path == key
    assert _entries("sess-base") == entries  # no entry rows written
    assert db.session.get(DecisionLogSession, "sess-base").repository_entries == 3
    audited = db.session.execute(text(
        "SELECT count(*) FROM audit_log WHERE table_name = 'decision_log_transcripts' AND record_id = :v "
        "AND action = 'INSERT'"), {"v": current.id}).scalar()
    assert audited == 1
    assert _verify(s3)["status"] == "valid"
    assert verify_decision_logs(db.session)["mismatch_count"] == 0
    assert store_verify.verify_decision_logs_against_store(db.session, s3)["status"] == "valid"
    extended = LONGER + (rec("user", "done.", "2026-03-16T13:00:00Z", "u9") + "\n").encode()
    assert _upload(client, member, "sess-base", extended).status_code == 409  # the store holds it now


# --------------------------------------------------------------------------
# F2 + F5: refusals and non-import outcomes are re-derived on every run
# --------------------------------------------------------------------------

@pytest.mark.parametrize("key,body,kind,status,issue", [
    (LOG_KEY, TRANSCRIPT, "decision_log", "rejected", "recorded rejected, but an import of its body is not refused"),
    (LOG_KEY, TRANSCRIPT, "decision_log", "too_large", "recorded too_large, but its body is within"),
    (LOG_KEY, TRANSCRIPT, "decision_log", "unchanged", "recorded unchanged, but its session does not exist"),
    (PENTEST_KEY, PENTEST, "pentest_evidence", "unchanged", "recorded unchanged, but the store's namespace"),
    (PENTEST_KEY, PENTEST, "pentest_evidence", "rejected", "recorded rejected, but an import of its body is not"),
    (PENTEST_KEY, PENTEST, "pentest_evidence", "too_large", "recorded too_large, but its"),
    (REVIEW_KEY, REVIEW, "evidence_document", "rejected", "never refuses the content"),
], ids=["decision_log-rejected", "decision_log-too_large", "decision_log-unchanged", "pentest-unchanged",
        "pentest-rejected", "pentest-too_large", "document-rejected"])
def test_an_inserted_refusal_the_body_does_not_prove_fails_without_full(pg_app, s3, key, body, kind, status, issue):
    run_sync()
    version = s3.put(key, body)
    _insert_record(key, version, kind, status, s3)
    assert run_sync().counts["new"] == 0  # the inserted outcome keeps the sync from importing the version
    result = _verify(s3)
    assert result["status"] == "broken"
    assert any(k == key and issue in i for k, i in _failures(result)), _failures(result)
    if status in ("rejected", "too_large"):
        refusals = result["records"]["refusals"]
        assert result["records"]["refusals_count"] == 1 and (refusals[0]["key"], refusals[0]["status"]) == (key, status)


def test_an_unchanged_record_hiding_an_extension_fails_without_full(pg_app, s3):
    s3.put(LOG_KEY, TRANSCRIPT)
    run_sync()
    current = DecisionLogTranscript.query.filter_by(session_id="sess-store", status="current").one()
    key = "decision-logs/2026-10-02T000000Z_sess-store.jsonl"
    version = s3.put(key, LONGER)  # its third entry extends the session
    _insert_record(key, version, "decision_log", "unchanged", s3, {
        "decision_log": {"session_id": "sess-store", "outcome": "kept_existing", "entries": 2,
                         "matched_version": current.id}})
    run_sync()
    assert DecisionLogTranscript.query.filter_by(session_id="sess-store", status="current").one().entry_count == 2
    result = _verify(s3)
    assert result["status"] == "broken"
    assert (key, "recorded unchanged, but its entries are not identical to, or a prefix of, its session's stored "
                 "entries") in _failures(result)


def test_genuine_refusals_rederive_and_are_listed(pg_app, s3, monkeypatch):
    from app.services import transcript_ingest

    member = team_service.create_member("Member", "member@example.com", "human")
    assert _upload(pg_app.test_client(), member, "sess-api", LONGER).status_code < 300
    conflict = "decision-logs/2026-01-01T000000Z_sess-api.jsonl"
    s3.put(conflict, (rec("user", "ship it now", "2026-03-16T12:00:00Z", "zz1") + "\n").encode())
    many = "decision-logs/2026-10-01T000000Z_sess-many.jsonl"
    big = "decision-logs/2026-10-01T000000Z_sess-big.jsonl"
    nul = "pentest-evidence/layer3/nul.json"
    s3.put(many, LONGER)
    s3.put(big, LONGER + LONGER)
    s3.put(PENTEST_KEY, b"not json")
    s3.put(nul, json.dumps({"findings": [{"severity": "LOW", "summary": "a\u0000b"}]}).encode())
    monkeypatch.setattr(transcript_ingest, "MAX_TRANSCRIPT_ENTRIES", 2)
    monkeypatch.setattr(dl, "MAX_TRANSCRIPT_BYTES", len(LONGER) + 10)
    run_sync()
    statuses = {key: record(key).status for key in (conflict, many, big, PENTEST_KEY, nul)}
    assert statuses == {conflict: "rejected", many: "too_large", big: "too_large", PENTEST_KEY: "rejected",
                        nul: "rejected"}
    assert "NUL character" in record(nul).detail
    result = _verify(s3)
    assert result["status"] == "valid", _failures(result)
    assert result["records"]["refusals_count"] == 5 and result["store_conflicts_count"] == 1


# --------------------------------------------------------------------------
# F3: a replayed repository conflict naming a store object
# --------------------------------------------------------------------------

def test_a_replayed_conflict_naming_a_store_object_is_broken(pg_app, s3):
    member = team_service.create_member("Member", "member@example.com", "human")
    assert _upload(pg_app.test_client(), member, "sess-g", LONGER).status_code < 300
    forged = (rec("user", "ship it now", "2026-03-16T12:00:00Z", "zz1") + "\n").encode()
    key = "decision-logs/2026-01-01T000000Z_sess-g.jsonl"
    s3.put(key, forged)
    run_sync()
    obj = record(key)
    assert obj.status == "rejected"
    # The database role replays the repository-conflict path, naming the refused store object.
    token = dl._STORE_OBJECT.set(obj.id)
    try:
        result = dl._import(forged, "sess-g", obj.sha256, len(forged), source_path=key, exit_reason=None,
                            submitted_by=None, authority=dl.AUTHORITY_SYSTEM, dry_run=False, named_agent=None)
    finally:
        dl._STORE_OBJECT.reset(token)
    db.session.commit()
    assert result.status == "replaced" and result.conflict
    issues = [m["issue"] for m in verify_decision_logs(db.session)["mismatches"]]
    assert any("successor is a store import" in issue for issue in issues), issues
    assert any("not recorded as imported (rejected)" in issue for issue in issues), issues
    store_result = _verify(s3)
    assert store_result["status"] == "broken"
    assert any(k == key and "recorded rejected, but an import of its body is not refused" in i
               for k, i in _failures(store_result))


# --------------------------------------------------------------------------
# F4: the store's pentest findings
# --------------------------------------------------------------------------

def test_store_findings_are_immutable_through_the_api_and_the_database(pg_app, s3):
    s3.put(PENTEST_KEY, PENTEST)
    run_sync()
    row = record(PENTEST_KEY)
    identity = evidence_import.identity_digest(evidence_import.finding_keys(json.loads(PENTEST)["findings"]))
    assert row.status == "ingested" and row.import_info == {"findings": 2, "identity_sha256": identity, "stored": True}
    member = team_service.create_member("Member", "member@example.com", "human")
    client, headers = pg_app.test_client(), {"X-API-Key": member.issued_api_key}
    finding = _store_findings().filter_by(severity="HIGH").one()
    assert client.put(f"/api/pentest-findings/{finding.id}", json={"severity": "LOW"}, headers=headers).status_code \
        == 409
    refused = client.delete(f"/api/pentest-findings/{finding.id}", headers=headers)
    assert refused.status_code == 409 and "immutable" in refused.get_json()["error"]
    assert client.post("/api/pentest-findings", json={"layer": 2, "source_file": STORE_HOLDER},
                       headers=headers).status_code == 409
    evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, OTHER_PENTEST, namespace="git-src")
    db.session.commit()
    other = PentestFinding.query.filter_by(source_file="git-src:layer2/scan-1.json").one()
    assert client.put(f"/api/pentest-findings/{other.id}", json={"source_file": STORE_HOLDER},
                      headers=headers).status_code == 409
    assert client.put(f"/api/pentest-findings/{other.id}", json={"severity": "MEDIUM"},
                      headers=headers).status_code == 200  # another namespace's findings stay editable
    _refused("DELETE FROM pentest_findings WHERE source_file LIKE 'evidence-store:%'")
    _refused("UPDATE pentest_findings SET severity = 'LOW' WHERE source_file LIKE 'evidence-store:%'")
    _refused("UPDATE pentest_findings SET description = 'noted' WHERE source_file LIKE 'evidence-store:%'")
    _refused("UPDATE pentest_findings SET source_file = :s WHERE source_file LIKE 'git-src:%'", {"s": STORE_HOLDER})
    _refused("TRUNCATE pentest_findings")
    db.session.execute(text("DELETE FROM pentest_findings WHERE source_file LIKE 'git-src:%'"))
    db.session.commit()
    assert _store_findings().count() == 2 and _store_findings().filter_by(severity="HIGH").count() == 1
    assert _verify(s3)["status"] == "valid"


def test_a_deleted_or_edited_store_finding_fails_without_full(pg_app, s3):
    s3.put(PENTEST_KEY, PENTEST)
    run_sync()
    assert _verify(s3)["status"] == "valid"
    high = _store_findings().filter_by(severity="HIGH").one()
    issue = ("recorded ingested, but the store's namespace does not hold exactly the findings it imported (their "
             "count and identity, recomputed from their content)")
    tamper("UPDATE pentest_findings SET severity = 'LOW' WHERE id = :i", {"i": high.id}, table="pentest_findings")
    weakened = _verify(s3)
    assert weakened["status"] == "broken" and (PENTEST_KEY, issue) in _failures(weakened)
    tamper("DELETE FROM pentest_findings WHERE id = :i", {"i": high.id}, table="pentest_findings")
    deleted = _verify(s3)
    assert deleted["status"] == "broken" and (PENTEST_KEY, issue) in _failures(deleted)


def test_full_rederives_an_ingested_pentest_file_from_its_body(pg_app, s3):
    from app.services.evidence_store import plans

    run_sync()
    version = s3.put(PENTEST_KEY, PENTEST)
    # The database role writes other findings into the store's namespace, under the ids this version gives
    # them, and records them as the import.
    with pytest.raises(ValueError, match="written only by the evidence store's sync"):
        evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, OTHER_PENTEST,
                                            namespace="evidence-store")
    forged = plans.check_pentest(PENTEST_KEY, json.loads(OTHER_PENTEST), version)
    plans.insert_store_findings(forged)
    db.session.commit()
    _insert_record(PENTEST_KEY, version, "pentest_evidence", "ingested", s3, dict(forged.info(), stored=True))
    assert _verify(s3)["status"] == "valid"  # the database agrees with itself
    full = _verify(s3, full=True)
    assert full["status"] == "broken"
    assert (PENTEST_KEY, "recorded ingested, but the findings of its body are not the ones it recorded "
                         "importing") in _failures(full)


def _sync_bucket(s3, bucket, objects):
    """Put ``{key: body}`` into another bucket and sync it."""
    make_bucket(s3, bucket)
    other = ChecksummingS3(s3.client, bucket)
    other.checksums, other.head_overrides, other.policies = s3.checksums, s3.head_overrides, s3.policies
    for key, body in objects.items():
        other.put(key, body)
    run, created = scheduler.enqueue_evidence_store_sync(bucket, "manual")
    assert created and scheduler.execute_claimed("evidence_store_sync", run.id) == "executed"
    db.session.expire_all()


def test_a_second_store_object_never_replaces_the_stores_findings(pg_app, s3):
    s3.put(PENTEST_KEY, PENTEST)
    run_sync()
    ids = sorted(f.id for f in _store_findings())
    _sync_bucket(s3, "evidence-second-test", {PENTEST_KEY: PENTEST})
    _sync_bucket(s3, "evidence-third-test", {PENTEST_KEY: OTHER_PENTEST})
    same = EvidenceStoreObject.query.filter_by(bucket="evidence-second-test").one()
    different = EvidenceStoreObject.query.filter_by(bucket="evidence-third-test").one()
    assert same.status == "unchanged" and same.import_info["findings"] == 2
    assert different.status == "rejected" and "conflict: the store's namespace already holds" in different.detail
    assert sorted(f.id for f in _store_findings()) == ids
    result = _verify(s3)  # every record, of every bucket, re-derives
    assert result["status"] == "valid", _failures(result)


def test_a_duplicate_whose_counterpart_is_edited_fails_until_reevaluated(pg_app, s3):
    evidence_import.import_dataset_file("pentest-findings", PENTEST_KEY, PENTEST, namespace="git-src")
    db.session.commit()
    s3.put(PENTEST_KEY, PENTEST)
    run_sync()
    row = record(PENTEST_KEY)
    assert row.status == "duplicate" and row.import_info["findings"] == 2
    assert _verify(s3)["status"] == "valid"
    member = team_service.create_member("Member", "member@example.com", "human")
    counterpart = PentestFinding.query.filter_by(source_file="git-src:layer2/scan-1.json", severity="HIGH").one()
    assert pg_app.test_client().put(f"/api/pentest-findings/{counterpart.id}", json={"severity": "LOW"},
                                    headers={"X-API-Key": member.issued_api_key}).status_code == 200
    stale = _verify(s3)
    assert stale["status"] == "broken"
    assert (PENTEST_KEY, "recorded duplicate, but its counterpart does not hold exactly the findings of its "
                         "body") in _failures(stale)
    run = run_sync()  # the per-sync re-check imports the store's copy
    assert run.counts["reevaluated"] == 1 and record(PENTEST_KEY).status == "ingested"
    assert _store_findings().count() == 2 and _verify(s3)["status"] == "valid"


# --------------------------------------------------------------------------
# F6: the retention floor is append-only
# --------------------------------------------------------------------------

def test_retention_floors_are_appended_dated_by_the_database_and_lowerings_listed(pg_app, s3):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    run_sync()
    first = service.retention_floor(BUCKET)
    assert first.days == 7 * 365 and first.set_by is None
    _refused("UPDATE evidence_store_retention_floors SET days = 1, set_by = :m, reason = 'x', "
             "set_at = now() + interval '1 second'", {"m": admin.id})
    _refused("DELETE FROM evidence_store_retention_floors")
    _refused("INSERT INTO evidence_store_retention_floors (id, bucket, days, reason) VALUES ('f2', :b, 1, 'no admin')",
             {"b": BUCKET})
    db.session.execute(text(
        "INSERT INTO evidence_store_retention_floors (id, bucket, days, set_by, reason, set_at, created_at) "
        "VALUES ('f3', :b, 1, :m, 'lowered for a one-day test object', 'infinity', 'infinity')"),
        {"b": BUCKET, "m": admin.id})
    db.session.commit()
    lowered = db.session.get(EvidenceStoreRetentionFloor, "f3")
    assert lowered.set_at > first.set_at and lowered.set_at.year == datetime.now(timezone.utc).year
    assert service.retention_floor(BUCKET).id == "f3" and db.session.get(EvidenceStoreRetentionFloor, first.id).days \
        == 7 * 365
    s3.set_default_retention(BUCKET, {"Mode": "GOVERNANCE", "Days": 1})
    result = _verify(s3)
    assert result["status"] == "valid" and result["bucket_check"]["retention_floor_days"] == 1
    assert result["bucket_check"]["retention_floor_lowerings_count"] == 1
    lowering = result["bucket_check"]["retention_floor_lowerings"][0]
    assert (lowering["from_days"], lowering["to_days"], lowering["set_by"]) == (7 * 365, 1, admin.id)


def test_a_floor_seeded_before_the_first_sync_fails(pg_app, s3):
    db.session.execute(text("INSERT INTO evidence_store_retention_floors (id, bucket, days, reason) "
                            "VALUES ('f1', :b, 1, 'seeded')"), {"b": BUCKET})
    db.session.commit()
    s3.put(REVIEW_KEY, REVIEW)
    run_sync()
    result = _verify(s3)
    assert result["status"] == "broken"
    assert any("first retention floor (1 days) is not the default retention its first sync observed (2555 days"
               in issue for issue in result["bucket_check"]["issues"]), result["bucket_check"]["issues"]


def test_the_first_floor_comes_from_the_first_sync(pg_app, s3):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    with pytest.raises(service.EvidenceStoreError, match="first sync"):
        service.set_retention_floor(BUCKET, 3650, "before any sync", admin.id)
    db.session.rollback()
    run_sync()
    assert service.set_retention_floor(BUCKET, 3650, "raised", admin.id).days == 3650
    db.session.commit()
    assert EvidenceStoreRetentionFloor.query.filter_by(bucket=BUCKET).count() == 2


# --------------------------------------------------------------------------
# N4: the policy's partition and erasure principals; bulk acknowledgement
# --------------------------------------------------------------------------

def test_policy_resources_must_be_in_the_portals_partition(monkeypatch):
    policy = json.dumps(bucket_policy("b"))
    china = policy.replace("arn:aws:s3:::", "arn:aws-cn:s3:::")
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    assert store_verify.check_policy(policy, "b") == ([], [])
    assert len(store_verify.check_policy(china, "b")[0]) == 5
    monkeypatch.setenv("AWS_REGION", "cn-north-1")
    assert store_verify.check_policy(china, "b") == ([], [])
    assert len(store_verify.check_policy(policy, "b")[0]) == 5
    monkeypatch.delenv("AWS_REGION")
    client = types.SimpleNamespace(meta=types.SimpleNamespace(region_name="us-gov-west-1"))
    assert store_verify.portal_partition(client) == "aws-us-gov" and store_verify.portal_partition() == "aws"
    assert [store_verify.partition_for_region(r) for r in ("eu-west-1", "cn-northwest-1", "us-gov-east-1", None)] \
        == ["aws", "aws-cn", "aws-us-gov", "aws"]


def test_an_erasure_principal_with_a_policy_variable_fails():
    issues, _ = store_verify.check_policy(json.dumps(bucket_policy("b", erasure_principal="${aws:PrincipalArn}")),
                                          "b", "aws")
    assert any("policy variable" in issue for issue in issues), issues


def test_the_writer_role_statement_never_fails_the_policy():
    plain = bucket_policy("b")
    assert any(s.get("Sid") == "OnlyTheWriterRoleWritesEvidence"
               and s["Condition"] == {"ArnNotEquals": {"aws:PrincipalArn": WRITER_ROLE}} for s in plain["Statement"])
    assert store_verify.check_policy(json.dumps(plain), "b", "aws") == ([], [])
    erasing = bucket_policy("b", erasure_principal=ERASER)
    assert store_verify.check_policy(json.dumps(erasing), "b", "aws") == ([], [ERASER])
    for policy in (plain, erasing):  # wherever it stands among the statements
        policy["Statement"].reverse()
    assert store_verify.check_policy(json.dumps(plain), "b", "aws") == ([], [])
    assert store_verify.check_policy(json.dumps(erasing), "b", "aws") == ([], [ERASER])


def test_acknowledge_refuses_unparseable_lines_by_number_and_goes_on(pg_app, s3, migrated_pg_url, monkeypatch,
                                                                     tmp_path):
    from cli import evidence_store_cmd

    version = s3.put("codex-reviews/a.md", REVIEW, checksum=None)
    run_sync()
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    real_loads = json.loads

    def loads(raw, *args, **kwargs):  # a parser that runs out of stack on a deeply nested line
        if raw.startswith(b"[["):
            raise RecursionError("maximum recursion depth exceeded")
        return real_loads(raw, *args, **kwargs)

    monkeypatch.setattr(evidence_store_cmd, "json", types.SimpleNamespace(loads=loads, dumps=json.dumps))
    lines = [b"[" * 4000 + b"]" * 4000, json.dumps({"key": "codex-reviews/a.md", "version_id": "v\u0000"}).encode(),
             b"{\x80}", json.dumps({"key": "codex-reviews/a.md", "version_id": version}).encode()]
    path = tmp_path / "acknowledge.jsonl"
    path.write_bytes(b"\n".join(lines) + b"\n")
    code, out = _cli(migrated_pg_url, monkeypatch, "evidence-store", "acknowledge", "--file", str(path), "--reason",
                     "uploaded before checksums were required", "--admin", admin.email)
    assert code == 2 and "Acknowledged 1 version(s); refused 3." in out, out
    assert "line 1: refused: not a JSON object" in out and "line 3: refused: not a JSON object" in out
    assert "line 2: refused:" in out
    assert record("codex-reviews/a.md").status == "acknowledged"


def test_an_acknowledged_version_that_conforms_fails(pg_app, s3):
    run_sync()
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    version = s3.put(REVIEW_KEY, REVIEW)
    _insert_record(REVIEW_KEY, version, "evidence_document", "non_conforming", s3)
    service.acknowledge(record(REVIEW_KEY), "looked non-conforming", admin.id)
    db.session.commit()
    result = _verify(s3)
    assert result["status"] == "broken"
    assert (REVIEW_KEY, "recorded as non-conforming, but the version has a full-object SHA-256 checksum its body "
                        "matches") in _failures(result)
