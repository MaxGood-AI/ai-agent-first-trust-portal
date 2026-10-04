"""audit-verify-archive: what an archive dump contains (round 5).

Fixtures (tests/fixtures/audit_archive/) are real ``pg_dump --format=custom``
archives (PostgreSQL 17, gzip and uncompressed) of a small portal database
whose chain has rows from before the hash chain, v1 rows, a fork and v2 rows;
``expected.json`` is what verifying that database directly reported.
"""

import hashlib
import io
import json
import os

import boto3
import pytest
from moto import mock_aws
from sqlalchemy import create_engine, text

from app import runtime_config
from app.services import audit_archive, audit_witness
from app.services.audit_archive_dump import DumpError, verify_archive_dump

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "audit_archive")
DUMP = os.path.join(FIXTURES, "portal.dump")
UNCOMPRESSED = os.path.join(FIXTURES, "portal-uncompressed.dump")
with open(os.path.join(FIXTURES, "expected.json"), encoding="utf-8") as _handle:
    EXPECTED = json.load(_handle)
BUCKET = "witness"


def _sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _scratch_schemas(url):
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return conn.execute(text("SELECT nspname FROM pg_namespace WHERE nspname LIKE 'audit_archive_%'")).all()
    finally:
        engine.dispose()


@pytest.fixture
def s3(monkeypatch):
    with mock_aws():
        for name, value in (("AWS_ACCESS_KEY_ID", "testing"), ("AWS_SECRET_ACCESS_KEY", "testing"),
                            ("AWS_REGION", "us-east-1")):
            monkeypatch.setenv(name, value)
        for name in ("AWS_RUNTIME_ROLE_ARN", "PORTAL_SECRET_ID", "AUDIT_WITNESS_DISABLED", "AUDIT_WITNESS_BUCKET"):
            monkeypatch.delenv(name, raising=False)
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
        yield client


def _publish(s3, row_id, row_hash, stamp="20261001T000000Z"):
    head = {"format": audit_witness.FORMAT, "chain_id": EXPECTED["chain_id"], "id": row_id, "row_hash": row_hash,
            "published_at": f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]}T{stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]}Z"}
    s3.put_object(Bucket=BUCKET, Key=audit_witness.object_key(head), Body=json.dumps(head).encode())


def _publish_genuine(s3):
    rows = EXPECTED["hashed_rows"]
    _publish(s3, rows[3]["id"], rows[3]["row_hash"], "20261001T010000Z")
    _publish(s3, rows[-1]["id"], rows[-1]["row_hash"], "20261001T020000Z")


def _manifest(s3, **overrides):
    manifest = {"format": audit_archive.FORMAT, "archive_id": "final.dump",
                "archive_key": f"archives/{EXPECTED['chain_id']}/final.dump", "archive_version_id": None,
                "archive_size": os.path.getsize(DUMP), "archive_sha256": _sha(DUMP),
                "chain_id": EXPECTED["chain_id"], "final_row_id": EXPECTED["final_row_id"],
                "final_row_hash": EXPECTED["final_row_hash"], "entries": EXPECTED["entries"],
                "verify": {"status": EXPECTED["status"]}, "created_at": "2026-10-01T00:00:00Z"}
    manifest.update(overrides)
    key = audit_archive.manifest_object_key(EXPECTED["chain_id"], "final.dump")
    audit_archive.write_manifest(s3, BUCKET, key, manifest)
    return key


def _cli(monkeypatch, argv):
    from cli import admin_cmd
    from cli.__main__ import build_parser

    runtime_config._reset_for_tests()
    out = io.StringIO()
    return admin_cmd.run(build_parser().parse_args(argv), out=out), out.getvalue()


@pytest.mark.parametrize("dump", [DUMP, UNCOMPRESSED])
def test_archive_dump_chain_with_forks_and_pre_v2_rows_verifies(migrated_pg_url, dump):
    result = verify_archive_dump(dump, migrated_pg_url)
    assert result["issues"] == []
    # Internally consistent, but not checked against the witness or a manifest: not "verified".
    assert result["ok"] is False and len(result["unchecked"]) == 2
    verify = result["verify"]
    assert (verify["status"], verify["forks"], verify["true_breaks"], verify["unhashed_entries"], verify["verified"]) \
        == (EXPECTED["status"], EXPECTED["forks"], 0, EXPECTED["unhashed_entries"], EXPECTED["verified"])
    assert result["chain_id"] == EXPECTED["chain_id"]
    assert result["final_row"] == {"id": EXPECTED["final_row_id"], "row_hash": EXPECTED["final_row_hash"]}
    assert result["dump"]["rows"] == EXPECTED["entries"]
    assert result["dump"]["sha256"] == _sha(dump) and result["dump"]["size"] == os.path.getsize(dump)
    assert result["dump"]["archive_version"] == "1.16"
    assert _scratch_schemas(migrated_pg_url) == []  # dropped


def test_archive_dump_against_the_witness_and_the_manifest(migrated_pg_url, s3, monkeypatch):
    _publish_genuine(s3)
    key = _manifest(s3)
    code, out = _cli(monkeypatch, ["audit-verify-archive", "--dump", DUMP, "--scratch-url", migrated_pg_url,
                                   "--bucket", BUCKET, "--manifest", key])
    assert code == 0, out
    assert out.startswith("verified: dump sha256=" + _sha(DUMP))
    assert "witness: heads_checked=2 mismatches=0 invalid_objects=0" in out


def test_archive_dump_missing_a_published_row_fails(migrated_pg_url, s3, monkeypatch):
    """The archive must hold every published row: a head after the dump's final row fails."""
    _publish_genuine(s3)
    _publish(s3, EXPECTED["final_row_id"] + 3, "c" * 64, "20261001T030000Z")
    code, out = _cli(monkeypatch, ["audit-verify-archive", "--dump", DUMP, "--scratch-url", migrated_pg_url,
                                   "--bucket", BUCKET])
    assert code == 1 and out.startswith("NOT VERIFIED")
    assert "the archived chain does not verify: broken" in out


def test_archive_dump_with_a_different_published_row_fails(migrated_pg_url, s3):
    rows = EXPECTED["hashed_rows"]
    _publish(s3, rows[2]["id"], "d" * 64)
    result = verify_archive_dump(DUMP, migrated_pg_url, bucket=BUCKET, client=s3)
    assert result["ok"] is False and result["verify"]["witness_mismatches"] == 1


@pytest.mark.parametrize("field, value", [
    ("archive_sha256", "f" * 64), ("archive_size", 1), ("final_row_hash", "e" * 64),
    ("final_row_id", 999), ("entries", 3)])
def test_archive_dump_that_is_not_the_manifests_fails(migrated_pg_url, s3, field, value):
    _publish_genuine(s3)
    key = _manifest(s3, **{field: value})
    result = verify_archive_dump(DUMP, migrated_pg_url, bucket=BUCKET, client=s3, manifest_key=key)
    assert result["ok"] is False
    assert any(issue.startswith(f"the dump's {field} ") for issue in result["issues"]), result["issues"]


def test_archive_dump_without_any_published_head_is_not_verified(migrated_pg_url, s3):
    result = verify_archive_dump(DUMP, migrated_pg_url, bucket=BUCKET, client=s3)
    assert result["ok"] is False
    assert result["issues"] == [f"the witness published no head for chain {EXPECTED['chain_id']}"]


def test_archive_dump_unreadable_or_truncated_is_a_usage_error(migrated_pg_url, tmp_path, monkeypatch):
    truncated = tmp_path / "truncated.dump"
    with open(DUMP, "rb") as handle:
        truncated.write_bytes(handle.read()[:2000])
    with pytest.raises(DumpError, match="truncated"):
        verify_archive_dump(str(truncated), migrated_pg_url)
    plain = tmp_path / "plain.sql"
    plain.write_text("-- PostgreSQL database dump\n")
    code, out = _cli(monkeypatch, ["audit-verify-archive", "--dump", str(plain), "--scratch-url", migrated_pg_url])
    assert code == 2 and "not a pg_dump custom-format archive" in out
    assert _scratch_schemas(migrated_pg_url) == []


def test_archive_dump_keep_leaves_the_scratch_schema(migrated_pg_url):
    result = verify_archive_dump(DUMP, migrated_pg_url, keep=True)
    schema = result["scratch_schema"]
    assert [row[0] for row in _scratch_schemas(migrated_pg_url)] == [schema]
    engine = create_engine(migrated_pg_url)
    try:
        with engine.begin() as conn:
            persistence = conn.execute(text("SELECT relpersistence FROM pg_class WHERE oid = to_regclass(:t)"),
                                       {"t": f"{schema}.audit_log"}).scalar()
            conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
    finally:
        engine.dispose()
    assert persistence == "u"  # UNLOGGED: no WAL for the scratch copy
