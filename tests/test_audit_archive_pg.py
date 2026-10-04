"""Archive manifests: an anchor is verified against the Object Lock archive,
never taken on its own word.

The attack these tests close: the database owner empties the audit log and
anchors a new chain at the witness's last published head. Anchoring now
requires an archive manifest in the witness bucket (written once, with
operator credentials), and verification accepts the anchor only when the
manifest, the archive object and the archived chain's published final head
all match it (``app.services.audit_archive``).
"""

import io
import json
from datetime import datetime, timezone

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws
from sqlalchemy import text

from app import runtime_config
from app.models import Control, db

BUCKET = "witness"
DUMP = b"-- PostgreSQL database dump\n" + b"x" * 4096


@pytest.fixture
def s3(monkeypatch):
    with mock_aws():
        for name, value in (("AWS_ACCESS_KEY_ID", "testing"), ("AWS_SECRET_ACCESS_KEY", "testing"),
                            ("AWS_REGION", "us-east-1"), ("AUDIT_WITNESS_BUCKET", BUCKET)):
            monkeypatch.setenv(name, value)
        for name in ("AUDIT_WITNESS_DISABLED", "AWS_RUNTIME_ROLE_ARN", "PORTAL_SECRET_ID"):
            monkeypatch.delenv(name, raising=False)
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
        yield client


def _writes(*names):
    for name in names:
        db.session.add(Control(id=name, name=name, category="security"))
        db.session.commit()


def _restore_without_audit_history():
    """Stands for restoring the final dump, all but the audit history, into a new database."""
    db.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    db.session.execute(text("DELETE FROM audit_log"))
    db.session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    db.session.commit()


def _archive(s3, tmp_path, name="final.dump", content=DUMP, **kwargs):
    from app.services import audit_archive

    dump = tmp_path / "final-dump.bin"
    dump.write_bytes(content)
    return audit_archive.create_archive_manifest(db.session, bucket=BUCKET, client=s3, dump_path=str(dump),
                                                 name=name, **kwargs)


def _anchor(s3, manifest_key):
    """Anchor from the manifest and publish the new chain's head (as audit-anchor does)."""
    from app.services import audit_archive, audit_witness

    anchored = audit_archive.anchor_from_manifest(db.session, bucket=BUCKET, client=s3, manifest_key=manifest_key)
    db.session.commit()
    audit_witness.publish_head(db.session, client=s3)
    return anchored


def _verify(s3, rehash=False):
    from app.services.audit_archive import verify_anchor
    from app.services.audit_chain import verify_chain
    from app.services.audit_witness import load_heads_s3

    return verify_chain(db.session, witness_heads=load_heads_s3(BUCKET, client=s3),
                        anchor_verifier=lambda anchor: verify_anchor(anchor, bucket=BUCKET, client=s3,
                                                                     rehash=rehash))


def _forge_anchor(**fields):
    """The owner inserts an ANCHOR row by hand (triggers off), naming whatever it likes."""
    from app.services.audit_chain import insert_anchor

    defaults = {"archive_id": "forged", "archive_sha256": "a" * 64, "archived_entries": 1,
                "manifest_key": "archives/0000000000000000/forged.manifest.json", "manifest_sha256": "b" * 64}
    defaults.update(fields)
    insert_anchor(db.session, **defaults)
    db.session.commit()


def _cli(monkeypatch, url, argv):
    """Run an admin command of ``python -m cli`` against ``url``; returns (exit code, output)."""
    from cli import admin_cmd
    from cli.__main__ import build_parser

    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", url)
    runtime_config._reset_for_tests()
    out = io.StringIO()
    code = admin_cmd.run(build_parser().parse_args(argv), out=out)
    return code, out.getvalue()


# --------------------------------------------------------------------------
# The attack: empty the audit log and anchor at the last published head
# --------------------------------------------------------------------------

@mock_aws
def test_empty_and_anchor_without_a_manifest_fails_verification(pg_app, migrated_pg_url, monkeypatch):
    from app.services import audit_witness

    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AUDIT_WITNESS_BUCKET", BUCKET)
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
    _writes("c1", "c2")
    audit_witness.arm(db.session, note="test")
    last = audit_witness.publish_head(db.session, client=s3)["head"]

    # The owner empties the audit log and writes an ANCHOR row naming the last
    # published head, with a made-up archive reference and no manifest.
    _restore_without_audit_history()
    db.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    db.session.execute(text("""
        WITH v AS (SELECT CAST(:head AS text) AS prev, now() AS ts,
                          jsonb_build_object('archive_id', 'fake', 'archive_sha256', repeat('a', 64),
                                             'archived_chain_head', CAST(:head AS text),
                                             'archived_entries', 2) AS nv)
        INSERT INTO audit_log (table_name, record_id, action, new_values, changed_at, previous_hash,
                               row_hash, hash_version)
        SELECT 'audit_log', 'fake', 'ANCHOR', nv, ts, prev,
               encode(sha256(convert_to(prev || 'audit_log' || 'fake' || 'ANCHOR' || '' ||
                   to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || '' || nv::text,
                   'UTF8')), 'hex'), 2
        FROM v"""), {"head": last["row_hash"]})
    db.session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    db.session.commit()
    _writes("c3")
    audit_witness.publish_head(db.session, client=s3)

    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-verify", "--witness-s3"])
    assert code == 1, out
    assert out.startswith("status=broken")
    assert "anchor_verification=failed" in out and "names no archive manifest" in out


def test_anchor_naming_a_missing_manifest_fails(pg_app, s3):
    from app.services import audit_witness

    _writes("c1")
    audit_witness.arm(db.session, note="test")
    last = audit_witness.publish_head(db.session, client=s3)["head"]
    _restore_without_audit_history()
    _forge_anchor(archived_chain_head=last["row_hash"])
    result = _verify(s3)
    assert result["status"] == "broken"
    assert result["anchor_verification"]["status"] == "failed"
    assert result["anchor_verification"]["issues"] == [
        "no archive manifest at archives/0000000000000000/forged.manifest.json"]
    assert result["first_break"]["issue"].startswith("Anchor not verified: no archive manifest")


def test_cli_anchor_refuses_a_missing_manifest(migrated_pg_url, s3, monkeypatch):
    monkeypatch.setenv("DATABASE_OWNER_URL", migrated_pg_url)
    code, out = _cli(monkeypatch, migrated_pg_url,
                     ["audit-anchor", "--manifest", "archives/0000000000000000/none.manifest.json"])
    assert code == 1 and out == "error: no archive manifest at archives/0000000000000000/none.manifest.json\n"
    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-anchor", "--manifest", "chain-heads/x.json"])
    assert code == 1 and "archives/<chain id>/<name>.manifest.json" in out
    from sqlalchemy import create_engine

    engine = create_engine(migrated_pg_url)
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar() == 0
    engine.dispose()


# --------------------------------------------------------------------------
# Manifest mismatches
# --------------------------------------------------------------------------

def test_manifest_with_the_wrong_sha_fails(pg_app, s3, tmp_path):
    from app.services import audit_archive

    _writes("c1", "c2")
    written = _archive(s3, tmp_path)
    manifest = written["manifest"]
    _restore_without_audit_history()
    # The anchor names the real manifest but a different archive SHA-256.
    _forge_anchor(archive_id=manifest["archive_id"], archive_sha256="f" * 64,
                  archived_chain_head=manifest["final_row_hash"], archived_entries=manifest["entries"],
                  manifest_key=written["manifest_key"], manifest_sha256=written["manifest_sha256"])
    result = _verify(s3)
    assert result["status"] == "broken"
    assert result["anchor_verification"]["issues"] == ["the anchor's archive SHA-256 differs from the manifest's"]

    # A manifest whose bytes differ from the one the anchor records (another version at the key).
    s3.put_object(Bucket=BUCKET, Key=written["manifest_key"],
                  Body=json.dumps(dict(manifest, archive_sha256="f" * 64)).encode())
    assert audit_archive.verify_anchor(result["anchor"], bucket=BUCKET, client=s3)["issues"] == [
        f"the manifest at {written['manifest_key']} is not the one the anchor names (manifest SHA-256 differs)"]


def test_manifest_sha_that_does_not_match_the_archive_bytes_fails_the_rehash(pg_app, s3, tmp_path):
    from app.services import audit_witness

    _writes("c1")
    cid = audit_witness.chain_id(db.session)
    # The object under archives/ holds other bytes of the same size than the local dump.
    key = f"archives/{cid}/uploaded-earlier"
    s3.put_object(Bucket=BUCKET, Key=key, Body=b"y" * len(DUMP))
    written = _archive(s3, tmp_path, name="final.dump", archive_key=key)
    assert written["manifest"]["archive_key"] == key
    _restore_without_audit_history()
    _anchor(s3, written["manifest_key"])
    _writes("c2")
    assert _verify(s3)["status"] == "valid"  # key, version and size match
    rehashed = _verify(s3, rehash=True)
    assert rehashed["status"] == "broken"
    assert rehashed["anchor_verification"]["rehashed"] is True
    assert rehashed["anchor_verification"]["issues"] == [
        "the archive object's bytes do not hash to the manifest's archive_sha256"]


def test_manifest_with_the_wrong_final_head_fails(pg_app, s3, tmp_path):
    from app.services import audit_archive, audit_witness

    _writes("c1", "c2")
    written = _archive(s3, tmp_path)
    manifest = written["manifest"]
    _restore_without_audit_history()
    # The anchor names the real manifest but links to another head.
    _forge_anchor(archive_id=manifest["archive_id"], archive_sha256=manifest["archive_sha256"],
                  archived_chain_head="e" * 64, archived_entries=manifest["entries"],
                  manifest_key=written["manifest_key"], manifest_sha256=written["manifest_sha256"])
    result = _verify(s3)
    assert result["status"] == "broken"
    assert result["anchor_verification"]["issues"] == [
        "the anchor's archived chain head (its previous_hash) is not the manifest's final row hash"]

    # A manifest whose final head the witness never published.
    unpublished = dict(manifest, archive_id="unpublished", final_row_hash="d" * 64,
                       final_row_id=manifest["final_row_id"] + 1000)
    key = audit_archive.manifest_object_key(manifest["chain_id"], "unpublished")
    body = audit_archive.write_manifest(s3, BUCKET, key, unpublished)
    anchor = {"archive_id": "unpublished", "archive_sha256": manifest["archive_sha256"],
              "archived_chain_head": "d" * 64, "archived_entries": manifest["entries"],
              "archive_manifest_key": key, "archive_manifest_sha256": body["sha256"]}
    issues = audit_archive.verify_anchor(anchor, bucket=BUCKET, client=s3)["issues"]
    assert issues == [f"the witness never published the archived chain's final head (row "
                      f"{unpublished['final_row_id']}) under chain-heads/{manifest['chain_id']}/"]
    with pytest.raises(audit_archive.ArchiveError, match="never published"):
        audit_archive.anchor_from_manifest(db.session, bucket=BUCKET, client=s3, manifest_key=key)

    # The archived chain kept writing after its manifest: a later head was published.
    later = dict(audit_witness.current_head(db.session) or {}, chain_id=manifest["chain_id"],
                 id=manifest["final_row_id"] + 5, row_hash="c" * 64,
                 published_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    audit_witness.publish_head(db.session, client=s3, head=later, require_armed=False)
    good = {"archive_id": manifest["archive_id"], "archive_sha256": manifest["archive_sha256"],
            "archived_chain_head": manifest["final_row_hash"], "archived_entries": manifest["entries"],
            "archive_manifest_key": written["manifest_key"], "archive_manifest_sha256": written["manifest_sha256"]}
    issues = audit_archive.verify_anchor(good, bucket=BUCKET, client=s3)["issues"]
    assert issues == [f"the witness published a head of the archived chain after its final row "
                      f"(row {manifest['final_row_id'] + 5}): the archive does not hold every published row"]


def test_manifest_with_a_missing_archive_object_fails(pg_app, s3, tmp_path):
    from app.services import audit_archive

    _writes("c1")
    written = _archive(s3, tmp_path)
    manifest = written["manifest"]
    missing = dict(manifest, archive_id="gone", archive_key=f"archives/{manifest['chain_id']}/gone.dump",
                   archive_version_id=None)
    key = audit_archive.manifest_object_key(manifest["chain_id"], "gone")
    body = audit_archive.write_manifest(s3, BUCKET, key, missing)
    with pytest.raises(audit_archive.ArchiveError, match="gone.dump is missing"):
        audit_archive.anchor_from_manifest(db.session, bucket=BUCKET, client=s3, manifest_key=key)
    _restore_without_audit_history()
    _forge_anchor(archive_id="gone", archive_sha256=manifest["archive_sha256"],
                  archived_chain_head=manifest["final_row_hash"], archived_entries=manifest["entries"],
                  manifest_key=key, manifest_sha256=body["sha256"])
    result = _verify(s3)
    assert result["status"] == "broken"
    assert result["anchor_verification"]["issues"] == [
        f"the archive object archives/{manifest['chain_id']}/gone.dump is missing"]

    # The pinned version, and the stated size, must both be there.
    wrong_version = dict(manifest, archive_id="wrong-version", archive_version_id="not-a-version")
    wrong_size = dict(manifest, archive_id="wrong-size", archive_size=manifest["archive_size"] + 1)
    for name, variant, issue in (
            ("wrong-version", wrong_version, f"the archive object {manifest['archive_key']} "
                                             "(version not-a-version) is missing"),
            ("wrong-size", wrong_size, f"the archive object {manifest['archive_key']} has "
                                       f"{manifest['archive_size']} bytes; the manifest states "
                                       f"{manifest['archive_size'] + 1}")):
        key = audit_archive.manifest_object_key(manifest["chain_id"], name)
        body = audit_archive.write_manifest(s3, BUCKET, key, variant)
        anchor = {"archive_id": name, "archive_sha256": manifest["archive_sha256"],
                  "archived_chain_head": manifest["final_row_hash"], "archived_entries": manifest["entries"],
                  "archive_manifest_key": key, "archive_manifest_sha256": body["sha256"]}
        assert audit_archive.verify_anchor(anchor, bucket=BUCKET, client=s3)["issues"] == [issue]


# --------------------------------------------------------------------------
# The happy path, and what "unverified" means
# --------------------------------------------------------------------------

def test_archive_restore_anchor_verify(pg_app, s3, tmp_path):
    from app.services import audit_archive, audit_witness

    _writes("c1", "c2")
    source_head = audit_witness.current_head(db.session)
    written = _archive(s3, tmp_path)
    manifest = written["manifest"]
    cid = source_head["chain_id"]
    assert written["manifest_key"] == f"archives/{cid}/final.dump.manifest.json"
    assert manifest["archive_key"] == f"archives/{cid}/final.dump"
    assert manifest["archive_size"] == len(DUMP)
    assert manifest["archive_sha256"] == __import__("hashlib").sha256(DUMP).hexdigest()
    assert (manifest["final_row_id"], manifest["final_row_hash"]) == (source_head["id"], source_head["row_hash"])
    assert manifest["entries"] == 2 and manifest["verify"]["status"] == "valid"
    assert manifest["final_head_key"].startswith(f"chain-heads/{cid}/")
    assert manifest["archive_version_id"]
    stored = s3.get_object(Bucket=BUCKET, Key=written["manifest_key"])["Body"].read()
    assert json.loads(stored) == manifest

    _restore_without_audit_history()
    anchored = _anchor(s3, written["manifest_key"])
    row = db.session.execute(text("SELECT new_values FROM audit_log ORDER BY id LIMIT 1")).scalar()
    assert row["archive_manifest_key"] == written["manifest_key"]
    assert row["archive_manifest_sha256"] == written["manifest_sha256"]
    assert row["archive_sha256"] == manifest["archive_sha256"]
    _writes("c3")
    audit_witness.publish_head(db.session, client=s3)

    result = _verify(s3)
    assert result["status"] == "valid", result
    assert result["anchor"]["id"] == anchored["anchor_id"]
    checked = result["anchor_verification"]
    assert checked["status"] == "verified" and checked["issues"] == [] and checked["manifest_versions"] == 1
    assert checked["archived_chain"]["status"] == "valid" and checked["archived_chain"]["chain_id"] == cid
    assert result["witness"]["continued_chains"][0]["chain_id"] == cid
    rehashed = _verify(s3, rehash=True)
    assert rehashed["status"] == "valid" and rehashed["anchor_verification"]["rehashed"] is True

    # Without witness access the anchor is unverified, never valid.
    from app.services.audit_archive import verify_anchor
    from app.services.audit_chain import verify_chain

    assert verify_chain(db.session)["status"] == "unverified"
    assert verify_chain(db.session, anchor_verifier=lambda a: verify_anchor(a, bucket=None))["status"] \
        == "unverified"

    class Denied:
        def get_paginator(self, name):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListObjectVersions")

    denied = verify_chain(db.session, anchor_verifier=lambda a: verify_anchor(a, bucket=BUCKET, client=Denied()))
    assert denied["status"] == "unverified"
    assert denied["anchor_verification"]["reasons"] == ["cannot read the witness bucket (AccessDenied)"]
    # Resumed slices report the anchor's standing too.
    first = verify_chain(db.session, max_rows=1, chunk_size=1)
    rest = verify_chain(db.session, after_id=first["next_after_id"],
                        expected_previous_hash=first["expected_previous_hash"])
    assert rest["status"] == "unverified"
    assert audit_archive.parse_manifest(stored)["archive_id"] == "final.dump"


def test_large_dumps_are_uploaded_in_parts(pg_app, s3, tmp_path, monkeypatch):
    from app.services import audit_archive

    calls = []
    real_complete = s3.complete_multipart_upload

    def recording_complete(**kwargs):
        calls.append(kwargs)
        return real_complete(**kwargs)

    monkeypatch.setattr(s3, "complete_multipart_upload", recording_complete)
    _writes("c1")
    content = b"p" * (5 * 1024 * 1024) + b"tail"
    written = _archive(s3, tmp_path, content=content, part_size=5 * 1024 * 1024)
    assert calls and calls[0]["IfNoneMatch"] == "*" and len(calls[0]["MultipartUpload"]["Parts"]) == 2
    manifest = written["manifest"]
    assert manifest["archive_size"] == len(content)
    assert manifest["archive_sha256"] == __import__("hashlib").sha256(content).hexdigest()
    _restore_without_audit_history()
    _anchor(s3, written["manifest_key"])
    assert _verify(s3, rehash=True)["status"] == "valid"
    assert audit_archive.sha256_file(str(tmp_path / "final-dump.bin")) == (manifest["archive_sha256"], len(content))


@mock_aws
def test_cli_cutover_sequence(migrated_pg_url, tmp_path, monkeypatch):
    """final dump -> audit-archive-manifest -> restore -> audit-anchor -> audit-verify."""
    from sqlalchemy import create_engine

    for name, value in (("AWS_ACCESS_KEY_ID", "testing"), ("AWS_SECRET_ACCESS_KEY", "testing"),
                        ("AWS_REGION", "us-east-1"), ("AUDIT_WITNESS_BUCKET", BUCKET)):
        monkeypatch.setenv(name, value)
    for name in ("AUDIT_WITNESS_DISABLED", "AWS_RUNTIME_ROLE_ARN", "PORTAL_SECRET_ID",
                 "DATABASE_OWNER_USER", "DATABASE_OWNER_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
    monkeypatch.setenv("DATABASE_OWNER_URL", migrated_pg_url)
    assert _cli(monkeypatch, migrated_pg_url, ["create-admin", "--name", "Ops", "--email", "ops@example.com",
                                               "--key-file", str(tmp_path / "ops.key")])[0] == 0
    dump = tmp_path / "final.dump"
    dump.write_bytes(DUMP)

    code, out = _cli(monkeypatch, migrated_pg_url,
                     ["audit-archive-manifest", "--dump", str(dump), "--name", "final.dump"])
    assert code == 0, out
    manifest_key = out.splitlines()[2].split()[1]
    assert manifest_key.startswith("archives/") and manifest_key.endswith("/final.dump.manifest.json")
    assert out.splitlines()[-1] == f"Anchor the new database with: python -m cli audit-anchor --manifest {manifest_key}"
    code, out = _cli(monkeypatch, migrated_pg_url,
                     ["audit-archive-manifest", "--dump", str(dump), "--name", "final.dump"])
    assert code == 1 and "already exists" in out  # written once

    engine = create_engine(migrated_pg_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        for statement in ("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only", "DELETE FROM audit_log",
                          "ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"):
            conn.execute(text(statement))
    engine.dispose()

    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-anchor", "--manifest", manifest_key, "--note", "cutover"])
    assert code == 0, out
    assert out.startswith("Anchored audit log at row ") and "Published chain head to chain-heads/" in out
    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-verify"])
    assert code == 4 and out.startswith("status=unverified")
    assert "anchor_verification=unverified" in out
    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-verify", "--witness-s3"])
    assert code == 0 and out.startswith("status=valid"), out
    assert "anchor_verification=verified" in out and "archived_chain=" in out
    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-verify", "--witness-s3", "--rehash-archive"])
    assert code == 0 and "rehashed=True" in out
    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-verify", "--rehash-archive"])
    assert code == 2 and out == "error: --rehash-archive needs --witness-s3\n"
    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-verify", "--json"])
    assert code == 4 and json.loads(out)["anchor_verification"]["status"] == "unverified"


def test_api_checks_the_anchor_from_the_witness_bucket(pg_app, s3, tmp_path, monkeypatch):
    from app.services import audit_witness, team_service

    _writes("c1")
    written = _archive(s3, tmp_path)
    _restore_without_audit_history()
    _anchor(s3, written["manifest_key"])
    admin = team_service.create_member("Admin", "a@example.com", "human", is_compliance_admin=True)
    headers = {"X-API-Key": admin.issued_api_key}
    client = pg_app.test_client()
    ok = client.get("/api/audit-log/verify", headers=headers).get_json()
    assert ok["status"] == "valid" and ok["anchor_verification"]["status"] == "verified"

    monkeypatch.setenv("AUDIT_WITNESS_DISABLED", "true")
    off = client.get("/api/audit-log/verify", headers=headers).get_json()
    assert off["status"] == "unverified" and off["anchor_verification"]["status"] == "unverified"
    monkeypatch.delenv("AUDIT_WITNESS_DISABLED")

    class Denied:
        def get_paginator(self, name):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListObjectVersions")

    monkeypatch.setattr(audit_witness, "s3_client", lambda: Denied())
    denied = client.get("/api/audit-log/verify", headers=headers).get_json()
    assert denied["status"] == "unverified"
    db.session.remove()


# --------------------------------------------------------------------------
# Kill switch, write-once, and the anchor function's own checks
# --------------------------------------------------------------------------

def test_kill_switch_blocks_writing_a_manifest(pg_app, migrated_pg_url, s3, tmp_path, monkeypatch):
    from app.services import audit_archive

    _writes("c1")
    monkeypatch.setenv("AUDIT_WITNESS_DISABLED", "true")
    with pytest.raises(audit_archive.WitnessDisabledError):
        _archive(s3, tmp_path)
    dump = tmp_path / "cli.dump"
    dump.write_bytes(DUMP)
    code, out = _cli(monkeypatch, migrated_pg_url,
                     ["audit-archive-manifest", "--dump", str(dump), "--name", "cli.dump", "--bucket", BUCKET])
    assert code == 2 and out == "error: AUDIT_WITNESS_DISABLED is set: no manifest is written\n"
    assert s3.list_object_versions(Bucket=BUCKET).get("Versions", []) == []


def test_archive_and_manifest_are_written_once(pg_app, s3, tmp_path, monkeypatch):
    from app.services import audit_archive

    calls = []
    real_put = s3.put_object

    def recording_put(**kwargs):
        calls.append(kwargs)
        return real_put(**kwargs)

    monkeypatch.setattr(s3, "put_object", recording_put)
    _writes("c1")
    written = _archive(s3, tmp_path)
    assert {c["Key"].split("/")[0] for c in calls} == {"archives", "chain-heads"}
    assert all(c["IfNoneMatch"] == "*" and c["ChecksumAlgorithm"] == "SHA256" for c in calls)
    with pytest.raises(audit_archive.ArchiveError, match="already exists"):
        _archive(s3, tmp_path)
    # Re-using the uploaded archive under the same name still cannot replace the manifest.
    with pytest.raises(audit_archive.ArchiveError, match="already exists"):
        _archive(s3, tmp_path, archive_key=written["manifest"]["archive_key"])
    with pytest.raises(audit_archive.ArchiveError, match="--name"):
        _archive(s3, tmp_path, name="../escape")
    with pytest.raises(audit_archive.ArchiveError, match="under archives/"):
        _archive(s3, tmp_path, name="other", archive_key="chain-heads/x")
    with pytest.raises(audit_archive.ArchiveError, match="has 1 bytes"):
        real_put(Bucket=BUCKET, Key="archives/small", Body=b"s")
        _archive(s3, tmp_path, name="other", archive_key="archives/small")


def test_planted_or_unexpected_objects_fail_closed(pg_app, s3, tmp_path):
    """Only a failure to READ the bucket makes an anchor unverified; anything a
    writer of chain-heads/ can plant, or any unexpected error, fails it."""
    from botocore.exceptions import EndpointConnectionError

    from app.services.audit_archive import verify_anchor

    _writes("c1")
    written = _archive(s3, tmp_path)
    manifest = written["manifest"]
    anchor = {"archive_id": manifest["archive_id"], "archive_sha256": manifest["archive_sha256"],
              "archived_chain_head": manifest["final_row_hash"], "archived_entries": manifest["entries"],
              "archive_manifest_key": written["manifest_key"], "archive_manifest_sha256": written["manifest_sha256"]}
    assert verify_anchor(anchor, bucket=BUCKET, client=s3)["status"] == "verified"
    # The runtime role may write chain-heads/: a malformed object at the final row's id
    # is an invalid witness object, not a reason to stop checking.
    planted_key = (f"chain-heads/{manifest['chain_id']}/2099/01/01/"
                   f"20990101T000000Z-{manifest['final_row_id']}.json")
    s3.put_object(Bucket=BUCKET, Key=planted_key, Body=b"not json")
    planted = verify_anchor(anchor, bucket=BUCKET, client=s3)
    assert planted["status"] == "failed"
    assert planted["issues"] == [f"1 invalid witness object(s) under chain-heads/{manifest['chain_id']}/ "
                                 f"(first: {planted_key}: not JSON)"]

    class Unreachable:
        def get_paginator(self, name):
            raise EndpointConnectionError(endpoint_url="https://s3.example")

    class Broken:
        def get_paginator(self, name):
            raise RuntimeError("boom")

    unreachable = verify_anchor(anchor, bucket=BUCKET, client=Unreachable())
    assert unreachable["status"] == "unverified"
    assert unreachable["reasons"] == ["cannot read the witness bucket (EndpointConnectionError)"]
    broken = verify_anchor(anchor, bucket=BUCKET, client=Broken())
    assert broken["status"] == "failed"
    assert broken["issues"] == ["the anchor could not be checked: RuntimeError: boom"]


def test_anchor_function_requires_a_manifest_reference(pg_app):
    from app.services.audit_chain import AuditChainError, insert_anchor

    base = {"archive_id": "a", "archive_sha256": "a" * 64, "archived_chain_head": "b" * 64, "archived_entries": 1}
    for manifest_key, manifest_sha, message in (
            ("chain-heads/x.json", "c" * 64, "manifest key must be"),
            ("archives/x/y.manifest.json", "nothex", "manifest sha256 must be")):
        with pytest.raises(Exception, match=message):
            db.session.execute(text(
                "SELECT audit_log_insert_anchor(:a, :s, :h, 1, :k, :m, NULL)"),
                {"a": "a", "s": "a" * 64, "h": "b" * 64, "k": manifest_key, "m": manifest_sha})
        db.session.rollback()
    with pytest.raises(AuditChainError, match="manifest_key"):
        insert_anchor(db.session, manifest_key="x.json", manifest_sha256="c" * 64, **base)
    with pytest.raises(AuditChainError, match="manifest_sha256"):
        insert_anchor(db.session, manifest_key="archives/x/y.manifest.json", manifest_sha256="", **base)
