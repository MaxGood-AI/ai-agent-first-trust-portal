"""Witness tamper scenarios, one named test each (fix round 4).

C1 / W2 / H3: head objects are authenticated by their KEY, invalid objects
are reported (never a crash), and a foreign chain is accepted only through a
verified archive manifest. N1 i-v: the chain-replacement variants. Manifest
version games, manifests of another chain or archive, forged dumps, a 412
pre-publication and every "unverified" downgrade. W1: the witness publishes
only once armed (owner-only, audited). N6: bounded verify API output.
"""

import io
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app import runtime_config
from app.models import Control, db
from app.services import audit_archive, audit_witness
from app.services.audit_chain import insert_anchor, verify_chain

BUCKET = "witness"
DUMP = b"-- PostgreSQL database dump\n" + b"d" * 2048


@pytest.fixture
def s3(monkeypatch):
    with mock_aws():
        for name, value in (("AWS_ACCESS_KEY_ID", "testing"), ("AWS_SECRET_ACCESS_KEY", "testing"),
                            ("AWS_REGION", "us-east-1"), ("AUDIT_WITNESS_BUCKET", BUCKET)):
            monkeypatch.setenv(name, value)
        for name in ("AUDIT_WITNESS_DISABLED", "AWS_RUNTIME_ROLE_ARN", "PORTAL_SECRET_ID"):
            monkeypatch.delenv(name, raising=False)
        audit_witness._armed_cache.clear()
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
        yield client
        audit_witness._armed_cache.clear()


@pytest.fixture
def app_url(migrated_pg_url):
    from cli.db_cmd import provision_app_role

    role = f"tpa_{uuid.uuid4().hex[:8]}"
    url = make_url(migrated_pg_url).set(username=role, password="app-" + uuid.uuid4().hex)
    rendered = url.render_as_string(hide_password=False)
    assert provision_app_role(migrated_pg_url, rendered) is True
    return rendered


# --------------------------------------------------------------------------
# helpers (pg_app connects as the NON-superuser owner)
# --------------------------------------------------------------------------

def _writes(*names):
    for name in names:
        db.session.add(Control(id=name, name=name, category="security"))
        db.session.commit()


def _arm():
    audit_witness.arm(db.session, note="test")
    db.session.commit()


def _publish(s3, **kwargs):
    return audit_witness.publish_head(db.session, client=s3, **kwargs)


def _empty_audit_log():
    """The owner's rewrite (or a restore without the audit history)."""
    db.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    db.session.execute(text("DELETE FROM audit_log"))
    db.session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    db.session.commit()


def _scan(s3):
    return audit_witness.load_heads_s3(BUCKET, client=s3)


def _verify(s3, rehash=False, client=None):
    heads = audit_witness.load_heads_s3(BUCKET, client=client or s3)
    return verify_chain(db.session, witness_heads=heads, anchor_verifier=lambda anchor: audit_archive.verify_anchor(
        anchor, bucket=BUCKET, client=client or s3, rehash=rehash, heads=heads))


def _archive(s3, tmp_path, name="final.dump", content=DUMP, **kwargs):
    dump = tmp_path / f"{name}.bin"
    dump.write_bytes(content)
    return audit_archive.create_archive_manifest(db.session, bucket=BUCKET, client=s3, dump_path=str(dump),
                                                 name=name, **kwargs)


def _anchor(s3, manifest_key):
    anchored = audit_archive.anchor_from_manifest(db.session, bucket=BUCKET, client=s3, manifest_key=manifest_key)
    db.session.commit()
    _publish(s3)
    return anchored


def _cutover(s3, tmp_path, name="final.dump"):
    """Chain A (armed, heads published) -> archive -> restore -> chain B anchored, heads published."""
    _arm()
    _writes(f"{name}-a1")
    _publish(s3)
    _writes(f"{name}-a2")
    _publish(s3)
    chain_a = audit_witness.chain_id(db.session)
    written = _archive(s3, tmp_path, name=name)
    _empty_audit_log()
    _anchor(s3, written["manifest_key"])
    _writes(f"{name}-b1")
    _publish(s3)
    return {"written": written, "manifest": written["manifest"], "chain_a": chain_a,
            "chain_b": audit_witness.chain_id(db.session)}


def _replay_anchor(written, **overrides):
    """The owner re-anchors an EMPTY audit log with values of its choosing."""
    manifest = written["manifest"]
    values = {"archive_id": manifest["archive_id"], "archive_sha256": manifest["archive_sha256"],
              "archived_chain_head": manifest["final_row_hash"], "archived_entries": manifest["entries"],
              "manifest_key": written["manifest_key"], "manifest_sha256": written["manifest_sha256"],
              "note": "replayed"}
    values.update(overrides)
    insert_anchor(db.session, **values)
    db.session.commit()


def _fake_head(chain, row_id, row_hash, stamp="20261001T050000Z"):
    published_at = datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"format": audit_witness.FORMAT, "chain_id": chain, "id": row_id, "row_hash": row_hash,
            "hash_version": 2, "published_at": published_at, "database": "x", "anchor": None,
            "portal_version": None}


def _put(s3, key, body):
    s3.put_object(Bucket=BUCKET, Key=key, Body=body if isinstance(body, bytes) else json.dumps(body).encode())


def _cli(monkeypatch, url, argv):
    from cli import admin_cmd
    from cli.__main__ import build_parser

    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", url)
    runtime_config._reset_for_tests()
    out = io.StringIO()
    code = admin_cmd.run(build_parser().parse_args(argv), out=out)
    return code, out.getvalue()


class FailingReads:
    """Wraps a client; reading the given keys fails with ``code`` (KMS, SSE-C, ...)."""

    def __init__(self, client, keys, code="AccessDenied"):
        self.client, self.keys, self.code = client, set(keys), code

    def get_object(self, **kwargs):
        if kwargs["Key"] in self.keys:
            raise ClientError({"Error": {"Code": self.code, "Message": "cannot decrypt"}}, "GetObject")
        return self.client.get_object(**kwargs)

    def __getattr__(self, name):
        return getattr(self.client, name)


# --------------------------------------------------------------------------
# C1: replayed manifest + one forged head for the replaced chain
# --------------------------------------------------------------------------

def test_c1_replayed_manifest_with_a_forged_head_for_the_replaced_chain_is_broken(
        pg_app, migrated_pg_url, s3, tmp_path, monkeypatch):
    state = _cutover(s3, tmp_path)
    assert _verify(s3)["status"] == "valid"
    manifest, chain_b = state["manifest"], state["chain_b"]

    # The owner empties chain B and re-anchors with the SAME legitimate manifest.
    _empty_audit_log()
    _replay_anchor(state["written"])
    _writes("c1")
    _publish(s3)
    # The runtime role writes ONE head for chain B naming A's final hash, newer than any real B head.
    fake = _fake_head(chain_b, 999999999, manifest["final_row_hash"])
    _put(s3, audit_witness.object_key(fake), fake)

    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-verify", "--witness-s3"])
    assert code == 1, out
    assert out.startswith("status=broken")
    assert chain_b in out and "no verified archive manifest of the current chain continues" in out
    result = _verify(s3)
    assert result["status"] == "broken"
    assert [c["chain_id"] for c in result["witness"]["continued_chains"]] == [state["chain_a"]]
    assert [m["chain_id"] for m in result["witness"]["mismatches"]] == [chain_b]
    assert result["anchor_verification"]["status"] == "verified"  # the manifest itself is genuine


def test_c1_forged_head_under_an_unrelated_key_is_an_invalid_object(pg_app, s3, tmp_path):
    state = _cutover(s3, tmp_path)
    fake = _fake_head(state["chain_b"], 999999998, state["manifest"]["final_row_hash"])
    key = f"chain-heads/{'0' * 16}/2026/10/01/20261001T050001Z-999999998.json"  # body names chain B
    _put(s3, key, fake)
    result = _verify(s3)
    assert result["status"] == "broken"
    assert result["witness"]["invalid_heads"] == [
        {"key": key, "version_id": result["witness"]["invalid_heads"][0]["version_id"],
         "reason": "body disagrees with its key (chain id or row id)"}]
    assert result["first_break"]["issue"].startswith("Invalid witness objects: 1")


# --------------------------------------------------------------------------
# W2 / H3: every kind of invalid head object is reported, never a crash
# --------------------------------------------------------------------------

def test_h3_each_invalid_head_object_is_reported_with_its_key(pg_app, s3):
    _arm()
    _writes("c1")
    head = _publish(s3)["head"]
    cid, row = head["chain_id"], head["id"]
    base = f"chain-heads/{cid}/2026/10/01/"
    planted = {
        f"{base}20261001T000001Z-{row}.json": (b"x" * 5000, "object larger than 4096 bytes"),
        f"{base}20261001T000002Z-{row}.json": (b"{not json", "not JSON"),
        f"{base}20261001T000003Z-{row}.json": (json.dumps({"format": audit_witness.FORMAT, "chain_id": cid,
                                                           "id": row}).encode(),
                                               "chain_id, id or row_hash missing or malformed"),
        f"{base}20261001T000004Z-{row + 1}.json": (json.dumps(dict(head, id=row)).encode(),
                                                   "body disagrees with its key (chain id or row id)"),
        f"chain-heads/{cid}/notes.txt": (b"hello", "key is not of the chain head form"),
        f"{base}20261001T000005Z-{row}.json": (json.dumps(head).encode(), "unreadable (AccessDenied)"),
    }
    for key, (body, _) in planted.items():
        _put(s3, key, body)
    unreadable = FailingReads(s3, [f"{base}20261001T000005Z-{row}.json"])
    result = _verify(s3, client=unreadable)
    assert result["status"] == "broken"
    reported = {entry["key"]: entry["reason"] for entry in result["witness"]["invalid_heads"]}
    assert reported == {key: reason for key, (_, reason) in planted.items()}
    assert result["invalid_witness_objects"] == len(planted)
    assert result["witness"]["checked"] == 1 and result["witness_mismatches"] == 0


def test_h3_every_witness_and_archive_write_uses_sse_s3(pg_app, s3, tmp_path, monkeypatch):
    """Heads, manifests and archives are written with SSE-S3, so an auditor can always read them
    (the bucket policy denies any other encryption for the runtime role)."""
    calls = []
    for name in ("put_object", "create_multipart_upload"):
        real = getattr(s3, name)

        def recording(real=real, name=name, **kwargs):
            calls.append((name, kwargs.get("Key"), kwargs.get("ServerSideEncryption")))
            return real(**kwargs)

        monkeypatch.setattr(s3, name, recording)
    _cutover(s3, tmp_path)
    assert calls and {encryption for _, _, encryption in calls} == {"AES256"}
    assert {key.split("/")[0] for _, key, _ in calls} == {"chain-heads", "archives"}


# --------------------------------------------------------------------------
# N1 i-v: replacing the chain
# --------------------------------------------------------------------------

def test_n1_i_truncated_tail_is_broken(pg_app, s3):
    _arm()
    _writes("c1", "c2")
    head = _publish(s3)["head"]
    db.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    db.session.execute(text("DELETE FROM audit_log WHERE id = :i"), {"i": head["id"]})
    db.session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    db.session.commit()
    result = _verify(s3)
    assert result["status"] == "broken" and result["first_witness_mismatch_id"] == head["id"]


def test_n1_ii_chain_recomputed_from_row_one_is_broken(pg_app, s3):
    _arm()
    _writes("c1", "c2")
    _publish(s3)
    _empty_audit_log()
    db.session.execute(text("UPDATE controls SET name = 'rewritten' WHERE id = 'c1'"))
    db.session.commit()
    result = _verify(s3)
    assert result["status"] == "broken" and result["witness"]["checked"] == 0


def test_n1_iii_reanchored_at_an_unpublished_head_is_broken(pg_app, s3):
    _arm()
    _writes("c1")
    _publish(s3)
    _empty_audit_log()
    insert_anchor(db.session, archive_id="fake", archive_sha256="a" * 64, archived_chain_head="b" * 64,
                  archived_entries=1, manifest_key="archives/0000000000000000/fake.manifest.json",
                  manifest_sha256="c" * 64)
    db.session.commit()
    _publish(s3)
    result = _verify(s3)
    assert result["status"] == "broken" and result["anchor_verification"]["status"] == "failed"


def test_n1_iv_reanchored_at_the_last_published_head_without_a_manifest_is_broken(pg_app, s3):
    _arm()
    _writes("c1")
    last = _publish(s3)["head"]
    _empty_audit_log()
    insert_anchor(db.session, archive_id="fake", archive_sha256="a" * 64, archived_chain_head=last["row_hash"],
                  archived_entries=1, manifest_key="archives/0000000000000000/fake.manifest.json",
                  manifest_sha256="c" * 64)
    db.session.commit()
    _publish(s3)
    result = _verify(s3)
    assert result["status"] == "broken"
    assert result["anchor_verification"]["issues"] == [
        "no archive manifest at archives/0000000000000000/fake.manifest.json"]
    assert result["witness"]["continued_chains"] == []


def test_n1_v_reanchored_with_the_legitimate_manifest_after_the_new_chain_published_is_broken(
        pg_app, s3, tmp_path):
    state = _cutover(s3, tmp_path)
    _empty_audit_log()
    _replay_anchor(state["written"])
    _publish(s3)
    result = _verify(s3)
    assert result["status"] == "broken"
    assert [m["chain_id"] for m in result["witness"]["mismatches"]] == [state["chain_b"]]


# --------------------------------------------------------------------------
# Manifest version games, foreign manifests, key shape
# --------------------------------------------------------------------------

def test_manifest_version_game_a_second_version_fails(pg_app, s3, tmp_path):
    state = _cutover(s3, tmp_path)
    forged = dict(state["manifest"], archive_sha256="f" * 64)
    _put(s3, state["written"]["manifest_key"], json.dumps(forged, sort_keys=True, indent=2).encode())
    result = _verify(s3)
    assert result["status"] == "broken"
    assert "is not the one the anchor names" in result["anchor_verification"]["issues"][0]


def test_manifest_version_game_anchor_pinned_to_an_added_version_fails(pg_app, s3, tmp_path):
    state = _cutover(s3, tmp_path)
    forged = json.dumps(dict(state["manifest"], entries=1), sort_keys=True, indent=2).encode()
    _put(s3, state["written"]["manifest_key"], forged)
    _empty_audit_log()
    _replay_anchor(state["written"], archived_entries=1,
                   manifest_sha256=__import__("hashlib").sha256(forged).hexdigest())
    result = _verify(s3)
    assert result["status"] == "broken"
    assert "is not the one the anchor names" in result["anchor_verification"]["issues"][0]


def test_manifest_version_game_delete_marker_keeps_the_pinned_manifest(pg_app, s3, tmp_path):
    state = _cutover(s3, tmp_path)
    s3.delete_object(Bucket=BUCKET, Key=state["written"]["manifest_key"])  # a delete marker, not a deletion
    result = _verify(s3)
    assert result["status"] == "valid"
    assert result["anchor_verification"]["manifest_versions"] == 1


def test_manifest_of_another_chain_does_not_continue_the_replaced_chain(pg_app, s3, tmp_path):
    other = _cutover(s3, tmp_path, name="other.dump")      # chain X archived, chain B continues it
    _empty_audit_log()
    state = _cutover(s3, tmp_path, name="final.dump")       # chain Y archived, chain Z continues it
    _empty_audit_log()
    _replay_anchor(other["written"])                        # the owner re-anchors with X's manifest
    _publish(s3)
    result = _verify(s3)
    assert result["status"] == "broken"
    rejected = {m["chain_id"] for m in result["witness"]["mismatches"]}
    assert state["chain_a"] in rejected and state["chain_b"] in rejected


def test_an_earlier_archive_of_the_same_chain_is_rejected(pg_app, s3, tmp_path):
    _arm()
    _writes("a1")
    _publish(s3)
    early = _archive(s3, tmp_path, name="early.dump")      # a mid-life archive of chain A
    _writes("a2")
    _publish(s3)                                            # chain A continued and was published
    _empty_audit_log()
    _replay_anchor(early)
    _publish(s3)
    result = _verify(s3)
    assert result["status"] == "broken"
    assert any("after its final row" in issue for issue in result["anchor_verification"]["issues"])


def test_manifest_key_outside_archives_is_rejected(pg_app, s3, tmp_path):
    """The runtime role can write chain-heads/, so a manifest there proves nothing."""
    state = _cutover(s3, tmp_path)
    body = json.dumps(state["manifest"], sort_keys=True, indent=2).encode()
    key = f"chain-heads/{state['manifest']['chain_id']}/final.dump.manifest.json"
    _put(s3, key, body)
    anchor = {"archive_id": "final.dump", "archive_sha256": state["manifest"]["archive_sha256"],
              "archived_chain_head": state["manifest"]["final_row_hash"],
              "archived_entries": state["manifest"]["entries"], "archive_manifest_key": key,
              "archive_manifest_sha256": __import__("hashlib").sha256(body).hexdigest()}
    checked = audit_archive.verify_anchor(anchor, bucket=BUCKET, client=s3)
    assert checked["status"] == "failed"
    assert checked["issues"] == [f"the anchor's manifest key {key} is not archives/<chain id>/<name>.manifest.json"]


# --------------------------------------------------------------------------
# Forged dumps
# --------------------------------------------------------------------------

def test_forged_dump_as_a_new_version_does_not_replace_the_pinned_archive(pg_app, s3, tmp_path):
    state = _cutover(s3, tmp_path)
    _put(s3, state["manifest"]["archive_key"], b"f" * len(DUMP))  # same size, other bytes, new version
    result = _verify(s3, rehash=True)
    assert result["status"] == "valid" and result["anchor_verification"]["rehashed"] is True


def test_forged_dump_that_the_manifest_does_not_hash_to_fails_the_rehash(pg_app, s3, tmp_path):
    _arm()
    _writes("a1")
    _publish(s3)
    cid = audit_witness.chain_id(db.session)
    key = f"archives/{cid}/uploaded-earlier"
    _put(s3, key, b"f" * len(DUMP))
    written = _archive(s3, tmp_path, archive_key=key)
    _empty_audit_log()
    _anchor(s3, written["manifest_key"])
    assert _verify(s3)["status"] == "valid"
    rehashed = _verify(s3, rehash=True)
    assert rehashed["status"] == "broken"
    assert rehashed["anchor_verification"]["issues"] == [
        "the archive object's bytes do not hash to the manifest's archive_sha256"]


# --------------------------------------------------------------------------
# 412: a head pre-published at the publisher's key
# --------------------------------------------------------------------------

def test_412_pre_published_forged_head_is_a_conflict_and_the_head_is_republished(pg_app, s3, caplog):
    _arm()
    _writes("c1")
    head = audit_witness.current_head(db.session)
    key = audit_witness.object_key(head)
    _put(s3, key, dict(head, row_hash="e" * 64))                 # forged, at the exact key
    with caplog.at_level(logging.ERROR, logger="app.services.audit_witness"):
        published = _publish(s3, head=head)
    assert published["conflicts"] == [key] and published["key"] != key
    assert published["outcome"] == "published"
    assert "audit_witness_conflict" in caplog.text
    genuine = json.loads(s3.get_object(Bucket=BUCKET, Key=published["key"])["Body"].read())
    assert genuine["row_hash"] == head["row_hash"]
    outcome = db.session.execute(text("SELECT outcome FROM audit_witness_publications ORDER BY id DESC "
                                      "LIMIT 1")).scalar()
    assert outcome == "conflict"
    result = _verify(s3)
    assert result["status"] == "broken"                           # the forged object is still evidence
    assert result["witness"]["mismatches"][0]["key"] == key


def test_412_identical_object_is_already_published(pg_app, s3):
    _arm()
    _writes("c1")
    head = audit_witness.current_head(db.session)
    first = _publish(s3, head=head)
    again = _publish(s3, head=head)
    assert first["outcome"] == "published" and again["outcome"] == "already" and again["key"] == first["key"]


# --------------------------------------------------------------------------
# "unverified" downgrades
# --------------------------------------------------------------------------

def test_unverified_downgrade_unreadable_head_of_the_archived_chain_fails(pg_app, s3, tmp_path):
    state = _cutover(s3, tmp_path)
    manifest = state["manifest"]
    key = f"chain-heads/{manifest['chain_id']}/2026/10/01/20261001T060000Z-{manifest['final_row_id']}.json"
    _put(s3, key, _fake_head(manifest["chain_id"], manifest["final_row_id"], manifest["final_row_hash"],
                             "20261001T060000Z"))
    result = _verify(s3, client=FailingReads(s3, [key], code="InvalidRequest"))  # e.g. SSE-C
    assert result["status"] == "broken"
    assert result["anchor_verification"]["status"] == "failed"
    assert any("invalid witness object" in issue for issue in result["anchor_verification"]["issues"])


def test_unverified_downgrade_only_a_bucket_wide_read_failure_is_unverified(
        pg_app, migrated_pg_url, s3, tmp_path, monkeypatch):
    state = _cutover(s3, tmp_path)

    class Denied:
        def get_paginator(self, name):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListObjectVersions")

    checked = audit_archive.verify_anchor({"archive_manifest_key": state["written"]["manifest_key"],
                                           "archive_manifest_sha256": state["written"]["manifest_sha256"]},
                                          bucket=BUCKET, client=Denied())
    assert checked["status"] == "unverified" and checked["lineage"] == []
    # The CLI cannot list the bucket: a usage error, never a verdict.
    monkeypatch.setattr(audit_witness, "s3_client", lambda: Denied())
    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-verify", "--witness-s3"])
    assert code == 2 and out.startswith("error: cannot list the witness bucket")


def test_unverified_downgrade_heads_from_a_file_cannot_continue_a_foreign_chain(pg_app, s3, tmp_path):
    state = _cutover(s3, tmp_path)
    heads = _scan(s3)
    # Without the manifest check the archived chain is an unverified continuation...
    unchecked = verify_chain(db.session, witness_heads=heads)
    assert unchecked["status"] == "unverified"
    assert [c["chain_id"] for c in unchecked["witness"]["unverified_continuations"]] == [state["chain_a"]]
    # ...but a forged chain the anchor does not name is still broken, not unverified.
    fake = _fake_head("f" * 16, 5, "e" * 64)
    heads["valid"].append({"key": audit_witness.object_key(fake), "version_id": None, "head": fake})
    assert verify_chain(db.session, witness_heads=heads)["status"] == "broken"


# --------------------------------------------------------------------------
# Lineage: two cutovers in a row
# --------------------------------------------------------------------------

def test_two_generation_lineage_verifies(pg_app, s3, tmp_path):
    first = _cutover(s3, tmp_path, name="first.dump")          # A archived, B anchored
    second = _archive(s3, tmp_path, name="second.dump")         # B archived (its anchor is recorded)
    assert second["manifest"]["source_anchor"]["archive_manifest_key"] == first["written"]["manifest_key"]
    _empty_audit_log()
    _anchor(s3, second["manifest_key"])                         # C anchored to B
    _writes("c1")
    _publish(s3)
    result = _verify(s3, rehash=True)
    assert result["status"] == "valid", result["witness"]
    assert {c["chain_id"] for c in result["witness"]["continued_chains"]} == {first["chain_a"], first["chain_b"]}
    assert len(result["anchor_verification"]["lineage"]) == 2


# --------------------------------------------------------------------------
# W1: arming
# --------------------------------------------------------------------------

def test_w1_unarmed_witness_never_publishes(pg_app, migrated_pg_url, s3, monkeypatch):
    _writes("c1")
    assert audit_witness.witness_state(db.session) == "unarmed"
    assert _publish(s3) is None
    assert audit_witness.PeriodicPublisher()(pg_app) is None
    health = pg_app.test_client().get("/api/health").get_json()
    assert health["witness"] == "unarmed" and health["last_published_at"] is None
    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-publish-head"])
    assert code == 2 and "not armed" in out
    assert s3.list_objects_v2(Bucket=BUCKET).get("KeyCount", 0) == 0


def test_w1_arming_is_owner_only_append_only_and_audited(migrated_pg_url, app_url, s3, monkeypatch):
    engine = create_engine(app_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            for statement, message in (
                    ("SELECT public.audit_witness_arm('app')", "permission denied"),
                    ("INSERT INTO audit_witness_arming (armed_by) VALUES ('app')",
                     "permission denied|written only by audit_witness_arm"),
                    ("DELETE FROM audit_witness_arming", "permission denied|written only by audit_witness_arm")):
                with pytest.raises(Exception, match=message):
                    conn.execute(text(statement))
    finally:
        engine.dispose()
    owner = create_engine(migrated_pg_url, isolation_level="AUTOCOMMIT")
    try:
        with owner.connect() as conn:
            role = make_url(app_url).username
            conn.execute(text(f'GRANT INSERT, UPDATE, DELETE ON audit_witness_arming TO "{role}"'))
    finally:
        owner.dispose()
    engine = create_engine(app_url, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:  # even a mis-grant does not let the app role arm
            with pytest.raises(Exception, match="written only by audit_witness_arm"):
                conn.execute(text("INSERT INTO audit_witness_arming (armed_by) VALUES ('app')"))
    finally:
        engine.dispose()

    monkeypatch.setenv("DATABASE_OWNER_URL", migrated_pg_url)
    code, out = _cli(monkeypatch, app_url, ["audit-witness-arm", "--note", "production from today"])
    assert code == 0 and out.startswith("Armed the audit witness")
    owner = create_engine(migrated_pg_url)
    try:
        with owner.connect() as conn:
            armed_by = conn.execute(text("SELECT armed_by FROM audit_witness_arming")).scalar()
            audited = conn.execute(text("SELECT count(*) FROM audit_log WHERE table_name = 'audit_witness_arming' "
                                        "AND action = 'INSERT'")).scalar()
            with pytest.raises(Exception, match="written only by audit_witness_arm"):
                conn.execute(text("UPDATE audit_witness_arming SET note = 'x'"))
    finally:
        owner.dispose()
    assert armed_by == make_url(migrated_pg_url).username and audited == 1


def test_w1_arming_publishes_and_health_reports_the_last_publication(pg_app, migrated_pg_url, s3, monkeypatch):
    _writes("c1")
    monkeypatch.setenv("DATABASE_OWNER_URL", migrated_pg_url)
    code, out = _cli(monkeypatch, migrated_pg_url, ["audit-witness-arm"])
    assert code == 0 and "Published chain head to chain-heads/" in out
    health = pg_app.test_client().get("/api/health").get_json()
    assert health["witness"] == "enabled" and health["last_published_at"] and health["witness_stale"] is False


def test_w1_kill_switch_overrides_arming(pg_app, s3, monkeypatch):
    _arm()
    _writes("c1")
    monkeypatch.setenv("AUDIT_WITNESS_DISABLED", "true")
    assert _publish(s3) is None
    assert audit_witness.PeriodicPublisher()(pg_app) is None
    assert pg_app.test_client().get("/api/health").get_json()["witness"] == "disabled"
    assert s3.list_objects_v2(Bucket=BUCKET).get("KeyCount", 0) == 0


def test_w1_audit_anchor_arms_the_witness(pg_app, s3, tmp_path):
    state = _cutover(s3, tmp_path)
    notes = [row[0] for row in db.session.execute(text("SELECT note FROM audit_witness_arming ORDER BY id"))]
    assert notes[-1] == f"cutover: anchored to {state['written']['manifest_key']}"


def test_w1_stale_witness_is_logged_and_flagged(pg_app, s3, monkeypatch, caplog):
    from app.services import team_service
    from tests.conftest import login

    _arm()
    _writes("c1")
    head = _publish(s3)["head"]
    db.session.execute(text("UPDATE audit_witness_publications SET published_at = :t"),
                       {"t": datetime.now(timezone.utc) - timedelta(hours=3)})
    db.session.commit()
    _writes("c2")  # the head moves; publishing now fails

    class Broken:
        def put_object(self, **kwargs):
            raise ClientError({"Error": {"Code": "InternalError", "Message": "down"}}, "PutObject")

    monkeypatch.setattr(audit_witness, "s3_client", lambda: Broken())
    with caplog.at_level(logging.WARNING, logger="app.services.audit_witness"):
        assert audit_witness.PeriodicPublisher()(pg_app) is None
    assert "audit_witness_stale" in caplog.text and f"last_published_id={head['id']}" in caplog.text
    health = pg_app.test_client().get("/api/health").get_json()
    assert health["witness"] == "enabled" and health["witness_stale"] is True
    admin = team_service.create_member("Admin", "a@example.com", "human", is_compliance_admin=True)
    client = pg_app.test_client()
    login(client, admin)
    page = client.get("/admin/").get_data(as_text=True)
    assert 'id="witness-stale"' in page


def test_publish_uses_the_timeout_client(pg_app, monkeypatch):
    _arm()
    _writes("c1")
    monkeypatch.setenv("AUDIT_WITNESS_BUCKET", BUCKET)
    made = []

    class Client:
        def put_object(self, **kwargs):
            return {}

    def factory():
        made.append(True)
        return Client()

    monkeypatch.setattr(audit_witness, "s3_client", factory)
    assert audit_witness.publish_head(db.session)["outcome"] == "published"
    assert made == [True]


# --------------------------------------------------------------------------
# N6: the verify API's output is bounded; malformed heads are a 400
# --------------------------------------------------------------------------

def test_n6_verify_api_truncates_findings_with_counts(pg_app):
    from app.services import team_service

    _writes("c1")
    cid = audit_witness.chain_id(db.session)
    items = []
    for n in range(150):
        head = _fake_head(cid, 1000 + n, "a" * 64)
        items.append({"key": audit_witness.object_key(head), "head": head})
    admin = team_service.create_member("Admin", "a@example.com", "human", is_compliance_admin=True)
    body = pg_app.test_client().post("/api/audit-log/verify", json={"heads": items},
                                     headers={"X-API-Key": admin.issued_api_key}).get_json()
    assert body["status"] == "broken" and body["witness_mismatches"] == 150
    assert len(body["witness"]["mismatches"]) == audit_witness.MAX_REPORTED
    assert body["witness"]["mismatches_count"] == 150


def test_n6_verify_api_rejects_malformed_heads(pg_app):
    from app.services import team_service

    _writes("c1")
    head = audit_witness.current_head(db.session)
    admin = team_service.create_member("Admin", "a@example.com", "human", is_compliance_admin=True)
    client = pg_app.test_client()
    headers = {"X-API-Key": admin.issued_api_key}
    for heads in ([head], [{"key": "chain-heads/x.json", "head": head}],
                  [{"key": audit_witness.object_key(dict(head, id=head["id"] + 1)), "head": head}],
                  "not a list", [{"key": audit_witness.object_key(head), "head": "x" * 5000}]):
        response = client.post("/api/audit-log/verify", json={"heads": heads}, headers=headers)
        assert response.status_code == 400, heads
