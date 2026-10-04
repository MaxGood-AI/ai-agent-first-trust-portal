"""Audit-log hash chain on PostgreSQL: trigger behaviour, verification,
anchors, append-only protection and role separation."""

import threading
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.models import Control, db
from app.services import team_service
from app.services.audit_chain import AuditChainError, insert_anchor, verify_chain

HEX64 = "a" * 64


def _control(name="MFA", **extra):
    control = Control(id=str(uuid.uuid4()), name=name, category="security", **extra)
    db.session.add(control)
    db.session.commit()
    return control


def _rows(table=None):
    sql = "SELECT id, table_name, record_id, action, old_values, new_values, hash_version, " \
          "previous_hash, row_hash FROM audit_log"
    if table:
        sql += " WHERE table_name = :t"
    return db.session.execute(text(sql + " ORDER BY id"), {"t": table}).mappings().all()


def test_trigger_writes_v2_chained_rows(pg_app):
    control = _control()
    control.description = "changed"
    db.session.commit()
    db.session.delete(control)
    db.session.commit()

    rows = _rows("controls")
    assert [r["action"] for r in rows] == ["INSERT", "UPDATE", "DELETE"]
    assert all(r["hash_version"] == 2 for r in rows)
    assert rows[0]["previous_hash"] == "0" * 64
    assert rows[1]["previous_hash"] == rows[0]["row_hash"]
    result = verify_chain(db.session)
    assert result["status"] == "valid"
    assert result["verified"] == 3
    assert result["chain_head"] == rows[-1]["row_hash"]


def test_noop_and_updated_at_only_updates_are_not_audited(pg_app):
    control = _control()
    before = len(_rows())
    db.session.execute(text("UPDATE controls SET name = name WHERE id = :id"), {"id": control.id})
    db.session.execute(text("UPDATE controls SET updated_at = now() WHERE id = :id"), {"id": control.id})
    db.session.commit()
    assert len(_rows()) == before
    db.session.execute(text("UPDATE controls SET name = 'Other' WHERE id = :id"), {"id": control.id})
    db.session.commit()
    assert len(_rows()) == before + 1


def test_api_key_hash_is_recorded_as_digest_only(pg_app):
    member = team_service.create_member("Agent", "a@example.com", "agent")
    team_service.regenerate_key(member.id)
    rows = _rows("team_members")
    assert rows
    for row in rows:
        for values in (row["old_values"], row["new_values"]):
            if values:
                assert values["api_key_hash"].startswith("sha256:")
                assert member.api_key_hash not in str(values)
                assert member.issued_api_key not in str(values)


def test_changed_by_is_recorded_and_hashed(pg_app):
    member = team_service.create_member("Human", "h@example.com", "human")
    db.session.execute(text("SET LOCAL app.current_team_member = :m"), {"m": member.id})
    _control("Attributed")
    row = _rows("controls")[-1]
    stored = db.session.execute(text("SELECT changed_by FROM audit_log WHERE id = :i"), {"i": row["id"]}).scalar()
    assert stored == member.id
    assert verify_chain(db.session)["status"] == "valid"


def test_verify_detects_altered_content_and_broken_links(pg_app):
    for i in range(4):
        _control(f"C{i}")
    ids = [r["id"] for r in _rows()]
    db.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    db.session.execute(text("UPDATE audit_log SET changed_by = 'forged' WHERE id = :i"), {"i": ids[1]})
    db.session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    db.session.commit()
    result = verify_chain(db.session)
    assert result["status"] == "broken"
    assert result["first_break"]["id"] == ids[1]
    assert "Content altered" in result["first_break"]["issue"]
    assert (result["content_mismatches"], result["forks"], result["true_breaks"]) == (1, 0, 0)
    assert result["first_content_mismatch_id"] == ids[1]


def _tamper(sql, params=None):
    db.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    db.session.execute(text(sql), params or {})
    db.session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    db.session.commit()


def _insert_v1(record_id, previous_hash, changed_at_offset=0):
    """Append a v1-formula row with an explicit previous_hash (as the old trigger wrote them)."""
    new_values = '{"name": "%s"}' % record_id
    _tamper(
        "INSERT INTO audit_log (table_name, record_id, action, new_values, previous_hash, row_hash) "
        "VALUES ('controls', :rid, 'INSERT', CAST(:nv AS jsonb), :prev, "
        "encode(sha256(convert_to(:prev || 'controls' || :rid || 'INSERT' || CAST(:nv AS jsonb)::text, "
        "'UTF8')), 'hex'))",
        {"rid": record_id, "nv": new_values, "prev": previous_hash})
    return db.session.execute(text("SELECT id, row_hash FROM audit_log ORDER BY id DESC LIMIT 1")).first()


def test_verify_classifies_forks_from_concurrent_writers(pg_app):
    genesis = "0" * 64
    a = _insert_v1("a", genesis)
    _insert_v1("b", a.row_hash)
    c = _insert_v1("c", a.row_hash)       # raced with b: both read a as the head -> fork
    d = _insert_v1("d", c.row_hash)
    e = _insert_v1("e", genesis)          # raced with the very first write -> fork to genesis
    _insert_v1("f", e.row_hash)
    result = verify_chain(db.session)
    assert result["status"] == "intact_with_forks"
    assert (result["content_mismatches"], result["forks"], result["true_breaks"]) == (0, 2, 0)
    assert result["first_fork_id"] == c.id
    assert result["first_true_break_id"] is None
    assert "Fork" in result["first_break"]["issue"]
    assert d.id  # linked to its predecessor


def test_verify_classifies_true_breaks_and_content_mismatches(pg_app):
    genesis = "0" * 64
    a = _insert_v1("a", genesis)
    b = _insert_v1("b", a.row_hash)
    c = _insert_v1("c", b.row_hash)
    orphan = _insert_v1("orphan", HEX64)  # points at no row at all
    _insert_v1("x", orphan.row_hash)
    _tamper("UPDATE audit_log SET new_values = CAST('{\"name\": \"forged\"}' AS jsonb) WHERE id = :i",
            {"i": b.id})
    result = verify_chain(db.session)
    assert result["status"] == "broken"
    assert (result["content_mismatches"], result["forks"], result["true_breaks"]) == (1, 0, 1)
    assert result["first_content_mismatch_id"] == b.id
    assert result["first_true_break_id"] == orphan.id
    assert result["first_break"]["id"] == b.id and "Content altered" in result["first_break"]["issue"]
    assert c.id


def test_link_to_a_later_row_is_a_true_break(pg_app):
    genesis = "0" * 64
    a = _insert_v1("a", genesis)
    b = _insert_v1("b", a.row_hash)
    later = _insert_v1("later", b.row_hash)
    _tamper("UPDATE audit_log SET previous_hash = :h WHERE id = :i", {"h": later.row_hash, "i": b.id})
    result = verify_chain(db.session)
    # b now points at a later row (true break, and its v1 hash no longer recomputes);
    # "later" still links to b's stored row_hash.
    assert result["true_breaks"] == 1 and result["first_true_break_id"] == b.id
    assert result["status"] == "broken"


def test_mislink_after_an_anchor_is_a_true_break(pg_app):
    """Rows after the (hash_version 2) anchor are written by the serialized
    trigger, so a row linked to the archived head instead of its predecessor
    cannot be a race: it is a true break."""
    head = "d" * 64
    insert_anchor(db.session, archive_id="arch", archive_sha256="e" * 64,
                  archived_chain_head=head, archived_entries=10,
                  manifest_key="archives/x/y.manifest.json", manifest_sha256="c" * 64)
    db.session.commit()
    anchor_row = db.session.execute(text("SELECT id, row_hash FROM audit_log ORDER BY id LIMIT 1")).first()
    x = _insert_v1("x", anchor_row.row_hash)
    y = _insert_v1("y", head)
    _insert_v1("z", y.row_hash)
    result = verify_chain(db.session)
    assert result["anchor"]["archived_chain_head"] == head
    assert result["status"] == "broken"
    assert (result["content_mismatches"], result["forks"], result["true_breaks"]) == (0, 0, 1)
    assert result["first_true_break_id"] == y.id
    assert x.id


def test_audit_log_is_append_only(pg_app):
    _control()
    for statement in ("UPDATE audit_log SET action = 'X'", "DELETE FROM audit_log", "TRUNCATE audit_log"):
        with pytest.raises(Exception) as excinfo:
            db.session.execute(text(statement))
        assert "append-only" in str(excinfo.value)
        db.session.rollback()


def test_concurrent_writers_never_fork_the_chain(pg_app):
    app = pg_app
    errors = []

    def writer(n):
        try:
            with app.app_context():
                for i in range(10):
                    db.session.add(Control(id=str(uuid.uuid4()), name=f"T{n}-{i}", category="security"))
                    db.session.commit()
                db.session.remove()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    result = verify_chain(db.session)
    assert result["verified"] == 60
    assert result["status"] == "valid"


def test_verify_in_chunks_resumes(pg_app):
    for i in range(5):
        _control(f"R{i}")
    first = verify_chain(db.session, max_rows=2, chunk_size=1)
    assert first["complete"] is False and first["verified"] == 2
    rest = verify_chain(db.session, after_id=first["next_after_id"],
                        expected_previous_hash=first["expected_previous_hash"])
    assert rest["status"] == "valid" and rest["complete"] is True and rest["verified"] == 3
    with pytest.raises(AuditChainError):
        verify_chain(db.session, after_id=1)


def test_verify_empty_and_legacy_unhashed_rows(pg_app):
    assert verify_chain(db.session)["status"] == "empty"
    db.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    db.session.execute(text(
        "INSERT INTO audit_log (table_name, record_id, action, new_values) "
        "VALUES ('controls', 'legacy', 'INSERT', '{}')"))
    db.session.commit()
    assert verify_chain(db.session)["status"] == "no_hashes"
    _control("after-legacy")
    result = verify_chain(db.session)
    assert result["status"] == "valid"
    assert result["unhashed_entries"] == 1


def test_verify_accepts_v1_rows_from_migration_014(pg_app):
    # A row hashed with the v1 formula (no changed_by / changed_at).
    db.session.execute(text(
        "INSERT INTO audit_log (table_name, record_id, action, new_values, previous_hash, row_hash) "
        "SELECT 'controls', 'v1', 'INSERT', '{\"name\": \"x\"}'::jsonb, repeat('0', 64), "
        "encode(sha256(convert_to(repeat('0', 64) || 'controls' || 'v1' || 'INSERT' || "
        "('{\"name\": \"x\"}'::jsonb)::text, 'UTF8')), 'hex')"))
    db.session.commit()
    _control("v2-after-v1")
    result = verify_chain(db.session)
    assert result["status"] == "valid"
    assert result["verified"] == 2


def test_anchor_starts_chain_from_archived_head(pg_app):
    anchor_id = insert_anchor(db.session, archive_id="archive-2026-09", archive_sha256="b" * 64,
                              archived_chain_head=HEX64, archived_entries=19950594,
                              manifest_key="archives/x/y.manifest.json", manifest_sha256="c" * 64,
                              note="cutover")
    db.session.commit()
    _control("post-anchor")
    result = verify_chain(db.session)
    # Intact, but the anchor was not checked against its archive manifest.
    assert result["status"] == "unverified"
    assert result["anchor_verification"]["status"] == "unverified"
    assert result["anchor"]["archive_manifest_key"] == "archives/x/y.manifest.json"
    assert result["anchor"]["archive_manifest_sha256"] == "c" * 64
    assert result["verified"] == 2
    assert result["anchor"]["id"] == anchor_id
    assert result["anchor"]["archived_chain_head"] == HEX64
    assert result["anchor"]["archive_sha256"] == "b" * 64
    assert result["anchor"]["archived_entries"] == 19950594
    rows = _rows()
    assert rows[0]["action"] == "ANCHOR" and rows[0]["previous_hash"] == HEX64
    assert rows[1]["previous_hash"] == rows[0]["row_hash"]


def test_anchor_refused_when_audit_log_not_empty(pg_app):
    _control()
    with pytest.raises(Exception) as excinfo:
        insert_anchor(db.session, archive_id="late", archive_sha256="b" * 64,
                      archived_chain_head=HEX64, archived_entries=1,
                      manifest_key="archives/x/y.manifest.json", manifest_sha256="c" * 64)
    assert "not empty" in str(excinfo.value)
    db.session.rollback()
    with pytest.raises(AuditChainError):
        insert_anchor(db.session, archive_id="x", archive_sha256="nothex",
                      archived_chain_head=HEX64, archived_entries=1,
                      manifest_key="archives/x/y.manifest.json", manifest_sha256="c" * 64)


def test_verify_api_in_slices(pg_app):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    headers = {"X-API-Key": admin.issued_api_key}
    client = pg_app.test_client()
    _control("second row")
    verified = client.get("/api/audit-log/verify?max_rows=1", headers=headers).get_json()
    assert verified["verified"] == 1 and verified["complete"] is False
    follow = client.get(f"/api/audit-log/verify?after_id={verified['next_after_id']}"
                        f"&expected_previous_hash={verified['expected_previous_hash']}",
                        headers=headers).get_json()
    assert follow["status"] == "valid" and follow["complete"] is True


def test_app_role_cannot_modify_audit_log_but_audited_writes_work(pg_app, migrated_pg_url):
    from cli.db_cmd import provision_app_role

    app_user = f"tp_app_{uuid.uuid4().hex[:8]}"
    app_url = make_url(migrated_pg_url).set(username=app_user, password="app-pass-123")
    owner_url = migrated_pg_url
    # The pg_url fixture drops the roles the owner created.
    assert provision_app_role(owner_url, app_url.render_as_string(hide_password=False)) is True
    # Re-running (every container start) updates the password and grants idempotently.
    assert provision_app_role(owner_url, app_url.render_as_string(hide_password=False)) is True
    engine = create_engine(app_url.render_as_string(hide_password=False))
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO controls (id, name, category) VALUES ('c-app', 'App', 'security')"))
    with engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM audit_log WHERE record_id = 'c-app'")).scalar() == 1
        for statement in (
            "INSERT INTO audit_log (table_name, record_id, action) VALUES ('x', 'y', 'INSERT')",
            "UPDATE audit_log SET action = 'X'",
            "DELETE FROM audit_log",
            "UPDATE alembic_version SET version_num = 'x'",
        ):
            with pytest.raises(Exception) as excinfo:
                conn.execute(text(statement))
            assert "permission denied" in str(excinfo.value)
            conn.rollback()
    engine.dispose()
    assert provision_app_role(owner_url, owner_url) is False


def test_verify_works_on_a_pre_016_database(pg_url):
    """An archived database (schema before migration 016) verifies with the v1 formula."""
    from alembic import command
    from sqlalchemy.orm import Session

    from tests.test_migrations_pg import _alembic_config

    command.upgrade(_alembic_config(pg_url), "015")
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO controls (id, name, category) VALUES ('c1', 'A', 'security')"))
        conn.execute(text("INSERT INTO controls (id, name, category) VALUES ('c2', 'B', 'security')"))
        conn.execute(text("UPDATE controls SET name = 'C' WHERE id = 'c1'"))
    with Session(engine) as session:
        result = verify_chain(session)
    engine.dispose()
    assert result["status"] == "valid"
    assert result["verified"] == 3
